//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/jcmturner/gokrb5/v8/types"
)

// This file talks to the local Kerberos authentication package via the LSA so
// that GoSPN can recover the *session key* of a service ticket it just had the
// SSP mint. That key is required to decrypt the AP-REQ authenticator produced
// during the TGT-delegation trick (see tgtdeleg.go).
//
// Retrieving your own tickets is unprivileged: the LSA returns the session key
// for tickets belonging to the caller's logon session.

var (
	secur32DLL = syscall.NewLazyDLL("secur32.dll")

	procLsaConnectUntrusted            = secur32DLL.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPackage = secur32DLL.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPackage   = secur32DLL.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer            = secur32DLL.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogonProcess      = secur32DLL.NewProc("LsaDeregisterLogonProcess")

	advapi32DLL            = syscall.NewLazyDLL("advapi32.dll")
	procLsaOpenPolicy      = advapi32DLL.NewProc("LsaOpenPolicy")
	procLsaQueryInfoPolicy = advapi32DLL.NewProc("LsaQueryInformationPolicy")
	procLsaFreeMemory      = advapi32DLL.NewProc("LsaFreeMemory")
	procLsaClose           = advapi32DLL.NewProc("LsaClose")
)

// KERB_PROTOCOL_MESSAGE_TYPE
const kerbRetrieveEncodedTicketMessage = 8

// lsaString is an LSA_STRING (ANSI), used to name the auth package.
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// getTicketSessionKey returns the session key of the cached service ticket for
// targetSPN, fetching it through KerbRetrieveEncodedTicketMessage.
func getTicketSessionKey(targetSPN string) (types.EncryptionKey, error) {
	var key types.EncryptionKey

	var lsaHandle uintptr
	if st, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaHandle))); st != 0 {
		return key, fmt.Errorf("LsaConnectUntrusted failed: NTSTATUS 0x%x", st)
	}
	defer procLsaDeregisterLogonProcess.Call(lsaHandle)

	// Resolve the Kerberos authentication package id.
	pkgNameBytes := append([]byte("Kerberos"), 0)
	lstr := lsaString{
		Length:        uint16(len("Kerberos")),
		MaximumLength: uint16(len("Kerberos") + 1),
		Buffer:        uintptr(unsafe.Pointer(&pkgNameBytes[0])),
	}
	var authPkg uint32
	if st, _, _ := procLsaLookupAuthenticationPackage.Call(
		lsaHandle,
		uintptr(unsafe.Pointer(&lstr)),
		uintptr(unsafe.Pointer(&authPkg)),
	); st != 0 {
		return key, fmt.Errorf("LsaLookupAuthenticationPackage failed: NTSTATUS 0x%x", st)
	}

	submit := buildRetrieveTktRequest(targetSPN)

	var (
		retBuf    unsafe.Pointer
		retLen    uint32
		protoStat uint32
	)
	st, _, _ := procLsaCallAuthenticationPackage.Call(
		lsaHandle,
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&submit[0])),
		uintptr(len(submit)),
		uintptr(unsafe.Pointer(&retBuf)),
		uintptr(unsafe.Pointer(&retLen)),
		uintptr(unsafe.Pointer(&protoStat)),
	)
	if st != 0 {
		return key, fmt.Errorf("LsaCallAuthenticationPackage failed: NTSTATUS 0x%x", st)
	}
	if protoStat != 0 {
		return key, fmt.Errorf("KerbRetrieveEncodedTicket for %q failed: NTSTATUS 0x%x", targetSPN, protoStat)
	}
	if retBuf == nil {
		return key, fmt.Errorf("LSA returned no ticket for %q", targetSPN)
	}
	defer procLsaFreeReturnBuffer.Call(uintptr(retBuf))

	return parseExternalTicketSessionKey(retBuf)
}

// buildRetrieveTktRequest lays out a KERB_RETRIEVE_TKT_REQUEST followed by the
// UTF-16 target name in one contiguous buffer, with the TargetName.Buffer field
// pointing at the appended string (x64 layout).
func buildRetrieveTktRequest(targetSPN string) []byte {
	const structSize = 64 // sizeof(KERB_RETRIEVE_TKT_REQUEST) on x64

	name := syscall.StringToUTF16(targetSPN) // includes trailing NUL
	nameBytes := (*[1 << 20]byte)(unsafe.Pointer(&name[0]))[: len(name)*2 : len(name)*2]
	nameLenNoNull := (len(name) - 1) * 2

	buf := make([]byte, structSize+len(nameBytes))
	copy(buf[structSize:], nameBytes)

	put32 := func(off int, v uint32) {
		buf[off] = byte(v)
		buf[off+1] = byte(v >> 8)
		buf[off+2] = byte(v >> 16)
		buf[off+3] = byte(v >> 24)
	}
	put16 := func(off int, v uint16) {
		buf[off] = byte(v)
		buf[off+1] = byte(v >> 8)
	}
	putPtr := func(off int, p uintptr) {
		for i := 0; i < 8; i++ {
			buf[off+i] = byte(p >> (8 * i))
		}
	}

	put32(0, kerbRetrieveEncodedTicketMessage) // MessageType
	// LogonId (LUID) at 4..12 left zero -> current logon session.
	// TargetName UNICODE_STRING at offset 16.
	put16(16, uint16(nameLenNoNull)) // Length
	put16(18, uint16(len(nameBytes))) // MaximumLength (incl. NUL)
	putPtr(24, uintptr(unsafe.Pointer(&buf[structSize])))
	// TicketFlags(32)=0, CacheOptions(36)=0 (KERB_RETRIEVE_TICKET_DEFAULT),
	// EncryptionType(40)=0, CredentialsHandle(48)=0.
	return buf
}

// parseExternalTicketSessionKey reads the SessionKey out of the
// KERB_EXTERNAL_TICKET pointed to by ptr (x64 field offsets).
func parseExternalTicketSessionKey(base unsafe.Pointer) (types.EncryptionKey, error) {
	var key types.EncryptionKey

	read32 := func(off uintptr) uint32 {
		return *(*uint32)(unsafe.Add(base, off))
	}

	// KERB_EXTERNAL_TICKET.SessionKey (KERB_CRYPTO_KEY) begins at offset 72:
	//   KeyType LONG @72, Length ULONG @76, Value PUCHAR @80
	keyType := int32(read32(72))
	keyLen := read32(76)
	valPtr := *(*unsafe.Pointer)(unsafe.Add(base, 80))
	if valPtr == nil || keyLen == 0 || keyLen > 1024 {
		return key, fmt.Errorf("ticket has no usable session key (type %d, len %d)", keyType, keyLen)
	}

	keyVal := make([]byte, keyLen)
	copy(keyVal, unsafe.Slice((*byte)(valPtr), keyLen))

	key.KeyType = keyType
	key.KeyValue = keyVal
	return key, nil
}

// getDomainFromLSA reads the machine's DNS domain name from the LSA policy.
// Works for any account (including NETWORK SERVICE) unlike USERDNSDOMAIN which
// is only set for interactive domain logons.
func getDomainFromLSA() (string, error) {
	// LSA_OBJECT_ATTRIBUTES on x64: Length(4)+pad(4)+RootDir(8)+ObjName(8)+Attrs(4)+pad(4)+SecDesc(8)+SecQoS(8) = 48 bytes.
	// Zeroed except Length = sizeof.
	var objAttrs [48]byte
	*(*uint32)(unsafe.Pointer(&objAttrs[0])) = 48

	var handle uintptr
	if st, _, _ := procLsaOpenPolicy.Call(
		0, // NULL = local system
		uintptr(unsafe.Pointer(&objAttrs[0])),
		0x00000001, // POLICY_VIEW_LOCAL_INFORMATION
		uintptr(unsafe.Pointer(&handle)),
	); st != 0 {
		return "", fmt.Errorf("LsaOpenPolicy: NTSTATUS 0x%x", st)
	}
	defer procLsaClose.Call(handle)

	var info unsafe.Pointer
	if st, _, _ := procLsaQueryInfoPolicy.Call(
		handle,
		12, // PolicyDnsDomainInformation
		uintptr(unsafe.Pointer(&info)),
	); st != 0 {
		return "", fmt.Errorf("LsaQueryInformationPolicy: NTSTATUS 0x%x", st)
	}
	defer procLsaFreeMemory.Call(uintptr(info))

	if info == nil {
		return "", fmt.Errorf("no domain information returned")
	}

	// POLICY_DNS_DOMAIN_INFO layout on x64:
	//   Offset  0: Name          (LSA_UNICODE_STRING, 16 bytes)
	//   Offset 16: DnsDomainName (LSA_UNICODE_STRING, 16 bytes)
	// LSA_UNICODE_STRING: Length(2) MaxLen(2) [pad 4] Buffer*(8)
	dnsLen := *(*uint16)(unsafe.Add(info, 16))
	dnsBuf := *(*uintptr)(unsafe.Add(info, 24))
	if dnsLen == 0 || dnsBuf == 0 {
		return "", fmt.Errorf("machine is not domain-joined")
	}
	chars := unsafe.Slice((*uint16)(unsafe.Pointer(dnsBuf)), dnsLen/2)
	return syscall.UTF16ToString(chars), nil
}
