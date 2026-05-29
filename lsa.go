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
