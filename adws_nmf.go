//go:build windows
// +build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
)

// adwsConn drives the .NET Message Framing Protocol ([MC-NMF]) over a TCP
// connection to ADWS (TCP 9389), upgraded to an authenticated, sealed channel
// via the .NET NegotiateStream Protocol ([MC-NNS]). Authentication uses the
// current logon session through Windows SSPI Negotiate (SPNEGO -> Kerberos), so
// no credentials are required.
type adwsConn struct {
	conn   net.Conn
	ctx    *negotiate.ClientContext
	sealed bool
}

// NMF record type bytes ([MC-NMF] 2.2.1).
const (
	nmfVersion        = 0x00
	nmfMode           = 0x01
	nmfVia            = 0x02
	nmfKnownEncoding  = 0x03
	nmfSizedEnvelope  = 0x06
	nmfEnd            = 0x07
	nmfFault          = 0x08
	nmfUpgradeRequest = 0x09
	nmfUpgradeResp    = 0x0A
	nmfPreambleAck    = 0x0B
	nmfPreambleEnd    = 0x0C

	nmfModeDuplex      = 0x02
	nmfEncodingNBFSE   = 0x08 // SOAP 1.2 binary with in-band dictionary
	nnsInProgress byte = 0x16
	nnsError      byte = 0x15
	nnsDone       byte = 0x14
)

// adwsReqFlags requests a mutually authenticated, sealed, sequenced context.
const adwsReqFlags = sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_INTEGRITY |
	sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_CONNECTION |
	sspi.ISC_REQ_REPLAY_DETECT | sspi.ISC_REQ_SEQUENCE_DETECT

// dialADWS connects to the DC's ADWS endpoint, negotiates the NMF preamble,
// upgrades to a sealed NegotiateStream, and is then ready to exchange SOAP.
func dialADWS(fqdn, spn, resource string) (*adwsConn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(fqdn, "9389"), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to ADWS on %s:9389: %w", fqdn, err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	c := &adwsConn{conn: conn}

	via := fmt.Sprintf("net.tcp://%s:9389/ActiveDirectoryWebServices/%s", fqdn, resource)
	if err := c.sendPreamble(via); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.upgrade(spn); err != nil {
		conn.Close()
		return nil, err
	}
	// Preamble end + ack are exchanged over the now-sealed channel.
	if err := c.writeFramed([]byte{nmfPreambleEnd}); err != nil {
		conn.Close()
		return nil, err
	}
	ack, err := c.readFramed()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(ack) == 0 || ack[0] != nmfPreambleAck {
		conn.Close()
		return nil, fmt.Errorf("expected preamble ack, got record 0x%02x", firstByte(ack))
	}
	return c, nil
}

func (c *adwsConn) Close() error {
	// Best-effort polite close.
	_ = c.writeFramed([]byte{nmfEnd})
	return c.conn.Close()
}

// sendPreamble writes Version, Mode, Via and KnownEncoding records (raw).
func (c *adwsConn) sendPreamble(via string) error {
	var pre []byte
	pre = append(pre, nmfVersion, 0x01, 0x00) // version 1.0
	pre = append(pre, nmfMode, nmfModeDuplex)
	pre = append(pre, nmfVia)
	pre = append(pre, mb31Bytes(len(via))...)
	pre = append(pre, []byte(via)...)
	pre = append(pre, nmfKnownEncoding, nmfEncodingNBFSE)
	_, err := c.conn.Write(pre)
	return err
}

// upgrade requests the NegotiateStream upgrade and performs the SSPI handshake.
func (c *adwsConn) upgrade(spn string) error {
	proto := "application/negotiate"
	req := []byte{nmfUpgradeRequest}
	req = append(req, mb31Bytes(len(proto))...)
	req = append(req, []byte(proto)...)
	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		return fmt.Errorf("reading upgrade response: %w", err)
	}
	if resp[0] == nmfFault {
		return fmt.Errorf("server faulted on upgrade request")
	}
	if resp[0] != nmfUpgradeResp {
		return fmt.Errorf("expected upgrade response, got record 0x%02x", resp[0])
	}

	if err := c.handshake(spn); err != nil {
		return err
	}
	c.sealed = true
	return nil
}

// handshake runs the SSPI Negotiate token exchange inside NNS handshake frames.
func (c *adwsConn) handshake(spn string) error {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return fmt.Errorf("acquiring Negotiate credentials: %w", err)
	}
	defer cred.Release()

	ctx, token, err := negotiate.NewClientContextWithFlags(cred, spn, adwsReqFlags)
	if err != nil {
		return fmt.Errorf("initializing Negotiate context for %q: %w", spn, err)
	}
	c.ctx = ctx

	if err := c.sendHandshake(nnsInProgress, token); err != nil {
		return err
	}

	for {
		msgID, payload, err := c.recvHandshake()
		if err != nil {
			return err
		}
		if msgID == nnsError {
			return fmt.Errorf("NegotiateStream auth failed (server error 0x%x)", payload)
		}
		if len(payload) > 0 {
			done, out, err := ctx.Update(payload)
			if err != nil {
				return fmt.Errorf("advancing Negotiate context: %w", err)
			}
			if len(out) > 0 {
				if err := c.sendHandshake(nnsInProgress, out); err != nil {
					return err
				}
			}
			_ = done
		}
		if msgID == nnsDone {
			return nil
		}
	}
}

func (c *adwsConn) sendHandshake(msgID byte, payload []byte) error {
	hdr := []byte{msgID, 0x01, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(payload)))
	if _, err := c.conn.Write(append(hdr, payload...)); err != nil {
		return fmt.Errorf("sending handshake frame: %w", err)
	}
	return nil
}

func (c *adwsConn) recvHandshake() (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, hdr); err != nil {
		return 0, nil, fmt.Errorf("reading handshake header: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[3:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, nil, fmt.Errorf("reading handshake payload: %w", err)
	}
	return hdr[0], payload, nil
}

// sendEnvelope encodes the NBFSE payload, wraps it in a SizedEnvelope record,
// and writes it over the sealed channel.
func (c *adwsConn) sendEnvelope(payload []byte) error {
	rec := []byte{nmfSizedEnvelope}
	rec = append(rec, mb31Bytes(len(payload))...)
	rec = append(rec, payload...)
	return c.writeFramed(rec)
}

// recvEnvelope reads a SizedEnvelope record and returns its NBFSE payload.
func (c *adwsConn) recvEnvelope() ([]byte, error) {
	rec, err := c.readFramed()
	if err != nil {
		return nil, err
	}
	if len(rec) == 0 {
		return nil, fmt.Errorf("empty NMF record")
	}
	if rec[0] == nmfFault {
		return nil, fmt.Errorf("server returned an NMF fault")
	}
	if rec[0] != nmfSizedEnvelope {
		return nil, fmt.Errorf("expected sized envelope, got record 0x%02x", rec[0])
	}
	size, n := decodeMB31(rec[1:])
	start := 1 + n
	if start+size > len(rec) {
		return nil, fmt.Errorf("sized envelope truncated (want %d, have %d)", size, len(rec)-start)
	}
	return rec[start : start+size], nil
}

// writeFramed writes one NMF record, sealing it if the channel is upgraded.
func (c *adwsConn) writeFramed(rec []byte) error {
	if !c.sealed {
		_, err := c.conn.Write(rec)
		return err
	}
	sealed, err := c.ctx.EncryptMessage(append([]byte(nil), rec...), 0, 0)
	if err != nil {
		return fmt.Errorf("sealing record: %w", err)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(sealed)))
	if _, err := c.conn.Write(append(hdr[:], sealed...)); err != nil {
		return err
	}
	return nil
}

// readFramed reads one NMF record. When sealed it reassembles a SizedEnvelope
// that the NNS layer may have split across multiple data packets.
func (c *adwsConn) readFramed() ([]byte, error) {
	if !c.sealed {
		buf := make([]byte, 65536)
		n, err := c.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}

	rec, err := c.readSealedPacket()
	if err != nil {
		return nil, err
	}
	if len(rec) == 0 || rec[0] != nmfSizedEnvelope {
		return rec, nil // control records (ack/fault) arrive whole
	}

	size, n := decodeMB31(rec[1:])
	have := len(rec) - (1 + n)
	for have < size {
		more, err := c.readSealedPacket()
		if err != nil {
			return nil, err
		}
		rec = append(rec, more...)
		have += len(more)
	}
	return rec, nil
}

// readSealedPacket reads and unseals one NNS data packet.
func (c *adwsConn) readSealedPacket() ([]byte, error) {
	var sz [4]byte
	if _, err := io.ReadFull(c.conn, sz[:]); err != nil {
		return nil, fmt.Errorf("reading NNS data length: %w", err)
	}
	n := binary.LittleEndian.Uint32(sz[:])
	if n == 0 || n > 16<<20 {
		return nil, fmt.Errorf("implausible NNS data length %d", n)
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(c.conn, blob); err != nil {
		return nil, fmt.Errorf("reading NNS data body: %w", err)
	}
	_, plain, err := c.ctx.DecryptMessage(blob, 0)
	if err != nil {
		return nil, fmt.Errorf("unsealing NNS data: %w", err)
	}
	return plain, nil
}

// mb31Bytes encodes a non-negative int as an NMF/NBFX MultiByteInt31.
func mb31Bytes(v int) []byte {
	const max = 0x7F
	var out []byte
	for i := 0; i < 5; i++ {
		b := byte(v & max)
		v >>= 7
		if v != 0 {
			b |= max + 1
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// decodeMB31 decodes a MultiByteInt31 and returns the value and bytes consumed.
func decodeMB31(b []byte) (int, int) {
	const max = 0x7F
	value, n := 0, 0
	for i := 0; i < 5 && i < len(b); i++ {
		n++
		value |= int(b[i]&max) << (7 * i)
		if b[i]&(max+1) == 0 {
			break
		}
	}
	return value, n
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
