//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// This file implements just enough of the .NET binary XML formats to drive ADWS:
//
//	[MC-NBFX]  .NET Binary Format: XML Data Structure
//	[MC-NBFS]  .NET Binary Format: SOAP Data Structure
//	[MC-NBFSE] .NET Binary Format: SOAP Extension (in-band string dictionary)
//
// It is ported from the SoaPy reference implementation. Encoding is done with
// inline strings only (we never emit dictionary references for our own
// requests, and send an empty in-band dictionary). Decoding resolves dictionary
// references against the static dictionary below plus the per-message in-band
// dictionary the server prepends.

// ---------------------------------------------------------------------------
// MultiByteInt31 / UTF-8 string primitives ([MC-NBFX] 2.1)
// ---------------------------------------------------------------------------

func putMB31(buf *bytes.Buffer, v int) {
	const max = 0x7F
	for i := 0; i < 5; i++ {
		b := byte(v & max)
		v >>= 7
		if v != 0 {
			b |= max + 1
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

func putString(buf *bytes.Buffer, s string) {
	putMB31(buf, len(s))
	buf.WriteString(s)
}

// nbfxReader is a cursor over a decoded NBFX record stream.
type nbfxReader struct {
	b   []byte
	pos int
}

func (r *nbfxReader) eof() bool   { return r.pos >= len(r.b) }
func (r *nbfxReader) byteAt() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, fmt.Errorf("nbfx: unexpected end of stream")
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

func (r *nbfxReader) readN(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, fmt.Errorf("nbfx: short read of %d bytes at %d/%d", n, r.pos, len(r.b))
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *nbfxReader) mb31() (int, error) {
	const max = 0x7F
	value := 0
	for i := 0; i < 5; i++ {
		c, err := r.byteAt()
		if err != nil {
			return 0, err
		}
		value |= int(c&max) << (7 * i)
		if c&(max+1) == 0 {
			break
		}
	}
	return value, nil
}

func (r *nbfxReader) str() (string, error) {
	n, err := r.mb31()
	if err != nil {
		return "", err
	}
	b, err := r.readN(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------------------------------------------------------------------------
// Encoder: build a SOAP message as an NBFX record stream (inline strings only).
// ---------------------------------------------------------------------------

type nbfxWriter struct{ buf bytes.Buffer }

// startElem writes an element start. An empty prefix uses ShortElement (0x40).
func (w *nbfxWriter) startElem(prefix, name string) {
	if prefix == "" {
		w.buf.WriteByte(0x40)
		putString(&w.buf, name)
		return
	}
	w.buf.WriteByte(0x41)
	putString(&w.buf, prefix)
	putString(&w.buf, name)
}

func (w *nbfxWriter) endElem() { w.buf.WriteByte(0x01) }

// xmlns writes a namespace declaration. Empty prefix => default xmlns.
func (w *nbfxWriter) xmlns(prefix, uri string) {
	if prefix == "" {
		w.buf.WriteByte(0x08)
		putString(&w.buf, uri)
		return
	}
	w.buf.WriteByte(0x09)
	putString(&w.buf, prefix)
	putString(&w.buf, uri)
}

// attr writes an attribute. Empty prefix uses ShortAttribute (0x04).
func (w *nbfxWriter) attr(prefix, name, value string) {
	if prefix == "" {
		w.buf.WriteByte(0x04)
		putString(&w.buf, name)
	} else {
		w.buf.WriteByte(0x05)
		putString(&w.buf, prefix)
		putString(&w.buf, name)
	}
	w.value(value)
}

// value writes a text/value record, special-casing the canonical booleans.
func (w *nbfxWriter) value(s string) {
	switch s {
	case "0":
		w.buf.WriteByte(0x80)
		return
	case "1":
		w.buf.WriteByte(0x82)
		return
	case "false":
		w.buf.WriteByte(0x84)
		return
	case "true":
		w.buf.WriteByte(0x86)
		return
	}
	data := []byte(s)
	switch {
	case len(data) < 0x100:
		w.buf.WriteByte(0x98) // Chars8
		w.buf.WriteByte(byte(len(data)))
	case len(data) < 0x10000:
		w.buf.WriteByte(0x9A) // Chars16
		var l [2]byte
		binary.LittleEndian.PutUint16(l[:], uint16(len(data)))
		w.buf.Write(l[:])
	default:
		w.buf.WriteByte(0x9C) // Chars32
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(data)))
		w.buf.Write(l[:])
	}
	w.buf.Write(data)
}

// text writes element text content.
func (w *nbfxWriter) text(s string) { w.value(s) }

// encodeNBFSE wraps the record stream with an empty in-band dictionary, the
// form ADWS accepts ([MC-NBFSE] with a zero-length string table).
func (w *nbfxWriter) encodeNBFSE() []byte {
	out := make([]byte, 0, w.buf.Len()+1)
	out = append(out, 0x00) // empty in-band dictionary (size 0)
	return append(out, w.buf.Bytes()...)
}

// ---------------------------------------------------------------------------
// Decoder: parse an NBFSE message into a lightweight element tree.
// ---------------------------------------------------------------------------

type nbfxAttr struct {
	prefix string
	name   string
	value  string
}

type nbfxNode struct {
	prefix   string
	name     string
	attrs    []nbfxAttr
	text     string
	children []*nbfxNode
}

// decodeNBFSE parses a complete NBFSE message (in-band dictionary + records).
func decodeNBFSE(data []byte) (*nbfxNode, error) {
	r := &nbfxReader{b: data}

	dictSize, err := r.mb31()
	if err != nil {
		return nil, fmt.Errorf("reading in-band dictionary size: %w", err)
	}
	dictBytes, err := r.readN(dictSize)
	if err != nil {
		return nil, fmt.Errorf("reading in-band dictionary: %w", err)
	}
	session, err := parseInbandDict(dictBytes)
	if err != nil {
		return nil, err
	}

	d := &nbfxDecoder{r: r, session: session}
	root := &nbfxNode{name: "#root"}
	if err := d.parseRecords(root); err != nil {
		return nil, err
	}
	return root, nil
}

func parseInbandDict(b []byte) ([]string, error) {
	r := &nbfxReader{b: b}
	var words []string
	for !r.eof() {
		s, err := r.str()
		if err != nil {
			return nil, fmt.Errorf("parsing in-band dictionary entry: %w", err)
		}
		words = append(words, s)
	}
	return words, nil
}

type nbfxDecoder struct {
	r       *nbfxReader
	session []string
}

// resolveDict maps a dictionary index to its string. Even indices are static
// dictionary entries; odd indices are in-band/session entries ([MC-NBFSE]).
func (d *nbfxDecoder) resolveDict(idx int) string {
	if idx%2 == 0 {
		if s, ok := nbfxStaticDict[idx]; ok {
			return s
		}
		return fmt.Sprintf("[[static_0x%x]]", idx)
	}
	sIdx := (idx - 1) / 2
	if sIdx < len(d.session) {
		return d.session[sIdx]
	}
	return fmt.Sprintf("[[session_%d]]", sIdx)
}

// parseRecords consumes records as children of parent until the stream ends or
// parent's matching EndElement is read.
func (d *nbfxDecoder) parseRecords(parent *nbfxNode) error {
	stack := []*nbfxNode{parent}
	cur := func() *nbfxNode { return stack[len(stack)-1] }

	for !d.r.eof() {
		t, err := d.r.byteAt()
		if err != nil {
			return err
		}

		switch {
		case t == 0x01: // EndElement
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case t == 0x02: // Comment
			if _, err := d.r.str(); err != nil {
				return err
			}
		case t >= 0x80: // value/text record (odd => with-end-element)
			withEnd := t%2 == 1
			vt := t
			if withEnd {
				vt = t - 1
			}
			s, err := d.parseValue(vt)
			if err != nil {
				return err
			}
			cur().text += s
			if withEnd && len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case t >= 0x40 && t <= 0x77: // element
			el, err := d.parseElement(t)
			if err != nil {
				return err
			}
			cur().children = append(cur().children, el)
			stack = append(stack, el)
		case t >= 0x04 && t <= 0x3F: // attribute
			a, err := d.parseAttr(t)
			if err != nil {
				return err
			}
			cur().attrs = append(cur().attrs, a)
		default:
			return fmt.Errorf("nbfx: unsupported record type 0x%02x at %d", t, d.r.pos-1)
		}
	}
	return nil
}

func (d *nbfxDecoder) parseElement(t byte) (*nbfxNode, error) {
	n := &nbfxNode{}
	switch {
	case t == 0x40: // ShortElement
		name, err := d.r.str()
		if err != nil {
			return nil, err
		}
		n.name = name
	case t == 0x41: // Element (prefix, name)
		p, err := d.r.str()
		if err != nil {
			return nil, err
		}
		name, err := d.r.str()
		if err != nil {
			return nil, err
		}
		n.prefix, n.name = p, name
	case t == 0x42: // ShortDictionaryElement
		idx, err := d.r.mb31()
		if err != nil {
			return nil, err
		}
		n.name = d.resolveDict(idx)
	case t == 0x43: // DictionaryElement (prefix, idx)
		p, err := d.r.str()
		if err != nil {
			return nil, err
		}
		idx, err := d.r.mb31()
		if err != nil {
			return nil, err
		}
		n.prefix, n.name = p, d.resolveDict(idx)
	case t >= 0x44 && t <= 0x5D: // PrefixDictionaryElement[a-z]
		idx, err := d.r.mb31()
		if err != nil {
			return nil, err
		}
		n.prefix = string(rune('a' + int(t) - 0x44))
		n.name = d.resolveDict(idx)
	case t >= 0x5E && t <= 0x77: // PrefixElement[a-z]
		name, err := d.r.str()
		if err != nil {
			return nil, err
		}
		n.prefix = string(rune('a' + int(t) - 0x5E))
		n.name = name
	default:
		return nil, fmt.Errorf("nbfx: bad element type 0x%02x", t)
	}
	return n, nil
}

func (d *nbfxDecoder) parseAttr(t byte) (nbfxAttr, error) {
	var a nbfxAttr
	readVal := func() (string, error) {
		vt, err := d.r.byteAt()
		if err != nil {
			return "", err
		}
		if vt%2 == 1 { // tolerate a with-end marker on an attribute value
			vt--
		}
		return d.parseValue(vt)
	}
	switch {
	case t == 0x04: // ShortAttribute
		name, err := d.r.str()
		if err != nil {
			return a, err
		}
		a.name = name
		a.value, err = readVal()
		return a, err
	case t == 0x05: // Attribute
		p, err := d.r.str()
		if err != nil {
			return a, err
		}
		name, err := d.r.str()
		if err != nil {
			return a, err
		}
		a.prefix, a.name = p, name
		a.value, err = readVal()
		return a, err
	case t == 0x06: // ShortDictionaryAttribute
		idx, err := d.r.mb31()
		if err != nil {
			return a, err
		}
		a.name = d.resolveDict(idx)
		a.value, err = readVal()
		return a, err
	case t == 0x07: // DictionaryAttribute
		p, err := d.r.str()
		if err != nil {
			return a, err
		}
		idx, err := d.r.mb31()
		if err != nil {
			return a, err
		}
		a.prefix, a.name = p, d.resolveDict(idx)
		a.value, err = readVal()
		return a, err
	case t == 0x08: // ShortXmlnsAttribute
		uri, err := d.r.str()
		if err != nil {
			return a, err
		}
		a.name, a.value = "xmlns", uri
		return a, nil
	case t == 0x09: // XmlnsAttribute
		p, err := d.r.str()
		if err != nil {
			return a, err
		}
		uri, err := d.r.str()
		if err != nil {
			return a, err
		}
		a.name, a.value = "xmlns:"+p, uri
		return a, nil
	case t == 0x0A: // ShortDictionaryXmlnsAttribute
		idx, err := d.r.mb31()
		if err != nil {
			return a, err
		}
		a.name, a.value = "xmlns", d.resolveDict(idx)
		return a, nil
	case t == 0x0B: // DictionaryXmlnsAttribute
		p, err := d.r.str()
		if err != nil {
			return a, err
		}
		idx, err := d.r.mb31()
		if err != nil {
			return a, err
		}
		a.name, a.value = "xmlns:"+p, d.resolveDict(idx)
		return a, nil
	case t >= 0x0C && t <= 0x25: // PrefixDictionaryAttribute[a-z]
		idx, err := d.r.mb31()
		if err != nil {
			return a, err
		}
		a.prefix = string(rune('a' + int(t) - 0x0C))
		a.name = d.resolveDict(idx)
		a.value, err = readVal()
		return a, err
	case t >= 0x26 && t <= 0x3F: // PrefixAttribute[a-z]
		name, err := d.r.str()
		if err != nil {
			return a, err
		}
		a.prefix = string(rune('a' + int(t) - 0x26))
		a.name = name
		a.value, err = readVal()
		return a, err
	}
	return a, fmt.Errorf("nbfx: bad attribute type 0x%02x", t)
}

// parseValue reads a value record body (vt is the even/base type code) and
// returns its string form.
func (d *nbfxDecoder) parseValue(vt byte) (string, error) {
	switch vt {
	case 0x80:
		return "0", nil
	case 0x82:
		return "1", nil
	case 0x84:
		return "false", nil
	case 0x86:
		return "true", nil
	case 0x88: // Int8
		b, err := d.r.readN(1)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(int(int8(b[0]))), nil
	case 0x8A: // Int16
		b, err := d.r.readN(2)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(int(int16(binary.LittleEndian.Uint16(b)))), nil
	case 0x8C: // Int32
		b, err := d.r.readN(4)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(b))), 10), nil
	case 0x8E: // Int64
		b, err := d.r.readN(8)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(b)), 10), nil
	case 0xB2: // UInt64
		b, err := d.r.readN(8)
		if err != nil {
			return "", err
		}
		return strconv.FormatUint(binary.LittleEndian.Uint64(b), 10), nil
	case 0x90: // Float
		b, err := d.r.readN(4)
		if err != nil {
			return "", err
		}
		return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 'g', -1, 32), nil
	case 0x92: // Double
		b, err := d.r.readN(8)
		if err != nil {
			return "", err
		}
		return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(b)), 'g', -1, 64), nil
	case 0x96: // DateTime
		b, err := d.r.readN(8)
		if err != nil {
			return "", err
		}
		v := binary.LittleEndian.Uint64(b)
		ticks := int64(v & 0x3FFFFFFFFFFFFFFF) // strip the 2 tz bits
		return strconv.FormatInt(ticks, 10), nil
	case 0x98: // Chars8
		return d.charsN(1)
	case 0x9A: // Chars16
		return d.charsN(2)
	case 0x9C: // Chars32
		return d.charsN(4)
	case 0x9E: // Bytes8
		return d.bytesN(1)
	case 0xA0: // Bytes16
		return d.bytesN(2)
	case 0xA2: // Bytes32
		return d.bytesN(4)
	case 0xA8: // EmptyText
		return "", nil
	case 0xAA: // DictionaryText
		idx, err := d.r.mb31()
		if err != nil {
			return "", err
		}
		return d.resolveDict(idx), nil
	case 0xAC, 0xB0: // UniqueId / Uuid
		b, err := d.r.readN(16)
		if err != nil {
			return "", err
		}
		return formatGUID(b, vt == 0xAC), nil
	case 0xB4: // Bool
		b, err := d.r.readN(1)
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			return "false", nil
		}
		return "true", nil
	case 0xBC: // QNameDictionary
		pb, err := d.r.byteAt()
		if err != nil {
			return "", err
		}
		idx, err := d.r.mb31()
		if err != nil {
			return "", err
		}
		return string(rune('a'+int(pb))) + ":" + d.resolveDict(idx), nil
	}
	return "", fmt.Errorf("nbfx: unsupported value record 0x%02x at %d", vt, d.r.pos-1)
}

func (d *nbfxDecoder) charsN(n int) (string, error) {
	l, err := d.readLen(n)
	if err != nil {
		return "", err
	}
	b, err := d.r.readN(l)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (d *nbfxDecoder) bytesN(n int) (string, error) {
	l, err := d.readLen(n)
	if err != nil {
		return "", err
	}
	b, err := d.r.readN(l)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (d *nbfxDecoder) readLen(n int) (int, error) {
	b, err := d.r.readN(n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return int(b[0]), nil
	case 2:
		return int(binary.LittleEndian.Uint16(b)), nil
	default:
		return int(binary.LittleEndian.Uint32(b)), nil
	}
}

func formatGUID(b []byte, urn bool) string {
	g := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
	if urn {
		return "urn:uuid:" + g
	}
	return g
}

// ---------------------------------------------------------------------------
// tree helpers used by the ADWS enumeration code
// ---------------------------------------------------------------------------

// findAll returns every descendant element with the given local name.
func (n *nbfxNode) findAll(local string) []*nbfxNode {
	var out []*nbfxNode
	var walk func(node *nbfxNode)
	walk = func(node *nbfxNode) {
		for _, c := range node.children {
			if c.name == local {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(n)
	return out
}

// firstText returns the text of the first descendant with the given local name
// that actually has text content, or "" if none. Preferring non-empty matches
// avoids structural wrapper elements that share a local name with a leaf (e.g.
// wsen:Filter vs adlq:Filter).
func (n *nbfxNode) firstText(local string) string {
	for _, c := range n.findAll(local) {
		if c.text != "" {
			return c.text
		}
	}
	return ""
}
