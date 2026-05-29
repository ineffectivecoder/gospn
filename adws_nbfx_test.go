//go:build windows
// +build windows

package main

import "testing"

// TestNBFXRoundTrip verifies that an NBFSE message produced by the encoder can
// be parsed back by the decoder with structure and text intact. (Dictionary
// reference resolution is exercised separately by live responses.)
func TestNBFXRoundTrip(t *testing.T) {
	filter := "(&(samAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
	baseDN := "DC=corp,DC=example,DC=com"
	msg := buildEnumerate("dc01.corp.example.com", filter, baseDN, adwsRoastAttrs, newUUID())

	root, err := decodeNBFSE(msg)
	if err != nil {
		t.Fatalf("decodeNBFSE failed: %v", err)
	}

	env := root.children
	if len(env) != 1 || env[0].name != "Envelope" || env[0].prefix != "s" {
		t.Fatalf("expected single s:Envelope root, got %+v", env)
	}

	if got := root.firstText("Filter"); got != filter {
		t.Errorf("Filter round-trip mismatch:\n have %q\n want %q", got, filter)
	}
	if got := root.firstText("BaseObject"); got != baseDN {
		t.Errorf("BaseObject mismatch: have %q want %q", got, baseDN)
	}
	if got := root.firstText("Scope"); got != "Subtree" {
		t.Errorf("Scope mismatch: have %q want Subtree", got)
	}
	if got := root.firstText("Action"); got != actionEnumerate {
		t.Errorf("Action mismatch: have %q want %q", got, actionEnumerate)
	}

	props := root.findAll("SelectionProperty")
	if len(props) != len(adwsRoastAttrs) {
		t.Fatalf("expected %d SelectionProperty elements, got %d", len(adwsRoastAttrs), len(props))
	}
	for i, p := range props {
		want := "addata:" + adwsRoastAttrs[i]
		if p.text != want {
			t.Errorf("SelectionProperty[%d] = %q, want %q", i, p.text, want)
		}
	}

	// mustUnderstand="1" must survive as an attribute on a:Action.
	var action *nbfxNode
	for _, n := range root.findAll("Action") {
		action = n
	}
	if action == nil || len(action.attrs) == 0 {
		t.Fatalf("a:Action lost its attributes")
	}
	found := false
	for _, a := range action.attrs {
		if a.name == "mustUnderstand" && a.value == "1" && a.prefix == "s" {
			found = true
		}
	}
	if !found {
		t.Errorf("s:mustUnderstand=\"1\" not preserved on a:Action: %+v", action.attrs)
	}
}

// TestMB31RoundTrip checks the MultiByteInt31 encode/decode across boundaries.
func TestMB31RoundTrip(t *testing.T) {
	for _, v := range []int{0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF} {
		b := mb31Bytes(v)
		got, n := decodeMB31(b)
		if got != v || n != len(b) {
			t.Errorf("mb31 round-trip for %d: got %d (n=%d, bytes=%d)", v, got, n, len(b))
		}
	}
}
