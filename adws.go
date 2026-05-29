//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// ADWS namespaces and constants (mirroring SoaPy's soap_templates).
const (
	nsSOAP   = "http://www.w3.org/2003/05/soap-envelope"
	nsWSA    = "http://www.w3.org/2005/08/addressing"
	nsAD     = "http://schemas.microsoft.com/2008/1/ActiveDirectory"
	nsADData = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
	nsADLQ   = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"
	nsWSEN   = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	nsXSD    = "http://www.w3.org/2001/XMLSchema"
	nsXSI    = "http://www.w3.org/2001/XMLSchema-instance"

	dialectLdapQuery = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"
	dialectXPath1    = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"
	addrAnonymous    = "http://www.w3.org/2005/08/addressing/anonymous"

	actionEnumerate = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	actionPull      = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
)

// adwsRoastAttrs are the LDAP attributes GoSPN selects for each roastable user.
var adwsRoastAttrs = []string{
	"sAMAccountName",
	"servicePrincipalName",
	"distinguishedName",
	"pwdLastSet",
	"msDS-SupportedEncryptionTypes",
}

// searchRoastableUsersADWS enumerates roastable accounts over Active Directory
// Web Services (TCP 9389) using WS-Enumeration, mirroring the LDAP backend.
func searchRoastableUsersADWS(cfg *Config) ([]roastTarget, error) {
	spn := "HOST/" + cfg.DC
	// ADWS selects the directory instance via the <ad:instance> header: the
	// domain LDAP server ("ldap:389") or the forest-wide Global Catalog
	// ("gc:3268"). The GC search uses an empty base object to span all domains.
	baseDN := domainToBaseDN(cfg.Domain)
	instance := "ldap:389"
	if cfg.UseGC {
		instance = "gc:3268"
		baseDN = ""
	}
	filter := buildUserFilter(cfg)

	conn, err := dialADWS(cfg.DC, spn, "Windows/Enumeration")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 1. Enumerate: establish a result set and obtain its context token.
	if err := conn.sendEnvelope(buildEnumerate(cfg.DC, filter, baseDN, adwsRoastAttrs, newUUID(), instance)); err != nil {
		return nil, fmt.Errorf("sending ADWS Enumerate: %w", err)
	}
	respBytes, err := conn.recvEnvelope()
	if err != nil {
		return nil, fmt.Errorf("reading ADWS Enumerate response: %w", err)
	}
	root, err := decodeNBFSE(respBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding ADWS Enumerate response: %w", err)
	}
	if msg := soapFault(root); msg != "" {
		return nil, fmt.Errorf("ADWS Enumerate fault: %s", msg)
	}
	enumCtx := root.firstText("EnumerationContext")
	if enumCtx == "" {
		return nil, fmt.Errorf("ADWS Enumerate returned no EnumerationContext")
	}

	// 2. Pull repeatedly until the server signals EndOfSequence.
	var targets []roastTarget
	for i := 0; i < 1000; i++ {
		if err := conn.sendEnvelope(buildPull(cfg.DC, enumCtx, newUUID(), instance)); err != nil {
			return nil, fmt.Errorf("sending ADWS Pull: %w", err)
		}
		pullBytes, err := conn.recvEnvelope()
		if err != nil {
			return nil, fmt.Errorf("reading ADWS Pull response: %w", err)
		}
		proot, err := decodeNBFSE(pullBytes)
		if err != nil {
			return nil, fmt.Errorf("decoding ADWS Pull response: %w", err)
		}
		if msg := soapFault(proot); msg != "" {
			return nil, fmt.Errorf("ADWS Pull fault: %s", msg)
		}

		targets = append(targets, parseRoastItems(proot)...)

		if nc := proot.firstText("EnumerationContext"); nc != "" {
			enumCtx = nc
		}
		if len(proot.findAll("EndOfSequence")) > 0 || len(proot.findAll("Items")) == 0 {
			break
		}
	}
	return targets, nil
}

// parseRoastItems turns each enumerated object into a roastTarget.
func parseRoastItems(root *nbfxNode) []roastTarget {
	var out []roastTarget
	for _, items := range root.findAll("Items") {
		for _, obj := range items.children {
			t := objectToTarget(obj)
			if t.SPN != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func objectToTarget(obj *nbfxNode) roastTarget {
	return roastTarget{
		SAMAccountName:    firstAttrValue(obj, "sAMAccountName"),
		DistinguishedName: firstAttrValue(obj, "distinguishedName"),
		SPN:               firstAttrValue(obj, "servicePrincipalName"), // first SPN is enough
		PwdLastSet:        formatPwdLastSet(firstAttrValue(obj, "pwdLastSet")),
		SupportedETypes:   formatSupportedETypes(firstAttrValue(obj, "msDS-SupportedEncryptionTypes")),
	}
}

// firstAttrValue finds the named addata attribute element anywhere within the
// object subtree and returns its first value.
func firstAttrValue(obj *nbfxNode, name string) string {
	for _, a := range obj.findAll(name) {
		if vs := attrValues(a); len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// attrValues returns the ad:value text(s) under an addata attribute element.
func attrValues(attr *nbfxNode) []string {
	vnodes := attr.findAll("value")
	if len(vnodes) == 0 {
		if attr.text != "" {
			return []string{attr.text}
		}
		return nil
	}
	out := make([]string, 0, len(vnodes))
	for _, v := range vnodes {
		out = append(out, v.text)
	}
	return out
}

// soapFault returns the fault reason text if the response carries an s:Fault.
func soapFault(root *nbfxNode) string {
	if len(root.findAll("Fault")) == 0 {
		return ""
	}
	if r := root.firstText("Text"); r != "" {
		return r
	}
	if r := root.firstText("Reason"); r != "" {
		return r
	}
	return "unspecified SOAP fault"
}

// buildEnumerate builds the WS-Enumeration Enumerate request as NBFSE bytes.
func buildEnumerate(fqdn, filter, baseDN string, attrs []string, msgID, instance string) []byte {
	w := &nbfxWriter{}
	w.startElem("s", "Envelope")
	envelopeNamespaces(w)

	w.startElem("s", "Header")
	headerCommon(w, actionEnumerate, msgID, fqdn, instance)
	w.endElem() // Header

	w.startElem("s", "Body")
	w.xmlns("wsen", nsWSEN)
	w.xmlns("adlq", nsADLQ)
	w.startElem("wsen", "Enumerate")

	w.startElem("wsen", "Filter")
	w.attr("", "Dialect", dialectLdapQuery)
	w.startElem("adlq", "LdapQuery")
	w.startElem("adlq", "Filter")
	w.text(filter)
	w.endElem()
	w.startElem("adlq", "BaseObject")
	w.text(baseDN)
	w.endElem()
	w.startElem("adlq", "Scope")
	w.text("Subtree")
	w.endElem()
	w.endElem() // LdapQuery
	w.endElem() // Filter

	w.startElem("ad", "Selection")
	w.attr("", "Dialect", dialectXPath1)
	for _, a := range attrs {
		w.startElem("ad", "SelectionProperty")
		w.text("addata:" + a)
		w.endElem()
	}
	w.endElem() // Selection

	w.endElem() // Enumerate
	w.endElem() // Body
	w.endElem() // Envelope
	return w.encodeNBFSE()
}

// buildPull builds the WS-Enumeration Pull request as NBFSE bytes.
func buildPull(fqdn, enumCtx, msgID, instance string) []byte {
	w := &nbfxWriter{}
	w.startElem("s", "Envelope")
	envelopeNamespaces(w)

	w.startElem("s", "Header")
	headerCommon(w, actionPull, msgID, fqdn, instance)
	w.endElem()

	w.startElem("s", "Body")
	w.xmlns("wsen", nsWSEN)
	w.startElem("wsen", "Pull")
	w.startElem("wsen", "EnumerationContext")
	w.text(enumCtx)
	w.endElem()
	w.startElem("wsen", "MaxElements")
	w.text("256")
	w.endElem()
	w.endElem() // Pull
	w.endElem() // Body
	w.endElem() // Envelope
	return w.encodeNBFSE()
}

func envelopeNamespaces(w *nbfxWriter) {
	w.xmlns("s", nsSOAP)
	w.xmlns("a", nsWSA)
	w.xmlns("addata", nsADData)
	w.xmlns("ad", nsAD)
	w.xmlns("xsd", nsXSD)
	w.xmlns("xsi", nsXSI)
}

func headerCommon(w *nbfxWriter, action, msgID, fqdn, instance string) {
	w.startElem("a", "Action")
	w.attr("s", "mustUnderstand", "1")
	w.text(action)
	w.endElem()

	w.startElem("ad", "instance")
	w.text(instance)
	w.endElem()

	w.startElem("a", "MessageID")
	w.text("urn:uuid:" + msgID)
	w.endElem()

	w.startElem("a", "ReplyTo")
	w.startElem("a", "Address")
	w.text(addrAnonymous)
	w.endElem()
	w.endElem()

	w.startElem("a", "To")
	w.attr("s", "mustUnderstand", "1")
	w.text(fmt.Sprintf("net.tcp://%s:9389/ActiveDirectoryWebServices/Windows/Enumeration", fqdn))
	w.endElem()
}

// domainToBaseDN turns "corp.example.com" into "DC=corp,DC=example,DC=com".
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
