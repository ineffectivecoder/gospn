//go:build windows
// +build windows

package main

import "fmt"

// banner is the GoSPN logo: a clean figlet "GoSPN" wordmark with a flame motif,
// echoing gospn.jpg (a Go gopher roasting an SPN ticket over a Kerberos fire).
const banner = "" +
	"\r\n" +
	"   ____      ____  ____  _   _\r\n" +
	"  / ___| ___/ ___||  _ \\| \\ | |        ( (        [ $krb5tgs$ ]\r\n" +
	" | |  _ / _ \\___ \\| |_) |  \\| |       ) ) )\r\n" +
	" | |_| | (_) |__) |  __/| |\\  |       ( ( (   roast SPNs over the fire\r\n" +
	"  \\____|\\___/____/|_|   |_| \\_|      __)_)_)__\r\n" +
	"                                     \\_______/   Kerberoasting Tool\r\n"

// printBanner writes the GoSPN logo and the action line.
func printBanner() {
	fmt.Print(banner)
	fmt.Print("\r\n[*] Action: Kerberoasting (current logon session)\r\n\r\n")
}
