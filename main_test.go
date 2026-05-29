//go:build windows
// +build windows

package main

import (
	"reflect"
	"testing"
)

func TestNormalizeFlagArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"/rc4opsec"}, []string{"-rc4opsec"}},
		{[]string{"/method:adws"}, []string{"-method=adws"}},
		{[]string{"/spn:MSSQLSvc/db:1433"}, []string{"-spn=MSSQLSvc/db:1433"}}, // only first colon
		{[]string{"-method", "ldap", "/tgtdeleg"}, []string{"-method", "ldap", "-tgtdeleg"}},
		{[]string{"-user", "sg"}, []string{"-user", "sg"}}, // untouched
		{[]string{"/user:svc_sql"}, []string{"-user=svc_sql"}},
	}
	for _, c := range cases {
		got := normalizeFlagArgs(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("normalizeFlagArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
