// Package dnsmsg parses and builds DNS messages (RFC 1035) including name
// compression and the EDNS0 OPT pseudo-record (RFC 6891).
package dnsmsg

import (
	"fmt"
	"strconv"
)

// Type is an RR type.
type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeOPT   Type = 41
	TypeANY   Type = 255
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypeMX: "MX",
	TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT", TypeANY: "ANY",
}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType converts "A", "mx", "TYPE65" to a Type.
func ParseType(s string) (Type, error) {
	for t, n := range typeNames {
		if equalFoldASCII(n, s) {
			return t, nil
		}
	}
	if len(s) > 4 && equalFoldASCII(s[:4], "TYPE") {
		n, err := strconv.ParseUint(s[4:], 10, 16)
		if err == nil {
			return Type(n), nil
		}
	}
	return 0, fmt.Errorf("unknown RR type %q", s)
}

// Class is an RR class. Only IN is used in practice.
type Class uint16

const (
	ClassINET Class = 1
	ClassANY  Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassINET:
		return "IN"
	case ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// RCode is a response code (4 bits in the header, 12 bits with EDNS).
type RCode uint16

const (
	RCodeSuccess        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3 // NXDOMAIN
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
	RCodeBadVers        RCode = 16 // EDNS version not supported
)

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	case RCodeBadVers:
		return "BADVERS"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
