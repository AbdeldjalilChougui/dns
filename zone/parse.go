// Package zone reads RFC 1035 master (zone) files and answers queries
// authoritatively from them.
package zone

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
)

// Supported syntax (a practical subset of RFC 1035 §5.1):
//
//	$ORIGIN example.com.
//	$TTL 1h
//	@       IN SOA ns1 hostmaster ( 2024010101 7200 900 1209600 300 )
//	        IN NS  ns1
//	www  300 IN A 192.0.2.1          ; owner, ttl and class in either order
//	     IN AAAA 2001:db8::1         ; blank owner = previous owner
//	@       MX 10 mail
//	@       TXT "v=spf1 -all" "two strings"
//
// Names without a trailing dot are relative to $ORIGIN; "@" is the origin.
// TTLs accept BIND units (s m h d w), e.g. 1h30m.

type token struct {
	text   string
	quoted bool
}

type entry struct {
	line     int
	blankOwn bool // the entry started with whitespace
	toks     []token
}

// lex splits the input into logical entries, joining parenthesised lines
// and dropping comments.
func lex(r io.Reader) ([]entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []entry
	var cur *entry
	depth := 0
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if depth == 0 {
			if cur != nil && len(cur.toks) > 0 {
				out = append(out, *cur)
			}
			cur = &entry{line: lineNo, blankOwn: len(line) > 0 && (line[0] == ' ' || line[0] == '\t')}
		}
		for i := 0; i < len(line); {
			c := line[i]
			switch {
			case c == ';':
				i = len(line)
			case c == ' ' || c == '\t' || c == '\r':
				i++
			case c == '(':
				depth++
				i++
			case c == ')':
				if depth == 0 {
					return nil, fmt.Errorf("line %d: unbalanced ')'", lineNo)
				}
				depth--
				i++
			case c == '"':
				var sb strings.Builder
				i++
				closed := false
				for i < len(line) {
					if line[i] == '\\' && i+1 < len(line) {
						sb.WriteByte(line[i+1])
						i += 2
						continue
					}
					if line[i] == '"' {
						closed = true
						i++
						break
					}
					sb.WriteByte(line[i])
					i++
				}
				if !closed {
					return nil, fmt.Errorf("line %d: unterminated string", lineNo)
				}
				cur.toks = append(cur.toks, token{sb.String(), true})
			default:
				j := i
				for j < len(line) && !strings.ContainsRune(" \t\r;()\"", rune(line[j])) {
					j++
				}
				cur.toks = append(cur.toks, token{line[i:j], false})
				i = j
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced '(' at end of file")
	}
	if cur != nil && len(cur.toks) > 0 {
		out = append(out, *cur)
	}
	return out, nil
}

// ParseTTL parses "3600", "1h", "1h30m", "2d".
func ParseTTL(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	var total, num uint64
	digits := false
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if s[i] >= '0' && s[i] <= '9' {
			num = num*10 + uint64(s[i]-'0')
			digits = true
			continue
		}
		mult := map[byte]uint64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[c]
		if mult == 0 || !digits {
			return 0, fmt.Errorf("bad TTL %q", s)
		}
		total += num * mult
		num, digits = 0, false
	}
	if s == "" || digits || total > 0x7FFFFFFF {
		return 0, fmt.Errorf("bad TTL %q", s)
	}
	return uint32(total), nil
}

func isTTL(s string) bool {
	_, err := ParseTTL(s)
	return err == nil && s != "" && s[0] >= '0' && s[0] <= '9'
}

// Parse reads a zone file. origin is used until a $ORIGIN line changes it.
func Parse(r io.Reader, origin string) (*Zone, error) {
	entries, err := lex(r)
	if err != nil {
		return nil, err
	}
	origin = dnsmsg.CanonicalName(origin)
	var defTTL uint32 = 3600
	haveDefTTL := false
	prevOwner := ""
	var records []dnsmsg.RR

	abs := func(name string) string {
		if name == "@" {
			return origin
		}
		if strings.HasSuffix(name, ".") && !strings.HasSuffix(name, `\.`) {
			return dnsmsg.CanonicalName(name)
		}
		if origin == "." {
			return dnsmsg.CanonicalName(name + ".")
		}
		return dnsmsg.CanonicalName(name + "." + origin)
	}

	for _, e := range entries {
		fail := func(f string, a ...any) error {
			return fmt.Errorf("line %d: %s", e.line, fmt.Sprintf(f, a...))
		}
		t := e.toks
		switch strings.ToUpper(t[0].text) {
		case "$ORIGIN":
			if len(t) != 2 {
				return nil, fail("$ORIGIN needs one name")
			}
			origin = abs(t[1].text)
			continue
		case "$TTL":
			if len(t) != 2 {
				return nil, fail("$TTL needs one value")
			}
			if defTTL, err = ParseTTL(t[1].text); err != nil {
				return nil, fail("%v", err)
			}
			haveDefTTL = true
			continue
		case "$INCLUDE":
			return nil, fail("$INCLUDE is not supported")
		}

		owner := prevOwner
		if !e.blankOwn {
			owner = abs(t[0].text)
			t = t[1:]
		}
		if owner == "" {
			return nil, fail("no owner name")
		}
		prevOwner = owner

		ttl, ttlSet := defTTL, false
		// TTL and class may come in either order before the type.
		for len(t) > 0 {
			up := strings.ToUpper(t[0].text)
			if up == "IN" {
				t = t[1:]
				continue
			}
			if up == "CH" || up == "HS" || up == "CS" {
				return nil, fail("only class IN is supported")
			}
			if isTTL(t[0].text) {
				if ttl, err = ParseTTL(t[0].text); err != nil {
					return nil, fail("%v", err)
				}
				ttlSet = true
				t = t[1:]
				continue
			}
			break
		}
		if len(t) == 0 {
			return nil, fail("missing record type")
		}
		typ, err := dnsmsg.ParseType(t[0].text)
		if err != nil {
			return nil, fail("%v", err)
		}
		args := t[1:]
		rr := dnsmsg.RR{Name: owner, Type: typ, Class: dnsmsg.ClassINET, TTL: ttl}
		need := func(n int) error {
			if len(args) != n {
				return fail("%s needs %d fields, got %d", typ, n, len(args))
			}
			return nil
		}
		switch typ {
		case dnsmsg.TypeA, dnsmsg.TypeAAAA:
			if err := need(1); err != nil {
				return nil, err
			}
			ip, err := netip.ParseAddr(args[0].text)
			if err != nil {
				return nil, fail("%v", err)
			}
			if typ == dnsmsg.TypeA {
				if !ip.Is4() {
					return nil, fail("A needs an IPv4 address")
				}
				rr.Data = &dnsmsg.A{Addr: ip}
			} else {
				if !ip.Is6() {
					return nil, fail("AAAA needs an IPv6 address")
				}
				rr.Data = &dnsmsg.AAAA{Addr: ip}
			}
		case dnsmsg.TypeCNAME:
			if err := need(1); err != nil {
				return nil, err
			}
			rr.Data = &dnsmsg.CNAME{Target: abs(args[0].text)}
		case dnsmsg.TypeNS:
			if err := need(1); err != nil {
				return nil, err
			}
			rr.Data = &dnsmsg.NS{Host: abs(args[0].text)}
		case dnsmsg.TypeMX:
			if err := need(2); err != nil {
				return nil, err
			}
			pref, err := strconv.ParseUint(args[0].text, 10, 16)
			if err != nil {
				return nil, fail("bad MX preference %q", args[0].text)
			}
			rr.Data = &dnsmsg.MX{Preference: uint16(pref), Exchange: abs(args[1].text)}
		case dnsmsg.TypeTXT:
			if len(args) == 0 {
				return nil, fail("TXT needs at least one string")
			}
			var texts []string
			for _, a := range args {
				if len(a.text) > 255 {
					return nil, fail("TXT string longer than 255 bytes; split it")
				}
				texts = append(texts, a.text)
			}
			rr.Data = &dnsmsg.TXT{Texts: texts}
		case dnsmsg.TypeSOA:
			if err := need(7); err != nil {
				return nil, err
			}
			var v [5]uint32
			for i := range v {
				if v[i], err = ParseTTL(args[2+i].text); err != nil {
					return nil, fail("SOA field %d: %v", i+3, err)
				}
			}
			rr.Data = &dnsmsg.SOA{MName: abs(args[0].text), RName: abs(args[1].text),
				Serial: v[0], Refresh: v[1], Retry: v[2], Expire: v[3], Minimum: v[4]}
			// RFC 2308: without $TTL, the SOA's TTL defaults to its minimum.
			if !ttlSet && !haveDefTTL {
				rr.TTL = v[4]
			}
		default:
			return nil, fail("record type %s is not supported", typ)
		}
		records = append(records, rr)
	}
	return New(records)
}
