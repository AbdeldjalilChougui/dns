package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"
)

func TestPackKnownQuery(t *testing.T) {
	q := NewQuery(0x1234, "example.com", TypeA, true)
	got, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("123401000001000000000000" + "076578616d706c6503636f6d00" + "00010001")
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func fullMessage() *Message {
	m := &Message{
		Header:    Header{ID: 7, Response: true, Authoritative: true, RecursionDesired: true, RCode: RCodeSuccess},
		Questions: []Question{{"www.example.com.", TypeA, ClassINET}},
		Answers: []RR{
			{Name: "www.example.com.", Type: TypeCNAME, Class: ClassINET, TTL: 300, Data: &CNAME{"web.example.com."}},
			{Name: "web.example.com.", Type: TypeA, Class: ClassINET, TTL: 60, Data: &A{netip.MustParseAddr("192.0.2.1")}},
			{Name: "web.example.com.", Type: TypeAAAA, Class: ClassINET, TTL: 60, Data: &AAAA{netip.MustParseAddr("2001:db8::1")}},
			{Name: "example.com.", Type: TypeMX, Class: ClassINET, TTL: 60, Data: &MX{10, "mail.example.com."}},
			{Name: "example.com.", Type: TypeTXT, Class: ClassINET, TTL: 60, Data: &TXT{[]string{"v=spf1 -all", "second"}}},
		},
		Authority: []RR{
			{Name: "example.com.", Type: TypeNS, Class: ClassINET, TTL: 3600, Data: &NS{"ns1.example.com."}},
			{Name: "example.com.", Type: TypeSOA, Class: ClassINET, TTL: 3600, Data: &SOA{"ns1.example.com.", "hostmaster.example.com.", 2024010101, 7200, 900, 1209600, 300}},
		},
		Additional: []RR{
			{Name: "x.example.com.", Type: Type(99), Class: ClassINET, TTL: 1, Data: &Unknown{T: 99, Raw: []byte{1, 2, 3}}},
		},
	}
	m.SetEDNS(EDNS{UDPSize: 1232, DO: true, Options: []EDNSOption{{Code: 10, Data: []byte("cookie12")}}})
	return m
}

func TestRoundTrip(t *testing.T) {
	m := fullMessage()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip mismatch\n got: %s\nwant: %s", got, m)
	}
	e, ok := got.EDNS()
	if !ok || e.UDPSize != 1232 || !e.DO || string(e.Options[0].Data) != "cookie12" {
		t.Fatalf("edns %+v", e)
	}
}

func TestCompressionShrinks(t *testing.T) {
	m := fullMessage()
	b, _ := m.Pack()
	// Without compression every "example.com" costs 13 bytes; count raw copies.
	if n := bytes.Count(b, []byte("\x07example\x03com")); n != 1 {
		t.Fatalf("example.com written %d times, want once (rest compressed)", n)
	}
}

func TestExtendedRCode(t *testing.T) {
	m := NewQuery(1, "a.", TypeA, false).Reply()
	m.SetEDNS(EDNS{UDPSize: 512})
	m.RCode = RCodeBadVers
	b, _ := m.Pack()
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.RCode != RCodeBadVers {
		t.Fatalf("rcode %v", got.RCode)
	}
}

func TestMalformed(t *testing.T) {
	good, _ := fullMessage().Pack()
	for i := 0; i < len(good); i++ {
		Unpack(good[:i]) // must not panic
	}
	// A pointer to itself must be rejected, not loop forever.
	loop, _ := hex.DecodeString("000000000001000000000000" + "c00c" + "00010001")
	if _, err := Unpack(loop); err == nil {
		t.Fatal("self-pointer accepted")
	}
	// Forward pointer.
	fwd, _ := hex.DecodeString("000000000001000000000000" + "c020" + "00010001")
	if _, err := Unpack(fwd); err == nil {
		t.Fatal("forward pointer accepted")
	}
}

func TestNames(t *testing.T) {
	if !IsSubdomain("a.B.example.com", "example.COM.") || IsSubdomain("badexample.com.", "example.com.") {
		t.Fatal("IsSubdomain")
	}
	if Parent("a.b.c.") != "b.c." || Parent("c.") != "." || CountLabels(".") != 0 {
		t.Fatal("Parent/CountLabels")
	}
	m := NewQuery(1, `we\.ird.example.com`, TypeA, false)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Unpack(b)
	if got.Question().Name != `we\.ird.example.com.` {
		t.Fatalf("escaped name %q", got.Question().Name)
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := NewQuery(1, string(long)+".com", TypeA, false).Pack(); err != ErrLabelTooLong {
		t.Fatalf("long label: %v", err)
	}
}

func TestPackLimitTruncates(t *testing.T) {
	m := NewQuery(1, "big.example.", TypeTXT, false).Reply()
	for i := 0; i < 20; i++ {
		m.Answers = append(m.Answers, RR{Name: "big.example.", Type: TypeTXT, Class: ClassINET, TTL: 1,
			Data: &TXT{[]string{string(bytes.Repeat([]byte("x"), 100))}}})
	}
	m.SetEDNS(EDNS{UDPSize: 1232})
	b, err := m.PackLimit(512)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Unpack(b)
	if len(b) > 512 || !got.Truncated || len(got.Answers) != 0 || got.OPT() == nil {
		t.Fatalf("len=%d tc=%v answers=%d", len(b), got.Truncated, len(got.Answers))
	}
}

func TestParseType(t *testing.T) {
	for in, want := range map[string]Type{"a": TypeA, "AAAA": TypeAAAA, "mx": TypeMX, "TYPE65": 65} {
		if got, err := ParseType(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
}
