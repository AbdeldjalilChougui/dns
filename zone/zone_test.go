package zone

import (
	"os"
	"strings"
	"testing"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
)

func load(t *testing.T) *Zone {
	t.Helper()
	f, err := os.Open("../testdata/example.com.zone")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := Parse(f, ".")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func ask(z *Zone, name string, t dnsmsg.Type) *dnsmsg.Message {
	q := dnsmsg.NewQuery(1, name, t, false)
	resp := q.Reply()
	z.Answer(q.Question(), resp)
	return resp
}

func TestParse(t *testing.T) {
	z := load(t)
	if z.Origin != "example.com." {
		t.Fatalf("origin %q", z.Origin)
	}
	soa := z.SOA.Data.(*dnsmsg.SOA)
	if soa.MName != "ns1.example.com." || soa.Refresh != 7200 || soa.Retry != 900 || soa.Expire != 1209600 || soa.Minimum != 300 {
		t.Fatalf("soa %+v", soa)
	}
	www := z.Records("WWW.example.com", dnsmsg.TypeAAAA)
	if len(www) != 1 || www[0].TTL != 300 || www[0].Data.String() != "2001:db8::10" {
		t.Fatalf("www AAAA %v", www)
	}
	if a := z.Records("www.example.com.", dnsmsg.TypeA); a[0].TTL != 300 {
		t.Fatalf("ttl before class: %v", a)
	}
	if mx := z.Records("example.com.", dnsmsg.TypeMX); mx[0].Data.String() != "10 mail.example.com." || mx[0].TTL != 3600 {
		t.Fatalf("mx %v", mx)
	}
	txt := z.Records("example.com.", dnsmsg.TypeTXT)[0].Data.(*dnsmsg.TXT)
	if len(txt.Texts) != 2 || txt.Texts[0] != "v=spf1 mx -all" {
		t.Fatalf("txt %q", txt.Texts)
	}
	if ns := z.Records("example.com.", dnsmsg.TypeNS); ns[1].Data.String() != "ns2.example.net." {
		t.Fatalf("absolute NS %v", ns)
	}
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		"@ IN A 1.2.3.4\n":                              "no SOA",
		"@ SOA a b 1 2 3 4 5\n@ SOA a b 1 2 3 4 5\n":    "more than one SOA",
		"@ SOA a b 1 2 3 4 5\nx A 2001:db8::1\n":        "IPv4",
		"@ SOA a b ( 1 2 3 4 5\n":                       "unbalanced",
		"@ SOA a b 1 2 3 4 5\nx TXT \"open\n":           "unterminated",
		"@ SOA a b 1 2 3 4 5\nx SRV 1 2 3 y\n":          "unknown RR type",
		"@ SOA a b 1 2 3 4 5\nx TYPE99 abc\n":           "not supported",
		"@ SOA a b 1 2 3 4 5\nx CNAME y\nx A 1.2.3.4\n": "coexist",
		"@ SOA a b 1 2 3 4 5\nx.other. A 1.2.3.4\n":     "outside",
	}
	for in, want := range bad {
		_, err := Parse(strings.NewReader(in), "example.com.")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", in, err, want)
		}
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]uint32{"300": 300, "1h": 3600, "1h30m": 5400, "2d": 172800, "1W": 604800} {
		if got, err := ParseTTL(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "h", "1x", "5h3"} {
		if _, err := ParseTTL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestAnswer(t *testing.T) {
	z := load(t)

	r := ask(z, "www.example.com", dnsmsg.TypeA)
	if !r.Authoritative || r.RCode != 0 || len(r.Answers) != 1 || r.Answers[0].Data.String() != "192.0.2.10" {
		t.Fatalf("A: %s", r)
	}

	r = ask(z, "alias.example.com", dnsmsg.TypeA) // alias -> web -> www
	if len(r.Answers) != 3 || r.Answers[0].Type != dnsmsg.TypeCNAME || r.Answers[2].Type != dnsmsg.TypeA {
		t.Fatalf("cname chain: %s", r)
	}

	r = ask(z, "outside.example.com", dnsmsg.TypeA) // out-of-zone target: stop
	if len(r.Answers) != 1 || r.Answers[0].Data.String() != "www.example.org." {
		t.Fatalf("out of zone cname: %s", r)
	}

	r = ask(z, "nope.example.com", dnsmsg.TypeA)
	if r.RCode != dnsmsg.RCodeNameError || len(r.Authority) != 1 || r.Authority[0].Type != dnsmsg.TypeSOA || r.Authority[0].TTL != 300 {
		t.Fatalf("nxdomain: %s", r)
	}

	r = ask(z, "www.example.com", dnsmsg.TypeMX) // NODATA
	if r.RCode != 0 || len(r.Answers) != 0 || r.Authority[0].Type != dnsmsg.TypeSOA {
		t.Fatalf("nodata: %s", r)
	}

	r = ask(z, "b.deep.example.com", dnsmsg.TypeA) // empty non-terminal → NODATA, not NXDOMAIN
	if r.RCode != 0 || len(r.Answers) != 0 {
		t.Fatalf("ENT: %s", r)
	}

	r = ask(z, "host.sub.example.com", dnsmsg.TypeA) // referral with glue
	if r.Authoritative || len(r.Answers) != 0 || r.Authority[0].Type != dnsmsg.TypeNS ||
		len(r.Additional) != 1 || r.Additional[0].Data.String() != "192.0.2.200" {
		t.Fatalf("referral: %s", r)
	}

	r = ask(z, "example.com", dnsmsg.TypeMX) // MX with glue for mail
	if len(r.Additional) != 1 || r.Additional[0].Name != "mail.example.com." {
		t.Fatalf("mx glue: %s", r)
	}
}
