package resolver

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
	"github.com/AbdeldjalilChougui/dns/server"
	"github.com/AbdeldjalilChougui/dns/zone"
)

// A fake DNS hierarchy served in-process: each "server IP" maps to an
// authoritative handler with its zones. No network is involved, so the
// tests are fast and deterministic.

const rootZone = `
$ORIGIN .
$TTL 86400
@ SOA a.root-servers.test. nstld.test. 1 1800 900 604800 86400
@ NS a.root-servers.test.
a.root-servers.test. A 10.0.0.1
com. NS a.gtld.test.
org. NS a.gtld.test.
a.gtld.test. A 10.0.0.2
`

const tldZones = `
$ORIGIN com.
$TTL 172800
@ SOA a.gtld.test. nstld.test. 1 1800 900 604800 900
@ NS a.gtld.test.
example NS ns1.example
ns1.example A 10.0.1.1
noglue NS ns.example.org.
lame NS ns.lame
ns.lame A 10.0.9.9
`

const orgZone = `
$ORIGIN org.
$TTL 172800
@ SOA a.gtld.test. nstld.test. 1 1800 900 604800 900
@ NS a.gtld.test.
example NS ns.example
ns.example A 10.0.2.1
`

const exampleCom = `
$ORIGIN example.com.
$TTL 300
@ SOA ns1 host 1 7200 900 1209600 60
@ NS ns1
ns1 A 10.0.1.1
www A 192.0.2.1
www AAAA 2001:db8::1
short 5 A 192.0.2.5
local CNAME www
cross CNAME www.example.org.
loop1 CNAME loop2
loop2 CNAME loop1
`

const exampleOrg = `
$ORIGIN example.org.
$TTL 300
@ SOA ns host 1 7200 900 1209600 60
@ NS ns
ns A 10.0.2.1
www A 198.51.100.7
`

const noglueCom = `
$ORIGIN noglue.com.
$TTL 300
@ SOA ns.example.org. host 1 7200 900 1209600 60
@ NS ns.example.org.
www A 203.0.113.9
`

type fakeNet struct {
	mu      sync.Mutex
	servers map[netip.Addr]server.Handler
	queries map[netip.Addr]int
	dead    map[netip.Addr]bool
}

func (f *fakeNet) Exchange(ctx context.Context, q *dnsmsg.Message, srv netip.AddrPort) (*dnsmsg.Message, error) {
	f.mu.Lock()
	f.queries[srv.Addr()]++
	h, ok := f.servers[srv.Addr()]
	dead := f.dead[srv.Addr()]
	f.mu.Unlock()
	if !ok || dead {
		return nil, errors.New("timeout")
	}
	// Round-trip through the wire format so the parser is exercised too.
	s := &server.Server{Handler: h}
	raw, _ := q.Pack()
	out := s.Handle(ctx, raw, true)
	return dnsmsg.Unpack(out)
}

func (f *fakeNet) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.queries {
		n += c
	}
	return n
}

func mustZone(t *testing.T, text string) *zone.Zone {
	t.Helper()
	z, err := zone.Parse(strings.NewReader(text), ".")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T) (*Resolver, *fakeNet, *clock) {
	auth := func(zs ...string) server.Handler {
		a := &server.Authoritative{}
		for _, z := range zs {
			a.Zones = append(a.Zones, mustZone(t, z))
		}
		return a
	}
	ip := netip.MustParseAddr
	fn := &fakeNet{
		servers: map[netip.Addr]server.Handler{
			ip("10.0.0.1"): auth(rootZone),
			ip("10.0.0.2"): auth(tldZones, orgZone),
			ip("10.0.1.1"): auth(exampleCom),
			ip("10.0.2.1"): auth(exampleOrg, noglueCom),
		},
		queries: map[netip.Addr]int{},
		dead:    map[netip.Addr]bool{},
	}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	r := &Resolver{
		Roots:     []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:53")},
		Exchanger: fn,
		Cache:     NewCache(clk.Now),
	}
	return r, fn, clk
}

var ctx = context.Background()

func answers(res *Result) string {
	var parts []string
	for _, rr := range res.Answers {
		parts = append(parts, rr.Type.String()+"="+rr.Data.String())
	}
	return strings.Join(parts, " ")
}

func TestResolveFromRoot(t *testing.T) {
	r, fn, _ := setup(t)
	res, err := r.Resolve(ctx, "www.example.com", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if res.RCode != 0 || answers(res) != "A=192.0.2.1" {
		t.Fatalf("got %v %s", res.RCode, answers(res))
	}
	// root → com → example.com: three queries.
	if fn.total() != 3 {
		t.Fatalf("queries %d", fn.total())
	}
	// Second lookup is served from cache. AAAA only needs the example.com server.
	if _, err := r.Resolve(ctx, "www.example.com", dnsmsg.TypeA); err != nil || fn.total() != 3 {
		t.Fatalf("cache miss: %v queries=%d", err, fn.total())
	}
	res, _ = r.Resolve(ctx, "www.example.com", dnsmsg.TypeAAAA)
	if answers(res) != "AAAA=2001:db8::1" || fn.total() != 4 {
		t.Fatalf("aaaa %s queries=%d", answers(res), fn.total())
	}
}

func TestCNAMEChasing(t *testing.T) {
	r, _, _ := setup(t)
	res, err := r.Resolve(ctx, "local.example.com", dnsmsg.TypeA)
	if err != nil || answers(res) != "CNAME=www.example.com. A=192.0.2.1" {
		t.Fatalf("in-zone: %v %s", err, answers(res))
	}
	// Cross-zone: example.com gives only the CNAME; the target lives under .org.
	res, err = r.Resolve(ctx, "cross.example.com", dnsmsg.TypeA)
	if err != nil || answers(res) != "CNAME=www.example.org. A=198.51.100.7" {
		t.Fatalf("cross-zone: %v %s", err, answers(res))
	}
	// Cached CNAME + cached target.
	res, _ = r.Resolve(ctx, "cross.example.com", dnsmsg.TypeA)
	if answers(res) != "CNAME=www.example.org. A=198.51.100.7" {
		t.Fatalf("cached chain: %s", answers(res))
	}
	if _, err := r.Resolve(ctx, "loop1.example.com", dnsmsg.TypeA); err == nil {
		t.Fatal("CNAME loop should fail")
	}
}

func TestNegativeCaching(t *testing.T) {
	r, fn, clk := setup(t)
	res, err := r.Resolve(ctx, "nope.example.com", dnsmsg.TypeA)
	if err != nil || res.RCode != dnsmsg.RCodeNameError {
		t.Fatalf("%v %v", err, res)
	}
	n := fn.total()
	// NXDOMAIN covers every type for 60s (the SOA minimum).
	res, _ = r.Resolve(ctx, "nope.example.com", dnsmsg.TypeMX)
	if res.RCode != dnsmsg.RCodeNameError || fn.total() != n {
		t.Fatalf("negative cache miss")
	}
	clk.Add(61 * time.Second)
	r.Resolve(ctx, "nope.example.com", dnsmsg.TypeA)
	if fn.total() == n {
		t.Fatal("negative entry did not expire")
	}
	// NODATA.
	res, _ = r.Resolve(ctx, "www.example.com", dnsmsg.TypeMX)
	if res.RCode != 0 || len(res.Answers) != 0 {
		t.Fatalf("nodata %v %s", res.RCode, answers(res))
	}
}

func TestTTLCountsDown(t *testing.T) {
	r, fn, clk := setup(t)
	res, _ := r.Resolve(ctx, "short.example.com", dnsmsg.TypeA)
	if res.Answers[0].TTL != 5 {
		t.Fatalf("ttl %d", res.Answers[0].TTL)
	}
	clk.Add(3 * time.Second)
	res, _ = r.Resolve(ctx, "short.example.com", dnsmsg.TypeA)
	if res.Answers[0].TTL != 2 {
		t.Fatalf("cached ttl %d, want 2", res.Answers[0].TTL)
	}
	n := fn.total()
	clk.Add(3 * time.Second)
	r.Resolve(ctx, "short.example.com", dnsmsg.TypeA)
	if fn.total() != n+1 {
		t.Fatalf("expired entry not refetched (queries %d -> %d)", n, fn.total())
	}
}

func TestNSWithoutGlue(t *testing.T) {
	r, _, _ := setup(t)
	// noglue.com's NS is ns.example.org: the resolver has to resolve that
	// name first (a nested resolution) before it can continue.
	res, err := r.Resolve(ctx, "www.noglue.com", dnsmsg.TypeA)
	if err != nil || answers(res) != "A=203.0.113.9" {
		t.Fatalf("%v %s", err, answers(res))
	}
}

func TestDeadServerFailsOver(t *testing.T) {
	r, fn, _ := setup(t)
	r.Roots = append([]netip.AddrPort{netip.MustParseAddrPort("10.9.9.9:53")}, r.Roots...)
	fn.dead[netip.MustParseAddr("10.9.9.9")] = true
	if _, err := r.Resolve(ctx, "www.example.com", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, "www.lame.com", dnsmsg.TypeA); err == nil {
		t.Fatal("unreachable delegation should fail")
	}
}

func TestBailiwick(t *testing.T) {
	// A hostile example.com server answers referrals with glue for a name
	// outside its delegation. The glue must not be cached.
	evil := server.HandlerFunc(func(_ context.Context, req *dnsmsg.Message) *dnsmsg.Message {
		resp := req.Reply()
		resp.Authority = []dnsmsg.RR{{Name: "sub.example.com.", Type: dnsmsg.TypeNS, Class: dnsmsg.ClassINET, TTL: 300,
			Data: &dnsmsg.NS{Host: "ns.sub.example.com."}}}
		resp.Additional = []dnsmsg.RR{
			{Name: "ns.sub.example.com.", Type: dnsmsg.TypeA, Class: dnsmsg.ClassINET, TTL: 300, Data: &dnsmsg.A{Addr: netip.MustParseAddr("10.0.1.1")}},
			{Name: "www.example.org.", Type: dnsmsg.TypeA, Class: dnsmsg.ClassINET, TTL: 300, Data: &dnsmsg.A{Addr: netip.MustParseAddr("6.6.6.6")}},
		}
		return resp
	})
	r, fn, _ := setup(t)
	fn.servers[netip.MustParseAddr("10.0.1.1")] = evil
	r.Resolve(ctx, "x.sub.example.com", dnsmsg.TypeA) // loops on referrals; error is fine
	if rrs, _, ok := r.Cache.Get("www.example.org.", dnsmsg.TypeA); ok {
		t.Fatalf("out-of-bailiwick glue cached: %v", rrs)
	}
}

func TestUpwardReferralRejected(t *testing.T) {
	up := server.HandlerFunc(func(_ context.Context, req *dnsmsg.Message) *dnsmsg.Message {
		resp := req.Reply()
		resp.Authority = []dnsmsg.RR{{Name: "com.", Type: dnsmsg.TypeNS, Class: dnsmsg.ClassINET, TTL: 300,
			Data: &dnsmsg.NS{Host: "a.gtld.test."}}}
		return resp
	})
	r, fn, _ := setup(t)
	fn.servers[netip.MustParseAddr("10.0.1.1")] = up
	_, err := r.Resolve(ctx, "www.example.com", dnsmsg.TypeA)
	if !errors.Is(err, ErrLameServers) {
		t.Fatalf("want lame-server error, got %v", err)
	}
}

func TestRecursiveHandler(t *testing.T) {
	r, _, _ := setup(t)
	h := Handler(r)
	q := dnsmsg.NewQuery(42, "cross.example.com", dnsmsg.TypeA, true)
	resp := h.ServeDNS(ctx, q)
	if !resp.RecursionAvailable || resp.ID != 42 || len(resp.Answers) != 2 {
		t.Fatalf("%s", resp)
	}
	q.RecursionDesired = false
	if resp := h.ServeDNS(ctx, q); resp.RCode != dnsmsg.RCodeRefused {
		t.Fatalf("non-RD query: %v", resp.RCode)
	}
}

func TestCacheEviction(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	c := NewCache(clk.Now)
	c.MaxEntries = 10
	for i := 0; i < 50; i++ {
		c.Put([]dnsmsg.RR{{Name: strings.Repeat("a", i+1) + ".", Type: dnsmsg.TypeA, TTL: 60,
			Data: &dnsmsg.A{Addr: netip.MustParseAddr("192.0.2.1")}}})
	}
	if c.Len() > 10 {
		t.Fatalf("cache grew to %d", c.Len())
	}
}
