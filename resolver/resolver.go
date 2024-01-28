// Package resolver is an iterative ("recursive" from the client's point of
// view) DNS resolver: it starts at the root servers, follows referrals down
// the hierarchy, chases CNAMEs, and caches everything by TTL.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
	"github.com/AbdeldjalilChougui/dns/server"
)

// Exchanger sends one query to one server and returns its reply.
type Exchanger interface {
	Exchange(ctx context.Context, q *dnsmsg.Message, server netip.AddrPort) (*dnsmsg.Message, error)
}

// RootHints are the IPv4 addresses of a few root servers (from IANA's
// named.root). They're used only to bootstrap.
var RootHints = []netip.AddrPort{
	netip.MustParseAddrPort("198.41.0.4:53"),    // a.root-servers.net
	netip.MustParseAddrPort("170.247.170.2:53"), // b.root-servers.net
	netip.MustParseAddrPort("192.33.4.12:53"),   // c.root-servers.net
	netip.MustParseAddrPort("199.7.91.13:53"),   // d.root-servers.net
	netip.MustParseAddrPort("192.5.5.241:53"),   // f.root-servers.net
	netip.MustParseAddrPort("193.0.14.129:53"),  // k.root-servers.net
}

// Resolver resolves names iteratively.
type Resolver struct {
	Roots     []netip.AddrPort
	Exchanger Exchanger
	Cache     *Cache
	Port      uint16 // port used for name servers learned from referrals (53)
}

// New returns a resolver using the real network.
func New() *Resolver {
	return &Resolver{Roots: RootHints, Exchanger: &NetExchanger{Timeout: 2 * time.Second}, Cache: NewCache(nil), Port: 53}
}

// Result is the outcome of a resolution.
type Result struct {
	RCode   dnsmsg.RCode
	Answers []dnsmsg.RR // any CNAME chain first, then the final records
}

var (
	ErrLoop        = errors.New("resolver: too many steps (loop?)")
	ErrNoServers   = errors.New("resolver: no reachable name servers")
	ErrLameServers = errors.New("resolver: referral did not get closer to the answer")
)

const (
	maxDepth     = 8  // nested resolutions (NS names without glue)
	maxReferrals = 16 // referrals followed for one name
	maxCNAMEs    = 10
)

// Resolve answers name/t.
func (r *Resolver) Resolve(ctx context.Context, name string, t dnsmsg.Type) (*Result, error) {
	return r.resolve(ctx, dnsmsg.CanonicalName(name), t, 0)
}

func (r *Resolver) resolve(ctx context.Context, name string, t dnsmsg.Type, depth int) (*Result, error) {
	if depth > maxDepth {
		return nil, ErrLoop
	}
	res := &Result{}
	for hop := 0; hop <= maxCNAMEs; hop++ {
		// 1. Cache: final answer or negative answer.
		if rrs, rc, ok := r.Cache.Get(name, t); ok {
			res.RCode = rc
			res.Answers = append(res.Answers, rrs...)
			return res, nil
		}
		// 2. Cache: a CNAME we can follow without asking anyone.
		if t != dnsmsg.TypeCNAME {
			if c, _, ok := r.Cache.Get(name, dnsmsg.TypeCNAME); ok && len(c) > 0 {
				res.Answers = append(res.Answers, c...)
				name = dnsmsg.CanonicalName(c[0].Data.(*dnsmsg.CNAME).Target)
				continue
			}
		}
		// 3. Ask the hierarchy.
		resp, err := r.iterate(ctx, name, t, depth)
		if err != nil {
			return nil, err
		}
		r.Cache.Put(resp.Answers)

		// Walk the answer section along the CNAME chain.
		cur := name
		var final []dnsmsg.RR
		for i := 0; i <= maxCNAMEs; i++ {
			final = pick(resp.Answers, cur, t)
			if len(final) > 0 {
				break
			}
			c := pick(resp.Answers, cur, dnsmsg.TypeCNAME)
			if len(c) == 0 || t == dnsmsg.TypeCNAME {
				break
			}
			res.Answers = append(res.Answers, c...)
			cur = dnsmsg.CanonicalName(c[0].Data.(*dnsmsg.CNAME).Target)
		}
		if len(final) > 0 {
			res.RCode = dnsmsg.RCodeSuccess
			res.Answers = append(res.Answers, final...)
			return res, nil
		}
		if cur != name {
			// The server gave us a CNAME but not the target's data (target is
			// in another zone). Resolve the target from scratch.
			name = cur
			continue
		}
		// Negative answer. Cache it for the SOA's negative TTL.
		ttl := negativeTTL(resp)
		r.Cache.PutNegative(name, t, resp.RCode, ttl)
		res.RCode = resp.RCode
		return res, nil
	}
	return nil, fmt.Errorf("resolver: CNAME chain longer than %d", maxCNAMEs)
}

func pick(rrs []dnsmsg.RR, name string, t dnsmsg.Type) []dnsmsg.RR {
	var out []dnsmsg.RR
	for _, rr := range rrs {
		if rr.Type == t && dnsmsg.CanonicalName(rr.Name) == name {
			out = append(out, rr)
		}
	}
	return out
}

func negativeTTL(resp *dnsmsg.Message) uint32 {
	for _, rr := range resp.Authority {
		if soa, ok := rr.Data.(*dnsmsg.SOA); ok {
			return min(rr.TTL, soa.Minimum)
		}
	}
	return 0
}

// iterate walks referrals from the closest known zone cut until a server
// gives a final answer (data, NXDOMAIN, or authoritative NODATA).
func (r *Resolver) iterate(ctx context.Context, name string, t dnsmsg.Type, depth int) (*dnsmsg.Message, error) {
	zone, servers := r.closestServers(name)
	for step := 0; step < maxReferrals; step++ {
		resp, err := r.queryAny(ctx, servers, name, t)
		if err != nil {
			return nil, err
		}
		if len(resp.Answers) > 0 || resp.RCode != dnsmsg.RCodeSuccess || resp.Authoritative {
			if resp.RCode != dnsmsg.RCodeSuccess && resp.RCode != dnsmsg.RCodeNameError {
				return nil, fmt.Errorf("resolver: %s for %s %s", resp.RCode, name, t)
			}
			return resp, nil
		}
		// A referral: NS records for a zone that is closer to name.
		var ns []dnsmsg.RR
		for _, rr := range resp.Authority {
			if rr.Type == dnsmsg.TypeNS {
				ns = append(ns, rr)
			}
		}
		if len(ns) == 0 {
			return resp, nil // non-authoritative NODATA; accept it
		}
		child := dnsmsg.CanonicalName(ns[0].Name)
		// The new zone must be strictly below the current one and contain
		// name. Otherwise the server is lame or hostile (an "upward referral").
		if !dnsmsg.IsSubdomain(name, child) || !dnsmsg.IsSubdomain(child, zone) || child == zone {
			return nil, fmt.Errorf("%w: %s referred %s to %s", ErrLameServers, zone, name, child)
		}
		r.Cache.Put(ns)
		// Glue is only trusted if it is an address for one of the NS hosts
		// and lies inside the zone of the server we asked (bailiwick rule).
		// That stops a server for evil.com from planting an A record for
		// www.bank.com via the additional section.
		hosts := map[string]bool{}
		for _, rr := range ns {
			hosts[dnsmsg.CanonicalName(rr.Data.(*dnsmsg.NS).Host)] = true
		}
		var glue []dnsmsg.RR
		for _, rr := range resp.Additional {
			if (rr.Type == dnsmsg.TypeA || rr.Type == dnsmsg.TypeAAAA) &&
				hosts[dnsmsg.CanonicalName(rr.Name)] && dnsmsg.IsSubdomain(rr.Name, zone) {
				glue = append(glue, rr)
			}
		}
		r.Cache.Put(glue)
		zone = child
		servers = r.addrsFor(ctx, ns, depth)
		if len(servers) == 0 {
			return nil, fmt.Errorf("%w for %s", ErrNoServers, child)
		}
	}
	return nil, ErrLoop
}

// closestServers finds the deepest zone cut for name with cached NS records
// whose addresses are known, falling back to the roots.
func (r *Resolver) closestServers(name string) (string, []netip.AddrPort) {
	for z := name; ; z = dnsmsg.Parent(z) {
		if z == "." {
			return ".", r.Roots
		}
		if ns, _, ok := r.Cache.Get(z, dnsmsg.TypeNS); ok && len(ns) > 0 {
			if addrs := r.cachedAddrs(ns); len(addrs) > 0 {
				return z, addrs
			}
		}
	}
}

func (r *Resolver) port() uint16 {
	if r.Port == 0 {
		return 53
	}
	return r.Port
}

func (r *Resolver) cachedAddrs(ns []dnsmsg.RR) []netip.AddrPort {
	var out []netip.AddrPort
	for _, rr := range ns {
		host := rr.Data.(*dnsmsg.NS).Host
		for _, t := range []dnsmsg.Type{dnsmsg.TypeA, dnsmsg.TypeAAAA} {
			rrs, _, _ := r.Cache.Get(host, t)
			out = append(out, addrsOf(rrs, r.port())...)
		}
	}
	return out
}

// addrsFor returns server addresses for an NS set, resolving NS host names
// that came without glue (one level deeper).
func (r *Resolver) addrsFor(ctx context.Context, ns []dnsmsg.RR, depth int) []netip.AddrPort {
	if out := r.cachedAddrs(ns); len(out) > 0 {
		return out
	}
	for _, rr := range ns {
		host := rr.Data.(*dnsmsg.NS).Host
		res, err := r.resolve(ctx, dnsmsg.CanonicalName(host), dnsmsg.TypeA, depth+1)
		if err == nil {
			if out := addrsOf(res.Answers, r.port()); len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func addrsOf(rrs []dnsmsg.RR, port uint16) []netip.AddrPort {
	var out []netip.AddrPort
	for _, rr := range rrs {
		switch d := rr.Data.(type) {
		case *dnsmsg.A:
			out = append(out, netip.AddrPortFrom(d.Addr, port))
		case *dnsmsg.AAAA:
			out = append(out, netip.AddrPortFrom(d.Addr, port))
		}
	}
	return out
}

// queryAny asks the servers in random order until one answers usefully.
func (r *Resolver) queryAny(ctx context.Context, servers []netip.AddrPort, name string, t dnsmsg.Type) (*dnsmsg.Message, error) {
	order := rand.Perm(len(servers))
	var lastErr error = ErrNoServers
	for _, i := range order {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		q := dnsmsg.NewQuery(uint16(rand.UintN(1<<16)), name, t, false)
		q.SetEDNS(dnsmsg.EDNS{UDPSize: 1232})
		resp, err := r.Exchanger.Exchange(ctx, q, servers[i])
		if err != nil {
			lastErr = err
			continue
		}
		if resp.RCode == dnsmsg.RCodeServerFailure || resp.RCode == dnsmsg.RCodeRefused {
			lastErr = fmt.Errorf("%s answered %s", servers[i], resp.RCode)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// NetExchanger talks to real servers over UDP, retrying over TCP when the
// answer is truncated.
type NetExchanger struct {
	Timeout time.Duration
}

func (e *NetExchanger) Exchange(ctx context.Context, q *dnsmsg.Message, srv netip.AddrPort) (*dnsmsg.Message, error) {
	resp, err := e.exchange(ctx, "udp", q, srv)
	if err == nil && resp.Truncated {
		return e.exchange(ctx, "tcp", q, srv)
	}
	return resp, err
}

func (e *NetExchanger) exchange(ctx context.Context, network string, q *dnsmsg.Message, srv netip.AddrPort) (*dnsmsg.Message, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, srv.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	b, err := q.Pack()
	if err != nil {
		return nil, err
	}
	var raw []byte
	if network == "tcp" {
		if err := server.WriteTCPMessage(conn, b); err != nil {
			return nil, err
		}
		if raw, err = server.ReadTCPMessage(conn); err != nil {
			return nil, err
		}
	} else {
		if _, err := conn.Write(b); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			raw = buf[:n]
			// Ignore stray datagrams that don't match our ID (spoofing guard).
			if n >= 2 && uint16(raw[0])<<8|uint16(raw[1]) == q.ID {
				break
			}
		}
	}
	resp, err := dnsmsg.Unpack(raw)
	if err != nil {
		return nil, err
	}
	if resp.ID != q.ID || !resp.Response || len(resp.Questions) != 1 ||
		dnsmsg.CanonicalName(resp.Question().Name) != dnsmsg.CanonicalName(q.Question().Name) ||
		resp.Question().Type != q.Question().Type {
		return nil, errors.New("resolver: reply does not match the query")
	}
	return resp, nil
}

// Handler serves recursive queries with the resolver.
func Handler(r *Resolver) server.Handler {
	return server.HandlerFunc(func(ctx context.Context, req *dnsmsg.Message) *dnsmsg.Message {
		resp := req.Reply()
		resp.RecursionAvailable = true
		if !req.RecursionDesired {
			resp.RCode = dnsmsg.RCodeRefused
			return resp
		}
		q := req.Question()
		res, err := r.Resolve(ctx, q.Name, q.Type)
		if err != nil {
			resp.RCode = dnsmsg.RCodeServerFailure
			return resp
		}
		resp.RCode = res.RCode
		resp.Answers = res.Answers
		return resp
	})
}
