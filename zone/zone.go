package zone

import (
	"errors"
	"fmt"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
)

// Zone is an in-memory authoritative zone.
type Zone struct {
	Origin string
	SOA    dnsmsg.RR
	nodes  map[string]map[dnsmsg.Type][]dnsmsg.RR // canonical owner → type → RRset
	exists map[string]bool                        // owners and every ancestor up to the apex
}

// New builds a zone from records. Exactly one SOA is required; its owner is
// the zone apex.
func New(records []dnsmsg.RR) (*Zone, error) {
	z := &Zone{nodes: map[string]map[dnsmsg.Type][]dnsmsg.RR{}, exists: map[string]bool{}}
	for _, rr := range records {
		if rr.Type == dnsmsg.TypeSOA {
			if z.Origin != "" {
				return nil, errors.New("zone has more than one SOA")
			}
			z.Origin, z.SOA = dnsmsg.CanonicalName(rr.Name), rr
		}
	}
	if z.Origin == "" {
		return nil, errors.New("zone has no SOA record")
	}
	for _, rr := range records {
		name := dnsmsg.CanonicalName(rr.Name)
		if !dnsmsg.IsSubdomain(name, z.Origin) {
			return nil, fmt.Errorf("%s is outside the zone %s", rr.Name, z.Origin)
		}
		rr.Name = name
		if z.nodes[name] == nil {
			z.nodes[name] = map[dnsmsg.Type][]dnsmsg.RR{}
		}
		z.nodes[name][rr.Type] = append(z.nodes[name][rr.Type], rr)
		for n := name; ; n = dnsmsg.Parent(n) {
			z.exists[n] = true
			if n == z.Origin || n == "." {
				break
			}
		}
	}
	for name, set := range z.nodes {
		if _, ok := set[dnsmsg.TypeCNAME]; ok && len(set) > 1 {
			return nil, fmt.Errorf("%s: CNAME cannot coexist with other data", name)
		}
		if len(set[dnsmsg.TypeCNAME]) > 1 {
			return nil, fmt.Errorf("%s: more than one CNAME", name)
		}
	}
	return z, nil
}

// Records returns the RRset for name and type.
func (z *Zone) Records(name string, t dnsmsg.Type) []dnsmsg.RR {
	return z.nodes[dnsmsg.CanonicalName(name)][t]
}

// Answer fills an authoritative response for q into resp.
//
// The steps follow RFC 1034 §4.3.2:
//  1. Walking down from the apex, an NS set below the apex is a zone cut.
//     The answer is a referral (NS in authority, glue in additional, AA off).
//  2. If the name exists and has the type, answer with it.
//  3. If the name has a CNAME, answer with it and keep following the target
//     while it stays inside this zone.
//  4. If the name exists (or is an empty non-terminal) but lacks the type,
//     the answer is NODATA (NOERROR, SOA in authority).
//  5. Otherwise the answer is NXDOMAIN with the SOA in authority.
func (z *Zone) Answer(q dnsmsg.Question, resp *dnsmsg.Message) {
	resp.Authoritative = true
	name := dnsmsg.CanonicalName(q.Name)
	for hops := 0; hops < 8; hops++ {
		if cut := z.findCut(name); cut != "" {
			// A referral. If the chain already produced answers, stop here
			// and let the resolver follow the delegation.
			if len(resp.Answers) == 0 {
				resp.Authoritative = false
				resp.Authority = append(resp.Authority, z.nodes[cut][dnsmsg.TypeNS]...)
				z.addGlue(resp, resp.Authority)
			}
			return
		}
		set, ok := z.nodes[name]
		if ok {
			if q.Type == dnsmsg.TypeANY {
				for _, rrs := range set {
					resp.Answers = append(resp.Answers, rrs...)
				}
				return
			}
			if rrs := set[q.Type]; len(rrs) > 0 {
				resp.Answers = append(resp.Answers, rrs...)
				z.addGlue(resp, rrs)
				return
			}
			if c := set[dnsmsg.TypeCNAME]; len(c) > 0 {
				resp.Answers = append(resp.Answers, c...)
				target := dnsmsg.CanonicalName(c[0].Data.(*dnsmsg.CNAME).Target)
				if !dnsmsg.IsSubdomain(target, z.Origin) {
					return // out of zone; the resolver chases it
				}
				name = target
				continue
			}
		}
		if ok || z.exists[name] {
			z.negative(resp) // NODATA
			return
		}
		if len(resp.Answers) == 0 {
			resp.RCode = dnsmsg.RCodeNameError
		}
		z.negative(resp)
		return
	}
}

// findCut returns the closest delegation point at or above name (but below
// the apex), or "".
func (z *Zone) findCut(name string) string {
	// Collect ancestors from just below the apex down to name.
	var chain []string
	for n := name; n != z.Origin && n != "."; n = dnsmsg.Parent(n) {
		chain = append(chain, n)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if len(z.nodes[chain[i]][dnsmsg.TypeNS]) > 0 {
			return chain[i]
		}
	}
	return ""
}

// negative adds the SOA for negative caching. Its TTL is min(SOA TTL, MINIMUM)
// per RFC 2308 §3.
func (z *Zone) negative(resp *dnsmsg.Message) {
	soa := z.SOA
	if m := soa.Data.(*dnsmsg.SOA).Minimum; m < soa.TTL {
		soa.TTL = m
	}
	resp.Authority = append(resp.Authority, soa)
}

// addGlue puts in-zone A/AAAA records for NS and MX targets in additional.
func (z *Zone) addGlue(resp *dnsmsg.Message, rrs []dnsmsg.RR) {
	for _, rr := range rrs {
		var host string
		switch d := rr.Data.(type) {
		case *dnsmsg.NS:
			host = d.Host
		case *dnsmsg.MX:
			host = d.Exchange
		default:
			continue
		}
		host = dnsmsg.CanonicalName(host)
		resp.Additional = append(resp.Additional, z.nodes[host][dnsmsg.TypeA]...)
		resp.Additional = append(resp.Additional, z.nodes[host][dnsmsg.TypeAAAA]...)
	}
}
