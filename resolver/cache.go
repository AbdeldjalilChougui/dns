package resolver

import (
	"sync"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
)

// Cache stores RRsets and negative answers until their TTL runs out.
// Returned records carry the *remaining* TTL, as a resolver must report.
type Cache struct {
	mu         sync.Mutex
	m          map[cacheKey]*cacheEntry
	Now        func() time.Time
	MaxTTL     time.Duration // cap on positive TTLs (default 1 day)
	MaxEntries int           // default 10000
}

type cacheKey struct {
	name string
	t    dnsmsg.Type // 0 = "whole name is NXDOMAIN"
}

type cacheEntry struct {
	rrs     []dnsmsg.RR
	rcode   dnsmsg.RCode
	expires time.Time
}

func NewCache(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{m: map[cacheKey]*cacheEntry{}, Now: now, MaxTTL: 24 * time.Hour, MaxEntries: 10000}
}

// Get returns a cached answer. ok is false on a miss. A cached negative
// answer has ok true, no records, and rcode NXDOMAIN or NOERROR (NODATA).
func (c *Cache) Get(name string, t dnsmsg.Type) (rrs []dnsmsg.RR, rcode dnsmsg.RCode, ok bool) {
	name = dnsmsg.CanonicalName(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	for _, k := range []cacheKey{{name, 0}, {name, t}} {
		e, found := c.m[k]
		if !found {
			continue
		}
		if !now.Before(e.expires) {
			delete(c.m, k)
			continue
		}
		left := uint32(e.expires.Sub(now) / time.Second)
		out := make([]dnsmsg.RR, len(e.rrs))
		for i, rr := range e.rrs {
			rr.TTL = left
			out[i] = rr
		}
		return out, e.rcode, true
	}
	return nil, 0, false
}

// Put caches records, grouped into RRsets. An RRset's TTL is the minimum of
// its members' TTLs.
func (c *Cache) Put(rrs []dnsmsg.RR) {
	sets := map[cacheKey][]dnsmsg.RR{}
	var order []cacheKey
	for _, rr := range rrs {
		if rr.Type == dnsmsg.TypeOPT {
			continue
		}
		k := cacheKey{dnsmsg.CanonicalName(rr.Name), rr.Type}
		if _, seen := sets[k]; !seen {
			order = append(order, k)
		}
		sets[k] = append(sets[k], rr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range order {
		set := sets[k]
		ttl := set[0].TTL
		for _, rr := range set {
			ttl = min(ttl, rr.TTL)
		}
		if ttl == 0 {
			continue
		}
		d := min(time.Duration(ttl)*time.Second, c.MaxTTL)
		c.store(k, &cacheEntry{rrs: set, expires: c.Now().Add(d)})
	}
}

// PutNegative caches NXDOMAIN (for every type of name) or NODATA (for t).
func (c *Cache) PutNegative(name string, t dnsmsg.Type, rcode dnsmsg.RCode, ttl uint32) {
	if ttl == 0 {
		return
	}
	k := cacheKey{dnsmsg.CanonicalName(name), t}
	if rcode == dnsmsg.RCodeNameError {
		k.t = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d := min(time.Duration(ttl)*time.Second, 3*time.Hour) // RFC 2308 §5 suggests ≤ 3h
	c.store(k, &cacheEntry{rcode: rcode, expires: c.Now().Add(d)})
}

func (c *Cache) store(k cacheKey, e *cacheEntry) {
	if len(c.m) >= c.MaxEntries {
		now := c.Now()
		for kk, ee := range c.m {
			if !now.Before(ee.expires) {
				delete(c.m, kk)
			}
		}
		// Still full: evict arbitrary entries (map order is random).
		for kk := range c.m {
			if len(c.m) < c.MaxEntries {
				break
			}
			delete(c.m, kk)
		}
	}
	c.m[k] = e
}

// Len returns the number of entries (including expired ones not yet removed).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
