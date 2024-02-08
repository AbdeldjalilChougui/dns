# dns

[![Go Reference](https://pkg.go.dev/badge/github.com/AbdeldjalilChougui/dns.svg)](https://pkg.go.dev/github.com/AbdeldjalilChougui/dns)

DNS from scratch in Go, using only the standard library. It has three parts:

- **`dnsmsg`**: an RFC 1035 message parser and builder with name compression,
  A/AAAA/CNAME/NS/MX/TXT/SOA records, unknown types kept raw (RFC 3597), and
  EDNS0 (RFC 6891: the OPT record, buffer size, DO bit, extended RCODE).
- **`zone` + `server`**: an authoritative server that answers from zone files
  over UDP and TCP.
- **`resolver`**: an iterative resolver. It starts at the root servers,
  follows referrals, chases CNAMEs and caches by TTL, including negative
  answers.

## What it teaches

- Binary protocol parsing. That includes compression pointers, and rejecting
  pointer loops and forward pointers so malformed packets can't hang the
  parser.
- How authoritative answers are built (RFC 1034 §4.3.2): referrals at zone
  cuts with glue, CNAME chains inside a zone, NXDOMAIN vs. NODATA, empty
  non-terminals, and SOA-based negative TTLs (RFC 2308).
- What a recursive resolver really does: root hints, referrals, NS names
  without glue (a nested resolution), lame and upward referrals, and the
  **bailiwick rule** that stops cache poisoning through the additional
  section.
- UDP size limits: 512 bytes without EDNS, the client's buffer size with it,
  the TC bit, and falling back to TCP.

## Install

Use the packages (`dnsmsg`, `zone`, `server`, `resolver`) as a library:

```sh
go get github.com/AbdeldjalilChougui/dns@latest
```

Or install the `dnsd` binary:

```sh
go install github.com/AbdeldjalilChougui/dns/cmd/dnsd@latest
```

## Quick start

```sh
# Authoritative server for the sample zone
go run ./cmd/dnsd -addr 127.0.0.1:5353 -zone testdata/example.com.zone
dig @127.0.0.1 -p 5353 alias.example.com A +norec

# Recursive resolver (uses the real root servers; needs outbound UDP/TCP 53)
go run ./cmd/dnsd -addr 127.0.0.1:5354 -recursive
dig @127.0.0.1 -p 5354 www.wikipedia.org

# One-off iterative lookup
go run ./cmd/dnsd -lookup www.wikipedia.org -type A
```

### Zone file syntax

The parser covers the common subset of RFC 1035 §5: `$ORIGIN`, `$TTL`, `@`,
relative names, blank owners, TTL and class in either order, parentheses
across lines, `;` comments, quoted TXT strings, and BIND TTL units (`1h30m`).
See [testdata/example.com.zone](testdata/example.com.zone).

## How it works

```
query ─► server.Handle: unpack → validate (opcode, 1 question, EDNS version)
                       → Handler.ServeDNS → add OPT if the client sent one
                       → UDP: PackLimit(min(client size, 1232)), TC if too big
                         TCP: 2-byte length prefix, several queries per connection

Authoritative.ServeDNS: pick the most specific zone → Zone.Answer
    zone cut below the apex? → referral (NS + glue, AA=0)
    name has the type?       → answer
    name has a CNAME?        → answer it and follow the chain inside the zone
    name exists / is an ENT? → NODATA + SOA
    otherwise                → NXDOMAIN + SOA

Resolver.Resolve(name, type)
    cache hit (positive or negative)? → done
    cached CNAME? → follow it
    iterate: start at the closest cached zone cut (or the roots)
        answer / NXDOMAIN / authoritative NODATA → cache and return
        referral → check it is a strictly deeper zone that contains the name,
                   keep only in-bailiwick glue for the NS hosts,
                   resolve NS names without glue, then continue
```

## Tests

```sh
go test -race ./...
```

- `dnsmsg`: a byte-exact known query, a full round trip of every record type
  plus EDNS options, compression, the extended RCODE, every truncation point
  of a valid message (no panics), pointer loops, escaped names, and the
  truncation/TC logic.
- `zone`: parsing, parse errors, and the authoritative answer logic (CNAME
  chains, NXDOMAIN, NODATA, empty non-terminals, referral with glue, MX glue).
- `resolver`: a **fake hierarchy in-process** (root → com/org → example.com,
  example.org, noglue.com), where every query goes through the wire format.
  It covers resolution from the root, query counts proving the cache works,
  in-zone and cross-zone CNAMEs, CNAME loops, negative caching and its
  expiry, TTLs counting down on a fake clock, NS without glue, failover past
  a dead server, rejecting out-of-bailiwick glue, and rejecting upward
  referrals.
- `server`: real UDP/TCP on localhost. It covers EDNS negotiation, REFUSED
  outside the served zones, 512-byte truncation with TC and the TCP retry,
  FORMERR, BADVERS and NOTIMP.

## Status and limitations

This is a learning project.

- **No DNSSEC.** The DO bit is parsed but nothing is signed or validated.
  There's no protection against spoofing beyond random IDs, matching the
  question, and the bailiwick rule (no source-port randomisation logic, no
  0x20 case randomisation).
- Record types: A, AAAA, CNAME, NS, MX, TXT and SOA. Others are carried as
  raw RDATA but can't be written in zone files. There are no wildcards
  (`*.example.com`), DNAME, zone transfers (AXFR/IXFR), dynamic updates or
  NOTIFY.
- The resolver queries over IPv4 or IPv6 using whatever addresses it learns,
  with no RTT-based server selection (it picks at random), no
  prefetch/serve-stale, and no QNAME minimisation.
- The truncation strategy is simple: if the answer doesn't fit, all
  answer/authority data is dropped and TC is set.
- `$INCLUDE` and `$GENERATE` aren't supported in zone files.

## License

MIT. See [LICENSE](LICENSE).
