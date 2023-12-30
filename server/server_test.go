package server_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
	"github.com/AbdeldjalilChougui/dns/resolver"
	"github.com/AbdeldjalilChougui/dns/server"
	"github.com/AbdeldjalilChougui/dns/zone"
)

func start(t *testing.T, zones ...*zone.Zone) (*server.Server, netip.AddrPort) {
	t.Helper()
	s := &server.Server{Handler: &server.Authoritative{Zones: zones}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeUDP(pc)
	go s.ServeTCP(ln)
	t.Cleanup(func() { s.Close() })
	return s, netip.MustParseAddrPort(pc.LocalAddr().String())
}

func exampleZone(t *testing.T) *zone.Zone {
	f, err := os.Open("../testdata/example.com.zone")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.Parse(f, ".")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

var ctx = context.Background()

func TestUDPQuery(t *testing.T) {
	_, addr := start(t, exampleZone(t))
	ex := &resolver.NetExchanger{Timeout: 2 * time.Second}
	q := dnsmsg.NewQuery(99, "www.example.com", dnsmsg.TypeA, false)
	resp, err := ex.Exchange(ctx, q, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Authoritative || len(resp.Answers) != 1 || resp.Answers[0].Data.String() != "192.0.2.10" {
		t.Fatalf("%s", resp)
	}
	if _, ok := resp.EDNS(); ok {
		t.Fatal("no EDNS in query, so none expected in the answer")
	}
	q.SetEDNS(dnsmsg.EDNS{UDPSize: 4096})
	resp, _ = ex.Exchange(ctx, q, addr)
	if e, ok := resp.EDNS(); !ok || e.UDPSize != 1232 {
		t.Fatalf("EDNS answer %+v %v", e, ok)
	}
}

func TestRefusedOutsideZones(t *testing.T) {
	_, addr := start(t, exampleZone(t))
	ex := &resolver.NetExchanger{}
	resp, err := ex.Exchange(ctx, dnsmsg.NewQuery(1, "example.org", dnsmsg.TypeA, false), addr)
	if err != nil || resp.RCode != dnsmsg.RCodeRefused {
		t.Fatalf("%v %v", err, resp)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	var zt strings.Builder
	zt.WriteString("$ORIGIN big.test.\n@ SOA ns host 1 2 3 4 5\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&zt, "txt TXT \"%s-%02d\"\n", strings.Repeat("x", 100), i)
	}
	z, err := zone.Parse(strings.NewReader(zt.String()), ".")
	if err != nil {
		t.Fatal(err)
	}
	_, addr := start(t, z)

	// Raw UDP without EDNS: must be truncated to 512 bytes with TC set.
	conn, _ := net.Dial("udp", addr.String())
	defer conn.Close()
	b, _ := dnsmsg.NewQuery(5, "txt.big.test", dnsmsg.TypeTXT, false).Pack()
	conn.Write(b)
	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := dnsmsg.Unpack(buf[:n])
	if n > 512 || !m.Truncated {
		t.Fatalf("udp reply %d bytes, tc=%v", n, m.Truncated)
	}
	// The exchanger retries over TCP and gets everything.
	resp, err := (&resolver.NetExchanger{}).Exchange(ctx, dnsmsg.NewQuery(6, "txt.big.test", dnsmsg.TypeTXT, false), addr)
	if err != nil || resp.Truncated || len(resp.Answers) != 30 {
		t.Fatalf("tcp: %v tc=%v answers=%d", err, resp.Truncated, len(resp.Answers))
	}
}

func TestProtocolErrors(t *testing.T) {
	s := &server.Server{Handler: &server.Authoritative{Zones: []*zone.Zone{exampleZone(t)}}}
	// Garbage after a valid header → FORMERR echoing the ID.
	out := s.Handle(ctx, []byte{0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xFF}, true)
	m, err := dnsmsg.Unpack(out)
	if err != nil || m.ID != 0xABCD || m.RCode != dnsmsg.RCodeFormatError {
		t.Fatalf("%v %v", err, m)
	}
	if s.Handle(ctx, []byte{1, 2}, true) != nil {
		t.Fatal("answered a 2-byte packet")
	}
	// EDNS version 1 → BADVERS (extended rcode).
	q := dnsmsg.NewQuery(7, "www.example.com", dnsmsg.TypeA, false)
	q.SetEDNS(dnsmsg.EDNS{UDPSize: 1232, Version: 1})
	raw, _ := q.Pack()
	m, _ = dnsmsg.Unpack(s.Handle(ctx, raw, true))
	if m.RCode != dnsmsg.RCodeBadVers {
		t.Fatalf("rcode %v", m.RCode)
	}
	// Non-zero opcode → NOTIMP.
	q = dnsmsg.NewQuery(8, "www.example.com", dnsmsg.TypeA, false)
	q.Opcode = 2
	raw, _ = q.Pack()
	m, _ = dnsmsg.Unpack(s.Handle(ctx, raw, true))
	if m.RCode != dnsmsg.RCodeNotImplemented {
		t.Fatalf("rcode %v", m.RCode)
	}
	// Responses are ignored.
	q.Response = true
	raw, _ = q.Pack()
	if s.Handle(ctx, raw, true) != nil {
		t.Fatal("answered a response")
	}
}
