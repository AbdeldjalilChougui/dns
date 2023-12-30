// Package server runs a DNS handler over UDP and TCP.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
	"github.com/AbdeldjalilChougui/dns/zone"
)

// Handler answers one query. req has passed basic validation (one question,
// standard opcode, EDNS version 0). The returned message should be built
// with req.Reply().
type Handler interface {
	ServeDNS(ctx context.Context, req *dnsmsg.Message) *dnsmsg.Message
}

type HandlerFunc func(ctx context.Context, req *dnsmsg.Message) *dnsmsg.Message

func (f HandlerFunc) ServeDNS(ctx context.Context, req *dnsmsg.Message) *dnsmsg.Message {
	return f(ctx, req)
}

// Server serves a Handler. UDPSize is the EDNS buffer size we advertise
// (default 1232, the DNS Flag Day 2020 recommendation).
type Server struct {
	Handler Handler
	UDPSize uint16
	Log     *slog.Logger

	mu      sync.Mutex
	closers map[io.Closer]struct{}
	wg      sync.WaitGroup
}

func (s *Server) udpSize() uint16 {
	if s.UDPSize == 0 {
		return 1232
	}
	return s.UDPSize
}

func (s *Server) track(c io.Closer) {
	s.mu.Lock()
	if s.closers == nil {
		s.closers = map[io.Closer]struct{}{}
	}
	s.closers[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.closers, c)
	s.mu.Unlock()
}

// Close stops all listeners and waits for in-flight queries.
func (s *Server) Close() error {
	s.mu.Lock()
	for c := range s.closers {
		c.Close()
	}
	s.closers = nil
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// Handle turns raw query bytes into raw response bytes; limit is the
// maximum size (UDP) or 0 for no limit (TCP). It returns nil when the input
// is too broken to answer at all.
func (s *Server) Handle(ctx context.Context, raw []byte, udp bool) []byte {
	req, err := dnsmsg.Unpack(raw)
	if err != nil {
		if len(raw) < 12 {
			return nil
		}
		// Answer FORMERR with the original ID so the client stops waiting.
		resp := &dnsmsg.Message{Header: dnsmsg.Header{ID: binary.BigEndian.Uint16(raw), Response: true, RCode: dnsmsg.RCodeFormatError}}
		b, _ := resp.Pack()
		return b
	}
	if req.Response {
		return nil // never answer answers
	}
	resp := s.dispatch(ctx, req)
	_, hasEDNS := req.EDNS()
	if hasEDNS {
		resp.SetEDNS(dnsmsg.EDNS{UDPSize: s.udpSize()})
	}
	var b []byte
	if udp {
		limit := min(req.MaxUDPSize(), int(s.udpSize()))
		if !hasEDNS {
			limit = 512
		}
		b, err = resp.PackLimit(limit)
	} else {
		b, err = resp.Pack()
	}
	if err != nil {
		if s.Log != nil {
			s.Log.Error("pack response", "err", err)
		}
		fail := req.Reply()
		fail.RCode = dnsmsg.RCodeServerFailure
		b, _ = fail.Pack()
	}
	return b
}

func (s *Server) dispatch(ctx context.Context, req *dnsmsg.Message) *dnsmsg.Message {
	fail := func(rc dnsmsg.RCode) *dnsmsg.Message {
		r := req.Reply()
		r.RCode = rc
		return r
	}
	if req.Opcode != 0 {
		return fail(dnsmsg.RCodeNotImplemented)
	}
	if len(req.Questions) != 1 {
		return fail(dnsmsg.RCodeFormatError)
	}
	if e, ok := req.EDNS(); ok && e.Version > 0 {
		return fail(dnsmsg.RCodeBadVers)
	}
	resp := s.Handler.ServeDNS(ctx, req)
	if resp == nil {
		return fail(dnsmsg.RCodeServerFailure)
	}
	return resp
}

// ServeUDP answers queries arriving on pc until it is closed.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	s.track(pc)
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		raw := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if out := s.Handle(ctx, raw, true); out != nil {
				pc.WriteTo(out, addr)
			}
		}()
	}
}

// ServeTCP answers length-prefixed queries (RFC 1035 §4.2.2, RFC 7766),
// several per connection.
func (s *Server) ServeTCP(ln net.Listener) error {
	s.track(ln)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.track(c)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer c.Close()
			for {
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				raw, err := ReadTCPMessage(c)
				if err != nil {
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				out := s.Handle(ctx, raw, false)
				cancel()
				if out == nil || WriteTCPMessage(c, out) != nil {
					return
				}
			}
		}()
	}
}

// ListenAndServe serves on addr over both UDP and TCP.
func (s *Server) ListenAndServe(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- s.ServeUDP(pc) }()
	go func() { errc <- s.ServeTCP(ln) }()
	return <-errc
}

func ReadTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func WriteTCPMessage(w io.Writer, b []byte) error {
	if len(b) > 0xFFFF {
		return errors.New("dns: message too large for TCP")
	}
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	return err
}

// Authoritative serves a set of zones, picking the most specific zone that
// contains the query name. Names in none of them are REFUSED.
type Authoritative struct {
	Zones []*zone.Zone
}

func (a *Authoritative) ServeDNS(_ context.Context, req *dnsmsg.Message) *dnsmsg.Message {
	resp := req.Reply()
	resp.RecursionDesired = req.RecursionDesired
	q := req.Question()
	var best *zone.Zone
	for _, z := range a.Zones {
		if dnsmsg.IsSubdomain(q.Name, z.Origin) && (best == nil || dnsmsg.CountLabels(z.Origin) > dnsmsg.CountLabels(best.Origin)) {
			best = z
		}
	}
	if best == nil || q.Class != dnsmsg.ClassINET {
		resp.RCode = dnsmsg.RCodeRefused
		return resp
	}
	best.Answer(q, resp)
	return resp
}
