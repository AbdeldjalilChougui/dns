package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Header is the fixed 12-byte message header without the section counts
// (those are derived from the slices).
type Header struct {
	ID                 uint16
	Response           bool // QR
	Opcode             uint8
	Authoritative      bool  // AA
	Truncated          bool  // TC
	RecursionDesired   bool  // RD
	RecursionAvailable bool  // RA
	AuthenticData      bool  // AD
	CheckingDisabled   bool  // CD
	RCode              RCode // low 4 bits on the wire; upper 8 live in OPT
}

type Question struct {
	Name  string
	Type  Type
	Class Class
}

func (q Question) String() string { return fmt.Sprintf("%s %s %s", q.Name, q.Class, q.Type) }

// RR is a resource record.
type RR struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32
	Data  RData
}

func (rr RR) String() string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", rr.Name, rr.TTL, rr.Class, rr.Type, rr.Data)
}

// Message is a whole DNS message.
type Message struct {
	Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

const headerLen = 12

// Pack encodes the message with name compression.
func (m *Message) Pack() ([]byte, error) {
	b := make([]byte, headerLen, 512)
	m.packHeader(b, len(m.Answers), len(m.Authority), len(m.Additional))
	comp := map[string]int{}
	var err error
	for _, q := range m.Questions {
		if b, err = appendName(b, q.Name, comp); err != nil {
			return nil, err
		}
		b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
		b = binary.BigEndian.AppendUint16(b, uint16(q.Class))
	}
	add := m.Additional
	if m.RCode > 0xF && m.OPT() != nil {
		// Extended RCODE: the upper 8 bits travel in the OPT record's TTL.
		add = append([]RR(nil), m.Additional...)
		for i := range add {
			if add[i].Type == TypeOPT {
				add[i].TTL = add[i].TTL&0x00FFFFFF | uint32(m.RCode>>4)<<24
			}
		}
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, add} {
		for _, rr := range sec {
			if b, err = appendRR(b, rr, comp); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// PackLimit encodes the message, dropping records from the end (additional,
// then authority, then answers) and setting TC if it would exceed limit
// bytes. The OPT record is always kept. This is what a UDP server does when
// the client's buffer is too small.
func (m *Message) PackLimit(limit int) ([]byte, error) {
	b, err := m.Pack()
	if err != nil || len(b) <= limit {
		return b, err
	}
	t := *m
	opt := t.OPT()
	t.Additional = nil
	if opt != nil {
		t.Additional = []RR{*opt}
	}
	// Truncation drops the answer/authority data entirely and sets TC so the
	// client retries over TCP (RFC 2181 §9: don't send partial RRsets).
	t.Answers, t.Authority = nil, nil
	t.Truncated = true
	return t.Pack()
}

func (m *Message) packHeader(b []byte, an, ns, ar int) {
	binary.BigEndian.PutUint16(b[0:], m.ID)
	var f uint16
	if m.Response {
		f |= 1 << 15
	}
	f |= uint16(m.Opcode&0xF) << 11
	if m.Authoritative {
		f |= 1 << 10
	}
	if m.Truncated {
		f |= 1 << 9
	}
	if m.RecursionDesired {
		f |= 1 << 8
	}
	if m.RecursionAvailable {
		f |= 1 << 7
	}
	if m.AuthenticData {
		f |= 1 << 5
	}
	if m.CheckingDisabled {
		f |= 1 << 4
	}
	f |= uint16(m.RCode & 0xF)
	binary.BigEndian.PutUint16(b[2:], f)
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(b[6:], uint16(an))
	binary.BigEndian.PutUint16(b[8:], uint16(ns))
	binary.BigEndian.PutUint16(b[10:], uint16(ar))
}

func appendRR(b []byte, rr RR, comp map[string]int) ([]byte, error) {
	var err error
	if b, err = appendName(b, rr.Name, comp); err != nil {
		return b, err
	}
	typ := rr.Type
	if typ == 0 && rr.Data != nil {
		typ = rr.Data.Type()
	}
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Class))
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	lenOff := len(b)
	b = append(b, 0, 0)
	if rr.Data != nil {
		if b, err = rr.Data.pack(b, comp); err != nil {
			return b, err
		}
	}
	rdlen := len(b) - lenOff - 2
	if rdlen > 0xFFFF {
		return b, errors.New("dns: rdata too long")
	}
	binary.BigEndian.PutUint16(b[lenOff:], uint16(rdlen))
	return b, nil
}

// Unpack decodes a message.
func Unpack(msg []byte) (*Message, error) {
	if len(msg) < headerLen {
		return nil, ErrShort
	}
	m := &Message{}
	m.ID = binary.BigEndian.Uint16(msg[0:])
	f := binary.BigEndian.Uint16(msg[2:])
	m.Response = f&(1<<15) != 0
	m.Opcode = uint8(f>>11) & 0xF
	m.Authoritative = f&(1<<10) != 0
	m.Truncated = f&(1<<9) != 0
	m.RecursionDesired = f&(1<<8) != 0
	m.RecursionAvailable = f&(1<<7) != 0
	m.AuthenticData = f&(1<<5) != 0
	m.CheckingDisabled = f&(1<<4) != 0
	m.RCode = RCode(f & 0xF)
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	counts := [3]int{
		int(binary.BigEndian.Uint16(msg[6:])),
		int(binary.BigEndian.Uint16(msg[8:])),
		int(binary.BigEndian.Uint16(msg[10:])),
	}
	off := headerLen
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(msg) {
			return nil, ErrShort
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  Type(binary.BigEndian.Uint16(msg[n:])),
			Class: Class(binary.BigEndian.Uint16(msg[n+2:])),
		})
		off = n + 4
	}
	secs := [3]*[]RR{&m.Answers, &m.Authority, &m.Additional}
	for s, sec := range secs {
		for i := 0; i < counts[s]; i++ {
			rr, n, err := readRR(msg, off)
			if err != nil {
				return nil, fmt.Errorf("section %d record %d: %w", s, i, err)
			}
			*sec = append(*sec, rr)
			off = n
		}
	}
	// The full 12-bit RCODE combines the header with the OPT record.
	if opt := m.OPT(); opt != nil {
		m.RCode |= RCode(opt.TTL>>24) << 4
	}
	return m, nil
}

func readRR(msg []byte, off int) (RR, int, error) {
	name, n, err := readName(msg, off)
	if err != nil {
		return RR{}, 0, err
	}
	if n+10 > len(msg) {
		return RR{}, 0, ErrShort
	}
	rr := RR{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(msg[n:])),
		Class: Class(binary.BigEndian.Uint16(msg[n+2:])),
		TTL:   binary.BigEndian.Uint32(msg[n+4:]),
	}
	rdlen := int(binary.BigEndian.Uint16(msg[n+8:]))
	start := n + 10
	end := start + rdlen
	if end > len(msg) {
		return RR{}, 0, ErrShort
	}
	rr.Data, err = unpackRData(rr.Type, msg, start, end)
	if err != nil {
		return RR{}, 0, fmt.Errorf("%s %s: %w", rr.Name, rr.Type, err)
	}
	return rr, end, nil
}

// Question returns the first question or a zero value.
func (m *Message) Question() Question {
	if len(m.Questions) == 0 {
		return Question{}
	}
	return m.Questions[0]
}

// NewQuery builds a standard query.
func NewQuery(id uint16, name string, t Type, rd bool) *Message {
	return &Message{
		Header:    Header{ID: id, RecursionDesired: rd},
		Questions: []Question{{Name: Fqdn(name), Type: t, Class: ClassINET}},
	}
}

// Reply creates a response skeleton that echoes the query's ID, opcode,
// RD/CD bits and question.
func (m *Message) Reply() *Message {
	return &Message{
		Header: Header{
			ID: m.ID, Response: true, Opcode: m.Opcode,
			RecursionDesired: m.RecursionDesired, CheckingDisabled: m.CheckingDisabled,
		},
		Questions: append([]Question(nil), m.Questions...),
	}
}

func (m *Message) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, ";; id=%d rcode=%s qr=%v aa=%v tc=%v rd=%v ra=%v\n",
		m.ID, m.RCode, m.Response, m.Authoritative, m.Truncated, m.RecursionDesired, m.RecursionAvailable)
	for _, q := range m.Questions {
		fmt.Fprintf(&sb, ";%s\n", q)
	}
	for _, sec := range []struct {
		n   string
		rrs []RR
	}{{"ANSWER", m.Answers}, {"AUTHORITY", m.Authority}, {"ADDITIONAL", m.Additional}} {
		if len(sec.rrs) > 0 {
			fmt.Fprintf(&sb, ";; %s\n", sec.n)
			for _, rr := range sec.rrs {
				sb.WriteString(rr.String())
				sb.WriteByte('\n')
			}
		}
	}
	return sb.String()
}
