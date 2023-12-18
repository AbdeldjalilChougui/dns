package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

// EDNS0 (RFC 6891) reuses RR fields in the OPT pseudo-record:
//
//	NAME  = root
//	CLASS = requester's UDP payload size
//	TTL   = extended RCODE (8) | version (8) | DO bit (1) | zero (15)
//	RDATA = {option code, option length, option data}*

// EDNSOption is one {code, data} option, e.g. a cookie (10) or padding (12).
type EDNSOption struct {
	Code uint16
	Data []byte
}

// OPTData is the RDATA of an OPT record.
type OPTData struct{ Options []EDNSOption }

func (*OPTData) Type() Type { return TypeOPT }
func (o *OPTData) String() string {
	return fmt.Sprintf("%d options", len(o.Options))
}
func (o *OPTData) pack(b []byte, _ map[string]int) ([]byte, error) {
	for _, opt := range o.Options {
		b = binary.BigEndian.AppendUint16(b, opt.Code)
		b = binary.BigEndian.AppendUint16(b, uint16(len(opt.Data)))
		b = append(b, opt.Data...)
	}
	return b, nil
}

func unpackOPT(rd []byte) (RData, error) {
	o := &OPTData{}
	for p := 0; p < len(rd); {
		if p+4 > len(rd) {
			return nil, ErrShort
		}
		code := binary.BigEndian.Uint16(rd[p:])
		l := int(binary.BigEndian.Uint16(rd[p+2:]))
		if p+4+l > len(rd) {
			return nil, ErrShort
		}
		o.Options = append(o.Options, EDNSOption{code, append([]byte(nil), rd[p+4:p+4+l]...)})
		p += 4 + l
	}
	return o, nil
}

// EDNS is the decoded view of an OPT record.
type EDNS struct {
	UDPSize uint16
	Version uint8
	DO      bool // DNSSEC OK
	Options []EDNSOption
}

// OPT returns the OPT record from the additional section, if any.
func (m *Message) OPT() *RR {
	for i := range m.Additional {
		if m.Additional[i].Type == TypeOPT {
			return &m.Additional[i]
		}
	}
	return nil
}

// EDNS decodes the OPT record; ok is false when the message has none.
func (m *Message) EDNS() (e EDNS, ok bool) {
	rr := m.OPT()
	if rr == nil {
		return EDNS{}, false
	}
	e.UDPSize = uint16(rr.Class)
	e.Version = uint8(rr.TTL >> 16)
	e.DO = rr.TTL&(1<<15) != 0
	if d, ok := rr.Data.(*OPTData); ok {
		e.Options = d.Options
	}
	return e, true
}

// SetEDNS adds or replaces the OPT record. The upper bits of m.RCode are
// stored in it when the message is packed.
func (m *Message) SetEDNS(e EDNS) {
	ttl := uint32(e.Version) << 16
	if e.DO {
		ttl |= 1 << 15
	}
	ttl |= uint32(m.RCode>>4) << 24
	rr := RR{Name: ".", Type: TypeOPT, Class: Class(e.UDPSize), TTL: ttl, Data: &OPTData{Options: e.Options}}
	if old := m.OPT(); old != nil {
		*old = rr
		return
	}
	m.Additional = append(m.Additional, rr)
}

// MaxUDPSize is the response size limit for a query: the EDNS buffer size
// (at least 512) or 512 without EDNS.
func (m *Message) MaxUDPSize() int {
	if e, ok := m.EDNS(); ok && e.UDPSize > 512 {
		return int(e.UDPSize)
	}
	return 512
}
