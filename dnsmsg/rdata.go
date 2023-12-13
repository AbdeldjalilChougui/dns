package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RData is the type-specific part of a record.
type RData interface {
	Type() Type
	String() string
	pack(b []byte, comp map[string]int) ([]byte, error)
}

type A struct{ Addr netip.Addr }
type AAAA struct{ Addr netip.Addr }
type CNAME struct{ Target string }
type NS struct{ Host string }
type MX struct {
	Preference uint16
	Exchange   string
}
type TXT struct{ Texts []string }
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

// Unknown keeps the raw bytes of a type we don't parse (RFC 3597).
type Unknown struct {
	T   Type
	Raw []byte
}

func (*A) Type() Type         { return TypeA }
func (*AAAA) Type() Type      { return TypeAAAA }
func (*CNAME) Type() Type     { return TypeCNAME }
func (*NS) Type() Type        { return TypeNS }
func (*MX) Type() Type        { return TypeMX }
func (*TXT) Type() Type       { return TypeTXT }
func (*SOA) Type() Type       { return TypeSOA }
func (u *Unknown) Type() Type { return u.T }

func (r *A) String() string     { return r.Addr.String() }
func (r *AAAA) String() string  { return r.Addr.String() }
func (r *CNAME) String() string { return r.Target }
func (r *NS) String() string    { return r.Host }
func (r *MX) String() string    { return fmt.Sprintf("%d %s", r.Preference, r.Exchange) }
func (r *TXT) String() string {
	q := make([]string, len(r.Texts))
	for i, t := range r.Texts {
		q[i] = strconv.Quote(t)
	}
	return strings.Join(q, " ")
}
func (r *SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
}
func (u *Unknown) String() string { return fmt.Sprintf(`\# %d %x`, len(u.Raw), u.Raw) }

func (r *A) pack(b []byte, _ map[string]int) ([]byte, error) {
	if !r.Addr.Is4() {
		return b, errors.New("dns: A record needs an IPv4 address")
	}
	a := r.Addr.As4()
	return append(b, a[:]...), nil
}

func (r *AAAA) pack(b []byte, _ map[string]int) ([]byte, error) {
	if !r.Addr.Is6() || r.Addr.Is4In6() {
		return b, errors.New("dns: AAAA record needs an IPv6 address")
	}
	a := r.Addr.As16()
	return append(b, a[:]...), nil
}

// Names inside CNAME/NS/MX/SOA rdata may be compressed (RFC 3597 §4).
func (r *CNAME) pack(b []byte, c map[string]int) ([]byte, error) { return appendName(b, r.Target, c) }
func (r *NS) pack(b []byte, c map[string]int) ([]byte, error)    { return appendName(b, r.Host, c) }
func (r *MX) pack(b []byte, c map[string]int) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.Preference)
	return appendName(b, r.Exchange, c)
}

func (r *TXT) pack(b []byte, _ map[string]int) ([]byte, error) {
	if len(r.Texts) == 0 {
		return append(b, 0), nil // one empty string
	}
	for _, t := range r.Texts {
		if len(t) > 255 {
			return b, errors.New("dns: TXT character-string longer than 255 bytes")
		}
		b = append(b, byte(len(t)))
		b = append(b, t...)
	}
	return b, nil
}

func (r *SOA) pack(b []byte, c map[string]int) ([]byte, error) {
	var err error
	if b, err = appendName(b, r.MName, c); err != nil {
		return b, err
	}
	if b, err = appendName(b, r.RName, c); err != nil {
		return b, err
	}
	for _, v := range []uint32{r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b, nil
}

func (u *Unknown) pack(b []byte, _ map[string]int) ([]byte, error) { return append(b, u.Raw...), nil }

// unpackRData decodes msg[start:end]. Names are read with the whole message
// so compression pointers resolve.
func unpackRData(t Type, msg []byte, start, end int) (RData, error) {
	rd := msg[start:end]
	nameAt := func(off int) (string, int, error) {
		n, next, err := readName(msg[:end], off)
		return n, next, err
	}
	switch t {
	case TypeA:
		if len(rd) != 4 {
			return nil, errors.New("bad A length")
		}
		return &A{netip.AddrFrom4([4]byte(rd))}, nil
	case TypeAAAA:
		if len(rd) != 16 {
			return nil, errors.New("bad AAAA length")
		}
		return &AAAA{netip.AddrFrom16([16]byte(rd))}, nil
	case TypeCNAME, TypeNS:
		n, next, err := nameAt(start)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, errors.New("trailing bytes after name")
		}
		if t == TypeNS {
			return &NS{n}, nil
		}
		return &CNAME{n}, nil
	case TypeMX:
		if len(rd) < 3 {
			return nil, ErrShort
		}
		n, next, err := nameAt(start + 2)
		if err != nil {
			return nil, err
		}
		if next != end {
			return nil, errors.New("trailing bytes after name")
		}
		return &MX{binary.BigEndian.Uint16(rd), n}, nil
	case TypeTXT:
		var texts []string
		for p := 0; p < len(rd); {
			l := int(rd[p])
			if p+1+l > len(rd) {
				return nil, ErrShort
			}
			texts = append(texts, string(rd[p+1:p+1+l]))
			p += 1 + l
		}
		return &TXT{texts}, nil
	case TypeSOA:
		mname, next, err := nameAt(start)
		if err != nil {
			return nil, err
		}
		rname, next, err := nameAt(next)
		if err != nil {
			return nil, err
		}
		if end-next != 20 {
			return nil, errors.New("bad SOA length")
		}
		v := func(i int) uint32 { return binary.BigEndian.Uint32(msg[next+4*i:]) }
		return &SOA{mname, rname, v(0), v(1), v(2), v(3), v(4)}, nil
	case TypeOPT:
		return unpackOPT(rd)
	}
	return &Unknown{T: t, Raw: append([]byte(nil), rd...)}, nil
}
