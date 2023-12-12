package dnsmsg

import (
	"errors"
	"strings"
)

// Names are presentation-format strings ending in a dot: "www.example.com.".
// The root is ".". A dot inside a label is escaped as "\." and other unusual
// bytes as "\DDD".

var (
	ErrLabelTooLong = errors.New("dns: label longer than 63 bytes")
	ErrNameTooLong  = errors.New("dns: name longer than 255 bytes")
	ErrBadPointer   = errors.New("dns: bad compression pointer")
	ErrShort        = errors.New("dns: message too short")
)

// Fqdn adds the trailing dot if missing.
func Fqdn(name string) string {
	if strings.HasSuffix(name, ".") && !strings.HasSuffix(name, `\.`) {
		return name
	}
	return name + "."
}

// CanonicalName lower-cases a name and makes it fully qualified. DNS name
// comparison is case-insensitive for ASCII.
func CanonicalName(name string) string {
	return strings.ToLower(Fqdn(name))
}

// IsSubdomain reports whether child is equal to or below parent.
func IsSubdomain(child, parent string) bool {
	child, parent = CanonicalName(child), CanonicalName(parent)
	if parent == "." || child == parent {
		return true
	}
	return strings.HasSuffix(child, "."+parent) && !strings.HasSuffix(child, `\.`+parent)
}

// Parent strips the left-most label: "a.b.c." -> "b.c.", "c." -> ".".
func Parent(name string) string {
	labels, _ := splitLabels(Fqdn(name))
	if len(labels) <= 1 {
		return "."
	}
	return joinLabels(labels[1:])
}

// CountLabels returns the number of labels ("." has 0).
func CountLabels(name string) int {
	l, _ := splitLabels(Fqdn(name))
	return len(l)
}

// splitLabels converts a presentation name into raw label bytes.
func splitLabels(name string) ([][]byte, error) {
	if name == "." || name == "" {
		return nil, nil
	}
	var labels [][]byte
	var cur []byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '\\' && i+3 < len(name) && isDigit(name[i+1]) && isDigit(name[i+2]) && isDigit(name[i+3]):
			v := int(name[i+1]-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
			if v > 255 {
				return nil, errors.New("dns: bad \\DDD escape")
			}
			cur = append(cur, byte(v))
			i += 3
		case c == '\\' && i+1 < len(name):
			cur = append(cur, name[i+1])
			i++
		case c == '.':
			if len(cur) == 0 {
				return nil, errors.New("dns: empty label in " + name)
			}
			labels = append(labels, cur)
			cur = nil
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		labels = append(labels, cur)
	}
	total := 1
	for _, l := range labels {
		if len(l) > 63 {
			return nil, ErrLabelTooLong
		}
		total += len(l) + 1
	}
	if total > 255 {
		return nil, ErrNameTooLong
	}
	return labels, nil
}

func joinLabels(labels [][]byte) string {
	if len(labels) == 0 {
		return "."
	}
	var sb strings.Builder
	for _, l := range labels {
		for _, c := range l {
			switch {
			case c == '.' || c == '\\':
				sb.WriteByte('\\')
				sb.WriteByte(c)
			case c < '!' || c > '~':
				sb.WriteByte('\\')
				sb.WriteByte('0' + c/100)
				sb.WriteByte('0' + c/10%10)
				sb.WriteByte('0' + c%10)
			default:
				sb.WriteByte(c)
			}
		}
		sb.WriteByte('.')
	}
	return sb.String()
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// appendName writes name, reusing earlier suffixes through compression
// pointers when comp is non-nil (RFC 1035 §4.1.4).
func appendName(b []byte, name string, comp map[string]int) ([]byte, error) {
	labels, err := splitLabels(Fqdn(name))
	if err != nil {
		return b, err
	}
	for i := range labels {
		if comp != nil {
			key := strings.ToLower(joinLabels(labels[i:]))
			if off, ok := comp[key]; ok {
				return append(b, byte(0xC0|off>>8), byte(off)), nil
			}
			if len(b) < 0x3FFF {
				comp[key] = len(b)
			}
		}
		b = append(b, byte(len(labels[i])))
		b = append(b, labels[i]...)
	}
	return append(b, 0), nil
}

// readName decodes a possibly compressed name at off. It returns the name
// and the offset just after the name in the original position.
func readName(msg []byte, off int) (string, int, error) {
	var labels [][]byte
	end := -1
	total := 1
	// Each pointer must point strictly backwards, which rules out loops.
	limit := off
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if end < 0 {
					end = off + 1
				}
				return joinLabels(labels), end, nil
			}
			if off+1+c > len(msg) {
				return "", 0, ErrShort
			}
			total += c + 1
			if total > 255 {
				return "", 0, ErrNameTooLong
			}
			labels = append(labels, msg[off+1:off+1+c])
			off += 1 + c
		case 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrShort
			}
			ptr := (c&0x3F)<<8 | int(msg[off+1])
			if end < 0 {
				end = off + 2
			}
			if ptr >= limit {
				return "", 0, ErrBadPointer
			}
			jumps++
			if jumps > 64 {
				return "", 0, ErrBadPointer
			}
			limit, off = ptr, ptr
		default:
			return "", 0, errors.New("dns: reserved label type")
		}
	}
}
