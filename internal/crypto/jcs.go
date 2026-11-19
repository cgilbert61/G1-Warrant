package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// CanonicalizeJSON implements RFC 8785 JSON Canonicalization Scheme (JCS).
// It parses arbitrary JSON bytes and emits deterministic UTF-8 canonical JSON:
//   - No insignificant whitespace
//   - Object properties sorted lexicographically by UTF-16 code units
//   - Minimal string escaping per RFC 8785 Section 3.2.2.2
//   - Deterministic IEEE-754 number formatting per RFC 8785 Section 3.2.2.3
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("jcs decode failed: %w", err)
	}
	var trailing any
	if dec.Decode(&trailing) == nil {
		return nil, errors.New("jcs decode failed: trailing tokens after top-level value")
	}
	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeStruct marshals a typed Go value and returns its RFC 8785 JCS bytes.
func CanonicalizeStruct(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs marshal struct: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalSHA256Hex computes the SHA-256 hex digest of the RFC 8785 canonical JSON of v.
func CanonicalSHA256Hex(v any) (string, []byte, error) {
	canon, err := CanonicalizeStruct(v)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), canon, nil
}

// SHA256Hex returns the lowercase hex SHA-256 digest of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeCanonicalValue(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		formatted, err := formatJCSNumber(val.String())
		if err != nil {
			return err
		}
		buf.WriteString(formatted)
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return errors.New("jcs prohibits NaN or Infinity")
		}
		formatted, err := formatFloat64JCS(val)
		if err != nil {
			return err
		}
		buf.WriteString(formatted)
	case string:
		writeJCSString(buf, val)
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		canon, err := CanonicalizeJSON(raw)
		if err != nil {
			return err
		}
		buf.Write(canon)
	}
	return nil
}

func compareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	minLen := len(ua)
	if len(ub) < minLen {
		minLen = len(ub)
	}
	for i := 0; i < minLen; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}

func writeJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			if r >= 0x00 && r <= 0x1F {
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func formatJCSNumber(numStr string) (string, error) {
	f, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return "", fmt.Errorf("invalid json number %q: %w", numStr, err)
	}
	return formatFloat64JCS(f)
}

func formatFloat64JCS(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs prohibits NaN or Infinity")
	}
	if f == 0 {
		return "0", nil
	}
	abs := math.Abs(f)
	// ES6 / RFC 8785 exponential vs fixed range: [1e-6, 1e21) uses fixed decimal
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	// Normalize exponent e+05 -> e+5 and e-07 -> e-7 per ES6 Number.toString()
	for i := 0; i < len(s); i++ {
		if s[i] == 'e' || s[i] == 'E' {
			mantissa := s[:i]
			sign := s[i+1]
			expDigits := s[i+2:]
			for len(expDigits) > 1 && expDigits[0] == '0' {
				expDigits = expDigits[1:]
			}
			return mantissa + "e" + string(sign) + expDigits, nil
		}
	}
	return s, nil
}
