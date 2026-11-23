package main

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Stage 2a signed records contain integers, strings, booleans, null, arrays
// and objects. Reject all non-integer JSON numbers, including negative zero,
// rather than guessing a floating-point JCS representation. Every signed
// Machine record in this protocol uses integer numeric fields.
func jcsValue(value any, out *bytes.Buffer) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		if e.Encode(v) != nil {
			return invalid
		}
		s := strings.TrimSuffix(b.String(), "\n")
		s = strings.ReplaceAll(s, `\u2028`, "\u2028")
		s = strings.ReplaceAll(s, `\u2029`, "\u2029")
		out.WriteString(s)
	case json.Number:
		s := string(v)
		if s == "-0" || !regexpInteger.MatchString(s) {
			return invalid
		}
		n, err := strconv.ParseInt(s, 10, 64)
		const maxSafe = (1 << 53) - 1
		if err != nil || n < -maxSafe || n > maxSafe {
			return invalid
		}
		out.WriteString(s)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if jcsValue(item, out) != nil {
				return invalid
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
			for n := 0; n < len(a) && n < len(b); n++ {
				if a[n] != b[n] {
					return a[n] < b[n]
				}
			}
			return len(a) < len(b)
		})
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if jcsValue(key, out) != nil {
				return invalid
			}
			out.WriteByte(':')
			if jcsValue(v[key], out) != nil {
				return invalid
			}
		}
		out.WriteByte('}')
	default:
		return invalid
	}
	return nil
}

func canonicalSignedJSON(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > 16384 {
		return nil, invalid
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	if validateJSON(scan, 0) != nil {
		return nil, invalid
	}
	if _, err := scan.Token(); err != io.EOF {
		return nil, invalid
	}
	var value any
	read := json.NewDecoder(bytes.NewReader(data))
	read.UseNumber()
	if read.Decode(&value) != nil {
		return nil, invalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalid
	}
	var out bytes.Buffer
	if jcsValue(object, &out) != nil || !bytes.Equal(out.Bytes(), data) {
		return nil, invalid
	}
	return object, nil
}

var regexpInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
