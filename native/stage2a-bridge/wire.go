package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var invalid = errors.New("invalid bridge protocol")

// validateJSON checks object occurrence before ordinary Go decoding, which
// otherwise accepts duplicate object members. Limit recursive nesting.
func validateJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return invalid
	}
	token, err := decoder.Token()
	if err != nil {
		return invalid
	}
	switch token {
	case json.Delim('{'):
		names := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || names[name] {
				return invalid
			}
			names[name] = true
			if validateJSON(decoder, depth+1) != nil {
				return invalid
			}
		}
	case json.Delim('['):
		for decoder.More() {
			if validateJSON(decoder, depth+1) != nil {
				return invalid
			}
		}
	default:
		return nil
	}
	_, err = decoder.Token()
	return err
}

func decode(data []byte, out any) error {
	if !utf8.Valid(data) {
		return invalid
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	if validateJSON(scan, 0) != nil {
		return invalid
	}
	if _, err := scan.Token(); err != io.EOF {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
