package main

import (
	"sort"
	"strings"
)

type observedHeaderShape struct {
	Schema           string            `json:"schema"`
	Host             string            `json:"host"`
	RequiredFixed    map[string]string `json:"required_fixed"`
	RequiredVolatile map[string]string `json:"required_volatile"`
	Forbidden        []string          `json:"forbidden"`
	AllowExtra       bool              `json:"allow_extra"`
}

type observedAncillaryPolicy struct {
	Schema               string              `json:"schema"`
	BodyProfile          string              `json:"body_profile"`
	NormalizedBodySHA256 string              `json:"normalized_body_sha256"`
	FirstHeaderShape     observedHeaderShape `json:"first_header_shape"`
	FirstHeadersSHA256   string              `json:"first_headers_sha256"`
	SecondHeaderShape    observedHeaderShape `json:"second_header_shape"`
	SecondHeadersSHA256  string              `json:"second_headers_sha256"`
	Order                []string            `json:"order"`
	TargetAfter          []string            `json:"target_after"`
	MaxAncillary         int                 `json:"max_ancillary"`
	AncillaryHTTPStatus  int                 `json:"ancillary_http_status"`
}

var observedVolatileHeaderGrammar = map[string]string{
	"content-length":           "decimal-buffered-body-bytes/v1",
	"x-api-key":                "signed-client-key-sha256/v1",
	"x-claude-code-session-id": "uuid/v1",
}

var observedForbiddenHeaders = []string{"authorization", "cookie", "proxy-authorization"}

func (shape observedHeaderShape) validate(schema, host string) error {
	if shape.Schema != schema || shape.Host != host || shape.AllowExtra ||
		len(shape.RequiredFixed) != len(observedFixedHeaderNames) ||
		len(shape.RequiredVolatile) != len(observedVolatileHeaderGrammar) ||
		len(shape.Forbidden) != len(observedForbiddenHeaders) ||
		!idPattern.MatchString(host) {
		return invalid
	}
	for name, expected := range observedVolatileHeaderGrammar {
		if shape.RequiredVolatile[name] != expected {
			return invalid
		}
	}
	for index, name := range observedForbiddenHeaders {
		if shape.Forbidden[index] != name {
			return invalid
		}
	}
	for _, name := range observedFixedHeaderNames {
		value, ok := shape.RequiredFixed[name]
		if !ok || value == "" || strings.ContainsAny(value, "\r\n") {
			return invalid
		}
	}
	if shape.RequiredFixed["accept"] != "application/json" ||
		shape.RequiredFixed["content-type"] != "application/json" ||
		shape.RequiredFixed["x-stainless-retry-count"] != "0" {
		return invalid
	}
	return nil
}

func (shape observedHeaderShape) validateSigned(wantSHA256, schema, host string) error {
	if !validDigest(wantSHA256) || shape.validate(schema, host) != nil {
		return invalid
	}
	canonical, err := canonicalJSONValue(shape)
	if err != nil || digest(canonical) != wantSHA256 {
		return invalid
	}
	return nil
}

func observedFixedHeadersDigest(fixed map[string]string) string {
	names := make([]string, 0, len(fixed))
	for name := range fixed {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(fixed[name])
		canonical.WriteByte('\n')
	}
	return digest([]byte(canonical.String()))
}

func (p observedAncillaryPolicy) validate(wantSHA256, host string) error {
	if !validDigest(wantSHA256) || p.Schema != "stage2a-stock-ancillary-local-test-profile/v1" ||
		p.BodyProfile != "stage2a-stock-ancillary-one-block/v1" ||
		!validDigest(p.NormalizedBodySHA256) ||
		p.FirstHeaderShape.validate("stage2a-stock-ancillary-header-shape/v1", host) != nil ||
		p.SecondHeaderShape.validate("stage2a-stock-ancillary-header-shape/v1", host) != nil ||
		!validDigest(p.FirstHeadersSHA256) || !validDigest(p.SecondHeadersSHA256) ||
		p.FirstHeadersSHA256 == p.SecondHeadersSHA256 ||
		observedFixedHeadersDigest(p.FirstHeaderShape.RequiredFixed) != p.FirstHeadersSHA256 ||
		observedFixedHeadersDigest(p.SecondHeaderShape.RequiredFixed) != p.SecondHeadersSHA256 ||
		len(p.Order) != 2 || p.Order[0] != "first" || p.Order[1] != "second" ||
		len(p.TargetAfter) != 1 || p.TargetAfter[0] != "first" ||
		p.MaxAncillary != 2 || p.AncillaryHTTPStatus != 422 {
		return invalid
	}
	canonical, err := canonicalJSONValue(p)
	if err != nil || digest(canonical) != wantSHA256 {
		return invalid
	}
	return nil
}
