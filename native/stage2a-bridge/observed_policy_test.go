package main

import (
	"strings"
	"testing"
)

func observedAncillaryPolicyFixture(t *testing.T) (observedAncillaryPolicy, string) {
	t.Helper()
	_, header := observedHeaderFixture()
	shape := observedHeaderShape{
		Schema: "stage2a-stock-ancillary-header-shape/v1", Host: header.Host,
		RequiredFixed: header.RequiredFixed,
		RequiredVolatile: map[string]string{
			"content-length":           "decimal-buffered-body-bytes/v1",
			"x-api-key":                "signed-client-key-sha256/v1",
			"x-claude-code-session-id": "uuid/v1",
		},
		Forbidden: []string{"authorization", "cookie", "proxy-authorization"},
	}
	second := shape
	second.RequiredFixed = make(map[string]string, len(shape.RequiredFixed))
	for name, value := range shape.RequiredFixed {
		second.RequiredFixed[name] = value
	}
	second.RequiredFixed["anthropic-beta"] = "second-value"
	p := observedAncillaryPolicy{
		Schema:               "stage2a-stock-ancillary-local-test-profile/v1",
		BodyProfile:          "stage2a-stock-ancillary-one-block/v1",
		NormalizedBodySHA256: digest([]byte("synthetic source body")),
		FirstHeaderShape:     shape, FirstHeadersSHA256: observedFixedHeadersDigest(shape.RequiredFixed),
		SecondHeaderShape: second, SecondHeadersSHA256: observedFixedHeadersDigest(second.RequiredFixed),
		Order: []string{"first", "second"}, TargetAfter: []string{"first"},
		MaxAncillary: 2, AncillaryHTTPStatus: 422,
	}
	canonical, err := canonicalJSONValue(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, digest(canonical)
}

func TestObservedAncillaryPolicyIsExactAndDigestBound(t *testing.T) {
	p, signedSHA := observedAncillaryPolicyFixture(t)
	if err := p.validate(signedSHA, "fixture.invalid"); err != nil {
		t.Fatalf("signed ancillary profile refused: %v", err)
	}
	for name, change := range map[string]func(*observedAncillaryPolicy){
		"wrong_signature_digest": func(p *observedAncillaryPolicy) {},
		"extra_header": func(p *observedAncillaryPolicy) {
			p.FirstHeaderShape.RequiredFixed["authorization"] = "unexpected"
		},
		"wrong_beta": func(p *observedAncillaryPolicy) {
			p.SecondHeaderShape.RequiredFixed["anthropic-beta"] = "changed"
		},
		"wrong_volatile_grammar": func(p *observedAncillaryPolicy) {
			p.FirstHeaderShape.RequiredVolatile["content-length"] = "unbounded"
		},
		"wrong_order":  func(p *observedAncillaryPolicy) { p.Order[0] = "second" },
		"target_first": func(p *observedAncillaryPolicy) { p.TargetAfter = nil },
		"target_after_both": func(p *observedAncillaryPolicy) {
			p.TargetAfter = []string{"first", "second"}
		},
		"extra_ancillary": func(p *observedAncillaryPolicy) { p.MaxAncillary = 3 },
		"provider_status": func(p *observedAncillaryPolicy) { p.AncillaryHTTPStatus = 200 },
		"wrong_host":      func(p *observedAncillaryPolicy) { p.FirstHeaderShape.Host = "other.invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated, signed := observedAncillaryPolicyFixture(t)
			change(&mutated)
			if name == "wrong_signature_digest" {
				signed = "sha256:" + strings.Repeat("0", 64)
			} else if name == "target_first" || name == "target_after_both" {
				// A newly signed profile still cannot widen the observed order.
				canonical, err := canonicalJSONValue(mutated)
				if err != nil {
					t.Fatal(err)
				}
				signed = digest(canonical)
			}
			if err := mutated.validate(signed, "fixture.invalid"); err == nil {
				t.Fatal("unreviewed or unsigned ancillary profile accepted")
			}
		})
	}
}

func TestObservedTargetHeaderShapeMustMatchSignedBytes(t *testing.T) {
	p, _ := observedAncillaryPolicyFixture(t)
	shape := p.FirstHeaderShape
	shape.Schema = "stage2a-observed-body-header-shape/v1"
	canonical, err := canonicalJSONValue(shape)
	if err != nil {
		t.Fatal(err)
	}
	wantSHA := digest(canonical)
	if err := shape.validateSigned(wantSHA, "stage2a-observed-body-header-shape/v1", "fixture.invalid"); err != nil {
		t.Fatalf("signed target header shape refused: %v", err)
	}
	shape.RequiredFixed["anthropic-beta"] = "altered"
	if err := shape.validateSigned(wantSHA, "stage2a-observed-body-header-shape/v1", "fixture.invalid"); err == nil {
		t.Fatal("unsigned target header value accepted")
	}
}
