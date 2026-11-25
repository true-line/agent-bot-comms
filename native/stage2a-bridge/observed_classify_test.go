package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func observedClassifyRequest(fixed map[string]string, body []byte) *http.Request {
	req := &http.Request{Method: "POST", Proto: "HTTP/1.1", Host: "fixture.invalid",
		RequestURI: "/v1/messages?beta=true", Header: make(http.Header),
		ContentLength: int64(len(body))}
	for name, value := range fixed {
		req.Header.Set(name, value)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Api-Key", "client key")
	req.Header.Set("X-Claude-Code-Session-Id", "11111111-1111-1111-1111-111111111111")
	return req
}

func observedClassificationFixture(t *testing.T) (observedAuthority, []byte, []byte) {
	t.Helper()
	lt := observedLocalTestFixture(t)
	target, source := observedBodyFixture(t)
	target = []byte(strings.ReplaceAll(string(target), source.ChildCWDLexical,
		lt.ExpectedChildCWDLexical))
	target = []byte(strings.ReplaceAll(string(target), source.MemoryPath,
		lt.ExpectedMemoryPathLexical))
	lt.Model = source.Model
	lt.OwnerPromptSHA256 = source.OwnerPromptSHA256
	lt.StaticProjectionSHA256 = source.ProjectionSHA256
	lt.FirstBriefSHA256 = source.ExpectedBriefSHA256
	userID := `{"account_uuid":"","device_id":"` + strings.Repeat("a", 64) +
		`","session_id":"11111111-1111-1111-1111-111111111111"}`
	ancillary := map[string]any{
		"max_tokens": 32000, "messages": []any{map[string]any{"role": "user",
			"content": []any{map[string]any{"type": "text", "text": "local ancillary"}}}},
		"metadata": map[string]any{"user_id": userID}, "model": source.Model,
		"output_config": map[string]any{}, "stream": true, "system": []any{},
		"temperature": 1, "thinking": map[string]any{"type": "disabled"}, "tools": []any{},
	}
	ancillaryBody, err := json.Marshal(ancillary)
	if err != nil {
		t.Fatal(err)
	}
	ancillary["metadata"] = map[string]any{"user_id": observedUserIDToken}
	projection, err := canonicalJSONValue(ancillary)
	if err != nil {
		t.Fatal(err)
	}
	lt.AncillaryProfile.NormalizedBodySHA256 = digest(projection)
	policyBytes, err := canonicalJSONValue(lt.AncillaryProfile)
	if err != nil {
		t.Fatal(err)
	}
	lt.AncillaryProfileSHA256 = digest(policyBytes)
	if err := lt.validate("fixture.installation", "st_111111111111111111111111"); err != nil {
		t.Fatalf("signed local-test fixture invalid: %v", err)
	}
	authority := observedAuthority{FD3: observedFD3{
		Selectors: observedSelectors{InstallationID: "fixture.installation",
			StartID: "st_111111111111111111111111"}, LocalTest: lt,
	}}
	return authority, target, ancillaryBody
}

func TestObservedClassifyUsesOnlySignedProfiles(t *testing.T) {
	authority, target, ancillaryBody := observedClassificationFixture(t)
	lt := authority.FD3.LocalTest
	for _, test := range []struct {
		name  string
		class observedRequestClass
		fixed map[string]string
		body  []byte
	}{
		{"first", observedAncillaryA, lt.AncillaryProfile.FirstHeaderShape.RequiredFixed, ancillaryBody},
		{"second", observedAncillaryB, lt.AncillaryProfile.SecondHeaderShape.RequiredFixed, ancillaryBody},
		{"target", observedTarget, lt.HeaderShape.RequiredFixed, target},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := observedClassifyRequest(test.fixed, test.body)
			got, err := classifyObservedRequest(req, test.body, authority)
			if err != nil || got.Class != test.class || !validDigest(got.HeadersSHA256) {
				t.Fatalf("signed source class refused: %+v %v", got, err)
			}
			if test.class == observedTarget && got.Body.BodySHA256 != digest(target) {
				t.Fatal("target raw body digest changed")
			}
			req.Header.Set("Anthropic-Beta", "unsigned")
			if _, err := classifyObservedRequest(req, test.body, authority); err == nil {
				t.Fatal("changed fixed header accepted")
			}
			wrong := []byte(strings.Replace(string(test.body), "local ancillary",
				"changed ancillary", 1))
			if test.class == observedTarget {
				wrong = []byte(strings.Replace(string(test.body),
					"Return the fixture response.", "Return a different response.", 1))
			}
			req = observedClassifyRequest(test.fixed, wrong)
			if _, err := classifyObservedRequest(req, wrong, authority); err == nil {
				t.Fatal("changed body accepted")
			}
		})
	}
}
