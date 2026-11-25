package main

import (
	"net/http"
	"strings"
	"testing"
)

func observedHeaderFixture() (*http.Request, observedHeaderProfile) {
	fixed := make(map[string]string, len(observedFixedHeaderNames))
	for _, name := range observedFixedHeaderNames {
		fixed[name] = "fixed-value"
	}
	fixed["accept"] = "application/json"
	fixed["content-type"] = "application/json"
	fixed["x-stainless-retry-count"] = "0"
	p := observedHeaderProfile{Host: "fixture.invalid", MessagesQuery: "beta=true",
		ClientKeySHA256: digest([]byte("synthetic-key")), RequiredFixed: fixed}
	req := &http.Request{Method: "POST", Proto: "HTTP/1.1", RequestURI: "/v1/messages?beta=true",
		Host: p.Host, Header: make(http.Header), ContentLength: 100}
	for name, value := range fixed {
		req.Header.Set(name, value)
	}
	req.Header.Set("Content-Length", "100")
	req.Header.Set("X-Api-Key", "synthetic-key")
	req.Header.Set("X-Claude-Code-Session-Id", "11111111-1111-1111-1111-111111111111")
	return req, p
}

func TestObservedHeadersRequireExactStockShape(t *testing.T) {
	req, p := observedHeaderFixture()
	baseline, err := inspectObservedHeaders(req, 100, p)
	if err != nil || !validDigest(baseline) {
		t.Fatalf("baseline rejected: %s %v", baseline, err)
	}
	for name, change := range map[string]func(*http.Request){
		"wrong_host":  func(r *http.Request) { r.Host = "other.invalid" },
		"wrong_query": func(r *http.Request) { r.RequestURI = "/v1/messages?other=true" },
		"wrong_key":   func(r *http.Request) { r.Header.Set("X-Api-Key", "wrong") },
		"wrong_fixed_value": func(r *http.Request) {
			r.Header.Set("Anthropic-Beta", "wrong")
		},
		"extra_header":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") },
		"missing_header":   func(r *http.Request) { r.Header.Del("User-Agent") },
		"duplicate_header": func(r *http.Request) { r.Header.Add("Accept", "application/json") },
		"bad_length":       func(r *http.Request) { r.Header.Set("Content-Length", "0100") },
	} {
		t.Run(name, func(t *testing.T) {
			copy := req.Clone(req.Context())
			change(copy)
			if _, err := inspectObservedHeaders(copy, 100, p); err == nil {
				t.Fatal("changed headers accepted")
			}
		})
	}
	// Only the pinned credential and UUID may change without changing the
	// observed nonvolatile header digest.
	other := req.Clone(req.Context())
	other.Header.Set("X-Claude-Code-Session-Id", "22222222-2222-2222-2222-222222222222")
	got, err := inspectObservedHeaders(other, 100, p)
	if err != nil || got != baseline {
		t.Fatalf("valid session ID changed canonical headers: %s %v", got, err)
	}
	if strings.Contains(baseline, "synthetic-key") {
		t.Fatal("credential leaked into digest")
	}
}
