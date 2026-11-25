package main

import (
	"net/http"
	"strconv"
	"strings"
)

// The selected stock client emitted these fixed header names in two
// source-derived first-turn captures. Their exact values come from the
// signed one-use local-test assignment, never from an HTTP request.
var observedFixedHeaderNames = []string{
	"accept", "accept-encoding", "anthropic-beta",
	"anthropic-dangerous-direct-browser-access", "anthropic-version",
	"connection", "content-type", "user-agent", "x-app",
	"x-stainless-arch", "x-stainless-lang", "x-stainless-os",
	"x-stainless-package-version", "x-stainless-retry-count",
	"x-stainless-runtime", "x-stainless-runtime-version", "x-stainless-timeout",
}

type observedHeaderProfile struct {
	Host            string
	MessagesQuery   string
	ClientKeySHA256 string
	RequiredFixed   map[string]string
}

// inspectObservedHeaders computes the current Comms canonical header digest
// only after exact name/value, credential and session checks. Host is checked
// separately because Go's HTTP parser stores it in req.Host, not Header.
func inspectObservedHeaders(req *http.Request, bodyBytes int, p observedHeaderProfile) (string, error) {
	if req == nil || req.Method != "POST" || req.Proto != "HTTP/1.1" ||
		req.RequestURI != "/v1/messages?"+p.MessagesQuery || req.Host != p.Host ||
		!validDigest(p.ClientKeySHA256) || bodyBytes < 1 || bodyBytes > maxBody ||
		req.ContentLength != int64(bodyBytes) ||
		req.Header.Get("Content-Length") != strconv.Itoa(bodyBytes) ||
		len(p.RequiredFixed) != len(observedFixedHeaderNames) ||
		len(req.Header) != len(observedFixedHeaderNames)+3 {
		return "", invalid
	}
	for _, name := range observedFixedHeaderNames {
		value, ok := p.RequiredFixed[name]
		if !ok || value == "" || strings.ContainsAny(value, "\r\n") ||
			req.Header.Get(name) != value {
			return "", invalid
		}
	}
	if digest([]byte(req.Header.Get("X-Api-Key"))) != p.ClientKeySHA256 ||
		!uuidPattern.MatchString(req.Header.Get("X-Claude-Code-Session-Id")) {
		return "", invalid
	}
	for name, values := range req.Header {
		if len(values) != 1 || strings.ContainsAny(values[0], "\r\n") {
			return "", invalid
		}
		lower := strings.ToLower(name)
		if _, fixed := p.RequiredFixed[lower]; fixed {
			continue
		}
		switch lower {
		case "content-length", "x-api-key", "x-claude-code-session-id":
		default:
			return "", invalid
		}
	}
	return observedFixedHeadersDigest(p.RequiredFixed), nil
}
