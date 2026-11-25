package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

const (
	observedBindContext           = "agent-bot-stage2a-observed-body-local-test-bind-v1"
	observedIngressKeyContext     = "agent-bot-stage2a-observed-body-local-test-ingress-subkey-v1"
	observedIngressOriginContext  = "agent-bot-stage2a-observed-body-local-test-ingress-origin-v1"
	observedCompleteKeyContext    = "agent-bot-stage2a-observed-body-local-test-completion-subkey-v1"
	observedCompleteOriginContext = "agent-bot-stage2a-observed-body-local-test-completion-origin-v1"
)

// The bind proof is public to HQ. It must never serve as a subkey input.
// The sixteen ordered values are built from a validated Machine assignment
// and HQ challenge; this helper rejects extra components and embedded NULs.
func observedBindProof(rawFD4 []byte, parts []string) (string, error) {
	if len(rawFD4) != 32 || len(parts) != 16 || parts[0] != observedBindContext {
		return "", invalid
	}
	for _, part := range parts {
		if part == "" || strings.ContainsRune(part, 0) {
			return "", invalid
		}
	}
	mac := hmac.New(sha256.New, rawFD4)
	io.WriteString(mac, strings.Join(parts, "\x00"))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func observedSubkey(rawFD4 []byte, reservation, context string) ([]byte, error) {
	if len(rawFD4) != 32 || !validDigest(reservation) ||
		(context != observedIngressKeyContext && context != observedCompleteKeyContext) {
		return nil, invalid
	}
	mac := hmac.New(sha256.New, rawFD4)
	io.WriteString(mac, context)
	mac.Write([]byte{0})
	io.WriteString(mac, reservation)
	return mac.Sum(nil), nil
}

func observedOriginMAC(subkey []byte, context string, core any) (string, error) {
	if len(subkey) != 32 ||
		(context != observedIngressOriginContext && context != observedCompleteOriginContext) {
		return "", invalid
	}
	canonical, err := canonicalJSONValue(core)
	if err != nil {
		return "", invalid
	}
	mac := hmac.New(sha256.New, subkey)
	io.WriteString(mac, context)
	mac.Write([]byte{0})
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
