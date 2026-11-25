package main

import (
	"context"
	"time"
)

type observedAuthorized struct {
	AuthorizationEnvelopeSHA256 string
	IngressCoreSHA256           string
	Provider                    observedProviderResponse
	Result                      observedIngressResult
}

// One B-origin attempt can authorize one provider claim. The caller's current
// check must re-observe the same relay peer and both pinned socket identities;
// a failed attempt is still spent locally and Machine spends it durably.
func (b *broker) authorizeObserved(ctx context.Context, core observedIngressCore,
	ingressKey []byte, authority observedAuthority,
	current func() bool, attempted *bool) (observedAuthorized, error) {
	defer clear(ingressKey)
	if b == nil || current == nil || attempted == nil || *attempted ||
		!time.Now().Before(authority.FD3.Expires) || !current() ||
		validateObservedIngressCore(core, time.Now()) != nil {
		return observedAuthorized{}, invalid
	}
	coreBytes, err := canonicalJSONValue(core)
	if err != nil {
		return observedAuthorized{}, invalid
	}
	mac, err := observedOriginMAC(ingressKey, observedIngressOriginContext, core)
	if err != nil {
		return observedAuthorized{}, invalid
	}
	*attempted = true
	var reply observedIngressResult
	if b.call(ctx, "ingress", observedIngressOp,
		observedIngressPayload{Core: core, IngressOriginMAC: mac}, &reply) != nil ||
		!current() {
		return observedAuthorized{}, invalid
	}
	authorizationSHA, err := verifyObservedIngressResult(reply, authority.Pin[:], core,
		authority, time.Now())
	if err != nil || !current() {
		return observedAuthorized{}, invalid
	}
	return observedAuthorized{AuthorizationEnvelopeSHA256: authorizationSHA,
		IngressCoreSHA256: digest(coreBytes), Provider: reply.Provider, Result: reply}, nil
}
