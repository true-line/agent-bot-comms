package main

import "time"

// The provider response is only useful after the A-signed ingress
// authorization is checked. Its text must also match the selected lead's
// A-signed response digest before B prepares any SSE bytes.
type observedProviderResponse struct {
	Mode               string `json:"mode"`
	Model              string `json:"model"`
	ObservedBodySHA256 string `json:"observed_body_sha256"`
	ResponseText       string `json:"response_text"`
	ResponseSHA256     string `json:"response_sha256"`
	Invocation         int    `json:"invocation"`
}

type observedIngressResult struct {
	observedAuthorizationReply
	IngressCoreSHA256          string                   `json:"ingress_core_sha256"`
	Provider                   observedProviderResponse `json:"provider"`
	ProviderRequestBodySHA256  string                   `json:"provider_request_body_sha256"`
	ProviderResponseBodySHA256 string                   `json:"provider_response_body_sha256"`
}

func verifyObservedIngressResult(result observedIngressResult, pin []byte,
	core observedIngressCore, authority observedAuthority, now time.Time) (string, error) {
	authorizationSHA, err := verifyObservedAuthorization(result.observedAuthorizationReply,
		pin, core, authority.FD3.Expires, now)
	if err != nil || authority.FD3.Selectors != core.Selectors ||
		result.IngressCoreSHA256 == "" || !validDigest(authority.ResponseTextSHA256) {
		return "", invalid
	}
	coreBytes, err := canonicalJSONValue(core)
	if err != nil || digest(coreBytes) != result.IngressCoreSHA256 {
		return "", invalid
	}
	provider := result.Provider
	if provider.Mode != "observed-body-local-test/v1" ||
		provider.Model != authority.FD3.LocalTest.Model ||
		provider.ObservedBodySHA256 != core.ObservedBodySHA256 ||
		provider.Invocation != 1 || provider.ResponseText == "" ||
		len(provider.ResponseText) > 16384 ||
		digest([]byte(provider.ResponseText)) != provider.ResponseSHA256 ||
		provider.ResponseSHA256 != authority.ResponseTextSHA256 {
		return "", invalid
	}
	request := map[string]any{"mode": provider.Mode, "model": provider.Model,
		"observed_body_sha256": provider.ObservedBodySHA256}
	requestBytes, err := canonicalJSONValue(request)
	if err != nil || digest(requestBytes) != result.ProviderRequestBodySHA256 {
		return "", invalid
	}
	config := map[string]any{
		"schema":        "stage2a-observed-body-local-test-fixture/v1",
		"model":         provider.Model,
		"response_text": provider.ResponseText,
	}
	configBytes, err := canonicalJSONValue(config)
	if err != nil || digest(configBytes) != authority.FD3.LocalTest.FixtureConfigSHA256 {
		return "", invalid
	}
	responseBytes, err := canonicalJSONValue(provider)
	if err != nil || digest(responseBytes) != result.ProviderResponseBodySHA256 {
		return "", invalid
	}
	return authorizationSHA, nil
}

func prepareObservedResponse(provider observedProviderResponse, model string) (preparedHTTP, error) {
	zero := 0
	response := qualificationResult{Model: provider.Model, Text: provider.ResponseText,
		Stop: "end_turn"}
	response.Usage.Input = &zero
	response.Usage.Output = &zero
	if !response.valid(model) || provider.ResponseSHA256 != digest([]byte(response.Text)) {
		return preparedHTTP{}, invalid
	}
	return prepareHTTP(200, "text/event-stream", response.eventStream()), nil
}
