package main

import (
	"bytes"
	"encoding/json"
)

const maxObservedAncillaryBody = 8192

// Both selected-R stock ancillary POSTs are local client work and must
// receive a refusal without reaching HQ's provider. A signed source fixture
// pins their shared body after only metadata.user_id is removed.
func inspectObservedAncillary(data []byte, model, projectionSHA256 string) error {
	if len(data) == 0 || len(data) > maxObservedAncillaryBody || model == "" || !validDigest(projectionSHA256) ||
		decode(data, &json.RawMessage{}) != nil {
		return invalid
	}
	reader := json.NewDecoder(bytes.NewReader(data))
	reader.UseNumber()
	var root map[string]any
	if reader.Decode(&root) != nil {
		return invalid
	}
	fields, ok := objectHasKeys(root, "max_tokens", "messages", "metadata", "model", "output_config",
		"stream", "system", "temperature", "thinking", "tools")
	if !ok || fields["model"] != model || fields["stream"] != true {
		return invalid
	}
	messages, ok := fields["messages"].([]any)
	if !ok || len(messages) != 1 {
		return invalid
	}
	message, ok := objectHasKeys(messages[0], "role", "content")
	if !ok || message["role"] != "user" {
		return invalid
	}
	blocks, ok := message["content"].([]any)
	if !ok || len(blocks) != 1 {
		return invalid
	}
	block, ok := objectHasKeys(blocks[0], "type", "text")
	text, textOK := block["text"].(string)
	if !ok || block["type"] != "text" || !textOK || text == "" {
		return invalid
	}
	metadata, ok := objectHasKeys(fields["metadata"], "user_id")
	userID, userOK := metadata["user_id"].(string)
	if !ok || !userOK || !validStockUserID(userID) {
		return invalid
	}
	metadata["user_id"] = observedUserIDToken
	projection, err := canonicalJSONValue(fields)
	if err != nil || digest(projection) != projectionSHA256 {
		return invalid
	}
	return nil
}
