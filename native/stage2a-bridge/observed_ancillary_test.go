package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestObservedAncillaryIsPinnedLocalRefusalShape(t *testing.T) {
	userID := `{"account_uuid":"","device_id":"` + strings.Repeat("a", 64) + `","session_id":"11111111-1111-1111-1111-111111111111"}`
	root := map[string]any{
		"max_tokens": 32000, "messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "<session>\nReturn the fixture response.\n</session>\n\nWrite a title."}}}},
		"metadata": map[string]any{"user_id": userID}, "model": "probe", "output_config": map[string]any{},
		"stream": true, "system": []any{}, "temperature": 1, "thinking": map[string]any{"type": "disabled"}, "tools": []any{},
	}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	root["metadata"] = map[string]any{"user_id": observedUserIDToken}
	projected, err := canonicalJSONValue(root)
	if err != nil {
		t.Fatal(err)
	}
	projection := digest(projected)
	if err := inspectObservedAncillary(data, "probe", projection); err != nil {
		t.Fatalf("pinned ancillary rejected: %v", err)
	}
	for name, changed := range map[string]string{
		"changed_title_instruction": strings.Replace(string(data), "Write a title.", "Write a different title.", 1),
		"changed_owner_text":        strings.Replace(string(data), "Return the fixture response.", "Return something else.", 1),
		"extra_block":               strings.Replace(string(data), `"content":[{`, `"content":[{"type":"text","text":"extra"},{`, 1),
		"duplicate_model":           strings.Replace(string(data), `"model":"probe"`, `"model":"probe","model":"probe"`, 1),
		"extra_field":               strings.Replace(string(data), `"model":"probe"`, `"model":"probe","other":true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if inspectObservedAncillary([]byte(changed), "probe", projection) == nil {
				t.Fatal("unreviewed ancillary accepted")
			}
		})
	}
}
