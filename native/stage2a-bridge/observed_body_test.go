package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func observedBodyFixture(t *testing.T) ([]byte, observedBodyProfile) {
	t.Helper()
	cwd := "/private/var/stage2a/child-a/work"
	lexicalCWD := "/var/stage2a/child-a/work"
	memory := "/var/stage2a/child-a/home/.claude/projects/-private-var-stage2a-child-a-work/memory/"
	content := make([]any, 10)
	content[0] = map[string]any{"type": "text", "text": "<system-reminder>\n - Primary working directory: " + cwd +
		"\n - Additional working directories:\n  - " + lexicalCWD + "\n</system-reminder>"}
	for i := 1; i < 8; i++ {
		content[i] = map[string]any{"type": "text", "text": "stock reminder " + string(rune('0'+i))}
	}
	brief := "Brief from the entry point. You are m_lead, the lead of agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b.\n" +
		"Before continuing, read your waiting directives and your open tasks from HQ, and reconcile anything whose outcome you do not know.\n" +
		"There are no handoff notes."
	const firstBriefSHA256 = "sha256:53796ff22d8ab5009c8671640f008c7a55d74449e7739f23369f8380ab3df185"
	if len(brief) != 258 || digest([]byte(brief)) != firstBriefSHA256 {
		t.Fatal("selected R no-notes brief source fixture changed")
	}
	content[8] = map[string]any{"type": "text", "text": brief}
	content[9] = map[string]any{"type": "text", "text": "Return the fixture response.",
		"cache_control": map[string]any{"type": "ephemeral"}}
	system := []any{
		map[string]any{"type": "text", "text": "static system one"},
		map[string]any{"type": "text", "text": "static system two", "cache_control": map[string]any{"type": "ephemeral"}},
		map[string]any{"type": "text", "text": "memory at " + memory, "cache_control": map[string]any{"type": "ephemeral"}},
	}
	userID := `{"account_uuid":"","device_id":"` + strings.Repeat("a", 64) + `","session_id":"11111111-1111-1111-1111-111111111111"}`
	root := map[string]any{"context_management": map[string]any{"edits": []any{}}, "max_tokens": 32000,
		"messages": []any{map[string]any{"role": "user", "content": content}},
		"metadata": map[string]any{"user_id": userID}, "model": "probe", "stream": true,
		"system": system, "thinking": map[string]any{"type": "enabled", "budget_tokens": 31999},
		"tools": []any{map[string]any{"name": "Read", "description": "fixed tool"}}}
	projected := map[string]any{}
	for key, value := range root {
		projected[key] = value
	}
	projected["metadata"] = map[string]any{"user_id": observedUserIDToken}
	projectedContent := make([]any, len(content))
	for i, value := range content {
		copy := map[string]any{}
		for k, v := range value.(map[string]any) {
			copy[k] = v
		}
		projectedContent[i] = copy
	}
	projectedContent[0].(map[string]any)["text"] = "<system-reminder>\n - Primary working directory: " + observedCWDToken +
		"\n - Additional working directories:\n  - " + observedLexicalCWDToken + "\n</system-reminder>"
	projected["messages"] = []any{map[string]any{"role": "user", "content": projectedContent}}
	projectedSystem := append([]any(nil), system...)
	projectedSystem[2] = map[string]any{"type": "text", "text": "memory at " + observedMemoryToken,
		"cache_control": map[string]any{"type": "ephemeral"}}
	projected["system"] = projectedSystem
	staticBytes, err := canonicalJSONValue(projected)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return body, observedBodyProfile{Model: "probe", OwnerPromptSHA256: digest([]byte("Return the fixture response.")),
		ProjectionSHA256: digest(staticBytes), ChildCWD: cwd, ChildCWDLexical: lexicalCWD, MemoryPath: memory,
		ExpectedBriefSHA256: firstBriefSHA256, MaxBriefBytes: 32768}
}

func TestObservedBodyOnlyNamedDynamics(t *testing.T) {
	body, profile := observedBodyFixture(t)
	got, err := inspectObservedBody(body, profile)
	if err != nil || got.BodySHA256 != digest(body) || !validDigest(got.BriefSHA256) {
		t.Fatalf("baseline rejected: %+v, %v", got, err)
	}
	// Distinct Machine-selected starts produce different raw bodies but one
	// signed static profile after only their derived paths are replaced.
	other := profile
	other.ChildCWD = "/private/var/stage2a/child-b/work"
	other.ChildCWDLexical = "/var/stage2a/child-b/work"
	other.MemoryPath = "/var/stage2a/child-b/home/.claude/projects/-private-var-stage2a-child-b-work/memory/"
	second := strings.ReplaceAll(string(body), profile.ChildCWD, other.ChildCWD)
	second = strings.ReplaceAll(second, profile.ChildCWDLexical, other.ChildCWDLexical)
	second = strings.ReplaceAll(second, profile.MemoryPath, other.MemoryPath)
	otherResult, err := inspectObservedBody([]byte(second), other)
	if err != nil || otherResult.BodySHA256 == got.BodySHA256 || other.ProjectionSHA256 != profile.ProjectionSHA256 {
		t.Fatalf("second start did not preserve static profile: %+v, %v", otherResult, err)
	}
	changedUserID := strings.Replace(string(body), strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
	if userResult, err := inspectObservedBody([]byte(changedUserID), profile); err != nil || userResult.BodySHA256 == got.BodySHA256 {
		t.Fatalf("shaped user ID volatility rejected: %+v, %v", userResult, err)
	}
	for name, changed := range map[string]string{
		"same_final_prompt_changed_earlier_instruction": strings.Replace(string(body), "stock reminder 3", "new instruction", 1),
		"same_final_prompt_changed_tool":                strings.Replace(string(body), "fixed tool", "new tool", 1),
		"wrong_final_prompt":                            strings.Replace(string(body), "Return the fixture response.", "Return other text.", 1),
		"wrong_cwd":                                     strings.Replace(string(body), profile.ChildCWD, "/private/var/stage2a/child-b/work", 1),
		"wrong_memory":                                  strings.Replace(string(body), profile.MemoryPath, "/private/var/stage2a/child-b/memory/", 1),
		"physical_memory_alias":                         strings.Replace(string(body), profile.MemoryPath, "/private"+profile.MemoryPath, 1),
		"extra_top_level_key":                           strings.Replace(string(body), `"model":"probe"`, `"model":"probe","other":true`, 1),
		"duplicate_key":                                 strings.Replace(string(body), `"stream":true`, `"stream":true,"stream":true`, 1),
		"wrong_brief_slot":                              strings.Replace(string(body), "Brief from the entry point.", "Other introduction.", 1),
		"unreviewed_handoff":                            strings.Replace(string(body), "There are no handoff notes.", "Handoff notes, oldest first: []", 1),
		"escaped_cwd_alias":                             strings.Replace(string(body), profile.ChildCWD, strings.ReplaceAll(profile.ChildCWD, "/", `\/`), 1),
		"reserved_token_in_input":                       strings.Replace(string(body), "stock reminder 3", observedCWDToken, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspectObservedBody([]byte(changed), profile); err == nil {
				t.Fatal("changed stock request accepted")
			}
		})
	}
}
