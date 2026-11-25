package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// observedBodyProfile is the source-reviewed content predicate for a single
// local-test target. Its path and projection values must come from the signed
// start assignment; none may come from the HTTP request being checked.
type observedBodyProfile struct {
	Model               string
	OwnerPromptSHA256   string
	ProjectionSHA256    string
	ChildCWD            string
	ChildCWDLexical     string
	MemoryPath          string
	ExpectedBriefSHA256 string
	MaxBriefBytes       int
}

type observedBodyResult struct {
	BodySHA256  string
	BriefSHA256 string
}

const (
	observedCWDToken        = "<path:cwd-physical>"
	observedLexicalCWDToken = "<path:cwd-lexical-additional>"
	observedMemoryToken     = "<path:memory-lexical-home-physical-slug>"
	observedUserIDToken     = "<volatile:metadata.user_id>"
)

func objectHasKeys(value any, keys ...string) (map[string]any, bool) {
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := obj[key]; !ok {
			return nil, false
		}
	}
	return obj, true
}

func replaceOne(text, old, replacement string) (string, bool) {
	if old == "" || strings.Count(text, old) != 1 || strings.Contains(text, replacement) {
		return "", false
	}
	return strings.Replace(text, old, replacement, 1), true
}

// inspectObservedBody checks the selected first lead turn before any provider
// operation. It commits all unlisted body values through a signed projection;
// only the shaped user ID and start-derived path spans vary. The exact R brief
// remains in the signed projection and has its own pinned digest.
// The observed digest itself is over the exact buffered HTTP body bytes.
func inspectObservedBody(data []byte, p observedBodyProfile) (observedBodyResult, error) {
	if len(data) == 0 || len(data) > maxBody || !validDigest(p.OwnerPromptSHA256) ||
		!validDigest(p.ProjectionSHA256) || p.ChildCWD == "" || p.ChildCWDLexical == "" || p.MemoryPath == "" ||
		!validDigest(p.ExpectedBriefSHA256) || p.MaxBriefBytes < 1 || p.MaxBriefBytes > 32768 {
		return observedBodyResult{}, invalid
	}
	var root map[string]any
	if decode(data, &json.RawMessage{}) != nil {
		return observedBodyResult{}, invalid
	}
	reader := json.NewDecoder(bytes.NewReader(data))
	reader.UseNumber()
	if reader.Decode(&root) != nil {
		return observedBodyResult{}, invalid
	}
	// Stock JSON.stringify emits these paths literally. This rejects alternate
	// escapes or a second copy before projection can erase either span.
	primaryRaw := []byte(" - Primary working directory: " + p.ChildCWD + `\n`)
	lexicalRaw := []byte(" - Additional working directories:" + `\n` + "  - " + p.ChildCWDLexical + `\n`)
	if bytes.Count(data, primaryRaw) != 1 || bytes.Count(data, lexicalRaw) != 1 ||
		bytes.Count(data, []byte(p.MemoryPath)) != 1 {
		return observedBodyResult{}, invalid
	}
	inputCanonical, err := json.Marshal(root)
	if err != nil || bytes.Contains(inputCanonical, []byte(observedCWDToken)) ||
		bytes.Contains(inputCanonical, []byte(observedLexicalCWDToken)) ||
		bytes.Contains(inputCanonical, []byte(observedMemoryToken)) ||
		bytes.Contains(inputCanonical, []byte(observedUserIDToken)) {
		return observedBodyResult{}, invalid
	}
	fields, ok := objectHasKeys(root, "context_management", "max_tokens", "messages", "metadata",
		"model", "stream", "system", "thinking", "tools")
	if !ok || fields["model"] != p.Model || fields["stream"] != true {
		return observedBodyResult{}, invalid
	}
	messages, ok := fields["messages"].([]any)
	if !ok || len(messages) != 1 {
		return observedBodyResult{}, invalid
	}
	message, ok := objectHasKeys(messages[0], "role", "content")
	if !ok || message["role"] != "user" {
		return observedBodyResult{}, invalid
	}
	blocks, ok := message["content"].([]any)
	if !ok || len(blocks) != 10 {
		return observedBodyResult{}, invalid
	}
	for i, value := range blocks {
		keys := []string{"type", "text"}
		if i == 9 {
			keys = append(keys, "cache_control")
		}
		block, ok := objectHasKeys(value, keys...)
		text, textOK := block["text"].(string)
		if !ok || block["type"] != "text" || !textOK || text == "" ||
			!utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
			return observedBodyResult{}, invalid
		}
		if i == 9 {
			control, ok := objectHasKeys(block["cache_control"], "type")
			if !ok || control["type"] != "ephemeral" || digest([]byte(text)) != p.OwnerPromptSHA256 {
				return observedBodyResult{}, invalid
			}
		}
	}
	first := blocks[0].(map[string]any)
	firstText := first["text"].(string)
	cwdLine := " - Primary working directory: " + p.ChildCWD + "\n"
	firstText, ok = replaceOne(firstText, cwdLine,
		" - Primary working directory: "+observedCWDToken+"\n")
	if !ok {
		return observedBodyResult{}, invalid
	}
	lexicalLine := " - Additional working directories:\n  - " + p.ChildCWDLexical + "\n"
	firstText, ok = replaceOne(firstText, lexicalLine,
		" - Additional working directories:\n  - "+observedLexicalCWDToken+"\n")
	if !ok {
		return observedBodyResult{}, invalid
	}
	first["text"] = firstText
	system, ok := fields["system"].([]any)
	if !ok || len(system) != 3 {
		return observedBodyResult{}, invalid
	}
	third, ok := objectHasKeys(system[2], "type", "text", "cache_control")
	if !ok || third["type"] != "text" {
		return observedBodyResult{}, invalid
	}
	memoryText, ok := third["text"].(string)
	if !ok {
		return observedBodyResult{}, invalid
	}
	memoryText, ok = replaceOne(memoryText, p.MemoryPath, observedMemoryToken)
	if !ok {
		return observedBodyResult{}, invalid
	}
	third["text"] = memoryText
	brief := blocks[8].(map[string]any)
	briefText := brief["text"].(string)
	if len([]byte(briefText)) > p.MaxBriefBytes || digest([]byte(briefText)) != p.ExpectedBriefSHA256 {
		return observedBodyResult{}, invalid
	}
	briefDigest := digest([]byte(briefText))
	metadata, ok := objectHasKeys(fields["metadata"], "user_id")
	userID, userOK := metadata["user_id"].(string)
	if !ok || !userOK || !validStockUserID(userID) {
		return observedBodyResult{}, invalid
	}
	metadata["user_id"] = observedUserIDToken
	projection, err := canonicalJSONValue(fields)
	if err != nil || digest(projection) != p.ProjectionSHA256 {
		return observedBodyResult{}, invalid
	}
	return observedBodyResult{BodySHA256: digest(data), BriefSHA256: briefDigest}, nil
}

func validStockUserID(userID string) bool {
	if len(userID) > 1024 {
		return false
	}
	fields := objectFields([]byte(userID), "account_uuid", "device_id", "session_id")
	if len(fields) != 3 {
		return false
	}
	var account, device, session string
	return json.Unmarshal(fields["account_uuid"], &account) == nil &&
		json.Unmarshal(fields["device_id"], &device) == nil &&
		json.Unmarshal(fields["session_id"], &session) == nil &&
		account == "" &&
		hexPattern.MatchString(device) && uuidPattern.MatchString(session)
}
