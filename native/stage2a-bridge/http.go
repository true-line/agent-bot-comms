package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maxBody = 256 << 10

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func readRequest(conn *net.UnixConn) (*http.Request, error) {
	reader := bufio.NewReaderSize(conn, 16384)
	var headers bytes.Buffer
	seen := make(map[string]bool)
	for lineNumber := 0; lineNumber < 64; lineNumber++ {
		line, err := reader.ReadSlice('\n')
		if err != nil || !bytes.HasSuffix(line, []byte("\r\n")) || headers.Len()+len(line) > 16384 {
			return nil, invalid
		}
		headers.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			return http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(headers.Bytes()), reader)))
		}
		if lineNumber == 0 {
			continue
		}
		name, _, ok := strings.Cut(string(line), ":")
		if !ok || strings.TrimSpace(name) != name {
			return nil, invalid
		}
		name = strings.ToLower(name)
		switch name {
		case "transfer-encoding", "trailer", "upgrade", "expect", "content-encoding", "proxy-connection":
			return nil, invalid
		}
		if seen[name] {
			return nil, invalid
		}
		seen[name] = true
	}
	return nil, invalid
}

func objectFields(data []byte, allowed ...string) map[string]json.RawMessage {
	var result map[string]json.RawMessage
	if decode(data, &result) != nil || result == nil {
		return nil
	}
	for key := range result {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return result
}

// requestFields recognizes the first streaming Messages shape from stock
// Claude ACP v0.109.0 on macOS and the existing eleven-field shape. The
// assignment digest distinguishes particular requests in either shape.
func requestFields(data []byte) (map[string]json.RawMessage, []string) {
	request := objectFields(data, "context_management", "max_tokens", "messages", "metadata", "model",
		"output_config", "safeguards", "stream", "system", "thinking", "tools")
	switch {
	case len(request) == 9 && request["output_config"] == nil && request["safeguards"] == nil:
		return request, []string{"user"}
	case len(request) == 11:
		return request, []string{"user", "system"}
	default:
		return nil, nil
	}
}

// normalizedRequest removes the only observed volatile stock-client field.
// It validates every JSON object for duplicate keys, then serializes the
// original raw values with metadata set to {}. All remaining body bytes are
// committed by the Machine-signed request_sha256 in the B assignment.
// The separate prompt digest binds the one parsed user text block without
// sending its bytes to HQ. Neither the raw body nor user_id leaves B.
func normalizedRequest(data []byte, config assignment) (string, string, error) {
	fields, roles := requestFields(data)
	if fields == nil {
		return "", "", invalid
	}
	var model string
	var stream bool
	var messages []json.RawMessage
	if json.Unmarshal(fields["model"], &model) != nil || model != config.Model ||
		json.Unmarshal(fields["stream"], &stream) != nil || !stream ||
		json.Unmarshal(fields["messages"], &messages) != nil || len(messages) != len(roles) {
		return "", "", invalid
	}
	var promptSHA256 string
	for index, expected := range roles {
		allowed := []string{"role", "content"}
		if index == 1 {
			allowed = append(allowed, "output_config")
		}
		message := objectFields(messages[index], allowed...)
		var role string
		if message == nil || json.Unmarshal(message["role"], &role) != nil || role != expected ||
			len(message) != len(allowed) {
			return "", "", invalid
		}
		if expected == "user" {
			var blocks []json.RawMessage
			if json.Unmarshal(message["content"], &blocks) != nil || len(blocks) != 1 {
				return "", "", invalid
			}
			block := objectFields(blocks[0], "type", "text")
			var kind, prompt string
			if len(block) != 2 || json.Unmarshal(block["type"], &kind) != nil || kind != "text" ||
				json.Unmarshal(block["text"], &prompt) != nil || prompt == "" ||
				!utf8.ValidString(prompt) || strings.ContainsRune(prompt, utf8.RuneError) {
				return "", "", invalid
			}
			promptSHA256 = digest([]byte(prompt))
		}
	}
	metadata := objectFields(fields["metadata"], "user_id")
	var userID string
	if len(metadata) != 1 || json.Unmarshal(metadata["user_id"], &userID) != nil || len(userID) > 1024 {
		return "", "", invalid
	}
	var identity struct {
		Account string `json:"account_uuid"`
		Device  string `json:"device_id"`
		Session string `json:"session_id"`
	}
	if decode([]byte(userID), &identity) != nil || (identity.Account != "" && !uuidPattern.MatchString(identity.Account)) ||
		!hexPattern.MatchString(identity.Device) || !uuidPattern.MatchString(identity.Session) {
		return "", "", invalid
	}
	fields["metadata"] = json.RawMessage(`{}`)
	// encoding/json sorts object keys and compacts RawMessage values. This
	// exact Go byte profile is versioned by stage2a-b-assignment/v2; the
	// independent signer pins its digest, never a client-supplied digest.
	normalized, err := json.Marshal(fields)
	if err != nil || digest(normalized) != config.RequestDigest {
		return "", "", invalid
	}
	return config.RequestDigest, promptSHA256, nil
}

// approvedHeaders commits every nonvolatile header, including the API version,
// beta list and dangerous-browser flag. Credential and session identifiers are
// checked locally and discarded; they never enter the HQ/provider payload.
func approvedHeaders(req *http.Request, config assignment) bool {
	if req.Host != config.HTTPHost || req.Header.Get("Accept") != "application/json" ||
		req.Header.Get("Anthropic-Version") == "" || req.Header.Get("Anthropic-Beta") == "" ||
		req.Header.Get("Anthropic-Dangerous-Direct-Browser-Access") == "" ||
		req.Header.Get("X-Stainless-Retry-Count") != "0" ||
		req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" ||
		req.Header.Get("Proxy-Authorization") != "" {
		return false
	}
	key := req.Header.Get("X-Api-Key")
	if key == "" || digest([]byte(key)) != config.ClientKeyDigest ||
		!uuidPattern.MatchString(req.Header.Get("X-Claude-Code-Session-Id")) {
		return false
	}
	names := make([]string, 0, len(req.Header))
	for name, values := range req.Header {
		if len(values) != 1 || strings.ContainsAny(values[0], "\r\n") {
			return false
		}
		switch strings.ToLower(name) {
		case "content-length", "x-api-key", "x-claude-code-session-id":
			continue
		}
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(req.Header.Get(name))
		canonical.WriteByte('\n')
	}
	return digest([]byte(canonical.String())) == config.HeadersDigest
}

type httpWrite struct {
	SHA256      string
	Bytes       int
	Status      int
	StartedAt   time.Time
	CompletedAt time.Time
}

func writeHTTP(conn *net.UnixConn, status int, contentType string, data []byte) (httpWrite, error) {
	var response bytes.Buffer
	fmt.Fprintf(&response, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
		status, http.StatusText(status), contentType, len(data))
	response.Write(data)
	if conn.SetWriteDeadline(deadline()) != nil {
		return httpWrite{}, invalid
	}
	wire := response.Bytes()
	started := time.Now().UTC()
	for written := 0; written < len(wire); {
		n, err := conn.Write(wire[written:])
		written += n
		if err != nil || n == 0 {
			return httpWrite{}, invalid
		}
	}
	return httpWrite{digest(wire), len(wire), status, started, time.Now().UTC()}, nil
}

type qualificationResult struct {
	Model string `json:"model"`
	Text  string `json:"text"`
	Stop  string `json:"stop_reason"`
	Usage struct {
		Input  *int `json:"input_tokens"`
		Output *int `json:"output_tokens"`
	} `json:"usage"`
}

func (r qualificationResult) valid(model string) bool {
	return r.Model == model && r.Text != "" && len(r.Text) <= 16384 && r.Stop == "end_turn" &&
		r.Usage.Input != nil && r.Usage.Output != nil && *r.Usage.Input >= 0 && *r.Usage.Output >= 0 &&
		*r.Usage.Input <= 1<<30 && *r.Usage.Output <= 1<<30
}

func (r qualificationResult) eventStream() []byte {
	var out bytes.Buffer
	emit := func(kind string, fields map[string]any) {
		fields["type"] = kind
		data, _ := json.Marshal(fields)
		fmt.Fprintf(&out, "event: %s\ndata: %s\n\n", kind, data)
	}
	emit("message_start", map[string]any{"message": map[string]any{"id": "msg_stage2a", "type": "message", "role": "assistant",
		"model": r.Model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil,
		"usage": map[string]int{"input_tokens": *r.Usage.Input, "output_tokens": 0}}})
	emit("content_block_start", map[string]any{"index": 0, "content_block": map[string]string{"type": "text", "text": ""}})
	emit("content_block_delta", map[string]any{"index": 0, "delta": map[string]string{"type": "text_delta", "text": r.Text}})
	emit("content_block_stop", map[string]any{"index": 0})
	emit("message_delta", map[string]any{"delta": map[string]any{"stop_reason": r.Stop, "stop_sequence": nil}, "usage": r.Usage})
	emit("message_stop", map[string]any{})
	return out.Bytes()
}

func serve(ctx context.Context, conn *net.UnixConn, b *broker, config assignment, relay endpoint, bindReceipt string, attempted *bool) error {
	if conn.SetReadDeadline(deadline()) != nil {
		return nil
	}
	req, err := readRequest(conn)
	if err != nil || req.Proto != "HTTP/1.1" || req.Host == "" {
		writeHTTP(conn, 400, "text/plain", nil)
		return nil
	}
	// Connection close discards any unread or pipelined request bytes.
	if req.Method == "GET" && req.RequestURI == "/api/claude_code/policy_limits" && req.ContentLength == 0 {
		writeHTTP(conn, 200, "application/json", []byte(`{"policy_limits":{},"restrictions":{},"compliance_taints":[]}`))
		return nil
	}
	path := "/v1/messages"
	if config.MessagesQuery != "" {
		path += "?" + config.MessagesQuery
	}
	if req.Method != "POST" || req.RequestURI != path {
		writeHTTP(conn, 404, "text/plain", nil)
		return nil
	}
	if *attempted {
		writeHTTP(conn, 409, "text/plain", nil)
		return nil
	}
	size := req.ContentLength
	if size < 1 || size > maxBody || req.Header.Get("Content-Length") != strconv.FormatInt(size, 10) ||
		req.Header.Get("Content-Type") != "application/json" {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, size+1))
	if err != nil || int64(len(data)) != size || !approvedHeaders(req, config) {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	requestDigest, promptDigest, err := normalizedRequest(data, config)
	if err != nil {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	if ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		return invalid
	}
	*attempted = true
	payload := struct {
		Model        string `json:"model"`
		PromptDigest string `json:"prompt_sha256"`
	}{config.Model, requestDigest}
	var result qualificationResult
	if b.call(ctx, "ingress", relayIngressOp, payload, &result) != nil || !result.valid(config.Model) ||
		ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		writeHTTP(conn, 503, "text/plain", nil)
		return invalid
	}
	written, err := writeHTTP(conn, 200, "text/event-stream", result.eventStream())
	if err != nil || ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		return errors.New("response write or endpoint verification failed")
	}
	var ack struct {
		Accepted bool `json:"accepted"`
	}
	completion := completionPayload{
		Selectors: config.Selectors, BindReceiptSHA256: bindReceipt,
		RequestSHA256: requestDigest, PromptSHA256: promptDigest, Model: config.Model,
		ResponseWireSHA256: written.SHA256, ResponseWireBytes: written.Bytes,
		HTTPStatus: written.Status, WriteStartedAt: written.StartedAt,
		WriteCompletedAt: written.CompletedAt,
	}
	if b.call(ctx, "complete", relayCompletionOp, completion, &ack) != nil || !ack.Accepted ||
		ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		return errors.New("broker completion rejected")
	}
	return nil
}
