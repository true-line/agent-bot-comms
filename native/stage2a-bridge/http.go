package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxBody = 256 << 10

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

func exactPrompt(data []byte, config assignment) bool {
	fields := objectFields(data, "model", "stream", "messages")
	if fields == nil {
		return false
	}
	var model string
	var stream bool
	var messages []json.RawMessage
	if json.Unmarshal(fields["model"], &model) != nil || model != config.Model ||
		json.Unmarshal(fields["stream"], &stream) != nil || !stream ||
		json.Unmarshal(fields["messages"], &messages) != nil || len(messages) != 1 {
		return false
	}
	message := objectFields(messages[0], "role", "content")
	var role string
	if json.Unmarshal(message["role"], &role) != nil || role != "user" {
		return false
	}
	var text string
	content := message["content"]
	if len(content) > 0 && content[0] == '"' && json.Unmarshal(content, &text) == nil {
		return digest([]byte(text)) == config.PromptDigest
	}
	var blocks []json.RawMessage
	if json.Unmarshal(content, &blocks) != nil || len(blocks) != 1 {
		return false
	}
	block := objectFields(blocks[0], "type", "text")
	var kind string
	return json.Unmarshal(block["type"], &kind) == nil && kind == "text" && len(block["text"]) > 0 &&
		block["text"][0] == '"' && json.Unmarshal(block["text"], &text) == nil && digest([]byte(text)) == config.PromptDigest
}

func writeHTTP(conn *net.UnixConn, status int, contentType string, data []byte) {
	if conn.SetWriteDeadline(deadline()) != nil {
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
		status, http.StatusText(status), contentType, len(data))
	conn.Write(data)
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

func serve(ctx context.Context, conn *net.UnixConn, b *broker, config assignment, relay endpoint, attempted *bool) error {
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
	if err != nil || int64(len(data)) != size || !exactPrompt(data, config) {
		writeHTTP(conn, 422, "text/plain", nil)
		return nil
	}
	if ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		return invalid
	}
	*attempted = true
	payload := struct {
		Model  string `json:"model"`
		Digest string `json:"prompt_sha256"`
	}{config.Model, config.PromptDigest}
	var result qualificationResult
	if b.call(ctx, "qualify", qualifyOp, payload, &result) != nil || !result.valid(config.Model) ||
		ctx.Err() != nil || !relay.current() || !config.Broker.current() {
		writeHTTP(conn, 503, "text/plain", nil)
		return invalid
	}
	writeHTTP(conn, 200, "text/event-stream", result.eventStream())
	return nil
}
