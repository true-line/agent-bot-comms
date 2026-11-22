package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	config   assignment
	status   chan string
	peer     atomic.Uint32
	requests chan string
	done     chan error
	drop     chan struct{}
}

type statusWriter struct{ status chan string }

func (s statusWriter) Write(p []byte) (int, error) { s.status <- string(p); return len(p), nil }
func (s statusWriter) Close() error                { return nil }

func newFixture(t *testing.T, stale bool, providerDelay time.Duration) *fixture {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fixture{status: make(chan string, 1), requests: make(chan string, 4), done: make(chan error, 1), drop: make(chan struct{})}
	f.peer.Store(321)
	brokerDir, relayDir := filepath.Join(dir, "broker"), filepath.Join(dir, "relay")
	if os.Mkdir(brokerDir, 0750) != nil || os.Mkdir(relayDir, 0750) != nil {
		t.Fatal("could not provision paths")
	}
	cfg := &f.config
	cfg.Epoch = strings.Repeat("a", 64)
	cfg.BridgeUID, cfg.HQUID, cfg.RunnerUID = 322, 310, 321
	cfg.Model, cfg.PromptDigest, cfg.MessagesQuery = "probe", digest([]byte("exact prompt")), "beta=true"
	cfg.Expires = time.Now().Add(time.Minute)
	cfg.Selectors = selectors{"soul", "st_" + strings.Repeat("b", 24), "ln_" + strings.Repeat("c", 24), "plan", strings.Repeat("d", 64), "sha256:" + strings.Repeat("e", 64)}
	cfg.Broker.Path, cfg.Relay.Path = filepath.Join(brokerDir, "broker.sock"), filepath.Join(relayDir, "relay.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Broker.Path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	cfg.Broker.Parent, _ = observe(brokerDir, os.ModeDir)
	cfg.Broker.Socket, _ = observe(cfg.Broker.Path, os.ModeSocket)
	cfg.Relay.Parent, _ = observe(relayDir, os.ModeDir)
	cfg.Relay.Socket = identity{UID: cfg.Relay.Parent.UID, GID: cfg.Relay.Parent.GID, Mode: 0660}
	key := []byte(strings.Repeat("k", 32))
	go func() {
		conn, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		go func() { <-f.drop; conn.Close() }()
		scanner := bufio.NewScanner(conn)
		encoder := json.NewEncoder(conn)
		for scanner.Scan() {
			var req struct {
				ID      string         `json:"id"`
				Op      string         `json:"op"`
				Payload map[string]any `json:"payload"`
			}
			if json.Unmarshal(scanner.Bytes(), &req) != nil {
				return
			}
			f.requests <- req.Op
			var result any
			switch req.Op {
			case "bridge.bind.v2.challenge":
				expiration := time.Now().Add(15 * time.Second)
				if stale {
					expiration = time.Now().Add(-time.Second)
				}
				result = challenge{strings.Repeat("f", 64), "hmac-sha256", bindContext, cfg.Epoch, expiration}
			case "bridge.bind.v2":
				mac := hmac.New(sha256.New, []byte(strings.Repeat("k", 32)))
				s := cfg.Selectors
				message := strings.Join([]string{bindContext, strings.Repeat("f", 64), cfg.Epoch, s.Installation, s.Start,
					s.Launch, s.Plan, s.PlanDigest, s.Reservation, "322", cfg.Broker.Path}, "\x00")
				mac.Write([]byte(message))
				if len(req.Payload) != 7 || req.Payload["proof"] != hex.EncodeToString(mac.Sum(nil)) {
					return
				}
				result = map[string]string{"bind_receipt": strings.Repeat("1", 64)}
			case qualifyOp:
				time.Sleep(providerDelay)
				if len(req.Payload) != 2 || req.Payload["model"] != cfg.Model || req.Payload["prompt_sha256"] != cfg.PromptDigest {
					return
				}
				result = map[string]any{"model": cfg.Model, "text": "fixture response", "stop_reason": "end_turn",
					"usage": map[string]int{"input_tokens": 1, "output_tokens": 2}}
			default:
				return
			}
			if encoder.Encode(map[string]any{"id": req.ID, "ok": true, "result": result}) != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.drop:
		default:
			close(f.drop)
		}
	})
	go func() {
		f.done <- run(ctx, *cfg, key, statusWriter{f.status}, func(conn *net.UnixConn) (uint32, error) {
			if conn.RemoteAddr().String() == cfg.Broker.Path {
				return cfg.HQUID, nil
			}
			return f.peer.Load(), nil
		})
	}()
	return f
}

func (f *fixture) ready(t *testing.T) {
	t.Helper()
	select {
	case status := <-f.status:
		if !strings.Contains(status, digest([]byte(strings.Repeat("1", 64)))) {
			t.Fatalf("unexpected readiness %s", status)
		}
	case err := <-f.done:
		t.Fatalf("never became ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("readiness timeout")
	}
}

func (f *fixture) stopped(t *testing.T, message string) {
	t.Helper()
	select {
	case err := <-f.done:
		if err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("wrong failure: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop timeout")
	}
}

func (f *fixture) http(t *testing.T, body string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", f.config.Relay.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(qualificationTimeout + 2*ioTimeout))
	fmt.Fprintf(conn, "POST /v1/messages?beta=true HTTP/1.1\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data)
}

const prompt = `{"model":"probe","stream":true,"messages":[{"role":"user","content":"exact prompt"}]}`

func TestRelayRejectsWrongPeerAndMalformedHTTPThenQualifiesOnce(t *testing.T) {
	f := newFixture(t, false, 0)
	f.ready(t)
	f.peer.Store(322)
	if status, _ := f.http(t, prompt); status != 0 {
		t.Fatalf("wrong peer received HTTP %d", status)
	}
	f.peer.Store(321)
	for _, body := range []string{
		strings.Replace(prompt, "exact prompt", "wrong prompt", 1),
		strings.Replace(prompt, `"stream":true`, `"stream":true,"runtime_id":"other"`, 1),
		strings.Replace(prompt, `"stream":true`, `"stream":false,"stream":true`, 1),
		strings.Replace(prompt, `"content":"exact prompt"`, `"content":"exact prompt","extra":false`, 1),
		strings.Replace(prompt, `"model":"probe"`, `"model":"other"`, 1),
	} {
		if status, _ := f.http(t, body); status != 422 {
			t.Fatalf("malformed input returned %d", status)
		}
	}
	for _, extra := range []string{
		`"system":"alternate instructions"`,
		`"tools":[{"name":"alternate_tool","input_schema":{"type":"object"}}]`,
		`"tool_choice":{"type":"tool","name":"alternate_tool"}`,
		`"thinking":{"type":"enabled","budget_tokens":1024}`,
		`"temperature":0.5`,
		`"metadata":{"user_id":"another-user"}`,
		`"max_tokens":32`,
	} {
		body := strings.TrimSuffix(prompt, "}") + "," + extra + "}"
		if status, _ := f.http(t, body); status != 422 {
			t.Fatalf("unpinned field %s returned %d", extra, status)
		}
	}
	for _, content := range []string{
		`"role":"assistant","role":"user","content":"exact prompt"`,
		`"role":"user","content":[{"type":"text","text":"exact prompt","cache_control":{"type":"ephemeral"}}]`,
		`"role":"user","content":[{"type":"text","text":"alternate prompt","text":"exact prompt"}]`,
	} {
		body := strings.Replace(prompt, `"role":"user","content":"exact prompt"`, content, 1)
		if status, _ := f.http(t, body); status != 422 {
			t.Fatalf("unpinned nested fields returned %d for %s", status, content)
		}
	}
	if status, body := f.http(t, prompt); status != 200 || !strings.Contains(body, "fixture response") || !strings.Contains(body, "event: message_stop") {
		t.Fatalf("unexpected response %d %s", status, body)
	}
	if status, _ := f.http(t, prompt); status != 409 {
		t.Fatalf("replay returned %d", status)
	}
	for _, op := range []string{"bridge.bind.v2.challenge", "bridge.bind.v2", qualifyOp} {
		if got := <-f.requests; got != op {
			t.Fatalf("op %s != %s", got, op)
		}
	}
	select {
	case op := <-f.requests:
		t.Fatalf("unexpected op: %s", op)
	default:
	}
}

func TestStaleChallengeNeverCreatesRelay(t *testing.T) {
	f := newFixture(t, true, 0)
	f.stopped(t, "broker bind rejected")
	if _, err := os.Lstat(f.config.Relay.Path); !os.IsNotExist(err) {
		t.Fatalf("unexpected relay: %v", err)
	}
	if got := <-f.requests; got != "bridge.bind.v2.challenge" {
		t.Fatal(got)
	}
	select {
	case status := <-f.status:
		t.Fatal(status)
	default:
	}
}

func TestBrokerDisconnectCleansUpOwnedSocket(t *testing.T) {
	f := newFixture(t, false, 0)
	f.ready(t)
	close(f.drop)
	f.stopped(t, "broker disconnected")
	if _, err := os.Lstat(f.config.Relay.Path); !os.IsNotExist(err) {
		t.Fatalf("owned relay remains: %v", err)
	}
}

func TestEndpointReplacementStopsRelayAndPreservesReplacement(t *testing.T) {
	f := newFixture(t, false, 0)
	f.ready(t)
	if err := os.Rename(f.config.Relay.Path, f.config.Relay.Path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config.Relay.Path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	f.stopped(t, "endpoint identity changed")
	data, err := os.ReadFile(f.config.Relay.Path)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement modified: %s, %v", data, err)
	}
}

func TestUnavailableVerifierFailsClosed(t *testing.T) {
	if peerMatches(nil, 321, nil) || peerMatches(nil, 321, func(*net.UnixConn) (uint32, error) { return 321, errors.New("unavailable") }) {
		t.Fatal("unavailable kernel verification granted authority")
	}
}

func TestQualificationCanExceedBindAndRequestTimeout(t *testing.T) {
	f := newFixture(t, false, ioTimeout+200*time.Millisecond)
	f.ready(t)
	if status, body := f.http(t, prompt); status != 200 || !strings.Contains(body, "fixture response") {
		t.Fatalf("delayed qualification got %d %s", status, body)
	}
	if status, _ := f.http(t, prompt); status != 409 {
		t.Fatalf("delayed qualification replay got %d", status)
	}
}

func TestRelayPostBindMismatchReportsUncertainCleanup(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "b-cleanup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	parent, err := observe(dir, os.ModeDir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "relay.sock")
	target := endpoint{
		Path: path, Parent: parent,
		Socket: identity{UID: parent.UID, GID: parent.GID + 1, Mode: 0660},
	}
	listener, _, _, err := listenRelay(target)
	if listener != nil || !errors.Is(err, errCleanupUnconfirmed) {
		t.Fatalf("wrong result for unverified post-bind socket: %v", err)
	}
	if _, err := observe(path, os.ModeSocket); err != nil {
		t.Fatalf("unverified pathname was removed: %v", err)
	}
	stream, err := net.Dial("unix", path)
	if err == nil {
		stream.Close()
		t.Fatal("unverified listener was left open")
	}
}
