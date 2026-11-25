package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestObservedBindPartsMatchCrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Selectors observedSelectors `json:"selectors"`
		Bind      struct {
			Parts []string `json:"parts"`
		} `json:"bind"`
	}
	if json.Unmarshal(data, &vector) != nil || len(vector.Bind.Parts) != 16 {
		t.Fatal("invalid shared bind vector")
	}
	want := vector.Bind.Parts
	uid, err := strconv.ParseUint(want[9], 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	in := observedBindInput{
		Selectors: vector.Selectors, Epoch: want[2], BridgeUID: uint32(uid),
		BrokerPath: want[10], RunnerAccount: want[11], ChildCWDEmitted: want[12],
		BodyProfile: want[13], StaticProjectionSHA256: want[14], OwnerPromptSHA256: want[15],
	}
	got, err := in.parts(want[1])
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("bind preimage fields differ from Contracts vector: %v", err)
	}
	in.ChildCWDEmitted = "/var/agent-bot-soul-runner-test/work"
	changed, err := in.parts(want[1])
	if err != nil || reflect.DeepEqual(changed, want) {
		t.Fatal("lexical cwd substitution kept emitted-cwd bind preimage")
	}
	in.BodyProfile = "stage2a-b-assignment/v2"
	if _, err := in.parts(want[1]); err == nil {
		t.Fatal("v2 profile entered distinct bind")
	}
}

func TestObservedBindUsesSingleBrokerStream(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex string            `json:"raw_fd4_hex"`
		Selectors observedSelectors `json:"selectors"`
		Bind      struct {
			Parts    []string `json:"parts"`
			ProofHex string   `json:"proof_hex"`
		} `json:"bind"`
	}
	if json.Unmarshal(data, &vector) != nil || len(vector.Bind.Parts) != 16 {
		t.Fatal("invalid shared bind vector")
	}
	rawFD4, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "observed-bind-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	parent, err := observe(dir, os.ModeDir)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := observe(path, os.ModeSocket)
	if err != nil {
		t.Fatal(err)
	}
	e := endpoint{Path: path, Parent: parent, Socket: socket}
	parts := vector.Bind.Parts
	input := observedBindInput{Selectors: vector.Selectors, Epoch: parts[2], BridgeUID: 301,
		BrokerPath: path, RunnerAccount: parts[11], ChildCWDEmitted: parts[12],
		BodyProfile: parts[13], StaticProjectionSHA256: parts[14], OwnerPromptSHA256: parts[15],
		Expires: time.Now().Add(10 * time.Second)}
	actualParts, err := input.parts(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	expectedProof, err := observedBindProof(rawFD4, actualParts)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewScanner(conn)
		encoder := json.NewEncoder(conn)
		for index := 0; index < 2; index++ {
			if !reader.Scan() {
				serverDone <- invalid
				return
			}
			var request struct {
				ID      string          `json:"id"`
				Op      string          `json:"op"`
				Payload json.RawMessage `json:"payload"`
			}
			if decode(reader.Bytes(), &request) != nil {
				serverDone <- invalid
				return
			}
			var result any
			if index == 0 {
				var selectors observedSelectors
				if request.ID != "challenge" || request.Op != observedBindChallengeOp ||
					decode(request.Payload, &selectors) != nil || selectors != vector.Selectors {
					serverDone <- invalid
					return
				}
				result = challenge{parts[1], "hmac-sha256", observedBindContext,
					parts[2], time.Now().Add(5 * time.Second)}
			} else {
				var bind struct {
					Selectors observedSelectors `json:"selectors"`
					Proof     string            `json:"proof"`
				}
				if request.ID != "bind" || request.Op != observedBindOp ||
					decode(request.Payload, &bind) != nil || bind.Selectors != vector.Selectors ||
					bind.Proof != expectedProof {
					serverDone <- invalid
					return
				}
				result = map[string]string{"bind_receipt": strings.Repeat("1", 64)}
			}
			if err := encoder.Encode(map[string]any{"id": request.ID, "ok": true, "result": result}); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := openBroker(ctx, assignment{Broker: e, HQUID: parent.UID},
		func(*net.UnixConn) (uint32, error) { return parent.UID, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.conn.Close()
	receipt, err := b.bindObserved(ctx, input, rawFD4, e.current)
	if err != nil || receipt != digest([]byte(strings.Repeat("1", 64))) {
		t.Fatalf("observed bind refused same-stream reply: %s %v", receipt, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("H saw different observed bind wire: %v", err)
	}
	for _, value := range rawFD4 {
		if value != 0 {
			t.Fatal("raw FD4 retained after bind")
		}
	}
}
