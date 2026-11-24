package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCompletionOriginMachineHQVector(t *testing.T) {
	data, err := os.ReadFile("testdata/completion-origin-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex           string         `json:"raw_fd4_hex"`
		Completion          completionCore `json:"completion"`
		CompletionKeyHex    string         `json:"completion_key_hex"`
		CompletionOriginMAC string         `json:"completion_origin_mac"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid shared completion vector")
	}
	raw, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	subkey, err := deriveCompletionSubkey(raw, vector.Completion.Selectors.Reservation)
	if err != nil || hex.EncodeToString(subkey) != vector.CompletionKeyHex {
		t.Fatalf("completion subkey differs from Machine/HQ vector: %v", err)
	}
	canonical, err := canonicalJSONValue(vector.Completion)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSum := sha256.Sum256(canonical)
	if hex.EncodeToString(canonicalSum[:]) != "7dc32def5361deb8f655b17a18272f1493910a97ee877a53398bb9e6862c3a63" {
		t.Fatal("completion JCS differs from Machine/HQ vector")
	}
	mac, err := completionOriginMAC(subkey, vector.Completion)
	if err != nil || mac != vector.CompletionOriginMAC {
		t.Fatalf("completion MAC differs from Machine/HQ vector: %v", err)
	}
	for name, change := range map[string]func(*completionCore){
		"wire":      func(c *completionCore) { c.ResponseWireBytes++ },
		"peer":      func(c *completionCore) { c.Peer["pid"] = float64(4102) },
		"receipt":   func(c *completionCore) { c.PrewriteReceipt = "0" + c.PrewriteReceipt[1:] },
		"timestamp": func(c *completionCore) { c.WriteCompletedAt = c.WriteCompletedAt.Add(1) },
		"reservation": func(c *completionCore) {
			c.Selectors.Reservation = "sha256:" + vector.Completion.Selectors.Reservation[7:63] + "bbbbbbbb"
		},
	} {
		changed := vector.Completion
		changed.Peer = make(map[string]any, len(vector.Completion.Peer))
		for key, value := range vector.Completion.Peer {
			changed.Peer[key] = value
		}
		change(&changed)
		got, err := completionOriginMAC(subkey, changed)
		if err != nil || got == vector.CompletionOriginMAC {
			t.Errorf("%s change retained completion MAC: %v", name, err)
		}
	}
	clear(subkey)
	for _, b := range subkey {
		if b != 0 {
			t.Fatal("completion subkey was not cleared")
		}
	}
}
