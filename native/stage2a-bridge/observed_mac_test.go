package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestObservedLocalTestGoldenMACs(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex string `json:"raw_fd4_hex"`
		Selectors struct {
			Reservation string `json:"reservation_digest"`
		} `json:"selectors"`
		Bind struct {
			Parts       []string `json:"parts"`
			PreimageHex string   `json:"preimage_hex"`
			ProofHex    string   `json:"proof_hex"`
		} `json:"bind"`
		Ingress struct {
			Core         json.RawMessage `json:"core"`
			CoreJCS      string          `json:"core_jcs"`
			SubkeyHex    string          `json:"subkey_hex"`
			OriginMACHex string          `json:"origin_mac_hex"`
		} `json:"ingress"`
		Completion struct {
			Core         json.RawMessage `json:"core"`
			CoreJCS      string          `json:"core_jcs"`
			SubkeyHex    string          `json:"subkey_hex"`
			OriginMACHex string          `json:"origin_mac_hex"`
		} `json:"completion"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid golden fixture")
	}
	raw, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString([]byte(strings.Join(vector.Bind.Parts, "\x00"))) != vector.Bind.PreimageHex {
		t.Fatal("bind preimage differs from cross-language vector")
	}
	proof, err := observedBindProof(raw, vector.Bind.Parts)
	if err != nil || proof != vector.Bind.ProofHex {
		t.Fatalf("bind proof differs from vector: %s %v", proof, err)
	}
	for _, row := range []struct {
		name, keyDomain, macDomain, wantKey, wantMAC, wantJCS string
		core                                                  json.RawMessage
	}{
		{"ingress", observedIngressKeyContext, observedIngressOriginContext,
			vector.Ingress.SubkeyHex, vector.Ingress.OriginMACHex, vector.Ingress.CoreJCS, vector.Ingress.Core},
		{"completion", observedCompleteKeyContext, observedCompleteOriginContext,
			vector.Completion.SubkeyHex, vector.Completion.OriginMACHex, vector.Completion.CoreJCS, vector.Completion.Core},
	} {
		t.Run(row.name, func(t *testing.T) {
			var typed any
			if row.name == "ingress" {
				var core observedIngressCore
				if decode(row.core, &core) != nil {
					t.Fatal("typed ingress core rejected golden vector")
				}
				typed = core
			} else {
				var core observedCompletionCore
				if decode(row.core, &core) != nil {
					t.Fatal("typed completion core rejected golden vector")
				}
				typed = core
			}
			canonical, err := canonicalJSONValue(typed)
			if err != nil || string(canonical) != row.wantJCS {
				t.Fatal("core JCS differs from cross-language vector")
			}
			key, err := observedSubkey(raw, vector.Selectors.Reservation, row.keyDomain)
			if err != nil || hex.EncodeToString(key) != row.wantKey {
				t.Fatal("FD4 subkey differs from cross-language vector")
			}
			got, err := observedOriginMAC(key, row.macDomain, typed)
			clear(key)
			if err != nil || got != row.wantMAC {
				t.Fatalf("origin MAC differs from vector: %s %v", got, err)
			}
			// HQ knows the public bind proof; it cannot turn that into B's MAC.
			public, _ := hex.DecodeString(proof)
			forgedKey, err := observedSubkey(public, vector.Selectors.Reservation, row.keyDomain)
			if err != nil {
				t.Fatal(err)
			}
			forged, err := observedOriginMAC(forgedKey, row.macDomain, typed)
			clear(forgedKey)
			if err != nil || forged == row.wantMAC {
				t.Fatal("public bind proof forged B origin MAC")
			}
		})
	}
}
