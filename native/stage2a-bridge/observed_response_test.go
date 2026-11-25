package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestObservedPrewriteAndCompletionMatchGoldenCore(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex string `json:"raw_fd4_hex"`
		Selectors struct {
			Reservation string `json:"reservation_digest"`
		} `json:"selectors"`
		Ingress struct {
			Core observedIngressCore `json:"core"`
		} `json:"ingress"`
		Authorization struct {
			EnvelopeSHA string `json:"envelope_sha256"`
		} `json:"authorization"`
		Completion struct {
			Core         observedCompletionCore `json:"core"`
			CoreJCS      string                 `json:"core_jcs"`
			OriginMACHex string                 `json:"origin_mac_hex"`
		} `json:"completion"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid shared completion vector")
	}
	coreBytes, err := canonicalJSONValue(vector.Ingress.Core)
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedHTTP{Wire: []byte("synthetic response wire"),
		SHA256: digest([]byte("synthetic response wire")), Bytes: 23, Status: 200}
	now := time.Date(2026, 11, 24, 12, 0, 1, 0, time.UTC)
	prewrite, err := buildObservedPrewrite(vector.Ingress.Core, observedAuthorized{
		AuthorizationEnvelopeSHA256: vector.Authorization.EnvelopeSHA,
		IngressCoreSHA256:           digest(coreBytes),
	}, prepared, now)
	if err != nil {
		t.Fatalf("golden prewrite refused: %v", err)
	}
	wantPrewrite := vector.Completion.Core.observedPrewrite
	wantPrewrite.Schema = "stage2a-observed-body-local-test-prewrite/v1"
	if prewrite != wantPrewrite {
		t.Fatal("prewrite differs from cross-language vector")
	}
	started, _ := time.Parse(time.RFC3339Nano, vector.Completion.Core.WriteStartedAt)
	completed, _ := time.Parse(time.RFC3339Nano, vector.Completion.Core.WriteCompletedAt)
	completion, err := buildObservedCompletion(prewrite, vector.Completion.Core.PrewriteReceipt,
		httpWrite{SHA256: prepared.SHA256, Bytes: prepared.Bytes, Status: prepared.Status,
			StartedAt: started, CompletedAt: completed})
	if err != nil || completion != vector.Completion.Core {
		t.Fatalf("golden completion differs: %v", err)
	}
	canonical, err := canonicalJSONValue(completion)
	if err != nil || string(canonical) != vector.Completion.CoreJCS {
		t.Fatal("golden completion JCS differs")
	}
	rawFD4, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := observedSubkey(rawFD4, vector.Selectors.Reservation, observedCompleteKeyContext)
	if err != nil {
		t.Fatal(err)
	}
	attempted := false
	sealed, err := sealObservedCompletion(completion, key, &attempted)
	if err != nil || sealed.CompletionOriginMAC != vector.Completion.OriginMACHex || !attempted {
		t.Fatalf("golden full-write MAC differs: %v", err)
	}
	if _, err := sealObservedCompletion(completion, key, &attempted); err == nil {
		t.Fatal("second completion attempt accepted")
	}
	prepared.Wire[0] ^= 1
	if _, err := buildObservedPrewrite(vector.Ingress.Core, observedAuthorized{
		AuthorizationEnvelopeSHA256: vector.Authorization.EnvelopeSHA,
		IngressCoreSHA256:           digest(coreBytes),
	}, prepared, now); err == nil {
		t.Fatal("changed response wire accepted before prewrite")
	}
	prewrite.ResponseWireSHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := buildObservedCompletion(prewrite, vector.Completion.Core.PrewriteReceipt,
		httpWrite{SHA256: digest([]byte("synthetic response wire")), Bytes: 23,
			Status: 200, StartedAt: started, CompletedAt: completed}); err == nil {
		t.Fatal("changed response wire accepted at completion")
	}
}

func TestObservedPrewriteJoinsEverySignedIngressField(t *testing.T) {
	data, err := os.ReadFile("testdata/local-test-golden-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Ingress struct {
			Core observedIngressCore `json:"core"`
		} `json:"ingress"`
		Authorization struct {
			EnvelopeSHA string `json:"envelope_sha256"`
		} `json:"authorization"`
		Completion struct {
			Core observedCompletionCore `json:"core"`
		} `json:"completion"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	prewrite := vector.Completion.Core.observedPrewrite
	prewrite.Schema = "stage2a-observed-body-local-test-prewrite/v1"
	if err := verifyObservedPrewriteJoins(prewrite, vector.Ingress.Core,
		vector.Authorization.EnvelopeSHA); err != nil {
		t.Fatalf("golden ingress/prewrite join refused: %v", err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	for name, change := range map[string]func(*observedPrewrite){
		"selectors":         func(p *observedPrewrite) { p.Selectors.LaunchID = "ln_" + strings.Repeat("3", 24) },
		"bind_receipt":      func(p *observedPrewrite) { p.BindReceiptSHA256 = wrong },
		"authorization":     func(p *observedPrewrite) { p.AuthorizationEnvelopeSHA256 = wrong },
		"ingress_core":      func(p *observedPrewrite) { p.IngressCoreSHA256 = wrong },
		"body":              func(p *observedPrewrite) { p.ObservedBodySHA256 = wrong },
		"headers":           func(p *observedPrewrite) { p.ObservedHeadersSHA256 = wrong },
		"static_projection": func(p *observedPrewrite) { p.StaticProjectionSHA256 = wrong },
		"owner_prompt":      func(p *observedPrewrite) { p.OwnerPromptSHA256 = wrong },
		"peer":              func(p *observedPrewrite) { p.Peer.PID++ },
		"peer_sha":          func(p *observedPrewrite) { p.PeerSHA256 = wrong },
	} {
		t.Run(name, func(t *testing.T) {
			changed := prewrite
			change(&changed)
			if verifyObservedPrewriteJoins(changed, vector.Ingress.Core,
				vector.Authorization.EnvelopeSHA) == nil {
				t.Fatal("cross-ingress prewrite splice accepted")
			}
		})
	}
}
