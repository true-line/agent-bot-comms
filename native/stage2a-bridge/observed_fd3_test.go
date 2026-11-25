package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// This record is signed with a public deterministic test key. Its host and
// header values are synthetic; it is not an installed Machine assignment.
func observedFD3Fixture(t *testing.T) (observedFD3, []byte, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/observed-fd3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		MachinePublicKey string      `json:"machine_public_key_base64url"`
		FD3              observedFD3 `json:"b_fd3"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	pin, err := base64.RawURLEncoding.DecodeString(fixture.MachinePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.FD3, pin, time.Date(2026, 11, 24, 12, 0, 10, 0, time.UTC)
}

func TestObservedFD3RequiresSignedExactEntry(t *testing.T) {
	fd3, pin, now := observedFD3Fixture(t)
	raw, err := json.Marshal(fd3)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > cooperativeFD3MaxBytes {
		t.Fatal("synthetic FD3 exceeds launch cap")
	}
	authority, err := verifyObservedFD3(raw, pin, now)
	if err != nil {
		t.Fatalf("synthetic signed FD3 refused: %v", err)
	}
	if authority.FD3.Selectors.LaunchID != fd3.Selectors.LaunchID ||
		authority.FD3.LocalTest.SelectedLaunchID != fd3.LocalTest.SelectedLaunchID ||
		authority.FD3.Selectors.LaunchID == fd3.LocalTest.SelectedLaunchID {
		t.Fatal("outer and selected-member launch were conflated")
	}
	const childRoot = "/var/agent-bot-soul-runner-_abm-sr-8418d3315c8a4f09327c/" +
		"state/child-70799e6441e7d13e10b2"
	if fd3.LocalTest.ExpectedChildCWDLexical != childRoot+"/work" ||
		fd3.LocalTest.ExpectedChildCWDEmitted != "/private"+childRoot+"/work" ||
		fd3.LocalTest.ExpectedChildHomeLexical != childRoot+"/home" ||
		len(fd3.LocalTest.AncillaryProfile.TargetAfter) != 1 ||
		fd3.LocalTest.AncillaryProfile.TargetAfter[0] != "first" {
		t.Fatal("signed c5 child paths or ancillary order differ from Machine source")
	}
	for name, mutate := range map[string]func(*observedFD3){
		"wrong_assignment_purpose": func(f *observedFD3) {
			f.AssignmentEnvelope = f.AuthorityEnvelope
		},
		"unsigned_local_test": func(f *observedFD3) {
			f.LocalTest.Model = "other-model"
		},
		"wrong_relay_path": func(f *observedFD3) {
			f.Relay.Path += ".other"
		},
		"created_relay_inode": func(f *observedFD3) {
			f.Relay.Socket.Inode = 1
		},
		"created_relay_device": func(f *observedFD3) {
			f.Relay.Socket.Device = 1
		},
		"other_outer_launch": func(f *observedFD3) {
			f.Selectors.LaunchID = "ln_" + strings.Repeat("3", 24)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := fd3
			mutate(&changed)
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyObservedFD3(raw, pin, now); err == nil {
				t.Fatal("mutated FD3 accepted before socket setup")
			}
		})
	}
	wrongPin := append([]byte(nil), pin...)
	wrongPin[0] ^= 1
	if _, err := verifyObservedFD3(raw, wrongPin, now); err == nil {
		t.Fatal("different Machine pin accepted")
	}
	if _, err := verifyObservedFD3(raw, pin, fd3.Expires); err == nil {
		t.Fatal("expired signed FD3 accepted")
	}
}
