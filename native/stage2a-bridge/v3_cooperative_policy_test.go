package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type cooperativePolicyFixture struct {
	Source    string                `json:"contracts_fixture_source"`
	PublicKey string                `json:"issuer_public_key_base64url"`
	FD3       cooperativeFD3        `json:"fd3"`
	Policy    cooperativePolicyWire `json:"policy"`
}

func TestCooperativeBindUsesOneBrokerConnection(t *testing.T) {
	a, _, _, _ := policyFixture(t)
	a.Expires = time.Now().Add(12 * time.Second)
	dir, err := os.MkdirTemp("/tmp", "cb-")
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
	parent, _ := observe(dir, os.ModeDir)
	socket, _ := observe(path, os.ModeSocket)
	endpoint := endpoint{Path: path, Parent: parent, Socket: socket}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
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
			if decode(reader.Bytes(), &request) != nil || request.Op != "bridge.bind.cooperative.v3" {
				serverDone <- invalid
				return
			}
			var result any
			if index == 0 {
				if string(request.Payload) != "{}" {
					serverDone <- invalid
					return
				}
				result = cooperativeChallenge{strings.Repeat("a", 64), "hmac-sha256",
					cooperativeBindContext, a.Epoch, time.Now().Add(5 * time.Second)}
			} else {
				var proof cooperativeBindRequest
				if decode(request.Payload, &proof) != nil || proof.Proof !=
					"85654dc15cb085f1a0cf9577e93141923bcdad1afa5bea4073fbc3733ead5683" ||
					proof.Assignment != a.AssignmentSHA || proof.Reservation != a.ReservationSHA ||
					proof.BrokerPath != a.BrokerPath {
					serverDone <- invalid
					return
				}
				result = map[string]string{"bind_receipt_sha256": "sha256:" + strings.Repeat("f", 64)}
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
	b, err := openBroker(ctx, assignment{Broker: endpoint, HQUID: parent.UID},
		func(*net.UnixConn) (uint32, error) { return parent.UID, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.conn.Close()
	receipt, err := b.bindCooperativeChecked(ctx, a, key, endpoint.current)
	if err != nil || receipt != "sha256:"+strings.Repeat("f", 64) {
		t.Fatalf("cooperative bind refused its same-stream H reply: %s %v", receipt, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("H saw a different cooperative bind wire: %v", err)
	}
}

func policyFixture(t *testing.T) (cooperativeBridgeAuthority, cooperativePolicyWire, []byte, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("testdata/v3-cooperative-policy-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cooperativePolicyFixture
	if decode(raw, &fixture) != nil || fixture.Source != "soul-contracts #87 cooperative two-member synthetic pair" {
		t.Fatal("invalid pinned Contracts policy fixture")
	}
	pin, err := base64.RawURLEncoding.DecodeString(fixture.PublicKey)
	if err != nil || len(pin) != ed25519.PublicKeySize {
		t.Fatal("invalid fixture A pin")
	}
	fd3, err := json.Marshal(fixture.FD3)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 14, 15, 19, 0, time.UTC)
	authority, err := verifyCooperativeFD3(fd3, pin, now)
	if err != nil {
		t.Fatalf("Contracts signed cooperative FD3 refused: %v", err)
	}
	return authority, fixture.Policy, pin, now
}

func fixtureEndpoint(t *testing.T, record map[string]any, created bool) endpoint {
	t.Helper()
	device, e1 := strconv.ParseUint(field(record, "parent_device"), 10, 64)
	inode, e2 := strconv.ParseUint(field(record, "parent_inode"), 10, 64)
	if e1 != nil || e2 != nil {
		t.Fatal("invalid signed parent")
	}
	owner, group := uint32(integer(record, "owner_uid")), uint32(integer(record, "group_gid"))
	socket := identity{UID: owner, GID: group, Mode: 0660}
	if created {
		socket.Device, socket.Inode = device, inode+1000
	}
	return endpoint{Path: field(record, "socket_path"),
		Parent: identity{UID: owner, GID: group, Device: device, Inode: inode, Mode: 02750},
		Socket: socket}
}

func TestCooperativePolicySignedPairAndRefusals(t *testing.T) {
	a, result, pin, now := policyFixture(t)
	broker := fixtureEndpoint(t, a.BrokerRecord, true)
	relay := fixtureEndpoint(t, a.RelayRecord, false)
	verified, err := verifyCooperativePolicy(result, a, pin, broker, relay, now)
	if err != nil || verified.FD3.Expires.IsZero() ||
		verified.FD3.Selectors.Reservation != a.ReservationSHA ||
		verified.Members[0].ID == verified.Members[1].ID {
		t.Fatalf("full A-signed two-member cooperative policy refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*cooperativePolicyWire, *cooperativeBridgeAuthority, *[]byte, *endpoint)
	}{
		{"wrong pin", func(_ *cooperativePolicyWire, _ *cooperativeBridgeAuthority, key *[]byte, _ *endpoint) {
			(*key)[0] ^= 1
		}},
		{"swapped envelopes", func(p *cooperativePolicyWire, _ *cooperativeBridgeAuthority, _ *[]byte, _ *endpoint) {
			p.AssignmentEnvelope, p.AuthorityEnvelope = p.AuthorityEnvelope, p.AssignmentEnvelope
			p.AssignmentSHA, p.AuthoritySHA = p.AuthoritySHA, p.AssignmentSHA
		}},
		{"changed detached B assignment", func(_ *cooperativePolicyWire, a *cooperativeBridgeAuthority, _ *[]byte, _ *endpoint) {
			a.AssignmentSHA = "sha256:" + strings.Repeat("0", 64)
		}},
		{"changed broker parent", func(_ *cooperativePolicyWire, _ *cooperativeBridgeAuthority, _ *[]byte, e *endpoint) {
			e.Parent.Inode++
		}},
		{"changed signed envelope", func(p *cooperativePolicyWire, _ *cooperativeBridgeAuthority, _ *[]byte, _ *endpoint) {
			p.AssignmentEnvelope = "A" + p.AssignmentEnvelope[1:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed, authority, key, endpoint := result, a, append([]byte(nil), pin...), broker
			tc.edit(&changed, &authority, &key, &endpoint)
			if _, err := verifyCooperativePolicy(changed, authority, key, endpoint, relay, now); err == nil {
				t.Fatal("changed cooperative policy accepted")
			}
		})
	}
	if _, err := verifyCooperativePolicy(result, a, pin, broker, relay, verified.FD3.Expires); err == nil {
		t.Fatal("expired cooperative member policy accepted")
	}
}

func TestCooperativeBindFixedPreimage(t *testing.T) {
	a, _, _, _ := policyFixture(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	proof, err := cooperativeProof(key, strings.Repeat("a", 64), a)
	if err != nil || proof != "85654dc15cb085f1a0cf9577e93141923bcdad1afa5bea4073fbc3733ead5683" {
		t.Fatalf("cooperative bind preimage differs from independent vector: %s %v", proof, err)
	}
	if _, err := cooperativeProof(key[:31], strings.Repeat("a", 64), a); err == nil {
		t.Fatal("truncated FD4 key accepted")
	}
}

func TestCooperativeSignedChildObservation(t *testing.T) {
	a, result, pin, now := policyFixture(t)
	broker := fixtureEndpoint(t, a.BrokerRecord, true)
	relay := fixtureEndpoint(t, a.RelayRecord, false)
	authority, err := verifyCooperativePolicy(result, a, pin, broker, relay, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/v3-cooperative-observation.jcs")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSpace(raw)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	observed, err := verifyCooperativeObservation(encoded, authority, now.Add(time.Second))
	if err != nil || observed.EnvelopeDigest != digest(raw) ||
		observed.Children[0].MemberID != authority.Members[0].ID ||
		observed.Children[1].MemberID != authority.Members[1].ID {
		t.Fatalf("A-signed cooperative two-child observation refused: %v", err)
	}
	if _, err := verifyV3Observation(encoded, authority, now.Add(time.Second)); err == nil {
		t.Fatal("cooperative observation crossed protected profile")
	}
	if _, err := verifyCooperativeObservation(encoded, authority, observed.Expires); err == nil {
		t.Fatal("expired cooperative child observation accepted")
	}
}
