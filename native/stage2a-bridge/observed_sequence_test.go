package main

import "testing"

func TestObservedSequenceAllowsOnlySelectedOrders(t *testing.T) {
	for name, classes := range map[string][]observedRequestClass{
		"A_target_B": {observedAncillaryA, observedTarget, observedAncillaryB},
		"A_B_target": {observedAncillaryA, observedAncillaryB, observedTarget},
	} {
		t.Run(name, func(t *testing.T) {
			var s observedSequence
			for _, class := range classes {
				if err := s.accept(class); err != nil {
					t.Fatalf("selected request order rejected: %v", err)
				}
			}
			if !s.complete() || s.accept(observedTarget) == nil || s.accept(observedAncillaryA) == nil ||
				s.accept(observedAncillaryB) == nil {
				t.Fatal("completed route accepted an extra request")
			}
		})
	}
	for name, classes := range map[string][]observedRequestClass{
		"target_first":    {observedTarget},
		"B_first":         {observedAncillaryB},
		"A_A":             {observedAncillaryA, observedAncillaryA},
		"A_target_target": {observedAncillaryA, observedTarget, observedTarget},
		"A_B_B":           {observedAncillaryA, observedAncillaryB, observedAncillaryB},
		"A_target_A":      {observedAncillaryA, observedTarget, observedAncillaryA},
		"unknown":         {observedAncillaryA, 0},
	} {
		t.Run(name, func(t *testing.T) {
			var s observedSequence
			refused := false
			for _, class := range classes {
				if s.accept(class) != nil {
					refused = true
					break
				}
			}
			if !refused {
				t.Fatal("unselected request order accepted")
			}
		})
	}
}

func TestObservedSequencePinsOneStockClientAcrossConnections(t *testing.T) {
	peer := observedPeer{UID: 303, PID: 4101, PIDVersion: 7,
		StartSeconds: 1795500000, ParentPID: 4001, ParentUID: 303,
		ParentStartSeconds: 1795499999}
	var s observedSequence
	if s.acceptFrom(observedAncillaryA, peer) != nil {
		t.Fatal("first stock peer refused")
	}
	other := peer
	other.PID++
	if s.acceptFrom(observedTarget, other) == nil || s.target {
		t.Fatal("sibling stock process joined the first ancillary")
	}
	other = peer
	other.PIDVersion++
	if s.acceptFrom(observedTarget, other) == nil || s.target {
		t.Fatal("reused stock PID joined the first ancillary")
	}
	if s.acceptFrom(observedTarget, peer) != nil || !s.target {
		t.Fatal("original stock process could not continue")
	}
}
