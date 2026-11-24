//go:build !darwin || !cgo

package main

func liveV3Child(v3ObservedChild, v3Member) bool { return false }

func cooperativeSelfMatches(map[string]any, map[string]any) bool { return false }
