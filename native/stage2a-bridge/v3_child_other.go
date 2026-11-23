//go:build !darwin || !cgo

package main

func liveV3Child(v3ObservedChild, v3Member) bool { return false }
