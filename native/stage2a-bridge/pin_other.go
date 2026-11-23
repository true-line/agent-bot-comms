//go:build !darwin || !cgo

package main

// A B v3 launch without Darwin's installed protected pin reader is refused.
func readMachinePin() ([]byte, error) { return nil, invalid }
