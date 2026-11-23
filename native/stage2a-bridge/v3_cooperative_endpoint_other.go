//go:build !darwin

package main

func cooperativeBirthtimeNS(string) (int64, error) { return 0, invalid }
