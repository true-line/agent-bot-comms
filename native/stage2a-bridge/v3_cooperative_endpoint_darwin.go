//go:build darwin

package main

import (
	"os"
	"syscall"
)

func cooperativeBirthtimeNS(path string) (int64, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	native, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return 0, invalid
	}
	return native.Birthtimespec.Sec*1_000_000_000 + native.Birthtimespec.Nsec, nil
}
