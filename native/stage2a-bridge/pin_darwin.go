//go:build darwin && cgo

package main

/*
#include <errno.h>
#include <stdlib.h>
#include <sys/acl.h>

// A pin path or ancestor with any extended ACL is refused. This is stricter
// than distinguishing grants from denies and avoids a spawned ACL inspector
// inside the confined B process.
static int no_extended_acl(const char *path) {
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (acl == NULL) return errno == ENOENT || errno == ENOATTR;
    acl_entry_t entry;
    int found = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    acl_free(acl);
    return found == 0;
}
*/
import "C"

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func safeACL(path string) bool {
	c := C.CString(path)
	defer C.free(unsafe.Pointer(c))
	return C.no_extended_acl(c) == 1
}

func readMachinePin() ([]byte, error) {
	const path = v3PinPath
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		stat, err := os.Lstat(dir)
		if err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || !safeACL(dir) {
			return nil, invalid
		}
		native, ok := stat.Sys().(*syscall.Stat_t)
		if !ok || native.Uid != 0 || native.Mode&0022 != 0 {
			return nil, invalid
		}
		if dir == "/" {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !safeACL(path) {
		return nil, invalid
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0444 ||
		st.Nlink != 1 || st.Size != 32 {
		return nil, invalid
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, invalid
	}
	defer syscall.Close(fd)
	var opened syscall.Stat_t
	if syscall.Fstat(fd, &opened) != nil || opened.Dev != st.Dev || opened.Ino != st.Ino ||
		opened.Uid != 0 || opened.Gid != 0 || opened.Mode&07777 != 0444 ||
		opened.Nlink != 1 || opened.Size != 32 {
		return nil, invalid
	}
	var pin [32]byte
	count := 0
	for count < len(pin) {
		n, err := syscall.Read(fd, pin[count:])
		if err != nil || n <= 0 {
			return nil, invalid
		}
		count += n
	}
	var extra [1]byte
	n, err := syscall.Read(fd, extra[:])
	if err != nil || n != 0 || !safeACL(path) {
		return nil, invalid
	}
	return pin[:], nil
}
