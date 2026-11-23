package main

import (
	"os"
	"path/filepath"
	"strconv"
)

func cooperativeEndpointIdentityMatches(record map[string]any, actual endpoint, created bool) bool {
	device, e1 := strconv.ParseUint(field(record, "parent_device"), 10, 64)
	inode, e2 := strconv.ParseUint(field(record, "parent_inode"), 10, 64)
	if e1 != nil || e2 != nil || actual.Path != field(record, "socket_path") ||
		actual.Parent.Device != device || actual.Parent.Inode != inode ||
		actual.Parent.UID != uint32(integer(record, "owner_uid")) ||
		actual.Parent.GID != uint32(integer(record, "group_gid")) ||
		actual.Parent.Mode != 02750 || actual.Socket.UID != actual.Parent.UID ||
		actual.Socket.GID != actual.Parent.GID || actual.Socket.Mode != 0660 {
		return false
	}
	if created {
		return actual.Socket.Inode != 0
	}
	return actual.Socket.Inode == 0 && actual.Socket.Device == 0
}

func cooperativeEndpointCurrent(record map[string]any, actual endpoint) bool {
	if !actual.current() || !cooperativeEndpointIdentityMatches(record, actual, true) {
		return false
	}
	want, err := strconv.ParseInt(field(record, "parent_birthtime_ns"), 10, 64)
	if err != nil || want <= 0 {
		return false
	}
	got, err := cooperativeBirthtimeNS(filepath.Dir(actual.Path))
	return err == nil && got == want
}

// The signed parent tuple is checked before B opens either assigned socket.
// A created relay has no socket inode yet; the broker and member must exist.
func cooperativeRuntimeEndpoint(record map[string]any, created bool) (endpoint, error) {
	path := field(record, "socket_path")
	parentPath := field(record, "directory")
	if path == "" || filepath.Dir(path) != parentPath {
		return endpoint{}, invalid
	}
	parentDevice, e1 := strconv.ParseUint(field(record, "parent_device"), 10, 64)
	parentInode, e2 := strconv.ParseUint(field(record, "parent_inode"), 10, 64)
	parentBirth, e3 := strconv.ParseInt(field(record, "parent_birthtime_ns"), 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || parentDevice == 0 || parentInode == 0 || parentBirth <= 0 {
		return endpoint{}, invalid
	}
	parent, err := observe(parentPath, os.ModeDir)
	if err != nil || parent.Device != parentDevice || parent.Inode != parentInode ||
		parent.UID != uint32(integer(record, "owner_uid")) ||
		parent.GID != uint32(integer(record, "group_gid")) || parent.Mode != 02750 {
		return endpoint{}, invalid
	}
	birth, err := cooperativeBirthtimeNS(parentPath)
	if err != nil || birth != parentBirth {
		return endpoint{}, invalid
	}
	result := endpoint{Path: path, Parent: parent,
		Socket: identity{UID: parent.UID, GID: parent.GID, Mode: 0660}}
	if created {
		socket, err := observe(path, os.ModeSocket)
		if err != nil || socket.UID != parent.UID || socket.GID != parent.GID ||
			socket.Mode != 0660 || socket.Inode == 0 {
			return endpoint{}, invalid
		}
		result.Socket = socket
	} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return endpoint{}, invalid
	}
	return result, nil
}
