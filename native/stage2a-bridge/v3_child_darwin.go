//go:build darwin && cgo

package main

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>

static int stage2a_child_snapshot(pid_t pid, struct proc_bsdinfo *info,
                                   char *path, size_t path_size) {
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info)) != sizeof(*info)) return -1;
    int n = proc_pidpath(pid, path, (uint32_t)path_size);
    if (n <= 0 || (size_t)n >= path_size || strnlen(path, path_size) >= path_size) return -1;
    return 0;
}
*/
import "C"

func childProcessSnapshot(pid int64) (C.struct_proc_bsdinfo, string, bool) {
	var info C.struct_proc_bsdinfo
	var path [4096]C.char
	if C.stage2a_child_snapshot(C.pid_t(pid), &info, &path[0], C.size_t(len(path))) != 0 {
		return info, "", false
	}
	return info, C.GoString(&path[0]), true
}

func sameProcessStart(a, b C.struct_proc_bsdinfo) bool {
	return a.pbi_pid == b.pbi_pid && a.pbi_uid == b.pbi_uid &&
		a.pbi_gid == b.pbi_gid && a.pbi_ppid == b.pbi_ppid &&
		a.pbi_pgid == b.pbi_pgid &&
		a.pbi_start_tvsec == b.pbi_start_tvsec &&
		a.pbi_start_tvusec == b.pbi_start_tvusec
}

// A's signature identifies the child; a fresh kernel view confirms that the
// assigned process has not exited or been replaced before B arms its slot.
func liveV3Child(child v3ObservedChild, member v3Member) bool {
	if child.PID < 2 || member.CommandPath == "" ||
		child.CommandDigest != member.CommandDigest {
		return false
	}
	info, path, ok := childProcessSnapshot(child.PID)
	if !ok {
		return false
	}
	if path != member.CommandPath || int64(info.pbi_pid) != child.PID ||
		uint32(info.pbi_uid) != child.UID || uint32(info.pbi_gid) != child.GID ||
		int64(info.pbi_ppid) != child.ParentPID ||
		int64(info.pbi_pgid) != child.ProcessGroup ||
		int64(info.pbi_start_tvsec) != child.StartSeconds ||
		int64(info.pbi_start_tvusec) != child.StartMicros {
		return false
	}
	launcher, _, ok := childProcessSnapshot(child.LauncherPID)
	if !ok || int64(launcher.pbi_pid) != child.LauncherPID ||
		uint32(launcher.pbi_uid) != child.LauncherUID ||
		uint32(launcher.pbi_gid) != child.LauncherGID ||
		int64(launcher.pbi_start_tvsec) != child.LauncherStartSeconds ||
		int64(launcher.pbi_start_tvusec) != child.LauncherStartMicros {
		return false
	}
	again, againPath, ok := childProcessSnapshot(child.PID)
	if !ok || againPath != path || !sameProcessStart(info, again) {
		return false
	}
	againLauncher, _, ok := childProcessSnapshot(child.LauncherPID)
	return ok && sameProcessStart(launcher, againLauncher)
}
