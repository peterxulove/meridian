//go:build !windows

package main

import (
	"syscall"
)

// RaiseFileLimit attempts to raise the OS open-file descriptor limit to at least
// target. It is a best-effort call; failures are logged but not fatal.
func RaiseFileLimit(target uint64) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		logf("[sys] getrlimit failed: %v", err)
		return
	}
	if rl.Cur >= target {
		return // already high enough
	}
	original := rl.Cur
	rl.Cur = target
	if rl.Max < target {
		rl.Max = target
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		logf("[sys] could not raise open-file limit from %d to %d: %v (run with sudo or set 'ulimit -n %d' before starting)", original, target, err, target)
		return
	}
	logf("[sys] open-file limit raised from %d to %d", original, target)
}
