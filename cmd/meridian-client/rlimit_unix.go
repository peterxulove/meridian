//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

// RaiseFileLimit attempts to raise the OS open-file descriptor limit to at least
// target. It is a best-effort call; failures are logged but not fatal.
func RaiseFileLimit(target uint64) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		fmt.Printf("[sys] getrlimit failed: %v\n", err)
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
		fmt.Printf("[sys] could not raise open-file limit from %d to %d: %v (run with sudo or set 'ulimit -n %d' before starting)\n", original, target, err, target)
		return
	}
	fmt.Printf("[sys] open-file limit raised from %d → %d\n", original, target)
}
