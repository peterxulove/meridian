//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// applySocketGID drops the process group so every socket created afterwards
// carries that GID. OpenClash's nftables output chain returns traffic whose
// socket GID is 65534 (nobody), which is what keeps a tunnel's own connection
// to the server from being redirected back into the local proxy.
//
// The UID is deliberately left alone: root still owns the log file and may
// bind low ports, and only the GID of newly created sockets matters here.
func applySocketGID(gid int) error {
	if gid <= 0 {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("not running as root, socket gid left unchanged")
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups(%d): %w", gid, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	return nil
}
