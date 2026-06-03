//go:build windows

package main

// RaiseFileLimit is a no-op on Windows.
func RaiseFileLimit(target uint64) {
	// Windows does not use POSIX rlimits
}
