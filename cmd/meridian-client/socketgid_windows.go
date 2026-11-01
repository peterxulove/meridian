//go:build windows

package main

// applySocketGID is a no-op on Windows, which has no socket GIDs.
func applySocketGID(int) error { return nil }
