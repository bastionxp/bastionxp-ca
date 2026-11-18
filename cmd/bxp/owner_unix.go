// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// chownLike gives f the owner and group of the file described by old.
func chownLike(f *os.File, old os.FileInfo) error {
	st, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}

// canChownLike reports an error if this process could not give a new
// file the owner of old: it must be root, or be that owner. (The group
// is a smaller matter: an owner may give a file any group it is in.)
func canChownLike(old os.FileInfo) error {
	st, ok := old.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() == 0 || int(st.Uid) == os.Geteuid() {
		return nil
	}
	return errors.New("not permitted")
}

// sameFilesystem reports whether the two paths are on the same file
// system (device).
func sameFilesystem(a, b string) bool {
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	stA, okA := infoA.Sys().(*syscall.Stat_t)
	stB, okB := infoB.Sys().(*syscall.Stat_t)
	return okA && okB && stA.Dev == stB.Dev
}
