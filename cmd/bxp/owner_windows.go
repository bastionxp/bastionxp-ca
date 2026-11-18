// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "os"

// On Windows a replaced file takes its permissions from the folder, so
// there is nothing to copy.

func chownLike(f *os.File, old os.FileInfo) error { return nil }

func canChownLike(old os.FileInfo) error { return nil }

// sameFilesystem is not checked on Windows.
func sameFilesystem(a, b string) bool { return false }
