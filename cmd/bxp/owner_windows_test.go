// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "os"

func sameOwner(a, b os.FileInfo) bool { return true }
