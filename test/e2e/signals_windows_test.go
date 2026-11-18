// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && windows

package e2e

import "os"

// stopSignal: Windows has no SIGTERM, so stop() ends the server outright.
// The tests that need a clean stop or a reload run on Linux and macOS.
var stopSignal = os.Kill
