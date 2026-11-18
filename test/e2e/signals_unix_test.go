// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import "syscall"

// stopSignal is what stops "bxp serve" cleanly: SIGTERM, as systemd sends.
var stopSignal = syscall.SIGTERM

// syscallHangup is what "systemctl reload" sends: reload the configuration.
var syscallHangup = syscall.SIGHUP
