// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// "systemctl reload bastionxp-ca" sends SIGHUP. It must turn into a reload
// request, and must not stop the program.
func TestHangupBecomesAReloadRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := reloadOnHangup(ctx)

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case done := <-requests:
		done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not become a reload request")
	}
}
