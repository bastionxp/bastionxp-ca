// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// bxp version shows the commit, local changes, the commit time in UTC, the
// Go version and the platform, and only the last two without git
// information.
func TestBuildDetails(t *testing.T) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	for _, tc := range []struct {
		name string
		vcs  vcsInfo
		want []string
	}{
		{"release", vcsInfo{revision: "1a2b3c4d5e6f7a8b9c0d", time: "2026-11-17T10:06:16Z"},
			[]string{"commit 1a2b3c4d5e6f", "2026-11-17 10:06 UTC", runtime.Version(), platform}},
		{"local changes", vcsInfo{revision: "1a2b3c4d5e6f7a8b9c0d", time: "2026-11-17T15:36:16+05:30", modified: true},
			[]string{"commit 1a2b3c4d5e6f with local changes", "2026-11-17 10:06 UTC", runtime.Version(), platform}},
		{"no git", vcsInfo{}, []string{runtime.Version(), platform}},
	} {
		if got := buildDetails(tc.vcs); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if text := versionText(); !strings.HasPrefix(text, version+" (") || !strings.Contains(text, runtime.Version()) {
		t.Errorf("versionText() = %q", text)
	}
}

// Set with -ldflags, as the container build does.
func TestVersionFromLinkerFlags(t *testing.T) {
	commit, commitTime = "abcdef1234567890", "2026-11-17T10:06:16Z"
	t.Cleanup(func() { commit, commitTime = "", "" })
	if got := buildDetails(readVCS()); !slices.Contains(got, "commit abcdef123456") || !slices.Contains(got, "2026-11-17 10:06 UTC") {
		t.Errorf("details = %q", got)
	}
}
