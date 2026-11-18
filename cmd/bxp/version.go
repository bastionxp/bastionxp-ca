// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// versionText is what "bxp --version" shows after "bxp version": the
// version, then the commit it was built from and that commit's date, the
// Go version and the platform. Go writes the commit into every binary built
// in a git checkout. The commit's date is shown, not the time of the
// build: two builds of the same source stay identical, so anybody can
// check that a release was built from the published source.
func versionText() string {
	return version + " (" + strings.Join(buildDetails(readVCS()), ", ") + ")"
}

// vcsInfo is what Go recorded about the source of this binary.
type vcsInfo struct {
	revision string
	time     string // RFC 3339
	modified bool   // built with uncommitted changes
}

func readVCS() vcsInfo {
	// Set with -ldflags, as in the container build.
	v := vcsInfo{revision: commit, time: commitTime}
	info, ok := debug.ReadBuildInfo()
	if !ok || v.revision != "" {
		return v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v.revision = s.Value
		case "vcs.time":
			v.time = s.Value
		case "vcs.modified":
			v.modified = s.Value == "true"
		}
	}
	return v
}

func buildDetails(v vcsInfo) []string {
	var details []string
	if v.revision != "" {
		commit := "commit " + v.revision[:min(12, len(v.revision))]
		if v.modified {
			commit += " with local changes"
		}
		details = append(details, commit)
	}
	if t, err := time.Parse(time.RFC3339, v.time); err == nil {
		details = append(details, t.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return append(details, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
}
