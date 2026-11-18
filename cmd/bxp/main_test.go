// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// The help shows the commands for getting certificates apart from those
// for running the CA, each group in the order of use.
func TestHelpGroups(t *testing.T) {
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	help := out.String()
	client := strings.Index(help, "Get certificates")
	server := strings.Index(help, "Run the CA")
	if client < 0 || server < 0 || client > server {
		t.Fatalf("groups missing or out of order:\n%s", help)
	}
	// Each command in its group, in the order of use.
	for _, order := range [][]string{{"trust", "tls", "ssh", "renew"}, {"init", "serve", "token", "revoke"}} {
		last := -1
		for _, name := range order {
			i := strings.Index(help, "\n  "+name+" ")
			if i < 0 || i < last {
				t.Errorf("%s missing or out of order in the help", name)
			}
			last = i
		}
	}
	if strings.Index(help, "\n  trust ") > server || strings.Index(help, "\n  init ") < server {
		t.Error("a command is in the wrong group")
	}
}
