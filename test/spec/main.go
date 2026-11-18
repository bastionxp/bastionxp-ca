// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Command spec writes the test case tables of the test specification,
// docs/testing/, from the tests themselves: each Test and Fuzz function,
// its level, what it verifies (its doc comment, or else its name), and
// where it is. The text around the tables is written by hand and kept.
//
//	go run ./test/spec          # rewrite the tables
//	go run ./test/spec -check   # fail if a table is out of date, or a test has no feature
//
// Every test belongs to one feature, by the rules in features.go. A new
// test file or test needs a rule there, or -check fails: that keeps the
// specification complete.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A testCase is one Test or Fuzz function.
type testCase struct {
	Pkg      string // e.g. internal/acme
	File     string // e.g. ari_test.go
	Name     string // e.g. TestRenewalInfo
	Doc      string // its doc comment
	Level    string
	Subtests int
}

const (
	levelUnit        = "Unit"
	levelIntegration = "Integration"
	levelDocker      = "Integration (Docker)"
	levelE2E         = "E2E"
	levelFuzz        = "Fuzz"
)

// Markers around the generated part of a page.
const (
	beginCases = "<!-- BEGIN GENERATED CASES: go run ./test/spec -->"
	endCases   = "<!-- END GENERATED CASES -->"
	beginTotal = "<!-- BEGIN GENERATED SUMMARY: go run ./test/spec -->"
	endTotal   = "<!-- END GENERATED SUMMARY -->"
)

func main() {
	check := flag.Bool("check", false, "fail if the pages are out of date instead of writing them")
	root := flag.String("root", ".", "the repository root")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, "spec:", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	cases, err := readTests(root)
	if err != nil {
		return err
	}
	byFeature := map[string][]testCase{}
	var unassigned []string
	for _, c := range cases {
		code := featureOf(c)
		if code == "" {
			unassigned = append(unassigned, c.Pkg+"/"+c.File+": "+c.Name)
			continue
		}
		byFeature[code] = append(byFeature[code], c)
	}
	if len(unassigned) > 0 {
		return fmt.Errorf("no feature for these tests; add a rule to test/spec/features.go:\n  %s", strings.Join(unassigned, "\n  "))
	}

	var stale []string
	update := func(path, begin, end, generated string) error {
		page, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		next, err := replaceBetween(string(page), begin, end, generated)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if next == string(page) {
			return nil
		}
		if check {
			stale = append(stale, path)
			return nil
		}
		return os.WriteFile(path, []byte(next), 0o644)
	}
	for _, f := range features {
		path := filepath.Join(root, "docs", "testing", f.Page)
		if err := update(path, beginCases, endCases, caseTable(f, byFeature[f.Code])); err != nil {
			return err
		}
	}
	if err := update(filepath.Join(root, "docs", "testing", "README.md"), beginTotal, endTotal, summary(byFeature)); err != nil {
		return err
	}
	if len(stale) > 0 {
		return fmt.Errorf("out of date, run \"go run ./test/spec\": %s", strings.Join(stale, ", "))
	}
	return nil
}

// A function of a test package: its name and body, for following helpers.
type function struct {
	name, body string
}

// readTests finds every Test and Fuzz function below root.
func readTests(root string) ([]testCase, error) {
	// The test files of each package directory, read together: a test's
	// level depends on the helpers it calls, which may be in another file.
	byDir := map[string][]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".tools", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		// The specification's own tests are not part of it.
		if strings.HasSuffix(path, "_test.go") && !strings.HasPrefix(filepath.ToSlash(path), filepath.ToSlash(filepath.Join(root, "test", "spec"))+"/") {
			byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var cases []testCase
	for dir, paths := range byDir {
		rel, _ := filepath.Rel(root, dir)
		pkg := filepath.ToSlash(rel)
		var funcs []function
		type found struct {
			file string
			fn   *ast.FuncDecl
			body string
		}
		var tests []found
		for _, path := range paths {
			src, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				body := string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
				funcs = append(funcs, function{fn.Name.Name, body})
				name := fn.Name.Name
				if fn.Recv == nil && name != "TestMain" && (strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Fuzz")) {
					tests = append(tests, found{filepath.Base(path), fn, body})
				}
			}
		}
		integration := integrationHelpers(funcs)
		for _, t := range tests {
			c := testCase{
				Pkg: pkg, File: t.file, Name: t.fn.Name.Name,
				Doc: strings.TrimSpace(t.fn.Doc.Text()), Subtests: strings.Count(t.body, "t.Run("),
			}
			c.Level = levelOf(c, t.body, integration)
			cases = append(cases, c)
		}
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Pkg != cases[j].Pkg {
			return cases[i].Pkg < cases[j].Pkg
		}
		if cases[i].File != cases[j].File {
			return cases[i].File < cases[j].File
		}
		return cases[i].Name < cases[j].Name
	})
	return cases, nil
}

// Signs that code runs a server, a listener, a fake service, or a client
// against one: an integration test, not a unit test.
var integrationSigns = []string{
	"httptest.", "net.Listen(", "runServe(", "ServeHTTP(", "oidctest.", "ldaptest.",
}

// integrationHelpers returns the names of the helpers that, themselves or
// through other helpers, show an integration sign.
func integrationHelpers(funcs []function) map[string]bool {
	marked := map[string]bool{}
	for _, f := range funcs {
		if hasSign(f.body) {
			marked[f.name] = true
		}
	}
	// Spread the mark to callers until nothing changes.
	for changed := true; changed; {
		changed = false
		for _, f := range funcs {
			if !marked[f.name] && callsAny(f.body, marked) {
				marked[f.name] = true
				changed = true
			}
		}
	}
	return marked
}

func hasSign(body string) bool {
	for _, s := range integrationSigns {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// callsAny reports whether body calls one of the named functions or
// methods: "name(" after something that is not part of a longer name.
func callsAny(body string, names map[string]bool) bool {
	for name := range names {
		for i := strings.Index(body, name+"("); i >= 0; {
			if i == 0 || !isNameByte(body[i-1]) {
				return true
			}
			next := strings.Index(body[i+1:], name+"(")
			if next < 0 {
				break
			}
			i += 1 + next
		}
	}
	return false
}

func isNameByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func levelOf(c testCase, body string, integration map[string]bool) string {
	switch {
	case c.Pkg == "test/e2e":
		return levelE2E
	case strings.HasPrefix(c.Name, "Fuzz"):
		return levelFuzz
	case strings.Contains(body, "startSamba(") || strings.Contains(body, "startKeycloak(") || strings.Contains(body, "startKind("):
		return levelDocker
	case hasSign(body) || callsAny(body, integration):
		return levelIntegration
	}
	return levelUnit
}

// caseTable is the generated part of a feature's page.
func caseTable(f feature, cases []testCase) string {
	var b bytes.Buffer
	counts := map[string]int{}
	for _, c := range cases {
		counts[c.Level]++
	}
	fmt.Fprintf(&b, "%d test cases: %s.\n\n", len(cases), levelCounts(counts))
	b.WriteString("| Case | Level | Verifies | Location |\n|---|---|---|---|\n")
	for _, c := range sortedForTable(cases) {
		what := describe(c)
		switch {
		case c.Subtests == 1:
			what += " (1 sub-case)"
		case c.Subtests > 1:
			what += fmt.Sprintf(" (%d sub-cases)", c.Subtests)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | [%s](../../%s/%s) |\n",
			c.Name, c.Level, escape(what), c.Pkg+"/"+c.File, c.Pkg, c.File)
	}
	return b.String()
}

// The order of levels in tables and counts: from the smallest scope up.
var levelOrder = []string{levelUnit, levelFuzz, levelIntegration, levelDocker, levelE2E}

func sortedForTable(cases []testCase) []testCase {
	rank := map[string]int{}
	for i, l := range levelOrder {
		rank[l] = i
	}
	out := append([]testCase(nil), cases...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Level] < rank[out[j].Level] })
	return out
}

func levelCounts(counts map[string]int) string {
	var parts []string
	for _, l := range levelOrder {
		if n := counts[l]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(l)))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// summary is the generated table of the README: cases per feature and level.
func summary(byFeature map[string][]testCase) string {
	var b bytes.Buffer
	b.WriteString("| Feature | Unit | Fuzz | Integration | Integration (Docker) | E2E | Total |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|\n")
	totals := map[string]int{}
	all := 0
	for _, f := range features {
		counts := map[string]int{}
		for _, c := range byFeature[f.Code] {
			counts[c.Level]++
			totals[c.Level]++
			all++
		}
		fmt.Fprintf(&b, "| [%s](%s) | %d | %d | %d | %d | %d | %d |\n", f.Title, f.Page,
			counts[levelUnit], counts[levelFuzz], counts[levelIntegration], counts[levelDocker], counts[levelE2E],
			len(byFeature[f.Code]))
	}
	fmt.Fprintf(&b, "| **All** | **%d** | **%d** | **%d** | **%d** | **%d** | **%d** |\n",
		totals[levelUnit], totals[levelFuzz], totals[levelIntegration], totals[levelDocker], totals[levelE2E], all)
	return b.String()
}

// describe says what a case verifies: the first paragraph of its doc
// comment, or else its name as a sentence. A comment that starts with the
// function's name, as Go's convention has it ("FuzzOCSP sends ..."), is
// shown without it: the name is in the table already.
func describe(c testCase) string {
	if c.Doc != "" {
		para, _, _ := strings.Cut(c.Doc, "\n\n")
		text := strings.Join(strings.Fields(para), " ")
		if rest, ok := strings.CutPrefix(text, c.Name+" "); ok && rest != "" {
			text = strings.ToUpper(rest[:1]) + rest[1:]
		}
		return text
	}
	return sentence(c.Name)
}

// Word boundaries in a Go test name: before a capital that follows a
// lower-case letter or digit ("signX509" | "Rejects"), and before the last
// capital of a run that starts a word ("ACME" | "Order").
var (
	lowerToUpper = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	runToWord    = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
	letterDigit  = regexp.MustCompile(`([a-z])([0-9])`)
)

// sentence turns TestSignX509RejectsBadTokens into "Sign X509 rejects bad
// tokens": capitalised runs (ACME, CA, X509, HTTP01) stay; other words
// become lower case.
func sentence(name string) string {
	name = strings.TrimPrefix(strings.TrimPrefix(name, "Test"), "Fuzz")
	spaced := runToWord.ReplaceAllString(lowerToUpper.ReplaceAllString(name, "$1 $2"), "$1 $2")
	spaced = letterDigit.ReplaceAllString(spaced, "$1 $2")
	words := strings.Fields(spaced)
	for i, w := range words {
		if len(w) < 2 || strings.ToUpper(w) != w {
			words[i] = strings.ToLower(w)
		}
	}
	if len(words) == 0 {
		return name
	}
	s := strings.Join(words, " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

func escape(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// replaceBetween puts generated between the begin and end markers.
func replaceBetween(page, begin, end, generated string) (string, error) {
	i := strings.Index(page, begin)
	j := strings.Index(page, end)
	if i < 0 || j < i {
		return "", fmt.Errorf("the markers %q and %q are missing", begin, end)
	}
	return page[:i+len(begin)] + "\n" + generated + page[j:], nil
}
