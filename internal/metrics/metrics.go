// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package metrics keeps the CA's counters and serves them in the
// Prometheus text format, for monitoring and alerts.
//
// It holds counts and dates only: never names, serial numbers or
// usernames. Who got what is in the log.
//
// The format is simple enough to write by hand, which spares the CA the
// dependencies of the Prometheus client library.
package metrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry holds the metrics. Create one with New. All methods are safe
// for concurrent use, and do nothing on a nil Registry or metric, so code
// that runs without metrics needs no checks.
type Registry struct {
	mu       sync.Mutex
	families []*family
	// collect is called at each scrape for values that are read, not
	// counted, such as the certificates in the database.
	collect []func(ctx context.Context, emit func(name string, labels []string, value float64))
}

type kind string

const (
	counter kind = "counter"
	gauge   kind = "gauge"
	summary kind = "summary"
)

type family struct {
	name, help string
	kind       kind
	labels     []string
	values     map[string]*value // by the joined label values
}

type value struct {
	labels     []string
	sum, count float64 // count is unused for counters and gauges
}

// New returns an empty registry.
func New() *Registry { return &Registry{} }

func (r *Registry) add(name, help string, k kind, labels []string) *family {
	f := &family{name: name, help: help, kind: k, labels: labels, values: make(map[string]*value)}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.families = append(r.families, f)
	return f
}

// CounterVec is a counter with labels.
type CounterVec struct {
	r *Registry
	f *family
}

// Counter adds a counter. The labels name the values each Inc gives.
func (r *Registry) Counter(name, help string, labels ...string) *CounterVec {
	if r == nil {
		return nil
	}
	return &CounterVec{r: r, f: r.add(name, help, counter, labels)}
}

// Inc adds one for the given label values.
func (c *CounterVec) Inc(labelValues ...string) {
	if c == nil {
		return
	}
	c.r.observe(c.f, labelValues, 1, false)
}

// SummaryVec counts observations and adds them up, e.g. durations.
type SummaryVec struct {
	r *Registry
	f *family
}

// Summary adds a summary (a sum and a count, no quantiles).
func (r *Registry) Summary(name, help string, labels ...string) *SummaryVec {
	if r == nil {
		return nil
	}
	return &SummaryVec{r: r, f: r.add(name, help, summary, labels)}
}

// Observe records one observation for the given label values.
func (s *SummaryVec) Observe(v float64, labelValues ...string) {
	if s == nil {
		return
	}
	s.r.observe(s.f, labelValues, v, true)
}

func (r *Registry) observe(f *family, labelValues []string, v float64, isSummary bool) {
	if len(labelValues) != len(f.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d labels, got %d", f.name, len(f.labels), len(labelValues)))
	}
	key := strings.Join(labelValues, "\x00")
	r.mu.Lock()
	defer r.mu.Unlock()
	val := f.values[key]
	if val == nil {
		val = &value{labels: append([]string(nil), labelValues...)}
		f.values[key] = val
	}
	val.sum += v
	if isSummary {
		val.count++
	}
}

// Gauge adds a gauge whose values are read at each scrape by collect,
// which calls emit once per set of label values.
func (r *Registry) Gauge(name, help string, labels []string,
	collect func(ctx context.Context, emit func(labelValues []string, v float64))) {
	if r == nil {
		return
	}
	f := r.add(name, help, gauge, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collect = append(r.collect, func(ctx context.Context, emit func(string, []string, float64)) {
		collect(ctx, func(labelValues []string, v float64) { emit(f.name, labelValues, v) })
	})
}

// Write writes all metrics in the Prometheus text format.
func (r *Registry) Write(ctx context.Context, w io.Writer) error {
	// Gauges first, outside the lock: they may read the database.
	r.mu.Lock()
	collectors := append([]func(context.Context, func(string, []string, float64)){}, r.collect...)
	r.mu.Unlock()
	gauges := map[string][]*value{}
	for _, collect := range collectors {
		collect(ctx, func(name string, labels []string, v float64) {
			gauges[name] = append(gauges[name], &value{labels: labels, sum: v})
		})
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, f := range r.families {
		values := gauges[f.name]
		if f.kind != gauge {
			for _, v := range f.values {
				values = append(values, v)
			}
		}
		sort.Slice(values, func(i, j int) bool {
			return strings.Join(values[i].labels, "\x00") < strings.Join(values[j].labels, "\x00")
		})
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		for _, v := range values {
			labels := formatLabels(f.labels, v.labels)
			if f.kind == summary {
				fmt.Fprintf(&b, "%s_sum%s %s\n%s_count%s %s\n", f.name, labels, formatValue(v.sum), f.name, labels, formatValue(v.count))
			} else {
				fmt.Fprintf(&b, "%s%s %s\n", f.name, labels, formatValue(v.sum))
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	parts := make([]string, len(names))
	for i, name := range names {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(values[i])
		parts[i] = name + `="` + v + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func formatValue(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Handler serves the metrics. With a token, only requests with
// "Authorization: Bearer <token>" get them.
func (r *Registry) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if token != "" {
			got, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="bastionxp-ca metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.Write(ctx, w)
	})
}
