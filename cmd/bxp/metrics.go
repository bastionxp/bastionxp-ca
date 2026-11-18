// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// newMetrics makes the server's counters, and the values read at each
// scrape: the build, the expiry of the CA's certificates, and the
// certificates in the database. The last are read, not counted, so that
// they include what "bxp revoke" did, which does not go through the
// server.
func newMetrics(cfg *config.Config, authority *ca.CA, db *store.Store) *metrics.CA {
	counters := metrics.NewCA()
	r := counters.Registry
	r.Gauge("bastionxp_ca_build_info", "The bxp version; always 1.", []string{"version"},
		func(_ context.Context, emit func([]string, float64)) { emit([]string{version}, 1) })
	r.Gauge("bastionxp_ca_ca_certificate_expiry_timestamp_seconds",
		"When the CA's own certificates expire, as a Unix time.", []string{"certificate"},
		func(_ context.Context, emit func([]string, float64)) {
			emit([]string{"root"}, float64(authority.RootCert().NotAfter.Unix()))
			emit([]string{"intermediate"}, float64(authority.IntermediateCert().NotAfter.Unix()))
		})
	r.Gauge("bastionxp_ca_certificates", "Certificates in the database, by kind and state.", []string{"kind", "state"},
		func(ctx context.Context, emit func([]string, float64)) {
			counts, err := db.CountCertificates(ctx, time.Now())
			if err != nil {
				return
			}
			for _, c := range counts {
				emit([]string{c.Template, c.State}, float64(c.Count))
			}
		})
	return counters
}

// serveMetrics serves the metrics on metrics.address, or on listener if
// given, until the returned server is shut down. Its end goes to done.
func serveMetrics(cfg *config.Config, counters *metrics.CA, listener net.Listener, done chan<- error, logger *slog.Logger) (*http.Server, error) {
	var token string
	if cfg.Metrics.TokenFile != "" {
		t, err := readPassphraseFile(cfg.Metrics.TokenFile)
		if err != nil {
			return nil, err
		}
		token = string(t)
	}
	if listener == nil {
		var err error
		if listener, err = net.Listen("tcp", cfg.Metrics.Address); err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", counters.Registry.Handler(token))
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() { done <- srv.Serve(listener) }()
	logger.Info("metrics served", "address", listener.Addr().String(), "token", token != "")
	return srv, nil
}
