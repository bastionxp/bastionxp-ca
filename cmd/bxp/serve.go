// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
	"github.com/bastionxp/bastionxp-ca/internal/ldap"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/scep"
	"github.com/bastionxp/bastionxp-ca/internal/server"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

func newServeCommand(configPath *string) *cobra.Command {
	logFormat := envOr("BXP_LOG_FORMAT", "text")
	logLevel := envOr("BXP_LOG_LEVEL", "info")
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the CA server",
		Long: "Run the HTTPS server that signs certificates.\n" +
			"Run \"bxp init\" once before the first start.\n" +
			"Stop the server with Ctrl-C or SIGTERM.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, err := newLogger(os.Stderr, logFormat, logLevel)
			if err != nil {
				return err
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}

			// Stop cleanly on Ctrl-C and on "kill".
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			listener, err := net.Listen("tcp", cfg.Server.Address)
			if err != nil {
				return err
			}
			// The plain HTTP address for the public information is optional.
			var publicListener net.Listener
			if cfg.Server.PublicAddress != "" {
				publicListener, err = net.Listen("tcp", cfg.Server.PublicAddress)
				if err != nil {
					listener.Close()
					return err
				}
			}
			hooks := serveHooks{
				Reload: reloadOnHangup(ctx),
				Load:   func() (*config.Config, error) { return config.Load(*configPath) },
			}
			return runServe(ctx, cfg, listener, publicListener, logger, hooks)
		},
	}
	cmd.Flags().StringVar(&logFormat, "log-format", logFormat,
		"text, or json for log collectors such as Elastic, Loki or Splunk (or BXP_LOG_FORMAT)")
	cmd.Flags().StringVar(&logLevel, "log-level", logLevel,
		"debug, info, warn or error (or BXP_LOG_LEVEL)")
	return cmd
}

// newLogger returns the server's logger. The log goes to w, as text or as
// one JSON object per line.
func newLogger(w io.Writer, format, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level must be debug, info, warn or error, got %q", level)
	}
	opts := &slog.HandlerOptions{Level: l}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("--log-format must be text or json, got %q", format)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// serveHooks are the places where the server reaches out to the world.
// The real program uses the real ones; tests put in their own.
type serveHooks struct {
	// ACMEDial opens the connection for an ACME challenge request.
	// Nil means: connect to the host itself, as it should be.
	ACMEDial func(ctx context.Context, network, address string) (net.Conn, error)

	// Reload asks the running server to read its configuration again.
	// The server answers on the channel it is sent: nil, or why the new
	// configuration was not used. Load reads the configuration.
	Reload chan chan error
	Load   func() (*config.Config, error)

	// MetricsListener is where the metrics are served, instead of
	// opening metrics.address. Tests use it to get a free port.
	MetricsListener net.Listener
}

// runServe serves HTTPS on the listener until ctx is cancelled. If
// publicListener is not nil, it also serves the CA's public information
// there with plain HTTP.
func runServe(ctx context.Context, cfg *config.Config, listener, publicListener net.Listener, logger *slog.Logger, hooks serveHooks) error {
	defer listener.Close()
	if publicListener != nil {
		defer publicListener.Close()
	}

	keys, err := loadServerKeys(cfg, os.Stderr)
	if err != nil {
		return err
	}
	authority, tokenKey := keys.ca, keys.tokenKey
	logKeyProtection(logger, cfg, keys)
	db, err := store.Open(filepath.Join(cfg.DataDir, store.FileName))
	if err != nil {
		return err
	}
	defer db.Close()

	// From here on every certificate the CA signs goes into the
	// database, the server's own included. This must come before the
	// first certificate is issued.
	authority.Record(db)
	if cfg.Server.PublicURL != "" {
		authority.PublishAt(cfg.Server.PublicURL)
	}

	tlsConfig, err := server.NewTLSConfig(authority, cfg.Server.Names)
	if err != nil {
		return err
	}

	// Metrics are off unless metrics.address is set.
	var counters *metrics.CA
	if cfg.Metrics.Address != "" {
		counters = newMetrics(cfg, authority, db)
	}

	opts := server.Options{
		CA:      authority,
		Tokens:  token.New(tokenKey),
		Store:   db,
		Log:     logger,
		Metrics: counters,
	}
	// Login with an OIDC identity provider is optional. It is on when an
	// issuer is set.
	if cfg.OIDC.Issuer != "" {
		opts.OIDC, err = newOIDCClient(cfg.OIDC)
		if err != nil {
			return err
		}
		opts.PublicURL = cfg.Server.URL
	}
	// Login with a directory password (Active Directory, LDAP) is
	// optional as well. It is on when a directory address is set.
	if cfg.LDAP.Enabled() {
		opts.LDAP, err = newLDAPClient(cfg.LDAP)
		if err != nil {
			return err
		}
	}
	// Both logins follow the same access rules.
	if loginEnabled(cfg) {
		opts.AccessRules = accessRules(cfg)
		opts.LoginProfiles = loginProfiles(cfg)
	}
	// The ACME server is optional too. It is on when domains are allowed.
	var acmeServer *acme.Server
	if cfg.ACME.Enabled() {
		acmeServer = acme.New(acme.Options{
			CA:          authority,
			Store:       db,
			Rules:       policy.NewACME(cfg.ACME.AllowedDomains).WithIPRanges(cfg.ACME.IPRanges()),
			Log:         logger,
			PublicURL:   cfg.Server.URL,
			Dial:        hooks.ACMEDial,
			DNSResolver: cfg.ACME.DNSResolver,
			Limits:      ptr(cfg.ACME.Limits.Resolved()),
			Challenges:  cfg.ACME.Challenges,
			Metrics:     counters,
			Profile:     acmeProfile(authority, cfg),
		})
		opts.ACME = acmeServer.Handler()
	}
	// And so is the SCEP server. It needs a key of its own, which is
	// made at the first start.
	if cfg.SCEP.Enabled {
		opts.SCEPRA, err = scep.LoadOrCreateRA(cfg.DataDir, authority)
		if err != nil {
			return err
		}
		if st := cfg.SCEP.Static; st.Enabled() {
			challenge, err := readPassphraseFile(st.ChallengeFile)
			if err != nil {
				return fmt.Errorf("scep.static.challenge_file: %w", err)
			}
			if len(challenge) < 16 {
				return errors.New("scep.static.challenge_file: the password must have at least 16 characters")
			}
			opts.SCEPStatic = &server.SCEPStatic{
				Challenge: string(challenge), Template: st.X509.CertProfile,
				DNSDomains: st.DNSDomains, EmailDomains: st.EmailDomains, MaxPerHour: st.PerHour(),
			}
		}
	}
	api := server.New(opts)
	// Caches the CRL and OCSP answers, and logs revocations made with
	// "bxp revoke", until the server stops.
	go api.WatchRevocations(ctx)
	httpServer := &http.Server{
		Handler:   api.Handler(),
		TLSConfig: tlsConfig,
		// Timeouts, so a slow or stuck client cannot hold a connection forever.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// Serve in the background, so this function can wait for the stop signal.
	servers := []*http.Server{httpServer}
	serveErr := make(chan error, 3)
	go func() {
		// The certificate comes from tlsConfig, so no files are named here.
		serveErr <- httpServer.ServeTLS(listener, "", "")
	}()
	// The public information, with plain HTTP.
	var publicServer *http.Server
	if publicListener != nil {
		publicServer = &http.Server{
			Handler:           api.PublicHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		servers = append(servers, publicServer)
		go func() { serveErr <- publicServer.Serve(publicListener) }()
		logger.Info("public information served", "address", publicListener.Addr().String(), "url", cfg.Server.PublicURL)
	}
	// The metrics, on an address of their own.
	if counters != nil {
		metricsServer, err := serveMetrics(cfg, counters, hooks.MetricsListener, serveErr, logger)
		if err != nil {
			httpServer.Close()
			return err
		}
		servers = append(servers, metricsServer)
	}
	logger.Info("server started",
		"address", listener.Addr().String(),
		"names", cfg.Server.Names,
		"oidc_login", cfg.OIDC.Issuer != "",
		"ldap_login", cfg.LDAP.Enabled(),
		"acme", cfg.ACME.Enabled(),
		"scep", cfg.SCEP.Enabled,
		// What clients need for "bxp trust", so it is easy to find.
		"root_fingerprint", ca.CertFingerprint(authority.RootCert()),
	)

	for running := true; running; {
		select {
		case err := <-serveErr:
			return err
		case done := <-hooks.Reload:
			done <- reload(cfg, hooks.Load, api, acmeServer, logger)
		case <-ctx.Done():
			running = false
		}
	}

	logger.Info("server stopping")
	// Give requests that are being answered ten seconds to finish.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	for range servers {
		if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

// expiryWarning is how long before a CA certificate expires that BastionXP CA
// starts to warn about it: a fifth of its lifetime, at most max. So a
// 3-year intermediate warns about 7 months ahead, a 5-year one a year.
func expiryWarning(cert *x509.Certificate, max time.Duration) time.Duration {
	return min(cert.NotAfter.Sub(cert.NotBefore)/5, max)
}

// The longest warning times: there is no need to know earlier.
const (
	intermediateWarningMax = 365 * 24 * time.Hour
	rootWarningMax         = 2 * 365 * 24 * time.Hour
)

// logKeyProtection says in the log how the keys are protected, and warns
// about what weakens that.
func logKeyProtection(logger *slog.Logger, cfg *config.Config, keys *serverKeys) {
	const serverKeys = "the server's keys (intermediate CA, SSH CA and token keys)"
	switch {
	case keys.encrypted:
		logger.Info(serverKeys+" are encrypted", "passphrase_from", keys.source)
	case rootKeyEncrypted(cfg):
		// The passphrase asked by "bxp init" is the root key's: say so,
		// or people think the warning is wrong.
		logger.Info("the root key is encrypted but " + serverKeys + " are not encrypted; " +
			"to encrypt them, " + seeDocs)
	default:
		logger.Info(serverKeys + " are not encrypted; to encrypt them, " + seeDocs)
	}
	if file := cfg.CA.KeyPassphraseFile; file != "" && sameFilesystem(file, cfg.DataDir) {
		logger.Warn("ca.key_passphrase_file is on the same disk as data_dir: a copy of the whole disk holds the keys and their passphrase. "+
			"A systemd credential sealed to the TPM is safer", "file", file)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootKeyFile)); err == nil {
		logger.Warn("the root key is in data_dir; the server does not need it. Move it to offline storage",
			"file", filepath.Join(cfg.DataDir, ca.RootKeyFile))
	}
	if inter := keys.ca.IntermediateCert(); time.Until(inter.NotAfter) < expiryWarning(inter, intermediateWarningMax) {
		logger.Warn("the intermediate certificate expires soon, and certificates issued now end with it at the latest: "+
			"replace it with \"bxp new-intermediate\"",
			"expires", keys.ca.IntermediateCert().NotAfter.Format(time.DateOnly))
	}
}

// rootKeyEncrypted reports whether the root key is in data_dir and
// encrypted. Once it is moved offline, or with a root of another CA, the
// server cannot know and says nothing about it.
func rootKeyEncrypted(cfg *config.Config) bool {
	encrypted, err := keyfile.IsEncrypted(filepath.Join(cfg.DataDir, ca.RootKeyFile))
	return err == nil && encrypted
}

// loginEnabled reports whether people can log in, with OIDC or LDAP.
func loginEnabled(cfg *config.Config) bool {
	return cfg.OIDC.Issuer != "" || cfg.LDAP.Enabled()
}

// newOIDCClient returns a client for the identity provider, with the
// client secret from the configuration or from its file.
func newOIDCClient(cfg config.OIDC) (*oidc.Client, error) {
	secret := cfg.ClientSecret
	if cfg.ClientSecretFile != "" {
		s, err := readPassphraseFile(cfg.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("oidc.client_secret_file: %w", err)
		}
		secret = string(s)
	}
	return oidc.New(oidc.Config{
		Issuer:        cfg.Issuer,
		ClientID:      cfg.ClientID,
		ClientSecret:  secret,
		UsernameClaim: cfg.UsernameClaim,
		GroupsClaim:   cfg.GroupsClaim,
		Scopes:        cfg.Scopes,
	}), nil
}

// newLDAPClient reads the files the ldap section names and returns a
// client for the directory.
func newLDAPClient(cfg config.LDAP) (*ldap.Client, error) {
	password, err := os.ReadFile(cfg.BindPasswordFile)
	if err != nil {
		return nil, fmt.Errorf("ldap.bind_password_file: %w", err)
	}
	// Editors and "echo" add a line end; it is not part of the password.
	bindPassword := strings.TrimRight(string(password), "\r\n")
	if bindPassword == "" {
		return nil, fmt.Errorf("ldap.bind_password_file: %s is empty", cfg.BindPasswordFile)
	}
	var roots *x509.CertPool
	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap.ca_file: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("ldap.ca_file: %s has no PEM certificate", cfg.CAFile)
		}
	}
	return ldap.New(ldap.Config{
		URL:               cfg.URL,
		StartTLS:          cfg.StartTLS,
		RootCAs:           roots,
		BaseDN:            cfg.BaseDN,
		BindDN:            cfg.BindDN,
		BindPassword:      bindPassword,
		UserFilter:        cfg.UserFilter,
		UsernameAttribute: cfg.UsernameAttribute,
		GroupBaseDN:       cfg.GroupBaseDN,
		GroupFilter:       cfg.GroupFilter,
	}), nil
}

// accessRules builds the rules for people who log in, from the
// configuration.
func accessRules(cfg *config.Config) *policy.Access {
	rules := make([]policy.Rule, 0, len(cfg.Access))
	for _, rule := range cfg.Access {
		rules = append(rules, policy.Rule{
			Users:         rule.Users,
			Groups:        rule.Groups,
			SSHPrincipals: rule.SSHPrincipals,
			Admin:         rule.Admin,
		})
	}
	return policy.NewAccess(rules)
}

// reloadOnHangup turns SIGHUP ("systemctl reload bastionxp-ca") into reload
// requests, until ctx ends.
func reloadOnHangup(ctx context.Context) chan chan error {
	requests := make(chan chan error)
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hangup)
		for {
			select {
			case <-hangup:
				done := make(chan error, 1)
				select {
				case requests <- done:
					<-done // the server logs the outcome
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return requests
}

// reload reads the configuration again and puts the parts that can change
// while the server runs into effect: who may log in and what they may have
// (the access rules), and the ACME domains.
//
// A configuration that does not load is not used at all: the server goes
// on with the one it has, so a typo cannot take the CA down. Changes that
// need a restart are reported and left for the next start.
func reload(running *config.Config, load func() (*config.Config, error), api *server.Server, acmeServer *acme.Server, logger *slog.Logger) error {
	next, err := load()
	if err != nil {
		logger.Error("configuration not reloaded; the server goes on with the one it has", "error", err)
		return err
	}
	if changed := needsRestart(running, next); len(changed) > 0 {
		logger.Warn("these changes need a restart and are not in effect yet", "settings", changed)
	}
	// A login that was switched off keeps running until the restart;
	// its people get the new rules all the same.
	if loginEnabled(running) {
		api.SetAccessRules(accessRules(next))
	}
	if acmeServer != nil && next.ACME.Enabled() {
		acmeServer.SetRules(policy.NewACME(next.ACME.AllowedDomains).WithIPRanges(next.ACME.IPRanges()))
		acmeServer.SetLimits(next.ACME.Limits.Resolved())
		acmeServer.SetChallenges(next.ACME.Challenges)
	}
	logger.Info("configuration reloaded",
		"access_rules", len(next.Access),
		"acme_domains", next.ACME.AllowedDomains,
	)
	return nil
}

// needsRestart lists the settings that differ between two configurations
// and that a reload cannot change: where the server listens and under
// which names, where its keys are, which parts are switched on.
func needsRestart(running, next *config.Config) []string {
	var changed []string
	check := func(name string, same bool) {
		if !same {
			changed = append(changed, name)
		}
	}
	check("data_dir", running.DataDir == next.DataDir)
	check("ca", reflect.DeepEqual(running.CA, next.CA))
	check("server", reflect.DeepEqual(running.Server, next.Server))
	check("acme (switching it on or off)", running.ACME.Enabled() == next.ACME.Enabled())
	check("acme.dns_resolver", running.ACME.DNSResolver == next.ACME.DNSResolver)
	check("acme.x509", running.ACME.X509 == next.ACME.X509)
	check("scep", reflect.DeepEqual(running.SCEP, next.SCEP))
	check("oidc", reflect.DeepEqual(running.OIDC, next.OIDC))
	check("ldap", running.LDAP == next.LDAP)
	check("metrics", running.Metrics == next.Metrics)
	check("profiles", reflect.DeepEqual(running.Profiles, next.Profiles))
	return changed
}

func ptr[T any](v T) *T { return &v }

// loginProfiles are the profiles each login verifier gives people for
// themselves (oidc.x509, oidc.ssh, ldap.x509, ldap.ssh).
func loginProfiles(cfg *config.Config) map[string]policy.Own {
	return map[string]policy.Own{
		"oidc": {
			SSHProfile:  cfg.OIDC.SSH.Or(config.DefaultLoginSSHProfile),
			X509Profile: cfg.OIDC.X509.Or(config.DefaultLoginX509Profile),
		},
		"ldap": {
			SSHProfile:  cfg.LDAP.SSH.Or(config.DefaultLoginSSHProfile),
			X509Profile: cfg.LDAP.X509.Or(config.DefaultLoginX509Profile),
		},
	}
}

// acmeProfile is the profile of ACME certificates (acme.x509).
func acmeProfile(authority *ca.CA, cfg *config.Config) *ca.X509Template {
	t, ok := authority.X509Template(cfg.ACME.X509.Or(config.DefaultACMEProfile))
	if !ok {
		return nil // the configuration was validated: not reached
	}
	return &t
}
