// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// loginTimeout is how long the program waits for the person to finish
// the login in the browser.
const loginTimeout = 5 * time.Minute

// loginRequest is what the person wants a one-time token for.
type loginRequest struct {
	// template is the profile; empty: the one the login gives people
	// for themselves of kind ("ssh" or "x509").
	template string
	kind     string
	names    []string // empty: all the CA allows the person
	subject  string
	validFor time.Duration
	// keyFingerprint ties the token to one key. Empty for a token that
	// is handed on to somebody else.
	keyFingerprint string
}

// loginResult is what comes back from the browser.
type loginResult struct {
	token string
	err   error
}

// browserLogin gets a one-time token by letting the person log in with
// the identity provider in their browser.
//
// It listens on a port of this machine, opens the CA's login address in
// the browser, and waits. After the login the CA sends the browser to
// that port with the token. See internal/server/login.go for the CA's
// side.
func browserLogin(ctx context.Context, conn connection, caClient *client.Client, want loginRequest) (string, error) {
	// Find out now which login to use, and not after the person has
	// waited in front of an error page.
	setUp, err := caClient.LoginIsSetUp(ctx, api.OIDCLoginPath)
	if err != nil {
		return "", err
	}
	if !setUp {
		return "", errors.New("this CA has no login in the browser: give a one-time token with --token, or log in with --ldap if the CA checks directory passwords")
	}

	// Port 0 means: any free port. 127.0.0.1 means: reachable from this
	// machine only.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("cannot listen for the result of the login: %w", err)
	}

	// A random value that the CA sends back with the result. A reply
	// without it did not come from the login started here.
	state, err := randomState()
	if err != nil {
		listener.Close()
		return "", err
	}

	results := make(chan loginResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		handleLoginCallback(w, r, state, results)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go server.Serve(listener)
	defer func() {
		// Shutdown, unlike Close, first lets the browser receive the
		// page that tells the person how the login went.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	query := url.Values{
		api.LoginCallback: {"http://" + listener.Addr().String() + "/callback"},
		api.LoginState:    {state},
		api.LoginProfile:  {want.template},
		api.LoginName:     want.names,
	}
	if want.template == "" {
		query.Del(api.LoginProfile)
		query.Set(api.LoginKind, want.kind)
	}
	if want.subject != "" {
		query.Set(api.LoginSubject, want.subject)
	}
	if want.validFor != 0 {
		query.Set(api.LoginValidFor, want.validFor.String())
	}
	if want.keyFingerprint != "" {
		query.Set(api.LoginKey, want.keyFingerprint)
	}
	loginURL := caClient.LoginURL(api.OIDCLoginPath, query)

	if conn.prompt == nil {
		conn.prompt = io.Discard
	}
	fmt.Fprintln(conn.prompt, "Your browser opens for a login.")
	fmt.Fprintln(conn.prompt, "If it does not, open this address yourself, on this machine:")
	fmt.Fprintf(conn.prompt, "\n  %s\n\n", loginURL)
	fmt.Fprintln(conn.prompt, "Waiting for the login...")
	if conn.openBrowser != nil {
		// If this fails the person can still open the address by hand.
		_ = conn.openBrowser(loginURL)
	}

	select {
	case result := <-results:
		return result.token, result.err
	case <-time.After(loginTimeout):
		return "", errors.New("gave up waiting for the login: run the command again")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// handleLoginCallback receives the result of the login from the browser.
func handleLoginCallback(w http.ResponseWriter, r *http.Request, state string, results chan<- loginResult) {
	query := r.URL.Query()

	// Any web page the person has open can make their browser call this
	// address. Only the CA knows the state, so only its reply is taken.
	// The waiting goes on: the real reply may still come.
	if subtle.ConstantTimeCompare([]byte(query.Get(api.ResultState)), []byte(state)) != 1 {
		http.Error(w, "This reply does not belong to the login that was started here.", http.StatusBadRequest)
		return
	}

	var result loginResult
	switch {
	case query.Get(api.ResultError) != "":
		result.err = errors.New("the CA refused the login: " + query.Get(api.ResultError))
		writeLoginPage(w, "Login failed", query.Get(api.ResultError))
	case query.Get(api.ResultToken) != "":
		result.token = query.Get(api.ResultToken)
		writeLoginPage(w, "Login succeeded", "You can close this window and go back to the terminal.")
	default:
		result.err = errors.New("the CA's reply contains no token")
		writeLoginPage(w, "Login failed", "The reply from the CA contains no token.")
	}

	// Take the first reply only. The channel has room for one.
	select {
	case results <- result:
	default:
	}
}

// writeLoginPage shows a small page in the browser at the end of a login.
func writeLoginPage(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The message comes from outside: escape it before it goes into HTML.
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>BastionXP CA</title></head>"+
		"<body style=\"font-family: sans-serif; margin: 3em\"><h1>%s</h1><p>%s</p></body></html>\n",
		html.EscapeString(title), html.EscapeString(message))
}

// randomState returns 128 random bits as hex.
func randomState() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// openBrowser opens an address in the default browser.
func openBrowser(address string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", address).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", address).Start()
	default: // Linux and the BSDs
		return exec.Command("xdg-open", address).Start()
	}
}
