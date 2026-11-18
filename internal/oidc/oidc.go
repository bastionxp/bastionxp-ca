// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package oidc finds out who a person is by letting them log in with an
// OpenID Connect identity provider: Microsoft Entra ID, AD FS, Google,
// Okta, Keycloak, Auth0, GitLab and others. One implementation covers
// them all, because they all speak the same protocol.
//
// It is the "who are you?" part of the login verifier: the person's
// browser goes to the provider and comes back to the CA with a code, and
// the CA turns the code into an ID token by asking the provider directly,
// with its client secret.
//
// What this package checks about the ID token:
//
//   - its signature, against the provider's published keys;
//   - that it was issued by the configured provider, for this CA (the
//     audience is our client ID), and has not expired;
//   - the nonce, which ties the token to the login that asked for it.
//
// The code is also protected with PKCE: only the CA, which knows the
// secret "verifier", can turn it into a token.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/bastionxp/bastionxp-ca/internal/policy"
)

// ErrLoginFailed is returned by Login when the provider does not accept
// the code, or the ID token does not pass the checks. The person has to
// start again.
var ErrLoginFailed = errors.New("the login failed")

// Config describes the identity provider.
type Config struct {
	// Issuer is the provider's address, e.g.
	// "https://login.microsoftonline.com/<tenant-id>/v2.0".
	Issuer string
	// ClientID and ClientSecret are those of the CA's registration at
	// the provider.
	ClientID     string
	ClientSecret string
	// UsernameClaim is the claim that names the person, e.g.
	// "preferred_username" or "email".
	UsernameClaim string
	// GroupsClaim is the claim with the person's groups, e.g. "groups".
	// Empty means the provider sends none.
	GroupsClaim string
	// Scopes are asked for at the login. "openid" is always included.
	Scopes []string
}

// Client talks to the identity provider. Create one with New. It is safe
// for concurrent use.
type Client struct {
	cfg Config

	// The provider's settings are fetched from it at the first login
	// and kept. A provider that cannot be reached when the CA starts
	// does not stop the CA: the logins wait for it, the rest works.
	mu       sync.Mutex
	provider *gooidc.Provider
}

// New returns a client for the provider. It does not contact it yet.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// discover fetches the provider's settings, once.
func (c *Client) discover(ctx context.Context) (*gooidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	provider, err := gooidc.NewProvider(ctx, c.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the identity provider at %s: %w", c.cfg.Issuer, err)
	}
	c.provider = provider
	return provider, nil
}

func (c *Client) oauth2Config(provider *gooidc.Provider, redirectURI string) *oauth2.Config {
	scopes := []string{gooidc.ScopeOpenID}
	for _, scope := range c.cfg.Scopes {
		if scope != gooidc.ScopeOpenID {
			scopes = append(scopes, scope)
		}
	}
	return &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       scopes,
	}
}

// AuthorizeURL returns the provider address to send the person's browser
// to. redirectURI is where the provider sends the browser afterwards.
// state is handed back unchanged; nonce comes back inside the ID token;
// verifier is the PKCE secret, of which only a hash goes to the browser.
func (c *Client) AuthorizeURL(ctx context.Context, redirectURI, state, nonce, verifier string) (string, error) {
	provider, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	return c.oauth2Config(provider, redirectURI).AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

// Login turns the code the provider sent back with the browser into the
// person's identity: their name and groups, from the checked ID token.
func (c *Client) Login(ctx context.Context, code, redirectURI, nonce, verifier string) (policy.Identity, error) {
	if code == "" {
		return policy.Identity{}, fmt.Errorf("%w: no code", ErrLoginFailed)
	}
	provider, err := c.discover(ctx)
	if err != nil {
		return policy.Identity{}, err
	}

	token, err := c.oauth2Config(provider, redirectURI).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var refused *oauth2.RetrieveError
		if errors.As(err, &refused) && refused.ErrorCode == "invalid_grant" {
			// A wrong, used or old code, or the wrong PKCE verifier.
			return policy.Identity{}, fmt.Errorf("%w: the provider did not accept the code", ErrLoginFailed)
		}
		// For example a wrong client secret: a mistake in the CA's
		// configuration, not something the person can fix.
		return policy.Identity{}, fmt.Errorf("the identity provider refused the login: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return policy.Identity{}, errors.New("the identity provider's answer has no ID token")
	}

	// Signature, issuer, audience (our client ID) and expiry.
	idToken, err := provider.Verifier(&gooidc.Config{ClientID: c.cfg.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return policy.Identity{}, fmt.Errorf("%w: the ID token is not valid: %v", ErrLoginFailed, err)
	}
	// The nonce ties the token to the login this CA started.
	if idToken.Nonce != nonce {
		return policy.Identity{}, fmt.Errorf("%w: the ID token belongs to another login", ErrLoginFailed)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return policy.Identity{}, fmt.Errorf("cannot read the ID token: %w", err)
	}
	return c.identity(claims)
}

// identity reads the person's name and groups from the ID token's claims.
func (c *Client) identity(claims map[string]any) (policy.Identity, error) {
	username, _ := claims[c.cfg.UsernameClaim].(string)
	username = strings.TrimSpace(username)
	if username == "" {
		return policy.Identity{}, fmt.Errorf("the ID token has no %q claim to name the person: check oidc.username_claim", c.cfg.UsernameClaim)
	}
	// An email address names a person only if the provider checked that
	// it is theirs. Some providers let people set an address they do not
	// own, or one that is not checked (Entra ID's "email" claim is the
	// known case): without this check, someone could log in with a
	// chosen address and match a rule meant for someone else.
	if c.cfg.UsernameClaim == "email" && !emailVerified(claims["email_verified"]) {
		return policy.Identity{}, fmt.Errorf("%w: the provider does not say the email address %s is verified; "+
			"use a claim the provider controls, such as preferred_username, as oidc.username_claim", ErrLoginFailed, username)
	}

	// Linux login names are lower case, and SSSD reports AD names in
	// lower case. The principals made from this name must match them.
	id := policy.Identity{Source: "oidc", Username: strings.ToLower(username)}

	if c.cfg.GroupsClaim == "" {
		return id, nil
	}
	// Entra ID leaves the groups out of the token when there are too
	// many (about 200), and says so in "_claim_names". Refuse, rather
	// than log the person in as a member of no groups at all.
	if names, ok := claims["_claim_names"].(map[string]any); ok {
		if _, overflow := names[c.cfg.GroupsClaim]; overflow {
			return policy.Identity{}, fmt.Errorf("%w: %s is in too many groups for the ID token; "+
				"limit the groups the provider sends (Entra ID: \"groups assigned to the application\")", ErrLoginFailed, id.Username)
		}
	}
	switch groups := claims[c.cfg.GroupsClaim].(type) {
	case nil:
		// No groups: the person is in none, or the provider was not
		// set up to send them. Rules by name still apply.
	case []any:
		for _, group := range groups {
			if name, ok := group.(string); ok && name != "" {
				id.Groups = append(id.Groups, name)
			}
		}
	case string:
		// Some providers send a single group as a plain string.
		if groups != "" {
			id.Groups = []string{groups}
		}
	default:
		return policy.Identity{}, fmt.Errorf("the %q claim in the ID token is not a list of groups", c.cfg.GroupsClaim)
	}
	return id, nil
}

// emailVerified reads the "email_verified" claim. Most providers send a
// boolean; some send the text "true".
func emailVerified(claim any) bool {
	switch v := claim.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// Check fetches the provider's settings, to find configuration mistakes
// before somebody tries to log in.
func (c *Client) Check(ctx context.Context) error {
	_, err := c.discover(ctx)
	return err
}
