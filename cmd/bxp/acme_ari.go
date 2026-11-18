// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	caacme "github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// "bxp acme renew" asks the CA when to renew (ACME Renewal Information,
// RFC 9773). BastionXP CA says "now" for a revoked certificate. A CA that
// does not answer leaves the decision to the usual rule: when a third of
// the lifetime is left.

// renewalInfoTimeout bounds the question: an unanswered one must not hold
// up the renewal.
const renewalInfoTimeout = 15 * time.Second

// acmeDirectoryURL is the ACME directory to use: --directory, or the one
// of the CA given with --ca-url.
func acmeDirectoryURL(conn connection, directory string) (string, error) {
	if directory != "" {
		return directory, nil
	}
	if conn.url == "" {
		return "", fmt.Errorf("give the CA server's address with --ca-url or %s", envURL)
	}
	return strings.TrimRight(conn.url, "/") + caacme.DirectoryPath, nil
}

// fetchRenewalWindow asks the CA when to renew cert.
func fetchRenewalWindow(ctx context.Context, httpClient *http.Client, directoryURL string, cert *x509.Certificate) (start, end time.Time, err error) {
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := getJSON(ctx, httpClient, directoryURL, &dir); err != nil {
		return start, end, err
	}
	if dir.RenewalInfo == "" {
		return start, end, errors.New("the CA gives no renewal information")
	}
	id, err := caacme.CertID(cert)
	if err != nil || len(cert.AuthorityKeyId) == 0 {
		return start, end, errors.New("the certificate has no authority key ID")
	}
	var info struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
	}
	if err := getJSON(ctx, httpClient, strings.TrimRight(dir.RenewalInfo, "/")+"/"+id, &info); err != nil {
		return start, end, err
	}
	start, end = info.SuggestedWindow.Start, info.SuggestedWindow.End
	if start.IsZero() || !end.After(start) {
		return time.Time{}, time.Time{}, errors.New("the CA's renewal window is not valid")
	}
	return start, end, nil
}

func getJSON(ctx context.Context, httpClient *http.Client, url string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dest)
}

// acmeRenewalDue says whether cert is due for renewal. If not, notYet is
// what to tell the user.
func acmeRenewalDue(ctx context.Context, conn connection, directory string, cert *x509.Certificate, now time.Time) (due bool, notYet string) {
	validUntil := cert.NotAfter.Local().Format(listTimeFormat)
	if directoryURL, err := acmeDirectoryURL(conn, directory); err == nil {
		if httpClient, err := client.NewHTTPClient(conn.root); err == nil {
			ctx, cancel := context.WithTimeout(ctx, renewalInfoTimeout)
			defer cancel()
			if start, end, err := fetchRenewalWindow(ctx, httpClient, directoryURL, cert); err == nil {
				// RFC 9773, section 4.2: a random moment in the window,
				// so that clients do not all come at once.
				at := start.Add(time.Duration(rand.Int64N(int64(end.Sub(start)) + 1)))
				if !now.Before(at) {
					return true, ""
				}
				return false, fmt.Sprintf("valid until %s; the CA suggests renewing between %s and %s",
					validUntil, start.Local().Format(listTimeFormat), end.Local().Format(listTimeFormat))
			}
		}
	}
	if renewDue(cert.NotBefore, cert.NotAfter, now) {
		return true, ""
	}
	from := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	return false, fmt.Sprintf("valid until %s, renews from %s on", validUntil, from.Local().Format(listTimeFormat))
}

// acmeRetry is when bxp's ACME client tries a failed request again. A CA
// over its rate limit (429) is not waited for: its Retry-After can be an
// hour, and a command run from a timer should say so at once (see
// explainACMEError). Other passing failures (a server error, a bad nonce)
// are tried again a few times, briefly.
func acmeRetry(n int, _ *http.Request, resp *http.Response) time.Duration {
	if resp.StatusCode == http.StatusTooManyRequests || n > 5 {
		return 0 // no more tries: the CA's own error is returned
	}
	return min(time.Duration(1<<(n-1))*time.Second, 10*time.Second)
}

// explainACMEError turns a CA's rate limit into a plain message, with when
// to try again. Other errors are returned as they are.
func explainACMEError(err error) error {
	var problem *acme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusTooManyRequests {
		return err
	}
	msg := "the CA limits requests and refused this one: " + problem.Detail
	if wait := retryAfter(problem.Header, time.Now()); wait > 0 {
		msg += fmt.Sprintf("; try again after %s (in %s)",
			time.Now().Add(wait).Local().Format("15:04"), wait.Round(time.Minute))
	} else {
		msg += "; try again later"
	}
	return errors.New(msg)
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now)
	}
	return 0
}
