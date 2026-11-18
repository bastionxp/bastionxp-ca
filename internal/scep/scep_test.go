// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// testEnv is a SCEP server with a CA behind it. The decision "may this
// device have a certificate" is a stand-in here: the challenge must be
// goodChallenge. The real decision, with tokens, is tested in the server
// package.
type testEnv struct {
	t      *testing.T
	ca     *ca.CA
	ra     *RA
	dir    string
	client *Client
	url    string

	mu     sync.Mutex
	issued []*x509.CertificateRequest // every CSR a certificate was issued for
	certs  []*x509.Certificate        // every certificate issued, for GetCert
}

func forKey(key *rsa.PrivateKey) func(*x509.Certificate) bool {
	return func(cert *x509.Certificate) bool { return key.PublicKey.Equal(cert.PublicKey) }
}

const goodChallenge = "the-right-challenge_with.odd-chars"

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := LoadOrCreateRA(dir, authority)
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{t: t, ca: authority, ra: ra, dir: dir}

	server := New(Options{
		RA:      ra,
		CACerts: []*x509.Certificate{authority.IntermediateCert(), authority.RootCert()},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issue: func(ctx context.Context, challenge string, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error) {
			if challenge != goodChallenge {
				return nil, errors.New("wrong challenge")
			}
			req, err := ca.RequestFromCSR(ca.TLSClient, csr)
			if err != nil {
				return nil, err
			}
			return env.record(csr, req)
		},
		// The real decision is in the server package. Here: a valid
		// certificate of this CA, renewed for its names.
		Renew: func(ctx context.Context, old *x509.Certificate, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error) {
			pool := x509.NewCertPool()
			pool.AddCert(authority.RootCert())
			inter := x509.NewCertPool()
			inter.AddCert(authority.IntermediateCert())
			if _, err := old.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return nil, err
			}
			return env.record(csr, ca.X509Request{Template: ca.TLSClient, PublicKey: csr.PublicKey, CommonName: old.Subject.CommonName, DNSNames: old.DNSNames})
		},
		Lookup: func(ctx context.Context, serial *big.Int) (*x509.Certificate, error) {
			env.mu.Lock()
			defer env.mu.Unlock()
			for _, cert := range env.certs {
				if cert.SerialNumber.Cmp(serial) == 0 {
					return cert, nil
				}
			}
			return nil, nil
		},
	})
	mux := http.NewServeMux()
	mux.Handle(Path, server)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	env.url = ts.URL + Path
	env.client = NewClient(env.url, ts.Client())
	return env
}

func (e *testEnv) record(csr *x509.CertificateRequest, req ca.X509Request) (*x509.Certificate, error) {
	cert, err := e.ca.IssueX509(req)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.issued = append(e.issued, csr)
	e.certs = append(e.certs, cert)
	return cert, nil
}

func (e *testEnv) issuedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.issued)
}

func newRSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func csrTemplate(name string) *x509.CertificateRequest {
	return &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}
}

// The whole road: a device asks for the server's certificates, sends a
// CSR with the challenge, and gets its certificate.
func TestEnroll(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	key := newRSAKey(t)

	caCerts, err := env.client.GetCACerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !caCerts.RA.Equal(env.ra.Cert) {
		t.Error("the client did not pick the RA certificate to encrypt for")
	}
	if len(caCerts.Others) != 2 {
		t.Errorf("%d CA certificates, want 2 (intermediate and root)", len(caCerts.Others))
	}
	// A client that knows only the root can tell that the RA is the CA's.
	roots := x509.NewCertPool()
	roots.AddCert(env.ca.RootCert())
	if err := caCerts.VerifyRA(roots); err != nil {
		t.Errorf("the RA certificate does not verify against the root: %v", err)
	}

	csr, err := NewCSR(csrTemplate("device1.example.com"), key, goodChallenge)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := env.client.Enroll(ctx, csr, key, caCerts)
	if err != nil {
		t.Fatal(err)
	}

	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("the certificate is for another key")
	}
	if cert.Subject.CommonName != "device1.example.com" {
		t.Errorf("common name = %q", cert.Subject.CommonName)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(env.ca.IntermediateCert())
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("the certificate does not verify against the root: %v", err)
	}
}

// SCEP enrollment is refused with a wrong challenge, without a challenge,
// with a CSR for another key than the one that signs the message, and with
// something that is not a CSR; nothing is issued.
func TestEnrollIsRefused(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	caCerts, err := env.client.GetCACerts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A wrong challenge.
	key := newRSAKey(t)
	csr, err := NewCSR(csrTemplate("device1.example.com"), key, "a-wrong-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.Enroll(ctx, csr, key, caCerts); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("wrong challenge: error = %v, want a refusal", err)
	}

	// No challenge at all: a plain CSR.
	plain, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate("device1.example.com"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.Enroll(ctx, plain, key, caCerts); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("no challenge: error = %v, want a refusal", err)
	}

	// A CSR for another key than the one that signs the message: a
	// device asking for a certificate for somebody else's key.
	otherKey := newRSAKey(t)
	foreign, err := NewCSR(csrTemplate("device1.example.com"), otherKey, goodChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.Enroll(ctx, foreign, key, caCerts); err == nil || !strings.Contains(err.Error(), "signature check failed") {
		t.Errorf("CSR for another key: error = %v, want 'signature check failed'", err)
	}

	// Something that is no CSR.
	if _, err := env.client.Enroll(ctx, []byte("hello"), key, caCerts); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("not a CSR: error = %v, want a refusal", err)
	}

	if n := env.issuedCount(); n != 0 {
		t.Errorf("%d certificates were issued for refused requests", n)
	}
}

// post sends a raw PKIOperation message and returns the HTTP status.
func (e *testEnv) post(message []byte) int {
	e.t.Helper()
	resp, err := http.Post(e.url+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(message))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// buildMessage makes a request message by hand, so that tests can get
// single parts of it wrong.
func buildMessage(t testing.TB, key *rsa.PrivateKey, encryptFor *x509.Certificate, csr []byte, messageType string) []byte {
	t.Helper()
	selfSigned, err := selfSignedCert(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := pkcs7.Encrypt(csr, []*x509.Certificate{encryptFor})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.AddSigner(selfSigned, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		printable(oidMessageType, messageType),
		printable(oidTransactionID, "txn-1"),
		{Type: oidSenderNonce, Value: []byte("0123456789abcdef")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	message, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// SCEP messages encrypted for another key, changed after signing, or without
// SCEP attributes are refused with 400, and issue nothing.
func TestMessagesTheServerCannotOpen(t *testing.T) {
	env := newTestEnv(t)
	key := newRSAKey(t)
	csr, err := NewCSR(csrTemplate("device1.example.com"), key, goodChallenge)
	if err != nil {
		t.Fatal(err)
	}
	good := buildMessage(t, key, env.ra.Cert, csr, messagePKCSReq)

	// First show that the hand-built message is right.
	if status := env.post(good); status != http.StatusOK || env.issuedCount() != 1 {
		t.Fatalf("a correct message: status %d, %d certificates issued; want 200 and 1", status, env.issuedCount())
	}

	// Encrypted for a key the server does not have.
	strangerKey := newRSAKey(t)
	stranger, err := selfSignedCert(strangerKey)
	if err != nil {
		t.Fatal(err)
	}
	forSomeoneElse := buildMessage(t, key, stranger, csr, messagePKCSReq)

	// Changed after it was signed.
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-10] ^= 0xff

	// Signed data that is not a SCEP message: no SCEP attributes.
	plainSigned, _ := pkcs7.NewSignedData([]byte("hello"))
	selfSigned, _ := selfSignedCert(key)
	plainSigned.AddSigner(selfSigned, key, pkcs7.SignerInfoConfig{})
	notSCEP, _ := plainSigned.Finish()

	bad := map[string][]byte{
		"empty":                      {},
		"not PKCS#7":                 []byte("hello"),
		"encrypted for someone else": forSomeoneElse,
		"changed after signing":      tampered,
		"signed but not SCEP":        notSCEP,
		"too large":                  bytes.Repeat([]byte("a"), maxBodyBytes+1),
	}
	for name, message := range bad {
		t.Run(name, func(t *testing.T) {
			if status := env.post(message); status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", status)
			}
		})
	}
	if n := env.issuedCount(); n != 1 {
		t.Errorf("%d certificates issued in total, want only the one for the correct message", n)
	}
}

// Enrollment, renewal and GetCert are supported. Other message types,
// and renewal or GetCert messages that are not what they say, get a
// proper SCEP refusal, and no certificate.
func TestOtherMessageTypesAreRefused(t *testing.T) {
	env := newTestEnv(t)
	key := newRSAKey(t)
	csr, err := NewCSR(csrTemplate("device1.example.com"), key, goodChallenge)
	if err != nil {
		t.Fatal(err)
	}
	// Renewal signed by a key that is not a certificate of the CA, with a
	// CSR for that same key; a GetCert whose content is a CSR; poll; GetCRL.
	for _, messageType := range []string{"17", "21", "20", "22"} {
		resp, err := http.Post(env.url+"?operation=PKIOperation", "application/x-pki-message",
			bytes.NewReader(buildMessage(t, key, env.ra.Cert, csr, messageType)))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("message type %s: status %d, want a SCEP answer with status 200", messageType, resp.StatusCode)
			continue
		}
		reply, err := pkcs7.Parse(body)
		if err != nil {
			t.Fatal(err)
		}
		var status string
		reply.UnmarshalSignedAttribute(oidPKIStatus, &status)
		if status != statusFailure {
			t.Errorf("message type %s: SCEP status %q, want failure", messageType, status)
		}
	}
	if n := env.issuedCount(); n != 0 {
		t.Errorf("%d certificates were issued", n)
	}
}

// A device with an ECDSA key cannot use SCEP: the answer could not be
// encrypted for it. It must get a refusal, not a server error.
func TestDeviceWithECDSAKeyIsRefused(t *testing.T) {
	env := newTestEnv(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: newSerialForTest(), Subject: pkix.Name{CommonName: "device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, _ := x509.ParseCertificate(der)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate("device1.example.com"), key)

	encrypted, err := pkcs7.Encrypt(csr, []*x509.Certificate{env.ra.Cert})
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := pkcs7.NewSignedData(encrypted)
	err = signed.AddSigner(selfSigned, key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		printable(oidMessageType, messagePKCSReq),
		printable(oidTransactionID, "txn-1"),
		{Type: oidSenderNonce, Value: []byte("0123456789abcdef")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	message, _ := signed.Finish()

	resp, err := http.Post(env.url+"?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want a SCEP answer with status 200", resp.StatusCode)
	}
	reply, err := pkcs7.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	var status, failInfo string
	reply.UnmarshalSignedAttribute(oidPKIStatus, &status)
	reply.UnmarshalSignedAttribute(oidFailInfo, &failInfo)
	if status != statusFailure || failInfo != failBadAlgorithm {
		t.Errorf("SCEP status %q, fail info %q; want failure, unsupported algorithm", status, failInfo)
	}
}

func newSerialForTest() *big.Int { return big.NewInt(time.Now().UnixNano()) }

// GetCACaps lists POSTPKIOperation, SHA-256, AES and SCEPStandard, and
// Renewal only when the server can renew; unknown operations are refused
// with 400.
func TestGetCACapsAndUnknownOperations(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.url + "?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	caps := strings.Fields(string(body))
	for _, want := range []string{"POSTPKIOperation", "SHA-256", "AES", "SCEPStandard"} {
		found := false
		for _, cap := range caps {
			found = found || cap == want
		}
		if !found {
			t.Errorf("capabilities %v lack %s", caps, want)
		}
	}
	// Renewal is advertised when the server can renew, and the client
	// reads it.
	if got, err := env.client.Capabilities(context.Background()); err != nil || !slices.Contains(got, "Renewal") {
		t.Errorf("client capabilities = %v, %v; want Renewal", got, err)
	}
	// What is not supported must not be advertised.
	noRenewal := httptest.NewServer(New(Options{RA: env.ra, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}))
	defer noRenewal.Close()
	if got, err := NewClient(noRenewal.URL, noRenewal.Client()).Capabilities(context.Background()); err != nil || slices.Contains(got, "Renewal") {
		t.Errorf("a server without renewal advertises %v (%v)", got, err)
	}

	for _, query := range []string{"", "?operation=Nonsense", "?operation=GetNextCACert"} {
		resp, err := http.Get(env.url + query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", query, resp.StatusCode)
		}
	}
}

// Old devices send the message as a parameter of a GET request.
func TestPKIOperationWithGET(t *testing.T) {
	env := newTestEnv(t)
	key := newRSAKey(t)
	csr, err := NewCSR(csrTemplate("device1.example.com"), key, goodChallenge)
	if err != nil {
		t.Fatal(err)
	}
	message := buildMessage(t, key, env.ra.Cert, csr, messagePKCSReq)

	resp, err := http.Get(env.url + "?operation=PKIOperation&message=" + url.QueryEscape(base64.StdEncoding.EncodeToString(message)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || env.issuedCount() != 1 {
		t.Errorf("status %d, %d certificates issued; want 200 and 1", resp.StatusCode, env.issuedCount())
	}

	resp, err = http.Get(env.url + "?operation=PKIOperation&message=not-base64!")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad base64: status %d, want 400", resp.StatusCode)
	}
}

// A client must not accept an answer that is not from the RA, or that
// belongs to another request.
func TestClientChecksTheAnswer(t *testing.T) {
	env := newTestEnv(t)
	key := newRSAKey(t)
	selfSigned, err := selfSignedCert(key)
	if err != nil {
		t.Fatal(err)
	}
	// A certificate for the device's key, as the answer would carry.
	cert, err := env.ca.IssueX509(ca.X509Request{Template: ca.TLSClient, PublicKey: key.Public(), CommonName: "device1"})
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef")
	req := &request{transactionID: "txn-1", senderNonce: nonce, signer: selfSigned}

	good, err := successReply(req, cert, env.ra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openReply(good, selfSigned, key, env.ra.Cert, "txn-1", nonce, forKey(key)); err != nil {
		t.Fatalf("a correct answer was refused: %v", err)
	}

	// Signed by somebody who is not the RA: an attacker between the
	// device and the CA, handing out a certificate of their own making.
	impostorKey := newRSAKey(t)
	impostorCert, _ := selfSignedCert(impostorKey)
	fromImpostor, err := successReply(req, cert, &RA{Cert: impostorCert, Key: impostorKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openReply(fromImpostor, selfSigned, key, env.ra.Cert, "txn-1", nonce, forKey(key)); err == nil {
		t.Error("an answer signed by someone else was accepted")
	}

	// A real answer of the RA, but to another request.
	if _, err := openReply(good, selfSigned, key, env.ra.Cert, "txn-2", nonce, forKey(key)); err == nil {
		t.Error("an answer with another transaction ID was accepted")
	}
	if _, err := openReply(good, selfSigned, key, env.ra.Cert, "txn-1", []byte("another-nonce-00"), forKey(key)); err == nil {
		t.Error("an answer with another nonce was accepted: a replayed old answer")
	}

	// An answer whose certificate is for another key.
	otherKey := newRSAKey(t)
	otherCert, _ := env.ca.IssueX509(ca.X509Request{Template: ca.TLSClient, PublicKey: otherKey.Public(), CommonName: "other"})
	wrongCert, err := successReply(req, otherCert, env.ra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openReply(wrongCert, selfSigned, key, env.ra.Cert, "txn-1", nonce, forKey(key)); err == nil {
		t.Error("a certificate for another key was accepted")
	}

	// A refusal is reported as one.
	refused, err := failureReply(req, failBadRequest, env.ra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openReply(refused, selfSigned, key, env.ra.Cert, "txn-1", nonce, forKey(key)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a refusal: error = %v, want one that says 'refused'", err)
	}
}

// The RA of one CA must not pass as the RA of another.
func TestVerifyRAAgainstAnotherCA(t *testing.T) {
	env := newTestEnv(t)
	other := newTestEnv(t)
	caCerts, err := env.client.GetCACerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other.ca.RootCert())
	if err := caCerts.VerifyRA(otherRoots); err == nil {
		t.Error("the RA certificate was accepted against another CA's root")
	}
}

// The challenge password in a CSR is written and read back, short or long,
// and the CSR stays valid for other software; an empty challenge is an
// error; a CSR without one, or something that is not a CSR, has none.
func TestChallengeInCSR(t *testing.T) {
	key := newRSAKey(t)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device1.example.com", Organization: []string{"Example"}},
		DNSNames: []string{"device1.example.com", "alt.example.com"},
	}
	// A challenge with the characters of a real token, and a long one.
	for _, challenge := range []string{"simple", goodChallenge, strings.Repeat("eyJhbGciOiJFUzI1NiJ9-_.", 30)} {
		der, err := NewCSR(template, key, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if got := Challenge(der); got != challenge {
			t.Errorf("challenge read back as %q, want %q", got, challenge)
		}
		// The CSR is still a good CSR for everybody else: the standard
		// library reads it, the signature holds, the names are there.
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Errorf("the signature of the CSR is not valid: %v", err)
		}
		if csr.Subject.CommonName != "device1.example.com" || len(csr.DNSNames) != 2 {
			t.Errorf("subject %q, DNS names %v", csr.Subject.CommonName, csr.DNSNames)
		}
	}

	if _, err := NewCSR(template, key, ""); err == nil {
		t.Error("expected an error for an empty challenge")
	}

	// CSRs without a challenge, and things that are no CSR.
	plain, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	for _, der := range [][]byte{plain, nil, []byte("hello")} {
		if got := Challenge(der); got != "" {
			t.Errorf("challenge = %q, want none", got)
		}
	}
}

// The SCEP RA certificate: an RSA key, not a CA, for signing and key
// encipherment, key file mode 600; created once and reused; a key that does
// not match the certificate is an error.
func TestLoadOrCreateRA(t *testing.T) {
	env := newTestEnv(t) // creates the RA once

	if _, ok := env.ra.Cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("the RA key is a %T, want RSA", env.ra.Cert.PublicKey)
	}
	if env.ra.Cert.IsCA {
		t.Error("the RA certificate is a CA certificate: it could sign certificates itself")
	}
	if env.ra.Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 || env.ra.Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("RA key usage = %b, want signing and key encipherment", env.ra.Cert.KeyUsage)
	}
	info, err := os.Stat(filepath.Join(env.dir, RAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("RA key file mode = %o, want 600", perm)
	}

	// A second start uses the same RA.
	again, err := LoadOrCreateRA(env.dir, env.ca)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Cert.Equal(env.ra.Cert) || !again.Key.Equal(env.ra.Key) {
		t.Error("the second start made a new RA")
	}

	// A key that does not belong to the certificate is an error, not
	// something to quietly work with.
	otherKey := newRSAKey(t)
	der, _ := x509.MarshalPKCS8PrivateKey(otherKey)
	if err := writeFile(filepath.Join(env.dir, RAKeyFile), pemEncode("PRIVATE KEY", der), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRA(env.dir, env.ca); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatched key: error = %v, want one that says so", err)
	}
}

// An RA certificate that ends soon is replaced at the next start.
func TestRAIsRenewedBeforeItEnds(t *testing.T) {
	env := newTestEnv(t)

	// Put an RA certificate in place that ends in a week.
	soon, err := env.ca.IssueX509(ca.X509Request{
		Template:   ca.X509Template{Name: "scep-ra", DefaultValidity: 7 * 24 * time.Hour, MaxValidity: 7 * 24 * time.Hour},
		PublicKey:  env.ra.Key.Public(),
		CommonName: "SCEP RA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(env.dir, RACertFile), ca.EncodeCertPEM(soon), 0o644); err != nil {
		t.Fatal(err)
	}

	renewed, err := LoadOrCreateRA(env.dir, env.ca)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Cert.Equal(soon) {
		t.Error("the RA certificate that ends soon was kept")
	}
	if time.Until(renewed.Cert.NotAfter) < raRenewBefore {
		t.Errorf("the new RA certificate ends in %s", time.Until(renewed.Cert.NotAfter))
	}
	if renewed.Key.Equal(env.ra.Key) {
		t.Error("the new RA certificate uses the old key")
	}
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// Renewal: signed with the current certificate, a CSR for a new key.
func TestRenew(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	caCerts, err := env.client.GetCACerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := newRSAKey(t)
	csr, _ := NewCSR(csrTemplate("device1.example.com"), oldKey, goodChallenge)
	old, err := env.client.Enroll(ctx, csr, oldKey, caCerts)
	if err != nil {
		t.Fatal(err)
	}

	newKey := newRSAKey(t)
	plain, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, newKey)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := env.client.Renew(ctx, plain, old, oldKey, caCerts)
	if err != nil {
		t.Fatal(err)
	}
	if !newKey.PublicKey.Equal(renewed.PublicKey) || renewed.Subject.CommonName != "device1.example.com" {
		t.Errorf("renewed: key matches %v, common name %q", newKey.PublicKey.Equal(renewed.PublicKey), renewed.Subject.CommonName)
	}

	// The same key again works too: RFC 8894 allows it, and many
	// devices renew that way.
	sameKeyCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, oldKey)
	again, err := env.client.Renew(ctx, sameKeyCSR, old, oldKey, caCerts)
	if err != nil {
		t.Fatalf("renewal with the same key: %v", err)
	}
	if !oldKey.PublicKey.Equal(again.PublicKey) || again.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Error("not a new certificate for the same key")
	}
	// A CSR whose signature is broken is refused.
	broken := append([]byte(nil), plain...)
	broken[len(broken)-1] ^= 0xff
	if _, err := env.client.Renew(ctx, broken, old, oldKey, caCerts); err == nil {
		t.Error("a CSR with a broken signature was accepted")
	}
	// A certificate the CA did not issue cannot renew.
	stranger := newRSAKey(t)
	selfMade, _ := selfSignedCert(stranger)
	if _, err := env.client.Renew(ctx, plain, selfMade, stranger, caCerts); err == nil {
		t.Error("a self-made certificate renewed")
	}
}

// GetCert: the holder of a certificate's key gets it again; nobody else.
func TestGetCert(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	caCerts, err := env.client.GetCACerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := newRSAKey(t)
	csr, _ := NewCSR(csrTemplate("device1.example.com"), key, goodChallenge)
	issued, err := env.client.Enroll(ctx, csr, key, caCerts)
	if err != nil {
		t.Fatal(err)
	}
	issuer := env.ca.IntermediateCert()

	got, err := env.client.GetCert(ctx, issuer, issued.SerialNumber, key, caCerts)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(issued) {
		t.Error("GetCert returned another certificate")
	}
	// Another key: refused.
	if _, err := env.client.GetCert(ctx, issuer, issued.SerialNumber, newRSAKey(t), caCerts); err == nil {
		t.Error("GetCert gave the certificate to someone without its key")
	}
	// No such serial, or another issuer: "no such certificate".
	_, err = env.client.GetCert(ctx, issuer, big.NewInt(12345), key, caCerts)
	if err == nil || !strings.Contains(err.Error(), "no such certificate") {
		t.Errorf("unknown serial: error = %v", err)
	}
	_, err = env.client.GetCert(ctx, env.ca.RootCert(), issued.SerialNumber, key, caCerts)
	if err == nil || !strings.Contains(err.Error(), "no such certificate") {
		t.Errorf("wrong issuer: error = %v", err)
	}
}
