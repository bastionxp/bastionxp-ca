// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"
)

// fakeRecorder remembers what it is told, or refuses.
type fakeRecorder struct {
	x509Certs []*x509.Certificate
	sshCerts  []*ssh.Certificate
	templates []string
	fail      error
}

func (r *fakeRecorder) RecordX509(cert *x509.Certificate, template, protocol string) error {
	if r.fail != nil {
		return r.fail
	}
	r.x509Certs = append(r.x509Certs, cert)
	r.templates = append(r.templates, template)
	return nil
}

func (r *fakeRecorder) RecordSSH(cert *ssh.Certificate, template string) error {
	if r.fail != nil {
		return r.fail
	}
	r.sshCerts = append(r.sshCerts, cert)
	r.templates = append(r.templates, template)
	return nil
}

func x509TestRequest(t *testing.T) X509Request {
	t.Helper()
	return X509Request{Template: TLSServer, PublicKey: newLeafKey(t).Public(), DNSNames: []string{"web.example.com"}}
}

func sshTestRequest(t *testing.T) SSHRequest {
	t.Helper()
	return SSHRequest{Template: SSHUser, PublicKey: newSSHKey(t), KeyID: "alice", Principals: []string{"alice"}}
}

// Every TLS and SSH certificate the CA issues is recorded, with its profile.
func TestEveryCertificateIsRecorded(t *testing.T) {
	authority := newTestCA(t)
	recorder := &fakeRecorder{}
	authority.Record(recorder)

	x509Cert, err := authority.IssueX509(x509TestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	sshCert, err := authority.IssueSSH(sshTestRequest(t))
	if err != nil {
		t.Fatal(err)
	}

	if len(recorder.x509Certs) != 1 || !recorder.x509Certs[0].Equal(x509Cert) {
		t.Errorf("X.509 certificates recorded: %d, want the one issued", len(recorder.x509Certs))
	}
	if len(recorder.sshCerts) != 1 || recorder.sshCerts[0].Serial != sshCert.Serial {
		t.Errorf("SSH certificates recorded: %d, want the one issued", len(recorder.sshCerts))
	}
	if len(recorder.templates) != 2 || recorder.templates[0] != "tls-server" || recorder.templates[1] != "ssh-user" {
		t.Errorf("templates recorded = %v", recorder.templates)
	}
}

// The CA must not hand out a certificate it could not record: nobody
// could revoke it later.
func TestNoCertificateWithoutARecord(t *testing.T) {
	authority := newTestCA(t)
	authority.Record(&fakeRecorder{fail: errors.New("disk full")})

	if cert, err := authority.IssueX509(x509TestRequest(t)); err == nil || cert != nil {
		t.Errorf("X.509: cert = %v, error = %v; want no certificate and an error", cert != nil, err)
	}
	if cert, err := authority.IssueSSH(sshTestRequest(t)); err == nil || cert != nil {
		t.Errorf("SSH: cert = %v, error = %v; want no certificate and an error", cert != nil, err)
	}
}

// A request the CA refuses anyway is not recorded.
func TestRefusedRequestsAreNotRecorded(t *testing.T) {
	authority := newTestCA(t)
	recorder := &fakeRecorder{}
	authority.Record(recorder)

	req := x509TestRequest(t)
	req.DNSNames = nil // a server certificate without a host name
	if _, err := authority.IssueX509(req); err == nil {
		t.Fatal("expected an error")
	}
	if len(recorder.x509Certs) != 0 {
		t.Error("a refused request was recorded")
	}
}

// With a public address set, certificates carry the CRL, OCSP and issuer-
// certificate addresses; without one, none.
func TestPublishAtWritesAddressesIntoCertificates(t *testing.T) {
	authority := newTestCA(t)

	// Without an address, certificates say nothing about where to ask.
	plain, err := authority.IssueX509(x509TestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.CRLDistributionPoints)+len(plain.OCSPServer)+len(plain.IssuingCertificateURL) != 0 {
		t.Errorf("addresses without PublishAt: %v %v %v", plain.CRLDistributionPoints, plain.OCSPServer, plain.IssuingCertificateURL)
	}

	authority.PublishAt("http://ca.example.com:8080/")
	cert, err := authority.IssueX509(x509TestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][]string{
		"http://ca.example.com:8080/crl":              cert.CRLDistributionPoints,
		"http://ca.example.com:8080/ocsp":             cert.OCSPServer,
		"http://ca.example.com:8080/intermediate.crt": cert.IssuingCertificateURL,
	}
	for want, got := range checks {
		if len(got) != 1 || got[0] != want {
			t.Errorf("got %v, want [%s]", got, want)
		}
	}
}

// A CRL is signed by the intermediate, lists each revoked serial number with
// its time and reason, has a sensible validity window, and can be empty.
func TestSignCRL(t *testing.T) {
	authority := newTestCA(t)
	revokedAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	der, err := authority.SignCRL([]Revoked{
		{Serial: big.NewInt(1234), RevokedAt: revokedAt, Reason: ReasonKeyCompromise},
		{Serial: big.NewInt(5678), RevokedAt: revokedAt, Reason: ReasonUnspecified},
	})
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	// Anybody who has the intermediate certificate can check the list.
	if err := crl.CheckSignatureFrom(authority.IntermediateCert()); err != nil {
		t.Errorf("the CRL is not signed by the intermediate: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("%d entries, want 2", len(crl.RevokedCertificateEntries))
	}
	first := crl.RevokedCertificateEntries[0]
	if first.SerialNumber.Int64() != 1234 || !first.RevocationTime.Equal(revokedAt) || first.ReasonCode != ReasonKeyCompromise {
		t.Errorf("first entry = %+v", first)
	}
	if !crl.NextUpdate.After(time.Now()) || crl.ThisUpdate.After(time.Now()) {
		t.Errorf("valid from %s to %s", crl.ThisUpdate, crl.NextUpdate)
	}

	// An empty list is a list too: it says "nothing is revoked".
	der, err = authority.SignCRL(nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := x509.ParseRevocationList(der)
	if err != nil || len(empty.RevokedCertificateEntries) != 0 {
		t.Errorf("empty CRL: %d entries, error %v", len(empty.RevokedCertificateEntries), err)
	}
}

// Each CRL has a higher number than the one before.
func TestCRLNumbersGoUp(t *testing.T) {
	authority := newTestCA(t)
	now := time.Now()
	authority.now = func() time.Time { return now }
	first, _ := authority.SignCRL(nil)
	authority.now = func() time.Time { return now.Add(time.Minute) }
	second, _ := authority.SignCRL(nil)

	a, _ := x509.ParseRevocationList(first)
	b, _ := x509.ParseRevocationList(second)
	if b.Number.Cmp(a.Number) <= 0 {
		t.Errorf("CRL numbers %s then %s, want them to go up", a.Number, b.Number)
	}
}

// OCSP answers are signed for good, revoked (with time and reason) and
// unknown certificates; unknown wins over revoked; each answer has a limited
// validity.
func TestSignOCSP(t *testing.T) {
	authority := newTestCA(t)
	cert, err := authority.IssueX509(x509TestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	tests := []struct {
		name   string
		status OCSPStatus
		want   int
	}{
		{"good", OCSPStatus{Known: true}, ocsp.Good},
		{"revoked", OCSPStatus{Known: true, Revoked: true, RevokedAt: revokedAt, Reason: ReasonKeyCompromise}, ocsp.Revoked},
		{"not ours", OCSPStatus{}, ocsp.Unknown},
		// "Revoked" for a certificate we do not know makes no sense;
		// unknown wins.
		{"unknown but marked revoked", OCSPStatus{Revoked: true}, ocsp.Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := authority.SignOCSP(cert.SerialNumber, tt.status)
			if err != nil {
				t.Fatal(err)
			}
			// ParseResponseForCert checks the signature against the
			// issuer, as a client does.
			resp, err := ocsp.ParseResponseForCert(der, cert, authority.IntermediateCert())
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != tt.want {
				t.Errorf("status = %d, want %d", resp.Status, tt.want)
			}
			if tt.want == ocsp.Revoked && (!resp.RevokedAt.Equal(revokedAt) || resp.RevocationReason != ReasonKeyCompromise) {
				t.Errorf("revoked at %s for reason %d", resp.RevokedAt, resp.RevocationReason)
			}
			if !resp.NextUpdate.After(time.Now()) {
				t.Errorf("the answer is valid until %s", resp.NextUpdate)
			}
		})
	}
}

// An OCSP request, with SHA-1 or SHA-256, is recognised as being about this
// CA's certificates, and not taken by another CA.
func TestIssuedByThisCA(t *testing.T) {
	authority := newTestCA(t)
	other := newTestCA(t)
	cert, err := authority.IssueX509(x509TestRequest(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		der, err := ocsp.CreateRequest(cert, authority.IntermediateCert(), &ocsp.RequestOptions{Hash: hash})
		if err != nil {
			t.Fatal(err)
		}
		req, err := ocsp.ParseRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if !authority.IssuedByThisCA(req) {
			t.Errorf("hash %v: a request about our own certificate was not recognised", hash)
		}
		if other.IssuedByThisCA(req) {
			t.Errorf("hash %v: another CA takes the request for its own", hash)
		}
	}
}
