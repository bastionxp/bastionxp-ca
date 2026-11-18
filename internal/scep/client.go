// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
)

// maxResponseBytes limits how much of an answer is read.
const maxResponseBytes = 1024 * 1024

// Client talks to a SCEP server. Create one with NewClient.
type Client struct {
	url  string
	http *http.Client
}

// NewClient returns a client for the SCEP server at url, for example
// "https://ca.example.com:8443/scep".
func NewClient(url string, httpClient *http.Client) *Client {
	return &Client{url: url, http: httpClient}
}

// CACerts are the certificates a SCEP server hands out.
type CACerts struct {
	// RA is the certificate requests are encrypted for, and the one
	// that signs the server's answers.
	RA *x509.Certificate
	// Others are the CA's certificates, such as the intermediate and
	// the root.
	Others []*x509.Certificate
}

// VerifyRA checks that the RA certificate comes from a CA in roots. The
// address of a SCEP server says nothing about who runs it; this does.
func (c *CACerts) VerifyRA(roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, cert := range c.Others {
		intermediates.AddCert(cert)
	}
	_, err := c.RA.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("the SCEP server's certificate is not from the expected CA: %w", err)
	}
	return nil
}

// GetCACerts asks the server for its certificates.
func (c *Client) GetCACerts(ctx context.Context) (*CACerts, error) {
	body, contentType, err := c.do(ctx, http.MethodGet, "GetCACert", nil)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	if strings.HasPrefix(contentType, "application/x-x509-ca-cert") {
		// A server without an RA sends its one certificate as it is.
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			return nil, fmt.Errorf("cannot read the SCEP server's certificate: %w", err)
		}
		certs = []*x509.Certificate{cert}
	} else {
		p7, err := pkcs7.Parse(body)
		if err != nil {
			return nil, fmt.Errorf("cannot read the SCEP server's certificates: %w", err)
		}
		certs = p7.Certificates
	}

	// The RA is the certificate that may be used to encrypt for: it is
	// not a CA itself, and it has an RSA key.
	result := &CACerts{}
	for _, cert := range certs {
		if result.RA == nil && !cert.IsCA && isRSA(cert) {
			result.RA = cert
		} else {
			result.Others = append(result.Others, cert)
		}
	}
	// No separate RA: then the CA certificate itself is the one.
	if result.RA == nil && len(certs) == 1 && isRSA(certs[0]) {
		result.RA, result.Others = certs[0], nil
	}
	if result.RA == nil {
		return nil, errors.New("the SCEP server sent no certificate that requests can be encrypted for")
	}
	return result, nil
}

// Enroll sends a CSR to the server and returns the certificate it issues.
//
// csrDER is a CSR made with NewCSR, so that it carries the challenge. key
// is the key of the CSR. caCerts is what GetCACerts returned.
func (c *Client) Enroll(ctx context.Context, csrDER []byte, key *rsa.PrivateKey, caCerts *CACerts) (*x509.Certificate, error) {
	// SCEP wants the request signed with a certificate, but the device
	// has none yet: that is what it is asking for. So it makes one for
	// itself, just for this message.
	selfSigned, err := selfSignedCert(key)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, messagePKCSReq, csrDER, selfSigned, key, &key.PublicKey, caCerts, func(cert *x509.Certificate) bool {
		return key.PublicKey.Equal(cert.PublicKey)
	})
}

// Renew asks for a new certificate (RenewalReq). The request is signed
// with the current certificate and its key; csrDER is a plain CSR for
// the new key, which must be an RSA key too.
func (c *Client) Renew(ctx context.Context, csrDER []byte, current *x509.Certificate, currentKey *rsa.PrivateKey, caCerts *CACerts) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	newKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the new key must be an RSA key")
	}
	return c.send(ctx, messageRenewalReq, csrDER, current, currentKey, newKey, caCerts, func(cert *x509.Certificate) bool {
		return newKey.Equal(cert.PublicKey)
	})
}

// GetCert asks for a certificate the CA issued before, by its issuer and
// serial number. key is the certificate's key: the server gives a
// certificate only to the holder of its key.
func (c *Client) GetCert(ctx context.Context, issuer *x509.Certificate, serial *big.Int, key *rsa.PrivateKey, caCerts *CACerts) (*x509.Certificate, error) {
	content, err := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{asn1.RawValue{FullBytes: issuer.RawSubject}, serial})
	if err != nil {
		return nil, err
	}
	selfSigned, err := selfSignedCert(key)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, messageGetCert, content, selfSigned, key, &key.PublicKey, caCerts, func(cert *x509.Certificate) bool {
		return cert.SerialNumber.Cmp(serial) == 0 && key.PublicKey.Equal(cert.PublicKey)
	})
}

// Capabilities returns what the server says it can do (GetCACaps), e.g.
// "Renewal".
func (c *Client) Capabilities(ctx context.Context) ([]string, error) {
	body, _, err := c.do(ctx, http.MethodGet, "GetCACaps", nil)
	if err != nil {
		return nil, err
	}
	var caps []string
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			caps = append(caps, line)
		}
	}
	return caps, nil
}

// send sends one PKIOperation: content encrypted for the RA, signed with
// signer and signerKey. The answer comes back encrypted for signer, and
// the certificate in it must satisfy want. transactionKey names the
// transaction: by convention a fingerprint of the key being certified.
func (c *Client) send(ctx context.Context, messageType string, content []byte, signer *x509.Certificate, signerKey *rsa.PrivateKey,
	transactionKey *rsa.PublicKey, caCerts *CACerts, want func(*x509.Certificate) bool) (*x509.Certificate, error) {
	keyDER, err := x509.MarshalPKIXPublicKey(transactionKey)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(keyDER)
	transactionID := hex.EncodeToString(fingerprint[:])
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Inner envelope: the content, encrypted for the RA.
	encrypted, err := pkcs7.Encrypt(content, []*x509.Certificate{caCerts.RA})
	if err != nil {
		return nil, fmt.Errorf("encrypt the request: %w", err)
	}
	// Outer envelope: signed, with the SCEP attributes.
	signed, err := pkcs7.NewSignedData(encrypted)
	if err != nil {
		return nil, err
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	err = signed.AddSigner(signer, signerKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		printable(oidMessageType, messageType),
		printable(oidTransactionID, transactionID),
		{Type: oidSenderNonce, Value: nonce},
	}})
	if err != nil {
		return nil, fmt.Errorf("sign the request: %w", err)
	}
	message, err := signed.Finish()
	if err != nil {
		return nil, err
	}

	reply, _, err := c.do(ctx, http.MethodPost, "PKIOperation", message)
	if err != nil {
		return nil, err
	}
	return openReply(reply, signer, signerKey, caCerts.RA, transactionID, nonce, want)
}

// openReply checks the server's answer and takes the certificate out.
func openReply(reply []byte, recipient *x509.Certificate, key *rsa.PrivateKey, ra *x509.Certificate, transactionID string, nonce []byte, want func(*x509.Certificate) bool) (*x509.Certificate, error) {
	outer, err := pkcs7.Parse(reply)
	if err != nil {
		return nil, fmt.Errorf("the server's answer is not a SCEP message: %w", err)
	}
	if err := outer.Verify(); err != nil {
		return nil, fmt.Errorf("the signature of the server's answer is not valid: %w", err)
	}
	// Signed, yes, but by whom? It must be the RA.
	signer := outer.GetOnlySigner()
	if signer == nil || !signer.Equal(ra) {
		return nil, errors.New("the server's answer is not signed by the SCEP server's certificate")
	}

	// The answer must belong to this request, and not be an old one
	// that somebody sends again.
	var gotTransaction string
	var gotNonce []byte
	if err := outer.UnmarshalSignedAttribute(oidTransactionID, &gotTransaction); err != nil || gotTransaction != transactionID {
		return nil, errors.New("the server's answer belongs to another request")
	}
	if err := outer.UnmarshalSignedAttribute(oidRecipientNonce, &gotNonce); err != nil || !bytes.Equal(gotNonce, nonce) {
		return nil, errors.New("the server's answer belongs to another request")
	}

	var status string
	if err := outer.UnmarshalSignedAttribute(oidPKIStatus, &status); err != nil {
		return nil, errors.New("the server's answer has no status")
	}
	if status != statusSuccess {
		var failInfo string
		_ = outer.UnmarshalSignedAttribute(oidFailInfo, &failInfo)
		return nil, fmt.Errorf("the CA refused the request (%s). The reason is in the CA's log", failText(status, failInfo))
	}

	inner, err := pkcs7.Parse(outer.Content)
	if err != nil {
		return nil, fmt.Errorf("the server's answer has no encrypted content: %w", err)
	}
	content, err := inner.Decrypt(recipient, key)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the server's answer: %w", err)
	}
	certs, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("the server's answer has no certificate: %w", err)
	}
	// Take the certificate asked for, in case the server sends its CA
	// certificates along.
	for _, cert := range certs.Certificates {
		if want(cert) {
			return cert, nil
		}
	}
	return nil, errors.New("the server's answer has no certificate for this key")
}

// failText turns SCEP's failure codes into words.
func failText(status, failInfo string) string {
	if status != statusFailure {
		return "status " + status
	}
	switch failInfo {
	case failBadAlgorithm:
		return "unsupported algorithm"
	case failBadMessageCheck:
		return "signature check failed"
	case failBadRequest:
		return "request not permitted or not understood"
	case failBadCertID:
		return "no such certificate"
	}
	return "failure " + failInfo
}

// selfSignedCert makes the throwaway certificate a request is signed with.
func selfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "SCEP request signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		// The server encrypts its answer for this certificate.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// do sends one SCEP request and returns the body and content type of
// the answer.
func (c *Client) do(ctx context.Context, method, operation string, body []byte) ([]byte, string, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+"?operation="+operation, reader)
	if err != nil {
		return nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-pki-message")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("cannot reach the SCEP server: %w", err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, "", fmt.Errorf("read the SCEP server's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("the SCEP server answered with status %s: %s", resp.Status, strings.TrimSpace(string(answer)))
	}
	return answer, resp.Header.Get("Content-Type"), nil
}
