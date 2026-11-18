// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

const staticChallenge = "e2e-shared-scep-challenge"

// staticSCEPCA is a CA with SCEP's shared challenge, for names below
// devices.e2e.localhost, with at most maxPerHour enrollments.
func staticSCEPCA(t *testing.T, maxPerHour int) *testCA {
	t.Helper()
	challengeFile := filepath.Join(t.TempDir(), "scep-challenge")
	writeFile(t, challengeFile, staticChallenge+"\n")
	c := newCA(t, fmt.Sprintf(`scep:
  enabled: true
  static:
    challenge_file: %s
    dns_domains: [devices.e2e.localhost]
    max_per_hour: %d
`, challengeFile, maxPerHour))
	c.start()
	return c
}

// enrollWithScepclient enrolls name with micromdm's scepclient and the
// challenge, and returns whether it got a certificate, and its file.
func enrollWithScepclient(t *testing.T, c *testCA, proxy, challenge, name string) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "device.pem")
	r := run(t, dir, nil, tool(t, "scepclient"),
		"-server-url", proxy+"/scep", "-challenge", challenge,
		"-cn", name, "-dnsname", name,
		"-private-key", filepath.Join(dir, "device.key"), "-certificate", pemFile,
		"-key-encipherment-selector")
	if r.code != 0 {
		return false, ""
	}
	return fileExists(pemFile), pemFile
}

// The shared challenge, as device management systems use it: devices in
// the allowed domain enroll; another domain, or a wrong challenge, do not.
func TestSCEPStaticChallenge(t *testing.T) {
	c := staticSCEPCA(t, 100)
	proxy := scepProxy(t, c)

	ok, pemFile := enrollWithScepclient(t, c, proxy, staticChallenge, "d1.devices.e2e.localhost")
	if !ok {
		t.Fatal("enrollment with the shared challenge failed")
	}
	c.verifyWithOpenSSLFor("sslclient", pemFile, "d1.devices.e2e.localhost")

	if ok, _ := enrollWithScepclient(t, c, proxy, staticChallenge, "laptop.other.e2e.localhost"); ok {
		t.Error("a name outside scep.static.dns_domains was enrolled")
	}
	c.waitForLog("verifier=scep_static") // refused for its name, not for something else
	if ok, _ := enrollWithScepclient(t, c, proxy, "not-the-challenge-at-all", "d2.devices.e2e.localhost"); ok {
		t.Error("a wrong challenge was accepted")
	}
}

// scep.static.max_per_hour stops enrollments with the shared challenge.
func TestSCEPStaticLimit(t *testing.T) {
	c := staticSCEPCA(t, 2)
	proxy := scepProxy(t, c)
	for i := 1; i <= 2; i++ {
		if ok, _ := enrollWithScepclient(t, c, proxy, staticChallenge, fmt.Sprintf("d%d.devices.e2e.localhost", i)); !ok {
			t.Fatalf("enrollment %d of 2 failed", i)
		}
	}
	if ok, _ := enrollWithScepclient(t, c, proxy, staticChallenge, "d3.devices.e2e.localhost"); ok {
		t.Error("a third enrollment went through with max_per_hour: 2")
	}
	c.waitForLog("too many enrollments with the static challenge this hour")
}

// "bxp scep getcert" fetches a certificate again, by serial number, with
// its key: exactly the one issued.
func TestSCEPGetCert(t *testing.T) {
	c := newCA(t, scepConfig)
	c.start()
	const name = "device.e2e.localhost"
	out := t.TempDir()
	c.client("scep", "enroll", "--ca-url", c.url, "--root", c.root,
		"--token", c.token("tls-device", name), "--out-dir", out)
	certFile, keyFile := filepath.Join(out, name+".crt"), filepath.Join(out, name+".key")
	issued := readCerts(t, certFile)[0]

	fetched := filepath.Join(t.TempDir(), "fetched.crt")
	c.client("scep", "getcert", "--ca-url", c.url, "--root", c.root,
		"--serial", issued.SerialNumber.Text(16), "--key", keyFile, "--out", fetched)
	if !bytes.Equal(readCerts(t, fetched)[0].Raw, issued.Raw) {
		t.Error("getcert returned another certificate")
	}
}
