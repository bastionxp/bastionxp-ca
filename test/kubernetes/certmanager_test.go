// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubernetes tests BastionXP CA with cert-manager in a real
// Kubernetes cluster, made with kind (Kubernetes in Docker). It is slow and
// needs Docker, so it runs only on request: make test-cert-manager.
package kubernetes

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The versions tested. kind's version fixes the Kubernetes version: kind
// v0.33.0 runs Kubernetes v1.37.0.
const (
	certManagerVersion = "v1.21.3"
	// bindImage is the DNS server. Its Ubuntu base also copies the CA's
	// data into place (the CA's image has no shell), so the test needs no
	// other image.
	bindImage = "internetsystemsconsortium/bind9:9.20"
)

const (
	// caImage is built from this repository and loaded into the cluster.
	caImage = "bastionxp-ca:cert-manager-test"
	// caURL is the CA's address inside the cluster: its Service.
	caURL = "https://bastionxp-ca.bastionxp-ca.svc:8443"
	// dnsIP is the fixed address of the DNS server for e2e.test, inside
	// the cluster's Service range.
	dnsIP = "10.96.0.53"
)

// cert-manager in a Kubernetes cluster gets certificates from BastionXP CA,
// running in the same cluster from its container image, through a
// ClusterIssuer with the CA's root as caBundle and dns-01 answered over
// RFC 2136 by a DNS server: a certificate, a wildcard, and a new
// certificate when the Certificate's names change, each verified with
// openssl; a name outside the CA's allowed domains is refused, and the
// order says why.
func TestCertManager(t *testing.T) {
	c := startKind(t)
	work := t.TempDir()

	t.Log("building the container image and loading it into the cluster")
	run(t, "", "docker", "build", "-t", caImage, "../..")
	run(t, "", c.kind, "load", "docker-image", caImage, "--name", c.name)

	t.Log("starting the DNS server for e2e.test")
	tsig := make([]byte, 32)
	rand.Read(tsig)
	tsigSecret := base64.StdEncoding.EncodeToString(tsig)
	c.apply(t, dnsServer(tsigSecret))
	c.kubectl(t, "", "-n", "dns", "rollout", "status", "deployment/dns", "--timeout=3m")

	t.Log("creating the CA with bxp init and starting it in the cluster")
	rootFile, intermediateFile := c.startCA(t, work)

	t.Log("installing cert-manager " + certManagerVersion)
	c.kubectl(t, "", "apply", "-f",
		"https://github.com/cert-manager/cert-manager/releases/download/"+certManagerVersion+"/cert-manager.yaml")
	// The names are in a private zone: cert-manager must check its TXT
	// records with that zone's DNS server, not the cluster's.
	c.kubectl(t, "", "-n", "cert-manager", "patch", "deployment", "cert-manager", "--type", "json", "-p",
		`[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--dns01-recursive-nameservers-only=true"},`+
			`{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--dns01-recursive-nameservers=`+dnsIP+`:53"}]`)
	for _, d := range []string{"cert-manager", "cert-manager-webhook", "cert-manager-cainjector"} {
		c.kubectl(t, "", "-n", "cert-manager", "rollout", "status", "deployment/"+d, "--timeout=3m")
	}

	t.Log("creating the ClusterIssuer")
	root := readFile(t, rootFile)
	issuer := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: rfc2136-tsig
  namespace: cert-manager
stringData:
  secret: %s
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: bastionxp-ca
spec:
  acme:
    server: %s/acme/directory
    caBundle: %s
    privateKeySecretRef:
      name: bastionxp-ca-acme-account
    solvers:
      - dns01:
          rfc2136:
            nameserver: %s:53
            tsigKeyName: cert-manager
            tsigAlgorithm: HMACSHA256
            tsigSecretSecretRef:
              name: rfc2136-tsig
              key: secret
`, tsigSecret, caURL, base64.StdEncoding.EncodeToString(root), dnsIP)
	// The webhook may refuse resources for a while after it is ready.
	eventually(t, 2*time.Minute, "the ClusterIssuer is accepted", func() error {
		_, err := c.try(issuer, "apply", "-f", "-")
		return err
	})
	c.kubectl(t, "", "wait", "--for=condition=Ready", "clusterissuer/bastionxp-ca", "--timeout=2m")

	c.apply(t, certificate("web", "web.e2e.test")+"---\n"+
		certificate("wildcard", "*.apps.e2e.test")+"---\n"+
		certificate("refused", "web.other.test"))

	verify := func(t *testing.T, secret, name string) *x509.Certificate {
		t.Helper()
		chain := c.secretCerts(t, secret)
		file := filepath.Join(t.TempDir(), "chain.pem")
		var pemData bytes.Buffer
		for _, cert := range chain {
			pem.Encode(&pemData, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
		writeFile(t, file, pemData.String())
		leaf := filepath.Join(t.TempDir(), "leaf.pem")
		writeFile(t, leaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw})))
		out := run(t, "", "openssl", "verify", "-CAfile", rootFile, "-untrusted", intermediateFile, "-purpose", "sslserver", leaf)
		if !strings.Contains(out, ": OK") {
			t.Fatalf("openssl verify: %s", out)
		}
		if err := chain[0].VerifyHostname(name); err != nil {
			t.Fatalf("%s: %v", secret, err)
		}
		return chain[0]
	}

	t.Run("certificate", func(t *testing.T) {
		c.kubectl(t, "", "wait", "--for=condition=Ready", "certificate/web", "--timeout=3m")
		verify(t, "web-tls", "web.e2e.test")
	})

	t.Run("wildcard", func(t *testing.T) {
		c.kubectl(t, "", "wait", "--for=condition=Ready", "certificate/wildcard", "--timeout=3m")
		verify(t, "wildcard-tls", "anything.apps.e2e.test")
	})

	t.Run("new names, new certificate", func(t *testing.T) {
		before := c.secretCerts(t, "web-tls")[0]
		c.kubectl(t, "", "patch", "certificate", "web", "--type", "merge", "-p",
			`{"spec":{"dnsNames":["web.e2e.test","www.e2e.test"]}}`)
		eventually(t, 3*time.Minute, "cert-manager stores a certificate with both names", func() error {
			cert := c.secretCerts(t, "web-tls")[0]
			if cert.SerialNumber.Cmp(before.SerialNumber) == 0 || !slices.Contains(cert.DNSNames, "www.e2e.test") {
				return fmt.Errorf("still serial %x, names %v", cert.SerialNumber, cert.DNSNames)
			}
			return nil
		})
		verify(t, "web-tls", "www.e2e.test")
	})

	t.Run("name outside the allowed domains", func(t *testing.T) {
		eventually(t, 3*time.Minute, "the order for web.other.test fails with the CA's reason", func() error {
			orders := c.kubectl(t, "", "get", "orders", "-o",
				`jsonpath={range .items[*]}{.spec.dnsNames}{"\t"}{.status.state}{"\t"}{.status.reason}{"\n"}{end}`)
			for _, line := range strings.Split(orders, "\n") {
				if strings.Contains(line, "web.other.test") && strings.Contains(line, "\terrored\t") &&
					strings.Contains(line, "rejectedIdentifier") {
					return nil
				}
			}
			return fmt.Errorf("orders:\n%s", orders)
		})
		if _, err := c.try("", "get", "secret", "refused-tls"); err == nil {
			t.Error("a certificate was stored for a refused name")
		}
	})

	t.Run("the CA's view", func(t *testing.T) {
		orders := c.kubectl(t, "", "-n", "bastionxp-ca", "exec", "deployment/bastionxp-ca", "--",
			"bxp", "list", "acme-orders", "--config", "/etc/bastionxp-ca/bastionxp-ca.yaml")
		for _, want := range []string{"web.e2e.test  valid  dns-01", "*.apps.e2e.test  valid  dns-01"} {
			if !strings.Contains(orders, want) {
				t.Errorf("bxp list acme-orders lacks %q:\n%s", want, orders)
			}
		}
	})
}

// cluster is a kind cluster. kubectl runs inside its node, which has it:
// nothing needs to be installed but Docker and kind.
type cluster struct {
	kind, name, node string
}

// startKind creates a kind cluster for the test and deletes it afterwards.
// The test is skipped unless BXP_TEST_CERT_MANAGER is set.
func startKind(t *testing.T) *cluster {
	t.Helper()
	if os.Getenv("BXP_TEST_CERT_MANAGER") == "" {
		t.Skip("set BXP_TEST_CERT_MANAGER=1 to test with cert-manager in a kind cluster (needs Docker)")
	}
	kind := "kind"
	if dir := os.Getenv("BXP_E2E_TOOLS"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, "bin", "kind")); err == nil {
			kind = filepath.Join(dir, "bin", "kind")
		}
	}
	for _, tool := range []string{kind, "docker", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is needed: %v (make test-cert-manager installs kind)", tool, err)
		}
	}
	c := &cluster{kind: kind, name: fmt.Sprintf("bxp-cert-manager-%d", os.Getpid())}
	c.node = c.name + "-control-plane"
	t.Log("creating the kind cluster " + c.name)
	// Its own kubeconfig, so the user's ~/.kube/config is left alone.
	run(t, "", kind, "create", "cluster", "--name", c.name,
		"--kubeconfig", filepath.Join(t.TempDir(), "kubeconfig"), "--wait", "3m")
	t.Cleanup(func() {
		if t.Failed() {
			for _, args := range [][]string{
				{"get", "pods", "-A"},
				{"describe", "pods", "-n", "bastionxp-ca"},
				{"describe", "pods", "-n", "dns"},
				{"describe", "pods", "-n", "cert-manager"},
				{"get", "certificates,certificaterequests,orders,challenges", "-A", "-o", "wide"},
				{"describe", "challenges", "-A"},
				{"-n", "cert-manager", "logs", "deployment/cert-manager", "--tail", "80"},
				{"-n", "bastionxp-ca", "logs", "deployment/bastionxp-ca", "--tail", "80"},
				{"-n", "dns", "logs", "deployment/dns", "--tail", "40"},
			} {
				out, _ := c.try("", args...)
				t.Logf("kubectl %s:\n%s", strings.Join(args, " "), out)
			}
		}
		exec.Command(kind, "delete", "cluster", "--name", c.name).Run()
	})
	return c
}

// try runs kubectl in the cluster's node with stdin, and returns its
// standard output, or an error with all it printed.
func (c *cluster) try(stdin string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", "-i", c.node,
		"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf"}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %s: %v\n%s%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

// kubectl is try for a command that must succeed.
func (c *cluster) kubectl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := c.try(stdin, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// apply creates or updates the resources in a YAML document.
func (c *cluster) apply(t *testing.T, yaml string) {
	t.Helper()
	c.kubectl(t, yaml, "apply", "-f", "-")
}

// secretCerts returns the certificates cert-manager stored in a TLS Secret
// in the default namespace, leaf first.
func (c *cluster) secretCerts(t *testing.T, secret string) []*x509.Certificate {
	t.Helper()
	encoded := c.kubectl(t, "", "get", "secret", secret, "-o", `jsonpath={.data.tls\.crt}`)
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		t.Fatalf("secret %s: %v", secret, err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("secret %s: %v", secret, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatalf("secret %s holds no certificate", secret)
	}
	return certs
}

// startCA creates a CA with the real bxp init on this machine, and runs it
// in the cluster from the container image, with its data directory copied
// from a Secret into the pod. The root key stays here, as it would stay
// offline. It returns the root and intermediate certificates' files.
func (c *cluster) startCA(t *testing.T, work string) (root, intermediate string) {
	t.Helper()
	bxp := filepath.Join(work, "bxp")
	run(t, "", "go", "build", "-o", bxp, "github.com/bastionxp/bastionxp-ca/cmd/bxp")
	configYAML := `ca:
  organization: Kubernetes Test
server:
  address: ":8443"
  url: ` + caURL + `
  names: [bastionxp-ca.bastionxp-ca.svc, bastionxp-ca.bastionxp-ca.svc.cluster.local]
acme:
  allowed_domains: [e2e.test]
  dns_resolver: ` + dnsIP + `:53
`
	dataDir := filepath.Join(work, "data")
	hostConfig := filepath.Join(work, "bastionxp-ca.yaml")
	writeFile(t, hostConfig, "data_dir: "+dataDir+"\n"+configYAML)
	passphrase := filepath.Join(work, "root-passphrase")
	writeFile(t, passphrase, "a root passphrase for the cert-manager test\n")
	run(t, "", bxp, "init", "--config", hostConfig, "--root-passphrase-file", passphrase)

	var files strings.Builder
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "root.key" {
			continue
		}
		fmt.Fprintf(&files, "  %s: %s\n", e.Name(), base64.StdEncoding.EncodeToString(readFile(t, filepath.Join(dataDir, e.Name()))))
	}

	c.apply(t, caManifest(files.String(), configYAML))
	c.kubectl(t, "", "-n", "bastionxp-ca", "rollout", "status", "deployment/bastionxp-ca", "--timeout=3m")
	return filepath.Join(dataDir, "root.crt"), filepath.Join(dataDir, "intermediate.crt")
}

// caManifest is the CA in the cluster: its namespace, the data directory as
// a Secret (files: the Secret's data lines), the configuration, and a
// Deployment whose first container copies the data into a writable
// directory for the server, which runs as the image's non-root user.
func caManifest(files, configYAML string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: bastionxp-ca
---
apiVersion: v1
kind: Secret
metadata:
  name: bastionxp-ca-data
  namespace: bastionxp-ca
data:
%s---
apiVersion: v1
kind: ConfigMap
metadata:
  name: bastionxp-ca-config
  namespace: bastionxp-ca
data:
  bastionxp-ca.yaml: |
    data_dir: /var/lib/bastionxp-ca
%s---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bastionxp-ca
  namespace: bastionxp-ca
spec:
  replicas: 1
  selector:
    matchLabels: {app: bastionxp-ca}
  template:
    metadata:
      labels: {app: bastionxp-ca}
    spec:
      initContainers:
        - name: data
          image: %s
          command: [sh, -c, "cp /init/* /data/ && chmod 600 /data/*.key && chown -R 65532:65532 /data && chmod 700 /data"]
          volumeMounts:
            - {name: init, mountPath: /init}
            - {name: data, mountPath: /data}
      containers:
        - name: ca
          image: %s
          imagePullPolicy: Never
          args: [serve, --config, /etc/bastionxp-ca/bastionxp-ca.yaml]
          ports:
            - containerPort: 8443
          readinessProbe:
            httpGet: {path: /health, port: 8443, scheme: HTTPS}
          volumeMounts:
            - {name: config, mountPath: /etc/bastionxp-ca}
            - {name: data, mountPath: /var/lib/bastionxp-ca}
      volumes:
        - name: init
          secret: {secretName: bastionxp-ca-data}
        - name: config
          configMap: {name: bastionxp-ca-config}
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: bastionxp-ca
  namespace: bastionxp-ca
spec:
  selector: {app: bastionxp-ca}
  ports:
    - port: 8443
`, files, indent(configYAML, "    "), bindImage, caImage)
}

// dnsServer is BIND, authoritative for e2e.test at dnsIP, taking updates
// signed with the TSIG key: cert-manager writes the dns-01 TXT records
// there over RFC 2136, and the CA (acme.dns_resolver) reads them.
func dnsServer(tsigSecret string) string {
	namedConf := `key "cert-manager" {
	algorithm hmac-sha256;
	secret "` + tsigSecret + `";
};
options {
	directory "/var/cache/bind";
	pid-file none;
	listen-on { any; };
	listen-on-v6 { none; };
	allow-query { any; };
	recursion no;
	dnssec-validation no;
};
zone "e2e.test" {
	type primary;
	file "/zones/e2e.test.zone";
	update-policy { grant cert-manager zonesub TXT; };
};
`
	zone := `$TTL 60
@	IN SOA ns.e2e.test. hostmaster.e2e.test. 1 60 60 3600 60
@	IN NS ns.e2e.test.
ns	IN A ` + dnsIP + `
`
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: dns
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: dns-config
  namespace: dns
data:
  named.conf: |
%s  e2e.test.zone: |
%s---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dns
  namespace: dns
spec:
  replicas: 1
  selector:
    matchLabels: {app: dns}
  template:
    metadata:
      labels: {app: dns}
    spec:
      initContainers:
        # The zone must be writable: updates go into it.
        - name: zone
          image: %[3]s
          command: [sh, -c, "cp /config/e2e.test.zone /zones/ && chown -R bind:bind /zones"]
          volumeMounts:
            - {name: config, mountPath: /config}
            - {name: zones, mountPath: /zones}
      containers:
        - name: named
          image: %[3]s
          command: [/usr/sbin/named, -g, -u, bind, -c, /config/named.conf]
          readinessProbe:
            tcpSocket: {port: 53}
          volumeMounts:
            - {name: config, mountPath: /config}
            - {name: zones, mountPath: /zones}
      volumes:
        - name: config
          configMap: {name: dns-config}
        - name: zones
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: dns
  namespace: dns
spec:
  clusterIP: %[4]s
  selector: {app: dns}
  ports:
    - {name: dns-udp, port: 53, protocol: UDP}
    - {name: dns-tcp, port: 53, protocol: TCP}
`, indent(namedConf, "    "), indent(zone, "    "), bindImage, dnsIP)
}

// certificate is a cert-manager Certificate in the default namespace,
// from the BastionXP CA ClusterIssuer, stored in the Secret <name>-tls.
func certificate(name string, dnsNames ...string) string {
	return fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %s
  namespace: default
spec:
  secretName: %s-tls
  dnsNames: ["%s"]
  issuerRef:
    kind: ClusterIssuer
    name: bastionxp-ca
`, name, name, strings.Join(dnsNames, `", "`))
}

// eventually calls check until it succeeds, and fails the test with its
// last error after the timeout.
func eventually(t *testing.T, timeout time.Duration, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s: %v", what, timeout, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// run runs a program, fails the test if it fails, and returns its
// standard output.
func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s%s", filepath.Base(name), strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// indent puts prefix before every line of text.
func indent(text, prefix string) string {
	lines := strings.SplitAfter(text, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "")
}
