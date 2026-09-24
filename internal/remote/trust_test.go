package remote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func unrelatedTestCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "unrelated.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestConfiguredRootPool(t *testing.T) {
	t.Setenv("SSL_CERT_DIR", "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	writeCert := func(name string, cert []byte) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv("SSL_CERT_FILE", writeCert("good.pem", server.TLS.Certificates[0].Certificate[0]))
	roots, err := configuredRootPool()
	if err != nil || roots == nil {
		t.Fatalf("configured CA unavailable: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("configured CA rejected: %v", err)
	}
	response.Body.Close()
	t.Setenv("SSL_CERT_FILE", writeCert("wrong.pem", unrelatedTestCertificate(t)))
	roots, err = configuredRootPool()
	if err != nil || roots == nil {
		t.Fatalf("wrong CA fixture load failed: %v", err)
	}
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("server accepted with wrong CA")
	}
	t.Setenv("SSL_CERT_FILE", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_DIR", dir)
	roots, err = configuredRootPool()
	if err != nil || roots == nil {
		t.Fatalf("configured CA directory unavailable: %v", err)
	}
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	response, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("configured CA directory rejected: %v", err)
	}
	response.Body.Close()
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "missing.pem"))
	if _, err := configuredRootPool(); err == nil {
		t.Fatal("missing configured CA source was ignored")
	}
}
