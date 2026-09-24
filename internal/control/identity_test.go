package control

import (
	"strings"
	"testing"
)

func TestControlIdentityKey(t *testing.T) {
	base := Identity{Endpoint: "https://SERVER.example.com/wsman", User: `EXAMPLE\alice`, TargetHost: "server.example.com", TrustKey: "trust-a"}
	if base.Key() != (Identity{Endpoint: "https://server.example.com:5986/wsman", User: `EXAMPLE\alice`, TargetHost: "SERVER.EXAMPLE.COM", TrustKey: "trust-a"}).Key() {
		t.Fatal("equivalent endpoint identities diverged")
	}
	for _, changed := range []Identity{
		{Endpoint: base.Endpoint, User: `EXAMPLE\bob`, TargetHost: base.TargetHost, TrustKey: base.TrustKey},
		{Endpoint: base.Endpoint, User: base.User, TargetHost: "other.example.com", TrustKey: base.TrustKey},
		{Endpoint: base.Endpoint, User: base.User, TargetHost: base.TargetHost, TrustKey: "trust-b"},
	} {
		if changed.Key() == base.Key() {
			t.Fatal("different target selected the same master")
		}
	}
	if len(base.Key()) > 80 || strings.Contains(base.Key(), "alice") || strings.Contains(base.Key(), "server") {
		t.Fatalf("socket key exposed identity or exceeded bounded size: %q", base.Key())
	}
}

func TestControlTrustKey(t *testing.T) {
	env := map[string]string{"SSL_CERT_FILE": "/tmp/ca-a.pem", "SSL_CERT_DIR": "/tmp/ca-dir", "GODEBUG": "asyncpreemptoff=1,x509sha1=1"}
	get := func(k string) string { return env[k] }
	initial := TrustKey(get)
	env["GODEBUG"] = "x509sha1=1,asyncpreemptoff=0"
	if TrustKey(get) != initial {
		t.Fatal("irrelevant GODEBUG changed trust identity")
	}
	env["GODEBUG"] = "x509sha1=0"
	if TrustKey(get) == initial {
		t.Fatal("x509 GODEBUG omitted from trust identity")
	}
	env["GODEBUG"] = "x509sha1=0,x509sha1=1"
	if TrustKey(get) != initial {
		t.Fatal("trust identity ignored the last effective x509 setting")
	}
	env["SSL_CERT_FILE"] = "/tmp/ca-b.pem"
	if TrustKey(get) == initial {
		t.Fatal("CA file omitted from trust identity")
	}
}

func TestRelativeCAPathsSelectDifferentMastersAcrossWorkingDirectories(t *testing.T) {
	firstDir := t.TempDir()
	secondDir := t.TempDir()
	get := func(name string) string {
		switch name {
		case "SSL_CERT_FILE":
			return "ca.pem"
		case "SSL_CERT_DIR":
			return "roots:more-roots"
		}
		return ""
	}
	t.Chdir(firstDir)
	first := TrustKey(get)
	t.Chdir(secondDir)
	if first == TrustKey(get) {
		t.Fatal("different effective CA paths selected the same master")
	}
}
