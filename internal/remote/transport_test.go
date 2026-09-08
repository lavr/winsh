package remote

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransportRefusesUnauthenticatedHTTP(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/soap+xml")
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	transport := newTransport(Request{Endpoint: server.URL, User: "alice", Password: "test-secret"})
	_, err := transport.post(t.Context(), "<soap>private command</soap>")
	if err == nil {
		t.Fatal("accepted unauthenticated session")
	}
	if body != "" {
		t.Fatal("sent command before authentication")
	}
}

func TestTransportTLSAndTimeout(t *testing.T) {
	t.Run("untrusted certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("reached application before verifying TLS") }))
		defer server.Close()
		_, err := newTransport(Request{Endpoint: server.URL, User: "a", Password: "test-secret"}).post(t.Context(), "<soap/>")
		if err == nil || strings.Contains(err.Error(), "test-secret") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("deadline during authentication", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err := newTransport(Request{Endpoint: server.URL, User: "a", Password: "test-secret"}).post(ctx, "<soap/>")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no redirect", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect") }))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		_, err := newTransport(Request{Endpoint: server.URL, User: "a", Password: "test-secret"}).post(t.Context(), "<soap/>")
		if err == nil {
			t.Fatal("accepted redirect")
		}
	})
}

func TestDiscoveryMayCloseConnection(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Connection", "close")
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(401)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Negotiate ") {
			t.Error("missing type-1 token")
		}
		w.Header().Set("WWW-Authenticate", "Negotiate eA==")
		w.WriteHeader(401)
	}))
	defer server.Close()
	_, err := newTransport(Request{Endpoint: server.URL, User: "alice", Password: "test-secret"}).post(t.Context(), "<soap/>")
	if requests != 2 {
		t.Fatalf("requests=%d; expected discovery and type-1 on separate connections: %v", requests, err)
	}
	if err == nil || !strings.Contains(err.Error(), "type-2") {
		t.Fatalf("expected invalid type-2 fixture rejection: %v", err)
	}
}
