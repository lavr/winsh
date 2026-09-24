package remote

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistentPyspnegoInterop(t *testing.T) {
	if os.Getenv("WINSH_TEST_PYSPNEGO") != "1" {
		t.Skip("set WINSH_TEST_PYSPNEGO=1 after installing pyspnego")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	endpoint := startPyspnegoFixture(t, ctx)
	command, cleanup, closeBoth, err := NewPersistentPosters(ctx, Request{Endpoint: endpoint, User: `EXAMPLE\alice`, Password: "test-secret"})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	defer closeBoth()
	const soap = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`
	for _, poster := range []Poster{command, command, cleanup} {
		got, err := poster.Post(ctx, soap)
		if err != nil || got != soap {
			t.Fatalf("sealed SOAP = %q, %v", got, err)
		}
	}
	calls := pyspnegoStats(t, ctx, endpoint)
	if len(calls) != 2 || calls[0] != 1 || calls[1] != 2 {
		t.Fatalf("expected two authenticated connections with 1 and 2 SOAP calls; got %v", calls)
	}
}

func startPyspnegoFixture(t *testing.T, ctx context.Context) string {
	t.Helper()
	processCtx, processCancel := context.WithTimeout(context.Background(), 10*time.Second)
	process := exec.CommandContext(processCtx, "python3", "../../scripts/ntlm-persistent-fixture.py")
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := process.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	process.Stderr = &stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if err := process.Wait(); err != nil {
			t.Errorf("pyspnego fixture: %v: %s", err, stderr.String())
		}
		processCancel()
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var endpoint string
	select {
	case endpoint = <-ready:
	case <-ctx.Done():
		t.Fatal("pyspnego fixture did not start")
	}
	if endpoint == "" {
		t.Fatalf("pyspnego fixture exited before ready: %s", stderr.String())
	}
	return endpoint
}

func pyspnegoStats(t *testing.T, ctx context.Context, endpoint string) []int {
	t.Helper()
	statsURL := endpoint[:len(endpoint)-len("/wsman")] + "/stats"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, statsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: &http.Transport{}}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var calls []int
	if err := json.NewDecoder(response.Body).Decode(&calls); err != nil {
		t.Fatal(err)
	}
	return calls
}

func TestPersistentRefusesUnauthenticatedSOAP(t *testing.T) {
	var bodies atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			bodies.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, _, _, err := NewPersistentPosters(t.Context(), Request{Endpoint: server.URL, User: "alice", Password: "test-secret"})
	if err == nil || bodies.Load() != 0 {
		t.Fatalf("unauthenticated connection accepted: err=%v bodies=%d", err, bodies.Load())
	}
}

func TestPersistentPosterReusesOneConnection(t *testing.T) {
	const validSOAP = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`
	var requests atomic.Int32
	addresses := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := requests.Add(1)
		addresses <- r.RemoteAddr
		body, _ := io.ReadAll(r.Body)
		plain, err := unsealMessage(testSession{}, body, r.Header.Get("Content-Type"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if call == 1 && string(plain) != "one" || call == 2 && string(plain) != "two" {
			t.Errorf("unexpected SOAP request %d: %q", call, plain)
		}
		response, ct, err := sealMessage(testSession{}, []byte(validSOAP))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(response)
	}))
	defer server.Close()
	var dials atomic.Int32
	rt := &http.Transport{MaxConnsPerHost: 1, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials.Add(1) != 1 {
			return nil, errors.New("redial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	for _, message := range []string{"one", "two"} {
		got, err := p.Post(t.Context(), message)
		if err != nil || got != validSOAP {
			t.Fatalf("post %q = %q, %v", message, got, err)
		}
	}
	if dials.Load() != 1 || requests.Load() != 2 || <-addresses != <-addresses {
		t.Fatalf("not one pinned connection: dials=%d requests=%d", dials.Load(), requests.Load())
	}
	p.Close()
	if _, err := p.Post(t.Context(), "three"); err == nil || requests.Load() != 2 {
		t.Fatalf("closed poster reused: err=%v requests=%d", err, requests.Load())
	}
}

func TestPersistentPosterInvalidResponseIsTerminal(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = io.WriteString(w, "<soap/>")
	}))
	defer server.Close()
	rt := &http.Transport{}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	for i := 0; i < 2; i++ {
		if _, err := p.Post(t.Context(), "<soap/>"); err == nil {
			t.Fatal("accepted invalid encrypted response")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("terminal lane sent %d requests", requests.Load())
	}
}

func TestPersistentPosterFailedSealIsTerminal(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	rt := &http.Transport{}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{fail: true}}
	defer p.Close()
	if _, err := p.Post(t.Context(), "<soap/>"); err == nil {
		t.Fatal("accepted failed sealing")
	}
	p.session = testSession{}
	if _, err := p.Post(t.Context(), "<soap/>"); err == nil || requests.Load() != 0 {
		t.Fatalf("failed seal did not close lane: err=%v requests=%d", err, requests.Load())
	}
}

func TestPersistentPosterInvalidSOAPIsTerminal(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		frame, contentType, err := sealMessage(testSession{}, []byte("<not-soap/>"))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(frame)
	}))
	defer server.Close()
	rt := &http.Transport{}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	for i := 0; i < 2; i++ {
		if _, err := p.Post(t.Context(), "<soap/>"); err == nil {
			t.Fatal("accepted response without SOAP envelope")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("invalid SOAP led to %d requests", requests.Load())
	}
}

func TestPersistentPosterOperationTimeoutAllowsAnotherPoll(t *testing.T) {
	const timeoutSOAP = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"><s:Header><a:Action>fault</a:Action></s:Header><s:Body><s:Fault><s:Detail><f:WSManFault Code="2150858793"/></s:Detail></s:Fault></s:Body></s:Envelope>`
	const outputSOAP = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"><s:Header><a:Action>receive</a:Action></s:Header><s:Body/></s:Envelope>`
	var requests atomic.Int32
	addresses := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := requests.Add(1)
		addresses <- r.RemoteAddr
		plain := outputSOAP
		if call == 1 {
			plain = timeoutSOAP
		}
		frame, contentType, err := sealMessage(testSession{}, []byte(plain))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if call == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write(frame)
	}))
	defer server.Close()
	rt := &http.Transport{MaxConnsPerHost: 1}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	for _, want := range []string{timeoutSOAP, outputSOAP} {
		got, err := p.Post(t.Context(), "<soap/>")
		if err != nil || got != want {
			t.Fatalf("poll = %q, %v", got, err)
		}
	}
	if requests.Load() != 2 || <-addresses != <-addresses {
		t.Fatalf("polling did not keep one connection: %d requests", requests.Load())
	}
}

func TestPersistentPosterNeverRedialsAfterAcknowledgedSOAP(t *testing.T) {
	const soap = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		frame, contentType, err := sealMessage(testSession{}, []byte(soap))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Connection", "close")
		_, _ = w.Write(frame)
	}))
	defer server.Close()
	rt, _ := pinnedHTTPTransport("")
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	if got, err := p.Post(t.Context(), soap); err != nil || got != soap {
		t.Fatalf("first SOAP = %q, %v", got, err)
	}
	if _, err := p.Post(t.Context(), soap); err == nil {
		t.Fatal("silently redialed after acknowledged SOAP")
	}
	if requests.Load() != 1 {
		t.Fatalf("redial sent a second SOAP request: %d", requests.Load())
	}
}

func TestPersistentPosterLostResponseNeverReplaysSOAP(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()
	rt, _ := pinnedHTTPTransport("")
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	for i := 0; i < 2; i++ {
		if _, err := p.Post(t.Context(), "<soap/>"); err == nil {
			t.Fatal("lost SOAP response accepted or replayed")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("uncertain SOAP executed %d times", requests.Load())
	}
}

func TestPersistentPosterCancelIsTerminal(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	}))
	defer server.Close()
	defer close(release)
	rt := &http.Transport{}
	p := &persistentPoster{endpoint: server.URL, client: &http.Client{Transport: rt}, transport: rt, encrypted: true, session: testSession{}}
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := p.Post(ctx, "<soap/>"); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock request")
	}
	if _, err := p.Post(t.Context(), "again"); err == nil {
		t.Fatal("canceled lane accepted another request")
	}
}
