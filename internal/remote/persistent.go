package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bodgit/ntlmssp"
)

// Poster owns one authenticated connection and its serial NTLM sealing state.
// Calls must not be replayed after an uncertain SOAP exchange.
type Poster interface {
	Post(context.Context, string) (string, error)
}

type persistentPoster struct {
	mu        sync.Mutex
	endpoint  string
	client    *http.Client
	transport *http.Transport
	session   securitySession
	encrypted bool
	failed    bool      // guarded by mu
	lastUsed  time.Time // guarded by mu
	closed    atomic.Bool
	cancel    context.CancelFunc
	closedCtx context.Context
}

// NewPersistentPosters authenticates two independent HTTP/1.1 connections.
// The returned posters retain NTLM security sessions, but no Request or
// ntlmssp.Client containing a plaintext password.
func NewPersistentPosters(ctx context.Context, r Request) (command, cleanup Poster, closeBoth func(), err error) {
	first, err := openPersistentWithRetries(ctx, r)
	if err != nil {
		return nil, nil, nil, err
	}
	second, err := openPersistentWithRetries(ctx, r)
	if err != nil {
		first.Close()
		return nil, nil, nil, err
	}
	return first, second, func() { first.Close(); second.Close() }, nil
}

func openPersistentWithRetries(ctx context.Context, r Request) (*persistentPoster, error) {
	var p *persistentPoster
	_, err := withHandshakeRetries(ctx, func() (string, error) {
		var attemptErr error
		p, attemptErr = authenticateConnection(ctx, r)
		return "", attemptErr
	})
	return p, err
}

// errReplayRefused is returned instead of opening a second TCP connection for
// an authenticated lane. Dial failure means this request was never written.
var errReplayRefused = errors.New("NTLM connection closed; refusing to replay authentication or command")

func pinnedHTTPTransport(targetHost string) (*http.Transport, *atomic.Bool) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dialed := &atomic.Bool{}
	rt := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: targetHost},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 35 * time.Second,
		MaxConnsPerHost:       1,
		MaxIdleConnsPerHost:   1,
		DisableCompression:    true,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		// A WinRM endpoint must never inherit HTTP_PROXY.
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errReplayRefused
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	return rt, dialed
}

func sendHTTP(ctx context.Context, client *http.Client, endpoint, auth string, body []byte, contentType string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, errors.New("invalid endpoint")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "winsh")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(data) > maxResponse {
		return 0, nil, nil, errors.New("WinRM response exceeds 4 MiB")
	}
	return resp.StatusCode, resp.Header, data, nil
}

func authenticateConnection(ctx context.Context, r Request) (p *persistentPoster, err error) {
	var roots *x509.CertPool
	if strings.HasPrefix(r.Endpoint, "https://") {
		roots, err = configuredRootPool()
		if err != nil {
			return nil, err
		}
	}
	user, domain := splitUser(r.User)
	ntlm, err := ntlmssp.NewClient(ntlmssp.SetUserInfo(user, r.Password), ntlmssp.SetDomain(domain), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	if err != nil {
		return nil, errors.New("cannot initialize NTLM")
	}
	rt, dialed := pinnedHTTPTransport(r.TargetHost)
	rt.TLSClientConfig.RootCAs = roots
	defer func() {
		if err != nil {
			rt.CloseIdleConnections()
		}
	}()
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const soapType = "application/soap+xml;charset=UTF-8"
	status, headers, _, err := sendHTTP(ctx, client, r.Endpoint, "", nil, soapType)
	if err != nil {
		return nil, &handshakeTransportError{phase: "NTLM discovery", cause: err}
	}
	if status != http.StatusUnauthorized {
		return nil, fmt.Errorf("expected NTLM authentication challenge, got HTTP %d", status)
	}
	scheme, _, err := challenge(headers, "")
	if err != nil {
		return nil, err
	}
	// Discovery may use a socket the server closes. No security context
	// exists yet; type-1 starts on a fresh connection.
	rt.CloseIdleConnections()
	dialed.Store(false)
	token, err := ntlm.Authenticate(nil, nil)
	if err != nil {
		return nil, errors.New("cannot create NTLM negotiate message")
	}
	status, headers, _, err = sendHTTP(ctx, client, r.Endpoint, scheme+" "+base64.StdEncoding.EncodeToString(token), nil, soapType)
	if err != nil {
		return nil, &handshakeTransportError{phase: "NTLM negotiation", cause: err}
	}
	if status != http.StatusUnauthorized {
		return nil, fmt.Errorf("expected NTLM type-2 challenge, got HTTP %d", status)
	}
	_, input, err := challenge(headers, scheme)
	if err != nil {
		return nil, err
	}
	encrypted := strings.HasPrefix(r.Endpoint, "http://")
	if err := validateChallenge(input, encrypted); err != nil {
		return nil, err
	}
	token, err = ntlm.Authenticate(input, nil)
	if err != nil {
		return nil, errors.New("invalid NTLM challenge or credentials")
	}
	status, _, _, err = sendHTTP(ctx, client, r.Endpoint, scheme+" "+base64.StdEncoding.EncodeToString(token), nil, soapType)
	if err != nil {
		return nil, &handshakeTransportError{phase: "NTLM authentication", cause: err}
	}
	if status != http.StatusOK && status != http.StatusBadRequest {
		return nil, fmt.Errorf("NTLM authentication failed: HTTP %d", status)
	}
	if !ntlm.Complete() || ntlm.SecuritySession() == nil {
		return nil, errors.New("NTLM authentication did not establish a session")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &persistentPoster{endpoint: r.Endpoint, client: client, transport: rt, session: ntlm.SecuritySession(), encrypted: encrypted, cancel: cancel, closedCtx: lifetime, lastUsed: time.Now()}, nil
}

func (p *persistentPoster) Post(ctx context.Context, message string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.postLocked(ctx, message)
}

const identifyRequest = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>`

// KeepAlive sends an authenticated WS-Management Identify when the lane has
// been idle for at least idle, so the server does not close the connection
// that carries the NTLM session. A lane held by another exchange is in use and
// is skipped without waiting. Identify changes no remote state; any failure
// still marks the lane failed because its NTLM sequence is then uncertain.
func (p *persistentPoster) KeepAlive(ctx context.Context, idle time.Duration) error {
	if !p.mu.TryLock() {
		return nil
	}
	defer p.mu.Unlock()
	if p.closed.Load() || p.failed {
		return errors.New("NTLM connection is closed")
	}
	if time.Since(p.lastUsed) < idle {
		return nil
	}
	reply, err := p.postLocked(ctx, identifyRequest)
	if err != nil {
		return err
	}
	var envelope struct {
		Body struct {
			Response *struct{} `xml:"http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd IdentifyResponse"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	if xml.Unmarshal([]byte(reply), &envelope) != nil || envelope.Body.Response == nil {
		p.fail()
		return errors.New("invalid WS-Management identify response")
	}
	return nil
}

// postLocked is called only with mu held.
func (p *persistentPoster) postLocked(ctx context.Context, message string) (string, error) {
	if p.closed.Load() || p.failed {
		return "", unsent(errors.New("NTLM connection is closed"))
	}
	if err := ctx.Err(); err != nil {
		return "", unsent(err)
	}
	requestCtx := ctx
	var stop func() bool
	if p.closedCtx != nil {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithCancel(ctx)
		stop = context.AfterFunc(p.closedCtx, cancel)
		defer func() { stop(); cancel() }()
	}
	const soapType = "application/soap+xml;charset=UTF-8"
	payload, contentType := []byte(message), soapType
	var err error
	if p.encrypted {
		payload, contentType, err = sealMessage(p.session, payload)
		if err != nil {
			p.fail()
			return "", unsent(err)
		}
	}
	status, headers, data, err := sendHTTP(requestCtx, p.client, p.endpoint, "", payload, contentType)
	if err != nil {
		p.fail()
		err = fmt.Errorf("WinRM SOAP exchange: %w", err)
		if errors.Is(err, errReplayRefused) {
			return "", unsent(err)
		}
		return "", err
	}
	if status != http.StatusOK && status != http.StatusInternalServerError {
		p.fail()
		return "", fmt.Errorf("WinRM request failed: HTTP %d", status)
	}
	if p.encrypted {
		data, err = unsealMessage(p.session, data, headers.Get("Content-Type"))
		if err != nil {
			p.fail()
			return "", err
		}
	} else if !strings.HasPrefix(strings.ToLower(headers.Get("Content-Type")), "application/soap+xml") {
		p.fail()
		return "", errors.New("expected SOAP response")
	}
	var envelope struct {
		XMLName xml.Name  `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
		Body    *struct{} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	if xml.Unmarshal(data, &envelope) != nil || envelope.Body == nil {
		p.fail()
		return "", errors.New("invalid SOAP response")
	}
	p.lastUsed = time.Now()
	return string(data), nil
}

// fail is called only with mu held. An authenticated lane cannot recover its
// NTLM sequence after an uncertain request or invalid response.
func (p *persistentPoster) fail() {
	p.failed = true
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

func (p *persistentPoster) Close() {
	if !p.closed.Swap(true) {
		if p.cancel != nil {
			p.cancel()
		}
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
	}
}
