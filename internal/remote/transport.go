package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bodgit/ntlmssp"
)

type transport struct{ request Request }

func newTransport(r Request) *transport { return &transport{request: r} }

// Each SOAP exchange has its own authenticated TCP connection. This prevents
// receive polling and cancellation from sharing NTLM sequence numbers, and
// avoids replaying a sealed message after a connection has been replaced.
func (t *transport) post(ctx context.Context, message string) (string, error) {
	user, domain := splitUser(t.request.User)
	ntlm, err := ntlmssp.NewClient(ntlmssp.SetUserInfo(user, t.request.Password), ntlmssp.SetDomain(domain), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	if err != nil {
		return "", errors.New("cannot initialize NTLM")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var dialed atomic.Bool
	rt := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.request.TargetHost},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 35 * time.Second,
		MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableCompression: true,
		// Direct connections only: a WinRM endpoint must not inherit HTTP_PROXY.
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("NTLM connection closed; refusing to replay authentication or command")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer rt.CloseIdleConnections()
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(auth string, body []byte, ct string) (int, http.Header, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.request.Endpoint, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, errors.New("invalid endpoint")
		}
		req.Header.Set("Content-Type", ct)
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
	const soapType = "application/soap+xml;charset=UTF-8"
	status, headers, _, err := send("", nil, soapType)
	if err != nil {
		return "", err
	}
	if status != 401 {
		return "", fmt.Errorf("expected NTLM authentication challenge, got HTTP %d", status)
	}
	scheme, _, err := challenge(headers, "")
	if err != nil {
		return "", err
	}
	// HTTP.sys commonly closes the unauthenticated discovery connection (401).
	// No NTLM session exists yet. Start type-1 on a fresh connection, then keep
	// the no-redial rule for type-2/type-3 and sealed SOAP unchanged.
	rt.CloseIdleConnections()
	dialed.Store(false)
	token, err := ntlm.Authenticate(nil, nil)
	if err != nil {
		return "", errors.New("cannot create NTLM negotiate message")
	}
	status, headers, _, err = send(scheme+" "+base64.StdEncoding.EncodeToString(token), nil, soapType)
	if err != nil {
		return "", err
	}
	if status != 401 {
		return "", fmt.Errorf("expected NTLM type-2 challenge, got HTTP %d", status)
	}
	_, input, err := challenge(headers, scheme)
	if err != nil {
		return "", err
	}
	encrypted := strings.HasPrefix(t.request.Endpoint, "http://")
	if err := validateChallenge(input, encrypted); err != nil {
		return "", err
	}
	token, err = ntlm.Authenticate(input, nil)
	if err != nil {
		return "", errors.New("invalid NTLM challenge or credentials")
	}
	auth := scheme + " " + base64.StdEncoding.EncodeToString(token)
	status, _, _, err = send(auth, nil, soapType)
	if err != nil {
		return "", err
	}
	// WSMan can return 400 for the empty authenticated handshake request.
	if status != 200 && status != 400 {
		return "", fmt.Errorf("NTLM authentication failed: HTTP %d", status)
	}
	if !ntlm.Complete() || ntlm.SecuritySession() == nil {
		return "", errors.New("NTLM authentication did not establish a session")
	}
	payload := []byte(message)
	ct := soapType
	if encrypted {
		payload, ct, err = sealMessage(ntlm.SecuritySession(), payload)
		if err != nil {
			return "", err
		}
	}
	status, headers, data, err := send("", payload, ct)
	if err != nil {
		return "", err
	}
	if status != 200 && status != 500 {
		return "", fmt.Errorf("WinRM request failed: HTTP %d", status)
	}
	if encrypted {
		data, err = unsealMessage(ntlm.SecuritySession(), data, headers.Get("Content-Type"))
		if err != nil {
			return "", err
		}
	} else if !strings.HasPrefix(strings.ToLower(headers.Get("Content-Type")), "application/soap+xml") {
		return "", errors.New("expected SOAP response")
	}
	return string(data), nil
}

func splitUser(user string) (string, string) {
	if domain, name, ok := strings.Cut(user, `\`); ok {
		return name, domain
	}
	if name, domain, ok := strings.Cut(user, "@"); ok {
		return name, domain
	}
	return user, ""
}

func challenge(h http.Header, want string) (string, []byte, error) {
	for _, line := range h.Values("WWW-Authenticate") {
		for _, part := range strings.Split(line, ",") {
			fields := strings.Fields(part)
			if len(fields) == 0 {
				continue
			}
			if !strings.EqualFold(fields[0], "Negotiate") && !strings.EqualFold(fields[0], "NTLM") {
				continue
			}
			if want != "" && !strings.EqualFold(fields[0], want) {
				continue
			}
			if len(fields) == 1 && want == "" {
				return fields[0], nil, nil
			}
			if len(fields) == 2 {
				b, err := base64.StdEncoding.DecodeString(fields[1])
				if err == nil && len(b) > 0 && len(b) < 65536 {
					return fields[0], b, nil
				}
			}
		}
	}
	return "", nil, errors.New("server did not provide a usable NTLM/Negotiate challenge")
}
