package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
)

type transport struct{ request Request }

func newTransport(r Request) *transport { return &transport{request: r} }

// handshakeTransportError is limited to empty-body NTLM exchanges. A SOAP
// request has not been dispatched, so retrying from a fresh authentication
// connection cannot replay a remote command or a transfer chunk.
type handshakeTransportError struct {
	phase string
	cause error
}

func (e *handshakeTransportError) Error() string { return e.phase + ": " + e.cause.Error() }
func (e *handshakeTransportError) Unwrap() error { return e.cause }

func retryableHandshake(err error) bool {
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout() ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

func withHandshakeRetries(ctx context.Context, attempt func() (string, error)) (string, error) {
	for i := 0; ; i++ {
		body, err := attempt()
		var handshakeErr *handshakeTransportError
		if err == nil || ctx.Err() != nil || !errors.As(err, &handshakeErr) ||
			!retryableHandshake(handshakeErr.cause) || i >= 2 {
			return body, err
		}
	}
}

func (t *transport) post(ctx context.Context, message string) (string, error) {
	return withHandshakeRetries(ctx, func() (string, error) { return t.postOnce(ctx, message) })
}

// Each standalone SOAP exchange authenticates its own connection.
func (t *transport) postOnce(ctx context.Context, message string) (string, error) {
	p, err := authenticateConnection(ctx, t.request)
	if err != nil {
		return "", err
	}
	defer p.Close()
	return p.Post(ctx, message)
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
