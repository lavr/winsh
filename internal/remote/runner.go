package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	winrm "github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

type poster interface {
	post(context.Context, string) (string, error)
}

func Run(ctx context.Context, r Request, stdout, stderr io.Writer) (int, error) {
	return run(ctx, r, stdout, stderr, newTransport(r))
}

func run(ctx context.Context, r Request, stdout, stderr io.Writer, p poster) (code int, runErr error) {
	command, err := Command(r.Command, r.PowerShell)
	if err != nil {
		return 0, err
	}
	// The dependency's command builder wraps literal text in CDATA. Split the
	// closing marker so arbitrary shell text cannot break out of the XML node.
	command = strings.ReplaceAll(command, "]]>", "]]]]><![CDATA[>")
	params := winrm.NewParameters("PT30S", "en-US", 153600)
	send := func(ctx context.Context, m *soap.SoapMessage) (response, error) {
		defer m.Free()
		body, err := p.post(ctx, m.String())
		if err != nil {
			return response{}, err
		}
		return parseResponse(body)
	}
	opened, err := send(ctx, winrm.NewOpenShellRequest(r.Endpoint, params))
	if err != nil {
		return 0, err
	}
	shellID := opened.Body.Shell.ID
	if opened.Header.Action != wsTransfer+"CreateResponse" || !validID(shellID) {
		return 0, errors.New("invalid WinRM shell response")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		m := winrm.NewDeleteShellRequest(r.Endpoint, shellID, params)
		defer m.Free()
		body, err := p.post(cleanup, m.String())
		if err == nil && body != "" {
			var reply response
			reply, err = parseResponse(body)
			if err == nil && reply.Header.Action != wsTransfer+"DeleteResponse" {
				err = errors.New("invalid shell cleanup response")
			}
		}
		if err != nil && runErr == nil {
			runErr = errors.New("remote command completed but shell cleanup failed")
		}
	}()
	started, err := send(ctx, winrm.NewExecuteCommandRequest(r.Endpoint, shellID, command, nil, params))
	if err != nil {
		return 0, err
	}
	commandID := started.Body.Command.ID
	if started.Header.Action != wsShell+"CommandResponse" || !validID(commandID) {
		return 0, errors.New("invalid WinRM command response")
	}
	// Noninteractive commands see EOF instead of waiting on an unconnected stdin.
	if _, err = send(ctx, winrm.NewSendInputRequest(r.Endpoint, shellID, commandID, nil, true, params)); err != nil {
		return 0, err
	}
	var decoder *charmap.Charmap
	if !r.PowerShell {
		switch r.Codepage {
		case "866":
			decoder = charmap.CodePage866
		case "1251":
			decoder = charmap.Windows1251
		}
	}
	if decoder != nil {
		out := transform.NewWriter(stdout, decoder.NewDecoder())
		errout := transform.NewWriter(stderr, decoder.NewDecoder())
		stdout = out
		stderr = errout
		defer func() {
			if err := errors.Join(out.Close(), errout.Close()); err != nil && runErr == nil {
				runErr = fmt.Errorf("decoding output: %w", err)
			}
		}()
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		received, err := send(ctx, winrm.NewGetOutputRequest(r.Endpoint, shellID, commandID, "stdout stderr", params))
		if errors.Is(err, errOperationTimeout) {
			continue
		}
		if err != nil {
			return 0, err
		}
		done, rc, err := received.receive(stdout, stderr)
		if err != nil {
			return 0, err
		}
		if done {
			return rc, nil
		}
	}
}
