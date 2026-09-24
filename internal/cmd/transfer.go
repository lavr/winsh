package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lavr/winsh/internal/remote"
)

// parseTransfer reuses parse's connection, config and credential precedence.
// A harmless dummy command satisfies the command parser after the literal
// transfer operands have been removed.
func parseTransfer(args []string, d Deps) (options, remote.TransferRequest, error) {
	var req remote.TransferRequest
	if len(args) == 0 || (args[0] != "upload" && args[0] != "download") {
		return options{}, req, errors.New("expected upload or download")
	}
	for _, arg := range args[1:] {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			return options{help: true}, req, nil
		}
	}
	separator := -1
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return options{}, req, errors.New("transfer requires -- and two paths")
	}
	if len(args)-separator-1 != 2 {
		return options{}, req, errors.New("transfer requires exactly two paths after --")
	}
	before := make([]string, 0, separator+2)
	before = append(before, "ps")
	for i := 1; i < separator; i++ {
		name, _, _ := strings.Cut(args[i], "=")
		if name == "-f" || name == "--codepage" || name == "--control" || name == "--control-persist" || name == "--control-path" {
			return options{}, req, errors.New("option does not apply to file transfer")
		}
		if name == "--force" {
			if args[i] != "--force" || req.Force {
				return options{}, req, errors.New("duplicate or invalid --force")
			}
			req.Force = true
			continue
		}
		before = append(before, args[i])
	}
	before = append(before, "--", "exit 0")
	o, err := parse(before, d)
	if err != nil {
		return o, req, err
	}
	if !o.timeoutConfigured {
		o.timeout = 30 * time.Minute
	}
	if args[0] == "upload" {
		req.Direction = remote.Upload
		req.LocalPath, req.RemotePath = args[separator+1], args[separator+2]
	} else {
		req.Direction = remote.Download
		req.RemotePath, req.LocalPath = args[separator+1], args[separator+2]
	}
	if req.LocalPath == "" || req.RemotePath == "" || req.LocalPath == "-" || req.RemotePath == "-" {
		return o, req, errors.New("transfer requires two file paths; stdin/stdout paths are unsupported")
	}
	req.Connection = o.request
	return o, req, nil
}

func runTransfer(ctx context.Context, args []string, d Deps) int {
	o, req, err := parseTransfer(args, d)
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	if o.help {
		usage(d.Stdout)
		return 0
	}
	password, err := resolvePassword(ctx, o, d)
	if ctx.Err() != nil {
		fmt.Fprintln(d.Stderr, "winsh: canceled while reading password")
		return 204
	}
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh: cannot read password")
		return 201
	}
	req.Connection.Password = password
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if o.verbose > 0 {
		fmt.Fprintln(d.Stderr, "winsh: starting NTLM file transfer; timeout", o.timeout)
	}
	var last time.Time
	progress := func(bytes int64) {
		if now := time.Now(); last.IsZero() || now.Sub(last) >= time.Second {
			fmt.Fprintf(d.Stderr, "winsh: %s: %d bytes\n", req.Direction, bytes)
			last = now
		}
	}
	if d.Transfer == nil {
		fmt.Fprintln(d.Stderr, "winsh: transfer unavailable")
		return 202
	}
	result, err := d.Transfer(ctx, req, progress)
	if err == nil && !result.Committed {
		err = errors.New("transfer was not committed")
	}
	if err == nil {
		fmt.Fprintf(d.Stderr, "winsh: %s: %d bytes total\n", req.Direction, result.Bytes)
		fmt.Fprintf(d.Stdout, "%s %d bytes SHA-256 %s\n", req.Direction, result.Bytes, result.SHA256)
		return 0
	}
	code := 202
	var remoteExit *remote.RemoteExitError
	var unknown *remote.FinalizationUnknownError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		code = 203
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		code = 204
	case remote.IsTransferInputError(err):
		code = 201
	case errors.As(err, &remoteExit):
		code = remoteExit.Code
	}
	message := "transfer failed"
	switch {
	case errors.As(err, &unknown):
		message = "finalization outcome unknown; inspect destination before retrying"
	case result.Committed:
		message = "transfer committed but cleanup failed"
	case code == 203:
		message = "transfer timeout"
	case code == 204:
		message = "transfer canceled"
	case remoteExit != nil:
		message = "remote command exited with nonzero status"
	case code == 201:
		message = "invalid transfer input"
	}
	fmt.Fprintln(d.Stderr, "winsh:", message)
	for _, artifact := range result.Artifacts {
		fmt.Fprintf(d.Stderr, "winsh: artifact %q\n", redact(artifact, password))
	}
	return code
}
