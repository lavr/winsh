// Package cmd parses the noninteractive CLI and maps failures to process status.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lavr/winsh/internal/config"
	"github.com/lavr/winsh/internal/control"
	"github.com/lavr/winsh/internal/remote"
	"github.com/lavr/winsh/internal/secret"
)

type Deps struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	LookupEnv      func(string) (string, bool)
	Execute        func(context.Context, remote.Request, io.Writer, io.Writer) (int, error)
	Transfer       func(context.Context, remote.TransferRequest, func(int64)) (remote.TransferResult, error)
	ControlStart   func(context.Context, control.Identity, control.Settings, func() (control.Bootstrap, error)) (string, error)
	ControlInvoke  func(context.Context, string, control.Call, io.Writer, io.Writer) (control.Result, error)
	ControlCheck   func(context.Context, string, control.Identity, time.Duration) (bool, error)
	ControlExit    func(context.Context, string, control.Identity, time.Duration) error
	Version        string
}

type options struct {
	request                          remote.Request
	passwordEnv, file                string
	passwordStdin, envExplicit, help bool
	timeout                          time.Duration
	verbose                          int
	configPath, contextName          string
	passwordReference                string
	passwordConfig                   *config.Config
	passwordCredentials              config.Credentials
	control                          control.Settings
	timeoutConfigured                bool
}

func Run(ctx context.Context, args []string, d Deps) int {
	var globalErr error
	args, globalErr = normalizeGlobals(args)
	if globalErr != nil {
		fmt.Fprintln(d.Stderr, "winsh:", globalErr)
		return 201
	}
	if len(args) == 0 {
		usage(d.Stderr)
		return 201
	}
	switch args[0] {
	case "--help", "-h", "help":
		usage(d.Stdout)
		return 0
	case "--version", "version":
		fmt.Fprintln(d.Stdout, "winsh", d.Version)
		return 0
	case "config":
		return runConfig(args[1:], d)
	case "control":
		return runControl(ctx, args[1:], d)
	case "upload", "download":
		return runTransfer(ctx, args, d)
	case "run", "ps":
	default:
		fmt.Fprintln(d.Stderr, "winsh: expected run, ps, upload, download or control; see --help")
		return 201
	}
	o, err := parse(args, d)
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	if o.help {
		usage(d.Stdout)
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if o.control.Mode == "auto" {
		return runControlled(ctx, o, d)
	}
	password, err := resolvePassword(ctx, o, d)
	if ctx.Err() != nil {
		fmt.Fprintln(d.Stderr, "winsh:", ctx.Err())
		return statusForContext(ctx.Err())
	}
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	o.request.Password = password
	if o.verbose > 0 {
		fmt.Fprintln(d.Stderr, "winsh: starting NTLM session; timeout", o.timeout)
	}
	rc, err := d.Execute(ctx, o.request, d.Stdout, d.Stderr)
	if err == nil {
		return rc
	}
	code := 202
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		code = 203
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		code = 204
	}
	// Errors may contain server-controlled text. Never print credentials from them.
	fmt.Fprintln(d.Stderr, "winsh:", redact(err.Error(), password))
	return code
}

func statusForContext(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return 203
	}
	if errors.Is(err, context.Canceled) {
		return 204
	}
	return 202
}

func resolvePassword(ctx context.Context, o options, d Deps) (string, error) {
	if o.passwordConfig != nil {
		_, lookup := envLookups(d)
		password, err := o.passwordConfig.Resolve(o.passwordReference, o.passwordCredentials, lookup)
		if err != nil {
			return "", fmt.Errorf("configured password: %w", err)
		}
		return password, nil
	}
	lookup := d.Getenv
	if lookup == nil {
		lookup = os.Getenv
	}
	return secret.ReadContext(ctx, o.passwordEnv, o.passwordStdin, d.Stdin, lookup)
}

func redact(message, password string) string {
	if password == "" {
		return message
	}
	return strings.ReplaceAll(message, password, "[REDACTED]")
}

func parse(args []string, d Deps) (options, error) {
	o := options{passwordEnv: "WINRM_PASSWORD", timeout: 60 * time.Second, control: control.Settings{Mode: "off", Persist: 5 * time.Minute}}
	o.request.PowerShell = args[0] == "ps"
	var host, domain string
	var command []string
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			command = args[i+1:]
			break
		}
		if a == "--help" || a == "-h" {
			o.help = true
			return o, nil
		}
		if a == "-v" || a == "-vv" {
			o.verbose = len(a) - 1
			continue
		}
		if a == "--password-stdin" {
			if o.passwordStdin {
				return o, errors.New("duplicate password source")
			}
			o.passwordStdin = true
			continue
		}
		if !strings.HasPrefix(a, "-") {
			if host != "" {
				return o, errors.New("put remote command text after --")
			}
			host = a
			continue
		}
		name, value, inline := strings.Cut(a, "=")
		switch name {
		case "--config", "--context", "--endpoint", "--target-host", "--user", "--domain", "--auth", "--password-env", "--timeout", "--codepage", "--control", "--control-persist", "--control-path", "-f":
		default:
			return o, errors.New("unknown option; see --help (password values are never accepted as flags)")
		}
		if seen[name] {
			return o, errors.New("duplicate option")
		}
		seen[name] = true
		if !inline {
			i++
			if i >= len(args) || args[i] == "--" {
				return o, errors.New("option requires a value")
			}
			value = args[i]
		}
		switch name {
		case "--config":
			o.configPath = value
		case "--context":
			o.contextName = value
		case "--endpoint":
			o.request.Endpoint = value
		case "--target-host":
			o.request.TargetHost = value
		case "--user":
			o.request.User = value
		case "--domain":
			domain = value
		case "--auth":
			if value != "ntlm" {
				return o, errors.New("v0.1 supports --auth ntlm only")
			}
		case "--password-env":
			o.passwordEnv = value
			o.envExplicit = true
		case "--timeout":
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return o, errors.New("timeout must be a positive duration")
			}
			o.timeout = duration
			o.timeoutConfigured = true
		case "--control":
			if value != "auto" && value != "off" {
				return o, errors.New("control mode must be auto or off")
			}
			o.control.Mode = value
		case "--control-persist":
			persist, err := parseControlPersist(value)
			if err != nil {
				return o, err
			}
			o.control.Persist = persist
		case "--control-path":
			if value == "" {
				return o, errors.New("control path must be nonempty")
			}
			o.control.Path = value
		case "--codepage":
			o.request.Codepage = value
		case "-f":
			o.file = value
		}
	}
	if o.passwordStdin && o.envExplicit {
		return o, errors.New("choose --password-env or --password-stdin")
	}
	if o.passwordEnv == "" {
		return o, errors.New("password environment variable name is empty")
	}
	switch o.request.Codepage {
	case "", "raw", "utf-8", "866", "1251":
	default:
		return o, errors.New("codepage must be raw, utf-8, 866 or 1251")
	}
	if o.request.PowerShell && o.request.Codepage != "" && o.request.Codepage != "utf-8" {
		return o, errors.New("PowerShell output is UTF-8; --codepage applies to run")
	}
	if err := applyConfig(&o, &host, &domain, seen, d); err != nil {
		return o, err
	}
	if o.request.User == "" || strings.ContainsAny(o.request.User, "\r\n\x00") {
		return o, errors.New("--user is required")
	}
	if domain != "" {
		if strings.ContainsAny(domain, "\\@/ \t\r\n\x00") || strings.ContainsAny(o.request.User, "\\@") {
			return o, errors.New("--domain requires an unqualified --user")
		}
		o.request.User = domain + `\` + o.request.User
	}
	if strings.ContainsAny(o.request.TargetHost, "/\\@ \t\r\n\x00") {
		return o, errors.New("invalid --target-host")
	}
	endpoint, err := remote.Endpoint(host, o.request.Endpoint)
	if err != nil {
		return o, err
	}
	o.request.Endpoint = endpoint
	if o.file != "" {
		if !o.request.PowerShell || len(command) > 0 {
			return o, errors.New("-f requires ps and cannot be combined with command text")
		}
		// Bound script input before loading it; encoded commands also have a WinRM envelope limit.
		f, err := os.Open(o.file)
		if err != nil {
			return o, errors.New("cannot open script file")
		}
		data, err := io.ReadAll(io.LimitReader(f, 32769))
		f.Close()
		if err != nil || len(data) > 32768 {
			return o, errors.New("cannot read script or script exceeds 32 KiB")
		}
		o.request.Command = strings.TrimPrefix(string(data), "\ufeff")
	} else {
		o.request.Command = strings.Join(command, " ")
	}
	if strings.TrimSpace(o.request.Command) == "" {
		return o, errors.New("provide command text after -- or use ps -f")
	}
	if !utf8.ValidString(o.request.Command) || strings.ContainsRune(o.request.Command, 0) {
		return o, errors.New("command must be valid UTF-8 without NUL")
	}
	if len(o.request.Command) > 32768 {
		return o, errors.New("command exceeds 32 KiB")
	}
	if _, err := remote.Command(o.request.Command, o.request.PowerShell); err != nil {
		return o, err
	}
	return o, nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `winsh — noninteractive Windows command execution over WinRM

Usage:
  winsh run <host> [options] -- <cmd shell text ...>
  winsh ps  <host> [options] -- <PowerShell script ...>
  winsh ps  <host> [options] -f script.ps1
  winsh upload [host] [options] [--force] -- LOCAL_FILE REMOTE_FILE
  winsh download [host] [options] [--force] -- REMOTE_FILE LOCAL_FILE
  winsh control check [host] [options]
  winsh control exit  [host] [options]
  winsh [--config PATH] config get-contexts|current-context|view
  winsh [--config PATH] config use-context NAME

Host and credentials may be supplied by the selected configuration context.

Options:
  --config PATH          YAML config (or WINSH_CONFIG)
  --context NAME         Override current_context
  --endpoint URL         HTTP(S) /wsman URL; replaces host network address
  --user USER            DOMAIN\user, user@domain or local user
  --domain DOMAIN        Domain for an unqualified user
  --auth ntlm            Only NTLM is supported in v0.1
  --password-env NAME    Password variable name (default WINRM_PASSWORD)
  --password-stdin       Read password from first stdin line; no prompt
  --target-host NAME     TLS certificate name when using a tunnel
  --timeout DURATION    Overall timeout (run/ps 60s; transfers 30m)
  --control=auto|off   Reuse command NTLM connections (run/ps; default off)
  --control-persist DURATION  Master idle lifetime (default 5m; 1s to 1h)
  --control-path PATH  Explicit private Unix socket path
  --force               Replace an existing transfer destination
  --codepage CODEPAGE    run encoding: raw/utf-8 (default WinRS UTF-8), 866 or 1251
  -v, -vv                Session diagnostics on stderr (no wire dump)
  --help, --version

Quote complete remote commands to preserve Windows quoting. Everything after
-- is command text, including --help and -v. Remote stdin is not forwarded.
For upload/download, exactly two literal file paths follow --. The destination
parent must already exist. A transfer completes only after SHA-256 verification.
HTTP uses NTLM message encryption. HTTPS verifies the server certificate.
Control mode runs on Linux/macOS, opens a new remote Shell per command, and
reads the password only when starting a master. Control check/exit do not
read a password. A master belongs to the same local user and target identity.
`)
}
