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

	"github.com/lavr/winsh/internal/remote"
	"github.com/lavr/winsh/internal/secret"
)

type Deps struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Execute        func(context.Context, remote.Request, io.Writer, io.Writer) (int, error)
	Version        string
}

type options struct {
	request                          remote.Request
	passwordEnv, file                string
	passwordStdin, envExplicit, help bool
	timeout                          time.Duration
	verbose                          int
}

func Run(ctx context.Context, args []string, d Deps) int {
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
	case "run", "ps":
	default:
		fmt.Fprintln(d.Stderr, "winsh: expected run or ps; see --help")
		return 201
	}
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	if o.help {
		usage(d.Stdout)
		return 0
	}
	lookup := d.Getenv
	if lookup == nil {
		lookup = os.Getenv
	}
	password, err := secret.ReadContext(ctx, o.passwordEnv, o.passwordStdin, d.Stdin, lookup)
	if ctx.Err() != nil {
		fmt.Fprintln(d.Stderr, "winsh:", ctx.Err())
		return 204
	}
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	o.request.Password = password
	if o.verbose > 0 {
		fmt.Fprintln(d.Stderr, "winsh: starting NTLM session; timeout", o.timeout)
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
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
	fmt.Fprintln(d.Stderr, "winsh:", strings.ReplaceAll(err.Error(), password, "[REDACTED]"))
	return code
}

func parse(args []string) (options, error) {
	o := options{passwordEnv: "WINRM_PASSWORD", timeout: 60 * time.Second}
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
		case "--endpoint", "--target-host", "--user", "--domain", "--auth", "--password-env", "--timeout", "--codepage", "-f":
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

Options:
  --endpoint URL         HTTP(S) /wsman URL; replaces host network address
  --user USER            DOMAIN\user, user@domain or local user
  --domain DOMAIN        Domain for an unqualified user
  --auth ntlm            Only NTLM is supported in v0.1
  --password-env NAME    Password variable name (default WINRM_PASSWORD)
  --password-stdin       Read password from first stdin line; no prompt
  --target-host NAME     TLS certificate name when using a tunnel
  --timeout DURATION    Overall execution timeout (default 60s)
  --codepage CODEPAGE    run output: raw (default), utf-8, 866 or 1251
  -v, -vv                Session diagnostics on stderr (no wire dump)
  --help, --version

Quote complete remote commands to preserve Windows quoting. Everything after
-- is command text, including --help and -v. Remote stdin is not forwarded.
HTTP uses NTLM message encryption. HTTPS verifies the server certificate.
`)
}
