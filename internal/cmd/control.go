package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/lavr/winsh/internal/control"
)

type controlPasswordError struct{ error }

func controlIdentity(o options, d Deps) control.Identity {
	get, _ := envLookups(d)
	return control.Identity{Endpoint: o.request.Endpoint, User: o.request.User, TargetHost: o.request.TargetHost, TrustKey: control.TrustKey(get)}
}

func runControlled(ctx context.Context, o options, d Deps) int {
	identity := controlIdentity(o, d)
	start := d.ControlStart
	if start == nil {
		start = control.StartOrConnect
	}
	resolve := func() (control.Bootstrap, error) {
		password, err := resolvePassword(ctx, o, d)
		if err != nil {
			return control.Bootstrap{}, controlPasswordError{err}
		}
		return control.Bootstrap{Endpoint: identity.Endpoint, User: identity.User, TargetHost: identity.TargetHost, Password: password, Timeout: o.timeout}, nil
	}
	socket, err := start(ctx, identity, o.control, resolve)
	if err != nil {
		return controlFailure(ctx, err, d.Stderr)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return controlFailure(ctx, errors.New("missing command deadline"), d.Stderr)
	}
	invoke := d.ControlInvoke
	if invoke == nil {
		invoke = control.Invoke
	}
	result, err := invoke(ctx, socket, control.Call{Identity: identity, Command: o.request.Command, PowerShell: o.request.PowerShell, Codepage: o.request.Codepage, Deadline: deadline, Persist: o.control.Persist}, d.Stdout, d.Stderr)
	if err != nil {
		return controlFailure(ctx, err, d.Stderr)
	}
	if result.Category != "" {
		return controlFailure(ctx, control.CategoryError{Category: result.Category}, d.Stderr)
	}
	return result.ExitCode
}

func controlFailure(ctx context.Context, err error, stderr io.Writer) int {
	if ctx.Err() != nil {
		var category control.CategoryError
		if errors.As(err, &category) && category.Category == control.CategoryRemoteStateUnknown {
			fmt.Fprintln(stderr, "winsh:", ctx.Err(), "(remote-state-unknown)")
		} else {
			fmt.Fprintln(stderr, "winsh:", ctx.Err())
		}
		return statusForContext(ctx.Err())
	}
	var passwordError controlPasswordError
	if errors.As(err, &passwordError) {
		fmt.Fprintln(stderr, "winsh:", passwordError.Error())
		return 201
	}
	var category control.CategoryError
	if errors.As(err, &category) {
		if category.Category == control.CategoryRemoteStateUnknown && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			cause := context.Canceled
			if errors.Is(err, context.DeadlineExceeded) {
				cause = context.DeadlineExceeded
			}
			fmt.Fprintln(stderr, "winsh:", cause, "(remote-state-unknown)")
			return statusForContext(err)
		}
		fmt.Fprintln(stderr, "winsh:", category.Error())
		switch category.Category {
		case control.CategoryTimeout:
			return 203
		case control.CategoryCanceled:
			return 204
		}
		return 202
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "winsh:", err)
		return statusForContext(err)
	}
	fmt.Fprintln(stderr, "winsh: control master unavailable")
	return 202
}

func runControl(ctx context.Context, args []string, d Deps) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		usage(d.Stdout)
		return 0
	}
	var globals []string
	for len(args) > 0 {
		name, _, inline := strings.Cut(args[0], "=")
		if name != "--config" && name != "--context" {
			break
		}
		if inline {
			globals = append(globals, args[0])
			args = args[1:]
		} else if len(args) >= 2 {
			globals = append(globals, args[:2]...)
			args = args[2:]
		} else {
			fmt.Fprintln(d.Stderr, "winsh: global option requires a value")
			return 201
		}
	}
	if len(args) == 0 || args[0] != "check" && args[0] != "exit" {
		fmt.Fprintln(d.Stderr, "winsh: expected control check or exit")
		return 201
	}
	action := args[0]
	for _, arg := range args[1:] {
		name, _, _ := strings.Cut(arg, "=")
		if arg == "--" || name == "-f" || name == "--codepage" {
			fmt.Fprintln(d.Stderr, "winsh: control check/exit accepts target options only")
			return 201
		}
	}
	parseArgs := append([]string{"run"}, globals...)
	parseArgs = append(parseArgs, args[1:]...)
	parseArgs = append(parseArgs, "--", "exit 0")
	o, err := parse(parseArgs, d)
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh:", err)
		return 201
	}
	if o.help {
		usage(d.Stdout)
		return 0
	}
	identity := controlIdentity(o, d)
	socket, err := control.SocketPath(identity, o.control)
	if err != nil {
		fmt.Fprintln(d.Stderr, "winsh: invalid control socket path")
		return 201
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if action == "check" {
		check := d.ControlCheck
		if check == nil {
			check = control.Check
		}
		live, err := check(ctx, socket, identity, o.control.Persist)
		if err != nil {
			return controlFailure(ctx, err, d.Stderr)
		}
		if !live {
			fmt.Fprintln(d.Stdout, "control master is not running")
			return 202
		}
		fmt.Fprintln(d.Stdout, "control master is running")
		return 0
	}
	exit := d.ControlExit
	if exit == nil {
		exit = control.Exit
	}
	if err := exit(ctx, socket, identity, o.control.Persist); err != nil {
		return controlFailure(ctx, err, d.Stderr)
	}
	fmt.Fprintln(d.Stdout, "control master stopped")
	return 0
}
