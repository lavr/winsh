package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lavr/winsh/internal/config"
	"github.com/lavr/winsh/internal/control"
	"github.com/lavr/winsh/internal/secret"
)

// Move only leading global options behind the command. The command parser owns
// the remaining arguments, so flag values and everything after -- stay intact.
func normalizeGlobals(args []string) ([]string, error) {
	var leading []string
	for len(args) > 0 {
		name, value, inline := strings.Cut(args[0], "=")
		if name != "--config" && name != "--context" {
			break
		}
		args = args[1:]
		if !inline {
			if len(args) == 0 || args[0] == "--" {
				return nil, errors.New("global option requires a value")
			}
			value, args = args[0], args[1:]
		}
		if value == "" {
			return nil, errors.New("global option requires a nonempty value")
		}
		leading = append(leading, name+"="+value)
	}
	if len(leading) == 0 {
		return args, nil
	}
	if len(args) == 0 {
		return nil, errors.New("expected command after global options")
	}
	result := []string{args[0]}
	result = append(result, leading...)
	return append(result, args[1:]...), nil
}

func envLookups(d Deps) (func(string) string, secret.LookupEnv) {
	get := d.Getenv
	lookup := d.LookupEnv
	if get == nil {
		get = os.Getenv
	}
	if lookup == nil {
		if d.Getenv == nil {
			lookup = os.LookupEnv
		} else {
			lookup = func(name string) (string, bool) { v := get(name); return v, v != "" }
		}
	}
	return get, lookup
}

func applyConfig(o *options, host, domain *string, seen map[string]bool, d Deps) error {
	for _, name := range []string{"--config", "--context"} {
		if seen[name] && ((name == "--config" && o.configPath == "") || (name == "--context" && o.contextName == "")) {
			return errors.New("global option requires a nonempty value")
		}
	}
	get, lookup := envLookups(d)
	path, err := config.Discover(o.configPath, get)
	if err != nil {
		return err
	}
	if path == "" {
		if o.contextName != "" {
			return errors.New("context requires a configuration file")
		}
		return nil
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	selected, err := c.Select(o.contextName)
	if err != nil {
		return err
	}
	if *host != "" {
		if h, ok := c.Hosts[*host]; ok {
			selected.Host = h
			*host = ""
		} else {
			selected.Host = config.Host{}
		}
	}
	if !seen["--endpoint"] {
		o.request.Endpoint = selected.Host.Endpoint
	}
	if !seen["--target-host"] {
		o.request.TargetHost = selected.Host.TargetHost
	}
	if !seen["--auth"] && selected.Defaults.Auth != "" && selected.Defaults.Auth != "ntlm" {
		return errors.New("only ntlm authentication is supported")
	}
	if !seen["--timeout"] && selected.Defaults.Timeout != "" {
		duration, err := time.ParseDuration(selected.Defaults.Timeout)
		if err != nil || duration <= 0 {
			return errors.New("timeout must be a positive duration")
		}
		o.timeout = duration
		o.timeoutConfigured = true
	}
	if !seen["--control"] && selected.Defaults.ControlMaster != "" {
		if selected.Defaults.ControlMaster != "auto" && selected.Defaults.ControlMaster != "off" {
			return errors.New("control mode must be auto or off")
		}
		o.control.Mode = selected.Defaults.ControlMaster
	}
	if !seen["--control-persist"] && selected.Defaults.ControlPersist != "" {
		persist, err := parseControlPersist(selected.Defaults.ControlPersist)
		if err != nil {
			return err
		}
		o.control.Persist = persist
	}
	if !seen["--control-path"] && selected.Defaults.ControlPath != "" {
		o.control.Path = selected.Defaults.ControlPath
	}
	if !seen["--user"] && selected.Credentials.User != "" {
		o.request.User, err = c.Resolve(selected.Credentials.User, selected.Credentials, lookup)
		if err != nil {
			return fmt.Errorf("configured user: %w", err)
		}
	}
	if !seen["--domain"] && !strings.ContainsAny(o.request.User, `\@`) {
		*domain = selected.Credentials.Domain
	}
	if !o.passwordStdin && !o.envExplicit && selected.Credentials.Password != "" {
		o.passwordConfig = c
		o.passwordReference = selected.Credentials.Password
		o.passwordCredentials = selected.Credentials
	}
	return nil
}

func parseControlPersist(value string) (time.Duration, error) {
	persist, err := time.ParseDuration(value)
	if err != nil || persist < control.MinPersist || persist > time.Hour {
		return 0, errors.New("control persist must be between 1s and 1h")
	}
	return persist, nil
}

func runConfig(args []string, d Deps) int {
	fail := func(err error) int { fmt.Fprintln(d.Stderr, "winsh:", err); return 201 }
	var path string
	var positional []string
	seen := false
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		if name == "--config" {
			if seen {
				return fail(errors.New("duplicate --config"))
			}
			seen = true
			if !inline {
				i++
				if i >= len(args) {
					return fail(errors.New("--config requires a value"))
				}
				value = args[i]
			}
			if value == "" {
				return fail(errors.New("--config requires a nonempty value"))
			}
			path = value
		} else {
			positional = append(positional, args[i])
		}
	}
	if len(positional) == 0 {
		return fail(errors.New("expected config get-contexts, current-context, use-context or view"))
	}
	command := positional[0]
	expected := 1
	if command == "use-context" {
		expected = 2
	}
	if len(positional) != expected {
		return fail(errors.New("unexpected config arguments"))
	}
	switch command {
	case "get-contexts", "current-context", "use-context", "view":
	default:
		return fail(errors.New("unknown config command"))
	}
	get, _ := envLookups(d)
	path, err := config.Discover(path, get)
	if err != nil {
		return fail(err)
	}
	if path == "" {
		return fail(errors.New("no configuration file found"))
	}
	c, err := config.Load(path)
	if err != nil {
		return fail(err)
	}
	switch command {
	case "view":
		data, err := c.View()
		if err != nil {
			return fail(err)
		}
		if _, err = d.Stdout.Write(data); err != nil {
			return fail(err)
		}
	case "current-context":
		if c.CurrentContext == "" {
			return fail(errors.New("current_context is not set"))
		}
		fmt.Fprintln(d.Stdout, c.CurrentContext)
	case "get-contexts":
		names := make([]string, 0, len(c.Contexts))
		for name := range c.Contexts {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintln(d.Stdout, "CURRENT\tNAME\tHOST\tCREDENTIALS")
		for _, name := range names {
			mark := ""
			if name == c.CurrentContext {
				mark = "*"
			}
			ctx := c.Contexts[name]
			fmt.Fprintf(d.Stdout, "%s\t%s\t%s\t%s\n", mark, name, ctx.Host, ctx.Credentials)
		}
	case "use-context":
		if err = c.UseContext(positional[1]); err != nil {
			return fail(err)
		}
		fmt.Fprintln(d.Stdout, "Current context updated.")
	}
	return 0
}
