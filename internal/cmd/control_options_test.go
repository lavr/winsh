package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlOptions(t *testing.T) {
	base := []string{"run", "server.example.com", "--user", "alice", "--", "hostname"}
	o, err := parse(base, Deps{Getenv: func(string) string { return "" }})
	if err != nil || o.control.Mode != "off" || o.control.Persist != 5*time.Minute {
		t.Fatalf("default control = %+v, %v", o.control, err)
	}
	args := []string{"run", "server.example.com", "--user", "alice", "--control=auto", "--control-persist=10m", "--control-path=/tmp/winsh.sock", "--", "hostname"}
	o, err = parse(args, Deps{Getenv: func(string) string { return "" }})
	if err != nil || o.control.Mode != "auto" || o.control.Persist != 10*time.Minute || o.control.Path != "/tmp/winsh.sock" {
		t.Fatalf("configured control = %+v, %v", o.control, err)
	}
	for _, option := range []string{"--control=invalid", "--control-persist=0", "--control-persist=61m", "--control-persist=bogus", "--control-path="} {
		args := []string{"run", "server.example.com", "--user", "alice", option, "--", "hostname"}
		if _, err := parse(args, Deps{Getenv: func(string) string { return "" }}); err == nil {
			t.Errorf("accepted %s", option)
		}
	}
	args = []string{"run", "server.example.com", "--user", "alice", "--control=auto", "--control=off", "--", "hostname"}
	if _, err := parse(args, Deps{Getenv: func(string) string { return "" }}); err == nil {
		t.Fatal("accepted duplicate control mode")
	}
}

func TestControlConfigAndLazyPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `current_context: test
hosts: {windows: {endpoint: 'https://server.example.com/wsman'}}
credentials: {account: {user: alice, password: 'env:MISSING_SECRET'}}
contexts: {test: {host: windows, credentials: account}}
defaults: {control_master: auto, control_persist: 2m, control_path: /tmp/winsh.sock}
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	d := Deps{Getenv: func(string) string { return "" }, LookupEnv: func(string) (string, bool) { return "", false }}
	o, err := parse([]string{"run", "--config", path, "--", "hostname"}, d)
	if err != nil || o.control.Mode != "auto" || o.control.Persist != 2*time.Minute || o.control.Path != "/tmp/winsh.sock" {
		t.Fatalf("config parse or defaults failed: %+v, %v", o.control, err)
	}
	if _, err := resolvePassword(t.Context(), o, d); err == nil {
		t.Fatal("missing configured password was silently accepted")
	}
	o, err = parse([]string{"run", "--config", path, "--control=off", "--control-persist=1m", "--password-stdin", "--", "hostname"}, d)
	if err != nil || o.control.Mode != "off" || o.control.Persist != time.Minute {
		t.Fatalf("CLI precedence failed: %+v, %v", o.control, err)
	}
	d.Stdin = strings.NewReader("stdin-secret\n")
	if password, err := resolvePassword(t.Context(), o, d); err != nil || password != "stdin-secret" {
		t.Fatal("stdin override did not bypass configured password")
	}
}
