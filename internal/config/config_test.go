package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# Keep this comment.
current_context: test
hosts:
  win:
    endpoint: http://127.0.0.1:15985/wsman
  second:
    endpoint: https://windows.example.com/wsman
credentials:
  account:
    user: env:LOGIN
    password: plain-test-secret
    domain: EXAMPLE
    env_file: credentials.env
contexts:
  test:
    host: win
    credentials: account
  stage:
    host: second
    credentials: account
defaults:
  auth: ntlm
  timeout: 15s
`

func fixture(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "winsh.yaml")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSelectAndRedact(t *testing.T) {
	c, err := Load(fixture(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := c.Select("")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Host.Endpoint != "http://127.0.0.1:15985/wsman" || selected.Credentials.Domain != "EXAMPLE" || selected.Defaults.Timeout != "15s" {
		t.Fatal("wrong current context")
	}
	selected, err = c.Select("stage")
	if err != nil || selected.Host.Endpoint != "https://windows.example.com/wsman" {
		t.Fatal("override ignored")
	}
	if _, err = c.Select("missing"); err == nil {
		t.Fatal("accepted missing context")
	}
	view, err := c.View()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(view), "plain-test-secret") || !strings.Contains(string(view), "REDACTED") {
		t.Fatal("password not redacted")
	}
	if c.Credentials["account"].Password != "plain-test-secret" {
		t.Fatal("view mutated live config")
	}
}

func TestRejectInvalidConfig(t *testing.T) {
	for _, tt := range []struct{ name, text string }{
		{"unknown", "password: should-not-appear\n"},
		{"duplicate", "current_context: first\ncurrent_context: second\n"},
		{"multiple documents", "hosts: {}\n---\npassword: should-not-appear\n"},
		{"type mismatch", "credentials:\n  account:\n    password: [should-not-appear]\n"},
		{"dangling host", "contexts:\n  test: {host: missing, credentials: missing}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(fixture(t, tt.text))
			if err == nil {
				t.Fatal("accepted invalid config")
			}
			if strings.Contains(err.Error(), "should-not-appear") {
				t.Fatal("parser leaked value")
			}
		})
	}
}

func TestUseContextPreservesValues(t *testing.T) {
	path := fixture(t, sample)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.UseContext("stage"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "# Keep this comment.") || !strings.Contains(string(b), "plain-test-secret") {
		t.Fatal("save lost unrelated content")
	}
	after, err := Load(path)
	if err != nil || after.CurrentContext != "stage" {
		t.Fatal("context not saved")
	}
	before := string(b)
	if err = after.UseContext("missing"); err == nil {
		t.Fatal("accepted unknown context")
	}
	b, _ = os.ReadFile(path)
	if string(b) != before {
		t.Fatal("invalid selection modified file")
	}
	if err = os.WriteFile(path, []byte(sample+"# concurrent update\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = after.UseContext("test"); err == nil {
		t.Fatal("overwrote concurrent modification")
	}
}

func TestCredentialSource(t *testing.T) {
	path := fixture(t, sample)
	env := filepath.Join(filepath.Dir(path), "credentials.env")
	if err := os.WriteFile(env, []byte("LOGIN='file-user'\nPASS='file-secret'\nCOMMAND='$(touch SHOULD_NOT_EXIST)'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cred := c.Credentials["account"]
	lookup := func(name string) (string, bool) {
		if name == "PASS" {
			return "process-secret", true
		}
		if name == "EMPTY" {
			return "", true
		}
		return "", false
	}
	for _, tt := range []struct {
		name, token, want string
		fail              bool
	}{
		{"file user", "env:LOGIN", "file-user", false},
		{"process priority", "env:PASS", "process-secret", false},
		{"literal", "literal:env:PASS", "env:PASS", false},
		{"no execution", "env:COMMAND", "$(touch SHOULD_NOT_EXIST)", false},
		{"set empty", "env:EMPTY", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Resolve(tt.token, cred, lookup)
			if (err != nil) != tt.fail || got != tt.want {
				t.Errorf("matches=%v err=%v", got == tt.want, err)
			}
		})
	}
	if _, err := os.Stat("SHOULD_NOT_EXIST"); !os.IsNotExist(err) {
		t.Fatal("dotenv executed a command")
	}
	cred.EnvFile = "missing.env"
	if got, err := c.Resolve("plain", cred, lookup); err != nil || got != "plain" {
		t.Fatal("read unused env file")
	}
	if got, err := c.Resolve("env:PASS", cred, lookup); err != nil || got != "process-secret" {
		t.Fatal("env file overrode environment")
	}
}

func TestDiscover(t *testing.T) {
	t.Chdir(t.TempDir())
	lookup := func(name string) string {
		if name == "WINSH_CONFIG" {
			return "chosen.yaml"
		}
		return ""
	}
	path, err := Discover("explicit.yaml", lookup)
	if err != nil || path != "explicit.yaml" {
		t.Fatal("explicit precedence")
	}
	path, err = Discover("", lookup)
	if err != nil || path != "chosen.yaml" {
		t.Fatal("env precedence")
	}
	if err = os.WriteFile("winsh.yaml", []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	path, err = Discover("", func(string) string { return "" })
	if err != nil || path != "winsh.yaml" {
		t.Fatal("cwd fallback")
	}
}

func TestUseContextRejectsAnchoredCurrentContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("current_context: &selected test\nhosts: {win: {endpoint: 'http://localhost:5985/wsman'}}\ncredentials: {account: {user: alice, domain: *selected}}\ncontexts:\n  test: {host: win, credentials: account}\n  stage: {host: win, credentials: account}\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.UseContext("stage"); err == nil {
		t.Fatal("expected rejection of anchored current_context")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatal("modified config after rejection")
	}
}
