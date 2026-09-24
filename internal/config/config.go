// Package config loads WinRM hosts, credential sources and named contexts.
package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/lavr/winsh/internal/secret"
	"go.yaml.in/yaml/v3"
)

const maxFileSize = 1024 * 1024

type Host struct {
	Endpoint   string `yaml:"endpoint"`
	TargetHost string `yaml:"target_host,omitempty"`
}
type Credentials struct {
	Domain   string `yaml:"domain,omitempty"`
	EnvFile  string `yaml:"env_file,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
}
type Context struct {
	Host        string `yaml:"host"`
	Credentials string `yaml:"credentials"`
}
type Defaults struct {
	Auth           string `yaml:"auth,omitempty"`
	Timeout        string `yaml:"timeout,omitempty"`
	ControlMaster  string `yaml:"control_master,omitempty"`
	ControlPersist string `yaml:"control_persist,omitempty"`
	ControlPath    string `yaml:"control_path,omitempty"`
}
type File struct {
	CurrentContext string                 `yaml:"current_context,omitempty"`
	Hosts          map[string]Host        `yaml:"hosts,omitempty"`
	Credentials    map[string]Credentials `yaml:"credentials,omitempty"`
	Contexts       map[string]Context     `yaml:"contexts,omitempty"`
	Defaults       Defaults               `yaml:"defaults,omitempty"`
}
type Config struct {
	File
	Path string
	raw  []byte
	node yaml.Node
}
type Selection struct {
	Host        Host
	Credentials Credentials
	Defaults    Defaults
}

func Discover(explicit string, getenv func(string) string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if path := getenv("WINSH_CONFIG"); path != "" {
		return path, nil
	}
	paths := []string{"winsh.yaml"}
	dir := getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, ".config")
		}
	}
	if dir != "" {
		paths = append(paths, filepath.Join(dir, "winsh", "config.yaml"))
	}
	for _, path := range paths {
		_, err := os.Stat(path)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("cannot inspect configuration path")
		}
	}
	return "", nil
}

func readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil, errors.New("file must be regular and at most 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil, errors.New("file must be regular and at most 1 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil || len(b) > maxFileSize {
		return nil, errors.New("cannot read file or file exceeds 1 MiB")
	}
	return b, nil
}

func Load(path string) (*Config, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, errors.New("cannot open configuration file")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, errors.New("cannot resolve configuration path")
	}
	raw, err := readFile(resolved)
	if err != nil {
		return nil, errors.New("cannot read configuration file (maximum 1 MiB)")
	}
	c := &Config{Path: resolved, raw: raw}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err = decoder.Decode(&c.File); err != nil {
		return nil, errors.New("invalid YAML configuration; check field names, duplicate keys and types")
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	if err = yaml.Unmarshal(raw, &c.node); err != nil || len(c.node.Content) != 1 || c.node.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configuration must be a YAML mapping")
	}
	for name, ctx := range c.Contexts {
		if name == "" || strings.ContainsAny(name, "\t\r\n") {
			return nil, errors.New("invalid context name")
		}
		if _, ok := c.Hosts[ctx.Host]; !ok {
			return nil, errors.New("context references an unknown host")
		}
		if _, ok := c.Credentials[ctx.Credentials]; !ok {
			return nil, errors.New("context references unknown credentials")
		}
	}
	return c, nil
}

func (c *Config) Select(name string) (Selection, error) {
	selection := Selection{Defaults: c.Defaults}
	if name == "" {
		name = c.CurrentContext
	}
	if name == "" {
		return selection, nil
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return selection, errors.New("selected context does not exist")
	}
	selection.Host = c.Hosts[ctx.Host]
	selection.Credentials = c.Credentials[ctx.Credentials]
	return selection, nil
}

// Resolve consults an env_file only for a missing env: reference. Plain values,
// process values and explicit CLI overrides do not touch unused files.
func (c *Config) Resolve(value string, credentials Credentials, lookup secret.LookupEnv) (string, error) {
	if !strings.HasPrefix(value, "env:") {
		return secret.Resolve(value, lookup)
	}
	name := strings.TrimPrefix(value, "env:")
	if _, ok := lookup(name); ok || credentials.EnvFile == "" {
		return secret.Resolve(value, lookup)
	}
	path := credentials.EnvFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(c.Path), path)
	}
	raw, err := readFile(path)
	if err != nil {
		return "", errors.New("cannot read credential env_file (maximum 1 MiB)")
	}
	values, err := godotenv.Parse(bytes.NewReader(raw))
	if err != nil {
		return "", errors.New("invalid credential env_file")
	}
	return secret.Resolve(value, func(name string) (string, bool) {
		if value, ok := lookup(name); ok {
			return value, true
		}
		value, ok := values[name]
		return value, ok
	})
}
