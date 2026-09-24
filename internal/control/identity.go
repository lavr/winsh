// Package control owns local command-master identity and IPC.
package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lavr/winsh/internal/remote"
)

type Settings struct {
	Mode, Path string
	Persist    time.Duration
}

// Identity identifies a reusable authenticated master without password data.
// TrustKey captures the process settings that affect certificate validation.
type Identity struct {
	Endpoint, User, TargetHost, TrustKey string
}

func (i Identity) Key() string {
	canonical := i.canonical()
	data, _ := json.Marshal([5]string{canonical.Endpoint, canonical.User, canonical.TargetHost, canonical.TrustKey, "ntlm"})
	hash := sha256.Sum256(data)
	return "winsh-" + hex.EncodeToString(hash[:16])
}

func (i Identity) sameTarget(other Identity) bool {
	return i.canonical() == other.canonical()
}

func (i Identity) canonical() Identity {
	endpoint := i.Endpoint
	if normalized, err := remote.Endpoint("", endpoint); err == nil {
		endpoint = normalized
	}
	if u, err := url.Parse(endpoint); err == nil {
		u.Host = strings.ToLower(u.Host)
		endpoint = u.String()
	}
	return Identity{Endpoint: endpoint, User: i.User, TargetHost: strings.ToLower(i.TargetHost), TrustKey: i.TrustKey}
}

// TrustKey includes the effective environment settings relevant to Go's
// certificate roots and x509 behavior. Non-x509 GODEBUG options do not split
// masters. Changes to the contents of a CA file require master restart.
func TrustKey(getenv func(string) string) string {
	values := make(map[string]string)
	for _, item := range strings.Split(getenv("GODEBUG"), ",") {
		item = strings.TrimSpace(item)
		name, value, ok := strings.Cut(item, "=")
		if ok && strings.HasPrefix(name, "x509") {
			values[name] = value
		}
	}
	var x509 []string
	for name, value := range values {
		x509 = append(x509, name+"="+value)
	}
	sort.Strings(x509)
	data, _ := json.Marshal([3]string{effectiveCAFile(getenv("SSL_CERT_FILE")), effectiveCADirs(getenv("SSL_CERT_DIR")), strings.Join(x509, ",")})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func effectiveCAFile(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

func effectiveCADirs(paths string) string {
	if paths == "" {
		return ""
	}
	dirs := filepath.SplitList(paths)
	for i, dir := range dirs {
		dirs[i] = effectiveCAFile(dir)
	}
	return strings.Join(dirs, string(filepath.ListSeparator))
}
