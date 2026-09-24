package remote

import (
	"embed"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

//go:embed scripts/*.ps1
var scriptsFS embed.FS

// transferScript returns PowerShell source for the
// embedded script "name". Parameter values are emitted as UTF-16LE
// Base64 literals decoded inside PowerShell, so user-supplied paths and
// IDs never become executable syntax.
//
// Each script declares the parameter keys it accepts via its first
// "# @allow k1 k2 ..." header line; unknown keys are rejected up front
// so a typo does not silently pass through to the wrong variable.
//
// The resulting body is checked against PowerShell's 8000-character
// limit so a too-long script is rejected locally before it reaches the
// server.
func transferScript(name string, values map[string]string) (string, error) {
	allow, body, err := loadScript(name)
	if err != nil {
		return "", err
	}
	for k := range values {
		if _, ok := allow[k]; !ok {
			return "", fmt.Errorf("script %q: parameter %q not allowed", name, k)
		}
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'; ")
	b.WriteString("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); ")
	b.WriteString("$OutputEncoding = [Console]::OutputEncoding; ")
	for k, v := range values {
		if !utf8.ValidString(v) {
			return "", fmt.Errorf("script %q: parameter %q: invalid UTF-8", name, k)
		}
		encoded := base64.StdEncoding.EncodeToString(utf16LEBytes(v))
		fmt.Fprintf(&b, "$%s = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('%s')); ", k, encoded)
	}
	b.WriteString(body)
	// startSession invokes Command, which performs the one and only
	// -EncodedCommand conversion. Validate the resulting length here.
	if _, err := PowerShell(b.String()); err != nil {
		return "", err
	}
	return b.String(), nil
}

// utf16LEBytes returns s encoded as little-endian UTF-16 without a BOM.
// PowerShell's [Text.Encoding]::Unicode reads a BOM by default; the
// values emitted by transferScript have none, so the receiver gets the
// bytes verbatim.
func utf16LEBytes(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return buf
}

// loadScript reads scripts/<name>, parses the optional "# @allow k1 k2"
// header, and returns the allowlist and the script body with the
// header stripped.
func loadScript(name string) (map[string]struct{}, string, error) {
	data, err := scriptsFS.ReadFile("scripts/" + name)
	if err != nil {
		return nil, "", fmt.Errorf("script %q: %w", name, err)
	}
	body := string(data)
	allow := map[string]struct{}{}
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		first := body[:i]
		if strings.HasPrefix(first, "# @allow ") {
			for _, k := range strings.Fields(strings.TrimPrefix(first, "# @allow ")) {
				allow[k] = struct{}{}
			}
			body = body[i+1:]
		}
	}
	return allow, body, nil
}
