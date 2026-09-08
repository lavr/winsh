package remote

import (
	"encoding/base64"
	"golang.org/x/text/encoding/unicode"
	"strings"
	"testing"
)

func TestPowerShellEncoding(t *testing.T) {
	command, err := PowerShell("Write-Output 'Привет 😀'")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(command, prefix) {
		t.Fatalf("missing noninteractive flags: %s", command)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(command, prefix))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(b)
	if err != nil || !strings.HasSuffix(string(decoded), "Write-Output 'Привет 😀'") || !strings.Contains(string(decoded), "UTF8Encoding") {
		t.Fatalf("wrong script: %q (%v)", decoded, err)
	}
	if _, err := PowerShell(string([]byte{255})); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestEndpoint(t *testing.T) {
	for _, tt := range []struct {
		name, host, endpoint, want string
		fail                       bool
	}{
		{name: "host", host: "server.example", want: "http://server.example:5985/wsman"},
		{name: "tls", endpoint: "https://server.example", want: "https://server.example:5986/wsman"},
		{name: "tunnel", endpoint: "http://127.0.0.1:15985/wsman", want: "http://127.0.0.1:15985/wsman"},
		{name: "ipv6", host: "::1", want: "http://[::1]:5985/wsman"},
		{name: "credentials", endpoint: "http://u:test-secret@server:5985/wsman", fail: true},
		{name: "query", endpoint: "http://server/wsman?password=test-secret", fail: true},
		{name: "bad port", endpoint: "http://server:0/wsman", fail: true},
		{name: "path", endpoint: "http://server/other", fail: true},
		{name: "scheme", endpoint: "ftp://server", fail: true},
		{name: "empty", fail: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Endpoint(tt.host, tt.endpoint)
			if (err != nil) != tt.fail || got != tt.want {
				t.Errorf("got %q, %v; want %q failure=%v", got, err, tt.want, tt.fail)
			}
			if err != nil && strings.Contains(err.Error(), "test-secret") {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestRejectOversizedPowerShellCommand(t *testing.T) {
	if _, err := PowerShell(strings.Repeat("x", 5000)); err == nil {
		t.Fatal("accepted encoded command above cmd.exe 8191-character limit")
	}
}
