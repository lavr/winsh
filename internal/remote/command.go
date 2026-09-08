// Package remote implements WinRM execution and its HTTP authentication boundary.
package remote

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	winrm "github.com/masterzen/winrm"
)

type Request struct {
	Endpoint, TargetHost, User, Password, Command, Codepage string
	PowerShell                                              bool
}

func Endpoint(host, endpoint string) (string, error) {
	if endpoint == "" {
		if host == "" || strings.ContainsAny(host, "/?#@ \t\r\n") {
			return "", errors.New("provide a host or --endpoint")
		}
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return "", errors.New("use --endpoint to specify a port")
		}
		endpoint = "http://" + net.JoinHostPort(host, "5985") + "/wsman"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return "", errors.New("invalid endpoint; use an HTTP(S) URL without credentials, query or fragment")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("endpoint must use http or https")
	}
	if u.Path != "" && u.Path != "/wsman" {
		return "", errors.New("endpoint path must be /wsman")
	}
	port := u.Port()
	if port == "" {
		port = "5985"
		if u.Scheme == "https" {
			port = "5986"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid endpoint port")
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	u.Path = "/wsman"
	return u.String(), nil
}

func PowerShell(script string) (string, error) {
	if !utf8.ValidString(script) {
		return "", errors.New("PowerShell script must be UTF-8")
	}
	script = "$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $OutputEncoding = [Console]::OutputEncoding; " + script
	encoded := winrm.Powershell(script)
	if encoded == "" {
		return "", errors.New("cannot encode PowerShell script")
	}
	command := strings.Replace(encoded, "powershell.exe -EncodedCommand ", "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ", 1)
	if len(command) > 8000 {
		return "", errors.New("encoded PowerShell command exceeds the 8000-character limit; use a smaller script")
	}
	return command, nil
}

// Command reserves room below cmd.exe's 8191 UTF-16-code-unit limit for WinRS.
func Command(text string, powershell bool) (string, error) {
	if powershell {
		return PowerShell(text)
	}
	if len(utf16.Encode([]rune(text))) > 8000 {
		return "", errors.New("cmd command exceeds the 8000-character limit")
	}
	return text, nil
}
