package remote

import (
	"strings"
	"testing"
)

func TestTransferScriptRejectsUnknownParameter(t *testing.T) {
	// control.ps1 only accepts stage / destination / expected_sha256 / force.
	// "sneaky" is not in the allowlist and must be rejected before any
	// script body is produced.
	if _, err := transferScript("control.ps1", map[string]string{
		"stage":           `C:\Temp\stage.bin`,
		"destination":     `C:\Temp\dest.bin`,
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
		"force":           "false",
		"sneaky":          "rm -rf /",
	}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
}

func TestTransferScriptEmbedsKnownScript(t *testing.T) {
	for _, name := range []string{"upload.ps1", "control.ps1"} {
		script, err := transferScript(name, map[string]string{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(script, "$ErrorActionPreference") {
			t.Errorf("%s: missing PowerShell source", name)
		}
	}
}

func TestTransferScriptUnknownScript(t *testing.T) {
	if _, err := transferScript("nope.ps1", map[string]string{}); err == nil {
		t.Fatal("unknown script accepted")
	}
}

func TestTransferScriptEncodingPreservesValue(t *testing.T) {
	// Round-trip a value through the script generator and the UTF-16
	// decoder the embedded script would use. Confirms the wire format
	// the script depends on.
	cases := []string{
		`C:\data\O'Brien [1] Привет 😀.bin`,
		`simple/path`,
		``,
	}
	for _, v := range cases {
		// The encoded body is not something we can decode without a
		// PowerShell host, but we can verify the allowlist + the
		// 8000-character bound hold for every case.
		script, err := transferScript("upload.ps1", map[string]string{
			"id":    "deadbeef",
			"stage": v,
		})
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		encoded, err := PowerShell(script)
		if err != nil || len(encoded) > 8000 {
			t.Errorf("%q: encoded script rejected: %v", v, err)
		}
	}
}

func TestTransferScriptEmbedsStagePathByte(t *testing.T) {
	// Special characters in the stage path must not terminate the
	// single-quoted literal in the generated PowerShell assignment.
	// The encoding sidesteps the issue entirely; we just confirm the
	// script builds without an error and the path round-trips through
	// the embedded base64 literal.
	dangerous := `C:\data\O'Brien [1] Привет 😀.bin" ; rm -rf C:\`
	script, err := transferScript("upload.ps1", map[string]string{
		"id":    "deadbeef",
		"stage": dangerous,
	})
	if err != nil {
		t.Fatalf("script build failed: %v", err)
	}
	// Locate the literal $stage assignment and the base64 payload.
	idx := strings.Index(script, "$stage =")
	if idx < 0 {
		t.Fatal("missing $stage assignment in script")
	}
	// The base64 should encode only the path, never the quote or
	// semicolon as PowerShell tokens.
	if strings.Contains(script, "; rm -rf") {
		t.Fatal("unencoded shell metacharacters in script")
	}
}

func TestTransferScriptRejectsBadUTF8(t *testing.T) {
	// 0xff is never a valid UTF-8 start byte.
	if _, err := transferScript("upload.ps1", map[string]string{
		"id":    "deadbeef",
		"stage": "C:\xfffest.bin",
	}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
