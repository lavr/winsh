package secret

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	lookup := func(name string) (string, bool) {
		return map[string]string{"PASS": "from-env", "EMPTY": ""}[name], name == "PASS" || name == "EMPTY"
	}
	for _, tt := range []struct {
		name, input, want string
		fail              bool
	}{
		{"plain", " test-secret ", " test-secret ", false},
		{"env", "env:PASS", "from-env", false},
		{"base64", "base64:0J/RgNC40LLQtdGCIPCfmIA=", "Привет 😀", false},
		{"literal prefix", "literal:env:PASS", "env:PASS", false},
		{"literal literal", "literal:literal:value", "literal:value", false},
		{"missing", "env:MISSING", "", true},
		{"empty env", "env:EMPTY", "", true},
		{"bad env", "env:", "", true},
		{"bad base64", "base64:not-a-secret!", "", true},
		{"empty", "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.input, lookup)
			if (err != nil) != tt.fail || got != tt.want {
				t.Errorf("value matches=%v err=%v", got == tt.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "not-a-secret") {
				t.Fatal("value leaked")
			}
		})
	}
}
