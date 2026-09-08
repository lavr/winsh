package secret

import (
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	for _, tt := range []struct {
		name, env, input, value, want string
		stdin, fail                   bool
	}{
		{name: "environment", env: "PASS", value: " env secret ", want: " env secret "},
		{name: "line", stdin: true, input: " space secret \r\nremaining", want: " space secret "},
		{name: "last line", stdin: true, input: "test-secret", want: "test-secret"},
		{name: "empty env", env: "PASS", fail: true},
		{name: "empty stdin", stdin: true, fail: true},
		{name: "bounded", stdin: true, input: strings.Repeat("x", 65537), fail: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Read(tt.env, tt.stdin, strings.NewReader(tt.input), func(string) string { return tt.value })
			if (err != nil) != tt.fail || got != tt.want {
				t.Errorf("unexpected result: error=%v, value matches=%v", err, got == tt.want)
			}
		})
	}
}
