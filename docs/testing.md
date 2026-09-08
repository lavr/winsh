# Testing

`make check` runs formatting checks, vet, unit tests and the race detector.
Unit tests use synthetic credentials only. They cover command parsing, Unicode,
password sources, codepages, SOAP shell lifecycle, exit codes, cleanup contexts,
TLS verification, redirects, deadlines, NTLM challenge validation, and encrypted
message framing. Fuzz targets cover untrusted Type2 and multipart data.

```sh
go test ./internal/remote -run='^$' -fuzz=FuzzChallenge -fuzztime=10s
go test ./internal/remote -run='^$' -fuzz=FuzzUnseal -fuzztime=10s
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Independent NTLM interoperability test

`python scripts/ntlm-smoke.py --binary dist/winsh` runs a local HTTP WSMan fixture
using pyspnego 0.12.2 as the independent NTLM server. It checks authentication,
sealing and signatures in both directions, the decoded Unicode PowerShell
command, distinct output streams, exit status and shell cleanup. The fixture
creates a temporary file containing synthetic test credentials and removes it
on exit. Python/pyspnego are development test dependencies only; GitHub Actions
runs this test separately from the Go tests.

## Real Windows smoke test

Configure these environment variables using your usual credential mechanism:

| Variable | Purpose |
|---|---|
| `WINSH_TEST_ENDPOINT` | Complete HTTP(S) WinRM endpoint, including tunnel port |
| `WINSH_TEST_USER` | Test account, with domain or UPN if applicable |
| `WINSH_TEST_PASSWORD` | Password value, supplied through the environment |
| `WINSH_TEST_TARGET_HOST` | Optional TLS certificate name for a tunnel |

Run `make integration`. Without the endpoint, the Windows test explicitly skips.
With an endpoint, missing credentials fail the test. It executes only echo/
Write-Output, stderr output, and explicit exit codes. It does not change WinRM
configuration, services or files. Test both HTTP with AllowUnencrypted disabled
and HTTPS before declaring a stable release. Unit tests alone do not establish
compatibility with a real Windows installation.

Release automation deliberately requires these variables, preventing a skipped
Windows test from being mistaken for live validation.

## Live validation record

On 2026-09-08, Windows Server 2016 and 2019 passed HTTP NTLM tests with
AllowUnencrypted disabled: cmd/PowerShell, Unicode including supplementary
characters, separate stderr, nonzero exit statuses, script files, explicit
CP866 and execution timeout. The opt-in Go live suite passed on both versions.
HTTPS remains covered by local TLS tests; no live HTTPS listener was tested.
