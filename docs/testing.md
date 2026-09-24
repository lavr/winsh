# Testing

`make check` runs formatting checks, vet, unit tests and the race detector.
Unit tests use synthetic credentials only. They cover command parsing, Unicode,
password sources, codepages, SOAP shell lifecycle, exit codes, cleanup contexts,
TLS verification, redirects, deadlines, NTLM challenge validation, and encrypted
message framing. Fuzz targets cover untrusted Type2 and multipart data.
Transfer unit tests also cover staging and commits, byte framing, SHA-256
records, path validation, cancellation, uncertain finalization and cleanup.

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

Run `make integration`. Without the endpoint, live tests skip. With an endpoint,
missing credentials fail the command smoke test. That smoke test executes
echo/Write-Output, stderr output, and explicit exit codes. The opt-in transfer
round-trip and probe tests also run under this target: they create a unique
directory under the remote account's temporary directory, transfer synthetic
files, and remove that directory. They do not change WinRM configuration or
services. A skipped test does not establish compatibility.

`make integration-transfer` opts into the transfer fault suite and 100/200 MiB
round-trips; it can take longer than the routine integration target. Configure
the same explicit credentials and review the independent source/destination
SHA-256 checks. Test both HTTP with AllowUnencrypted disabled and HTTPS before
declaring a stable transfer release. Unit tests alone do not establish
compatibility with a real Windows installation.

Release automation deliberately requires these variables, preventing a skipped
Windows test from being mistaken for live validation.

## Live validation record

On 2026-09-08, Windows Server 2016 and 2019 passed HTTP NTLM tests with
AllowUnencrypted disabled: cmd/PowerShell, Unicode including supplementary
characters, separate stderr, nonzero exit statuses, script files, explicit
CP866 and execution timeout. The opt-in Go live suite passed on both versions.
For file transfer, a Windows Server 2016 endpoint passed the small, fault and
100/200 MiB live suites over encrypted HTTP. A Linux amd64 client also passed
small upload and download checks with independent destination hashes. File
transfer from Linux arm64, over HTTPS, or to Server 2019 remains unvalidated.
HTTPS remains covered by local TLS tests; no live HTTPS listener
was tested.

Client builds and CI cover Linux amd64/arm64 and macOS arm64. Windows clients
are unsupported; the real Windows endpoint in the live suite is the server.
