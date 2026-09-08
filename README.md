# winsh

[![Test](https://github.com/lavr/winsh/actions/workflows/test.yml/badge.svg)](https://github.com/lavr/winsh/actions/workflows/test.yml)

Run Windows commands and PowerShell scripts over WinRM from one standalone
binary. Domain NTLM, encrypted HTTP messages, verified HTTPS, separate output
streams, and remote exit status. No Python, Ansible, OpenSSL configuration or
runtime installation on the machine running winsh.

**Status:** v0.1 development. Automated protocol and CLI tests are included;
real Windows validation is opt-in. No stable release has been published yet.

## Build

Requires Go 1.26.6 or newer to build; the resulting binary needs no Go installation.

```sh
git clone https://github.com/lavr/winsh.git
cd winsh
make build
./dist/winsh --help
```

`make cross-build` produces static (CGO disabled) binaries for Linux amd64/arm64,
macOS arm64 and Windows amd64. Future tagged releases will provide archives and
SHA256SUMS on the [Releases page](https://github.com/lavr/winsh/releases).

## Run a command

Provide `WINRM_PASSWORD` through your environment or secret manager, then:

```sh
winsh run server.example.com --user 'EXAMPLE\alice' -- hostname
winsh run server.example.com --user alice --domain EXAMPLE -- 'dir "C:\Program Files"'
winsh ps server.example.com --user 'alice@example.com' -- 'Get-Service | Select-Object -First 5'
winsh ps server.example.com --user 'EXAMPLE\alice' -f examples/system-info.ps1
```

The password is never a flag value. `--password-env NAME` selects another
variable. `--password-stdin` reads the first stdin line without a prompt, for
example when connecting a secret manager's stdout to winsh's stdin. Credentials
are not cached or written to disk. Nothing from stdin is forwarded remotely.

Everything after `--` is remote shell text, joined with spaces. Quote the whole
command when Windows quoting or PowerShell expressions matter. Remote shell
metacharacters (`&`, `|`, redirection) are intentional; winsh never runs them in
a local shell. Do not interpolate untrusted values into shell text.

WinRS launches through cmd.exe, which limits command length. winsh conservatively
allows 8,000 UTF-16 code units for `run` and 8,000 characters for the **encoded**
PowerShell invocation (roughly 2.7 KiB of script). Larger input fails locally;
`-f` does not bypass this limit.

## Through an SSH tunnel

Create and manage the tunnel yourself:

```sh
ssh -N -L 15985:server.example.com:5985 jump.example.com
```

In another terminal with the password supplied through the environment:

```sh
winsh run --endpoint http://127.0.0.1:15985/wsman \
  --user 'EXAMPLE\alice' -- hostname
```

NTLM uses the configured account/domain, so the endpoint may be localhost.
HTTP messages use NTLMv2 signing and sealing with a 128-bit negotiated key.
There is no fallback to unencrypted SOAP and no need to enable
`AllowUnencrypted` on Windows. The target must already have a WinRM listener
and permit the account to use remote shells.

For HTTPS, certificates are verified using system trust. `--target-host`
selects the certificate name when connecting through a tunnel. There is no
`--insecure` switch. Kerberos and TLS channel binding are not implemented in
v0.1; servers requiring Strict CBT need a later version.

## Output and status

Remote stdout and stderr stream to their corresponding local streams.
PowerShell scripts are UTF-8 files/text encoded as UTF-16LE for execution;
PowerShell console output is configured as UTF-8. Windows PowerShell may still
format error records as CLIXML on stderr; v0.1 preserves those records.

`run` leaves bytes unchanged by default. Use `--codepage 866` or
`--codepage 1251` to decode a known console encoding to UTF-8; `utf-8` explicitly
selects pass-through. There is no automatic codepage probe in v0.1.

Remote exit status is returned directly. Local failures print `winsh:` on
stderr and use 201 (input), 202 (transport/protocol/output/cleanup), 203 (timeout),
or 204 (cancellation). These codes can overlap with Windows application codes.
On Unix, only the low eight bits of a Windows exit status are representable.
`--timeout 60s` bounds execution; shell cleanup has a separate five-second
budget. A broken connection can prevent cleanup, so cancellation cannot
promise that all remote child processes have stopped.

## Development

```sh
make check             # formatting, vet, unit tests, race detector
make integration       # live Windows test skips unless explicitly configured
make cross-build
```

See [testing](docs/testing.md), [architecture](docs/architecture.md), and
[roadmap](docs/roadmap.md). Releases use `./release.sh status` then
`./release.sh v0.1.0` from a clean main branch, with live test credentials in
the environment. The script pushes a tag and GitHub Actions builds the release.

## License and credits

Apache-2.0. Uses the [JohanVanosmael/go-winrm fork](https://github.com/JohanVanosmael/go-winrm)
of [masterzen/winrm](https://github.com/masterzen/winrm) for SOAP request builders
and PowerShell encoding, and [bodgit/ntlmssp](https://github.com/bodgit/ntlmssp) for
NTLMv2 authentication and session cryptography. Repository layout and build/release
conventions are based on [express-botx](https://github.com/lavr/express-botx).
