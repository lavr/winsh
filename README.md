# winsh

[![Test](https://github.com/lavr/winsh/actions/workflows/test.yml/badge.svg)](https://github.com/lavr/winsh/actions/workflows/test.yml)

Run Windows commands and PowerShell scripts over WinRM from one standalone
binary. Domain NTLM, encrypted HTTP messages, verified HTTPS, separate output
streams, and remote exit status. No Python, Ansible, OpenSSL configuration or
runtime installation on the machine running winsh.

**Status:** v0.1 development. Validated over encrypted HTTP on Windows Server
2016 and 2019. Automated protocol and CLI tests are included; live tests remain
opt-in. No stable release has been published yet.

## Build

Requires Go 1.26.6 or newer to build; the resulting binary needs no Go installation.

```sh
git clone https://github.com/lavr/winsh.git
cd winsh
make build
./dist/winsh --help
```

`make cross-build` produces static (CGO disabled) client binaries for Linux
amd64/arm64 and macOS arm64. Windows clients are unsupported; winsh connects
to a Windows server over WinRM. Future tagged releases will provide archives
and SHA256SUMS on the [Releases page](https://github.com/lavr/winsh/releases).

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

## Reuse command connections

On Linux and macOS, `run` and `ps` can share authenticated NTLM connections
across separate winsh invocations. Control mode is off by default:

```sh
winsh run server.example.com --user 'EXAMPLE\alice' --control=auto -- hostname
winsh ps server.example.com --user 'EXAMPLE\alice' --control=auto -- 'Get-Date'
winsh control check server.example.com --user 'EXAMPLE\alice'
winsh control exit server.example.com --user 'EXAMPLE\alice'
```

The first `--control=auto` call starts a local master and reads the normal
password source once. Later calls with the same endpoint, account, TLS target
and trust settings use that master without reading password stdin or resolving
the configured password again. The master retains authenticated NTLM sessions,
not the resolved password. While idle it sends a WS-Management Identify on
each connection every 30 seconds, so the server does not close them; if that
fails, the master finishes any active command and exits, and the next call
starts a new master. Each command still gets its own remote Shell and
exit status; PowerShell variables, working directory and processes do not
persist between calls. `--control=off` forces standalone execution.

The master exits after five idle minutes by default. Use
`--control-persist=10m` (from one second to one hour) or YAML
`defaults.control_persist` to change this; later calls must use the same
duration. `defaults.control_master: auto` enables reuse for a context.
`--control-path` or `defaults.control_path` selects a Unix socket inside a
user-owned mode-0700 directory. The socket is mode 0600. Processes running as
the same local user can issue commands through it, so protect that account as
you would an SSH ControlMaster socket. `control check` and `control exit` use
the same target options and never read a password. `exit` waits for an active
command and rejects commands still waiting in the queue.
`SSL_CERT_FILE`, `SSL_CERT_DIR` and relevant x509 `GODEBUG` settings are part
of master identity; restart the master after changing a CA file's contents
at the same path. Explicit CA sources replace system roots for that master.

One command runs at a time and up to 16 others can wait. The command timeout
includes master startup and queue time; cleanup has a separate five-second
budget. A connection or local reply lost after remote dispatch has an uncertain
outcome and is never replayed automatically. Only `not-started` guarantees that
the command never ran; after any other control failure, including
`unavailable`, it may have done part of its work, so do not treat the failure
as permission to repeat it. If the command connection fails,
the master tries Signal/Delete on a separate authenticated cleanup connection.
`upload` and `download` do not use the command master in this version.

## Transfer a file

```sh
winsh upload server.example.com --user 'EXAMPLE\alice' -- ./artifact.bin 'C:\Temp\artifact.bin'
winsh download --context lab --force -- 'C:\Temp\artifact.bin' ./artifact.bin
```

`upload` and `download` take exactly two literal file paths after `--` in the
order shown above. Quote Windows paths for your local shell. Paths cannot be
`-`; stdin and stdout are reserved for credentials and status. `-f` and
`--codepage` and control options apply to command execution only. A connection
can come from a positional host, an endpoint, or the selected configuration
context.

The destination parent directory must already exist. Remote paths must be
absolute drive-rooted paths (for example, `C:\Temp\file.bin`); UNC and device
paths, alternate data streams and wildcards are not supported. Files are streamed
through WinRM, checked by byte count and SHA-256, and committed through a
temporary file in the destination directory. The default refuses an existing
destination; `--force` allows replacement. Retry without `--force` first when
the final commit outcome is unknown. Inspect the destination and its checksum
before deciding whether to overwrite. Transfer does not resume an interrupted
stream, preserve timestamps or access control lists, or copy directories.
Cleanup is bounded, so a lost connection can leave a temporary artifact; the
error lists known artifact paths.

Progress and errors go to stderr. A completed transfer prints one stdout line
with direction, byte count and SHA-256. Upload and download use one overall
30-minute timeout unless `--timeout` or YAML `defaults.timeout` sets another
duration. A CLI timeout takes precedence over YAML. `run` and `ps` retain
their 60-second default. Transfer has been tested from a macOS arm64 client to
Windows Server 2016 over NTLM-encrypted HTTP, including 100 MiB and 200 MiB
round-trips. An amd64 Linux client also completed small upload and download
checks with independent destination SHA-256 verification. File transfer from
Linux arm64, over HTTPS, or to Server 2019 remains unvalidated;
cross-builds alone do not establish compatibility.

## Configuration and contexts

Copy [examples/config.yaml](examples/config.yaml) to your own configuration:

```sh
export WINSH_CONFIG=/path/to/winsh.yaml
winsh ps -- 'Get-Date'
winsh --context stage ps -- 'hostname'
winsh config get-contexts
winsh config use-context stage
winsh config current-context
winsh config view
```

Commands remain explicit (`ps` or `run`); `--` separates remote code from CLI
options. There is no `default_command`. Hosts and credentials can come from the
selected context. A positional host can name a configured host or a network host.

Config discovery: `--config PATH`, then `WINSH_CONFIG`, then `./winsh.yaml`, then
`$XDG_CONFIG_HOME/winsh/config.yaml` (or `~/.config/winsh/config.yaml`). Missing
explicit files are errors. Without a config, flag-only usage works as before.
`--config` and `--context` work before or after the command. Explicit connection
flags override context settings; `--context` overrides `current_context`.

Both `user` and `password` accept:

| YAML value | Meaning |
| --- | --- |
| `"alice"` | Plain text |
| `"env:WINDOWS_PASSWORD"` | Environment variable |
| `"base64:YWxpY2U="` | Standard Base64 of UTF-8 text (`alice`) |
| `"literal:env:example"` | Literal text `env:example` |

Prefixes are resolved once. Base64 is encoding, not encryption. An optional
credential `env_file` is parsed as dotenv data, without executing shell commands;
relative paths are resolved against the configuration file. Process variables take
precedence, including explicitly empty values (which cause a credential error).
Quote credential values in YAML to preserve their intended text.

`--user` supplies a literal override. `--password-env NAME` reads that process
variable and `--password-stdin` reads stdin; both bypass the configured password
and its env_file. Configuration management does not resolve credential references.
`config view` hides every stored password; `use-context` preserves comments and
credential sources, writes atomically and uses owner-only permissions on Unix.

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

`run` requests UTF-8 from WinRS and leaves the returned bytes unchanged by
default. `--codepage 866` or `--codepage 1251` requests that WinRS output encoding
and decodes it to UTF-8 locally. `raw` and `utf-8` retain the default UTF-8 WinRS
encoding with pass-through. There is no automatic codepage probe in v0.1.

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
make integration       # live Windows tests skip unless explicitly configured
make integration-transfer # extended live transfer tests, including 100/200 MiB
make cross-build
```

Live tests require `WINSH_TEST_ENDPOINT`, `WINSH_TEST_USER`, and
`WINSH_TEST_PASSWORD`. The transfer suite creates a unique directory below the
remote account's temporary directory and removes only that directory. The
extended target opts in to long measurements and fault injection; it is not
part of the routine 120-second integration gate. Missing credentials produce
skips, which do not establish compatibility.

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
