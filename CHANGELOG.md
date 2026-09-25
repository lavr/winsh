# Changelog

## v0.2.0 — 2026-09-25

- Add `upload` and `download`: streaming WinRM file transfer with SHA-256
  verification, progress, staged atomic commits and explicit handling of
  uncertain finalization.
- Stream transfer data over two persistent NTLM connections, one for input
  and one for output, instead of authenticating every chunk. A 100 MiB upload
  ran about twice as fast on the test route; download changed little. Upload
  stops sending as soon as the remote receiver exits early.
- Add `--control=auto` for `run` and `ps`: a local master keeps authenticated
  NTLM connections so later calls do not read the password again, with
  `control check` / `control exit`, a bounded command queue, idle keepalive
  and a separate cleanup connection. After Ctrl-C or timeout the client
  reports the master's cleanup result.
- Retry transient failures during the empty-body NTLM handshake before a SOAP
  request is sent; never retry an uncertain remote command or transfer chunk.
- **Breaking:** clients are built and released for Linux and macOS only.
  Windows client binaries and archives are no longer published; Windows
  remains the remote WinRM server.

## v0.1.0 — 2026-09-08

- Initial Go CLI with run and ps, NTLMv2, encrypted HTTP and verified HTTPS.
- Domain credentials through environment/stdin, manual endpoint and SSH tunnels.
- Separate output streams, remote exit status, timeout and cancellation cleanup.
- UTF-8 PowerShell and optional CP866/CP1251 decoding for cmd output.
- Tests, four-platform static builds and GitHub Actions release workflow.
- Cancel a blocked password read on Ctrl-C, including real OS stdin pipes.
- Handle HTTP.sys closing the anonymous authentication-discovery connection.
- Set WinRS output encoding when using --codepage 866/1251.
- Validate encrypted HTTP execution against Windows Server 2016 and 2019.
