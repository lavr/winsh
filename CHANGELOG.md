# Changelog

## Unreleased

- Add streaming WinRM upload and download with SHA-256 verification, progress,
  staged commits and explicit handling of uncertain finalization.
- Retry transient failures during the empty-body NTLM handshake before a SOAP
  request is sent; never retry an uncertain remote command or transfer chunk.
- Initial Go CLI with run and ps, NTLMv2, encrypted HTTP and verified HTTPS.
- Domain credentials through environment/stdin, manual endpoint and SSH tunnels.
- Separate output streams, remote exit status, timeout and cancellation cleanup.
- UTF-8 PowerShell and optional CP866/CP1251 decoding for cmd output.
- Tests, four-platform static builds and GitHub Actions release workflow.

- Cancel a blocked password read on Ctrl-C, including real OS stdin pipes.
- Handle HTTP.sys closing the anonymous authentication-discovery connection.
- Set WinRS output encoding when using --codepage 866/1251.
- Validate encrypted HTTP execution against Windows Server 2016 and 2019.
