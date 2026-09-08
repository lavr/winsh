# Architecture

`main.go` supplies process streams and cancellation to `internal/cmd`.
The CLI validates command boundaries, source selection and flags before loading
a password through `internal/secret`. A `remote.Request` is executed with a
single overall deadline. CLI tests replace only the remote execution boundary.

`internal/remote` uses the go-winrm fork's SOAP request builders and PowerShell
encoding. The module is replaced using its declared historical name,
`github.com/JohanVanosmaelAcerta/go-winrm`, pinned to commit
`2957497186ed0e2f08e064a3f608a7ca208c552e`. This resolves its self-imports of
`masterzen/winrm` without mixing copies of the protocol code.

The wrapper owns HTTP rather than using the library's default transport:

- Context covers connection establishment, authentication and response reading.
- Every exchange establishes an NTLM session on one TCP connection, with fresh
  session keys. Replacing the connection or replaying a request is forbidden.
  This costs extra round trips but avoids unsafe reuse of NTLM sequence state.
- Authentication accepts NTLM or Negotiate HTTP scheme with an NTLMv2 token.
  It does not implement Kerberos/SPNEGO token negotiation.
- HTTP requires 128-bit NTLM signing/sealing and Extended Session Security.
  The response's signature and original length are checked; malformed framing,
  anonymous NTLM and plaintext downgrade are rejected.
- HTTPS uses verified TLS 1.2 or newer. Custom CA trust comes from the system.
  TLS channel binding is not implemented yet.
- HTTP proxies and redirects are disabled. Wire dumps are never logged.
- Response bodies are limited to 4 MiB; malformed NTLM AV fields are rejected
  before being passed to the authentication library.

Execution is sequential: create shell, execute, send stdin EOF, receive until
finished, delete shell. WSMan OperationTimeout faults during receive mean
"no output yet"; the overall context still bounds the loop. Delete uses an
independent five-second context, including when execution was canceled.

Responses use a small namespace-aware encoding/xml parser. It validates output
base64 and exit codes and propagates local write failures. This avoids the
upstream receive parser's ignored errors. Command text is protected against a
CDATA closing sequence in the upstream request builder. Local shells are never
invoked by the program.

PowerShell disables profiles, prompts and progress records, enables terminating
errors and configures UTF-8 console output. Script text remains under the
caller's control; use explicit `exit $LASTEXITCODE` when propagating a native
program's exit code from a larger PowerShell script.
