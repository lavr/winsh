# Architecture

`main.go` supplies process streams and cancellation to `internal/cmd`.
The CLI validates command boundaries, source selection and flags before loading
a password through `internal/secret`. Standalone `run` and `ps` call
`remote.Run`; control mode routes them through `internal/control`.
`upload` and `download` call `remote.Transfer`. Each invocation has one overall
deadline. Password references are resolved only for standalone execution or
when a new control master must authenticate; a reused master and the control
check/exit commands do not read the password. Transfer commands use the same
CLI target and credential precedence, then require two literal paths after `--`.

The client runs on Linux and macOS. Local upload source checks and download
stage commits use Unix file operations; Windows path rules still apply to the
remote endpoint.

`internal/remote` uses the go-winrm fork's SOAP request builders and PowerShell
encoding. The module is replaced using its declared historical name,
`github.com/JohanVanosmaelAcerta/go-winrm`, pinned to commit
`2957497186ed0e2f08e064a3f608a7ca208c552e`. This resolves its self-imports of
`masterzen/winrm` without mixing copies of the protocol code.

The wrapper owns HTTP rather than using the library's default transport:

- Context covers connection establishment, authentication and response reading.
- The anonymous discovery connection may close after HTTP 401. Type-1 begins
  on a fresh connection; the following authentication and SOAP exchange must
  stay on that connection.
- Standalone commands and transfers establish a fresh NTLM session for every
  SOAP exchange. Control mode authenticates one pinned command connection and
  one pinned cleanup connection before it becomes ready. Each serial exchange
  advances the same connection's NTLM signing and sealing sequence. A failed
  SOAP exchange is never replayed. Transient failures during empty-body NTLM
  negotiation can be retried at most twice on a fresh connection, before SOAP
  is dispatched.
- Authentication accepts NTLM or Negotiate HTTP scheme with an NTLMv2 token.
  It does not implement Kerberos/SPNEGO token negotiation.
- HTTP requires 128-bit NTLM signing/sealing and Extended Session Security.
  The response's signature and original length are checked; malformed framing,
  anonymous NTLM and plaintext downgrade are rejected.
- HTTPS uses verified TLS 1.2 or newer. Without explicit CA settings, roots
  come from the OS. Setting `SSL_CERT_FILE` or `SSL_CERT_DIR` uses those
  configured roots instead.
  TLS channel binding is not implemented yet.
- HTTP proxies and redirects are disabled. Wire dumps are never logged.
- Response bodies are limited to 4 MiB; malformed NTLM AV fields are rejected
  before being passed to the authentication library.

For `run` and `ps`, execution opens a shell, starts the command, sends stdin
EOF, receives until completion, then deletes the shell. The shared session
helper polls Receive in a background goroutine; transfer can send file chunks
while polling continues. WSMan OperationTimeout faults during receive mean
"no output yet"; the overall context still bounds the loop. Shell deletion
uses an independent five-second cleanup context, including after cancellation.

Control mode uses a separate local master process. A private inherited pipe
passes the initial password to that child; neither argv, its environment nor
the public Unix socket carries a password field. The child authenticates both
NTLM connections, then drops password-bearing request data. It listens on a
mode-0600 Unix socket inside a user-owned mode-0700 directory and holds a
per-path lock across its lifetime. The socket identity includes endpoint,
account, TLS target and effective CA/x509 settings. A connected client sends
versioned frames bounded to 64 KiB; stdout and stderr are separate streams.
One command executes at a time, with 16 waiting clients. An absolute deadline
covers bootstrap, queue and execution; a separate five-second budget covers
Signal Terminate and Shell Delete. Each command has a distinct remote Shell
and Command ID. A broken command connection ends the master after cleanup,
and a lost post-dispatch reply is reported as an uncertain remote state rather
than retried. The cleanup connection remains available after command-lane
failure or caller cancellation. Idle masters exit after the configured positive
duration; `control exit` stops admission and waits for active work.

`remote.Transfer` streams one regular file through WinRM. Upload sends bounded
Base64 lines to a PowerShell receiver and compares byte count and SHA-256 with
the receiver's control record before committing a stage in the destination
directory. Download decodes the sender's output into a local stage, verifies
the count and hash, then commits the stage. The default refuses an existing
destination; `--force` permits replacement. A lost finalization response is
reported as an unknown outcome, so the client does not replay a possibly
completed commit. Cleanup is bounded and reports known leftover artifacts.

Responses use a small namespace-aware encoding/xml parser. It validates output
base64 and exit codes and propagates local write failures. This avoids the
upstream receive parser's ignored errors. Command text is protected against a
CDATA closing sequence in the upstream request builder. Local shells are never
invoked by the program.

PowerShell disables profiles, prompts and progress records, enables terminating
errors and configures UTF-8 console output. Script text remains under the
caller's control; use explicit `exit $LASTEXITCODE` when propagating a native
program's exit code from a larger PowerShell script.

For explicit CP866/CP1251, the wrapper sets WINRS_CODEPAGE as well as the local
decoder; changing cmd.exe with chcp alone does not set the WinRS stream encoding.
