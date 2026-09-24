# Roadmap

- **Current development:** run, ps, upload, download, NTLM, password env/stdin,
  endpoint/tunnel support, static binaries, explicit codepage decoding,
  bounded execution and cleanup, and opt-in command connection reuse on
  Linux/macOS. File transfer was implemented ahead of its original v0.3
  target; its release version is not assigned yet. Transfer connection reuse
  remains separate work.

Future ideas, without assigned release versions:

- Optional host inventory, probe, JSON output and service operations.
- Kerberos, TLS channel binding and broader domain compatibility.
- Optional SMB file transport.

Built-in SSH orchestration, pass-the-hash, interactive shells and multi-host
execution are outside the current scope. Unsupported options fail explicitly.
