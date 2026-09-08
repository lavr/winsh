# Roadmap

- **v0.1:** run, ps, NTLM, password env/stdin, endpoint/tunnel support, static
  binaries, explicit codepage decoding, bounded execution and cleanup.
- **v0.2:** optional host inventory, probe, JSON output, service operations.
- **v0.3:** chunked file transfer with SHA-256 verification and progress.
- **v0.4:** Kerberos, TLS channel binding and broader domain compatibility.
- **v0.5:** optional SMB file transport.

No built-in SSH orchestration, pass-the-hash, interactive shell or multi-host
execution is part of v0.1. Unsupported options fail explicitly.
