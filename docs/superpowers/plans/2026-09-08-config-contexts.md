# Configuration and contexts implementation plan

Execute inline using executing-plans and test-driven-development.
Spec: ../specs/2026-09-08-config-contexts-design.md

- [ ] Add tested secret.Resolve(string, LookupEnv) for env/base64/literal/plain.
- [ ] Add internal/config types, strict bounded YAML load/discovery, lazy dotenv
  resolution, selected host/credentials/defaults, redacted view and atomic
  use-context preserving other fields. Test malformed and conflicting inputs.
- [ ] Refactor cmd parsing to separate flags from configuration resolution and
  validate the effective request only after overrides. Keep -- boundaries and
  flag-only compatibility; test config management without network or secrets.
- [ ] Update examples, docs and repository rules; run make check integration
  cross-build, NTLM interop and govulncheck. Verify with real Windows using a
  private config, inspect public files/history, publish and verify GitHub CI.
