# Repository guidelines

winsh is a standalone, noninteractive WinRM CLI. Keep infrastructure examples
vendor-neutral and use example.com domains. Never commit credentials.

## Layout and checks

- main.go wires process context and streams; internal/cmd owns CLI behavior.
- internal/remote owns WinRM, NTLM and encoding; internal/secret reads passwords.
- Run `make check integration cross-build` before publishing changes.
- Tests requiring a real Windows endpoint use the integration build tag and
  explicit WINSH_TEST_ENDPOINT/WINSH_TEST_USER/WINSH_TEST_PASSWORD variables.
- Passwords are accepted only through environment variables or stdin, never a
  command-line value, config file, diagnostic trace, or cache.
- Never downgrade encrypted HTTP SOAP to unencrypted data, disable TLS
  verification, retry an uncertain remote command, or follow HTTP redirects.

## Releases

Use `./release.sh status`, then `./release.sh vMAJOR.MINOR.PATCH` from a clean,
up-to-date main branch. The script checks tests/builds and creates/pushes the tag;
GitHub Actions publishes the archives and checksums. Run the live Windows smoke
test before a release. No Helm chart, HTTP service, GitVerse mirror or Homebrew
publication is configured for this CLI yet.
