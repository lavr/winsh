# Configuration and contexts

Approved CLI design: keep explicit run/ps and the -- separator. No default_command.
YAML has current_context, defaults (auth, timeout), hosts (endpoint, target_host),
credentials (domain, env_file, user, password), contexts (host, credentials).
Both credential values accept env:NAME, base64:VALUE, literal:VALUE, or plain text.
Base64 is encoding only. This intentionally supersedes the initial design's ban
on passwords in configuration files. Password argv values remain unsupported.

Discovery: --config > WINSH_CONFIG > ./winsh.yaml > $XDG_CONFIG_HOME/winsh/config.yaml
(or ~/.config/winsh/config.yaml). An explicitly named missing file is an error;
absence of all optional files preserves the original flag-only CLI.
Flags --config and --context work before or after run/ps/config, but never parse
anything after --. Context selection is --context > current_context. Flag values
win over the selected context and defaults. A positional host can name a configured
host or a literal hostname. Direct --endpoint overrides either.

Only env: references read the environment/env_file. An explicitly set empty
process variable remains empty and fails credential validation; it must not fall
back to a file unexpectedly. Relative env_file paths are relative to the resolved
config file. dotenv is parsed as data, never sourced, and never mutates os.Environ.
Explicit --user bypasses configured user resolution; --password-env/--password-stdin
bypass configured password resolution. Missing effective passwords fail locally.

config get-contexts lists names and references, sorted, marking current context.
config current-context prints its name. config view prints YAML with all password
fields redacted, including encoded passwords and references, without resolving
any secret. config use-context NAME validates the name and atomically updates
current_context in the same resolved file, preserving other values/comments;
replace writes use owner-only permissions and detect concurrent file edits.
No commands print YAML parser errors containing scalar values, decoded passwords,
or dotenv content. Multi-document, duplicate-key and unknown-field YAML fails.

Validation: first failing tests for value resolution, config selection, malformed
input, context edits/redaction, CLI precedence and -- boundaries; then unit/race,
interop, four-platform builds and vulnerability scan. Live tests use private
out-of-repository configuration. Public docs/examples contain generic values only.
