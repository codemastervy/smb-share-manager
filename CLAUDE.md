# smb-share-manager: project rules

This container does ONE job: create and manage Samba shares, the SMB users who
access them, and a minimal folder browser for picking the folder to share.

## Scope (never add features outside it)
In scope:
- admin login
- folder browser limited to the configured volumes: list, mkdir, rename, delete, upload, and download as an attachment
- share create/edit/delete
- SMB user create / set password / delete
- view the generated config and live status
- one-time import from an old smb.conf + passdb
- a warning about filesystems without unix permissions

Out of scope: system stats, SMART, GPU, app launcher, terminal, file preview,
search, copy/move, telemetry, update checkers, external CDNs, runtime network calls.
Anything not listed under "in scope" is out.

## Security requirements are invariants
Each one has tests. Never weaken a requirement to make a feature or test pass.
1. Never render user files. Downloads: attachment + nosniff + CSP sandbox. App-wide strict CSP,
   no inline scripts, frame-ancestors 'none'.
2. No config injection. Control characters are rejected everywhere. The renderer REFUSES bad
   input and never escapes it.
3. A share with no members and no "all users" access is refused (and rendered unavailable).
4. File ops never overwrite and never follow symlinks; volume roots can't be deleted.
5. Least-privilege container (cap_drop ALL + documented add-backs, read-only rootfs,
   no-new-privileges, only the configured volumes mounted).
6. Auth: env password or argon2id hash, server-side sessions (8 h idle / 7 d absolute),
   CSRF + Origin + Host checks, throttled login keyed on the real peer, no public API docs.
7. Usernames are strict ASCII, `--` comes before positional arguments, uids are 3000+,
   passwords go via stdin only and are never logged.
8. Config write: render, testparm, atomic replace, reload, and roll back on failure
   (including the first config). The base smb.conf is never rewritten.
9. Never chown/chmod a host folder without explicit admin confirmation; never recursive.
10. Uploads: size limit, streamed, temp + rename, sanitised name, no overwrite.
11. Structured audit log to stdout; never secrets.

## Process model
The web app runs unprivileged. Anything that needs root goes through the helper
(src/ssm/helper) over a unix socket, using a fixed operation allowlist. Never add a generic
"run command" operation to the helper.

## Workflow
- Write tests before the code for anything touching a security requirement.
- Run the full local suite before every commit:

      uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run bandit -q -r src -c pyproject.toml && uv run pytest

- Integration tests (tests/integration) run in CI against the built image; see
  .github/workflows/build-test.yml.
- Small commits. Docs are plain text with code blocks.
