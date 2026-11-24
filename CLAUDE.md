CLAUDE.md
=========

Notes for anyone (human or AI) changing this repository. The rules below are invariants:
a change that breaks one is a bug, even if every test passes. If a rule has to change,
change it here, in SECURITY.md and in the tests in the same pull request.


Layout
------

- src/ssm/web: the admin web app (FastAPI, unprivileged, PUID/PGID). LAN/Tailscale only.
- src/ssm/helper: the root helper (fixed operation allowlist on unix sockets).
- src/ssm/dav: the WebDAV service (WsgiDAV + cheroot, its own container, DAV_UID). In
  development on the webdav branch.
- src/ssm/files.py, vpath.py, validators.py: shared, fd-based file operations and input
  validation. Reuse them; don't write path handling again.
- frontend: the React admin UI (static build, strict CSP).
- tests/unit, tests/fuzz: run with `uv run pytest`. tests/integration: run in CI against
  the built image (scripts/ci/integration.sh) on exFAT and ext4.


How to work here
----------------

- Write the test for a security rule before the code. Every rule below has a test.
- Small commits. Pull requests into main (main is protected; the owner merges).
- Commits and pull requests are authored by the owner only. No Co-Authored-By trailer.
- Before pushing: `uv run ruff check . && uv run ruff format --check . && uv run mypy &&
  uv run bandit -q -r src -c pyproject.toml && uv run pytest`.
- Don't add features outside the agreed scope. Out of scope: sharing or public links, sync
  clients, CalDAV/CardDAV, media streaming.


Invariants: deployment and updates
----------------------------------

- docker-compose.yml uses `image:` only, never `build:`. One image serves every service.
- All state lives in ./data. Every container can be recreated at any time.
- Every service has a healthcheck. restart: unless-stopped.
- The weekly --pull --no-cache rebuild, Trivy, cosign, SBOM and attestation stay. An image
  is pushed only after the full suite has passed against that exact image.
- Dependabot: minor/patch grouped and auto-merged after CI; majors labelled needs-review and
  never auto-merged. Node majors are moved by hand to the next LTS.
- Registry schema changes are additive only, so rolling the image back keeps working.
- /mnt/timenest is never mounted into any container.


Invariants: admin web app
-------------------------

- Refuses to start without ADMIN_PASSWORD or ADMIN_PASSWORD_HASH.
- Server-side sessions, only SHA-256 of the token stored; CSRF header + Origin check on every
  state change; Host allow-list (DNS rebinding); strict CSP, no inline scripts or styles.
- Login throttle with exponential backoff and bounded memory. X-Forwarded-* honoured only
  from TRUSTED_PROXIES (default none).
- User files are never rendered: attachment, application/octet-stream, nosniff,
  CSP default-src 'none' + sandbox.
- The admin UI is never reachable through the WebDAV port or hostname.


Invariants: root helper
-----------------------

- Fixed allowlist of operations per socket, exact argument names, every argument
  re-validated in the helper. No generic command execution. argv lists only (never a shell),
  `--` before positionals, passwords only on stdin or in a length-limited JSON field.
- The caller's uid comes from the kernel (SO_PEERCRED), never from the request.
- Passwords and NT hashes are never logged and never returned. audit.event refuses secret
  field names.
- The admin socket (/run/ssm/helper.sock) accepts PUID only. The verify socket
  (/run/ssm-dav/verify.sock) accepts DAV_UID only and serves exactly one operation,
  user_verify_password. DAV_UID must differ from PUID and from 0.


Invariants: Samba and config
----------------------------

- Validators refuse bad input; the renderer never escapes. testparm on a temp copy, the share
  set must match, atomic rename, rollback on failure. The base smb.conf is never rewritten.
- SMB2.10+, NTLMv2 only, no guest, restrict anonymous = 2, no wide links, no printing.
- A share with no members and no "all users" access is refused and unreachable everywhere,
  including WebDAV.


Invariants: file operations (admin folder browser)
--------------------------------------------------

- Only the configured volumes. Paths walked component by component with
  openat(O_NOFOLLOW); symlinks are never followed; control characters are refused.
- Nothing is ever overwritten (renameat2 RENAME_NOREPLACE or the locked fallback; uploads
  get "name (1).ext"). Shared folders, their parents and volume roots can't be moved or
  deleted. Cross-filesystem moves delete the source only after the copy is complete.


Invariants: WebDAV service (internet-reachable)
-----------------------------------------------

Process and container:

- Its own container and process, same image, started only when enabled. Runs as DAV_UID
  (default 2999) with group smbusers (3000): unprivileged, cap_drop ALL, no cap_add,
  no-new-privileges, read-only root filesystem. It refuses to start as root, as PUID, or
  with any effective capability.
- Mounts only the folders of the shares named in DAV_EXPOSED_SHARES (default empty: nothing
  is served) and the dav bridge volume. Never ./data, never a whole volume, never
  /mnt/timenest. An exposed share whose path is a volume root is refused at startup.
- It never imports the admin app. It reads the registry only through the ACL snapshot
  /run/ssm-dav/acl.json, which the admin app writes atomically on every registry change.
  The snapshot has no sessions and no secrets. Missing or invalid snapshot: refuse every
  request.

Authentication:

- HTTP Basic, checked against the Samba NT hash by the helper's verify-only operation. There
  is no second password store.
- Basic credentials are only read over HTTPS. X-Forwarded-Proto counts only from
  TRUSTED_PROXIES (default none). Plain HTTP gets 403 without WWW-Authenticate.
- Only users with the remote_access flag (default off) can authenticate. Others get the
  generic 401 without a helper call.
- Throttle per user and per real client IP, exponential backoff, bounded memory. The client
  IP comes from X-Forwarded-For (right-most untrusted entry) or CF-Connecting-IP, honoured
  only from TRUSTED_PROXIES, and is never the proxy's own address. During a lockout the
  password is not checked at all. Generic failure messages. dav_auth audit lines for ok,
  fail and locked; never the password.
- Optional ntfy notification when a per-user lockout starts (NTFY_URL, off by default),
  rate-limited, never blocking a request.
- The credential cache holds an HMAC of the password, never the password, and every entry
  is tied to the user's credential generation. Authorisation is never cached: membership,
  ro/rw, user removal and password changes take effect on the next request.

Authorisation and files:

- A user sees only the exposed shares they are a member of (or that have all-users access),
  as top-level collections, with exactly the registry's ro/rw. Zero-member shares and other
  users' shares give 404. Read-only members can't write anything (provider and middleware
  both check).
- Same fd-based O_NOFOLLOW walking as files.py. Never follow symlinks, refuse control and
  forbidden characters, no path escapes, nothing outside the share root.
- Overwrite rule (DAV only; the folder browser keeps "never overwrite"): PUT may replace an
  existing file, rw only, via a temp file in the same folder + atomic rename. MOVE/COPY
  replace only with an explicit Overwrite: T (a missing header counts as F), only file onto
  file, never a folder, a share root or a protected folder, never onto or into the source.
  A cross-filesystem MOVE deletes the source only after the copy is complete.
- PROPFIND Depth infinity (or missing Depth) is refused. Class 2 locks, in memory; a lock
  never grants access.
- Downloads: application/octet-stream, nosniff, CSP default-src 'none' + sandbox,
  attachment. Never an HTML listing. No Server or version banner. Header, body and upload
  size limits (MAX_UPLOAD) and per-request timeouts.
