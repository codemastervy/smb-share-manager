Security
========

Reporting
---------

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button
on this repository (Security tab), not in a public issue.


Threat model
------------

Deployment assumptions:

- A single administrator who is trusted. There are no other web users or roles.
- The server is reachable only from the home LAN and over Tailscale. It is never exposed
  to the internet. There is no built-in TLS; use Tailscale (encrypted) or a TLS reverse
  proxy if you want HTTPS.
- smbd runs as root inside the container, as Samba requires to switch to each user.

What we protect:

- the files on the mounted volumes
- SMB users' passwords
- root inside the container, and through it the host

Who we defend against:

- other devices on the LAN or tailnet, which may be compromised or curious
- malicious web pages open in the admin's browser (CSRF, DNS rebinding, clickjacking)
- hostile file contents, such as an .html or .svg file placed on a share by an SMB user
  and then opened through the folder browser (stored XSS)
- a bug in, or compromise of, the web application process

Out of scope: a malicious host root, physical access, a compromised admin browser or
machine, and internet exposure.


Boundaries and controls
-----------------------

Browser to web app:

- Login uses ADMIN_PASSWORD (hashed with argon2id at startup) or ADMIN_PASSWORD_HASH. The
  app refuses to start without one.
- Sessions are server-side: random 256-bit tokens, and only their SHA-256 is stored. Idle
  timeout is 8 h and the absolute limit is 7 days. Logout deletes the session. Changing
  the admin password (in .env, then restarting) revokes all sessions.
- The cookie is HttpOnly and SameSite=Strict, and Secure when HTTPS is used (or
  COOKIE_SECURE=true).
- Every state-changing request needs a per-session CSRF token and a matching
  Origin/Referer. Requests whose Host header is not an IP, localhost or an ALLOWED_HOSTS
  entry are rejected, which defeats DNS rebinding.
- Logins are throttled with exponential backoff (up to 15 minutes), keyed on the TCP peer
  address. X-Forwarded-For counts only from TRUSTED_PROXIES (default none). The throttle's
  memory is bounded.
- Only /login, /healthz (status, version, build date) and /static are reachable without
  logging in. There are no API docs.
- A strict Content-Security-Policy: default-src 'self', no inline scripts or styles,
  frame-ancestors 'none'. htmx is vendored, pinned by hash and has eval disabled.
- User files are never rendered. Downloads are always Content-Disposition: attachment,
  Content-Type application/octet-stream, nosniff, with a CSP of default-src 'none' plus
  sandbox. There is no preview feature.

Web app (unprivileged) to root helper:

- The web app runs as PUID/PGID with no capabilities and no-new-privs.
- The root helper listens on /run/ssm/helper.sock (mode 0660, group PGID). It checks the
  caller's uid from the kernel (SO_PEERCRED).
- The helper offers a fixed list of operations: apply shares, add/delete user, set
  password, status, permission plan/apply, import scan/user. It re-validates every
  argument itself.
- There is no generic command execution. Programs are run with an argv list (never a
  shell), with -- before positional arguments and passwords only on stdin.
- What a fully compromised web process could still do: change shares and SMB users, and
  apply the permission fix (group + g+rwxs, non-recursive) to a folder inside a configured
  volume. It could not run arbitrary commands as root or reach paths outside the volumes.

Config injection:

- Share names, usernames, comments and paths are validated with strict allow-lists, and
  control characters are rejected everywhere.
- The smb.conf renderer refuses bad input instead of escaping it, and checks every
  rendered line again.
- Each new config is checked with testparm on a temporary copy; the set of shares testparm
  reports must match exactly. It is then atomically renamed into place and Samba
  reloaded. On any failure the previous file is restored (or removed if it was the first
  one) and Samba reloaded again.
- The base smb.conf is part of the image and never rewritten.

Samba hardening:

- SMB 2.10 or newer only; signing and encryption are "desired"; NTLMv2 only.
- map to guest = never and restrict anonymous = 2.
- No printing, no wide links, no unix extensions; optional SMB_HOSTS_ALLOW.
- A share with no members and no "all users" access is refused, and would be rendered
  unavailable even if validation were bypassed.

Folder browser:

- Only the configured volumes are reachable.
- Paths are walked component by component with openat(O_NOFOLLOW). Symlinks are never
  followed; deleting a link deletes the link.
- Nothing is ever overwritten. Renames use renameat2(RENAME_NOREPLACE) when the filesystem
  supports it; otherwise a locked check-then-rename is used. Uploads use a temp file and
  "name (1).ext" on conflict.
- Volume roots and shared folders (or their parents) can't be deleted.
- Uploads are streamed with a size limit, and the file name is sanitised.

Container:

- Every capability is dropped. Only CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID and
  NET_BIND_SERVICE are added back; docker-compose.yml explains each. Not privileged, no
  SYS_ADMIN, no SYS_RAWIO.
- no-new-privileges, a read-only root filesystem with tmpfs for runtime state, and only
  ./data and the configured volumes mounted.
- SMB accounts are nologin with no home directory. Their uids start at 3000 and are never
  reused, and names of existing system accounts are refused.
- The audit log (JSON lines on stdout) records logins, share/user changes and file
  deletes. Passwords are never logged.


Known limitations
-----------------

- Signing and encryption are "desired", not "required", so very old clients can still
  connect without them. Set "server smb encrypt = required" yourself only if every client
  supports SMB3 encryption.
- On exFAT/FAT/NTFS there are no unix permissions. Access is enforced by Samba at share
  level only, and anything else that can reach the disk is not restricted by these
  settings.
- During a user import, the old NT hash is passed to pdbedit --set-nt-hash on its command
  line for a moment, inside the container. Only root and the web user exist there, and
  the web user is already trusted to set that user's password.
- The trusted-proxy logic takes the right-most untrusted X-Forwarded-For entry. If you put
  a proxy in front, list it in TRUSTED_PROXIES or the throttle will see only the proxy.
