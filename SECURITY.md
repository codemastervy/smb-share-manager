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
- The UI is a static React app; all data goes through a JSON API. Every state-changing
  request needs the per-session CSRF token in an X-CSRF-Token header (a cross-site form
  cannot set headers) and a matching Origin/Referer. Request bodies are strict: unknown
  fields are rejected. Requests whose Host header is not an IP, localhost or an ALLOWED_HOSTS
  entry are rejected, which defeats DNS rebinding.
- Logins are throttled with exponential backoff (up to 15 minutes), keyed on the TCP peer
  address. X-Forwarded-For counts only from TRUSTED_PROXIES (default none). The throttle's
  memory is bounded.
- Only /login, /healthz (status, version, build date) and /static are reachable without
  logging in. There are no API docs.
- A strict Content-Security-Policy: default-src 'self', no inline scripts or styles,
  frame-ancestors 'none'. The built UI is checked in CI for inline scripts, and its npm
  dependencies are installed from the lockfile (sha512 integrity) with install scripts
  disabled; npm audit runs on every build.
- User files are never rendered. Downloads are always Content-Disposition: attachment,
  Content-Type application/octet-stream, nosniff, with a CSP of default-src 'none' plus
  sandbox. The nas-dashboard preview feature was removed, and the API has no inline mode.

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
- Copy, move and search never follow symlinks and stay inside the volumes. Copy and move
  refuse to put a folder inside itself. A move across filesystems copies first and deletes
  the source only after the complete copy exists. Shared folders (and their parents) can't
  be moved or deleted.
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


WebDAV service
--------------

The deployment assumption "never exposed to the internet" still holds for the admin UI. It
does not hold for the optional WebDAV service (smb-dav), which is meant to be reached
through a Cloudflare Tunnel and Traefik (Pangolin) with the proxy's own login bypassed.

New exposure and accepted trade-offs:

- An internet-reachable endpoint protected only by a password. WebDAV clients (iOS Files,
  macOS Finder, Windows, Cryptomator) can only send HTTP Basic credentials, so the reverse
  proxy's own login (passkeys, OIDC) has to be bypassed for this hostname.
- Basic auth has no second factor, and the password goes with every request (inside TLS).
  TLS ends at Cloudflare, which sees the requests in plain text; Cloudflare to cloudflared
  is the tunnel, and cloudflared to Traefik to smb-dav is plain HTTP on your host.
- The WebDAV password is the user's SMB password, and Samba stores it as an unsalted NT
  hash. A leaked WebDAV password is also an SMB password on the LAN. Use 16 or more random
  characters for users with remote access.
- A per-user lockout lets an attacker slow down a user's new logins. Clients that already
  hold a verified password keep working (see the cache below).
- Anything that can connect to port 8094 from inside DAV_TRUSTED_PROXIES can claim any
  client address and HTTPS. With Pangolin that range is Traefik's Docker network, which also
  contains the Docker gateway, so other containers on that network and processes on the
  host are trusted this way. They still need a valid password, and the per-user throttle
  still applies. Keep the range as narrow as your setup allows.

Controls (each has a test, unit or against the built image):

- Off by default (compose profile dav). Only shares named in DAV_EXPOSED_SHARES are served
  (default empty: nothing), only their folders are mounted into the WebDAV container, and
  a share that covers a whole volume is refused at startup and dropped if it becomes one
  later. A renamed share is no longer served.
- Only users with the remote_access flag (default off) can log in. Others get the same
  401 without a password check, and it counts as a failure.
- Separate container and process, the same image. Runs as DAV_UID (default 2999, never 0 or
  PUID) with group smbusers, no capabilities, no-new-privileges, a read-only root filesystem
  and no env_file, so it never sees ADMIN_PASSWORD. It never imports the admin app, so
  no admin route exists on its port. It refuses to start as root, as PUID, with any
  effective capability, with ./data, /mnt/timenest, /import or the admin socket present,
  or with a whole volume mounted.
- It reads users and shares only from /run/ssm-dav/acl.json, which the admin app writes
  atomically on every registry change. The snapshot holds names, share paths, memberships,
  the remote flag and a credential generation number: no sessions, no hashes, no
  passwords. A missing or invalid snapshot means every request is refused.
- Passwords are checked by a verify-only operation of the root helper (user_verify_password)
  on its own socket, /run/ssm-dav/verify.sock, which accepts only DAV_UID (kernel peer
  credentials) and serves only that one operation, with a 4 KiB request limit. The helper
  computes the NT hash of the candidate and compares it with Samba's in constant time.
  Disabled accounts fail. Hashes never leave the helper, and passwords are never logged.
- Basic credentials are read only if the request arrived over HTTPS. X-Forwarded-Proto
  counts only from DAV_TRUSTED_PROXIES (default none). Plain HTTP gets 403 with no
  WWW-Authenticate, so a client is never invited to send its password in clear text.
  DAV_ALLOW_HTTP exists for CI only and is refused unless the port is bound to loopback.
- Login throttle per user and per real client IP: the right-most untrusted
  X-Forwarded-For entry, or CF-Connecting-IP if configured, both only from trusted proxies.
  It is never keyed on the proxy's own address; a trusted proxy that sends no client
  address is refused. Exponential backoff up to 15 minutes, bounded memory (LRU, 4096
  entries; names that are not real users count against the client address only, so
  sprayed junk names can't evict a real user's lockout), the same generic 401 for every
  failure, and no password check at all during a
  lockout. dav_auth audit lines for ok, fail and locked, dav_lockout when a user's lockout
  starts, and an optional ntfy notification (at most one per user per hour and 10 per hour
  in total, sent in the background).
- Verified credentials are cached for DAV_AUTH_CACHE_S (default 300 s) as an HMAC under a
  random per-process key, never the password, and each entry is tied to the user's
  credential generation, which changes before every password change. Authorisation is never
  cached: membership, ro/rw, user removal, the remote flag and password changes all take
  effect on the next request. Locks held by a user who is removed or loses remote access
  are released.
- Every path is walked component by component from the share folder with
  openat(O_NOFOLLOW), the same way as the folder browser. Symlinks, devices, FIFOs, the
  app's temp files and names that fail validation are invisible and unreachable. Control
  characters, "..", encoded slashes and Destination headers for another host, share or
  scheme are refused. Read-only members are refused every write in the guard and again in
  the provider.
- Overwriting: PUT may replace a file (read-write members only) through a temp file in the
  same folder and an atomic rename. MOVE and COPY replace only with an explicit
  Overwrite: T (a missing header counts as F), only a file onto a file, never a folder, a
  share root or a folder that contains a share, and never onto or into the source. A MOVE
  across filesystems deletes the source only after the copy is complete.
- Downloads are application/octet-stream, attachment, nosniff and CSP default-src 'none'
  with sandbox, and Cache-Control: private, no-store so Cloudflare never caches them. There
  is no HTML listing and no version banner. Error bodies are short plain text.
- Limits: request headers 16 KiB, XML bodies 256 KiB (no external entities), uploads
  DAV_MAX_UPLOAD_MB (checked up front and while streaming), PROPFIND Depth 0 or 1 only, at
  most 200 locks per user with a 1-hour timeout cap, stored properties at most 16 KiB each
  and 16 MiB in total, a 60-second socket timeout and a fixed pool of 32 worker threads.

Residual risks:

- Slow clients can hold worker threads for up to the socket timeout. Cloudflare and Traefik
  in front absorb most of this; a Cloudflare rate-limiting or country rule for the dav
  hostname is a cheap extra layer.
- The password check runs at the helper's pace (one at a time); an attacker who spreads
  guesses over many addresses is slowed by the per-user backoff, not stopped.
- Cloudflare's free plan caps a request at 100 MB (documented in the README).

What a fully compromised WebDAV process could still do: read and write the files of the
exposed shares, and ask the helper to check passwords at its pace. It could not change
shares, users or Samba, reach other folders, ./data or /mnt/timenest, or get root.


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
  a proxy in front of the admin UI, list it in TRUSTED_PROXIES or the throttle will see
  only the proxy. The WebDAV service refuses a trusted proxy's request without a client
  address instead.
