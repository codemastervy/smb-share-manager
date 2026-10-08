Updating smb-share-manager
==========================

This is how new versions reach the server, how that fits the monthly update script, and
how to check and roll back.


Where images come from
----------------------

GitHub Actions publishes the image to ghcr.io/codemastervy/smb-share-manager (public)
with three tags:

- latest: what docker-compose.yml uses
- YYYYMMDD: the build date, e.g. 20261008. Use it to pin or roll back.
- sha-<commit>: the exact source commit

An image is pushed only after the full test suite has passed against that exact image:
lint, type checks, bandit, pip-audit, npm audit, unit and fuzz tests, and the integration
tests (real smbclient connections on exFAT and ext4, plus a real Chromium session clicking
through the UI). Trivy must also find no fixable HIGH or CRITICAL
vulnerabilities. The image that was tested is the image that gets pushed; it is never
rebuilt in between. Each push gets an SBOM, a build provenance attestation and a cosign
signature.

Images are published in three situations:

1. A change is merged to main by a person: the publish workflow runs.
2. Every Monday at 03:23 UTC the weekly rebuild runs. It builds from scratch (--pull
   --no-cache), so Debian security updates and a refreshed base image land even when
   nothing in the repository changed, then runs everything above. It pushes latest (and
   the dated tag) only if everything is green.
3. Dependabot checks Python packages, the web UI's npm packages, the Docker base images
   and the GitHub Actions weekly:
   - Minor and patch updates are grouped into one pull request per kind and merged
     automatically once every CI check is green.
   - Major updates get their own pull request, labelled needs-review, and are never
     merged automatically.
   - GitHub does not start the publish workflow for merges made by the automation, so
     Dependabot updates reach the image through the next weekly rebuild, at most 7 days
     later.

If the weekly rebuild fails, nothing is pushed: the server keeps running the previous
image. The workflow opens an issue labelled weekly-build-failed, or comments on the open
one, and closes it again after the next green run. GitHub emails you about the issue if
you watch the repository.


Keepalive
---------

GitHub disables scheduled workflows in repositories with no activity for 60 days. The
weekly workflow's first step re-enables itself through the GitHub API every week, which
resets that timer, so the schedule doesn't silently stop.

There is a second check on the server: scripts/smoke-test.sh prints a WARN line when the
running image is more than 14 days old. A stopped schedule, or a failed pull (see below),
shows up there. To check the schedule on GitHub, the repository's Actions tab, workflow
"weekly-rebuild", must show a run every Monday.


How this fits the monthly update script
---------------------------------------

The script does this for each running compose project:

1. docker compose pull
2. tags the running images for rollback
3. tars the bind mounts
4. docker compose up -d

That works for this project because:

- docker-compose.yml uses image: only, with no build: section, so pull gets the newest
  latest.
- All state is in ./data (the registry database, Samba's password database and the SMB
  unix accounts), which the script's tar step backs up. The SMB folders themselves are
  your existing disks and are not part of ./data.
- The container can be stopped and recreated at any time. On start it pushes the shares
  from ./data into Samba again.
- restart: unless-stopped plus the healthcheck mean a broken start shows up as
  "unhealthy" or as a restart loop in docker compose ps.

Important: the script ignores pull failures. If the pull fails (registry down, network
problem, typo in the image name), the script carries on and up -d recreates the container
from the old image. Nothing tells you. To see what is actually running, check the footer of
the web UI (version and build date) or run:

```bash
curl -s http://127.0.0.1:8095/healthz
```

```bash
docker inspect -f '{{.Config.Image}} {{.Image}}' smb-share-manager
```

Or simply run the smoke test after each monthly update (see below). It warns when the
image is more than 14 days old.


After an update: smoke test
---------------------------

From the compose project folder:

```bash
SMB_SHARE=Files SMB_USER=isherveer ./scripts/smoke-test.sh
```

It asks for the SMB password, or reads SMB_PASSWORD from the environment. It prints OK,
WARN or FAIL per check and exits non-zero on any FAIL. The checks:

- the container is running and healthy
- which image is running
- /healthz works, and the image's version, build date and age
- the security headers are present
- testparm accepts the Samba configuration
- anonymous access is refused
- the SMB user can log in and list the share (smbclient against localhost, run inside the
  container)

If it reports FAIL, roll back (next section) and open an issue with the output of
docker compose logs --tail 200.


Rolling back
------------

Option 1: pin a dated tag. In docker-compose.yml, change

```
    image: ghcr.io/codemastervy/smb-share-manager:latest
```

to a known good date, for example

```
    image: ghcr.io/codemastervy/smb-share-manager:20261008
```

and run:

```bash
docker compose up -d
```

The monthly script will keep that version (pull fetches the same dated tag) until you put
:latest back. Available tags are listed at
https://github.com/codemastervy/smb-share-manager/pkgs/container/smb-share-manager

Option 2: use the rollback tag your monthly script created before the update. Point
image: at it, or retag it as latest locally, then run docker compose up -d.

The data format in ./data only changes in a backwards-compatible way, so rolling back the
image doesn't require restoring ./data. If a release ever needs a migration, its release
notes will say so.


Verifying an image (optional)
-----------------------------

```bash
cosign verify ghcr.io/codemastervy/smb-share-manager:latest --certificate-identity-regexp 'https://github.com/codemastervy/smb-share-manager/.github/workflows/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
gh attestation verify oci://ghcr.io/codemastervy/smb-share-manager:latest --repo codemastervy/smb-share-manager
```
