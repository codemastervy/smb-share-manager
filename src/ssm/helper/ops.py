"""The root helper's fixed set of operations.

Rules for this module:
- Every argument is re-validated here with the shared validators, whatever the caller did.
- External programs are run with an argv list (never a shell), a minimal environment,
  ``--`` before every positional argument, and passwords only on stdin.
- There is deliberately no generic "run a command" operation.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ssm import fsinfo, importer, render
from ssm import validators as v
from ssm.helper import extrausers
from ssm.models import ShareSpec

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
NT_HASH_RE = re.compile(r"[0-9A-F]{32}")
CMD_TIMEOUT = 60


class HelperOpError(Exception):
    """Refused or failed operation; the message is shown to the admin (never secrets)."""


@dataclass(frozen=True)
class HelperConfig:
    base_conf: str = "/etc/samba/smb.conf"
    shares_conf: str = "/data/samba/shares.conf"
    globals_conf: str = "/data/samba/globals.conf"
    extrausers_dir: str = "/data/extrausers"
    volumes: list[str] = field(default_factory=list)
    import_dir: str = "/import"
    bin_dir: str = "/usr/bin"
    tmp_dir: str = "/tmp/ssm-helper"  # noqa: S108  # nosec B108 - private 0700 dir on tmpfs
    smb_gid: int = 3000
    uid_min: int = 3000


def _v(fn: Any, value: Any) -> Any:
    try:
        return fn(value)
    except (v.ValidationError, TypeError) as e:
        raise HelperOpError(str(e)) from e


def _atomic_write(path: str, text: str, mode: int = 0o644) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ssm-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class HelperOps:
    def __init__(self, cfg: HelperConfig) -> None:
        self.cfg = cfg
        self.volumes = [os.path.realpath(p) for p in cfg.volumes]
        os.makedirs(cfg.tmp_dir, mode=0o700, exist_ok=True)

    # --- process execution -------------------------------------------------------------

    def _bin(self, name: str) -> str:
        return os.path.join(self.cfg.bin_dir, name)

    def _run(
        self, name: str, args: list[str], stdin: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        argv = [self._bin(name), *args]
        env = dict(SAFE_ENV)
        if "FAKE_DIR" in os.environ:  # test harness only; the image never sets this
            env["FAKE_DIR"] = os.environ["FAKE_DIR"]
        try:
            proc = subprocess.run(  # nosec B603 - fixed binary, validated argv list
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                env=env,
                timeout=CMD_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise HelperOpError(f"{name} could not be run") from e
        if check and proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip().splitlines()
            tail = msg[-1][:200] if msg else f"exit code {proc.returncode}"
            raise HelperOpError(f"{name} failed: {tail}")
        return proc

    # --- config ------------------------------------------------------------------------

    def _known_users(self) -> set[str]:
        return set(extrausers.read_users(self.cfg.extrausers_dir))

    def _testparm(self, conf: str) -> str:
        return self._run("testparm", ["-s", "--suppress-prompt", conf]).stdout

    def _check_with_testparm(self, shares_text: str, names: set[str]) -> str:
        """Validate a candidate shares file with testparm on a temporary full config."""
        base = Path(self.cfg.base_conf).read_text()
        include_line = re.compile(
            r"^(\s*include\s*=\s*)" + re.escape(self.cfg.shares_conf) + r"\s*$", re.M
        )
        if not include_line.search(base):
            raise HelperOpError("base smb.conf does not include the shares file")
        work = tempfile.mkdtemp(dir=self.cfg.tmp_dir)
        try:
            cand = os.path.join(work, "shares.conf")
            Path(cand).write_text(shares_text)
            top = os.path.join(work, "smb.conf")
            Path(top).write_text(include_line.sub(lambda m: m.group(1) + cand, base))
            out = self._testparm(top)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        got = set(render.parse_sections(out)) - {"global"}
        if got != names:
            raise HelperOpError(
                f"testparm produced unexpected shares: {sorted(got ^ names)}; nothing changed"
            )
        return out

    def apply_shares(self, shares: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(shares, list):
            raise HelperOpError("shares must be a list")
        known = self._known_users()
        specs: list[ShareSpec] = []
        for raw in shares:
            if not isinstance(raw, dict):
                raise HelperOpError("each share must be an object")
            try:
                spec = ShareSpec.from_dict(raw)
            except (KeyError, ValueError) as e:
                raise HelperOpError(f"invalid share: {e}") from e
            try:
                spec = v.validate_share(spec, self.volumes, known)
            except v.ValidationError as e:
                raise HelperOpError(f"{spec.name!r}: {e}") from e
            # Never trust the client's idea of the filesystem.
            spec = ShareSpec(
                **{**spec.to_dict(), "no_unix_perms": fsinfo.lacks_unix_perms(spec.path)}
            )
            specs.append(spec)
        try:
            text = render.render_shares(specs)
        except render.RenderError as e:
            raise HelperOpError(str(e)) from e
        names = {s.name for s in specs}
        self._check_with_testparm(text, names)

        live = self.cfg.shares_conf
        old: str | None = Path(live).read_text() if os.path.exists(live) else None
        old_sections = render.parse_sections(old or "")
        _atomic_write(live, text)
        try:
            self._run("smbcontrol", ["smbd", "reload-config"])
        except HelperOpError:
            if old is None:
                os.unlink(live)
            else:
                _atomic_write(live, old)
            self._run("smbcontrol", ["smbd", "reload-config"], check=False)
            raise
        new_sections = render.parse_sections(text)
        for name, params in old_sections.items():
            if name not in new_sections:
                self._run("smbcontrol", ["smbd", "close-share", name], check=False)
            elif new_sections[name] != params:
                self._run("smbcontrol", ["smbd", "close-denied-share", name], check=False)
        return {"shares": sorted(names)}

    def write_globals(self, hosts_allow: list[str], server_name: str, enable_nmbd: bool) -> None:
        try:
            text = render.render_globals(hosts_allow, server_name, enable_nmbd)
        except render.RenderError as e:
            raise HelperOpError(str(e)) from e
        _atomic_write(self.cfg.globals_conf, text)

    # --- users -------------------------------------------------------------------------

    def _system_account_exists(self, name: str) -> bool:
        return self._run("id", ["-u", "--", name], check=False).returncode == 0

    def user_add(self, name: str) -> None:
        name = _v(v.validate_username, name)
        if name in self._known_users():
            raise HelperOpError(f"user {name!r} already exists")
        if self._system_account_exists(name):
            raise HelperOpError(f"{name!r} is a system account name and cannot be used")
        try:
            extrausers.add_user(self.cfg.extrausers_dir, name, self.cfg.smb_gid, self.cfg.uid_min)
        except ValueError as e:
            raise HelperOpError(str(e)) from e

    def _require_smb_user(self, name: str) -> str:
        name = _v(v.validate_username, name)
        if name not in self._known_users():
            raise HelperOpError(f"{name!r} is not an SMB user managed here")
        return str(name)

    def user_set_password(self, name: str, password: str) -> None:
        name = self._require_smb_user(name)
        password = _v(v.validate_password, password)
        self._run("smbpasswd", ["-a", "-s", "--", name], stdin=f"{password}\n{password}\n")
        self._run("smbpasswd", ["-e", "--", name])

    def user_delete(self, name: str) -> None:
        name = self._require_smb_user(name)
        self._run("smbpasswd", ["-x", "--", name], check=False)
        try:
            extrausers.remove_user(self.cfg.extrausers_dir, name, self.cfg.smb_gid)
        except ValueError as e:
            raise HelperOpError(str(e)) from e

    def user_list(self) -> list[str]:
        out = self._run("pdbedit", ["-L"]).stdout
        return sorted({ln.split(":", 1)[0] for ln in out.splitlines() if ":" in ln})

    # --- status ------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        ping = self._run("smbcontrol", ["smbd", "ping"], check=False)
        tp = self._run("testparm", ["-s", "--suppress-prompt", self.cfg.base_conf], check=False)
        sections = render.parse_sections(tp.stdout) if tp.returncode == 0 else {}
        sections.pop("global", None)
        try:
            users = self.user_list()
        except HelperOpError:
            users = []
        return {
            "smbd_running": ping.returncode == 0,
            "shares": {k: {"path": p.get("path", "")} for k, p in sections.items()},
            "users": users,
            "config_text": tp.stdout if tp.returncode == 0 else tp.stderr[-2000:],
        }

    # --- permissions (requirement 9) -----------------------------------------------------

    def _share_dir(self, path: str) -> str:
        if not isinstance(path, str) or os.path.islink(path):
            raise HelperOpError("not a folder (symbolic links are not followed)")
        real = _v(lambda p: v.validate_share_path(p, self.volumes), path)
        return str(real)

    def perm_plan(self, path: str) -> dict[str, Any]:
        real = self._share_dir(path)
        st = os.lstat(real)
        mode = stat.S_IMODE(st.st_mode)
        before = {"uid": st.st_uid, "gid": st.st_gid, "mode": f"{mode:04o}"}
        if fsinfo.lacks_unix_perms(real):
            return {"path": real, "applicable": False, "changes": [], "before": before}
        want_mode = mode | stat.S_ISGID | stat.S_IRWXG
        changes = []
        if st.st_gid != self.cfg.smb_gid:
            changes.append(f"group: gid {st.st_gid} -> smbusers (gid {self.cfg.smb_gid})")
        if want_mode != mode:
            changes.append(f"mode: {mode:04o} -> {want_mode:04o} (group read/write + setgid)")
        return {"path": real, "applicable": True, "changes": changes, "before": before}

    def perm_apply(self, path: str, expected_before: dict[str, Any]) -> dict[str, Any]:
        plan = self.perm_plan(path)
        if not isinstance(expected_before, dict) or plan["before"] != {
            "uid": expected_before.get("uid"),
            "gid": expected_before.get("gid"),
            "mode": expected_before.get("mode"),
        }:
            raise HelperOpError("the folder changed since the plan was shown; reload and retry")
        if not plan["applicable"] or not plan["changes"]:
            return {"changed": False}
        fd = os.open(plan["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            mode = stat.S_IMODE(st.st_mode)
            if f"{mode:04o}" != plan["before"]["mode"] or st.st_gid != plan["before"]["gid"]:
                raise HelperOpError("the folder changed since the plan was shown")
            if st.st_gid != self.cfg.smb_gid:
                os.fchown(fd, -1, self.cfg.smb_gid)
            os.fchmod(fd, mode | stat.S_ISGID | stat.S_IRWXG)
        finally:
            os.close(fd)
        return {"changed": True, "changes": plan["changes"]}

    # --- import ------------------------------------------------------------------------

    def _passdb_copy(self) -> tuple[str, str]:
        """Copy the imported passdb.tdb into a private temp dir (never touch the original)."""
        src = os.path.join(self.cfg.import_dir, "var-lib-samba", "private", "passdb.tdb")
        if not os.path.isfile(src) or os.path.islink(src):
            raise HelperOpError("no passdb.tdb found under /import/var-lib-samba/private")
        work = tempfile.mkdtemp(dir=self.cfg.tmp_dir)
        dst = os.path.join(work, "passdb.tdb")
        shutil.copyfile(src, dst, follow_symlinks=False)
        os.chmod(dst, 0o600)
        return work, dst

    def _import_lines(self, extra: list[str]) -> list[str]:
        work, copy = self._passdb_copy()
        try:
            out = self._run("pdbedit", ["-b", f"tdbsam:{copy}", *extra]).stdout
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return [ln for ln in out.splitlines() if ":" in ln]

    def import_scan(self) -> dict[str, Any]:
        """Usernames from the old passdb (never hashes) and the old smb.conf sections."""
        sections = importer.read_sections(self.cfg.import_dir)
        users: list[str] = []
        skipped: list[str] = []
        try:
            lines = self._import_lines(["-L"])
        except HelperOpError as e:
            return {"users": [], "skipped": [], "users_error": str(e), "sections": sections}
        for ln in lines:
            name = ln.split(":", 1)[0]
            try:
                v.validate_username(name)
                users.append(name)
            except v.ValidationError:
                skipped.append(name)
        return {"users": sorted(users), "skipped": sorted(skipped), "sections": sections}

    def import_user(self, name: str) -> dict[str, Any]:
        name = _v(v.validate_username, name)
        nt_hash = None
        for ln in self._import_lines(["-L", "-w"]):
            parts = ln.split(":")
            if parts[0] == name and len(parts) >= 4:
                nt_hash = parts[3].upper()
        if nt_hash is None:
            raise HelperOpError(f"{name!r} is not in the imported passdb")
        if not NT_HASH_RE.fullmatch(nt_hash):
            raise HelperOpError(f"{name!r} has no usable password hash in the imported passdb")
        self.user_add(name)
        try:
            placeholder = secrets.token_urlsafe(24)
            self._run(
                "smbpasswd", ["-a", "-s", "--", name], stdin=f"{placeholder}\n{placeholder}\n"
            )
            self._run("pdbedit", [f"--user={name}", "--set-nt-hash", nt_hash])
            self._run("smbpasswd", ["-e", "--", name])
        except HelperOpError:
            self.user_delete(name)
            raise
        return {"imported": name}
