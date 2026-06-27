# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""The only module that can *change* system state — and it does so cautiously.

Its actions are: reclaiming clean caches via ``/proc/sys/vm/drop_caches``,
deleting idle/abandoned tmpfs files, provisioning a swapfile, and — the one
action that touches processes — gracefully stopping allowlisted, non-essential
workloads (``docker stop`` for containers, ``SIGTERM`` for standalone dev
servers).  The stop path never uses ``SIGKILL`` and never acts on a process the
planner did not mark eligible; every candidate is re-validated against the
untouchable set at action time.  Every safety gate (dry-run by default, the
right privilege check, dependency injection for tests) lives here so the
behaviour can be verified without ever touching a real machine.
"""

from __future__ import annotations

import os
import shutil

DROP_CACHES_PATH = "/proc/sys/vm/drop_caches"

# What each drop_caches level frees. Level 1 (page cache) is the safe default.
LEVEL_DESCRIPTIONS = {
    1: "page cache (clean file-backed pages)",
    2: "reclaimable slab (dentries and inodes)",
    3: "page cache + reclaimable slab",
}


def build_commands(level: int) -> list[str]:
    """The exact shell commands the apply path runs, for display/dry-run.

    ``sync`` first flushes dirty pages so they become reclaimable; otherwise
    dropping caches would leave dirty data un-freed.
    """
    return ["sync", f"echo {level} > {DROP_CACHES_PATH}"]


def is_root(geteuid=os.geteuid) -> bool:
    """True when the effective user can write ``drop_caches`` (root)."""
    return geteuid() == 0


def _default_writer(level: int) -> None:
    """Flush dirty pages, then ask the kernel to drop the requested caches."""
    os.sync()
    with open(DROP_CACHES_PATH, "w", encoding="ascii") as handle:
        handle.write(f"{level}\n")


def run_free(
    level: int = 1,
    *,
    apply: bool = False,
    geteuid=os.geteuid,
    writer=_default_writer,
    sample_available=None,
) -> dict[str, object]:
    """Plan or perform a safe cache reclaim and return a structured result.

    The function is dependency-injected so tests can drive every branch without
    root and without writing to ``/proc``:

    * ``geteuid``        — privilege check (default :func:`os.geteuid`).
    * ``writer``         — performs the actual reclaim (default writes /proc).
    * ``sample_available`` — returns current MemAvailable in kB, sampled before
      and after, to report how much was freed.

    Returns a dict with ``applied`` (bool), ``commands`` (list[str]),
    ``level``, ``reason``, and — when applied — ``before_kb``/``after_kb``/
    ``freed_kb``.
    """
    if level not in LEVEL_DESCRIPTIONS:
        raise ValueError(f"level must be one of {sorted(LEVEL_DESCRIPTIONS)}, got {level}")

    commands = build_commands(level)
    result: dict[str, object] = {
        "level": level,
        "level_description": LEVEL_DESCRIPTIONS[level],
        "commands": commands,
        "applied": False,
    }

    if not apply:
        result["reason"] = "dry-run"
        return result

    if not is_root(geteuid):
        result["reason"] = "not-root"
        # Re-running the tool under sudo is the correct, copy-pasteable form.
        # (`sudo echo N > file` would redirect as the *unprivileged* shell.)
        result["sudo_hint"] = f"sudo ram-optimizer free --apply --level {level}"
        return result

    before = sample_available() if sample_available else None
    writer(level)
    after = sample_available() if sample_available else None

    result["applied"] = True
    result["reason"] = "applied"
    if before is not None and after is not None:
        result["before_kb"] = before
        result["after_kb"] = after
        result["freed_kb"] = max(after - before, 0)
    return result


# --- stopping non-essential workloads ----------------------------------------
#
# Mirrors the cache/swap paths: dry-run by default, dependency-injected so tests
# never signal a real process or shell out, and a structured result. The plan
# comes from :func:`ramopt.analyze.plan_stop` (which already applied the
# allowlist + guards); this function re-checks the untouchable set one more time
# at action time — defence against the process table changing between plan and
# act — and routes each unit to its supervisor: `docker stop` (graceful by
# design: SIGTERM, then SIGKILL only after a grace period the daemon owns) for
# containers, and a single SIGTERM for standalone dev servers. Never SIGKILL.

SIGTERM = 15


def _default_signaller(pid: int, sig: int) -> None:
    """Send ``sig`` to ``pid`` (default action path for standalone processes)."""
    os.kill(pid, sig)


def _default_docker_stop(name: str) -> None:
    """Gracefully stop a container by name/id via the docker CLI."""
    import subprocess  # local import: only needed on the real apply path

    subprocess.run(["docker", "stop", name], check=True,
                   capture_output=True, text=True)


def _default_systemctl_stop(unit_id: str) -> None:
    """Gracefully stop a user systemd service (``--full-complete-sweep`` only).

    Uses ``systemctl --user``: the sweep only ever promotes *user-session*
    units (the planner filters to the caller's uid), which a normal user can
    stop without root. ``stop`` is graceful (the unit's own ExecStop / SIGTERM).
    """
    import subprocess  # local import: only needed on the real apply path

    subprocess.run(["systemctl", "--user", "stop", unit_id], check=True,
                   capture_output=True, text=True)


def _running_under_sudo(geteuid=os.geteuid) -> bool:
    """True when invoked via ``sudo`` (euid 0 with the caller's uid in SUDO_UID).

    This matters only for ``systemctl --user``: under sudo it binds to *root's*
    user manager, not the original user's, so a user service would never
    actually stop. The planner already honours ``SUDO_UID`` to *select* the
    unit; this lets the apply path warn that the action half won't follow.
    """
    return geteuid() == 0 and bool(os.environ.get("SUDO_UID"))


def _docker_reachable() -> bool:
    """True if the Docker daemon is reachable (root *or* ``docker`` group).

    ``docker info`` succeeds only when the caller can talk to the socket, which
    is exactly the precondition for ``docker stop`` — so this is the honest gate,
    unlike an euid check (the socket is ``root:docker`` group-rw, so a
    docker-group member reaches it without being root).
    """
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_stop_workloads(
    plan: dict,
    *,
    apply: bool = False,
    protected_pids: set[int] | None = None,
    docker_available=None,
    signaller=_default_signaller,
    docker_stop=_default_docker_stop,
    systemctl_stop=_default_systemctl_stop,
    under_sudo=_running_under_sudo,
    pid_alive=None,
    sleep=None,
) -> dict[str, object]:
    """Plan or perform a graceful stop of the planner's eligible units.

    Dependency-injected for tests (none of these run on a dry run):

    * ``docker_available`` — ``callable()->bool``: can we reach the Docker
      daemon? Docker access is **group-based** (the ``docker`` group), not a
      matter of being root, so this probes the socket rather than checking
      euid. Defaults to running ``docker info``.
    * ``signaller``    — ``callable(pid, sig)`` for standalone process units.
    * ``docker_stop``  — ``callable(name)`` to stop a container.
    * ``systemctl_stop`` — ``callable(unit_id)`` to stop a user systemd service
      (only ``--full-complete-sweep`` ever produces ``systemd`` units).
    * ``pid_alive``    — ``callable(pid)->bool`` used after signalling to report
      whether a process actually exited (default: ``/proc/<pid>`` exists check).
    * ``protected_pids`` — re-checked untouchable set; any unit whose members
      intersect it is skipped even if the planner marked it eligible.

    Returns ``{applied, planned, stopped, skipped, errors, freed_kb_est,
    reason}`` and an ``access_hint`` when docker units were refused because the
    daemon was unreachable.
    """
    protected_pids = protected_pids or set()
    pid_alive = pid_alive or _proc_pid_alive
    docker_available = docker_available or _docker_reachable
    if sleep is None:
        import time  # local import: only the real apply path needs to wait
        sleep = time.sleep
    units = list(plan.get("units", []))

    planned = [_stop_brief(u) for u in units]
    result: dict[str, object] = {
        "applied": False,
        "planned": planned,
        "planned_kb": sum(u["rss_kb"] for u in units),
        "stopped": [],
        "skipped": [],
        "errors": [],
        "freed_kb_est": 0,
    }

    # systemd user units stop via `systemctl --user`, which under sudo would
    # target root's manager, not yours — warn in both dry-run and apply so the
    # user runs the sweep non-sudo (the planner already selected by SUDO_UID).
    if any(u["kind"] == "systemd" for u in units) and under_sudo():
        result["systemd_hint"] = (
            "Stopping systemd user services uses `systemctl --user`, which under "
            "sudo binds to root's user manager, not yours — those units will not "
            "stop. Run the sweep WITHOUT sudo so it stays your user, e.g. "
            "`sg docker -c 'ram-optimizer stop --full-complete-sweep --apply'`.")

    if not apply:
        result["reason"] = "dry-run"
        return result

    # Docker access is via the `docker` group (or root), not root specifically —
    # so probe the daemon rather than checking euid. If it is unreachable, refuse
    # only the docker units (not the whole run) and surface how to get access.
    has_docker = any(u["kind"] == "docker" for u in units)
    docker_ok = docker_available() if has_docker else False
    if has_docker and not docker_ok:
        result["access_hint"] = (
            "Docker daemon unreachable. Use the docker group "
            "(sg docker -c 'ram-optimizer stop --apply'), add yourself with "
            "`sudo usermod -aG docker $USER` then re-login, or run via "
            "`sudo ram-optimizer stop --apply`.")

    stopped: list[dict] = []
    errors: list[dict] = []
    skipped: list[dict] = []
    freed = 0
    for unit in units:
        members = unit.get("members", [])
        if any(pid in protected_pids for pid in members):
            skipped.append({**_stop_brief(unit),
                            "reason": "became guarded since planning"})
            continue
        if unit["kind"] == "docker":
            if not docker_ok:
                skipped.append({**_stop_brief(unit),
                                "reason": "docker daemon unreachable "
                                          "(need root or docker-group access)"})
                continue
            try:
                docker_stop(unit["label"])
            except Exception as exc:  # noqa: BLE001 - report, never crash the run
                errors.append({**_stop_brief(unit), "error": str(exc)})
                continue
            stopped.append(_stop_brief(unit))
            freed += unit["rss_kb"]
        elif unit["kind"] == "systemd":  # user service: `systemctl --user stop`
            try:
                systemctl_stop(unit["key"])
            except Exception as exc:  # noqa: BLE001 - report, never crash the run
                errors.append({**_stop_brief(unit), "error": str(exc)})
                continue
            stopped.append(_stop_brief(unit))
            freed += unit["rss_kb"]
        else:  # standalone process: a single graceful SIGTERM
            pid = unit["key"]
            try:
                signaller(pid, SIGTERM)
            except ProcessLookupError:
                stopped.append({**_stop_brief(unit), "note": "already gone"})
                continue
            except OSError as exc:
                errors.append({**_stop_brief(unit), "error": str(exc)})
                continue
            # SIGTERM is asynchronous: a process mid-shutdown still exists for a
            # moment, so a single immediate check would almost always say "not
            # freed". Poll briefly (bounded) so freed_kb_est reflects reality.
            exited = _wait_gone(pid, pid_alive, sleep)
            entry = _stop_brief(unit)
            entry["exited"] = exited
            stopped.append(entry)
            if exited:
                freed += unit["rss_kb"]

    result["applied"] = True
    result["reason"] = "applied"
    result["stopped"] = stopped
    result["skipped"] = skipped
    result["errors"] = errors
    result["freed_kb_est"] = freed
    return result


def _stop_brief(unit: dict) -> dict:
    """The display subset of a unit, for planned/stopped/skipped lists."""
    return {"kind": unit["kind"], "label": unit["label"],
            "category": unit.get("category"), "rss_kb": unit.get("rss_kb", 0),
            "command": unit.get("command")}


def _proc_pid_alive(pid: int) -> bool:
    """True if ``/proc/<pid>`` still exists (the default liveness probe)."""
    return os.path.exists(f"/proc/{pid}")


def _wait_gone(pid, pid_alive, sleep, *, attempts: int = 10, interval: float = 0.2) -> bool:
    """Poll up to ``attempts × interval`` (~2s) for ``pid`` to exit after SIGTERM.

    Returns as soon as the process is gone.  ``sleep`` is injected so tests run
    instantly; a graceful dev server usually exits well within this window, and
    if it does not we simply report it as not-yet-exited rather than escalating.
    """
    for _ in range(attempts):
        if not pid_alive(pid):
            return True
        sleep(interval)
    return not pid_alive(pid)


def _default_remover(path: str) -> None:
    """Delete a file or directory tree without following symlinks."""
    if os.path.islink(path) or not os.path.isdir(path):
        os.remove(path)
    else:
        shutil.rmtree(path)


def _under_any_mount(path: str, mounts: list[str]) -> bool:
    """True only if ``path`` is strictly *inside* one of ``mounts``.

    Equality with a mountpoint is rejected: we never delete the mount itself,
    only entries beneath it.
    """
    for mount in mounts:
        root = mount.rstrip("/") + "/"
        if path.startswith(root) and path.rstrip("/") != mount.rstrip("/"):
            return True
    return False


def run_reclaim_tmpfs(
    candidates: list[dict],
    *,
    mounts: list[str],
    current_uid: int,
    apply: bool = False,
    remover=_default_remover,
    realpath=os.path.realpath,
) -> dict[str, object]:
    """Plan or perform deletion of reclaimable tmpfs artifacts, safely.

    ``candidates`` are the records the analyzer marked ``reclaimable`` (each with
    ``path``, ``size_kb``, ``uid``, ...).  Deleting one's own tmpfs files needs
    no root, so — unlike :func:`run_free` — there is no privilege gate; instead
    every candidate is re-validated at action time and silently *skipped* if it
    fails any guard.  This re-check defends against a bad caller and against the
    filesystem changing under us between scan and delete:

    * the resolved real path must lie strictly inside one of ``mounts`` (no
      escaping tmpfs via ``..`` or a symlink), and
    * the entry must be owned by ``current_uid``, and
    * the record must actually be flagged ``reclaimable``.

    Returns ``{applied, planned, deleted, skipped, freed_kb, ...}``.  On a dry
    run nothing is removed; ``planned`` lists exactly what ``--apply`` would do.
    """
    planned: list[dict] = []
    skipped: list[dict] = []
    for art in candidates:
        why = _reject_reason(art, mounts, current_uid, realpath)
        if why:
            skipped.append({"path": art.get("path"), "reason": why})
        else:
            planned.append(art)

    planned_kb = sum(a.get("size_kb", 0) for a in planned)
    result: dict[str, object] = {
        "applied": False,
        "planned": [{"path": a["path"], "size_kb": a.get("size_kb", 0),
                     "klass": a.get("klass"), "reason": a.get("reason")}
                    for a in planned],
        "skipped": skipped,
        "planned_kb": planned_kb,
        "deleted": [],
        "freed_kb": 0,
    }

    if not apply:
        result["reason"] = "dry-run"
        return result

    deleted: list[dict] = []
    errors: list[dict] = []
    freed = 0
    for art in planned:
        try:
            remover(art["path"])
        except OSError as exc:
            errors.append({"path": art["path"], "error": str(exc)})
            continue
        deleted.append({"path": art["path"], "size_kb": art.get("size_kb", 0)})
        freed += art.get("size_kb", 0)

    result["applied"] = True
    result["reason"] = "applied"
    result["deleted"] = deleted
    result["errors"] = errors
    result["freed_kb"] = freed
    return result


def _reject_reason(art, mounts, current_uid, realpath) -> str | None:
    """Return why a candidate must be skipped, or ``None`` if safe to delete."""
    path = art.get("path")
    if not path:
        return "no path"
    if not art.get("reclaimable"):
        return "not flagged reclaimable"
    if art.get("uid") not in (None, current_uid):
        return "owned by another user"
    if not _under_any_mount(realpath(path), mounts):
        return "resolves outside a tmpfs mount"
    return None


# --- swap provisioning -------------------------------------------------------
#
# Adds a swapfile so a memory spike on an overcommitted host has a soft landing
# instead of going straight to the OOM killer. Like the cache-drop path this is
# gated: dry-run by default, root required (mkswap/swapon need it), idempotent
# (refuses if swap is already active), and dependency-injected so tests never
# run the real privileged commands.

SWAP_MIN_GB = 4
SWAP_MAX_GB = 32
DEFAULT_SWAP_PATH = "/swap.img"
SWAPPINESS_PATH = "/proc/sys/vm/swappiness"


def validate_swap_size(size_gb: int) -> int:
    """Return ``size_gb`` if within the allowed band, else raise ``ValueError``."""
    if not isinstance(size_gb, int) or isinstance(size_gb, bool):
        raise ValueError("swap size must be an integer number of GiB")
    if not SWAP_MIN_GB <= size_gb <= SWAP_MAX_GB:
        raise ValueError(
            f"swap size must be between {SWAP_MIN_GB} and {SWAP_MAX_GB} GiB, "
            f"got {size_gb}")
    return size_gb


def build_swap_commands(
    size_gb: int,
    path: str = DEFAULT_SWAP_PATH,
    *,
    swappiness: int | None = None,
    file_exists: bool = False,
    currently_active: bool = False,
) -> list[str]:
    """The exact command sequence the apply path runs, for display/dry-run.

    ``fallocate`` sizes the file instantly; ``mkswap`` formats it; ``swapon``
    activates it. A pre-existing file at ``path`` is swapped *off* first so it
    can be safely resized and reformatted. An ``/etc/fstab`` entry makes the
    swap persist across reboots (added only if absent).
    """
    commands: list[str] = []
    if currently_active:
        commands.append(f"swapoff {path}")
    commands.append(f"fallocate -l {size_gb}G {path}")
    commands.append(f"chmod 600 {path}")
    commands.append(f"mkswap {path}")
    commands.append(f"swapon {path}")
    # Add the fstab entry only if this swap path is not already present. Match
    # by field (device in column 1, type "swap" in column 3) so ANY spacing is
    # recognised — crucially the installer's tab-separated form. A naive exact
    # "grep -qxF '<space-separated line>'" would miss a tab-separated entry and
    # append a duplicate, which makes systemd-fstab-generator fail to build the
    # swap unit ("Duplicate entry in /etc/fstab?") and breaks `swapon -a`.
    commands.append(
        f"awk '$1==\"{path}\" && $3==\"swap\"{{found=1}} END{{exit !found}}' "
        f"/etc/fstab || echo '{path} none swap sw 0 0' >> /etc/fstab")
    if swappiness is not None:
        commands.append(f"sysctl -w vm.swappiness={swappiness}")
    del file_exists  # reserved for callers that branch on resize-vs-create
    return commands


def _default_swap_runner(commands: list[str]) -> None:
    """Execute the swap-provisioning commands via a shell, stopping on error."""
    import subprocess  # local import: only needed on the real apply path

    for command in commands:
        subprocess.run(command, shell=True, check=True)


def _probe_swap_active(path: str) -> bool:
    """True if ``path`` currently appears as an active swap area."""
    try:
        with open("/proc/swaps", "r", encoding="utf-8") as handle:
            return any(line.split()[:1] == [path] for line in handle.read().splitlines()[1:])
    except OSError:
        return False


def run_add_swap(
    size_gb: int,
    *,
    path: str = DEFAULT_SWAP_PATH,
    swappiness: int | None = 10,
    apply: bool = False,
    geteuid=os.geteuid,
    runner=_default_swap_runner,
    swap_total_kb=None,
    swap_active=_probe_swap_active,
    file_exists=None,
) -> dict[str, object]:
    """Plan or perform adding a swapfile and return a structured result.

    Dependency-injected for tests:

    * ``geteuid``      — privilege check (mkswap/swapon need root).
    * ``runner``       — runs the command sequence (default shells out).
    * ``swap_total_kb``— callable returning current ``SwapTotal`` in kB; used to
      refuse when any swap is already configured.
    * ``swap_active``  — callable(path)->bool, whether *this* file is active.
    * ``file_exists``  — callable(path)->bool (default :func:`os.path.exists`).

    Returns ``applied`` (bool), ``commands``, ``size_gb``, ``path``, ``reason``,
    and a ``sudo_hint`` when refused for lack of privilege.
    """
    validate_swap_size(size_gb)
    file_exists = file_exists or os.path.exists
    already_active = swap_active(path)
    existing = file_exists(path)

    commands = build_swap_commands(
        size_gb, path, swappiness=swappiness,
        file_exists=existing, currently_active=already_active)
    result: dict[str, object] = {
        "size_gb": size_gb,
        "path": path,
        "swappiness": swappiness,
        "commands": commands,
        "applied": False,
    }

    if not apply:
        result["reason"] = "dry-run"
        return result

    # Refuse if the system already has swap — adding more is a separate, manual
    # decision, and we must never disturb an in-use swap area.
    total = swap_total_kb() if swap_total_kb else 0
    if total and total > 0:
        result["reason"] = "already-configured"
        result["swap_total_kb"] = total
        return result

    if not is_root(geteuid):
        result["reason"] = "not-root"
        result["sudo_hint"] = (
            f"sudo ram-optimizer swap --size-gb {size_gb} "
            f"--swappiness {swappiness} --apply")
        return result

    before = swap_total_kb() if swap_total_kb else None
    runner(commands)
    after = swap_total_kb() if swap_total_kb else None

    result["applied"] = True
    result["reason"] = "applied"
    if before is not None and after is not None:
        result["before_kb"] = before
        result["after_kb"] = after
        result["added_kb"] = max(after - before, 0)
    return result
