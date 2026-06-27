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
"""Read the live ``/proc`` filesystem and hand text to the pure parsers.

This is the only diagnostic module that performs I/O, and every read is
read-only.  Reads that fail (a process exited mid-scan, or we lack permission
for another user's ``smaps_rollup``) are handled gracefully rather than
crashing the scan.
"""

from __future__ import annotations

import os

from . import proc

PROC_ROOT = "/proc"


def read_text(path: str) -> str | None:
    """Read a file, returning ``None`` on any OS error (missing, race, EPERM)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def collect_meminfo(proc_root: str = PROC_ROOT) -> dict[str, int]:
    """Read and parse ``/proc/meminfo``."""
    text = read_text(os.path.join(proc_root, "meminfo"))
    return proc.parse_meminfo(text) if text else {}


def collect_pressure(proc_root: str = PROC_ROOT) -> dict[str, dict[str, float]] | None:
    """Read ``/proc/pressure/memory`` (PSI); ``None`` if the kernel lacks it."""
    text = read_text(os.path.join(proc_root, "pressure", "memory"))
    return proc.parse_pressure(text) if text else None


def collect_processes(proc_root: str = PROC_ROOT) -> list[dict]:
    """Scan every PID and return one memory record per readable process.

    PSS is read from ``smaps_rollup`` when accessible (the fair per-process
    charge); otherwise we fall back to RSS from ``status``.  Records whose
    ``status`` cannot be read at all are skipped.
    """
    records: list[dict] = []
    for entry in _iter_pids(proc_root):
        status_text = read_text(os.path.join(proc_root, entry, "status"))
        if not status_text:
            continue
        info = proc.parse_status(status_text)

        pss_kb: int | None = None
        rollup_text = read_text(os.path.join(proc_root, entry, "smaps_rollup"))
        if rollup_text:
            rollup = proc.parse_smaps_rollup(rollup_text)
            pss_kb = rollup.get("Pss")

        records.append({
            "pid": info["pid"],
            "name": info["name"],
            "uid": info["uid"],
            "rss_kb": info["rss_kb"],
            "swap_kb": info["swap_kb"],
            "pss_kb": pss_kb,
        })
    return records


def _iter_pids(proc_root: str):
    """Yield the numeric (PID) directory names under ``/proc``."""
    try:
        names = os.listdir(proc_root)
    except OSError:
        return
    for name in names:
        if name.isdigit():
            yield name


# --- tmpfs artifact scanning -------------------------------------------------
#
# These functions feed :func:`ramopt.analyze.classify_tmpfs_artifacts`. They do
# the (read-only) filesystem and ``/proc`` walking; all the *decisions* live in
# the pure analyzer so they stay unit-testable.

# Filesystem types whose contents occupy RAM (so deleting files frees memory).
TMPFS_TYPES = frozenset({"tmpfs", "ramfs"})


def collect_tmpfs_mounts(mounts_path: str = "/proc/mounts") -> list[dict[str, str]]:
    """Return the RAM-backed (tmpfs/ramfs) mounts from ``/proc/mounts``."""
    text = read_text(mounts_path)
    if not text:
        return []
    return [m for m in proc.parse_mounts(text) if m["fstype"] in TMPFS_TYPES]


def collect_open_paths(proc_root: str = PROC_ROOT, under: list[str] | None = None) -> set[str]:
    """Best-effort set of paths any process currently references.

    Scans each PID's ``cwd``, ``exe`` and open file descriptors (``fd/*``), plus
    memory-mapped files (``maps``), resolving them to absolute paths.  When
    ``under`` is given, only paths beneath one of those mountpoints are kept, so
    the result stays small.  Permission errors and races are ignored — a missed
    path only makes the reclaimer *more* conservative, never less safe.
    """
    prefixes = tuple(p.rstrip("/") + "/" for p in (under or []))

    def keep(path: str) -> bool:
        return not prefixes or any(path == p[:-1] or path.startswith(p) for p in prefixes)

    found: set[str] = set()
    for entry in _iter_pids(proc_root):
        base = os.path.join(proc_root, entry)
        for link in ("cwd", "exe"):
            target = _readlink(os.path.join(base, link))
            if target and keep(target):
                found.add(target)
        fd_dir = os.path.join(base, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            fds = []
        for fd in fds:
            target = _readlink(os.path.join(fd_dir, fd))
            # The kernel appends " (deleted)" to unlinked-but-open targets.
            if target:
                target = target.removesuffix(" (deleted)")
                if keep(target):
                    found.add(target)
        _collect_mapped_files(os.path.join(base, "maps"), keep, found)
    return found


def _collect_mapped_files(maps_path: str, keep, found: set[str]) -> None:
    """Add file-backed mappings from a ``/proc/<pid>/maps`` file to ``found``."""
    text = read_text(maps_path)
    if not text:
        return
    for line in text.splitlines():
        # Format: "addr perms offset dev inode   /path". Path starts at col 6.
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith("/"):
            path = parts[5].removesuffix(" (deleted)")
            if keep(path):
                found.add(path)


def scan_tmpfs_artifacts(
    mountpoints: list[str],
    *,
    now: float,
    current_uid: int,
    min_size_kb: int = 0,
) -> list[dict]:
    """Scan the top-level entries of each tmpfs mount into size/age records.

    Only the *immediate* children of each mountpoint are listed (so the unit of
    reclaim is a whole download dir, not 280k individual files).  Each record
    carries ``path, name, mount, size_kb, age_days, uid, is_symlink``.  ``now``
    is injected (epoch seconds) so age is deterministic in tests.  Entries
    smaller than ``min_size_kb`` are dropped to keep the report focused.

    Age is the time since the entry was last *modified* (the newest mtime in its
    tree), never since it was last *accessed*: atime is bumped by any read — a
    backup, a file indexer, even this tool's own size walk — so using it would
    make long-idle scratch look freshly used.  Walking the tree (already done for
    size) means a directory whose top entry is old but which has recently-written
    files inside is still correctly seen as recent.
    """
    records: list[dict] = []
    seen: set[str] = set()
    for mount in mountpoints:
        try:
            names = os.listdir(mount)
        except OSError:
            continue
        for name in names:
            path = os.path.join(mount, name)
            if path in seen:
                continue
            seen.add(path)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            is_symlink = os.path.islink(path)
            if is_symlink:
                size_kb, newest_mtime = 0, st.st_mtime  # don't follow symlinks
            else:
                size_kb, newest_mtime = _tree_size_and_mtime(path)
            if size_kb < min_size_kb:
                continue
            records.append({
                "path": path,
                "name": name,
                "mount": mount,
                "size_kb": size_kb,
                "age_days": max((now - newest_mtime) / 86400.0, 0.0),
                "uid": st.st_uid,
                "is_symlink": is_symlink,
            })
    return records


def _tree_size_and_mtime(path: str) -> tuple[int, float]:
    """Return ``(size_kb, newest_mtime)`` for a file or directory tree.

    Size is a file's own size or a dir's tree total (stays on one filesystem,
    never follows symlinks, mirroring ``du -x``).  ``newest_mtime`` is the most
    recent modification time anywhere in the tree — the honest "last changed"
    signal for reclaim, computed in the same walk so it costs nothing extra.
    Access time (atime) is deliberately not consulted; see
    :func:`scan_tmpfs_artifacts`.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return 0, 0.0
    if not os.path.isdir(path) or os.path.islink(path):
        return _bytes_to_kb(st.st_size), st.st_mtime
    total = st.st_size
    newest = st.st_mtime
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            try:
                entry = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            total += entry.st_size
            if entry.st_mtime > newest:
                newest = entry.st_mtime
    return _bytes_to_kb(total), newest


def _bytes_to_kb(size: int) -> int:
    return (size + 1023) // 1024


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def current_uid() -> int:
    """The user id of the human invoking the tool — honouring ``sudo``.

    Under ``sudo`` the process uid is 0, but the files and workloads the user
    means are still their own (uid 1000, exported as ``SUDO_UID``).  Honouring
    it keeps a dry-run (run as the user) and the ``sudo ... --apply`` that the
    tool prints in agreement: the same user-owned dev servers are planned and
    then actually stopped, instead of being silently dropped as "another user's"
    once re-run as root.  Used to limit both tmpfs reclaim and the stop planner
    to the caller's own processes/files.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        return int(sudo_uid)
    return os.getuid()


# --- workload enumeration (for the `stop` planner) ---------------------------
#
# The `stop` command needs three read-only facts: which processes are running
# (with their supervisor, so we act on the container/unit, not a respawning
# PID), the chain of our own ancestors (which must never be signalled), and the
# list of Docker containers. As everywhere else, the *decisions* live in the
# pure analyzer; this module only gathers.


def collect_self_ancestry(proc_root: str = PROC_ROOT, pid: int | None = None) -> set[int]:
    """Return the PIDs from ``pid`` (default: this process) up to PID 1.

    Walking the ``PPid`` chain yields exactly the processes whose death would
    take down the session running this tool — the CLI, its shell, the terminal,
    the login session, ``init``.  The stop planner treats every one of them as
    untouchable, independent of any allowlist.  ``pid`` is injectable so the
    walk is deterministic in tests.
    """
    start = os.getpid() if pid is None else pid
    chain: set[int] = {1}
    seen: set[int] = set()
    current = start
    while current and current > 0 and current not in seen:
        seen.add(current)
        chain.add(current)
        status_text = read_text(os.path.join(proc_root, str(current), "status"))
        if not status_text:
            break
        current = proc.parse_status(status_text).get("ppid") or 0
    return chain


def collect_workload_processes(proc_root: str = PROC_ROOT) -> list[dict]:
    """One enriched record per process for the stop planner.

    Extends :func:`collect_processes` with the two fields the planner needs:
    ``cmdline`` (to match dev-server patterns the bare ``name`` would miss, e.g.
    ``next-server``) and ``supervisor``/``supervisor_id`` (from cgroup, to route
    the action to ``docker stop`` / ``systemctl stop`` instead of a raw signal).
    """
    records: list[dict] = []
    for entry in _iter_pids(proc_root):
        base = os.path.join(proc_root, entry)
        status_text = read_text(os.path.join(base, "status"))
        if not status_text:
            continue
        info = proc.parse_status(status_text)

        pss_kb: int | None = None
        rollup_text = read_text(os.path.join(base, "smaps_rollup"))
        if rollup_text:
            pss_kb = proc.parse_smaps_rollup(rollup_text).get("Pss")

        cgroup_text = read_text(os.path.join(base, "cgroup")) or ""
        sup = proc.parse_cgroup(cgroup_text)

        records.append({
            "pid": info["pid"],
            "ppid": info["ppid"],
            "name": info["name"],
            "uid": info["uid"],
            "rss_kb": info["rss_kb"],
            "pss_kb": pss_kb,
            "cmdline": _read_cmdline(os.path.join(base, "cmdline")),
            "supervisor": sup["supervisor"],
            "supervisor_id": sup["id"],
        })
    return records


def _read_cmdline(path: str) -> str:
    """Read ``/proc/<pid>/cmdline`` (NUL-separated argv) as a single string."""
    text = read_text(path)
    if not text:
        return ""
    return text.replace("\x00", " ").strip()


def _default_docker_ps() -> str | None:
    """Run ``docker ps`` for running containers; ``None`` if unavailable.

    Connecting to the Docker socket needs root or ``docker`` group membership;
    a permission/connection failure simply yields ``None`` and the planner
    proceeds without containers (the human report flags that docker was present
    but unreachable so the user knows to re-run under sudo).
    """
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(
            ["docker", "ps", "--no-trunc", "--format",
             "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def docker_present() -> bool:
    """True if the ``docker`` CLI exists (regardless of socket access)."""
    import shutil
    return shutil.which("docker") is not None


def collect_docker_containers(runner=_default_docker_ps) -> list[dict[str, str]]:
    """Return running Docker containers, or ``[]`` when docker is unreachable."""
    text = runner()
    return proc.parse_docker_ps(text) if text else []
