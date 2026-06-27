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
"""Pure parsers for the ``/proc`` text formats this tool consumes.

Every function here takes a string and returns plain data structures.  Nothing
in this module touches the filesystem, so the parsers can be exercised directly
against captured fixtures (see ``tests/fixtures``).  All memory values are
returned in kibibytes (kB), matching the kernel's own units.
"""

from __future__ import annotations

import re

# Matches kernel "Key:   <number> kB" / "Key:  <number>" lines used by
# meminfo, smaps_rollup and the VmRSS-style lines of status.
_KV_KB = re.compile(r"^([A-Za-z0-9_()]+):\s+(\d+)(?:\s+kB)?\s*$")

# Matches a pressure line: "some avg10=0.00 avg60=0.00 avg300=0.83 total=123".
_PRESSURE_LINE = re.compile(r"^(some|full)\s+(.*)$")


def parse_mounts(text: str) -> list[dict[str, str]]:
    """Parse ``/proc/mounts`` (or ``/proc/self/mountinfo`` fstab form) lines.

    Each line is ``device mountpoint fstype options dump pass``; we keep the
    first four fields and octal-unescape the mountpoint (the kernel encodes
    spaces as ``\\040`` etc.).  Malformed lines are skipped rather than raising.
    Returns a list of ``{"device", "mountpoint", "fstype", "options"}`` dicts.
    """
    mounts: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mounts.append({
            "device": _unescape_mount(parts[0]),
            "mountpoint": _unescape_mount(parts[1]),
            "fstype": parts[2],
            "options": parts[3],
        })
    return mounts


def _unescape_mount(field: str) -> str:
    """Decode the kernel's octal escapes (e.g. ``\\040`` -> space) in a path."""
    if "\\" not in field:
        return field
    out: list[str] = []
    i = 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) + 1 and field[i + 1:i + 4].isdigit():
            try:
                out.append(chr(int(field[i + 1:i + 4], 8)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(field[i])
        i += 1
    return "".join(out)


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse ``/proc/meminfo`` into ``{field: value_in_kB}``.

    Unparseable lines are skipped rather than raising, so a kernel that adds an
    unfamiliar field never breaks the tool.
    """
    fields: dict[str, int] = {}
    for line in text.splitlines():
        match = _KV_KB.match(line)
        if match:
            fields[match.group(1)] = int(match.group(2))
    return fields


def parse_status(text: str) -> dict[str, object]:
    """Parse the memory-relevant fields of ``/proc/<pid>/status``.

    Returns a dict with ``name`` (str), ``pid`` (int or None), ``uid`` (int or
    None, the real uid), ``rss_kb`` and ``swap_kb`` (ints, defaulting to 0).
    """
    name = ""
    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None
    rss_kb = 0
    swap_kb = 0
    for line in text.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "Name":
            name = value
        elif key == "Pid":
            pid = _to_int(value)
        elif key == "PPid":
            ppid = _to_int(value)
        elif key == "Uid":
            # "Uid:\t<real>\t<effective>\t..."; take the real uid.
            uid = _to_int(value.split()[0]) if value.split() else None
        elif key == "VmRSS":
            rss_kb = _kb_value(value)
        elif key == "VmSwap":
            swap_kb = _kb_value(value)
    return {"name": name, "pid": pid, "ppid": ppid, "uid": uid,
            "rss_kb": rss_kb, "swap_kb": swap_kb}


def parse_smaps_rollup(text: str) -> dict[str, int]:
    """Parse ``/proc/<pid>/smaps_rollup`` into a ``{field: kB}`` mapping.

    The leading address-range header line has no ``Key:`` form and is ignored.
    Of interest to callers: ``Pss`` (proportional set size — RAM fairly charged
    to this process), ``Rss`` and ``Swap``.
    """
    fields: dict[str, int] = {}
    for line in text.splitlines():
        match = _KV_KB.match(line)
        if match:
            fields[match.group(1)] = int(match.group(2))
    return fields


def parse_pressure(text: str) -> dict[str, dict[str, float]]:
    """Parse ``/proc/pressure/memory`` (PSI) into nested floats.

    Example return::

        {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.83, "total": 211.0},
         "full": {...}}
    """
    result: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        match = _PRESSURE_LINE.match(line.strip())
        if not match:
            continue
        scope, rest = match.group(1), match.group(2)
        metrics: dict[str, float] = {}
        for token in rest.split():
            key, _, value = token.partition("=")
            number = _to_float(value)
            if number is not None:
                metrics[key] = number
        result[scope] = metrics
    return result


# A container id is 64 hex chars; we keep the 12-char short form Docker shows.
_DOCKER_ID = re.compile(r"docker[-/]([0-9a-f]{12,64})")
# A systemd unit path token — either a managed ".service" or a transient
# ".scope". Which one is the *leaf* of the cgroup path decides supervision:
# a ".service" leaf can carry Restart= (managed), while a ".scope" leaf merely
# groups interactively-launched processes (session-N.scope, app-*.scope,
# ptyxis-spawn-*/vte-spawn-*) and never respawns — so a ".scope" leaf means
# unsupervised, and a plain SIGTERM is the correct action there.
_UNIT_TOKEN = re.compile(r"([A-Za-z0-9@:._\\-]+\.(?:service|scope))")


def parse_cgroup(text: str) -> dict[str, str | None]:
    """Identify a process's supervisor from its ``/proc/<pid>/cgroup`` text.

    Returns ``{"supervisor": "docker"|"systemd"|None, "id": str|None}``.  The
    *unit of action* for stopping a workload is its supervisor, not the bare
    PID: a container must be stopped with ``docker stop`` and a managed
    ``.service`` with ``systemctl stop``, or a restart policy will simply
    respawn it.  Docker is detected first (its scope lives *under* a systemd
    slice on cgroup v2, so order matters); a ``.service`` is reported as a
    systemd supervisor.  A bare ``.scope`` is treated as *unsupervised*
    (``None``) — see :data:`_SYSTEMD_UNIT`.
    """
    docker = _DOCKER_ID.search(text)
    if docker:
        return {"supervisor": "docker", "id": docker.group(1)[:12]}
    # No container — inspect the *leaf* (deepest, rightmost) unit on the cgroup
    # path. Prefer the unified v2 hierarchy line ("0::<path>"); fall back to any
    # line for cgroup v1. Only a ".service" leaf is a managed supervisor.
    lines = text.splitlines()
    paths = [ln for ln in lines if ln.startswith("0::")] or lines
    leaf: str | None = None
    for line in paths:
        path = line.rsplit(":", 1)[-1]
        for match in _UNIT_TOKEN.finditer(path):
            leaf = match.group(1)  # keep the last => rightmost => deepest
    if leaf and leaf.endswith(".service"):
        return {"supervisor": "systemd", "id": leaf}
    return {"supervisor": None, "id": None}


def parse_docker_ps(text: str) -> list[dict[str, str]]:
    """Parse tab-separated ``docker ps`` output into container records.

    The collector requests a fixed ``--format`` of
    ``{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.State}}\\t{{.Status}}`` so this
    parser stays trivial and stable.  Lines with too few fields are skipped.
    The id is normalised to its 12-char short form for matching against cgroups.
    """
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        rows.append({
            "id": parts[0].strip()[:12],
            "name": parts[1].strip(),
            "image": parts[2].strip(),
            "state": parts[3].strip(),
            "status": parts[4].strip(),
        })
    return rows


def _kb_value(value: str) -> int:
    """Extract the integer kB count from a "  7708 kB" style value."""
    parts = value.split()
    return _to_int(parts[0]) or 0 if parts else 0


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
