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
"""Interpret raw ``/proc`` data into a human-meaningful memory picture.

Pure functions only: they take the dicts produced by :mod:`ramopt.proc` plus a
list of per-process records and return structured analysis.  This is where the
"why is so much RAM used" reasoning lives — including the central Linux fact
that page cache counted as "used" by naive tools is reclaimable, so
``MemAvailable`` is the number that actually matters.
"""

from __future__ import annotations

import fnmatch

# Heuristic thresholds, expressed as fractions of MemTotal unless noted.
# They are deliberately conservative: a flag means "worth a human look", never
# "take action automatically".
_LOW_AVAILABLE_FRAC = 0.10        # < 10% available => genuine pressure
_HIGH_SWAP_FRAC = 0.20            # > 20% of swap in use => meaningful swapping
_HIGH_SUNRECLAIM_FRAC = 0.15      # unreclaimable slab > 15% of RAM => kernel/driver
_HIGH_SHMEM_FRAC = 0.25           # shmem/tmpfs > 25% of RAM => check tmpfs mounts
_DOMINANT_PROC_FRAC = 0.30        # one process > 30% of RAM => single hog
# PSI "some" 60-second average above this means tasks are stalling on memory.
_PRESSURE_STALL_AVG60 = 5.0


def memory_breakdown(meminfo: dict[str, int]) -> dict[str, object]:
    """Turn a parsed meminfo mapping into a structured breakdown (kB).

    The components are grouped so they sum, roughly, back to MemTotal and make
    the reclaimable-vs-not distinction explicit.
    """
    total = meminfo.get("MemTotal", 0)
    free = meminfo.get("MemFree", 0)
    available = meminfo.get("MemAvailable", 0)

    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)
    shmem = meminfo.get("Shmem", 0)
    # "Cached" includes Shmem/tmpfs, which is NOT reclaimable like file cache.
    page_cache = max(cached - shmem, 0)
    sreclaimable = meminfo.get("SReclaimable", 0)
    sunreclaim = meminfo.get("SUnreclaim", 0)

    anon = meminfo.get("AnonPages", 0)
    kernel_stack = meminfo.get("KernelStack", 0)
    page_tables = meminfo.get("PageTables", 0)

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)

    # Cache the kernel can hand back instantly under pressure.
    reclaimable_cache = page_cache + buffers + sreclaimable
    # What MemAvailable already accounts as "in use" and not trivially freeable.
    truly_used = max(total - available, 0)

    return {
        "total_kb": total,
        "free_kb": free,
        "available_kb": available,
        "truly_used_kb": truly_used,
        "available_pct": _pct(available, total),
        "truly_used_pct": _pct(truly_used, total),
        "components_kb": {
            "process_anon": anon,
            "shmem_tmpfs": shmem,
            "page_cache": page_cache,
            "buffers": buffers,
            "slab_reclaimable": sreclaimable,
            "slab_unreclaimable": sunreclaim,
            "kernel_stack": kernel_stack,
            "page_tables": page_tables,
        },
        "reclaimable_cache_kb": reclaimable_cache,
        "swap": {
            "total_kb": swap_total,
            "used_kb": swap_used,
            "used_pct": _pct(swap_used, swap_total),
        },
    }


def top_processes(processes: list[dict], limit: int = 10) -> list[dict]:
    """Rank process records by their memory charge, descending.

    Each record should carry ``pss_kb`` (preferred, from smaps_rollup) and/or
    ``rss_kb``.  Ranking uses PSS when present (it fairly splits shared pages),
    otherwise RSS.  The ``sort_key_kb`` and ``ranked_by`` fields are added so
    callers/reports do not re-derive the choice.
    """
    ranked = []
    for proc in processes:
        pss = proc.get("pss_kb")
        if pss is not None:
            key, basis = pss, "pss"
        else:
            key, basis = proc.get("rss_kb", 0), "rss"
        ranked.append({**proc, "sort_key_kb": key, "ranked_by": basis})
    ranked.sort(key=lambda p: p["sort_key_kb"], reverse=True)
    return ranked[:limit]


def detect_flags(
    breakdown: dict[str, object],
    pressure: dict[str, dict[str, float]] | None,
    top: list[dict],
) -> list[dict[str, str]]:
    """Produce plain-language warnings about *why* memory looks high.

    Returns a list of ``{"id", "severity", "title", "detail"}`` dicts.  An empty
    list is the common, healthy case and should be reported as reassurance.
    """
    flags: list[dict[str, str]] = []
    total = breakdown["total_kb"] or 1
    components = breakdown["components_kb"]

    if breakdown["available_kb"] < _LOW_AVAILABLE_FRAC * total:
        flags.append({
            "id": "low_available",
            "severity": "high",
            "title": "Low available memory",
            "detail": (
                "MemAvailable is under 10% of RAM. Unlike cache fill, this is "
                "real pressure: new allocations may trigger reclaim, swapping "
                "or the OOM killer. Investigate the top processes below."
            ),
        })

    swap = breakdown["swap"]
    if swap["total_kb"] > 0 and swap["used_kb"] > _HIGH_SWAP_FRAC * swap["total_kb"]:
        flags.append({
            "id": "swapping",
            "severity": "medium",
            "title": "Significant swap in use",
            "detail": (
                "Over 20% of swap is occupied. Some swap use is normal for idle "
                "anonymous pages, but heavy use alongside memory pressure means "
                "anonymous memory exceeds RAM. Dropping caches will NOT help."
            ),
        })

    if swap["total_kb"] == 0:
        flags.append({
            "id": "no_swap",
            "severity": "medium",
            "title": "No swap configured",
            "detail": (
                "SwapTotal is zero. With no swap on an overcommitted host, a "
                "memory spike has no soft landing: the kernel cannot page idle "
                "anonymous memory out, so it jumps straight to the OOM killer. "
                "A modest swapfile (8-16 GiB) adds an OOM safety net without "
                "encouraging real swapping. Add one with: "
                "`ram-optimizer swap --size-gb 16`."
            ),
        })

    if components["slab_unreclaimable"] > _HIGH_SUNRECLAIM_FRAC * total:
        flags.append({
            "id": "high_unreclaimable_slab",
            "severity": "medium",
            "title": "Large unreclaimable kernel slab",
            "detail": (
                "SUnreclaim is a large share of RAM. This is kernel/driver "
                "memory that cache-dropping cannot free. Persistent growth can "
                "indicate a kernel or driver leak; check `slabtop -o`."
            ),
        })

    if components["shmem_tmpfs"] > _HIGH_SHMEM_FRAC * total:
        flags.append({
            "id": "high_shmem",
            "severity": "medium",
            "title": "Large shared / tmpfs memory",
            "detail": (
                "Shmem (tmpfs, /dev/shm, shared segments) is a large share of "
                "RAM. tmpfs lives in RAM until files are deleted — it is not "
                "page cache and is not freed by dropping caches. Check "
                "`df -h -t tmpfs` and large files under /dev/shm."
            ),
        })

    if top:
        leader = top[0]
        if leader["sort_key_kb"] > _DOMINANT_PROC_FRAC * total:
            flags.append({
                "id": "dominant_process",
                "severity": "medium",
                "title": f"One process dominates RAM: {leader.get('name', '?')}",
                "detail": (
                    "A single process accounts for over 30% of RAM. If "
                    "unexpected, inspect it (a leak, a large cache, or simply a "
                    "memory-hungry workload). Restarting it is the safe fix — "
                    "this tool never kills processes for you."
                ),
            })

    if pressure:
        some_avg60 = pressure.get("some", {}).get("avg60", 0.0)
        if some_avg60 > _PRESSURE_STALL_AVG60:
            flags.append({
                "id": "psi_stall",
                "severity": "high",
                "title": "Tasks are stalling on memory (PSI)",
                "detail": (
                    "The kernel pressure-stall 'some' 60s average is elevated, "
                    "meaning tasks are waiting on memory right now. This is the "
                    "most honest signal of real shortage."
                ),
            })

    return flags


def summarize(
    breakdown: dict[str, object],
    top: list[dict],
    pressure: dict[str, dict[str, float]] | None,
    flags: list[dict[str, str]],
) -> dict[str, object]:
    """Assemble the full analysis object consumed by the reporters."""
    return {
        "breakdown": breakdown,
        "top_processes": top,
        "pressure": pressure or {},
        "flags": flags,
        "healthy": not any(f["severity"] == "high" for f in flags),
    }


def _pct(part: int, whole: int) -> float:
    """Percentage of ``part`` in ``whole``, rounded to 1 dp, 0 when whole==0."""
    if whole <= 0:
        return 0.0
    return round(part / whole * 100, 1)


# --- tmpfs artifact reclaim --------------------------------------------------
#
# tmpfs (e.g. /tmp, /dev/shm) lives in RAM: every byte of a file there is a byte
# of memory that dropping caches will NOT free — only deleting the file frees
# it. These pure rules decide which top-level tmpfs entries are *safe* to delete
# (abandoned tool scratch, or idle and owned by the user) versus which must be
# kept (held open by a live process, a system socket/lock, or another user's).
# The classifier never touches the filesystem; it reasons over records produced
# by :func:`ramopt.collect.scan_tmpfs_artifacts`.

# Names that must never be deleted: IPC sockets, lock dirs, per-service private
# tmp, and database sockets. Matched as globs against the entry's basename.
_PROTECTED_GLOBS = (
    ".X*-unix", ".XIM-unix", ".font-unix", ".ICE-unix", ".Test-unix", ".*-unix",
    ".X*-lock", "ssh-*", "systemd-private-*", "snap-private-tmp",
    "PostgreSQL.*", ".s.PGSQL.*", "lttng-*", "dbus-*", "gpg-*", ".gnupg",
)

# Known single-use installer/download scratch: safe to delete outright once no
# process holds it open. These never get reused — a fresh run re-downloads.
_ABANDONED_GLOBS = (
    "playwright-download-*", "chrome-headless-shell-*",
    "*.zip", "*.tar", "*.tar.*", "*.tgz", "*.deb", "*.AppImage",
    "*.crdownload", "*.part", "core.*",
    "miniforge*.sh", "miniconda*.sh", "sonar-scanner*",
)

# Intentional cross-run caches: deleting them is safe but costs a re-warm, so
# they are reclaimed only when the caller explicitly opts in (--include-caches).
_REUSE_CACHE_GLOBS = (
    "node-compile-cache", "v8-compile-cache*", "*-cache", "*-cache-*",
    "*cache*", "*.cache", ".cache", "@prisma",
)


def _matches_any(name: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in globs)


def _is_in_use(path: str, open_paths: set[str]) -> bool:
    """True if ``path`` itself, or anything beneath it, is open by a process."""
    prefix = path.rstrip("/") + "/"
    for opened in open_paths:
        if opened == path or opened.startswith(prefix):
            return True
    return False


def classify_tmpfs_artifacts(
    artifacts: list[dict],
    open_paths: set[str],
    *,
    current_uid: int,
    idle_hours: float = 24.0,
    include_caches: bool = False,
    full: bool = False,
) -> list[dict]:
    """Classify each tmpfs entry and decide whether it is safe to reclaim.

    ``artifacts`` are records from :func:`ramopt.collect.scan_tmpfs_artifacts`
    (``path, name, mount, size_kb, age_days, uid, is_symlink``).  ``open_paths``
    is the set of paths any running process currently references (fd/cwd/maps).
    ``idle_hours`` is the age (in hours) past which a file you own is treated as
    idle and safe to delete.  ``full`` ignores age entirely — every entry you
    own that is not currently open and not a system socket becomes reclaimable
    (it also implies ``include_caches``).  The three hard guards are *never*
    bypassed, even with ``full``: another user's files, symlinks, and anything a
    live process holds open are always kept.

    Each returned record adds ``klass`` (one of ``protected``, ``in_use``,
    ``abandoned``, ``reuse_cache``, ``idle``, ``recent``), ``reclaimable``
    (bool) and a human ``reason``.  The safety order is deliberate: *not mine*,
    *protected* and *in use* are decided before any "delete me" class, so a file
    can never be both in use and reclaimable.
    """
    classified: list[dict] = []
    for art in artifacts:
        name = art.get("name", "")
        path = art.get("path", "")
        klass, reclaimable, reason = _classify_one(
            name, path, art, open_paths,
            current_uid=current_uid, idle_hours=idle_hours,
            include_caches=include_caches, full=full,
        )
        classified.append({**art, "klass": klass,
                           "reclaimable": reclaimable, "reason": reason})
    return classified


def _classify_one(name, path, art, open_paths, *, current_uid, idle_hours,
                  include_caches, full=False):
    age_hours = art.get("age_days", 0.0) * 24.0

    # --- hard guards: NEVER bypassed, not even by `full` ---------------------
    # Another user's files, symlinks (we never follow them), system
    # sockets/locks, and anything a live process holds open are always kept.
    if art.get("uid") not in (None, current_uid):
        return "protected", False, "owned by another user"
    if art.get("is_symlink"):
        return "protected", False, "symlink (not followed)"
    if _matches_any(name, _PROTECTED_GLOBS):
        return "protected", False, "system socket/lock/private dir"
    if _is_in_use(path, open_paths):
        return "in_use", False, "open by a running process"

    # --- past here: owned by you, not open, not a system socket --------------
    if _matches_any(name, _ABANDONED_GLOBS):
        return "abandoned", True, "single-use download/installer scratch"

    if _matches_any(name, _REUSE_CACHE_GLOBS):
        return ("reuse_cache", include_caches or full,
                "reusable cache (re-warms on next run)")

    if age_hours >= idle_hours:
        return "idle", True, f"untouched for {age_hours:.0f}h, owned by you"

    if full:
        return ("recent", True,
                "full mode: owned by you, not in use — deleting regardless of age")
    return "recent", False, f"modified {age_hours:.0f}h ago — review before deleting"


# --- stopping non-essential workloads ---------------------------------------
#
# `stop` is the tool's only process-affecting action, so its planner is built
# the inverse-safe way: an ALLOWLIST of recognised developer/app workloads is
# eligible, and everything else is left strictly alone. A missing allowlist
# entry just means a workload is not offered (harmless); there is no denylist
# whose omission could cause an essential to be killed. On top of that, a hard
# guard refuses anything on the essential list, any kernel thread, and any PID
# the caller marked untouchable (this process and its whole ancestry — the CLI,
# its shell, the terminal, the session, init). Two independent barriers.
#
# The unit of action is the *supervisor*, never a bare PID: a container is
# stopped with `docker stop` (graceful SIGTERM + wait) and a managed unit with
# `systemctl stop`, because signalling the PID of a process with a restart
# policy just makes it respawn. Containerised and systemd-managed processes are
# therefore grouped by supervisor; only genuinely standalone dev servers are
# signalled directly.

# Process names that must never be stopped, even if they somehow matched an
# allowlist. The desktop session, core daemons, the container runtime itself
# (we stop containers, not dockerd), terminals and shells, and this tool.
_ESSENTIAL_NAME_GLOBS = (
    "systemd", "systemd-*", "(sd-pam)", "init", "kthreadd",
    "dbus-daemon", "dbus-broker", "dbus-run-session",
    "NetworkManager", "wpa_supplicant", "ModemManager", "avahi-daemon",
    "polkitd", "rtkit-daemon", "udisksd", "upowerd", "accounts-daemon",
    "gdm*", "gnome-shell", "gnome-session*", "gnome-keyring*", "mutter",
    "Xorg", "Xwayland", "plasmashell", "kwin*", "sddm*",
    "pipewire", "pipewire-*", "wireplumber", "pulseaudio",
    "sshd", "login", "getty", "agetty", "(agetty)", "systemd-logind",
    "ptyxis", "gnome-terminal*", "konsole", "kgx", "alacritty", "kitty",
    "wezterm", "wezterm-gui", "foot", "xterm", "tmux*", "screen",
    "bash", "sh", "zsh", "fish", "dash", "-bash", "login-shell",
    "dockerd", "containerd", "containerd-shim*", "docker-proxy", "runc",
    "gvfs*", "gvfsd*", "at-spi*", "ibus*", "ibus-*", "fcitx*",
    "claude", "node-claude", "ssh-agent", "gpg-agent",
)

# Substrings (matched case-insensitively against the full command line) that
# identify a standalone developer server safe to stop with a graceful SIGTERM.
_DEV_SERVER_SUBSTRINGS = (
    "next-server", "next dev", "next start", "next-router-worker",
    "vite", "webpack", "webpack-dev-server", "nodemon", "react-scripts",
    "ng serve", "vue-cli-service", "astro dev", "nuxt", "remix vite",
    "storybook", "rollup -w", "esbuild --serve", "parcel",
    "vercel dev", "wrangler dev", "turbo dev", "turbopack",
    "jest --watch", "vitest", "playwright test",
    "vector --config", "gatsby develop", "ng build --watch",
)

# Substrings for user-owned apps that are non-essential but have network/UX
# side effects (a VPN tunnel, a diagnostic GUI). In the conservative default
# these are *surfaced for review* — listed with their cost — but never
# auto-selected. `--full-complete-sweep` promotes them to eligible (see below).
_REVIEW_APP_SUBSTRINGS = (
    "protonvpn", "openvpn", "wireguard", "nordvpn",
    "netdiag", "--gui", "syncthing", "dropbox", "megasync",
)

# Broader allowlist used only by the `--full-*` modes: developer runtimes and
# tooling that indicate a user-launched workload but are not specific dev
# *servers* (so the conservative default leaves them alone). Selection stays
# POSITIVE-ID even in full mode: we never invert to "stop everything not on the
# essential list", because process names in /proc are truncated to 15 chars and
# a denylist would inevitably miss a desktop helper (e.g. `mutter-x11-fram`).
# Matching a runtime here can only ever catch a dev process, never the desktop.
# Kept deliberately specific — bare "python"/"java" are excluded as too broad.
_DEV_RUNTIME_SUBSTRINGS = (
    # JS/TS runtimes and package managers running app code
    "node ", "/node ", "npm ", "npm exec", "npx ", "pnpm", "yarn",
    "bun ", "/bun ", "deno ", "tsx ", "ts-node", "nodemon",
    # Python app servers and dev tooling (NOT bare "python" — too broad)
    "uv ", "uvx", "uv tool", "uvicorn", "gunicorn", "hypercorn",
    "flask run", "runserver", "http.server", "poetry run", "pipenv run",
    # MCP / language servers commonly left running by editors and agents
    "mcp-server", "mcp_server", "-mcp", "language-server",
    # Other compiled/managed dev runtimes
    "cargo run", "cargo watch", "go run", "gradle",
    "mvn ", "./mvnw", "dotnet run", "dotnet watch", "rails server",
    "bundle exec",
)

# The three breadth modes for `stop`, escalating left to right. See `plan_stop`.
STOP_MODES = ("default", "full-safe", "full-complete-sweep")

SIGTERM = 15


def plan_stop(
    processes: list[dict],
    containers: list[dict],
    *,
    current_uid: int,
    protected_pids: set[int],
    scope: str = "all",
    keep: tuple[str, ...] = (),
    mode: str = "default",
) -> dict[str, object]:
    """Decide, purely, which workloads may be gracefully stopped.

    ``processes`` are :func:`ramopt.collect.collect_workload_processes` records;
    ``containers`` are :func:`ramopt.collect.collect_docker_containers` records
    (possibly empty if the docker socket was unreachable — units are then still
    synthesised from cgroup ids).  ``protected_pids`` is the externally computed
    untouchable set (this process + ancestry + PID 1); ``scope`` is ``all`` /
    ``docker`` / ``processes``; ``keep`` is a tuple of name globs to exclude.

    ``mode`` selects how much is auto-selected — the two hard guards (ancestry
    and the essential-NAME list) are absolute in *every* mode:

    * ``default`` — Docker containers (all) + standalone dev *servers* on the
      narrow :data:`_DEV_SERVER_SUBSTRINGS` allowlist. systemd units and
      VPN/sync apps are only surfaced for review.
    * ``full-safe`` — also stops your non-allowlisted developer *runtime*
      processes (:data:`_DEV_RUNTIME_SUBSTRINGS`: node/npm/uv/MCP servers, …),
      but **spares stateful Docker containers** and still only surfaces systemd
      units and VPN/sync apps. "Safe" = it never stops anything holding
      persistent state or with network/UX side effects.
    * ``full-complete-sweep`` — the maximal reclaim toward the essential
      baseline: everything ``full-safe`` stops **plus all Docker containers,
      your systemd user services (``systemctl --user stop``), and the VPN/sync
      review apps**.

    Returns ``{mode, scope, units, skipped, review, eligible_kb,
    eligible_count}`` where each *unit* is one supervisor-level action
    (``{kind, key, label, category, rss_kb, members, command, signal}``) and
    ``skipped``/``review`` explain what was considered but not auto-selected.
    """
    full = mode in ("full-safe", "full-complete-sweep")
    sweep = mode == "full-complete-sweep"
    # The narrow default allowlist, broadened with developer runtimes in full
    # modes. Selection stays positive-ID in every mode (see _DEV_RUNTIME...).
    proc_substrings = (
        _DEV_SERVER_SUBSTRINGS + _DEV_RUNTIME_SUBSTRINGS if full
        else _DEV_SERVER_SUBSTRINGS
    )
    by_pid = {p["pid"]: p for p in processes if p.get("pid") is not None}
    # Two guard sets with different reach. The ancestry guard (this process, its
    # parents, init) is absolute and applies to every unit. The essential-name
    # guard protects the *host* session (its shell, terminal, desktop daemons)
    # and so applies only to standalone process units — a container's own
    # internal `sh`/`postgres` must not block its graceful `docker stop`.
    ancestry_guard = set(protected_pids)
    essential_guard = {
        p["pid"] for p in processes if _is_guarded(p) and p.get("pid") is not None
    }
    process_guard = ancestry_guard | essential_guard

    units: list[dict] = []
    skipped: list[dict] = []
    review: list[dict] = []

    # 1) Docker containers — one unit per container, grouped from cgroups so the
    #    set is correct even when `docker ps` was unreachable (no names then).
    docker_pids_by_id: dict[str, list[int]] = {}
    for p in processes:
        if p.get("supervisor") == "docker" and p.get("supervisor_id"):
            docker_pids_by_id.setdefault(p["supervisor_id"], []).append(p["pid"])
    container_names = {c["id"]: c for c in containers}
    for cid in sorted(set(docker_pids_by_id) | set(container_names)):
        members = docker_pids_by_id.get(cid, [])
        meta = container_names.get(cid, {})
        name = meta.get("name") or cid
        rss = sum(by_pid.get(pid, {}).get("rss_kb", 0) for pid in members)
        unit = {
            "kind": "docker", "key": cid, "label": name,
            "category": "container",
            "image": meta.get("image", ""),
            "rss_kb": rss, "members": members,
            "command": f"docker stop {name}", "signal": None,
        }
        reason = _unit_block_reason(unit, members, ancestry_guard, keep, scope,
                                    wanted_scope="docker")
        # `--full-safe` deliberately spares stateful containers (databases keep
        # their data warm); only `--full-complete-sweep` stops them.
        if reason is None and mode == "full-safe":
            reason = ("stateful container spared by --full-safe; use "
                      "--full-complete-sweep to stop all containers")
        if reason:
            skipped.append({**_unit_brief(unit), "reason": reason})
        else:
            units.append(unit)

    # 2) Standalone (un-supervised) processes that match the dev-server
    #    allowlist (broadened to developer runtimes in the `--full-*` modes).
    for p in processes:
        pid = p.get("pid")
        if pid is None or p.get("supervisor") is not None:
            continue  # supervised processes are handled as their unit, or below
        cmd = (p.get("cmdline") or "").lower()
        if not _matches_substr(cmd, proc_substrings):
            continue
        category = ("dev-server" if _matches_substr(cmd, _DEV_SERVER_SUBSTRINGS)
                    else "dev-runtime")
        unit = {
            "kind": "process", "key": pid, "label": p.get("name", "?"),
            "category": category,
            "image": "", "rss_kb": p.get("rss_kb", 0), "members": [pid],
            "command": f"kill -TERM {pid}", "signal": SIGTERM,
        }
        reason = _unit_block_reason(unit, [pid], process_guard, keep, scope,
                                    wanted_scope="processes",
                                    uid_ok=p.get("uid") in (None, current_uid))
        if reason:
            skipped.append({**_unit_brief(unit), "reason": reason})
        else:
            units.append(unit)

    # 3) systemd-managed matches and review-only apps. In the default and
    #    `--full-safe` modes these are only *surfaced* (never auto-acted), since
    #    a systemd unit may respawn and a review app has network/UX side effects.
    #    `--full-complete-sweep` promotes both to eligible units: systemd matches
    #    are grouped by unit and stopped with `systemctl --user stop`; review
    #    apps get a graceful SIGTERM like any standalone process.
    systemd_members: dict[str, list[int]] = {}
    systemd_rss: dict[str, int] = {}
    for p in processes:
        pid = p.get("pid")
        if pid is None or pid in process_guard:
            continue
        cmd = (p.get("cmdline") or "").lower()
        uid_ok = p.get("uid") in (None, current_uid)
        if p.get("supervisor") == "systemd" and _matches_substr(cmd, proc_substrings):
            unit_id = p.get("supervisor_id")
            if sweep and uid_ok and unit_id:
                systemd_members.setdefault(unit_id, []).append(pid)
                systemd_rss[unit_id] = systemd_rss.get(unit_id, 0) + p.get("rss_kb", 0)
            else:
                skipped.append({
                    "label": p.get("name", "?"), "category": "systemd",
                    "rss_kb": p.get("rss_kb", 0),
                    "reason": f"managed by systemd unit {unit_id} — "
                              f"stop with: systemctl stop {unit_id}"
                              + ("" if uid_ok else " (owned by another user)"),
                })
        elif (p.get("supervisor") is None and uid_ok
              and _matches_substr(cmd, _REVIEW_APP_SUBSTRINGS)):
            if sweep:
                unit = {
                    "kind": "process", "key": pid, "label": p.get("name", "?"),
                    "category": "review-app",
                    "image": "", "rss_kb": p.get("rss_kb", 0), "members": [pid],
                    "command": f"kill -TERM {pid}", "signal": SIGTERM,
                }
                reason = _unit_block_reason(unit, [pid], process_guard, keep,
                                            scope, wanted_scope="processes")
                if reason:
                    skipped.append({**_unit_brief(unit), "reason": reason})
                else:
                    units.append(unit)
            else:
                review.append({
                    "label": p.get("name", "?"), "category": "review",
                    "pid": pid, "rss_kb": p.get("rss_kb", 0),
                    "reason": "user app with network/UX side effects — stop manually "
                              "if you want to (not auto-selected)",
                })

    # Emit one unit per systemd user service (sweep mode only).
    for unit_id in sorted(systemd_members):
        members = systemd_members[unit_id]
        unit = {
            "kind": "systemd", "key": unit_id, "label": unit_id,
            "category": "systemd",
            "image": "", "rss_kb": systemd_rss[unit_id], "members": members,
            "command": f"systemctl --user stop {unit_id}", "signal": None,
        }
        reason = _unit_block_reason(unit, members, process_guard, keep, scope,
                                    wanted_scope="processes")
        if reason:
            skipped.append({**_unit_brief(unit), "reason": reason})
        else:
            units.append(unit)

    units.sort(key=lambda u: u["rss_kb"], reverse=True)
    eligible_kb = sum(u["rss_kb"] for u in units)
    return {
        "mode": mode,
        "scope": scope,
        "units": units,
        "skipped": skipped,
        "review": review,
        "eligible_kb": eligible_kb,
        "eligible_count": len(units),
        "guarded_count": len(process_guard),
    }


def _is_guarded(proc: dict) -> bool:
    """True if a process must never be signalled (matches the essential list).

    Matched on the process *name*, which is readable even for another user's
    process — unlike ``cmdline``, which is empty when we lack permission.  We
    deliberately do not treat an empty cmdline as guarded: for a container's
    root-owned members that only means "unreadable as non-root", and it would
    wrongly block the whole container, whose ``docker stop`` is graceful anyway.
    A standalone process can never be *selected* without a cmdline match, so a
    genuine kernel thread is excluded by construction, not by this guard.
    """
    return _matches_any(proc.get("name", ""), _ESSENTIAL_NAME_GLOBS)


def _unit_block_reason(unit, members, guarded, keep, scope, *,
                       wanted_scope, uid_ok=True):
    """Return why a unit is not auto-selected, or ``None`` if it is eligible."""
    if scope not in ("all", wanted_scope):
        return f"excluded by --{'docker-only' if scope == 'docker' else 'processes-only'}"
    if not uid_ok:
        return "owned by another user"
    if _matches_any(unit["label"], keep):
        return "excluded by --keep"
    if any(pid in guarded for pid in members):
        return "contains a guarded/essential process"
    if not members:
        return "no live process found"
    return None


def _unit_brief(unit: dict) -> dict:
    """The display subset of a unit, for the skipped list."""
    return {"label": unit["label"], "category": unit["category"],
            "rss_kb": unit["rss_kb"]}


def _matches_substr(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack for n in needles)


def summarize_reclaim(classified: list[dict], *, idle_hours: float,
                      full: bool = False) -> dict[str, object]:
    """Aggregate classified artifacts into totals for the reclaim report."""
    by_class: dict[str, dict[str, int]] = {}
    reclaimable_kb = 0
    for art in classified:
        bucket = by_class.setdefault(art["klass"], {"count": 0, "size_kb": 0})
        bucket["count"] += 1
        bucket["size_kb"] += art.get("size_kb", 0)
        if art["reclaimable"]:
            reclaimable_kb += art.get("size_kb", 0)
    return {
        "idle_hours": idle_hours,
        "full": full,
        "artifacts": classified,
        "by_class": by_class,
        "total_kb": sum(a.get("size_kb", 0) for a in classified),
        "reclaimable_kb": reclaimable_kb,
        "reclaimable": [a for a in classified if a["reclaimable"]],
    }
