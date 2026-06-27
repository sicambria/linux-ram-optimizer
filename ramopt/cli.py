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
"""Command-line entry point: wire collection, analysis and reporting together.

Subcommands:

* ``diagnose`` (default) — read-only explanation of current memory use.
* ``free`` — safe, opt-in cache reclaim; dry-run unless ``--apply``.
* ``reclaim`` — safe, opt-in deletion of idle/abandoned tmpfs files (the RAM
  that ``free`` cannot reclaim); dry-run unless ``--apply``.
* ``swap`` — add a swapfile as an OOM safety net; dry-run unless ``--apply``.
* ``stop`` — gracefully stop allowlisted non-essential workloads (Docker
  containers, standalone dev servers); dry-run unless ``--apply``.
"""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__, analyze, collect, remediate, report


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the ``ram-optimizer`` command."""
    parser = argparse.ArgumentParser(
        prog="ram-optimizer",
        description="Diagnose why Linux RAM is in use and reclaim cache safely.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    diagnose = sub.add_parser("diagnose", help="explain current memory use (read-only)")
    diagnose.add_argument("--json", action="store_true", help="emit JSON instead of text")
    diagnose.add_argument("--top", type=int, default=10, metavar="N",
                          help="show the top N processes by memory (default 10)")

    free = sub.add_parser("free", help="safely reclaim clean caches (opt-in)")
    free.add_argument("--level", type=int, choices=(1, 2, 3), default=1,
                      help="1=page cache, 2=slab, 3=both (default 1)")
    free.add_argument("--apply", action="store_true",
                      help="actually reclaim (requires root); default is dry-run")
    free.add_argument("--json", action="store_true", help="emit JSON instead of text")

    reclaim = sub.add_parser(
        "reclaim",
        help="find and free idle/abandoned files in tmpfs (/tmp, /dev/shm)")
    reclaim.add_argument("--apply", action="store_true",
                         help="actually delete the safe items; default is dry-run")
    reclaim.add_argument("--idle-hours", type=float, default=24.0, metavar="N",
                         help="treat your files untouched for N+ hours as idle "
                              "and safe to delete (default 24)")
    reclaim.add_argument("--include-caches", action="store_true",
                         help="also delete reusable caches (they re-warm next run)")
    reclaim.add_argument("--full", action="store_true",
                         help="delete ALL your tmpfs files regardless of age "
                              "(implies --include-caches). Still keeps files open "
                              "by a process, system sockets, and other users' files")
    reclaim.add_argument("--min-size", type=float, default=10.0, metavar="MB",
                         help="ignore entries smaller than MB (default 10)")
    reclaim.add_argument("--json", action="store_true", help="emit JSON instead of text")

    swap = sub.add_parser(
        "swap",
        help="add a swapfile as an OOM safety net (recommended when none exists)")
    swap.add_argument("--size-gb", type=int, default=None, metavar="N",
                      help=f"swapfile size in GiB "
                           f"({remediate.SWAP_MIN_GB}-{remediate.SWAP_MAX_GB})")
    swap.add_argument("--path", default=remediate.DEFAULT_SWAP_PATH,
                      help=f"swapfile path (default {remediate.DEFAULT_SWAP_PATH})")
    swap.add_argument("--swappiness", type=int, default=10, metavar="N",
                      help="set vm.swappiness after enabling (default 10; "
                           "use -1 to leave it unchanged)")
    swap.add_argument("--apply", action="store_true",
                      help="actually create+enable swap (requires root); default is dry-run")
    swap.add_argument("--json", action="store_true", help="emit JSON instead of text")

    stop = sub.add_parser(
        "stop",
        help="gracefully stop allowlisted non-essential workloads "
             "(docker containers, dev servers)")
    stop.add_argument("--apply", action="store_true",
                      help="actually stop them; default is dry-run")
    scope = stop.add_mutually_exclusive_group()
    scope.add_argument("--docker-only", action="store_true",
                       help="only stop docker containers")
    scope.add_argument("--processes-only", action="store_true",
                       help="only stop standalone dev-server processes")
    mode = stop.add_mutually_exclusive_group()
    mode.add_argument("--full-safe", action="store_true",
                      help="aggressive but safe: also stop your non-allowlisted "
                           "developer runtime processes (node, npm, uv, MCP "
                           "servers, …). SPARES stateful Docker containers, "
                           "systemd units and VPN/sync apps (surfaced for review)")
    mode.add_argument("--full-complete-sweep", action="store_true",
                      help="maximal reclaim toward the essential RAM baseline: "
                           "everything --full-safe stops PLUS all Docker "
                           "containers, your systemd user services, and VPN/sync "
                           "apps. Hard guards (desktop, daemons, this shell) "
                           "still apply")
    stop.add_argument("--keep", action="append", default=[], metavar="NAME",
                      help="exclude a unit by name/glob (repeatable)")
    stop.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def run_diagnose(args: argparse.Namespace) -> int:
    """Collect live data, analyze it and print the diagnosis."""
    meminfo = collect.collect_meminfo()
    if not meminfo:
        print("error: could not read /proc/meminfo (is this Linux?)", file=sys.stderr)
        return 2
    pressure = collect.collect_pressure()
    processes = collect.collect_processes()

    breakdown = analyze.memory_breakdown(meminfo)
    top = analyze.top_processes(processes, limit=max(args.top, 0))
    flags = analyze.detect_flags(breakdown, pressure, top)
    analysis = analyze.summarize(breakdown, top, pressure, flags)

    if args.json:
        print(report.render_diagnosis_json(analysis))
    else:
        print(report.render_diagnosis_human(analysis))
    return 0


def run_free(args: argparse.Namespace) -> int:
    """Plan or apply a safe cache reclaim and report the outcome."""
    def sample_available() -> int:
        return collect.collect_meminfo().get("MemAvailable", 0)

    result = remediate.run_free(
        level=args.level,
        apply=args.apply,
        sample_available=sample_available,
    )

    if args.json:
        print(report.render_free_json(result))
    else:
        print(report.render_free_human(result))

    # Non-zero exit when an apply was requested but refused (e.g. not root),
    # so scripts can detect that nothing happened.
    if args.apply and not result["applied"]:
        return 1
    return 0


def run_reclaim(args: argparse.Namespace) -> int:
    """Scan tmpfs, classify entries, and plan or apply deletion of safe ones."""
    mounts = collect.collect_tmpfs_mounts()
    mountpoints = [m["mountpoint"] for m in mounts]
    if not mountpoints:
        print("error: no tmpfs mounts found (is this Linux?)", file=sys.stderr)
        return 2

    uid = collect.current_uid()
    artifacts = collect.scan_tmpfs_artifacts(
        mountpoints, now=time.time(), current_uid=uid,
        min_size_kb=int(args.min_size * 1024),
    )
    open_paths = collect.collect_open_paths(under=mountpoints)
    classified = analyze.classify_tmpfs_artifacts(
        artifacts, open_paths, current_uid=uid,
        idle_hours=args.idle_hours, include_caches=args.include_caches,
        full=args.full,
    )
    summary = analyze.summarize_reclaim(
        classified, idle_hours=args.idle_hours, full=args.full)
    result = remediate.run_reclaim_tmpfs(
        summary["reclaimable"], mounts=mountpoints, current_uid=uid, apply=args.apply,
    )

    if args.json:
        print(report.render_reclaim_json(summary, result))
    else:
        print(report.render_reclaim_human(summary, result))

    if args.apply and result.get("errors"):
        return 1
    return 0


def run_swap(args: argparse.Namespace) -> int:
    """Plan or apply adding a swapfile and report the outcome."""
    if args.size_gb is None:
        print("error: --size-gb is required (e.g. --size-gb 16)", file=sys.stderr)
        return 2
    try:
        remediate.validate_swap_size(args.size_gb)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    def swap_total_kb() -> int:
        return collect.collect_meminfo().get("SwapTotal", 0)

    swappiness = None if args.swappiness is not None and args.swappiness < 0 else args.swappiness
    result = remediate.run_add_swap(
        args.size_gb,
        path=args.path,
        swappiness=swappiness,
        apply=args.apply,
        swap_total_kb=swap_total_kb,
    )

    if args.json:
        print(report.render_swap_json(result))
    else:
        print(report.render_swap_human(result))

    # Non-zero when an apply was requested but refused (not root / already set).
    if args.apply and not result["applied"]:
        return 1
    return 0


def run_stop(args: argparse.Namespace) -> int:
    """Plan or apply a graceful stop of non-essential workloads."""
    scope = "docker" if args.docker_only else "processes" if args.processes_only else "all"
    mode = ("full-complete-sweep" if args.full_complete_sweep
            else "full-safe" if args.full_safe else "default")

    processes = collect.collect_workload_processes()
    containers = collect.collect_docker_containers()
    docker_blocked = collect.docker_present() and not containers
    protected = collect.collect_self_ancestry()

    plan = analyze.plan_stop(
        processes, containers,
        current_uid=collect.current_uid(),
        protected_pids=protected,
        scope=scope,
        keep=tuple(args.keep),
        mode=mode,
    )
    # Re-read ancestry at action time so the guard reflects the current process
    # tree, not the snapshot the plan was built from.
    result = remediate.run_stop_workloads(
        plan, apply=args.apply,
        protected_pids=collect.collect_self_ancestry(),
    )

    if args.json:
        print(report.render_stop_json(plan, result))
    else:
        print(report.render_stop_human(plan, result, docker_blocked=docker_blocked))

    # Non-zero when an apply hit errors or refused docker units for lack of access.
    if args.apply and (result.get("errors") or result.get("access_hint")):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch. Returns a process exit code."""
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()

    # With no subcommand, default to a read-only diagnosis. Prepending the
    # subcommand keeps a single source of truth for its options/defaults.
    top_level_flags = ("-h", "--help", "--version")
    commands = ("diagnose", "free", "reclaim", "swap", "stop")
    if not argv or (argv[0] not in commands and argv[0] not in top_level_flags):
        argv = ["diagnose", *argv]

    args = parser.parse_args(argv)
    if args.command == "free":
        return run_free(args)
    if args.command == "reclaim":
        return run_reclaim(args)
    if args.command == "swap":
        return run_swap(args)
    if args.command == "stop":
        return run_stop(args)
    return run_diagnose(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
