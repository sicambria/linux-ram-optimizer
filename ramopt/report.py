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
"""Render analysis and remediation results as human text or JSON.

Pure formatting: these functions take the dicts produced elsewhere and return
strings, so their output is stable and unit-testable.
"""

from __future__ import annotations

import json


def format_kb(kb: int) -> str:
    """Human-friendly size from a kB count (e.g. 1048576 -> '1.0 GiB')."""
    value = float(kb)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable, loop returns first


def render_diagnosis_json(analysis: dict) -> str:
    """Serialize the full analysis object as indented JSON."""
    return json.dumps(analysis, indent=2, sort_keys=True)


def render_diagnosis_human(analysis: dict) -> str:
    """Render the analysis as a readable, sectioned report."""
    breakdown = analysis["breakdown"]
    lines: list[str] = []

    lines.append("Linux memory diagnosis")
    lines.append("=" * 22)
    lines.append("")

    total = breakdown["total_kb"]
    available = breakdown["available_kb"]
    used = breakdown["truly_used_kb"]
    lines.append(f"Total RAM:        {format_kb(total)}")
    lines.append(
        f"Available:        {format_kb(available)} ({breakdown['available_pct']}%)"
        "  <- the number that matters"
    )
    lines.append(
        f"Truly used:       {format_kb(used)} ({breakdown['truly_used_pct']}%)"
        "  = Total - Available"
    )
    lines.append(
        f"Reclaimable cache:{format_kb(breakdown['reclaimable_cache_kb']):>12}"
        "  (counted as 'used' by `free`/`top`, freed automatically on demand)"
    )
    lines.append("")
    lines.append(
        "Note: Linux deliberately fills spare RAM with cache to speed up I/O. "
        "High 'used' is normal and healthy as long as Available stays comfortable."
    )
    lines.append("")

    lines.append("Where the memory is")
    lines.append("-" * 19)
    for label, key in (
        ("Process (anon)", "process_anon"),
        ("Shared/tmpfs", "shmem_tmpfs"),
        ("Page cache", "page_cache"),
        ("Buffers", "buffers"),
        ("Slab (reclaimable)", "slab_reclaimable"),
        ("Slab (unreclaimable)", "slab_unreclaimable"),
        ("Kernel stacks", "kernel_stack"),
        ("Page tables", "page_tables"),
    ):
        lines.append(f"  {label:<22} {format_kb(breakdown['components_kb'][key]):>12}")

    swap = breakdown["swap"]
    if swap["total_kb"] > 0:
        lines.append(
            f"  {'Swap used':<22} {format_kb(swap['used_kb']):>12} "
            f"({swap['used_pct']}% of swap)"
        )
    else:
        lines.append(f"  {'Swap':<22} {'(none configured)':>12}")
    lines.append("")

    top = analysis["top_processes"]
    if top:
        lines.append("Top processes by memory")
        lines.append("-" * 23)
        basis = top[0]["ranked_by"].upper()
        lines.append(f"  {'PID':>7}  {basis:>10}  NAME")
        for proc in top:
            lines.append(
                f"  {str(proc.get('pid', '?')):>7}  "
                f"{format_kb(proc['sort_key_kb']):>10}  {proc.get('name', '?')}"
            )
        lines.append("")

    pressure = analysis.get("pressure") or {}
    some = pressure.get("some")
    if some:
        lines.append("Memory pressure (PSI)")
        lines.append("-" * 21)
        lines.append(
            f"  some: avg10={some.get('avg10', 0)}  avg60={some.get('avg60', 0)}  "
            f"avg300={some.get('avg300', 0)}  (% of time tasks stalled on memory)"
        )
        lines.append("")

    flags = analysis.get("flags") or []
    lines.append("Findings")
    lines.append("-" * 8)
    if not flags:
        lines.append("  No memory concerns detected. Available memory is healthy and")
        lines.append("  high 'used' is just cache. No action needed.")
    else:
        for flag in flags:
            lines.append(f"  [{flag['severity'].upper()}] {flag['title']}")
            for wrapped in _wrap(flag["detail"], width=72, indent="        "):
                lines.append(wrapped)
    lines.append("")

    return "\n".join(lines)


def render_free_human(result: dict) -> str:
    """Render a remediation (cache reclaim) result for the terminal."""
    lines: list[str] = []
    level = result["level"]
    lines.append("Safe cache reclaim")
    lines.append("=" * 18)
    lines.append(f"Level {level}: frees {result['level_description']}.")
    lines.append("")
    lines.append("This frees only caches the kernel would release under pressure "
                 "anyway, so it")
    lines.append("rarely helps and can briefly slow the system while caches re-warm. "
                 "It will")
    lines.append("NOT free process memory, tmpfs, or unreclaimable slab.")
    lines.append("")
    lines.append("Commands:")
    for command in result["commands"]:
        lines.append(f"  {command}")
    lines.append("")

    reason = result["reason"]
    if reason == "dry-run":
        lines.append("DRY RUN: nothing was changed. Re-run with --apply (as root) to "
                     "execute.")
    elif reason == "not-root":
        lines.append("Refused: dropping caches requires root. Run, for example:")
        lines.append(f"  {result.get('sudo_hint', '')}")
    elif reason == "applied":
        if "freed_kb" in result:
            lines.append(
                f"Applied. MemAvailable {format_kb(result['before_kb'])} -> "
                f"{format_kb(result['after_kb'])} "
                f"(reclaimed ~{format_kb(result['freed_kb'])})."
            )
        else:
            lines.append("Applied.")
    return "\n".join(lines)


def render_free_json(result: dict) -> str:
    """Serialize a remediation result as indented JSON."""
    return json.dumps(result, indent=2, sort_keys=True)


# Human labels and display order for the artifact classes.
_CLASS_ORDER = ("abandoned", "idle", "reuse_cache", "recent", "in_use", "protected")
_CLASS_LABEL = {
    "abandoned": "Abandoned scratch (safe to delete)",
    "idle": "Idle, owned by you (safe to delete)",
    "reuse_cache": "Reusable cache (deletable; re-warms)",
    "recent": "Recent — review before deleting",
    "in_use": "In use by a process (kept)",
    "protected": "Protected: socket/lock/other user (kept)",
}


def render_reclaim_human(summary: dict, result: dict) -> str:
    """Render the tmpfs reclaim diagnosis + plan/outcome for the terminal.

    ``summary`` is :func:`ramopt.analyze.summarize_reclaim` output; ``result``
    is :func:`ramopt.remediate.run_reclaim_tmpfs` output.
    """
    lines: list[str] = []
    lines.append("Idle tmpfs reclaim (RAM-backed scratch)")
    lines.append("=" * 39)
    lines.append("")
    lines.append("tmpfs (e.g. /tmp, /dev/shm) lives in RAM. Dropping caches CANNOT free")
    lines.append("it — only deleting files does. This lists each top-level entry and what")
    lines.append("is safe to remove. Files open by a process or owned by others are kept.")
    lines.append("")
    if summary.get("full"):
        lines.append("!! FULL MODE: deleting ALL your tmpfs files regardless of age,")
        lines.append("   caches included. Still kept: files open by a process, system")
        lines.append("   sockets/locks, and other users' files. Review the list before --apply.")
        lines.append("")

    by_class = summary.get("by_class", {})
    artifacts = summary.get("artifacts", [])
    lines.append(
        f"Scanned {len(artifacts)} top-level entries, "
        f"{format_kb(summary.get('total_kb', 0))} total. "
        f"Reclaimable now: {format_kb(summary.get('reclaimable_kb', 0))}."
    )
    lines.append("")

    for klass in _CLASS_ORDER:
        items = [a for a in artifacts if a["klass"] == klass]
        if not items:
            continue
        bucket = by_class.get(klass, {})
        lines.append(
            f"{_CLASS_LABEL[klass]} — "
            f"{bucket.get('count', 0)} item(s), {format_kb(bucket.get('size_kb', 0))}"
        )
        for art in sorted(items, key=lambda a: a.get("size_kb", 0), reverse=True)[:12]:
            mark = "x" if art["reclaimable"] else " "
            lines.append(
                f"  [{mark}] {format_kb(art.get('size_kb', 0)):>10}  "
                f"{art.get('name', '?')}"
            )
            lines.append(f"          -> {art.get('reason', '')}")
        if len(items) > 12:
            lines.append(f"      ... and {len(items) - 12} more")
        lines.append("")

    reason = result.get("reason")
    skipped = result.get("skipped") or []
    if reason == "dry-run":
        lines.append(
            f"DRY RUN: would delete {len(result.get('planned', []))} item(s), "
            f"freeing ~{format_kb(result.get('planned_kb', 0))}."
        )
        lines.append("Re-run with --apply to delete. Add --include-caches to also clear")
        lines.append("reusable caches, or --idle-hours N to change the idle threshold.")
    elif reason == "applied":
        lines.append(
            f"Applied: deleted {len(result.get('deleted', []))} item(s), "
            f"freed ~{format_kb(result.get('freed_kb', 0))} of RAM."
        )
        errors = result.get("errors") or []
        if errors:
            lines.append(f"  {len(errors)} item(s) could not be removed:")
            for err in errors[:5]:
                lines.append(f"    {err['path']}: {err['error']}")
    if skipped:
        lines.append(f"Skipped {len(skipped)} candidate(s) failing a safety re-check.")
    return "\n".join(lines)


def render_reclaim_json(summary: dict, result: dict) -> str:
    """Serialize the reclaim summary and action result together as JSON."""
    return json.dumps({"summary": summary, "result": result},
                      indent=2, sort_keys=True)


def render_swap_human(result: dict) -> str:
    """Render a swap-provisioning (add swapfile) result for the terminal."""
    lines: list[str] = []
    lines.append("Add swap (OOM safety net)")
    lines.append("=" * 25)
    lines.append(
        f"Plan: a {result['size_gb']} GiB swapfile at {result['path']}"
        + (f", vm.swappiness={result['swappiness']}."
           if result.get("swappiness") is not None else "."))
    lines.append("")
    lines.append("Swap gives the kernel somewhere to page idle anonymous memory "
                 "under pressure")
    lines.append("instead of invoking the OOM killer. A small swapfile is an "
                 "insurance policy,")
    lines.append("not an invitation to swap heavily (keep swappiness low).")
    lines.append("")
    lines.append("Commands:")
    for command in result["commands"]:
        lines.append(f"  {command}")
    lines.append("")

    reason = result["reason"]
    if reason == "dry-run":
        lines.append("DRY RUN: nothing was changed. Re-run with --apply (as root) to "
                     "execute.")
    elif reason == "already-configured":
        lines.append(
            f"Refused: swap is already configured "
            f"(SwapTotal {format_kb(result.get('swap_total_kb', 0))}). "
            "Remove or resize it manually if you intend to change it.")
    elif reason == "not-root":
        lines.append("Refused: creating swap requires root. Run, for example:")
        lines.append(f"  {result.get('sudo_hint', '')}")
    elif reason == "applied":
        if "added_kb" in result:
            lines.append(
                f"Applied. SwapTotal {format_kb(result['before_kb'])} -> "
                f"{format_kb(result['after_kb'])} "
                f"(added ~{format_kb(result['added_kb'])}).")
        else:
            lines.append("Applied.")
    return "\n".join(lines)


def render_swap_json(result: dict) -> str:
    """Serialize a swap-provisioning result as indented JSON."""
    return json.dumps(result, indent=2, sort_keys=True)


def render_stop_human(plan: dict, result: dict, *, docker_blocked: bool = False) -> str:
    """Render the stop plan + outcome for the terminal.

    ``plan`` is :func:`ramopt.analyze.plan_stop` output; ``result`` is
    :func:`ramopt.remediate.run_stop_workloads` output.  ``docker_blocked`` is
    True when the docker CLI exists but its socket was unreachable (so the plan
    may under-count containers — re-run under sudo to see them).
    """
    lines: list[str] = []
    lines.append("Stop non-essential workloads")
    lines.append("=" * 28)
    lines.append("")
    lines.append("Stops only allowlisted developer workloads — Docker containers")
    lines.append("(via `docker stop`) and standalone dev servers (via SIGTERM). The")
    lines.append("desktop session, core daemons, this shell and its ancestors are")
    lines.append("never touched. Database containers stop cleanly; nothing is SIGKILLed.")
    lines.append("")

    mode = plan.get("mode", "default")
    if mode == "full-safe":
        lines.append("!! FULL-SAFE MODE: also stopping your non-allowlisted developer")
        lines.append("   runtime processes (node/npm/uv/MCP servers, …). Stateful Docker")
        lines.append("   containers, systemd units and VPN/sync apps are SPARED (see")
        lines.append("   skipped/review below). The hard guards — desktop, daemons, this")
        lines.append("   shell, every essential name — still apply. Review before --apply.")
        lines.append("")
    elif mode == "full-complete-sweep":
        lines.append("!! FULL COMPLETE-SWEEP MODE: stopping ALL Docker containers, your")
        lines.append("   developer runtime processes, your systemd user services, and")
        lines.append("   VPN/sync apps — everything above the essential RAM baseline.")
        lines.append("   Databases and tunnels WILL stop. The hard guards (desktop,")
        lines.append("   daemons, this shell) still apply. Review the list before --apply.")
        lines.append("")

    if docker_blocked:
        lines.append("Note: docker is installed but its socket was unreachable without")
        lines.append("root, so containers below are identified by id only. Re-run under")
        lines.append("sudo to resolve names and to apply.")
        lines.append("")

    units = plan.get("units", [])
    if units:
        lines.append(f"Eligible to stop ({plan.get('eligible_count', 0)} unit(s), "
                     f"~{format_kb(plan.get('eligible_kb', 0))} RSS):")
        for unit in units:
            tag = "container" if unit["kind"] == "docker" else unit.get("category", "process")
            lines.append(f"  [{tag:^10}] {format_kb(unit['rss_kb']):>10}  {unit['label']}")
            lines.append(f"               -> {unit['command']}")
        lines.append("")
    else:
        lines.append("No eligible non-essential workloads found.")
        lines.append("")

    review = plan.get("review", [])
    if review:
        lines.append("Review — user apps with side effects (NOT auto-selected):")
        for item in review:
            lines.append(f"  {format_kb(item['rss_kb']):>10}  {item['label']}  "
                         f"(pid {item.get('pid', '?')})")
        lines.append("")

    skipped = plan.get("skipped", [])
    if skipped:
        lines.append(f"Skipped {len(skipped)} candidate(s):")
        for item in skipped[:8]:
            lines.append(f"  {item.get('label', '?')}: {item.get('reason', '')}")
        if len(skipped) > 8:
            lines.append(f"  ... and {len(skipped) - 8} more")
        lines.append("")

    reason = result.get("reason")
    if reason == "dry-run":
        lines.append(
            f"DRY RUN: would stop {len(result.get('planned', []))} unit(s), "
            f"freeing up to ~{format_kb(result.get('planned_kb', 0))}.")
        lines.append("Re-run with --apply to stop them. Scope with --docker-only /")
        lines.append("--processes-only, or exclude with --keep NAME. Reclaim more with")
        lines.append("--full-safe (your dev runtimes too) or --full-complete-sweep")
        lines.append("(also all containers, systemd user units and VPN/sync apps).")
        lines.append("Note: if a dev server is run by a process manager (npm, pnpm,")
        lines.append("pm2, foreman), stop that parent instead — it may respawn workers.")
        if result.get("access_hint"):
            lines.append(result["access_hint"])
        if result.get("systemd_hint"):
            lines.append(result["systemd_hint"])
    elif reason == "applied":
        lines.append(
            f"Applied: stopped {len(result.get('stopped', []))} unit(s), "
            f"freed ~{format_kb(result.get('freed_kb_est', 0))} of RAM.")
        errors = result.get("errors") or []
        if errors:
            lines.append(f"  {len(errors)} unit(s) failed to stop:")
            for err in errors[:5]:
                lines.append(f"    {err.get('label', '?')}: {err.get('error', '')}")
        stop_skipped = result.get("skipped") or []
        if stop_skipped:
            lines.append(f"  {len(stop_skipped)} unit(s) skipped at action time:")
            for item in stop_skipped[:5]:
                lines.append(f"    {item.get('label', '?')}: {item.get('reason', '')}")
        if result.get("access_hint"):
            lines.append(f"  {result['access_hint']}")
        if result.get("systemd_hint"):
            lines.append(f"  {result['systemd_hint']}")
    return "\n".join(lines)


def render_stop_json(plan: dict, result: dict) -> str:
    """Serialize the stop plan and action result together as JSON."""
    return json.dumps({"plan": plan, "result": result}, indent=2, sort_keys=True)


def _wrap(text: str, width: int, indent: str) -> list[str]:
    """Greedy word-wrap with a fixed indent; avoids importing textwrap config."""
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if current != indent and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = indent + word
        else:
            current = current + (" " if current != indent else "") + word
    if current != indent:
        lines.append(current)
    return lines
