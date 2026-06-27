# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Tests for the analysis layer: breakdown arithmetic, ranking and flags."""

import pathlib
import unittest

from ramopt import analyze, proc

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def meminfo(name: str) -> dict:
    return proc.parse_meminfo((FIXTURES / name).read_text(encoding="utf-8"))


class BreakdownTests(unittest.TestCase):
    def setUp(self):
        self.breakdown = analyze.memory_breakdown(meminfo("meminfo_healthy.txt"))

    def test_truly_used_is_total_minus_available(self):
        self.assertEqual(self.breakdown["truly_used_kb"], 16384000 - 10240000)
        self.assertEqual(self.breakdown["available_pct"], 62.5)

    def test_page_cache_excludes_shmem(self):
        # Cached (5120000) - Shmem (512000)
        self.assertEqual(self.breakdown["components_kb"]["page_cache"], 4608000)

    def test_reclaimable_cache_sums_cache_buffers_sreclaimable(self):
        self.assertEqual(self.breakdown["reclaimable_cache_kb"], 4608000 + 256000 + 800000)

    def test_swap_used_zero_when_full_free(self):
        self.assertEqual(self.breakdown["swap"]["used_kb"], 0)

    def test_missing_fields_default_to_zero(self):
        breakdown = analyze.memory_breakdown({"MemTotal": 1000, "MemAvailable": 400})
        self.assertEqual(breakdown["components_kb"]["page_cache"], 0)
        self.assertEqual(breakdown["truly_used_kb"], 600)


class TopProcessesTests(unittest.TestCase):
    def test_ranks_by_pss_when_present(self):
        procs = [
            {"pid": 1, "name": "a", "pss_kb": 100, "rss_kb": 999},
            {"pid": 2, "name": "b", "pss_kb": 300, "rss_kb": 10},
            {"pid": 3, "name": "c", "pss_kb": 200, "rss_kb": 50},
        ]
        ranked = analyze.top_processes(procs, limit=2)
        self.assertEqual([p["pid"] for p in ranked], [2, 3])
        self.assertEqual(ranked[0]["ranked_by"], "pss")
        self.assertEqual(ranked[0]["sort_key_kb"], 300)

    def test_falls_back_to_rss_when_pss_missing(self):
        procs = [{"pid": 9, "name": "x", "pss_kb": None, "rss_kb": 42}]
        ranked = analyze.top_processes(procs)
        self.assertEqual(ranked[0]["ranked_by"], "rss")
        self.assertEqual(ranked[0]["sort_key_kb"], 42)

    def test_limit_caps_results(self):
        procs = [{"pid": i, "name": str(i), "pss_kb": i} for i in range(20)]
        self.assertEqual(len(analyze.top_processes(procs, limit=5)), 5)


class FlagTests(unittest.TestCase):
    def test_healthy_system_has_no_flags(self):
        breakdown = analyze.memory_breakdown(meminfo("meminfo_healthy.txt"))
        flags = analyze.detect_flags(breakdown, None, [])
        self.assertEqual(flags, [])

    def test_stressed_system_raises_expected_flags(self):
        breakdown = analyze.memory_breakdown(meminfo("meminfo_stressed.txt"))
        flags = analyze.detect_flags(breakdown, None, [])
        ids = {f["id"] for f in flags}
        self.assertIn("low_available", ids)
        self.assertIn("swapping", ids)
        self.assertIn("high_unreclaimable_slab", ids)
        self.assertIn("high_shmem", ids)

    def test_dominant_process_flag(self):
        breakdown = analyze.memory_breakdown(meminfo("meminfo_healthy.txt"))
        # One process at 40% of 16384000 kB total.
        top = analyze.top_processes(
            [{"pid": 1, "name": "hog", "pss_kb": int(0.40 * 16384000)}]
        )
        flags = analyze.detect_flags(breakdown, None, top)
        self.assertIn("dominant_process", {f["id"] for f in flags})

    def test_psi_stall_flag_triggers_above_threshold(self):
        breakdown = analyze.memory_breakdown(meminfo("meminfo_healthy.txt"))
        pressure = {"some": {"avg10": 10.0, "avg60": 9.0, "avg300": 8.0}}
        flags = analyze.detect_flags(breakdown, pressure, [])
        self.assertIn("psi_stall", {f["id"] for f in flags})

    def test_low_available_is_high_severity_and_unhealthy(self):
        breakdown = analyze.memory_breakdown(meminfo("meminfo_stressed.txt"))
        flags = analyze.detect_flags(breakdown, None, [])
        summary = analyze.summarize(breakdown, [], None, flags)
        self.assertFalse(summary["healthy"])

    def test_no_swap_flag_fires_only_when_swaptotal_zero(self):
        # Healthy fixture has SwapTotal > 0 -> no flag.
        healthy = analyze.memory_breakdown(meminfo("meminfo_healthy.txt"))
        self.assertNotIn("no_swap",
                         {f["id"] for f in analyze.detect_flags(healthy, None, [])})
        # Force SwapTotal to 0 -> the no_swap finding appears.
        info = proc.parse_meminfo((FIXTURES / "meminfo_healthy.txt").read_text("utf-8"))
        info["SwapTotal"] = 0
        info["SwapFree"] = 0
        breakdown = analyze.memory_breakdown(info)
        flags = analyze.detect_flags(breakdown, None, [])
        no_swap = [f for f in flags if f["id"] == "no_swap"]
        self.assertEqual(len(no_swap), 1)
        self.assertIn("swap", no_swap[0]["detail"].lower())


def _art(name, *, size_kb=100000, age_days=10.0, uid=1000, is_symlink=False, mount="/tmp"):
    return {
        "path": f"{mount}/{name}", "name": name, "mount": mount,
        "size_kb": size_kb, "age_days": age_days, "uid": uid,
        "is_symlink": is_symlink,
    }


class ClassifyTmpfsTests(unittest.TestCase):
    UID = 1000

    def classify(self, arts, open_paths=frozenset(), **kw):
        return analyze.classify_tmpfs_artifacts(
            arts, set(open_paths), current_uid=self.UID, **kw)

    def test_abandoned_download_is_reclaimable(self):
        out = self.classify([_art("playwright-download-AbCd")])[0]
        self.assertEqual(out["klass"], "abandoned")
        self.assertTrue(out["reclaimable"])

    def test_zip_archive_is_abandoned(self):
        self.assertEqual(self.classify([_art("miniforge.sh")])[0]["klass"], "abandoned")
        self.assertEqual(self.classify([_art("foo.zip")])[0]["klass"], "abandoned")

    def test_open_file_is_never_reclaimable(self):
        # Even an abandoned-looking name is kept if a process holds it open.
        art = _art("playwright-download-X")
        out = self.classify([art], open_paths={art["path"] + "/Chromium"})[0]
        self.assertEqual(out["klass"], "in_use")
        self.assertFalse(out["reclaimable"])

    def test_other_users_file_is_protected(self):
        out = self.classify([_art("foo.zip", uid=0)])[0]
        self.assertEqual(out["klass"], "protected")
        self.assertFalse(out["reclaimable"])

    def test_system_socket_dir_is_protected(self):
        self.assertEqual(self.classify([_art(".X11-unix")])[0]["klass"], "protected")
        self.assertEqual(
            self.classify([_art("systemd-private-abc")])[0]["klass"], "protected")

    def test_symlink_is_protected(self):
        out = self.classify([_art("link", is_symlink=True)])[0]
        self.assertEqual(out["klass"], "protected")

    def test_reuse_cache_kept_unless_opted_in(self):
        kept = self.classify([_art("node-compile-cache")])[0]
        self.assertEqual(kept["klass"], "reuse_cache")
        self.assertFalse(kept["reclaimable"])
        opted = self.classify([_art("node-compile-cache")], include_caches=True)[0]
        self.assertTrue(opted["reclaimable"])

    def test_idle_owned_file_reclaimable_recent_is_not(self):
        # idle_hours=72 (=3 days): a 9-day file is idle, a 1-day (24h) file isn't.
        idle = self.classify([_art("randomdir", age_days=9)], idle_hours=72.0)[0]
        self.assertEqual(idle["klass"], "idle")
        self.assertTrue(idle["reclaimable"])
        recent = self.classify([_art("randomdir", age_days=1)], idle_hours=72.0)[0]
        self.assertEqual(recent["klass"], "recent")
        self.assertFalse(recent["reclaimable"])

    def test_default_idle_threshold_is_24_hours(self):
        # A file untouched ~2 days is idle under the new 24h default; 12h is not.
        idle = self.classify([_art("d", age_days=2.0)])[0]
        self.assertEqual(idle["klass"], "idle")
        recent = self.classify([_art("d", age_days=0.5)])[0]   # 12h
        self.assertEqual(recent["klass"], "recent")
        self.assertIn("h", recent["reason"])                   # reason is in hours

    def test_full_mode_reclaims_recent_owned_files(self):
        # A 1-hour-old dir owned by you is "recent" normally, reclaimable in full.
        # (name avoids the cache/abandoned globs so it lands in "recent".)
        recent = self.classify([_art("projectbuild", age_days=0.04)])[0]
        self.assertFalse(recent["reclaimable"])
        full = self.classify([_art("projectbuild", age_days=0.04)], full=True)[0]
        self.assertEqual(full["klass"], "recent")
        self.assertTrue(full["reclaimable"])
        self.assertIn("full mode", full["reason"])

    def test_full_mode_implies_include_caches(self):
        out = self.classify([_art("node-compile-cache")], full=True)[0]
        self.assertTrue(out["reclaimable"])

    def test_full_mode_never_bypasses_hard_guards(self):
        # other user, system socket, and in-use are kept even with full=True.
        other = self.classify([_art("x", uid=0)], full=True)[0]
        sock = self.classify([_art(".X11-unix")], full=True)[0]
        art = _art("openthing")
        inuse = self.classify([art], open_paths={art["path"] + "/fd"}, full=True)[0]
        self.assertEqual(other["klass"], "protected")
        self.assertEqual(sock["klass"], "protected")
        self.assertEqual(inuse["klass"], "in_use")
        self.assertFalse(any(x["reclaimable"] for x in (other, sock, inuse)))

    def test_summary_totals_only_reclaimable(self):
        arts = self.classify([
            _art("foo.zip", size_kb=500),            # abandoned -> reclaimable
            _art(".X11-unix", size_kb=10),           # protected
            _art("fresh", size_kb=999, age_days=0),  # recent
        ])
        summary = analyze.summarize_reclaim(arts, idle_hours=72.0)
        self.assertEqual(summary["reclaimable_kb"], 500)
        self.assertEqual(summary["total_kb"], 1509)
        self.assertEqual(len(summary["reclaimable"]), 1)


def _proc(pid, name, *, uid=1000, rss_kb=1000, cmdline="", supervisor=None,
          supervisor_id=None, ppid=1):
    return {"pid": pid, "ppid": ppid, "name": name, "uid": uid,
            "rss_kb": rss_kb, "pss_kb": None, "cmdline": cmdline or name,
            "supervisor": supervisor, "supervisor_id": supervisor_id}


class PlanStopTests(unittest.TestCase):
    def plan(self, procs, containers=(), *, protected=frozenset({1}), **kw):
        return analyze.plan_stop(
            list(procs), list(containers),
            current_uid=1000, protected_pids=set(protected), **kw)

    def _labels(self, plan):
        return {u["label"] for u in plan["units"]}

    def test_docker_container_grouped_and_eligible(self):
        procs = [
            _proc(100, "beam.smp", uid=0, rss_kb=700000,
                  supervisor="docker", supervisor_id="abc123abc123"),
            _proc(101, "postgres", uid=0, rss_kb=50000,
                  supervisor="docker", supervisor_id="abc123abc123"),
        ]
        containers = [{"id": "abc123abc123", "name": "webapp",
                       "image": "img", "state": "running", "status": "Up"}]
        plan = self.plan(procs, containers)
        self.assertEqual(len(plan["units"]), 1)
        unit = plan["units"][0]
        self.assertEqual(unit["kind"], "docker")
        self.assertEqual(unit["label"], "webapp")
        self.assertEqual(unit["command"], "docker stop webapp")
        self.assertEqual(unit["rss_kb"], 750000)        # summed members
        self.assertEqual(sorted(unit["members"]), [100, 101])

    def test_container_internal_shell_does_not_block_stop(self):
        # A container running an internal `sh` (an essential-NAME match) must
        # still be eligible: the essential guard protects only the host session.
        procs = [_proc(200, "sh", uid=0, supervisor="docker",
                       supervisor_id="dddddddddddd")]
        plan = self.plan(procs)
        self.assertEqual(len(plan["units"]), 1)
        self.assertEqual(plan["units"][0]["kind"], "docker")

    def test_container_synthesised_without_docker_ps(self):
        # No `docker ps` data (socket unreachable) — still grouped by cgroup id.
        procs = [_proc(300, "node", uid=0, rss_kb=160000,
                       supervisor="docker", supervisor_id="ee11ee22ee33")]
        plan = self.plan(procs, containers=[])
        self.assertEqual(plan["units"][0]["label"], "ee11ee22ee33")
        self.assertEqual(plan["units"][0]["command"], "docker stop ee11ee22ee33")

    def test_standalone_dev_server_gets_sigterm(self):
        procs = [_proc(400, "next-server", cmdline="next-server (v16) /app")]
        plan = self.plan(procs)
        unit = plan["units"][0]
        self.assertEqual(unit["kind"], "process")
        self.assertEqual(unit["signal"], analyze.SIGTERM)
        self.assertEqual(unit["command"], "kill -TERM 400")

    def test_essential_host_process_is_never_selected(self):
        # gnome-shell matches the essential list; it must not be a unit even
        # though it is a standalone user process.
        procs = [_proc(500, "gnome-shell", cmdline="gnome-shell --mode=ubuntu"),
                 _proc(501, "vite", cmdline="vite dev")]
        plan = self.plan(procs)
        self.assertEqual(self._labels(plan), {"vite"})

    def test_ancestry_pid_is_guarded_even_if_it_matches(self):
        # A dev-server-looking process that is actually our ancestor: protected.
        procs = [_proc(600, "node", cmdline="vite dev")]
        plan = self.plan(procs, protected={1, 600})
        self.assertEqual(plan["units"], [])
        self.assertTrue(any("guarded" in s["reason"] for s in plan["skipped"]))

    def test_non_owned_standalone_process_skipped(self):
        procs = [_proc(700, "vite", uid=0, cmdline="vite dev")]
        plan = self.plan(procs)
        self.assertEqual(plan["units"], [])
        self.assertTrue(any("another user" in s["reason"] for s in plan["skipped"]))

    def test_docker_only_scope_excludes_processes(self):
        procs = [
            _proc(800, "vite", cmdline="vite dev"),
            _proc(801, "node", uid=0, supervisor="docker", supervisor_id="c1c1c1c1c1c1"),
        ]
        plan = self.plan(procs, scope="docker")
        self.assertEqual([u["kind"] for u in plan["units"]], ["docker"])

    def test_processes_only_scope_excludes_docker(self):
        procs = [
            _proc(810, "vite", cmdline="vite dev"),
            _proc(811, "node", uid=0, supervisor="docker", supervisor_id="c2c2c2c2c2c2"),
        ]
        plan = self.plan(procs, scope="processes")
        self.assertEqual([u["kind"] for u in plan["units"]], ["process"])

    def test_keep_glob_excludes_named_unit(self):
        procs = [_proc(820, "node", uid=0, supervisor="docker",
                       supervisor_id="dada", rss_kb=1)]
        containers = [{"id": "dada", "name": "keepme", "image": "i",
                       "state": "running", "status": "Up"}]
        plan = self.plan(procs, containers, keep=("keep*",))
        self.assertEqual(plan["units"], [])
        self.assertTrue(any("--keep" in s["reason"] for s in plan["skipped"]))

    def test_systemd_service_surfaced_not_acted(self):
        procs = [_proc(900, "vector", cmdline="vector --config /etc/vector.yaml",
                       supervisor="systemd", supervisor_id="vector.service")]
        plan = self.plan(procs)
        self.assertEqual(plan["units"], [])
        self.assertTrue(any("systemctl stop vector.service" in s["reason"]
                            for s in plan["skipped"]))

    def test_review_app_surfaced_but_not_eligible(self):
        procs = [_proc(910, "python3", cmdline="python3 protonvpn-app", rss_kb=300000)]
        plan = self.plan(procs)
        self.assertEqual(plan["units"], [])
        self.assertEqual(len(plan["review"]), 1)
        self.assertEqual(plan["review"][0]["pid"], 910)

    def test_units_sorted_by_rss_desc(self):
        procs = [
            _proc(920, "vite", cmdline="vite dev", rss_kb=100),
            _proc(921, "webpack", cmdline="webpack serve", rss_kb=500),
        ]
        plan = self.plan(procs)
        self.assertEqual([u["rss_kb"] for u in plan["units"]], [500, 100])
        self.assertEqual(plan["eligible_kb"], 600)

    # --- mode escalation: default / full-safe / full-complete-sweep ----------

    def _container(self, cid="cafe", name="db"):
        procs = [_proc(100, "postgres", uid=0, rss_kb=50000,
                       supervisor="docker", supervisor_id=cid)]
        containers = [{"id": cid, "name": name, "image": "postgres:17",
                       "state": "running", "status": "Up"}]
        return procs, containers

    def test_plan_records_mode(self):
        self.assertEqual(self.plan([])["mode"], "default")
        self.assertEqual(self.plan([], mode="full-safe")["mode"], "full-safe")

    def test_default_leaves_non_allowlisted_runtime_alone(self):
        # An MCP server (npm exec) is not a recognised dev *server* — the
        # conservative default must not select it.
        procs = [_proc(930, "node", cmdline="npm exec @acme/example-mcp")]
        self.assertEqual(self.plan(procs)["units"], [])

    def test_full_safe_stops_dev_runtime_process(self):
        procs = [_proc(931, "node", cmdline="npm exec @acme/example-mcp",
                       rss_kb=80000)]
        plan = self.plan(procs, mode="full-safe")
        self.assertEqual(self._labels(plan), {"node"})
        self.assertEqual(plan["units"][0]["category"], "dev-runtime")

    def test_full_safe_spares_containers(self):
        procs, containers = self._container()
        plan = self.plan(procs, containers, mode="full-safe")
        self.assertEqual(plan["units"], [])
        self.assertTrue(any("spared by --full-safe" in s["reason"]
                            for s in plan["skipped"]))

    def test_full_safe_does_not_promote_systemd_or_review(self):
        procs = [
            _proc(940, "node", cmdline="node /app/server.js",
                  supervisor="systemd", supervisor_id="myapp.service"),
            _proc(941, "openvpn", cmdline="openvpn --config /etc/vpn.conf"),
        ]
        plan = self.plan(procs, mode="full-safe")
        self.assertEqual(plan["units"], [])           # neither auto-stopped
        self.assertEqual(len(plan["review"]), 1)      # vpn still surfaced
        self.assertTrue(any(s["category"] == "systemd" for s in plan["skipped"]))

    def test_complete_sweep_stops_containers(self):
        procs, containers = self._container()
        plan = self.plan(procs, containers, mode="full-complete-sweep")
        self.assertEqual([u["kind"] for u in plan["units"]], ["docker"])

    def test_complete_sweep_promotes_systemd_unit(self):
        procs = [
            _proc(950, "node", cmdline="node /app/a.js", rss_kb=10000,
                  supervisor="systemd", supervisor_id="app.service"),
            _proc(951, "node", cmdline="node /app/b.js", rss_kb=20000,
                  supervisor="systemd", supervisor_id="app.service"),
        ]
        plan = self.plan(procs, mode="full-complete-sweep")
        self.assertEqual(len(plan["units"]), 1)
        unit = plan["units"][0]
        self.assertEqual(unit["kind"], "systemd")
        self.assertEqual(unit["command"], "systemctl --user stop app.service")
        self.assertEqual(unit["rss_kb"], 30000)               # summed members
        self.assertEqual(sorted(unit["members"]), [950, 951])

    def test_complete_sweep_promotes_review_app_to_sigterm(self):
        procs = [_proc(960, "openvpn", cmdline="openvpn --config x", rss_kb=5000)]
        plan = self.plan(procs, mode="full-complete-sweep")
        self.assertEqual(plan["review"], [])
        self.assertEqual(plan["units"][0]["kind"], "process")
        self.assertEqual(plan["units"][0]["category"], "review-app")
        self.assertEqual(plan["units"][0]["signal"], analyze.SIGTERM)

    def test_full_modes_never_catch_essential_or_desktop(self):
        # Positive-ID is what keeps the desktop safe: gnome-shell is name-guarded,
        # and a desktop helper that matches no dev runtime is simply never picked
        # — even in the most aggressive sweep, even though it is a user process.
        procs = [
            _proc(970, "gnome-shell", cmdline="gnome-shell --mode=ubuntu"),
            _proc(971, "mutter-x11-fram", cmdline="/usr/libexec/mutter-x11-frames"),
        ]
        plan = self.plan(procs, mode="full-complete-sweep")
        self.assertEqual(plan["units"], [])

    def test_full_safe_still_guards_ancestry(self):
        procs = [_proc(980, "node", cmdline="npm exec something-mcp")]
        plan = self.plan(procs, protected={1, 980}, mode="full-safe")
        self.assertEqual(plan["units"], [])


if __name__ == "__main__":
    unittest.main()
