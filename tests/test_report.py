# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Tests for the human and JSON reporters."""

import json
import pathlib
import unittest

from ramopt import analyze, proc, remediate, report

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def analysis_from(name: str) -> dict:
    meminfo = proc.parse_meminfo((FIXTURES / name).read_text(encoding="utf-8"))
    breakdown = analyze.memory_breakdown(meminfo)
    top = analyze.top_processes([{"pid": 1, "name": "demo", "pss_kb": 1024}])
    flags = analyze.detect_flags(breakdown, None, top)
    return analyze.summarize(breakdown, top, None, flags)


class FormatKbTests(unittest.TestCase):
    def test_scales_units(self):
        self.assertEqual(report.format_kb(512), "512.0 KiB")
        self.assertEqual(report.format_kb(1024), "1.0 MiB")
        self.assertEqual(report.format_kb(1024 * 1024), "1.0 GiB")


class DiagnosisReportTests(unittest.TestCase):
    def test_json_round_trips(self):
        analysis = analysis_from("meminfo_healthy.txt")
        text = report.render_diagnosis_json(analysis)
        self.assertEqual(json.loads(text)["breakdown"]["total_kb"], 16384000)

    def test_human_reports_healthy_state(self):
        text = report.render_diagnosis_human(analysis_from("meminfo_healthy.txt"))
        self.assertIn("Available", text)
        self.assertIn("No memory concerns detected", text)

    def test_human_lists_findings_when_stressed(self):
        text = report.render_diagnosis_human(analysis_from("meminfo_stressed.txt"))
        self.assertIn("[HIGH]", text)
        self.assertIn("Low available memory", text)


class FreeReportTests(unittest.TestCase):
    def test_dry_run_text_marks_no_change(self):
        result = remediate.run_free(level=1, apply=False)
        text = report.render_free_human(result)
        self.assertIn("DRY RUN", text)
        self.assertIn("echo 1 > /proc/sys/vm/drop_caches", text)

    def test_applied_text_reports_freed(self):
        result = {
            "level": 1, "level_description": "page cache",
            "commands": remediate.build_commands(1), "applied": True,
            "reason": "applied", "before_kb": 1000, "after_kb": 3048,
            "freed_kb": 2048,
        }
        text = report.render_free_human(result)
        self.assertIn("Applied", text)
        self.assertIn("2.0 MiB", text)  # freed_kb formatted

    def test_free_json_round_trips(self):
        result = remediate.run_free(level=2, apply=False)
        self.assertEqual(json.loads(report.render_free_json(result))["level"], 2)


class ReclaimReportTests(unittest.TestCase):
    def _summary_and_result(self, apply=False):
        arts = [
            {"path": "/tmp/foo.zip", "name": "foo.zip", "mount": "/tmp",
             "size_kb": 200000, "age_days": 9, "uid": 1000, "is_symlink": False},
            {"path": "/tmp/.X11-unix", "name": ".X11-unix", "mount": "/tmp",
             "size_kb": 10, "age_days": 9, "uid": 0, "is_symlink": False},
        ]
        classified = analyze.classify_tmpfs_artifacts(arts, set(), current_uid=1000)
        summary = analyze.summarize_reclaim(classified, idle_hours=72.0)
        result = remediate.run_reclaim_tmpfs(
            summary["reclaimable"], mounts=["/tmp"], current_uid=1000,
            apply=apply, realpath=lambda p: p)
        return summary, result

    def test_human_dry_run_lists_reclaimable_and_protected(self):
        text = report.render_reclaim_human(*self._summary_and_result(apply=False))
        self.assertIn("DRY RUN", text)
        self.assertIn("foo.zip", text)
        self.assertIn("Protected", text)  # the .X11-unix socket bucket

    def test_human_applied_reports_freed(self):
        text = report.render_reclaim_human(*self._summary_and_result(apply=True))
        self.assertIn("Applied", text)

    def test_json_round_trips(self):
        summary, result = self._summary_and_result()
        payload = json.loads(report.render_reclaim_json(summary, result))
        self.assertIn("summary", payload)
        self.assertEqual(payload["result"]["reason"], "dry-run")


class SwapReportTests(unittest.TestCase):
    def test_dry_run_lists_commands_and_marks_no_change(self):
        result = remediate.run_add_swap(
            16, apply=False, swap_active=lambda p: False, swap_total_kb=lambda: 0)
        text = report.render_swap_human(result)
        self.assertIn("16 GiB", text)
        self.assertIn("mkswap", text)
        self.assertIn("DRY RUN", text)

    def test_not_root_shows_sudo_hint(self):
        result = remediate.run_add_swap(
            16, apply=True, geteuid=lambda: 1000,
            swap_active=lambda p: False, swap_total_kb=lambda: 0,
            runner=lambda cmds: None)
        text = report.render_swap_human(result)
        self.assertIn("requires root", text)
        self.assertIn("sudo", text)

    def test_json_round_trips(self):
        result = remediate.run_add_swap(
            8, apply=False, swap_active=lambda p: False, swap_total_kb=lambda: 0)
        self.assertEqual(json.loads(report.render_swap_json(result))["size_gb"], 8)


class RenderStopTests(unittest.TestCase):
    PLAN = {
        "scope": "all", "eligible_count": 2, "eligible_kb": 750000,
        "guarded_count": 5,
        "units": [
            {"kind": "docker", "label": "webapp", "category": "container",
             "rss_kb": 700000, "command": "docker stop webapp"},
            {"kind": "process", "label": "vite", "category": "dev-server",
             "rss_kb": 50000, "command": "kill -TERM 400"},
        ],
        "review": [{"label": "python3", "pid": 99, "rss_kb": 300000,
                    "category": "review", "reason": "vpn"}],
        "skipped": [{"label": "gnome-shell", "reason": "essential"}],
    }

    def test_dry_run_lists_units_and_commands(self):
        result = {"reason": "dry-run", "planned": [1, 2], "planned_kb": 750000}
        text = report.render_stop_human(self.PLAN, result)
        self.assertIn("docker stop webapp", text)
        self.assertIn("kill -TERM 400", text)
        self.assertIn("DRY RUN", text)
        self.assertIn("Review", text)        # surfaced apps shown
        self.assertIn("SIGKILL", text)       # the safety promise is stated

    def test_applied_reports_freed_and_errors(self):
        result = {"reason": "applied",
                  "stopped": [{"label": "webapp"}],
                  "freed_kb_est": 700000,
                  "errors": [{"label": "vite", "error": "boom"}]}
        text = report.render_stop_human(self.PLAN, result)
        self.assertIn("stopped 1 unit", text)
        self.assertIn("boom", text)

    def test_json_round_trips(self):
        result = {"reason": "dry-run", "planned": [], "planned_kb": 0}
        out = json.loads(report.render_stop_json(self.PLAN, result))
        self.assertEqual(out["plan"]["eligible_count"], 2)
        self.assertEqual(out["result"]["reason"], "dry-run")

    def test_full_safe_banner_shown(self):
        result = {"reason": "dry-run", "planned": [1], "planned_kb": 50000}
        text = report.render_stop_human({**self.PLAN, "mode": "full-safe"}, result)
        self.assertIn("FULL-SAFE MODE", text)
        self.assertIn("SPARED", text)               # containers spared

    def test_complete_sweep_banner_shown(self):
        result = {"reason": "dry-run", "planned": [1], "planned_kb": 50000}
        text = report.render_stop_human(
            {**self.PLAN, "mode": "full-complete-sweep"}, result)
        self.assertIn("COMPLETE-SWEEP MODE", text)
        self.assertIn("ALL Docker containers", text)

    def test_default_mode_has_no_banner(self):
        result = {"reason": "dry-run", "planned": [], "planned_kb": 0}
        text = report.render_stop_human(self.PLAN, result)   # no "mode" key
        self.assertNotIn("FULL-SAFE MODE", text)
        self.assertNotIn("COMPLETE-SWEEP MODE", text)


if __name__ == "__main__":
    unittest.main()
