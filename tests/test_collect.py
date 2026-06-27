# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Tests for the collection layer's process/workload helpers.

The ancestry walk is safety-critical (its result is the set the stop planner
treats as untouchable), so it is exercised against a synthetic ``/proc`` tree
rather than the live one, keeping it deterministic.
"""

import os
import tempfile
import unittest
from pathlib import Path

from ramopt import collect


def _write_proc_tree(root: Path, tree: dict[int, int]) -> None:
    """Create ``<root>/<pid>/status`` files from a ``{pid: ppid}`` mapping."""
    for pid, ppid in tree.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "status").write_text(
            f"Name:\tp{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nVmRSS:\t10 kB\n",
            encoding="utf-8")


class SelfAncestryTests(unittest.TestCase):
    def test_walks_ppid_chain_up_to_pid1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_proc_tree(root, {1: 0, 10: 1, 42: 10, 99: 42})
            chain = collect.collect_self_ancestry(proc_root=str(root), pid=99)
            self.assertEqual(chain, {1, 10, 42, 99})

    def test_always_includes_pid1_even_if_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_proc_tree(root, {7: 1})  # no status for pid 1
            chain = collect.collect_self_ancestry(proc_root=str(root), pid=7)
            self.assertIn(1, chain)
            self.assertIn(7, chain)

    def test_stops_on_missing_parent_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_proc_tree(root, {5: 3})  # parent 3 has no status file
            chain = collect.collect_self_ancestry(proc_root=str(root), pid=5)
            # 3 is a known ancestor (5's PPid) so it is guarded even though its
            # status is unreadable; the walk then stops without crashing.
            self.assertEqual(chain, {1, 5, 3})


class ScanTmpfsAgeTests(unittest.TestCase):
    NOW = 1_000_000.0
    DAY = 86400.0

    def test_age_uses_mtime_not_atime(self):
        # A file modified 10 days ago but *read* just now must read as ~10 days
        # old — atime (the recent read) is ignored.
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "stale.bin"
            f.write_bytes(b"x" * 4096)
            old_mtime = self.NOW - 10 * self.DAY
            os.utime(f, (self.NOW, old_mtime))           # (atime=now, mtime=old)
            recs = collect.scan_tmpfs_artifacts(
                [tmp], now=self.NOW, current_uid=os.getuid(), min_size_kb=0)
            rec = next(r for r in recs if r["name"] == "stale.bin")
            self.assertAlmostEqual(rec["age_days"], 10.0, places=3)

    def test_dir_age_reflects_newest_file_inside(self):
        # An old directory with a freshly-written file inside reads as recent.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "proj"
            d.mkdir()
            (d / "fresh.bin").write_bytes(b"y" * 4096)
            os.utime(d / "fresh.bin", (self.NOW, self.NOW))   # modified "now"
            os.utime(d, (self.NOW, self.NOW - 30 * self.DAY))  # dir itself old
            recs = collect.scan_tmpfs_artifacts(
                [tmp], now=self.NOW, current_uid=os.getuid(), min_size_kb=0)
            rec = next(r for r in recs if r["name"] == "proj")
            self.assertLess(rec["age_days"], 1.0)        # deep mtime wins => recent


class DockerContainersTests(unittest.TestCase):
    def test_returns_empty_when_runner_yields_none(self):
        self.assertEqual(collect.collect_docker_containers(runner=lambda: None), [])

    def test_parses_runner_output(self):
        text = "abc123abc123\twebapp\timg\trunning\tUp 2 hours\n"
        rows = collect.collect_docker_containers(runner=lambda: text)
        self.assertEqual(rows[0]["name"], "webapp")


if __name__ == "__main__":
    unittest.main()
