# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Tests for the pure ``/proc`` parsers."""

import pathlib
import unittest

from ramopt import proc

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ParseMeminfoTests(unittest.TestCase):
    def test_parses_known_fields(self):
        result = proc.parse_meminfo(load("meminfo_healthy.txt"))
        self.assertEqual(result["MemTotal"], 16384000)
        self.assertEqual(result["MemAvailable"], 10240000)
        self.assertEqual(result["SUnreclaim"], 400000)

    def test_handles_non_kb_and_underscored_fields(self):
        result = proc.parse_meminfo(load("meminfo_healthy.txt"))
        # HugePages_Total has no "kB" suffix and an underscore in the key.
        self.assertEqual(result["HugePages_Total"], 0)

    def test_skips_garbage_lines(self):
        result = proc.parse_meminfo("MemTotal:  100 kB\nnonsense line\n: 5 kB\n")
        self.assertEqual(result, {"MemTotal": 100})


class ParseStatusTests(unittest.TestCase):
    def test_extracts_memory_fields(self):
        result = proc.parse_status(load("status_sample.txt"))
        self.assertEqual(result["name"], "sample-proc")
        self.assertEqual(result["pid"], 4242)
        self.assertEqual(result["uid"], 1000)  # real uid, first of the four
        self.assertEqual(result["rss_kb"], 123456)
        self.assertEqual(result["swap_kb"], 2048)

    def test_defaults_when_fields_absent(self):
        result = proc.parse_status("Name:\tx\nPid:\t1\n")
        self.assertEqual(result["rss_kb"], 0)
        self.assertEqual(result["swap_kb"], 0)


class ParseStatusPPidTests(unittest.TestCase):
    def test_reads_ppid(self):
        result = proc.parse_status("Name:\tx\nPid:\t42\nPPid:\t7\n")
        self.assertEqual(result["ppid"], 7)

    def test_ppid_defaults_to_none(self):
        self.assertIsNone(proc.parse_status("Name:\tx\nPid:\t1\n")["ppid"])


class ParseCgroupTests(unittest.TestCase):
    def test_detects_docker_scope_form(self):
        text = "0::/system.slice/docker-" + "a" * 64 + ".scope\n"
        result = proc.parse_cgroup(text)
        self.assertEqual(result["supervisor"], "docker")
        self.assertEqual(result["id"], "a" * 12)  # 12-char short form

    def test_detects_docker_path_form(self):
        text = "0::/docker/" + "b" * 64 + "\n"
        self.assertEqual(proc.parse_cgroup(text)["supervisor"], "docker")

    def test_scope_leaf_is_unsupervised(self):
        # An interactively-launched process lives in a .scope nested under the
        # user manager .service — the LEAF is the scope, so it is standalone.
        text = ("0::/user.slice/user-1000.slice/user@1000.service/"
                "app.slice/app-ptyxis-spawn-abc.scope\n")
        result = proc.parse_cgroup(text)
        self.assertIsNone(result["supervisor"])
        self.assertIsNone(result["id"])

    def test_service_leaf_is_systemd(self):
        text = "0::/system.slice/nginx.service\n"
        result = proc.parse_cgroup(text)
        self.assertEqual(result["supervisor"], "systemd")
        self.assertEqual(result["id"], "nginx.service")

    def test_no_unit_is_unsupervised(self):
        self.assertEqual(proc.parse_cgroup("0::/\n"),
                         {"supervisor": None, "id": None})


class ParseDockerPsTests(unittest.TestCase):
    def test_parses_tab_separated_rows(self):
        text = ("abc123def4567890\tweb-db\tpostgres:15\trunning\tUp 2 hours\n"
                "ff00ff00ff00\tcache\timg\trunning\tUp 1 day\n")
        rows = proc.parse_docker_ps(text)
        self.assertEqual(rows[0]["id"], "abc123def456")  # truncated to 12
        self.assertEqual(rows[0]["name"], "web-db")
        self.assertEqual(rows[0]["image"], "postgres:15")
        self.assertEqual(rows[1]["name"], "cache")

    def test_skips_blank_and_short_lines(self):
        self.assertEqual(proc.parse_docker_ps("\nonly\ttwo\n"), [])


class ParseSmapsRollupTests(unittest.TestCase):
    def test_reads_pss_and_rss(self):
        result = proc.parse_smaps_rollup(load("smaps_rollup_sample.txt"))
        self.assertEqual(result["Pss"], 65432)
        self.assertEqual(result["Rss"], 123456)
        self.assertEqual(result["Swap"], 2048)

    def test_ignores_address_header(self):
        result = proc.parse_smaps_rollup(load("smaps_rollup_sample.txt"))
        self.assertNotIn("rollup", result)


class ParsePressureTests(unittest.TestCase):
    def test_parses_some_and_full(self):
        result = proc.parse_pressure(load("pressure_sample.txt"))
        self.assertEqual(result["some"]["avg10"], 1.5)
        self.assertEqual(result["some"]["avg300"], 0.83)
        self.assertEqual(result["full"]["total"], 176366157.0)

    def test_empty_text_yields_empty_dict(self):
        self.assertEqual(proc.parse_pressure(""), {})


class ParseMountsTests(unittest.TestCase):
    def test_parses_fields_and_filters_nothing(self):
        text = (
            "tmpfs /tmp tmpfs rw,nosuid,size=14002304k 0 0\n"
            "/dev/sda2 / ext4 rw,relatime 0 0\n"
        )
        mounts = proc.parse_mounts(text)
        self.assertEqual(mounts[0], {
            "device": "tmpfs", "mountpoint": "/tmp",
            "fstype": "tmpfs", "options": "rw,nosuid,size=14002304k",
        })
        self.assertEqual(mounts[1]["fstype"], "ext4")

    def test_unescapes_octal_in_mountpoint(self):
        # The kernel encodes a space in a path as "\040".
        text = "tmpfs /run/my\\040dir tmpfs rw 0 0\n"
        self.assertEqual(proc.parse_mounts(text)[0]["mountpoint"], "/run/my dir")

    def test_skips_short_lines(self):
        self.assertEqual(proc.parse_mounts("garbage line\n\n"), [])


if __name__ == "__main__":
    unittest.main()
