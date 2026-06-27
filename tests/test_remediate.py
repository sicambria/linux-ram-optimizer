# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Tests for the remediation layer.

Every branch is driven through dependency injection, so these tests never run
``sync`` or write to ``/proc`` — the cache-drop side effect is fully mocked.
"""

import unittest

from ramopt import remediate


class BuildCommandsTests(unittest.TestCase):
    def test_commands_sync_then_drop(self):
        self.assertEqual(
            remediate.build_commands(2),
            ["sync", "echo 2 > /proc/sys/vm/drop_caches"],
        )


class RunFreeTests(unittest.TestCase):
    def test_dry_run_does_not_invoke_writer(self):
        called = []
        result = remediate.run_free(
            level=1, apply=False,
            writer=lambda level: called.append(level),
            geteuid=lambda: 0,
        )
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "dry-run")
        self.assertEqual(called, [])  # writer never called on a dry run

    def test_non_root_apply_refuses_without_writing(self):
        called = []
        result = remediate.run_free(
            level=1, apply=True,
            writer=lambda level: called.append(level),
            geteuid=lambda: 1000,
        )
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not-root")
        self.assertIn("sudo", result["sudo_hint"])
        self.assertEqual(called, [])  # refused: nothing written

    def test_root_apply_invokes_writer_and_reports_freed(self):
        called = []
        samples = iter([1000, 1500])  # before, after (kB)
        result = remediate.run_free(
            level=3, apply=True,
            writer=lambda level: called.append(level),
            geteuid=lambda: 0,
            sample_available=lambda: next(samples),
        )
        self.assertTrue(result["applied"])
        self.assertEqual(called, [3])
        self.assertEqual(result["before_kb"], 1000)
        self.assertEqual(result["after_kb"], 1500)
        self.assertEqual(result["freed_kb"], 500)

    def test_invalid_level_rejected(self):
        with self.assertRaises(ValueError):
            remediate.run_free(level=4, apply=False)

    def test_is_root_uses_injected_euid(self):
        self.assertTrue(remediate.is_root(lambda: 0))
        self.assertFalse(remediate.is_root(lambda: 1000))


def _cand(path, *, size_kb=1000, uid=1000, reclaimable=True):
    return {"path": path, "size_kb": size_kb, "uid": uid,
            "reclaimable": reclaimable, "klass": "abandoned", "reason": "test"}


class RunReclaimTmpfsTests(unittest.TestCase):
    MOUNTS = ["/tmp", "/dev/shm"]

    def reclaim(self, cands, **kw):
        kw.setdefault("realpath", lambda p: p)  # no symlink resolution in tests
        return remediate.run_reclaim_tmpfs(
            cands, mounts=self.MOUNTS, current_uid=1000, **kw)

    def test_dry_run_plans_but_removes_nothing(self):
        removed = []
        result = self.reclaim(
            [_cand("/tmp/foo.zip")], apply=False,
            remover=lambda p: removed.append(p))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "dry-run")
        self.assertEqual(removed, [])
        self.assertEqual(result["planned_kb"], 1000)

    def test_apply_removes_and_sums_freed(self):
        removed = []
        result = self.reclaim(
            [_cand("/tmp/a.zip", size_kb=500), _cand("/tmp/b.zip", size_kb=700)],
            apply=True, remover=lambda p: removed.append(p))
        self.assertTrue(result["applied"])
        self.assertEqual(removed, ["/tmp/a.zip", "/tmp/b.zip"])
        self.assertEqual(result["freed_kb"], 1200)

    def test_path_outside_tmpfs_is_skipped(self):
        removed = []
        result = self.reclaim(
            [_cand("/home/user/important")], apply=True,
            remover=lambda p: removed.append(p))
        self.assertEqual(removed, [])
        self.assertEqual(result["skipped"][0]["reason"], "resolves outside a tmpfs mount")

    def test_symlink_escape_is_skipped(self):
        # realpath resolves the candidate outside tmpfs -> must be rejected.
        removed = []
        result = remediate.run_reclaim_tmpfs(
            [_cand("/tmp/evil")], mounts=self.MOUNTS, current_uid=1000, apply=True,
            remover=lambda p: removed.append(p),
            realpath=lambda p: "/etc/passwd")
        self.assertEqual(removed, [])
        self.assertEqual(len(result["skipped"]), 1)

    def test_mountpoint_itself_is_never_deleted(self):
        result = self.reclaim([_cand("/tmp")], apply=True, remover=lambda p: None)
        self.assertEqual(result["skipped"][0]["reason"], "resolves outside a tmpfs mount")

    def test_other_user_and_non_reclaimable_skipped(self):
        result = self.reclaim(
            [_cand("/tmp/x", uid=0), _cand("/tmp/y", reclaimable=False)],
            apply=True, remover=lambda p: None)
        self.assertEqual(len(result["deleted"]), 0)
        reasons = {s["reason"] for s in result["skipped"]}
        self.assertIn("owned by another user", reasons)
        self.assertIn("not flagged reclaimable", reasons)

    def test_remove_error_recorded_not_raised(self):
        def boom(_):
            raise OSError("permission denied")
        result = self.reclaim([_cand("/tmp/z.zip")], apply=True, remover=boom)
        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["errors"][0]["path"], "/tmp/z.zip")


class AddSwapTests(unittest.TestCase):
    def add(self, gb, **kw):
        kw.setdefault("swap_active", lambda path: False)
        kw.setdefault("swap_total_kb", lambda: 0)
        return remediate.run_add_swap(gb, **kw)

    def test_size_must_be_in_band(self):
        with self.assertRaises(ValueError):
            remediate.validate_swap_size(2)
        with self.assertRaises(ValueError):
            remediate.validate_swap_size(64)
        self.assertEqual(remediate.validate_swap_size(16), 16)

    def test_dry_run_builds_commands_but_runs_nothing(self):
        ran = []
        result = self.add(16, apply=False, runner=lambda cmds: ran.append(cmds))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "dry-run")
        self.assertEqual(ran, [])
        # The sequence formats then activates the swapfile.
        joined = " ; ".join(result["commands"])
        self.assertIn("mkswap /swap.img", joined)
        self.assertIn("swapon /swap.img", joined)
        self.assertIn("fallocate -l 16G /swap.img", joined)

    def test_existing_active_file_is_swapped_off_first(self):
        result = self.add(8, apply=False, swap_active=lambda path: True)
        self.assertEqual(result["commands"][0], "swapoff /swap.img")

    def test_fstab_guard_matches_by_field_not_exact_line(self):
        # Must detect an existing entry in ANY spacing (e.g. tab-separated from
        # the installer), so it never appends a duplicate that breaks the
        # systemd swap-unit generator. So: field-matching awk, not `grep -qxF`.
        fstab_cmd = next(c for c in self.add(16, apply=False)["commands"]
                         if "/etc/fstab" in c)
        self.assertNotIn("grep -qxF", fstab_cmd)
        self.assertIn('$1=="/swap.img"', fstab_cmd)
        self.assertIn('$3=="swap"', fstab_cmd)

    def test_swappiness_appended_when_requested(self):
        result = self.add(8, apply=False, swappiness=10)
        self.assertIn("sysctl -w vm.swappiness=10", result["commands"])
        result_none = self.add(8, apply=False, swappiness=None)
        self.assertFalse(any("swappiness" in c for c in result_none["commands"]))

    def test_swappiness_persisted_via_sysctl_dropin(self):
        # `sysctl -w` only sets the live value, which reverts to the kernel
        # default on reboot. A drop-in under /etc/sysctl.d makes it stick, so
        # both commands must be present (live + persistent).
        result = self.add(8, apply=False, swappiness=10)
        persist_cmd = next(
            (c for c in result["commands"] if "/etc/sysctl.d/" in c), None)
        self.assertIsNotNone(persist_cmd)
        self.assertIn("vm.swappiness", persist_cmd)
        self.assertIn("10", persist_cmd)
        self.assertIn("99-ramopt-swappiness.conf", persist_cmd)
        # No drop-in is written when swappiness is left unmanaged.
        result_none = self.add(8, apply=False, swappiness=None)
        self.assertFalse(
            any("/etc/sysctl.d/" in c for c in result_none["commands"]))

    def test_refuses_when_swap_already_configured(self):
        ran = []
        result = self.add(16, apply=True, geteuid=lambda: 0,
                          swap_total_kb=lambda: 4096000,
                          runner=lambda cmds: ran.append(cmds))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "already-configured")
        self.assertEqual(ran, [])  # never touched an existing swap area

    def test_non_root_apply_refuses_with_hint(self):
        ran = []
        result = self.add(16, apply=True, geteuid=lambda: 1000,
                          runner=lambda cmds: ran.append(cmds))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not-root")
        self.assertIn("sudo", result["sudo_hint"])
        self.assertEqual(ran, [])

    def test_root_apply_runs_commands_and_reports_added(self):
        ran = []
        # swap_total_kb is sampled three times: guard check, before, after.
        samples = iter([0, 0, 16777216])
        result = self.add(16, apply=True, geteuid=lambda: 0,
                          swap_total_kb=lambda: next(samples),
                          runner=lambda cmds: ran.append(cmds))
        self.assertTrue(result["applied"])
        self.assertEqual(len(ran), 1)
        self.assertEqual(result["added_kb"], 16777216)


def _unit(kind, key, label, *, rss_kb=1000, members=None, command="cmd",
          category="container", signal=None):
    return {"kind": kind, "key": key, "label": label, "category": category,
            "image": "", "rss_kb": rss_kb,
            "members": members if members is not None else [key],
            "command": command, "signal": signal}


def _plan(units):
    return {"units": units}


class RunStopWorkloadsTests(unittest.TestCase):
    def test_dry_run_signals_and_runs_nothing(self):
        signalled, stopped = [], []
        plan = _plan([
            _unit("docker", "abc", "webapp", command="docker stop webapp"),
            _unit("process", 400, "vite", category="dev-server",
                  signal=15, command="kill -TERM 400"),
        ])
        result = remediate.run_stop_workloads(
            plan, apply=False,
            signaller=lambda pid, sig: signalled.append((pid, sig)),
            docker_stop=lambda name: stopped.append(name))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "dry-run")
        self.assertEqual(signalled, [])
        self.assertEqual(stopped, [])
        self.assertEqual(len(result["planned"]), 2)
        self.assertEqual(result["planned_kb"], 2000)

    def test_apply_stops_process_with_sigterm_only(self):
        signalled = []
        plan = _plan([_unit("process", 400, "vite", signal=15)])
        result = remediate.run_stop_workloads(
            plan, apply=True,
            signaller=lambda pid, sig: signalled.append((pid, sig)),
            pid_alive=lambda pid: False)  # exited cleanly
        self.assertTrue(result["applied"])
        self.assertEqual(signalled, [(400, 15)])     # SIGTERM (15), never 9
        self.assertEqual(result["freed_kb_est"], 1000)
        self.assertTrue(result["stopped"][0]["exited"])

    def test_process_that_survives_is_not_counted_freed(self):
        plan = _plan([_unit("process", 401, "vite", signal=15)])
        result = remediate.run_stop_workloads(
            plan, apply=True, signaller=lambda pid, sig: None,
            pid_alive=lambda pid: True,       # never exits within the grace poll
            sleep=lambda _: None)             # don't actually wait in tests
        self.assertFalse(result["stopped"][0]["exited"])
        self.assertEqual(result["freed_kb_est"], 0)

    def test_settle_poll_sees_delayed_exit(self):
        # The process is alive on the first probe, gone on the second — the
        # bounded poll must catch that and count it freed.
        probes = iter([True, False])
        plan = _plan([_unit("process", 403, "vite", rss_kb=5000, signal=15)])
        result = remediate.run_stop_workloads(
            plan, apply=True, signaller=lambda pid, sig: None,
            pid_alive=lambda pid: next(probes), sleep=lambda _: None)
        self.assertTrue(result["stopped"][0]["exited"])
        self.assertEqual(result["freed_kb_est"], 5000)

    def test_already_gone_process_is_recorded_not_an_error(self):
        def gone(pid, sig):
            raise ProcessLookupError()
        plan = _plan([_unit("process", 402, "vite", signal=15)])
        result = remediate.run_stop_workloads(
            plan, apply=True, signaller=gone, pid_alive=lambda pid: False)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["stopped"][0]["note"], "already gone")

    def test_docker_refused_when_daemon_unreachable(self):
        stopped = []
        plan = _plan([_unit("docker", "abc", "webapp")])
        result = remediate.run_stop_workloads(
            plan, apply=True, docker_available=lambda: False,
            docker_stop=lambda name: stopped.append(name))
        self.assertEqual(stopped, [])                       # refused, no access
        self.assertIn("unreachable", result["skipped"][0]["reason"])
        # The hint offers the docker-group path, not just sudo.
        self.assertIn("docker", result["access_hint"])
        self.assertIn("sg docker", result["access_hint"])

    def test_docker_runs_when_daemon_reachable_without_root(self):
        # Docker access is group-based: reachable daemon => stop runs, no root.
        stopped = []
        plan = _plan([_unit("docker", "abc", "webapp", rss_kb=700000)])
        result = remediate.run_stop_workloads(
            plan, apply=True, docker_available=lambda: True,
            docker_stop=lambda name: stopped.append(name))
        self.assertEqual(stopped, ["webapp"])
        self.assertEqual(result["freed_kb_est"], 700000)
        self.assertNotIn("access_hint", result)

    def test_docker_stop_error_recorded_not_raised(self):
        def boom(name):
            raise RuntimeError("daemon down")
        plan = _plan([_unit("docker", "abc", "webapp")])
        result = remediate.run_stop_workloads(
            plan, apply=True, docker_available=lambda: True, docker_stop=boom)
        self.assertEqual(result["stopped"], [])
        self.assertEqual(result["errors"][0]["error"], "daemon down")

    def test_systemd_unit_stopped_via_systemctl(self):
        called = []
        plan = _plan([_unit("systemd", "app.service", "app.service",
                            rss_kb=30000, members=[950, 951],
                            command="systemctl --user stop app.service")])
        result = remediate.run_stop_workloads(
            plan, apply=True,
            systemctl_stop=lambda unit_id: called.append(unit_id))
        self.assertEqual(called, ["app.service"])
        self.assertEqual(result["freed_kb_est"], 30000)
        self.assertEqual(result["stopped"][0]["label"], "app.service")

    def test_systemd_under_sudo_warns_user_manager_mismatch(self):
        # systemctl --user under sudo would target root's manager — warn so the
        # user re-runs non-sudo. Hint appears even on a dry run.
        plan = _plan([_unit("systemd", "app.service", "app.service",
                            command="systemctl --user stop app.service")])
        result = remediate.run_stop_workloads(
            plan, apply=False, under_sudo=lambda: True)
        self.assertIn("without sudo", result["systemd_hint"].lower())

    def test_systemd_without_sudo_has_no_hint(self):
        plan = _plan([_unit("systemd", "app.service", "app.service")])
        result = remediate.run_stop_workloads(
            plan, apply=True, under_sudo=lambda: False,
            systemctl_stop=lambda u: None)
        self.assertNotIn("systemd_hint", result)

    def test_systemd_stop_error_recorded_not_raised(self):
        def boom(unit_id):
            raise RuntimeError("unit failed")
        plan = _plan([_unit("systemd", "app.service", "app.service",
                            command="systemctl --user stop app.service")])
        result = remediate.run_stop_workloads(
            plan, apply=True, systemctl_stop=boom)
        self.assertEqual(result["stopped"], [])
        self.assertEqual(result["errors"][0]["error"], "unit failed")

    def test_unit_guarded_since_planning_is_skipped(self):
        # Action-time re-check: a member pid now in the protected set is refused
        # even though the planner had marked the unit eligible.
        signalled = []
        plan = _plan([_unit("process", 500, "vite", members=[500], signal=15)])
        result = remediate.run_stop_workloads(
            plan, apply=True, protected_pids={500},
            signaller=lambda pid, sig: signalled.append((pid, sig)))
        self.assertEqual(signalled, [])
        self.assertEqual(result["skipped"][0]["reason"], "became guarded since planning")


if __name__ == "__main__":
    unittest.main()
