# AGENTS.md — guidance for AI agents working on linux-ram-optimizer

A safe Linux RAM diagnostics + reclaim CLI. Pure Python 3 standard library, **no
third-party dependencies**. This file captures the conventions and the
environment gotchas that are easy to get wrong.

## What the tool does

`ram-optimizer <command>` (or `python3 -m ramopt <command>`):

- `diagnose` (default) — read-only memory explanation; leads with `MemAvailable`.
- `free` — drop clean caches via `/proc/sys/vm/drop_caches`. Root to apply.
- `reclaim` — delete idle/abandoned tmpfs files (`/tmp`, `/dev/shm`) — the RAM
  `free` can't reclaim. No root needed for your own files.
- `swap` — provision a swapfile (OOM safety net). Root to apply.
- `stop` — gracefully stop allowlisted non-essential workloads (Docker
  containers, standalone dev servers). The only process-affecting command.
  Three breadth modes via `analyze.plan_stop(mode=…)`: `default`,
  `--full-safe` (also your dev *runtimes* — node/npm/uv/MCP — but spares
  stateful containers, systemd units and VPN/sync apps), and
  `--full-complete-sweep` (everything above + all containers + `systemctl
  --user stop` for your systemd units + VPN/sync). The two hard guards
  (ancestry + essential-NAME) stay absolute in every mode, and selection stays
  **positive-ID** (never a denylist) precisely so a `/proc` name truncated to
  15 chars — e.g. `mutter-x11-fram` — can't slip through into a sweep.

Every state-changing command is **dry-run by default**; nothing happens without
`--apply`.

## Architecture (keep this layering)

| Module | Role | Rule |
| --- | --- | --- |
| `ramopt/proc.py` | Pure parsers for `/proc` text | No I/O. Takes a string, returns data. |
| `ramopt/collect.py` | Read live `/proc` + run probes | The only diagnostic I/O. Read-only. |
| `ramopt/analyze.py` | Pure analysis + planning | No I/O. All *decisions* live here (e.g. `plan_stop`). |
| `ramopt/remediate.py` | The only state-changing code | Dry-run default; dependency-injected; structured result dicts. |
| `ramopt/report.py` | Render text / JSON | Pure formatting. |
| `ramopt/cli.py` | Arg parsing + orchestration | Wires the above; one `run_*` per subcommand. |

**Conventions:**
- Put *decisions* in pure functions in `analyze.py`/`proc.py` so they're testable
  on fixtures without root or a particular machine state.
- In `remediate.py`, dependency-inject every side effect (writer, remover,
  runner, signaller, `docker_stop`, `docker_available`, `pid_alive`, `sleep`) so
  tests never touch the real machine. Return a structured dict
  (`{applied, planned, …, reason}`), never raise on an expected refusal.
- GPL-3.0 header on every source file. `from __future__ import annotations`
  (the code targets Python 3.9+; `X | Y` hints are stringized).
- Match the surrounding comment density and naming. The codebase explains *why*,
  not *what*.

## Testing

```sh
make test                                   # or:
python3 -m unittest discover -s tests       # 107 tests, hermetic (no root/network/live /proc)
```

Tests must stay hermetic: inject side effects, use `tests/fixtures/` for `/proc`
text, inject `sleep`/`pid_alive` so nothing actually waits or signals.

## Install

`./install.sh` (auto-picks pipx / pip --user / venv; handles PEP 668). Where
Python is **externally-managed (PEP 668)** it installs to `./.venv` — a
non-editable copy, so re-run `./install.sh` after code changes, or just use
`python3 -m ramopt …` from the source tree to test live code.

## The `stop` command's safety model (do not weaken)

- **Allowlist, not denylist.** Only recognised dev workloads are eligible. A
  missing allowlist entry is harmless; there is no denylist whose omission could
  kill an essential.
- **Act on the supervisor, not the PID.** `docker stop` for containers,
  `SIGTERM` for standalone servers — **never SIGKILL**. A `*.service` process is
  reported with its `systemctl stop` rather than signalled.
- **Two independent guards.** Ancestry (this process + parents + init, from
  `collect_self_ancestry`) applies to all units; the essential-name list applies
  only to host processes (never container members). Re-checked at action time.

## Environment gotchas (learned the hard way)

These bit during development; verify against them, don't re-derive:

- **Docker access is group-based, not root.** The socket is `root:docker`
  (`srw-rw----`), so `docker` group members use it without sudo. Gate docker
  actions on **daemon reachability** (`docker info` returns 0), never on
  `euid == 0`. Even when a user is in the `docker` group, a long-lived login
  session can have a **stale group set** (`id` omits `docker`) — run docker
  commands via **`sg docker -c '…'`** to activate the group without re-login.
  Example: `sg docker -c 'python3 -m ramopt stop --apply'`.
- **cgroup v2 puts everything in a `*.scope`.** Only a `*.service` *leaf* is a
  managed (respawning) supervisor; a `*.scope` leaf (app/session/ptyxis-spawn)
  is interactively-launched and SIGTERM-safe. Classify by the rightmost cgroup
  unit, not the deepest `.service` (which is the `user@UID.service` ancestor).
- **`os.getuid()` is 0 under sudo.** Honour `SUDO_UID` (see
  `collect.current_uid`) so a dry-run (as the user) and the `sudo … --apply` it
  prints agree on which uid-1000 workloads to act on.
- **Non-root can read `/proc/<pid>/status` but not `/proc/<pid>/cmdline`**
  (empty). Don't treat an empty cmdline as a guarded kernel thread for container
  members — match the essential guard on the readable `status` name instead.
- **A manual `docker stop` never respawns**, regardless of restart policy (only
  a daemon restart resurrects `restart: always`). Containers with
  `restart: unless-stopped` or no policy stay down after a manual stop until the
  stack is brought back up.
- **Target environment:** machines where RAM is the scarce resource — typically
  **no swap**, with `/tmp` and `/dev/shm` on tmpfs (RAM-backed). tmpfs files are
  pinned RAM that only deletion frees (not `drop_caches`).

## Git

Don't commit to `main` directly — branch first. End commit messages with the
`Co-Authored-By:` trailer when an agent authored them.

## Pre-push guardrail (this repo is public — keep it clean)

`scripts/check_sensitive.py` scans the **tracked** tree for personal,
host-unique, or secret-shaped data (current username/home path, personal
emails, credential tokens, public IPs) and refuses anything it finds. Run it
any time with `make check-sensitive`; it is also wired as the git pre-push hook.

- **Install the hook on a fresh clone** (git does not version `.git/hooks`):
  `ln -sf ../../scripts/pre-push.hook .git/hooks/pre-push`.
- **Username/home are detected at runtime**, never hard-coded, so the script
  itself carries no personal data and works on any checkout.
- **Private codenames / internal stack names** go in `scripts/sensitive-extra.txt`
  (one regex per line) — `.gitignore`d, so the block-list never ships. Add a
  term there rather than relying on memory.
- When you add fixtures or examples, use neutral names (`web-db`, `webapp`,
  `@acme/example-mcp`), not real project/container names.
