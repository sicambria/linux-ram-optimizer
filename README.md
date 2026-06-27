# linux-ram-optimizer

A small, safe, dependency-free command-line tool that explains **why** your
Linux machine is using so much RAM right now — and, only when you ask, reclaims
clean caches **safely**.

It is built around one fact that trips up almost everyone:

> On Linux, high "used" memory is usually **page cache**, which is reclaimable
> and *good*. The kernel fills spare RAM with cache to speed up I/O and hands it
> straight back when programs need it. The number that actually matters is
> **MemAvailable**, not "used".

So this tool leads with `MemAvailable`, separates reclaimable cache from real
process memory, and tells you plainly whether there is anything to worry about.

## Features

- **Read-only diagnosis by default.** Nothing is changed unless you explicitly
  opt in.
- Clear memory **breakdown**: process (anonymous) memory, page cache, buffers,
  shared/tmpfs, reclaimable vs unreclaimable kernel slab, page tables, swap.
- **Top processes by PSS** (proportional set size from `/proc/*/smaps_rollup`,
  the fair way to charge shared memory), falling back to RSS where unreadable.
- **Pressure Stall Information (PSI)** — the honest signal of *real* memory
  shortage versus benign cache fill.
- Plain-language **findings** for swapping, large unreclaimable slab, large
  tmpfs, a single dominating process, and genuine low-memory pressure.
- **Safe, opt-in cache reclaim** via `/proc/sys/vm/drop_caches`: dry-run by
  default, root required to apply, and it **never kills or signals processes**.
- **Safe, opt-in tmpfs reclaim** (`reclaim`): finds idle/abandoned files in
  RAM-backed tmpfs (`/tmp`, `/dev/shm`) — the memory `drop_caches` *cannot*
  free — and deletes only what is provably safe. Dry-run by default; it never
  touches files held open by a process, owned by another user, or outside a
  tmpfs mount.
- **Swap recommendation + provisioning** (`swap`): `diagnose` flags a host with
  no swap (a real OOM hazard when memory is overcommitted), and `swap --size-gb
  N` provisions a swapfile (4–32 GiB) as an OOM safety net. Dry-run by default;
  root required to apply; refuses if swap is already configured.
- **Graceful stop of non-essential workloads** (`stop`): reclaims the RAM held
  by *running processes* — the kind `free` and `reclaim` cannot touch. It works
  from an **allowlist** of recognised developer workloads (Docker containers and
  standalone dev servers), acting at the **supervisor level** (`docker stop` /
  `SIGTERM`, never `SIGKILL`) so restart-policied containers don't respawn. The
  desktop session, core daemons, and this process's own ancestry (its shell, the
  terminal, the login session, `init`) are protected by a hard guard, never the
  allowlist's absence. Dry-run by default; apps with network/UX side effects
  (a VPN, a GUI) are surfaced for review, never auto-stopped.
- Pure Python 3 standard library — **no `pip` dependencies**.

## Requirements

- Linux (reads `/proc`).
- Python 3.9 or newer.

## Setup and run

There are no dependencies to install — the tool is pure Python standard
library. You have two options.

### Option A — run straight from the source tree (zero setup)

```sh
git clone https://github.com/sicambria/linux-ram-optimizer
cd linux-ram-optimizer
python3 -m ramopt diagnose        # read-only; this is the default command
```

`python3 -m ramopt <command>` works for every subcommand without installing
anything.

### Option B — install the `ram-optimizer` command on your PATH

```sh
./install.sh                      # auto-picks the best method; never needs root
ram-optimizer diagnose
```

`install.sh` chooses the right method for your machine — `pipx` if present,
otherwise `pip --user`, and a local `.venv` as a fallback on PEP 668
"externally-managed" Pythons (modern Debian/Ubuntu) where `pip --user` is
blocked. Useful flags:

```sh
./install.sh --pipx          # force pipx (isolated venv on PATH)
./install.sh --user          # force pip --user
./install.sh --venv [DIR]    # force a venv (default ./.venv)
./install.sh --editable      # editable/develop install (-e)
./install.sh --uninstall     # remove it again
```

Equivalently, `make install` runs the script; plain `pip install .` also works
where your Python permits it.

### First run

```sh
ram-optimizer diagnose            # explain current memory use (read-only, safe)
ram-optimizer stop                # dry-run plan to reclaim RAM from workloads
```

`diagnose` changes nothing. `free`, `reclaim`, `swap` and `stop` are all
**dry-run by default** and only act when you add `--apply`.

## Usage

```sh
# Read-only diagnosis (this is also the default with no arguments)
ram-optimizer diagnose
ram-optimizer diagnose --top 20      # show more processes
ram-optimizer diagnose --json        # machine-readable output

# Safe cache reclaim — DRY RUN by default, shows what it would do
ram-optimizer free
ram-optimizer free --level 3         # 1=page cache, 2=slab, 3=both

# Actually reclaim (requires root). Re-run under sudo:
sudo ram-optimizer free --apply --level 1

# Reclaim idle/abandoned tmpfs files (/tmp, /dev/shm) — DRY RUN by default.
# tmpfs lives in RAM, so this frees memory that `free` above cannot.
ram-optimizer reclaim
ram-optimizer reclaim --idle-hours 72    # only files untouched for 72+ hours (default 24)
ram-optimizer reclaim --include-caches   # also clear reusable caches
ram-optimizer reclaim --full             # delete ALL your tmpfs files regardless of age
ram-optimizer reclaim --full --apply     # ...and actually do it (still keeps in-use/system files)
ram-optimizer reclaim --apply            # actually delete the safe items

# Add a swapfile as an OOM safety net — DRY RUN by default.
ram-optimizer swap --size-gb 16          # show the plan (4-32 GiB)
sudo ram-optimizer swap --size-gb 16 --swappiness 10 --apply   # create + enable

# Gracefully stop non-essential workloads — DRY RUN by default.
ram-optimizer stop                       # show what it would stop, and how much RAM
ram-optimizer stop --docker-only         # only Docker containers
ram-optimizer stop --processes-only      # only standalone dev servers
ram-optimizer stop --keep '*db*'         # exclude units whose name matches a glob
ram-optimizer stop --full-safe           # also your dev runtimes; SPARES DB containers
ram-optimizer stop --full-complete-sweep # also ALL containers + systemd units + VPN/sync
sudo ram-optimizer stop --apply          # actually stop them (root needed for docker)
```

`python3 -m ramopt ...` works identically if you have not installed the script.

## What "free" does — and what it deliberately does *not* do

`ram-optimizer free` runs, at most, the equivalent of:

```sh
sync
echo <1|2|3> > /proc/sys/vm/drop_caches
```

This frees only **clean, reclaimable cache** — memory the kernel would release
on its own the moment something needs it. Consequences to understand:

- It **rarely improves anything**. It mostly makes the "used" number look
  smaller while briefly *slowing the system down* as caches re-warm.
- It does **not** free process memory, tmpfs/`/dev/shm`, or unreclaimable slab.
- `free` will **never** kill, signal, or restart a process. To reclaim RAM held
  by *running* workloads, see `stop` below — the one command that touches
  processes, and only allowlisted, non-essential ones, opt-in.

If a diagnosis shows healthy `MemAvailable`, the correct action is **none**.

## What "stop" does — and what it refuses to touch

`ram-optimizer stop` is the only command that affects processes. It reclaims the
RAM that `free` and `reclaim` cannot — memory held by *running* workloads —
while going to some length not to disturb anything load-bearing:

- **Allowlist, not denylist.** Only recognised developer workloads are eligible:
  Docker containers, and standalone dev servers (`next-server`, `vite`,
  `webpack`, `nodemon`, …). Anything not on the list is simply left alone. A
  missing allowlist entry is harmless; there is no denylist whose omission could
  let an essential be killed.
- **Stops the supervisor, not the PID.** Containers are stopped with
  `docker stop` (graceful SIGTERM, then SIGKILL only after a grace period the
  daemon owns); standalone servers get a single **SIGTERM**. It **never** sends
  SIGKILL itself, so a clean shutdown (databases included) is always possible. A
  process under a `*.service` is reported with the `systemctl stop` to use rather
  than being signalled, so a restart policy can't respawn it.
- **A hard guard, independent of the allowlist.** This process and its entire
  ancestry — the CLI, its shell, the terminal, the login session, `init` — plus
  the desktop session and core daemons are protected and can never be selected,
  even if something matched. A container's *internal* `sh`/`postgres` never
  blocks its own graceful `docker stop`.
- **Dry-run is the gate.** `stop` shows exactly what it would stop and how much
  RAM that frees; nothing happens without `--apply`. Apps with network or UX
  side effects (a VPN, a diagnostic GUI) are surfaced *for review*, never
  auto-stopped — you decide.

### Three breadth modes

The default is deliberately narrow. Two opt-in switches escalate *which*
categories are auto-stopped — **the two hard guards (your ancestry and the
essential-name list) stay absolute in every mode**, and selection stays
positive-ID throughout (a runtime match can only ever catch a dev workload,
never a desktop helper, even though desktop names in `/proc` are truncated):

| | Dev *servers* | Your dev *runtimes* (node/npm/uv/MCP) | Docker containers | systemd user units | VPN/sync apps |
| --- | :---: | :---: | :---: | :---: | :---: |
| *(default)* | stop | review | **stop** | review | review |
| `--full-safe` | stop | **stop** | *spared* | review | review |
| `--full-complete-sweep` | stop | **stop** | **stop** | **stop** | **stop** |

- `--full-safe` broadens to your own developer *runtime/tool* processes
  (`node`, `npm`, `uv`, MCP/language servers, …) but **spares stateful Docker
  containers** (your databases keep their data warm) and still only surfaces
  systemd units and side-effecting apps. "Safe" = it never stops anything
  holding persistent state or with network/UX side effects. *(Note: this means
  `--full-safe` leaves containers running, where plain `stop` would stop them.)*
- `--full-complete-sweep` is the maximal reclaim toward the essential RAM
  baseline: everything above plus **all** containers, your systemd **user**
  services (`systemctl --user stop`), and the VPN/sync review apps. Databases
  and tunnels *will* stop — review the plan first.

```sh
ram-optimizer stop                       # dry-run: the plan + RAM each unit holds
ram-optimizer stop --docker-only         # containers only
ram-optimizer stop --processes-only      # standalone dev servers only
ram-optimizer stop --keep '*db*'         # exclude units whose name matches a glob
ram-optimizer stop --full-safe           # + your dev runtimes; spares DB containers
ram-optimizer stop --full-complete-sweep # + all containers, systemd units, VPN/sync
sudo ram-optimizer stop --apply          # actually stop them (root needed for docker)
```

**Sweep + `sudo` caveat:** `--full-complete-sweep` stops your *systemd user*
services with `systemctl --user`, which under `sudo` binds to **root's** user
manager rather than yours — so those units would not stop. Run the sweep
**without** sudo so it stays your user (Docker access is group-based, not
root): `sg docker -c 'ram-optimizer stop --full-complete-sweep --apply'`. The
tool detects this case and prints the same hint.

Run under `sudo`, it honours `SUDO_UID`, so the dry-run you saw as your user and
the `sudo … --apply` it prints agree on which user-owned servers to stop. If a
dev server is run by a process manager (npm, pnpm, pm2, foreman), stop *that*
parent — SIGTERMing a worker it supervises only invites a respawn.

## How it works

| Module | Responsibility |
| --- | --- |
| `ramopt/proc.py` | Pure parsers for `/proc` text (no I/O). |
| `ramopt/collect.py` | Read live `/proc` (read-only) and call the parsers. |
| `ramopt/analyze.py` | Pure analysis: breakdown, ranking, heuristic findings. |
| `ramopt/remediate.py` | The only state-changing code: safe, gated cache reclaim, tmpfs file deletion, swap provisioning, and graceful workload stop. |
| `ramopt/report.py` | Render results as text or JSON. |
| `ramopt/cli.py` | Argument parsing and orchestration. |

Parsing and analysis are pure functions, so the whole suite runs on captured
`/proc` fixtures without root or a particular machine state.

## Development & testing

```sh
make test             # or: python3 -m unittest discover -s tests -v
make check-sensitive  # scan tracked files for personal/host/secret data
```

The tests are hermetic: no root, no network, no live `/proc` reads, and the
cache-drop side effect is mocked.

A **pre-push guardrail** (`scripts/check_sensitive.py`) refuses to publish
personal, host-unique, or secret-shaped data (usernames, home paths, personal
emails, credential tokens, public IPs). Install it as a git hook on a clone with:

```sh
ln -sf ../../scripts/pre-push.hook .git/hooks/pre-push
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Copyright (C) 2026
linux-ram-optimizer contributors.
