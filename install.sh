#!/usr/bin/env bash
#
# install.sh — set up the `ram-optimizer` command from this source tree.
#
# linux-ram-optimizer is pure Python 3 standard library with no runtime
# dependencies, so "installing" just puts the `ram-optimizer` entry point on
# your PATH. This script picks the most appropriate method for your machine and
# never needs root:
#
#   1. pipx            — preferred: an isolated venv, command exposed on PATH.
#   2. pip --user      — a user-site install (no root, no system packages).
#   3. a local venv    — fallback for PEP 668 "externally-managed" Pythons
#                        (modern Debian/Ubuntu) where 2 is blocked; created at
#                        ./.venv, with a note on how to activate it.
#
# Usage:
#   ./install.sh                 # auto-pick the best method
#   ./install.sh --pipx          # force pipx
#   ./install.sh --user          # force pip --user
#   ./install.sh --venv [DIR]    # force a venv (default ./.venv)
#   ./install.sh --editable      # install in editable/develop mode (-e)
#   ./install.sh --uninstall     # remove a pipx / pip --user install
#   ./install.sh --help
#
# Run nothing changes outside your user account; see README for what the tool
# itself does (diagnose is read-only; free/reclaim/swap/stop are opt-in).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="linux-ram-optimizer"
CMD_NAME="ram-optimizer"
MIN_PY_MINOR=9                 # requires Python 3.9+
VENV_DIR="${REPO_DIR}/.venv"

METHOD="auto"
EDITABLE=0
UNINSTALL=0

note()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pipx)      METHOD="pipx" ;;
        --user)      METHOD="user" ;;
        --venv)      METHOD="venv"; [ "${2:-}" ] && case "$2" in -*) ;; *) VENV_DIR="$2"; shift ;; esac ;;
        --editable|-e) EDITABLE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)   usage ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# --- preflight: a new-enough Python 3 -----------------------------------------
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH."
PY_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])')"
if [ "$(python3 -c 'import sys; print(sys.version_info[0])')" -ne 3 ] \
   || [ "${PY_MINOR}" -lt "${MIN_PY_MINOR}" ]; then
    die "Python 3.${MIN_PY_MINOR}+ required; found $(python3 -V 2>&1)."
fi

# --- uninstall ----------------------------------------------------------------
if [ "${UNINSTALL}" -eq 1 ]; then
    if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -q "${PKG_NAME}"; then
        note "Removing pipx install of ${PKG_NAME}"; pipx uninstall "${PKG_NAME}"
    else
        note "Removing pip --user install of ${PKG_NAME}"
        python3 -m pip uninstall -y "${PKG_NAME}" || warn "nothing to uninstall via pip"
    fi
    [ -d "${VENV_DIR}" ] && { note "Removing venv at ${VENV_DIR}"; rm -rf "${VENV_DIR}"; }
    note "Done."; exit 0
fi

# --- choose a method when on auto ---------------------------------------------
# An "externally-managed" Python (PEP 668) rejects `pip --user`; detect it so we
# fall back to a venv instead of failing.
externally_managed() {
    python3 - <<'PY'
import sys, sysconfig, pathlib
stdlib = sysconfig.get_paths().get("stdlib", "")
marker = pathlib.Path(stdlib) / "EXTERNALLY-MANAGED"
sys.exit(0 if marker.exists() else 1)
PY
}

if [ "${METHOD}" = "auto" ]; then
    if command -v pipx >/dev/null 2>&1; then
        METHOD="pipx"
    elif externally_managed; then
        warn "this Python is externally managed (PEP 668); pip --user is blocked."
        warn "falling back to a local venv. Install 'pipx' for a nicer setup."
        METHOD="venv"
    else
        METHOD="user"
    fi
fi

PIP_TARGET="${REPO_DIR}"
[ "${EDITABLE}" -eq 1 ] && PIP_TARGET="-e ${REPO_DIR}"

# --- install ------------------------------------------------------------------
case "${METHOD}" in
    pipx)
        command -v pipx >/dev/null 2>&1 || die "--pipx requested but pipx not found."
        note "Installing with pipx (isolated venv on PATH)"
        # shellcheck disable=SC2086
        pipx install ${EDITABLE:+--editable} "${REPO_DIR}" --force
        pipx ensurepath >/dev/null 2>&1 || true
        ;;
    user)
        note "Installing with pip --user"
        # shellcheck disable=SC2086
        python3 -m pip install --user --upgrade ${PIP_TARGET}
        ;;
    venv)
        note "Creating venv at ${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
        # shellcheck disable=SC2086
        "${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
        # shellcheck disable=SC2086
        "${VENV_DIR}/bin/python" -m pip install --upgrade ${PIP_TARGET}
        ;;
    *) die "unknown method: ${METHOD}" ;;
esac

# --- verify + PATH guidance ---------------------------------------------------
if [ "${METHOD}" = "venv" ]; then
    BIN="${VENV_DIR}/bin/${CMD_NAME}"
    "${BIN}" --version >/dev/null || die "install verification failed."
    note "Installed. Run it with:"
    printf '    %s diagnose\n' "${BIN}"
    printf '  or activate the venv first:  source %s/bin/activate\n' "${VENV_DIR}"
else
    if command -v "${CMD_NAME}" >/dev/null 2>&1; then
        note "Installed: $(command -v "${CMD_NAME}")  ($("${CMD_NAME}" --version))"
        note "Try:  ${CMD_NAME} diagnose"
    else
        USER_BIN="$(python3 -m site --user-base 2>/dev/null)/bin"
        warn "${CMD_NAME} is installed but not on PATH."
        warn "add this to your shell rc:  export PATH=\"${USER_BIN}:\$PATH\""
        note "Until then, run:  python3 -m ramopt diagnose"
    fi
fi
