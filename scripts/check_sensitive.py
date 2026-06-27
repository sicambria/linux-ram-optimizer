#!/usr/bin/env python3
# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See <https://www.gnu.org/licenses/>.
"""Pre-push guardrail: refuse to publish personal / host-unique / secret data.

This scans the repository's **tracked** files (what a push would publish) for
material that should never leave the machine: the current user's name and home
path, personal email addresses, credential-shaped tokens, private IPs, and any
extra terms the maintainer lists in a *git-ignored* side file. It is the gate
behind ``.git/hooks/pre-push`` and ``make check-sensitive``.

Design choices that keep the guardrail itself publishable:

* The username and home directory are discovered **at runtime** (``getpass`` /
  ``$SUDO_USER`` / ``~``), never hard-coded — so this file contains no personal
  data and works on anyone's checkout.
* Project-specific secret terms (internal codenames, etc.) live in
  ``scripts/sensitive-extra.txt`` (one regex per line), which ``.gitignore``
  excludes. The guardrail loads it when present so the maintainer can block
  private terms without ever committing the list.

Exit status: ``0`` clean, ``1`` findings, ``2`` usage/environment error.
No third-party dependencies (standard library only), matching the project.
"""

from __future__ import annotations

import getpass
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXTRA_FILE = os.path.join(HERE, "sensitive-extra.txt")

# Binary / non-reviewable extensions we never scan as text.
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".gz", ".tgz", ".zip",
    ".xz", ".bz2", ".whl", ".pyc", ".so", ".o", ".woff", ".woff2", ".ttf",
    ".eot", ".mo", ".jar", ".class", ".bin", ".lock",
}

# Generic placeholders that are NOT a real person/home and must not trip the
# username/home rules (e.g. test fixtures using ``/home/user/...``).
_PLACEHOLDER_USERS = {
    "user", "users", "youruser", "username", "name", "example", "someone",
    "somebody", "foo", "bar", "test", "root", "admin", "ubuntu", "debian",
    "build", "runner", "ci", "me", "home",
}

# systemd unit suffixes — ``user@1000.service`` matches an email regex but is
# not an email. Anything ending in one of these is exempt from the email rule.
_UNIT_SUFFIXES = (
    ".service", ".scope", ".slice", ".target", ".mount", ".socket",
    ".device", ".timer", ".path", ".automount", ".swap",
)

# Email domains that are intentionally public / non-personal.
_EMAIL_OK = ("noreply", "example.com", "example.org", "gnu.org", "fsf.org")


def _credential_patterns() -> list[tuple[str, re.Pattern]]:
    """Credential-shaped tokens worth blocking outright."""
    return [(label, re.compile(rx)) for label, rx in [
        ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
        ("GitHub fine-grained PAT", r"github_pat_[A-Za-z0-9_]{20,}"),
        ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("Slack token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        ("OpenAI/Anthropic key", r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}"),
        ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        ("Assigned secret",
         r"(?i)\b(?:secret|api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\b"
         r"\s*[:=]\s*[\"'][A-Za-z0-9+/_\-]{12,}[\"']"),
    ]]


def _ip_is_public(ip: str) -> bool:
    """True for a routable-looking IPv4 (skip loopback / RFC1918 / link-local)."""
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    return all(0 <= int(x) <= 255 for x in ip.split("."))


def _identity_terms() -> list[tuple[str, re.Pattern]]:
    """Patterns derived from the *current* machine's identity (never hard-coded)."""
    terms: list[tuple[str, re.Pattern]] = []
    names = set()
    for candidate in (os.environ.get("SUDO_USER"), getpass.getuser(),
                      os.path.basename(os.path.expanduser("~"))):
        if candidate and len(candidate) >= 4 and candidate.lower() not in _PLACEHOLDER_USERS:
            names.add(candidate)
    for name in names:
        terms.append((f"current username '{name}'",
                     re.compile(r"\b" + re.escape(name) + r"\b")))
    home = os.path.expanduser("~")
    if home and home not in ("/", "/root"):
        terms.append((f"current home path '{home}'", re.compile(re.escape(home))))
    return terms


def _generic_home_re() -> re.Pattern:
    """Real-looking ``/home/<name>`` or ``/Users/<name>`` (placeholders excluded)."""
    return re.compile(r"/(?:home|Users)/([A-Za-z][A-Za-z0-9._-]{2,})")


def _extra_patterns() -> list[tuple[str, re.Pattern]]:
    """Maintainer-supplied regexes from the git-ignored side file, if any."""
    out: list[tuple[str, re.Pattern]] = []
    if not os.path.exists(EXTRA_FILE):
        return out
    with open(EXTRA_FILE, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append((f"private term /{line}/", re.compile(line, re.IGNORECASE)))
            except re.error as exc:
                print(f"warning: bad regex in {EXTRA_FILE!r}: {line!r} ({exc})",
                      file=sys.stderr)
    return out


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _tracked_files() -> list[str]:
    out = subprocess.run(["git", "-C", REPO, "ls-files", "-z"],
                         capture_output=True, text=True, check=True)
    return [p for p in out.stdout.split("\0") if p]


def _findings_in(path: str, text: str, rules, identity, extra) -> list[str]:
    home_re = _generic_home_re()
    creds = _credential_patterns()
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        loc = f"{path}:{lineno}"
        # Identity (current user) and maintainer extras: highest signal.
        for label, rx in identity + extra:
            if rx.search(line):
                hits.append(f"{loc}: {label}")
        # Generic foreign home paths.
        for m in home_re.finditer(line):
            if m.group(1).lower() not in _PLACEHOLDER_USERS:
                hits.append(f"{loc}: home path '{m.group(0)}'")
        # Personal emails (minus public/systemd-unit lookalikes).
        for m in _EMAIL_RE.finditer(line):
            email = m.group(0)
            low = email.lower()
            if any(ok in low for ok in _EMAIL_OK):
                continue
            if low.endswith(_UNIT_SUFFIXES):
                continue
            hits.append(f"{loc}: email '{email}'")
        # Credential-shaped tokens.
        for label, rx in creds:
            if rx.search(line):
                hits.append(f"{loc}: {label}")
        # Public IPv4.
        for m in _IP_RE.finditer(line):
            if _ip_is_public(m.group(0)):
                hits.append(f"{loc}: public IP '{m.group(0)}'")
    return hits


def main() -> int:
    try:
        files = _tracked_files()
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"check_sensitive: cannot list tracked files: {exc}", file=sys.stderr)
        return 2

    identity = _identity_terms()
    extra = _extra_patterns()
    # This scanner names placeholder users etc.; don't scan itself or the
    # git-ignored extras file for the literal terms it is built to detect.
    self_rel = os.path.relpath(os.path.abspath(__file__), REPO)

    all_hits: list[str] = []
    for rel in files:
        if rel == self_rel:
            continue
        if os.path.splitext(rel)[1].lower() in _SKIP_EXT:
            continue
        full = os.path.join(REPO, rel)
        try:
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if b"\0" in raw:           # binary — skip
            continue
        text = raw.decode("utf-8", errors="replace")
        all_hits.extend(_findings_in(rel, text, None, identity, extra))

    if all_hits:
        print("✗ pre-push guardrail: potential personal/host/secret data found:\n",
              file=sys.stderr)
        for h in all_hits:
            print(f"  {h}", file=sys.stderr)
        print("\nScrub these (or add a deliberate exception) before pushing. "
              "To stage a known-safe term, see scripts/check_sensitive.py.",
              file=sys.stderr)
        return 1

    print(f"✓ pre-push guardrail: {len(files)} tracked files clean "
          "(no personal/host/secret data).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
