#!/usr/bin/env bash
# linux-ram-optimizer — enable SSD TRIM/discard through a LUKS(+LVM) stack.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See <https://www.gnu.org/licenses/>.
#
# Whole-disk-encryption installs (LUKS -> [LVM] -> filesystem) ship with
# discard DISABLED at the dm-crypt layer, so the weekly `fstrim.timer` never
# reaches the SSD on the encrypted root — only unencrypted /boot gets trimmed.
# Over time that raises write amplification and hurts sustained write speed.
#
# This re-enables periodic TRIM end-to-end:
#   1. set `allow-discards` on the LUKS2 header (applies live AND persists),
#   2. refresh any LVM LV stacked on top so it re-inherits discard from below
#      (an LV activated before discard existed caches "no discard" in its
#      device-mapper table until reloaded),
#   3. run a one-time catch-up `fstrim`, then print SMART wear.
# It enables the *capability* so the existing fstrim.timer works — it does NOT
# turn on continuous `discard` mounting (a separate, generally-avoided option).
#
# SECURITY TRADEOFF: allow-discards lets the pattern of *unused* blocks (and so
# approximate used space / filesystem type) show through LUKS on a powered-off
# disk. Your data stays encrypted and unreadable. This is the standard,
# widely-accepted tradeoff for a single-user workstation; leave discard OFF
# only under a strict "stolen powered-off disk must leak nothing" threat model.
#
# Usage:  sudo bash scripts/luks-ssd-trim.sh
# The cryptsetup step may prompt once for the LUKS passphrase (that is not a
# hang). Override autodetection by exporting LUKS_DEV=/dev/... and/or MAP_NAME.
# TIP: back up the LUKS header first (the only durable change):
#   sudo cryptsetup luksHeaderBackup <LUKS_DEV> --header-backup-file hdr.img
#   (that file is sensitive — keep it offline, never in a repo or cloud sync).
set -uo pipefail

# --- detect the encryption stack -------------------------------------------
LUKS_DEV="${LUKS_DEV:-$(lsblk -rno NAME,FSTYPE \
  | awk '$2=="crypto_LUKS"{print "/dev/"$1; exit}')}"
[ -n "$LUKS_DEV" ] || { echo "No crypto_LUKS device found (set LUKS_DEV=...)." >&2; exit 1; }
MAP_NAME="${MAP_NAME:-$(lsblk -rno NAME,TYPE "$LUKS_DEV" \
  | awk '$2=="crypt"{print $1; exit}')}"
[ -n "$MAP_NAME" ] || { echo "$LUKS_DEV is not open (no crypt mapper) — unlock it first." >&2; exit 1; }
DISK="/dev/$(lsblk -rno PKNAME "$LUKS_DEV" | head -1)"

echo "LUKS container : $LUKS_DEV"
echo "open mapper    : $MAP_NAME"
echo "backing disk   : $DISK"
echo

# --- 1. require LUKS2 (needed for the live, persistent header flag) ---------
VER=$(cryptsetup luksDump "$LUKS_DEV" | sed -n 's/^Version:[[:space:]]*//p')
echo "LUKS version   : ${VER:-unknown}"
if [ "$VER" != "2" ]; then
  echo "Not LUKS2 — add 'discard' to the crypttab entry and run" >&2
  echo "'update-initramfs -u' instead (a root device unlocks from initramfs)." >&2
  exit 1
fi

# --- 2. enable allow-discards on the LUKS layer (live + persisted) ----------
echo
echo "==> Enabling allow-discards on $MAP_NAME (may prompt for passphrase)"
cryptsetup --allow-discards --persistent refresh "$MAP_NAME" && echo "    refresh OK"
cryptsetup luksDump "$LUKS_DEV" | grep -i '^Flags:' \
  || echo "    WARNING: no Flags line in header — verify manually"

# --- 3. propagate discard up through any LVM logical volume -----------------
for lvdm in $(lsblk -rno NAME,TYPE "$LUKS_DEV" | awk '$2=="lvm"{print $1}'); do
  pair=$(lvs --noheadings -o vg_name,lv_name "/dev/mapper/$lvdm" 2>/dev/null \
         | awk 'NF>=2{print $1"/"$2; exit}')
  if [ -n "${pair:-}" ]; then
    echo "==> Refreshing LVM volume $pair so it inherits discard"
    lvchange --refresh "$pair" && echo "    refreshed"
  fi
done

# --- 4. verify discard now reaches every layer (DISC-MAX must be non-zero) --
echo
echo "==> Discard capability through the stack:"
lsblk -D -o NAME,DISC-GRAN,DISC-MAX,MOUNTPOINT "$DISK"

# --- 5. one-time catch-up TRIM ---------------------------------------------
echo
echo "==> Catch-up fstrim:"
fstrim -av

# --- 6. SSD wear (ground truth) --------------------------------------------
echo
echo "==> SSD wear:"
if command -v smartctl >/dev/null; then
  smartctl -a "$DISK" | grep -iE \
    'Model Number|Percentage Used|Data Units Written|Available Spare|Power On Hours|Media and Data Integrity|Critical Warning'
elif command -v nvme >/dev/null; then
  nvme smart-log "$DISK" | grep -iE \
    'percentage_used|data_units_written|available_spare|power_on_hours|media_errors|critical_warning'
else
  echo "    install smartmontools (or nvme-cli) for wear stats"
fi
echo
echo "done."
