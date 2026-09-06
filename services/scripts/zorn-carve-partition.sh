#!/bin/sh
# Carve a new partition for Linux out of the tail of Android's userdata.
#
# DRY RUN BY DEFAULT. Nothing is written without --commit.
#
# Why a new partition and not a bigger `arch`: the space freed by shrinking
# userdata lands at userdata's *end*, which is immediately before `arch`'s start.
# Growing `arch` would mean moving its start backwards, i.e. relocating the whole
# filesystem, which resize2fs cannot do. A new partition in the hole is clean, and
# it can then be bind-mounted, or joined to `arch` with btrfs/LVM, for the same
# effect.
#
# The only step that can destroy Android's data is the F2FS shrink. Shrinking F2FS
# is the least-travelled path in f2fs-tools -- growing is routine, shrinking is
# not -- so this script refuses to start unless there is real headroom, backs up
# the partition table first, and runs fsck before touching anything.
#
# Run it from Linux, not Android: userdata must be unmounted, and Android always
# has it mounted.
#
# Usage:
#   ./zorn-carve-partition.sh                 # dry run: check and print the plan
#   ./zorn-carve-partition.sh --commit        # actually do it
#   GIB=20 ./zorn-carve-partition.sh          # size of the new partition
set -eu

GIB=${GIB:-20}
HEADROOM_GIB=${HEADROOM_GIB:-10}      # free space that must remain in userdata
COMMIT=0
[ "${1:-}" = "--commit" ] && COMMIT=1

DISK=/dev/sda
UD=/dev/sda34                          # userdata
NEW=/dev/sda37                         # the partition this creates
BACKUP=/root/gpt-backup-$(date +%Y%m%d-%H%M%S)

say() { printf '%s\n' "$*"; }
die() { printf 'STOP: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- sanity checks
[ "$(id -u)" = 0 ] || die "run as root"
[ -b "$UD" ] || die "$UD is not a block device"
[ -b "$NEW" ] && die "$NEW already exists -- has this already been done?"

grep -qE "^$UD " /proc/mounts && die "$UD is mounted; unmount it first (and do not run this from Android)"

SECSZ=$(blockdev --getss "$DISK")
say "=== disk ==="
say "  $DISK logical sector size: $SECSZ bytes"
[ "$SECSZ" = 4096 ] || say "  (note: not 4096; all arithmetic below follows this value)"

# F2FS magic 0xF2F52010 little-endian at byte offset 1024
MAGIC=$(dd if="$UD" bs=1 skip=1024 count=4 2>/dev/null | od -An -tx4 | tr -d ' \n')
[ "$MAGIC" = "f2f52010" ] || die "$UD does not look like F2FS (magic $MAGIC)"
say "  $UD is F2FS"

for t in fsck.f2fs resize.f2fs sfdisk; do
	command -v "$t" >/dev/null || die "$t not installed (pacman -S f2fs-tools util-linux)"
done

# ------------------------------------------------------------------- the numbers
UD_START=$(cat /sys/class/block/$(basename $UD)/start)
UD_SIZE=$(cat /sys/class/block/$(basename $UD)/size)
# /sys reports 512-byte units regardless of the logical sector size
UD_START=$(( UD_START * 512 / SECSZ ))
UD_SIZE=$(( UD_SIZE * 512 / SECSZ ))
ARCH_START=$(( $(cat /sys/class/block/sda35/start) * 512 / SECSZ ))

WANT=$(( GIB * 1024 * 1024 * 1024 / SECSZ ))
UD_NEW=$(( UD_SIZE - WANT ))
# Align the new partition to 1 MiB
ALIGN=$(( 1024 * 1024 / SECSZ ))
NEW_START=$(( (UD_START + UD_NEW + ALIGN - 1) / ALIGN * ALIGN ))
NEW_SIZE=$(( ARCH_START - NEW_START ))

say "=== plan ==="
say "  userdata now:   start $UD_START  size $UD_SIZE  ($(( UD_SIZE * SECSZ / 1073741824 )) GiB)"
say "  userdata after: start $UD_START  size $UD_NEW  ($(( UD_NEW * SECSZ / 1073741824 )) GiB)"
say "  new $NEW:  start $NEW_START  size $NEW_SIZE  ($(( NEW_SIZE * SECSZ / 1073741824 )) GiB)"
say "  arch starts at $ARCH_START, so the new partition ends exactly where arch begins"
[ "$NEW_SIZE" -gt 0 ] || die "no room for a new partition"

# --------------------------------------------------- does the data actually fit?
TMP=$(mktemp -d)
mount -t f2fs -o ro "$UD" "$TMP" || die "cannot mount $UD read-only to measure it"
USED_KB=$(df -k "$TMP" | awk 'NR==2 {print $3}')
umount "$TMP"; rmdir "$TMP"
USED_GIB=$(( USED_KB / 1024 / 1024 ))
TARGET_GIB=$(( UD_NEW * SECSZ / 1073741824 ))
say "=== space ==="
say "  used in userdata: ${USED_GIB} GiB"
say "  target size:      ${TARGET_GIB} GiB"
say "  headroom needed:  ${HEADROOM_GIB} GiB (F2FS needs free segments to relocate blocks)"
[ $(( USED_GIB + HEADROOM_GIB )) -le "$TARGET_GIB" ] \
	|| die "does not fit: ${USED_GIB} + ${HEADROOM_GIB} > ${TARGET_GIB} GiB. Free more from Android first."
say "  fits"

if [ "$COMMIT" != 1 ]; then
	say ""
	say "Dry run only. Nothing was written. Re-run with --commit to proceed."
	exit 0
fi

# ------------------------------------------------------------------------ do it
say "=== backing up the partition table to $BACKUP.* ==="
sfdisk -d "$DISK" > "$BACKUP.sfdisk"
dd if="$DISK" of="$BACKUP.head" bs=1M count=1 status=none
say "  $BACKUP.sfdisk  (restore with: sfdisk $DISK < $BACKUP.sfdisk)"
say "  $BACKUP.head    (first 1 MiB, contains the primary GPT)"

say "=== fsck.f2fs -f (must pass before shrinking) ==="
fsck.f2fs -f "$UD" || die "fsck failed; do not shrink a filesystem that is not clean"

say "=== resize.f2fs -s -t $UD_NEW ==="
resize.f2fs -s -t "$UD_NEW" "$UD" || die "shrink refused or failed; the filesystem is untouched by the GPT edit below, so nothing is lost -- stop here"

say "=== rewriting the partition table ==="
awk -v ud="$UD" -v newsize="$UD_NEW" -v np="$NEW" -v ns="$NEW_START" -v nz="$NEW_SIZE" '
  $1 == ud { sub(/size=[ ]*[0-9]+/, "size= " newsize) }
  { print }
  END { printf "%s : start=%12d, size=%12d, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"linux-extra\"\n", np, ns, nz }
' "$BACKUP.sfdisk" > /root/gpt-new.sfdisk
say "  new table written to /root/gpt-new.sfdisk; applying"
sfdisk --no-reread --force "$DISK" < /root/gpt-new.sfdisk
partprobe "$DISK" 2>/dev/null || blockdev --rereadpt "$DISK" 2>/dev/null || true

say "=== formatting $NEW ==="
mkfs.ext4 -q -L linux-extra "$NEW"

say ""
say "Done. Before writing anything to $NEW:"
say "  1. reboot into Android and check its data is intact"
say "  2. then come back and add $NEW to /etc/fstab"
say "If Android is unhappy, restore the table with:"
say "  sfdisk $DISK < $BACKUP.sfdisk"
