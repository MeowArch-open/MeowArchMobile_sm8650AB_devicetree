#!/bin/bash
# Report, at every boot, whether the previous boot left a ramoops record.
#
# Our ramoops zone (0xa7000000, 4 MiB) has console-size = 1 MiB, so the kernel
# console is captured continuously -- that survives even a hard SoC reset, which
# is what we keep hitting and which loses the journal entirely. systemd-pstore
# moves whatever the pstore filesystem exposes into /var/lib/systemd/pstore, so
# copy it somewhere obvious and note whether there was anything at all.
#
# Caveat worth remembering: Android reserves the same address but with a
# different zone layout (console 2 MiB, pmsg 2 MiB, no dump records), so booting
# Android after a crash overwrites our records. To read a crash log, boot Linux
# again *before* Android.
set -u
OUT=/root/pstore-check.txt
{
	echo "=== boot at $(date -Is 2>/dev/null) (uptime $(cut -d' ' -f1 /proc/uptime)s) ==="
	echo "--- /sys/fs/pstore ---"
	ls -la /sys/fs/pstore/ 2>&1
	echo "--- /var/lib/systemd/pstore ---"
	find /var/lib/systemd/pstore -type f 2>/dev/null | head -40
} >> "$OUT"

mkdir -p /root/pstore
n=0
for f in $(find /var/lib/systemd/pstore -type f 2>/dev/null); do
	cp -f "$f" "/root/pstore/$(echo "$f" | tr '/' '_')" 2>/dev/null && n=$((n+1))
done
for f in /sys/fs/pstore/*; do
	[ -f "$f" ] || continue
	cp -f "$f" "/root/pstore/$(basename "$f")" 2>/dev/null && n=$((n+1))
done
echo "--- copied $n file(s) into /root/pstore ---" >> "$OUT"
sync
