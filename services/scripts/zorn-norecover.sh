#!/bin/bash
# Turn off remoteproc auto-recovery as early as possible, and snapshot the
# modem-relevant kernel messages to disk.
#
# Why this has to be early: `echo stop > .../state` hard-resets this SoC, so if
# the MPSS crashes while recovery is still enabled, remoteproc's recovery work
# stops the MPSS and takes the whole machine down -- black screen at ~3s, journal
# truncated, nothing to look at. rmtfs -s boots the modem at ~3.3s, so the knob
# has to be flipped before that. zorn-net-up.sh also does it, but that runs far
# too late to protect the boot itself.
set -u
REC=/sys/kernel/debug/remoteproc/remoteproc0/recovery
OUT=/root/dmesg-modem.txt

for i in $(seq 1 40); do
	[ -e "$REC" ] && break
	sleep 0.25
done

if [ -w "$REC" ]; then
	echo disabled > "$REC" 2>/dev/null
	echo "zorn-norecover: remoteproc0 recovery = $(cat "$REC" 2>/dev/null)"
else
	echo "zorn-norecover: $REC not present; a modem crash may reset the SoC"
	ls -la /sys/kernel/debug/remoteproc/ 2>&1
fi

# Snapshot in the background: a modem assert usually lands 30-60s in, and the
# journal does not survive a reset, so put it somewhere durable.
(
	sleep 45
	{
		printf '\n########## boot %s ##########\n' "$(date -Is 2>/dev/null)"
		echo "--- remoteproc states ---"
		for rp in /sys/class/remoteproc/remoteproc*; do
			[ -r "$rp/name" ] || continue
			echo "  $(basename "$rp") $(cat "$rp/name" 2>/dev/null) = $(cat "$rp/state" 2>/dev/null)"
		done
		echo "  recovery = $(cat "$REC" 2>/dev/null)"
		echo "--- modem / smmu / ipa kernel messages ---"
		dmesg 2>/dev/null | grep -iE "remoteproc|q6v5|fatal|smmu|ipa |rmnet|qrtr" | tail -60
	} >> "$OUT"
	sync
) &
exit 0
