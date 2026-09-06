#!/bin/bash
# Watch what happens when the modem asserts with remoteproc auto-recovery ON.
#
# The RTSAR "Smart Transmit License Check Failure" fires ~160s after the data
# call, every time. If the modem can restart itself and we can re-establish the
# call, mobile data becomes usable in ~3 minute cycles even without solving the
# licensing. The risk this run is here to measure: early in this project
# `echo stop > .../state` hard-reset the whole SoC, which is why recovery has
# been off ever since -- but that was with the IPA faults still in place.
#
# Everything is written with sync and mirrored to /dev/kmsg, because if the SoC
# does reset we lose anything still sitting in a buffer.
set -u
OUT=/root/net.txt
RP=/sys/class/remoteproc/remoteproc0
WATCH=330

say() {
	printf '%s\n' "$*" >> "$OUT"
	printf 'zorn-rec: %s\n' "$*" > /dev/kmsg 2>/dev/null || true
	sync
}

say ""
say "=== remoteproc recovery test (watching ${WATCH}s) ==="
say "  recovery knob = $(cat /sys/kernel/debug/remoteproc/remoteproc0/recovery 2>/dev/null)"
say "  state at start = $(cat $RP/state 2>/dev/null), uptime $(cut -d' ' -f1 /proc/uptime)s"

prev=$(cat $RP/state 2>/dev/null)
crashed_at=""
i=0
while [ "$i" -lt "$WATCH" ]; do
	cur=$(cat $RP/state 2>/dev/null)
	if [ "$cur" != "$prev" ]; then
		say "  [$(cut -d' ' -f1 /proc/uptime)s] state: $prev -> $cur"
		[ "$cur" = crashed ] && crashed_at=$(cut -d' ' -f1 /proc/uptime)
		prev=$cur
	fi
	i=$((i + 1))
	sleep 1
done

say "--- kernel view of the crash and recovery ---"
dmesg 2>/dev/null | grep -iE "fatal error received|crash detected|recover|stop|shutdown|q6v5|ipa" \
	| tail -40 | sed 's/^/    /' >> "$OUT"
say "  final state = $(cat $RP/state 2>/dev/null), uptime $(cut -d' ' -f1 /proc/uptime)s"
say "  crashed at ${crashed_at:-never}"
say "  rmnet_ipa0 present: $(ip -br link show rmnet_ipa0 2>/dev/null | wc -l)"
ip -br link show 2>/dev/null | grep -E "rmnet" | sed 's/^/    /' >> "$OUT"

# If the modem came back, see whether a second call can be brought up.
if [ "$(cat $RP/state 2>/dev/null)" = running ] && [ -n "$crashed_at" ]; then
	say "--- modem is back; trying a second data call ---"
	systemctl restart zorn-wds 2>&1 | sed 's/^/    /' >> "$OUT"
	sleep 15
	if [ -r /run/zorn-wds.env ]; then
		. /run/zorn-wds.env
		say "  second call: addr=${ADDR:-none}/${PFX:-?} gw=${GW:-none}"
		if [ -n "${ADDR:-}" ]; then
			ip addr flush dev rmnet0 2>/dev/null
			ip addr add "$ADDR/${PFX:-30}" dev rmnet0 2>/dev/null
			ip route replace default via "${GW:-0.0.0.0}" dev rmnet0 metric 700 2>/dev/null
			timeout 20 ping -c3 -W3 223.5.5.5 2>&1 | tail -3 | sed 's/^/    /' >> "$OUT"
		fi
	else
		say "  no /run/zorn-wds.env after the restart"
	fi
fi
sync
say "=== recovery test done ==="
