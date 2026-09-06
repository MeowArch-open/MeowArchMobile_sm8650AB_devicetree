#!/system/bin/sh
# Make the next Linux boot come up WITHOUT the modem, so it is bootable again,
# and install the step-by-step bring-up script.
R=/mnt/arch
W=$R/etc/systemd/system/multi-user.target.wants

echo "--- disabling autostart of the modem chain ---"
for u in zorn-mpss.service zorn-sim.service zorn-tqftpserv.service zorn-pd-mapper.service; do
	if [ -L "$W/$u" ]; then
		rm -f "$W/$u" && echo "  disabled $u"
	else
		echo "  $u was not enabled"
	fi
done

# ModemManager Wants= the modem units, so it would drag them back in.
for d in "$R/etc/systemd/system/multi-user.target.wants/ModemManager.service" \
         "$R/etc/systemd/system/dbus-org.freedesktop.ModemManager1.service"; do
	[ -L "$d" ] && rm -f "$d" && echo "  disabled $(basename "$d")"
done

echo "--- installing the step script ---"
cp /data/local/tmp/zorn-modem-step.sh "$R/usr/local/sbin/" && \
	chmod 755 "$R/usr/local/sbin/zorn-modem-step.sh" && echo "  ok"

echo "--- enabling systemd-pstore so a ramoops dump gets saved to disk ---"
if [ -f "$R/usr/lib/systemd/system/systemd-pstore.service" ]; then
	ln -sf ../systemd-pstore.service "$R/etc/systemd/system/sysinit.target.wants/systemd-pstore.service"
	echo "  enabled systemd-pstore.service"
else
	echo "  systemd-pstore.service not present in this systemd build"
fi

echo "--- state ---"
ls "$W" | grep -E "zorn|Modem" || echo "  (no zorn/ModemManager units enabled)"
sync
