#!/system/bin/sh
R=/mnt/arch
W=$R/etc/systemd/system/multi-user.target.wants

# Restore the alias systemd needs to own the D-Bus name. Without it, dbus-daemon
# cannot resolve SystemdService=dbus-org.freedesktop.ModemManager1.service and
# falls back to the activation file's Exec=/usr/bin/ModemManager -- giving a
# SECOND ModemManager process. The two then fight over the same modem: one
# enables it, the other re-probes and disables it, which is the
# enable -> disable -> "creating modem with plugin qcom-soc" loop we saw
# (PIDs 619 and 630 both logging).
ln -sf /usr/lib/systemd/system/ModemManager.service \
	"$R/etc/systemd/system/dbus-org.freedesktop.ModemManager1.service"
echo "alias:"; ls -la "$R/etc/systemd/system/dbus-org.freedesktop.ModemManager1.service"

# zorn-usbdbg polls `mmcli -L` every 5s from early boot, which D-Bus-activates
# ModemManager long before the radio is online. Its one real job (VBUS for the
# USB port) belongs to zorn-adsp.service anyway.
rm -f "$W/zorn-usbdbg.service"

echo "--- enabled ---"; ls "$W" | grep -E "zorn|Modem"
sync
