#!/bin/bash
# zorn-sensor-bringup: clean ADSP SSR, then serve HexagonFS so the SSC re-probes
# the i2c-hub sensors (qmc6308 mag / stk3bfx als+prox) at a moment their probe
# succeeds. The plain boot attach only brings up the I3C accel/gyro; the I2C-hub
# set + the fusion virtuals (gravity/game_rv) need a fresh post-boot PD probe
# (empirically confirmed 2026-09-25). ADSP SSR (remoteproc1) does NOT touch the
# modem (remoteproc0) or WiFi, so the ssh/hotspot uplink stays up.
#
# NOTE: the SSR-then-serve timing here was validated on a warm session; the
# cold-boot ordering is still being verified on-device.
set +e
HEXFS=${ZORN_HEXFS:-/var/lib/hexagonrpcd/hexfs}
echo stop  > /sys/class/remoteproc/remoteproc1/state; sleep 3
echo start > /sys/class/remoteproc/remoteproc1/state; sleep 5
exec /usr/local/sbin/hexagonrpcd -f /dev/fastrpc-adsp -d adsp -s -R "$HEXFS"
