# zorn sensors (ADSP sensor PD via HexagonFS)

The mainline sensor stack on zorn (SM8650) runs the Qualcomm SSC sensor PD on the
ADSP. It is fed by `hexagonrpcd`, the FastRPC HexagonFS file server (the mainline
replacement for Android's `sscrpd`). The daemon binary is built by the Builder
from the `MeowArchMobile_hexagonrpc` project and installed to
`/usr/local/sbin/hexagonrpcd`; the bring-up glue lives here:

- `../systemd/hexagonrpcd.service` — one-shot bring-up unit, enabled via
  `../enabled-multi-user.txt`. Skips itself (ConditionPathIsDirectory) when the
  `hexfs/` data below was not shipped.
- `../scripts/zorn-sensor-bringup.sh` — installed to
  `/usr/local/sbin/zorn-sensor-bringup.sh`. Does a clean ADSP SSR
  (remoteproc1 stop/start) and THEN serves HexagonFS, because a plain boot
  attach only brings up the I3C accel/gyro; the i2c-hub set (qmc6308 mag,
  stk3bfx als/prox) and the fusion virtuals need a fresh post-boot PD probe.
  The SSR is scoped to the ADSP and does not disturb the modem (remoteproc0) or
  WiFi. Cold-boot timing is still being verified on-device.

## `hexfs/` — vendor-derived data, NOT source-reproducible

`hexfs/` is the HexagonFS root the daemon serves (`-R`). It is extracted from the
device vendor partition and is not reproducible from any source in this project
(treat it like a firmware blob):

- `sensors/config/` — Qualcomm SSC per-sensor JSON descriptors.
- `sensors/registry/` — the sensor registry plus `parsed_file_list.csv`, which
  the sensor PD *rewrites* when it regenerates the registry. That write is only
  possible because the zorn `hexagonrpc` fork adds a HexagonFS write path.
- `sensors/sns_reg.conf`, `socinfo/`, `dsp/adsp/*.so` — SSC registry config,
  SoC identity (Snapdragon / SM8650 / soc_id 557 — generic, no secrets), and the
  ADSP-side sensor shim libraries.
- `acdb/` — empty HexagonFS mount point on the device; kept as a `.gitkeep` only.

The Builder / `install-meowarch.sh` install this tree read-shaped into
`/var/lib/hexagonrpcd/hexfs`, where the running (root) daemon can rewrite the
registry.
