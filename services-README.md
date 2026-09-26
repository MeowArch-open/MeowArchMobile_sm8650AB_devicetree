# Shared service notes

Subsystem-specific service material is stored below the subsystem that owns
it:

- `modem/services/zorn/`: Modem, IPA, QMI, QRTR, DIAG, Mink, RMTFS, state,
  and USB diagnostics.
- `display/services/`: Display deployment and probing helpers.
- `audio/services/`: Audio bring-up scripts, UCM files, and ADSP services.
- `wifi/services/`: Hostapd/libnl sources and hotspot networking.
- `common/services/`: cross-subsystem recovery, pstore, and partition
  helpers, plus the zorn charger authentication service
  (`charger/` source + `systemd/zorn-charger-auth.service`, enabled via
  `enabled-multi-user.txt`) and `scripts/zorn-charger-telemetry`. The charger
  auth binary is compiled by the Builder from `charger/src/`; see
  `charger/FORMAT.md` for the protected `records.bin` input format.
- `common/services/sensors/`: the ADSP sensor PD bring-up. The `hexagonrpcd`
  binary is built by the Builder from the `MeowArchMobile_hexagonrpc` project;
  the unit (`systemd/hexagonrpcd.service`, enabled via `enabled-multi-user.txt`),
  the SSR-then-serve `scripts/zorn-sensor-bringup.sh`, and the vendor-derived
  `sensors/hexfs/` HexagonFS data live here. See `sensors/README.md`.

The copied scripts retain device-specific paths and addresses from the original
bring-up workspace and should be reviewed before deployment.
