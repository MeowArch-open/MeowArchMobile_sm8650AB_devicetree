# Shared service notes

Subsystem-specific service material is stored below the subsystem that owns
it:

- `modem/services/zorn/`: Modem, IPA, QMI, QRTR, DIAG, Mink, RMTFS, state,
  and USB diagnostics.
- `display/services/`: Display deployment and probing helpers.
- `audio/services/`: Audio bring-up scripts, UCM files, and ADSP services.
- `wifi/services/`: Hostapd/libnl sources and hotspot networking.
- `common/services/`: only cross-subsystem recovery, pstore, and partition
  helpers.

The copied scripts retain device-specific paths and addresses from the original
bring-up workspace and should be reviewed before deployment.
