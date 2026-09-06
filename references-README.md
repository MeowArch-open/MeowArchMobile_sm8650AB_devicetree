# Reference material

Reference directories are not part of the clean-kernel patch series. They are
kept because the zorn drivers and services were developed by comparing Linux
against Android/vendor implementations.

- `display/panelgen/`: MIPI DSI panel driver generator.
- `display/spr-vendor/`: Xiaomi Qualcomm display vendor source.
- `display/tools/`: display probing and register/debug helpers.
- `modem/android-ipa/`: Android IPA reference source.
- `modem/android-rmnet/`: Android RMNET/QMAP/QMI reference source.
- `modem/headers/`: QMI/DIAG/EFS reference code and headers.
- `audio/android-audio/`: Android audio ground truth, mixer data, and SIA
  reference measurements.

Vendor-only runtime binaries from `qwes/`, `vbin/`, and `qm/` were not copied;
the source and firmware needed for the Linux-side implementation are kept in
`services/` and `firmware/` instead.
