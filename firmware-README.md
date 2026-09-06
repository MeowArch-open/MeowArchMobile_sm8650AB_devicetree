# Firmware notes

Firmware is kept below the subsystem that consumes it:

- `display/firmware/gpu/`: Gen70900 SQE, ZAP, and GMU firmware.
- `audio/firmware/qcom/sm8650/`: AudioReach topology variants, ADSP, ADSP DT,
  and service JSON files read from the current Arch rootfs.
- `modem/firmware/split/`: the earlier MDT/Bxx split package from the bring-up
  workspace.
- `modem/firmware/qcom/sm8650/`: the current Arch rootfs layout containing
  IPA firmware, Modem/Modem DT payloads, `modem_oem`, `modem_pr`, and Lanai
  data.

UEFI images, ESP images, Android partitions, journals, and compiled kernel or
userspace binaries were not copied here.
