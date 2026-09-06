# Shared material

`common/` contains material that is consumed by more than one subsystem or
does not belong to a single hardware block.

- `dts/`: complete Android/vendor trees, booted-tree snapshots, and historical
  variants used as bases for subsystem-specific DTS experiments.
- `services/`: cross-subsystem recovery, pstore, and partition helpers.
- `services/ssh/`: root SSH configuration used by the Arch bring-up image.
- `tools/`: shared helper space.
- `*-README.md`: notes retained from the extraction.

Display, touch, audio, Modem, and Wi-Fi-specific DTS, services, and firmware
live under their respective subsystem directories.
