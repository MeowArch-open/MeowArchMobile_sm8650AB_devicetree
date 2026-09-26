# zorn charger authentication protected input

`zorn-charger-auth` reads one fixed file, `/etc/zorn-charger-auth/records.bin`.
The path cannot be supplied through command-line arguments or the environment.
The file must be a regular, non-symlink, root-owned file with no group or other
permission bits. The installer creates its parent directory as mode `0700` and
the file as mode `0600`.

All integers are little-endian. The version 1 layout is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII magic `ZORNAUTH` |
| 8 | 4 | version (`1`) |
| 12 | 4 | header size (`40`) |
| 16 | 4 | record size (`52`) |
| 20 | 4 | record count (`1..10`) |
| 24 | 4 | seed size (`16`) |
| 28 | 4 | key size (`32`) |
| 32 | 4 | flags (`0`) |
| 36 | 4 | reserved (`0`) |

Each record contains a unique 32-bit index in the range `0..9`, followed by a
16-byte session seed and a 32-byte HMAC-SHA256 key. The total file length must
be exactly `40 + record_count * 52` bytes. No authentication material belongs
in this document, source code, build logs, command lines, or environment
variables.

The installed systemd service validates this container and runs public
SHA-256/HMAC-SHA256 self-tests. The binary also has a deterministic,
non-secret `--mock-self-test` which checks command ordering, explicit per-word
byte order, bounded retries/timeouts, disconnect/PDR aborts, SVID rejection,
HMAC rejection, commit gating, and cleanup.

The production sysfs backend is restricted to the discovered
`pmic_glink.power-supply.<number>/charger_diagnostics` device and the
`qcom-battmgr-usb` online node. It can write only `verify_process`,
`uvdm_command`, and `pd_auth_result`; it has no arbitrary path or property
interface. Live `--authenticate-once` and `--daemon` modes are compile-time
disabled by default (`ZORN_CHARGER_AUTH_ENABLE_LIVE=0`). Static reconstruction
of zorn's stock driver confirms that structured SET accepts 24-, 32-, and
52-byte acknowledgements, while structured GET requires the 32-byte word
response. The current Arch matcher follows those rules, but GET word
representation must still be verified on the deployed Arch kernel before live
mode is built. The validation-only systemd unit therefore remains the default
and cannot issue PMIC-GLINK writes.

For deployment validation, `common/services/scripts/zorn-charger-telemetry`
takes one read-only, sanitized snapshot. Run it before connecting a charger and
again after the state has settled; it never reads `uvdm_command`, writes sysfs,
or includes authentication bytes. A live authentication attempt remains
blocked in this build even if a protected container is present.
