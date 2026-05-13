# zephyr_ieee802154_efr32

Zephyr IEEE 802.15.4 radio driver for Silicon Labs EFR32 series SoCs,
targeting EFR32MG24 for Thread 1.4 and Matter-over-Thread. Wraps the
SiLabs RAIL (Radio Abstraction Interface Layer) prebuilt blob that
ships in `hal_silabs`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design rationale —
capabilities, the RX/TX boundary adjustments against RAIL, Enhanced
ACK timing, CSL, in-driver AES-CCM via RADIOAES, RAIL init lifecycle,
and how this driver leans on the Silicon Labs OpenThread platform
abstraction as a reference.

## Status

The driver implements the subset of `struct ieee802154_radio_api`
that Zephyr's OpenThread platform layer consumes. Validated on the
xg24_dk2601b development kit.

## Consuming this module

Pin in your downstream `west.yml`:

```yaml
manifest:
  projects:
    - name: zephyr_ieee802154_efr32
      url: https://github.com/mmmspatz/zephyr_ieee802154_efr32.git
      path: modules/zephyr_ieee802154_efr32
      revision: main
```

Zephyr discovers the module via `zephyr/module.yml`, which registers
this repository as both a `board_root` and a `dts_root` so the included
overlay and DT binding are found automatically.

## Building the OpenThread shell sample on xg24_dk2601b

The driver is built into any Zephyr application that has a Device Tree
node matching `compatible = "silabs,efr32-ieee802154"`. The included
overlay enables the radio on the xg24_dk2601b board:

```bash
west build -p always -b xg24_dk2601b \
  zephyr/samples/net/openthread/shell -- \
  -DEXTRA_DTC_OVERLAY_FILE="$(west topdir)/modules/zephyr_ieee802154_efr32/boards/silabs/dev_kits/xg24_dk2601b/xg24_dk2601b.overlay"
west flash -r jlink
```

After flash, `CONFIG_IEEE802154_EFR32=y` should appear in
`build/zephyr/.config`. If it doesn't, the overlay path was not picked
up by the build — Zephyr's `board_root` does not auto-apply overlays to
existing upstream boards, so passing `-DEXTRA_DTC_OVERLAY_FILE` is
required for builds that target upstream board definitions.

Bring the device up in the OpenThread shell:

```
> ot ifconfig up
> ot thread start
> ot state
leader
```

## Debug shell

Set `CONFIG_IEEE802154_EFR32_DEBUG=y` to enable the `efr32_radio`
shell command, which exposes event counters, radio state, source-match
table contents, MAC key slots, and the current CSL period. Adds
roughly 200 bytes of RAM and 2–4 KB of code.

## Sleepy End Device deployments

Three Kconfig symbols control SED behaviour:

- `CONFIG_PM` — registers RAIL with the Silicon Labs power manager so
  it can vote against EM2 while the radio is active.
- `CONFIG_PM_DEVICE` — wires the `efr32_pm_action` SUSPEND/RESUME
  callback.
- `CONFIG_IEEE802154_EFR32_SED` — a role marker for SED builds. It
  carries the LFXO devicetree precondition (HFXO is off in EM2, so CSL
  timing rides on the LFXO) and selects `CONFIG_PM` / `CONFIG_PM_DEVICE`.
  It does **not** appear in any `#ifdef`; the PM wiring is gated on
  the PM symbols directly.

`CONFIG_IEEE802154_EFR32_XTAL_ACCURACY` (default 40 PPM for EFR32MG24)
sets the value reported via `get_sch_acc()`. For SED builds, bump this
to the HFXO + LFXO ppm sum — LFXO drift accumulates in the CSL phase
budget while HFXO is asleep.

## License

Apache-2.0. See [LICENSE](LICENSE).
