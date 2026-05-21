# Architecture

`drivers/ieee802154/ieee802154_efr32.c` is a Zephyr
`struct ieee802154_radio_api` implementation for the Silicon Labs EFR32
radio. It wraps RAIL (the prebuilt Radio Abstraction Interface Layer that
ships in `hal_silabs`) and targets EFR32MG24 (Series 2) for Thread 1.4 and
Matter-over-Thread.

```
Zephyr ieee802154_radio_api calls
        │
    this driver
        │
    RAIL API calls   →   RAIL event callback   →   net_pkt delivery
```

OpenThread integration is automatic once `ieee802154_radio_api` is
implemented: the Zephyr OpenThread platform layer (`modules/openthread/
platform/radio.c` in the upstream Zephyr tree) translates `otPlatRadio*()`
into our API. We do not implement that layer.

The rest of this document is *why* the driver is shaped the way it is — the
invariants, the small number of decisions that are non-obvious from a single
call site, and the references that ground each design choice.

---

## 1. Capabilities

`efr32_get_capabilities()` returns:

| Cap | Why it's set |
|---|---|
| `HW_FCS` | RAIL validates and strips FCS on RX; generates it on TX. |
| `HW_FILTER` | Short / extended / PAN-ID filtering done by RAIL. |
| `HW_TX_RX_ACK` | **Mandatory** — the OpenThread platform layer `k_panic`s in `platformRadioInit()` if this is absent. |
| `HW_CSMA` | Built on `sl_rail_start_csma_tx()`. CSMA requires active RX; the driver forces RX before submission if idle. |
| `HW_ENERGY_SCAN` | RAIL has no native scan; implemented with polled `sl_rail_get_rssi()` (§6). |
| `HW_TXTIME` | CSL scheduled TX — used by sleepy children to TX into a parent's window. |
| `HW_RXTIME` | CSL scheduled RX — used by the SSED itself to open its own window. |
| `HW_SLEEP_TO_TX` | Deprecated per Zephyr issue #63670 but still a control-flow gate: the OT platform layer refuses `otPlatRadioTransmit()` from `SLEEP` without it, so indirect TX to sleepy children depends on the bit. |
| `RX_ON_WHEN_IDLE` | Drives the §3.3 yield-and-restart decision. |
| `HW_TX_SEC` | Unconditional (§3.2). |

---

## 2. Reference material

The driver leans heavily on the **Silicon Labs OpenThread platform
abstraction** that ships in the Simplicity SDK. That codebase implements
the same OpenThread radio API directly against RAIL, in C, with no
Zephyr in between. It is the closest answer to "how do you actually
combine these RAIL primitives to satisfy Thread?" and it was our primary
guide for translation patterns. Relevant files:

- `radio.c` — `otPlatRadio*` entry points, RAIL event handling, state
  machine.
- `mac_frame.cpp` — frame parsing, Enh-ACK construction, CSL phase math.
- `ieee802154-packet-utils.cpp` — RADIOAES-based TX security.

We cite these by filename throughout the source. They are not linked into
the driver — they are reference reading.

The **Zephyr OpenThread platform** (`modules/openthread/platform/radio.c`
in the upstream Zephyr tree) is the consumer. It dictates which
`ieee802154_radio_api` calls happen, in what order, with what expected
errno, and when `net_pkt_ieee802154_ack_fpb()` is read.

**Zephyr's nRF5 reference driver**
(`drivers/ieee802154/ieee802154_nrf5.c` in the upstream Zephyr tree) is
the closest structural peer in-tree and the authoritative reference for
Zephyr-API behavioural edges — PHR-strip timing, FCS-append shape,
ACK-FPB propagation.

The specifications we cite directly:

- **IEEE Std 802.15.4-2024** — frame formats (ch. 7), security (ch. 9),
  CSL (§10.5).
- **Thread 1.4.0 Specification** — SecurityLevel 5 mandate (§7.2.3), CSL
  usage, link-metrics probing.
- **Silicon Labs RAIL 3.0.2** — API symbols and event semantics; cited
  by symbol name (e.g. `SL_RAIL_EVENT_RX_PACKET_RECEIVED`,
  `sl_rail_ieee802154_get_address`).

---

## 3. Architectural invariants

Three rules hold everywhere in the driver. Breaking any of them surfaces as
intermittent RAIL asserts, stuck semaphores, or silent CCM* failures.

### 3.1 Single execution context for RAIL calls

RAIL is not thread-safe. Every `sl_rail_*()` function runs from exactly one
thread — either the driver's call chain through Zephyr's OpenThread radio
work queue (`iface_init` / `configure` / `tx`) or the dedicated RX thread.
The RAIL event callback runs in ISR context and may only:

- read event flags;
- copy RX packet data out during `SL_RAIL_EVENT_RX_PACKET_RECEIVED`
  (`sl_rail_get_rx_packet_info`, `sl_rail_copy_rx_packet`,
  `sl_rail_get_rx_packet_details`, `sl_rail_get_rx_time_sync_word_end`) —
  packets are auto-released when the callback returns; we never call
  `sl_rail_hold_rx_packet()` (incompatible with DMP);
- toggle frame-pending for Imm-ACK
  (`sl_rail_ieee802154_toggle_frame_pending`);
- build and write Enhanced ACKs
  (`sl_rail_ieee802154_write_enh_ack`);
- read the live SrcAddr (`sl_rail_ieee802154_get_address`);
- hand off to thread context via `k_sem_give` / `k_fifo_put`.

All other RAIL calls (`start_rx`, `start_tx`, `idle`, `set_tx_fifo`,
`config_rx_options`, `calibrate`, ...) happen from thread context. The
single-context model eliminates the locking question entirely; RAIL
explicitly warns against IRQ-locking around its state because deferred
interrupts can abort TXes mid-flight.

### 3.2 TX security is all-or-nothing

Because the driver owns Enhanced-ACK construction (§5) and the ACK frame
counter is drawn from the same per-slot counter as data frames, OpenThread
cannot be trusted with any part of TX crypto: a split would let the two
sides diverge. The driver therefore reports `IEEE802154_HW_TX_SEC`
unconditionally and encrypts every secured frame it emits — data frames in
`efr32_tx`, Enhanced ACKs in the `DATA_REQUEST_COMMAND` handler.

The retransmission contract, checked via `net_pkt_ieee802154_frame_secured()`:

- `frame_secured == true` (retransmission): do **not** re-encrypt and do
  **not** touch the frame counter — OpenThread expects the exact same bytes
  on air.
- `frame_secured == false`: write the current per-slot frame counter into
  the aux header, encrypt, increment the counter, set both
  `frame_secured` and `mac_hdr_rdy`.

Frame counters are **per-slot** (`struct efr32_mac_key_slot`, prev / current
/ next; current is always index 1 in Thread). A per-slot counter is the
only way to keep the retiring epoch intact during rotation: ACKs generated
for in-flight frames under the previous key must use slot[prev]'s FC, not
the new current slot's. A shared counter would let rotation consume
counter space from a slot the peer has stopped listening for.

### 3.3 Idle only when necessary; yield-and-restart in the ISR

RAIL handles most state transitions internally: `sl_rail_start_tx()` from
RX waits for any in-progress packet, and auto-transitions configured in
`sl_rail_ieee802154_init()` handle TX→RX and RX→RX transparently. We call
`sl_rail_idle()` only where the current state actively conflicts with the
next action: `stop()` / sleep, before disabling frame detection for an ED
scan, and before restarting continuous RX after a cancelled scheduled-RX
slot.

`sl_rail_yield_radio()` is separately important. In a single-protocol build
it is a no-op unless Power Manager is initialised, in which case it allows
EM2 entry. In DMP it hands the radio back to BLE. After a yield the radio
is idle: it cannot receive, cannot auto-ACK, and cannot start a CSMA TX
(which requires active RX). The Zephyr L2 contract has no "restart RX
after TX" callback, so the driver self-manages this in the ISR via
`efr32_yield_and_rx()` — yield, then immediately restart RX when the radio
should be continuously listening.

The gate is `rx_on_when_idle`. FTD/MTD (`true`) get the restart; SSED
(`false`) stays idle so the CSL scheduler can own when the radio
listens. Forcing RX back on for an SSED would leak an idle vote and
prevent EM2 entry between windows. The matching pattern in `efr32_pm_action`
is that `PM_DEVICE_ACTION_RESUME` is intentionally a no-op — the next
`rx_slot` / `start` call from OpenThread restarts RX if that's wanted.

---

## 4. RX path — RAIL→Zephyr boundary adjustments

Two adjustments sit on the RX boundary and are both load-bearing:

1. **Strip the PHR.** RAIL hands us packet data that begins with the
   1-byte PHR; Zephyr and OpenThread expect PSDU only. The driver
   advances `p_first_portion_data` by `PHR_SIZE` and decrements the byte
   counts before `sl_rail_copy_rx_packet()`.
2. **Append a dummy FCS when `CONFIG_IEEE802154_L2_PKT_INCL_FCS` is set.**
   RAIL validates and strips the FCS, so `packet_bytes` excludes it. When
   the upper layer expects an FCS, the frame is two bytes short and the
   parser rejects every packet. The driver appends `{0,0}` so
   `net_buf_frags_len` matches the expected `mLength`.

Both failure modes look identical from outside: frames arrive (RX counters
move) but OpenThread cannot parse any of them, so the device attaches as
nothing and self-promotes to leader.

**Extended-address byte order.** Three distinct forms appear in this
codebase and they are easy to confuse:

- *On-air / wire order* — `[802154-2024] §4`, rightmost octet first. What
  Zephyr's `filter->ieee_addr` hands us, what
  `sl_rail_ieee802154_set_long_address()` expects, and what appears
  inside PSDUs.
- *Canonical / MSO-first* — EUI-64 display form. What `[802154-2024]
  §9.3.2.1` requires as the CCM* nonce source address.
- *LE-in-address-field* — ext_addr as it sits inside a received PSDU;
  same bytes as on-air order.

The driver stores `data->mac` in canonical order (set up from the factory
EUI in `efr32_iface_init()`) and byte-reverses at the filter callback into
that form. `efr32_ext_addr_on_air_to_canonical()` encodes the contract at
its one call site — it must not be "simplified" into a `memcpy()`.

A second byte-order hazard lives in the ACK-IE table: Zephyr's API
contract states that `ack_ie.ext_addr` is big-endian while `ack_fpb.addr`
is little-endian (see `include/zephyr/net/ieee802154_radio.h`). The ISR
byte-reverses extended-address comparisons at compare time when matching
IE entries against the incoming SrcAddr.

---

## 5. Enhanced ACK and `DATA_REQUEST_COMMAND` — the timing-critical path

The `DATA_REQUEST_COMMAND` callback is the only place where the driver
runs against a ~500 µs hard deadline and must read frame state that is
still arriving. Most of what is interesting about this driver lives here.

### 5.1 Frame-version dispatch

- **FV0 / FV1** → Imm-ACK. RAIL generates the ACK; the driver's only job
  is to flip the frame-pending bit via
  `sl_rail_ieee802154_toggle_frame_pending()` if the SrcAddr matches a
  source-match table entry.
- **FV2** → Enhanced ACK. The driver hand-builds the ACK in
  `efr32_build_enh_ack()`, optionally injects header IEs (CSL IE with
  patched phase, Link-Metrics probing IEs), applies security, and hands
  the whole thing to `sl_rail_ieee802154_write_enh_ack()`. The FP bit
  lives in the FCF the driver writes; `toggle_frame_pending()` is not
  used in this path.

### 5.2 SrcAddr comes from RAIL's parser, not the FIFO

Measured on EFR32MG24 with RAIL 3.0.2: at `DATA_REQUEST_COMMAND` callback
entry, `sl_rail_get_rx_incoming_packet_info()` reports ~22 bytes for a
24-byte MHR — the last two bytes of SrcAddr have not yet been DMAed into
the FIFO. Building the Enh-ACK with the partial FIFO yields a zero/garbage
DstAddr, the peer discards it, and CSL synchronisation never converges.

`sl_rail_ieee802154_get_address()` reads RAIL's parser-owned state, not
FIFO bytes. By callback time the parser has consumed SrcAddr into internal
registers even when the FIFO is short, so the handler uses the getter for
SrcAddr only and falls through to the FIFO for the earlier MHR fields
(FCF, SeqNum, DstPAN, DstAddr, SrcPAN, AuxSecHdr) which sit before SrcAddr
on air and are therefore already committed. The "true on-air timestamp for
the still-incomplete frame" is *not* exposed by RAIL — callback-entry
`sl_rail_get_time()` is the supported anchor (§5.5).

### 5.3 The ext/ext PAN-ID presence asymmetry

`[802154-2024] Table 7-2` is not uniform. For Frame Version 2 with both
addresses extended:

- `pan_comp = 0` → DstPAN present, **SrcPAN absent**;
- `pan_comp = 1` → **both PANs absent**.

Every other "both present" combination carries DstPAN and uses `pan_comp`
to decide SrcPAN. Getting this row wrong is catastrophic and silent: a
phantom SrcPAN shifts `sec_hdr_offset` by +2, so SecurityControl is read
from the wrong byte, KeyIdMode and key-source size come out wrong,
`aux_hdr_len` inflates, and the frame counter and MIC are written at the
wrong offsets. FCS passes (it covers whatever we emitted), but the peer
rejects the frame at `Frame::ValidatePsdu()`.

`efr32_pan_presence()` encodes Table 7-2 once and is used by both the
parser (`efr32_parse_aux_sec`) and the Enh-ACK builder. The ext/ext case
must not be folded back into the general branch. The Enh-ACK builder
matches the same table: ext-dst ACKs use `PanComp=1` (no DstPAN), not
`PanComp=0` with `PAN=0x0000`.

### 5.4 Header IEs are authenticated, not encrypted

`[802154-2024] §9.3.3` puts header IEs in the a-data region;
`[802154-2024] Annex C §C.4.7` is the test vector. `efr32_header_ies_end()`
returns the byte offset of the first non-IE byte (after HT1/HT2 or at the
first type-1 IE). `efr32_process_tx_security` uses that offset to adjust:

```
a_len = aux.hdr_len + ie_area_len
m_len = aux.payload_len - ie_area_len
```

For pre-2015 MAC Command frames (FV0/FV1) the command-ID byte is part of
the MHR — `a_len += 1`, `m_len -= 1`. FV2 MAC Commands put the command ID
in the payload.

### 5.5 CSL phase anchor

`[802154-2024] §10.5.5.1` defines CSL Phase as the time until the next CSL
sample window, in 10-symbol units (160 µs per unit at 2.4 GHz O-QPSK),
encoded LE16. Rendezvous Time only appears when `macCslInterval != 0`;
Thread does not use it.

Zephyr wires the anchor through `IEEE802154_CONFIG_EXPECTED_RX_TIME`:
`cslAnchorPointNs = expected_rx_time + PHR_duration_ns`, and
`cslPhase = (startOfMhrNs − cslAnchorPointNs) / (10 · sym_ns) mod
cslPeriod`.

For an Enh-ACK in `DATA_REQUEST_COMMAND`, "start of MHR" is the instant
the ACK's MHR byte hits the air. The driver computes:

```
ack_mhr_us = rx_callback_us
           − rx_bytes_onair × 32 µs    (rewind to incoming SHR-end)
           + PHR_onair_us              (incoming PHR)
           + frame_len × 32 µs         (incoming payload + FCS)
           + RX_TO_TX_us               (turnaround)
           + PHR_onair_us              (ACK PHR)
           + SHR_duration_us           (ACK SHR)
           + PHR_onair_us              (anchor offset)
```

For outgoing data frames carrying a CSL IE, `tx_mhr_us = action_time_us +
SHR + PHR`, where `action_time_us` is either the `TXTIME_CCA` anchor
supplied by OpenThread or, when CSL is active on a CSMA-CA-mode frame, a
forced `now + SCHEDULE_TX_DELAY_US` — the scheduled anchor is pinned
regardless of CCA outcome, so phase does not drift across CSMA retries.
`SCHEDULE_TX_DELAY_US` is 3000 µs.

### 5.6 Per-slot frame counter and ACK key selection

`efr32_select_slot()` picks prev / current / next by matching the incoming
frame's key ID for ACKs, and always returns current for data TX. When the
upper layer rotates keys via `IEEE802154_CONFIG_MAC_KEYS`, the driver
carries the retiring current-slot FC into slot 0 if the caller didn't
supply one explicitly, preserving the previous epoch's counter state.

---

## 6. Energy scan

RAIL exposes no "scan N ms, return peak RSSI" call and no standalone CCA
in 3.0. The driver implements both with `sl_rail_get_rssi()` + a polled
multi-timer (`sl_rail_set_multi_timer`) at 128 µs cadence — eight symbols
at the 2.4 GHz O-QPSK symbol rate. Each sample updates a running peak;
`efr32_ed_scan_done` reports the peak to the OpenThread callback. LQI on
received frames comes directly from
`sl_rail_get_rx_packet_details()->lqi` rather than being derived locally.

---

## 7. AES-CCM — why in-driver RADIOAES, not PSA

Thread 1.4 §7.2.3 mandates SecurityLevel 5 (`ENC-MIC-32`) on all data
frames. Because the driver owns Enh-ACK construction and the ACK frame
counter is shared with data frames (§3.2), the driver also owns all TX
security. The choice of *how* to run AES-CCM is the interesting part:

- The generic OpenThread crypto path
  (`Crypto::AesCcm` → `Crypto::AesEcb` → `otPlatCryptoAesEncrypt`)
  terminates in Zephyr at `crypto_psa.c` as one `psa_cipher_encrypt()` per
  16-byte block. Under PSA each call crosses API boundaries, sets up
  context, waits on the Series-2 SE mailbox, and returns. For a secured
  Enhanced ACK with a ~500 µs deadline this is tens of PSA calls; it does
  not fit.
- **RADIOAES** is a separate AES accelerator from the main-CPU SLAES
  that mbedTLS/PSA drives. Register-level, sub-2 µs per AES-128 block, no
  OS dependencies, ISR-safe. CCM* for a small ACK runs in ~10–20 µs
  end-to-end.

The driver calls `sli_aes_crypt_ecb_radio()` directly via
`efr32_ccm_encrypt` and `efr32_process_tx_security`, for both the ISR
Enh-ACK path and the thread-context data-frame path. Using one path for
both keeps nonce construction and the a/m boundary co-located.

Nonce layout (per `[802154-2024] §9.3.2.1`): `ext_addr || frame_counter ||
sec_level`, all big-endian. `efr32_ccm_nonce()` encodes this; the OT-core
`Frame::GenerateNonce` is a useful cross-check.

MIC sizing (per `[802154-2024] §9.4.2.2 Table 9-6`): 0 → no MIC, 1 → 4 B,
2 → 8 B, 3 → 16 B, 4 → enc-only, 5 → enc + MIC32 (Thread 1.4 mandate).
Encoded in `efr32_mic_size()`.

Key-source size (per `[802154-2024] §9.4.2.3 Table 9-7`): 0 → 0 B, 1 → 4 B,
2 → 8 B. Encoded in `efr32_key_source_size()`.

---

## 8. CSL receiver and EM2

`IEEE802154_CONFIG_EXPECTED_RX_TIME` delivers the anchor in nanoseconds.
`IEEE802154_CONFIG_RX_SLOT` opens a single scheduled window via
`sl_rail_start_scheduled_rx()`. The init sequence makes this work in EM2:

1. `sl_rail_config_sleep()` with `TIMERSYNC_ENABLED` — unconditional,
   because CSL needs timer-sync even without sleep.
2. `sl_rail_init_power_manager()` — gated on `CONFIG_PM`. Idempotent in
   the prebuilt RAIL library, so a DMP build with both 802.15.4 and BLE
   calling it is safe by construction.
3. Sleep Timer + Power Manager set up RTC/PRS/compare handoff under the
   hood. The Power Manager sees the future scheduler task and votes for
   EM2 until `window_start − wakeup_process_time_us`.
4. On wake, RAIL resyncs HFXO (~0.5 µs worst case) and arms the RX
   window. After the window, `RX_SCHEDULED_RX_END` / `_MISSED` yield the
   radio, releasing the vote so the system can drop to EM2 again.

`efr32_pm_action`:

- `SUSPEND` — if `(state & RX_ACTIVE) == RX_ACTIVE` (mid-frame), return
  `-EBUSY`; `RX_ACTIVE` is the *composite* enum value (`RX | ACTIVE = 3`),
  so a plain `&` test would falsely match idle listening
  (`state == RX == 2`). Otherwise `sl_rail_idle(SL_RAIL_IDLE, true)` +
  `sl_rail_yield_radio()`.
- `RESUME` — no-op. The next `rx_slot` / `start` from OpenThread restarts
  RX, if that is wanted. Forcing RX on here would leak an idle vote for
  an SSED between windows.

`efr32_get_sch_acc()` returns `CONFIG_IEEE802154_EFR32_XTAL_ACCURACY`
(default 40 PPM for EFR32MG24's 38.4 MHz HFXO). SED deployments bump this
to include LFXO ppm: LFXO is the clock that runs while HFXO is off in
EM2, so its drift accumulates in the CSL phase budget.

### 8.1 `sl_rail_scheduled_rx_config_t` — open differences from SiLabs reference

Two fields in our `sl_rail_scheduled_rx_config_t` differ from the SiLabs
OpenThread platform abstraction and are worth a controlled experiment:

- `end_mode`: we use `SL_RAIL_TIME_ABSOLUTE` with `end = start + duration`;
  SiLabs uses `SL_RAIL_TIME_DELAY` with `end = duration`. Both work;
  DELAY is simpler.
- `hard_window_end`: we use `1` (abort in-flight reception at window
  end); SiLabs uses `0` (let an in-progress packet complete). The
  lenient SiLabs choice is plausibly correct for CSL — the echo reply
  often lands right at the window edge — but flipping this is a real
  behavioral change that wants its own commit + data, not a drive-by.

Past-time `start_us` is already handled by the pre-skip in the
driver (`rx_slot_sched_skip` counter); these two flags are a separate
question about behavior *inside* a window that was accepted.

---

## 9. RAIL initialisation, in one place

`efr32_rail_init()` encodes a small set of constraints that are easy to
miss in isolation:

- `sl_rail_util_pa_init()` **and** `sl_rail_config_tx_power()` are both
  required. The first loads PA curves; the second installs the
  configuration on the handle. Skipping the second yields
  `RAIL_ASSERT_SEQ_INVALID_PA_SELECTED` (error 64) from an IRQ on the
  first TX. This is the symptom most easily mistaken for a board-bringup
  bug.
- `sl_rail_ieee802154_config_e_options()` must run after
  `sl_rail_ieee802154_config_2p4_ghz_radio()`. The mask argument should be
  exactly `GB868 | ENH_ACK | IMPLICIT_BROADCAST`; passing
  `..._E_OPTIONS_ALL` clears bits RAIL set internally during
  `sl_rail_ieee802154_init` and returns 0x21. `ENH_ACK` must be set
  explicitly — without it RAIL silently rejects every Frame Version 2
  packet and Thread 1.2+ never works.
- `enable_early_frame_pending(true)` and `enable_data_frame_pending(true)`
  are both required for Thread 1.2: together they cause
  `DATA_REQUEST_COMMAND` to fire after the address fields on data frames
  (not after the MAC command byte, and not only for MAC command frames).
- `sl_rail_ieee802154_init()` installs the auto-ACK configuration. Do
  not additionally call `sl_rail_config_auto_ack()` — that path is for
  non-802.15.4 protocols.
- Calibration: `CAL_NEEDED` is recorded as a flag in the ISR; the actual
  `sl_rail_calibrate()` call runs in the RX thread once the radio is not
  in `RX_ACTIVE`.

---

## 10. Source match and `net_pkt_ieee802154_ack_fpb`

The frame-pending propagation path has three stages and all three are
required:

1. Software source-match table (`struct efr32_src_match`), mutated from
   thread context with a short `irq_lock()` because the ISR reads it.
2. ISR decision in `DATA_REQUEST_COMMAND` — Imm-ACK calls
   `toggle_frame_pending()`; Enh-ACK sets the FP bit in the FCF the driver
   writes.
3. Propagate the decision to the net_pkt — the Zephyr OpenThread
   platform reads `net_pkt_ieee802154_ack_fpb(pkt)` from the data-poll's
   net_pkt to decide whether to submit an indirect TX. The on-air FP bit
   alone is invisible to OpenThread. The driver stores the ISR's
   decision in `data->last_ack_fpb`, pairs it with the incoming packet on
   `RX_PACKET_RECEIVED`, and sets it on the net_pkt before
   `net_recv_data`.

If step 3 is missing, the radio ACKs polls with FP=1 on air but
OpenThread never schedules the follow-up frame — it thinks the ACK
carried FP=0.

---

## 11. SED gating

Three Kconfig symbols control sleepy-end-device behaviour, each on its
own concern:

- `CONFIG_PM` — calls `sl_rail_init_power_manager()` in `efr32_rail_init`.
  Matches the Silicon Labs BLE HCI driver's gate. Idempotent for DMP.
- `CONFIG_PM_DEVICE` — wires `efr32_pm_action` and `PM_DEVICE_DT_INST_DEFINE`.
- `CONFIG_IEEE802154_EFR32_SED` — a *role marker*, not a code gate. It
  does not appear in any `#ifdef`. It carries the LFXO devicetree
  precondition and `select`s `PM` and `PM_DEVICE`. A console-less FTD
  with `CONFIG_PM=y` is equally entitled to RAIL's power-manager
  integration.
