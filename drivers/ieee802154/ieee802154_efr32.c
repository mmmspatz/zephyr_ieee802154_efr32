/*
 * Copyright (c) 2026 LeafLabs, LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * IEEE 802.15.4 radio driver for Silicon Labs EFR32 series SoCs.
 * Wraps the RAIL (Radio Abstraction Interface Layer) library.
 */

#define DT_DRV_COMPAT silabs_efr32_ieee802154

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ieee802154_efr32, CONFIG_IEEE802154_DRIVER_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/net/ieee802154_ie.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

#if defined(CONFIG_NET_L2_OPENTHREAD)
#include <zephyr/net/openthread.h>
#endif

#if defined(CONFIG_PM_DEVICE)
#include <zephyr/pm/device.h>
#endif

#include <sl_rail.h>
#include <sl_rail_ieee802154.h>
/* sl_rail_util_pa_conversions_efr32.h references a RAIL 2.x type that is
 * not defined under sl_rail.h, so including it alongside sl_rail.h yields
 * conflicting-type errors. Forward-declare the two functions we need.
 */
extern void sl_rail_util_pa_init(void);
extern sl_rail_tx_power_config_t *sl_rail_util_pa_get_tx_power_config_2p4ghz(void);

#include <sl_rail_util_pa_config.h>

#include <em_system.h>

#include "ieee802154_efr32.h"

/* ---------- Static data ---------- */

static struct efr32_802154_data efr32_data;

/* RAIL TX FIFO — must persist for lifetime of RAIL */
static SL_RAIL_DECLARE_FIFO_BUFFER(efr32_tx_fifo, CONFIG_IEEE802154_EFR32_TX_FIFO_SIZE);

/* TX linearization buffer — static because TX runs on the ot_radio_workq
 * (small stack) and is serialized through the workqueue. */
static uint8_t efr32_tx_buf[IEEE802154_MAX_PHY_PACKET_SIZE];

/* RAIL RX FIFO */
static SL_RAIL_DECLARE_FIFO_BUFFER(efr32_rx_fifo_buf, CONFIG_IEEE802154_EFR32_RX_FIFO_SIZE);

/* RAIL RX packet queue */
static sl_rail_packet_queue_entry_t
	efr32_rx_packet_queue[CONFIG_IEEE802154_EFR32_RX_PACKET_QUEUE_SIZE];

/* RX buffer pool */
static struct efr32_rx_entry efr32_rx_entries[CONFIG_IEEE802154_EFR32_RX_BUF_COUNT];

/* RX thread stack */
static K_KERNEL_STACK_DEFINE(efr32_rx_stack, CONFIG_IEEE802154_EFR32_RX_STACK_SIZE);

/* ---------- Forward declarations ---------- */

static void efr32_rail_event_cb(sl_rail_handle_t rail_handle, sl_rail_events_t events);
static void efr32_rx_thread(void *p1, void *p2, void *p3);
static bool efr32_src_match_lookup(const struct efr32_src_match *sm,
				   const sl_rail_ieee802154_address_t *addr);

/* ---------- Helpers ---------- */

static inline const struct device *efr32_get_device(void)
{
	return DEVICE_DT_INST_GET(0);
}

/* ---------- RAIL initialization ---------- */

/* RAIL assertion handler — log and panic instead of silent hang */
void sl_railcb_assert_failed(sl_rail_handle_t rail_handle, sl_rail_assert_error_codes_t error_code,
			     int line)
{
	LOG_ERR("RAIL ASSERT: error=%d line=%d", error_code, line);
	k_panic();
}

static int efr32_rail_init(struct efr32_802154_data *data)
{
	sl_rail_status_t status;

	/* Step 1: sl_rail_init() */
	sl_rail_config_t rail_cfg = {
		.events_callback = efr32_rail_event_cb,
		.rx_packet_queue_entries = CONFIG_IEEE802154_EFR32_RX_PACKET_QUEUE_SIZE,
		.rx_fifo_bytes = CONFIG_IEEE802154_EFR32_RX_FIFO_SIZE,
		.tx_fifo_bytes = CONFIG_IEEE802154_EFR32_TX_FIFO_SIZE,
		.tx_fifo_init_bytes = 0,
		.p_rx_packet_queue = efr32_rx_packet_queue,
		.p_rx_fifo_buffer = efr32_rx_fifo_buf,
		.p_tx_fifo_buffer = efr32_tx_fifo,
	};

	sl_rail_handle_t handle = SL_RAIL_EFR32_HANDLE;

	/* Must run before sl_rail_init() for Series 3; no-op on Series 2. */
	status = sl_rail_copy_device_info(handle);
	if (status != SL_STATUS_OK) {
		LOG_ERR("sl_rail_copy_device_info failed: 0x%x", status);
		return -EIO;
	}

	status = sl_rail_init(&handle, &rail_cfg, NULL);
	if (status != SL_STATUS_OK) {
		LOG_ERR("sl_rail_init failed: 0x%x", status);
		return -EIO;
	}
	data->rail_handle = handle;

	/* Step 2: PA init (config is device-tree-sourced via sl_rail_util_pa_config.h) */
	sl_rail_util_pa_init();

	sl_rail_tx_power_config_t *pa_cfg = sl_rail_util_pa_get_tx_power_config_2p4ghz();
	if (pa_cfg != NULL) {
		status = sl_rail_config_tx_power(handle, pa_cfg);
		if (status != SL_STATUS_OK) {
			LOG_ERR("sl_rail_config_tx_power failed: 0x%x", status);
			return -EIO;
		}
	}

	/* Initial TX power from DT (deci-dBm) */
	status = sl_rail_set_tx_power_dbm(handle,
					  (sl_rail_tx_power_t)SL_RAIL_UTIL_PA_POWER_DECI_DBM);
	if (status != SL_STATUS_OK) {
		LOG_WRN("sl_rail_set_tx_power_dbm(%d) failed: 0x%x", SL_RAIL_UTIL_PA_POWER_DECI_DBM,
			status);
	}

	/* Step 3: Enable all calibrations */
	status = sl_rail_config_cal(handle, SL_RAIL_CAL_ALL);
	if (status != SL_STATUS_OK) {
		LOG_WRN("sl_rail_config_cal: 0x%x", status);
	}

	/* Step 4: PTI protocol label for Network Analyzer */
	sl_rail_set_pti_protocol(handle, SL_RAIL_PTI_PROTOCOL_802154);

	/*
	 * Step 5: IEEE 802.15.4 mode init. Struct shape and most values
	 * mirror the SiLabs OpenThread platform's radio.c; sl_rail_ieee802154.h
	 * is the docstring source for the defaults and the ack_timeout_us
	 * derivation.
	 *
	 *   ack_timeout_us = 672 — IEEE 802.15.4-2024 macAckWaitDuration is
	 *     54 symbols at 2.4 GHz O-QPSK. RAIL only times sync-word
	 *     detect, so subtract the ACK PHR (2 sym) + ACK payload
	 *     (10 sym): (54 - 12) * 16 µs/sym = 672 µs.
	 *   rx_to_tx = 256 — Thread 1.2+ value ("accommodate enhanced
	 *     ACKs"): more than the 192 µs / 12-symbol aTurnaroundTime so
	 *     the ISR has time to build the IE + CCM* an Enh-ACK requires.
	 *     Must equal RX_TO_TX_US (used in the CSL phase formula below).
	 *   idle_to_rx = idle_to_tx = 100 — RAIL example default; radio
	 *     warmup from idle, not spec-driven.
	 *   tx_to_rx = 246 — local value; no recorded provenance. The
	 *     SiLabs OpenThread platform uses 192 - 10 = 182, the RAIL
	 *     example uses 192 (one 12-symbol aTurnaroundTime). Kept as-is
	 *     until a regression motivates revisiting.
	 *   rx/tx_transitions = RX, frames_mask = ACCEPT_STANDARD_FRAMES,
	 *   promiscuous_mode/is_pan_coordinator/
	 *   default_frame_pending_in_outgoing_acks = false — RAIL example
	 *     defaults; promiscuous, PAN-coord, and frame-pending state
	 *     are reconfigured at runtime via
	 *     sl_rail_ieee802154_set_promiscuous_mode() etc.
	 */
	sl_rail_ieee802154_config_t ieee_cfg = {
		.p_addresses = NULL,
		.ack_config =
			{
				.enable = true,
				.ack_timeout_us = 672,
				.rx_transitions =
					{
						.success = SL_RAIL_RF_STATE_RX,
						.error = SL_RAIL_RF_STATE_RX,
					},
				.tx_transitions =
					{
						.success = SL_RAIL_RF_STATE_RX,
						.error = SL_RAIL_RF_STATE_RX,
					},
			},
		.timings =
			{
				.idle_to_rx = 100,
				.tx_to_rx = 246,
				.idle_to_tx = 100,
				.rx_to_tx = 256,
			},
		.frames_mask = SL_RAIL_IEEE802154_ACCEPT_STANDARD_FRAMES,
		.promiscuous_mode = false,
		.is_pan_coordinator = false,
		.default_frame_pending_in_outgoing_acks = false,
	};

	status = sl_rail_ieee802154_init(handle, &ieee_cfg);
	if (status != SL_STATUS_OK) {
		LOG_ERR("sl_rail_ieee802154_init failed: 0x%x", status);
		return -EIO;
	}

	/* Step 6+7: Thread 1.2 frame pending features */
	sl_rail_ieee802154_enable_early_frame_pending(handle, true);
	sl_rail_ieee802154_enable_data_frame_pending(handle, true);

	/* Map RAIL's raw correlator LQI onto an RSSI-derived 0..255 range.
	 * On EFR32xG24 the demodulator's chip-correlation peak saturates at
	 * 0xFF for any cleanly-synced frame, so the field is effectively
	 * binary without this conversion (see sl_rail_ieee802154.h:1789).
	 */
	sl_rail_convert_lqi(handle, sl_rail_ieee802154_convert_rssi_to_lqi);

	/* Step 8: TX FIFO — already configured via sl_rail_config_t */

	/* Step 9: Enable multi-timer (needed for ED scan) */
	sl_rail_config_multi_timer(handle, true);

	/* Step 10: Configure 2.4 GHz PHY (replaces sl_rail_config_channels) */
	status = sl_rail_ieee802154_config_2p4_ghz_radio(handle);
	if (status != SL_STATUS_OK) {
		LOG_ERR("config_2p4_ghz_radio failed: 0x%x", status);
		return -EIO;
	}

	/* Step 11: E-options — MUST be after config_2p4_ghz_radio (RAIL bug).
	 * Only set the specific bits we want — do NOT use E_OPTIONS_ALL as mask,
	 * that clears bits RAIL set internally and returns error 0x21.
	 */
	sl_rail_ieee802154_e_options_t e_opts_mask = SL_RAIL_IEEE802154_E_OPTION_GB868 |
						     SL_RAIL_IEEE802154_E_OPTION_ENH_ACK |
						     SL_RAIL_IEEE802154_E_OPTION_IMPLICIT_BROADCAST;

	status = sl_rail_ieee802154_config_e_options(handle, e_opts_mask, e_opts_mask);
	if (status != SL_STATUS_OK) {
		LOG_WRN("config_e_options: 0x%x", status);
	}

	/* Step 12: Enable RAIL events */
	sl_rail_events_t event_mask =
		SL_RAIL_EVENT_RX_PACKET_RECEIVED | SL_RAIL_EVENT_TX_PACKET_SENT |
		SL_RAIL_EVENT_TX_CHANNEL_BUSY | SL_RAIL_EVENT_TX_ABORTED |
		SL_RAIL_EVENT_TX_UNDERFLOW | SL_RAIL_EVENT_TX_BLOCKED |
		SL_RAIL_EVENT_RX_ACK_TIMEOUT | SL_RAIL_EVENT_RX_FRAME_ERROR |
		SL_RAIL_EVENT_RX_ADDRESS_FILTERED | SL_RAIL_EVENT_CAL_NEEDED |
		SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND | SL_RAIL_EVENT_TX_STARTED |
		SL_RAIL_EVENT_TXACK_PACKET_SENT | SL_RAIL_EVENT_TXACK_ABORTED |
		SL_RAIL_EVENT_TXACK_BLOCKED | SL_RAIL_EVENT_TXACK_UNDERFLOW |
		/* DMP scheduling — radio taken/returned by scheduler */
		SL_RAIL_EVENT_CONFIG_UNSCHEDULED | SL_RAIL_EVENT_CONFIG_SCHEDULED |
		/* DMP scheduler errors — task rejected or preempted */
		SL_RAIL_EVENT_SCHEDULER_STATUS |
		/* CSL — scheduled RX/TX */
		SL_RAIL_EVENT_RX_SCHEDULED_RX_END | SL_RAIL_EVENT_RX_SCHEDULED_RX_MISSED |
		SL_RAIL_EVENT_TX_SCHEDULED_TX_MISSED;

	sl_rail_config_events(handle, event_mask, event_mask);

	/* Step 13: Timer sync for sleep — prerequisite for CSL/SED */
	sl_rail_timer_sync_config_t tsync = SL_RAIL_TIMER_SYNC_DEFAULT;

	status = sl_rail_config_sleep(handle, &tsync);
	if (status != SL_STATUS_OK) {
		LOG_WRN("sl_rail_config_sleep: 0x%x", status);
	}

	if (IS_ENABLED(CONFIG_PM)) {
		/* Register RAIL with the Silicon Labs power manager so it votes
		 * against EM2 while the radio is active and allows EM2 once it
		 * has yielded. The prebuilt RAIL library guards internally —
		 * the first caller runs the body and subscribes the
		 * EM-transition callback; every subsequent caller returns
		 * SL_STATUS_OK and no-ops. Safe to call alongside the Silicon
		 * Labs BLE HCI driver in a DMP build.
		 */
		status = sl_rail_init_power_manager();
		if (status != SL_STATUS_OK) {
			LOG_WRN("sl_rail_init_power_manager: 0x%x", status);
		}
	}

	/* Seed get_time() base */
	data->last_rail_time = sl_rail_get_time(data->rail_handle);

	LOG_INF("RAIL initialized, handle=%p", data->rail_handle);
	return 0;
}

/* ---------- 802.15.4 FCF bit definitions ---------- */

#define FCF_FRAME_TYPE_MASK    0x0007
#define FCF_FRAME_TYPE_ACK     0x0002
#define FCF_FRAME_TYPE_CMD     0x0003
#define FCF_SECURITY_ENABLED   BIT(3)
#define FCF_FRAME_PENDING      BIT(4)
#define FCF_ACK_REQUEST        BIT(5)
#define FCF_PAN_ID_COMPRESSION BIT(6)
#define FCF_SEQ_NUM_SUPPRESS   BIT(8)
#define FCF_IE_PRESENT         BIT(9)
#define FCF_DST_ADDR_MASK      (0x03 << 10)
#define FCF_DST_ADDR_SHIFT     10
#define FCF_FRAME_VER_MASK     (0x03 << 12)
#define FCF_FRAME_VER_SHIFT    12
#define FCF_SRC_ADDR_MASK      (0x03 << 14)
#define FCF_SRC_ADDR_SHIFT     14

#define FCF_ADDR_NONE     0x00
#define FCF_ADDR_SHORT    0x02
#define FCF_ADDR_EXTENDED 0x03

#define FCF_FRAME_VER_2015 0x02

/* PHR size for 2.4 GHz (1 byte) */
#define PHR_SIZE 1

/* CSL timing constants (2.4 GHz O-QPSK) */
#define NSEC_PER_TEN_SYMBOLS (10 * IEEE802154_PHY_OQPSK_780_TO_2450MHZ_SYMBOL_PERIOD_NS)
#define USEC_PER_TEN_SYMBOLS 160 /* 10 * 16 µs */
/* One symbol-byte on air = 32 µs at 2.4 GHz O-QPSK. */
#define BYTE_ONAIR_US        32U
/* PHR transmission time. */
#define PHR_ONAIR_US         (PHR_SIZE * BYTE_ONAIR_US)
/* SHR = 4-byte preamble + 1-byte SFD = 5 bytes × 32 µs/byte = 160 µs. */
#define SHR_SIZE_BYTES       5U
#define SHR_DURATION_US      (SHR_SIZE_BYTES * BYTE_ONAIR_US)
/* RAIL RX→TX turnaround used by the SiLabs radio.c ackShrDoneTime formula. */
#define RX_TO_TX_US          256U
/* CCA warmup budget subtracted from scheduled-TX .when (SiLabs
 * CSL_CSMA_BACKOFF_TIME_IN_US).
 */
#define CSL_CSMA_BACKOFF_US  150U
/* Delay from otPlatRadioTransmit call to scheduled SHR anchor for CSL-child unscheduled TX. */
#define SCHEDULE_TX_DELAY_US 3000U
/* ED scan RSSI sample cadence: 8 symbols at 62.5 ksym/s. Matches the
 * SiLabs OpenThread platform's kEnergyScanRssiSampleInterval.
 */
#define ED_SCAN_SAMPLE_US    128U

/* ---------- Header IE scanning helpers ---------- */

/*
 * Decode the 2-byte header IE descriptor at psdu[pos]. Sets *id (element ID,
 * 7 bits), *len (IE content length, 7 bits), *type (0=header IE, 1=other).
 * Returns true iff the full IE fits within [pos, region_end).
 * Advance past an IE: pos += 2 + *len.
 */
static bool efr32_decode_ie_header(const uint8_t *psdu, uint16_t pos, uint16_t region_end,
				   uint8_t *id, uint8_t *len, bool *type)
{
	if (pos + 2 > region_end) {
		return false;
	}
	uint16_t hdr = psdu[pos] | ((uint16_t)psdu[pos + 1] << 8);

	*len = hdr & 0x007F;
	*id = (hdr >> 7) & 0x7F;
	*type = (hdr >> 15) & 1;
	return (uint32_t)pos + 2 + *len <= region_end;
}

/*
 * Return the byte offset of the first byte after all header IEs in
 * [ie_start, region_end). Per IEEE 802.15.4-2024 §9.3.3, header IEs are
 * authenticated but not encrypted; this locates the a/m-data boundary.
 *
 * Stops at: type=1 (payload IE), HT1/HT2 (after advancing past it),
 * or decode failure (returns region_end).
 *
 * Cross-reference: OT core's Mac::Frame::FindPayloadIndex() does the
 * same header-IE walk; it additionally advances past the FV0/FV1
 * command-ID byte (we handle that in efr32_process_tx_security
 * instead).
 */
static uint16_t efr32_header_ies_end(const uint8_t *psdu, uint16_t ie_start, uint16_t region_end)
{
	uint16_t pos = ie_start;
	uint8_t ie_id, ie_len;
	bool ie_type;

	while (efr32_decode_ie_header(psdu, pos, region_end, &ie_id, &ie_len, &ie_type)) {
		if (ie_type) {
			return pos;
		}
		pos += 2 + ie_len;
		if (ie_id == IEEE802154_HEADER_IE_ELEMENT_ID_HEADER_TERMINATION_1 ||
		    ie_id == IEEE802154_HEADER_IE_ELEMENT_ID_HEADER_TERMINATION_2) {
			return pos;
		}
	}
	return region_end;
}

/* ---------- IEEE 802.15.4 Auxiliary Security Header constants ---------- */

#include "sli_protocol_crypto.h"

/* Security Control field bits */
#define SEC_LEVEL_MASK        0x07
#define SEC_KEY_ID_MODE_MASK  0x18
#define SEC_KEY_ID_MODE_SHIFT 3

/* Security levels */
#define SEC_LEVEL_NONE       0
#define SEC_LEVEL_MIC32      1
#define SEC_LEVEL_MIC64      2
#define SEC_LEVEL_MIC128     3
#define SEC_LEVEL_ENC        4
#define SEC_LEVEL_ENC_MIC32  5
#define SEC_LEVEL_ENC_MIC64  6
#define SEC_LEVEL_ENC_MIC128 7

/* Key ID modes */
#define SEC_KEY_ID_MODE_0 0
#define SEC_KEY_ID_MODE_1 1
#define SEC_KEY_ID_MODE_2 2
#define SEC_KEY_ID_MODE_3 3

/* Sizes */
#define SEC_CTRL_SIZE      1
#define SEC_FRAME_CTR_SIZE 4
#define CCM_NONCE_SIZE     13
#define AES_BLOCK_SIZE     16
#define AES_KEY_BITS       128

/*
 * Return MIC size for a given security level per
 * IEEE 802.15.4-2024 §9.4.2.2 Table 9-6.
 *   Levels 0/4 have mic_len == 0 (0: no security; 4: ENC only, deprecated).
 */
static uint8_t efr32_mic_size(uint8_t sec_level)
{
	static const uint8_t mic_sizes[] = {0, 4, 8, 16, 0, 4, 8, 16};

	return (sec_level <= SEC_LEVEL_ENC_MIC128) ? mic_sizes[sec_level] : 0;
}

/*
 * Return key source size for a given key ID mode per
 * IEEE 802.15.4-2024 §9.4.2.3 Table 9-7. Mode 0: implicit (0). Mode 1:
 * none (0). Mode 2: 4. Mode 3: 8. Thread 1.4.0 §7.2.3 mandates Mode 1.
 */
static uint8_t efr32_key_source_size(uint8_t key_id_mode)
{
	static const uint8_t sizes[] = {0, 0, 4, 8};

	return (key_id_mode <= SEC_KEY_ID_MODE_3) ? sizes[key_id_mode] : 0;
}

/*
 * Parse the auxiliary security header from a raw PSDU.
 * Returns the offset to the end of the aux header (start of payload),
 * or 0 on failure. Populates output fields.
 */
struct efr32_aux_sec_hdr {
	uint8_t sec_level;
	uint8_t key_id_mode;
	uint8_t key_id;          /* Only valid for Key ID Mode 1 */
	uint16_t sec_hdr_offset; /* Offset to Security Control byte in PSDU */
	uint16_t fc_offset;      /* Offset to Frame Counter field in PSDU */
	uint16_t hdr_len;        /* Total MAC header length (end of aux hdr) */
	uint16_t payload_len;    /* Payload length (between header and MIC) */
	uint8_t mic_len;         /* MIC/tag length */
};

/*
 * Two byte-orders for an 802.15.4 extended address — not interchangeable:
 *
 *   on-air / wire order — IEEE 802.15.4-2024 §4, rightmost-octet-first.
 *     The form Zephyr's ieee802154_radio API and RAIL's address-filter
 *     ABI both use, and the form in RX'd PSDU bytes.
 *   canonical / MSO-first — the form IEEE 802.15.4-2024 §9.3.2.1
 *     requires as the CCM* nonce source address. We store this in
 *     `data->mac`.
 *
 * The filter callback byte-reverses the on-air form into data->mac so
 * the nonce construction stays correct after OT reconfigures the
 * EUI-64 (e.g. NVS restore). Keep the two forms textually distinct at
 * every boundary; a memcpy hides the mismatch until CCM* fails on air.
 */
static inline void efr32_ext_addr_on_air_to_canonical(uint8_t dst[8], const uint8_t src[8])
{
	for (int i = 0; i < 8; i++) {
		dst[i] = src[7 - i];
	}
}

/*
 * PAN ID presence per IEEE 802.15.4-2024 Table 7-2 (same layout as the
 * 2015 edition). FV2 ext/ext is the compression row: Src PAN is never
 * present; Dst PAN iff !pan_comp (rows 7/8). Other FV2 "both present"
 * cases: Dst PAN present, Src PAN iff !pan_comp. FV0/FV1: Dst PAN iff
 * DstAddr, Src PAN iff SrcAddr and !pan_comp. Rows 9–14 (one addr
 * present, one absent) are covered by the else-if branches.
 *
 * Cross-reference: OT core's Mac::Frame::IsDstPanIdPresent() and
 * IsSrcPanIdPresent() implement the same truth table against OT's
 * own frame-version constants.
 */
static void efr32_pan_presence(uint16_t frame_ver, uint8_t dst_mode, uint8_t src_mode,
			       bool pan_comp, bool *dst_present, bool *src_present)
{
	*dst_present = false;
	*src_present = false;

	if (frame_ver < FCF_FRAME_VER_2015) {
		*dst_present = (dst_mode != FCF_ADDR_NONE);
		*src_present = (src_mode != FCF_ADDR_NONE) && !pan_comp;
		return;
	}

	if (dst_mode == FCF_ADDR_EXTENDED && src_mode == FCF_ADDR_EXTENDED) {
		*dst_present = !pan_comp;
	} else if (dst_mode != FCF_ADDR_NONE && src_mode != FCF_ADDR_NONE) {
		*dst_present = true;
		*src_present = !pan_comp;
	} else if (dst_mode != FCF_ADDR_NONE) {
		*dst_present = !pan_comp;
	} else if (src_mode != FCF_ADDR_NONE) {
		*src_present = !pan_comp;
	} else {
		*dst_present = pan_comp;
	}
}

/*
 * Parse frame to extract security header info.
 * psdu points to the first byte of the PSDU (FCF).
 * psdu_len is total PSDU length (without FCS).
 *
 * Layout per IEEE 802.15.4-2024 §9.4. Byte layouts cross-checked
 * against OT core's Mac::Frame::GetSecurityControlField() etc.
 */
static bool efr32_parse_aux_sec(const uint8_t *psdu, uint16_t psdu_len,
				struct efr32_aux_sec_hdr *out)
{
	if (psdu_len < 2) {
		return false;
	}

	uint16_t fcf = psdu[0] | ((uint16_t)psdu[1] << 8);

	/* Must have Security Enabled */
	if (!(fcf & FCF_SECURITY_ENABLED)) {
		return false;
	}

	/* Skip FCF (2 bytes) */
	uint16_t pos = 2;

	/* Sequence number (unless suppressed in FV2) */
	uint16_t frame_ver = (fcf & FCF_FRAME_VER_MASK) >> FCF_FRAME_VER_SHIFT;
	bool seq_suppress = (frame_ver == FCF_FRAME_VER_2015) && (fcf & FCF_SEQ_NUM_SUPPRESS);

	if (!seq_suppress) {
		pos += 1; /* SeqNum */
	}

	/* Address fields — use same PAN/addr logic as efr32_build_enh_ack */
	uint8_t dst_mode = (fcf & FCF_DST_ADDR_MASK) >> FCF_DST_ADDR_SHIFT;
	uint8_t src_mode = (fcf & FCF_SRC_ADDR_MASK) >> FCF_SRC_ADDR_SHIFT;
	bool pan_comp = (fcf & FCF_PAN_ID_COMPRESSION) != 0;

	bool dst_pan_present;
	bool src_pan_present;

	efr32_pan_presence(frame_ver, dst_mode, src_mode, pan_comp, &dst_pan_present,
			   &src_pan_present);

	if (dst_pan_present) {
		pos += 2;
	}
	uint8_t dst_len = (dst_mode == FCF_ADDR_SHORT)      ? 2
			  : (dst_mode == FCF_ADDR_EXTENDED) ? 8
							    : 0;
	pos += dst_len;

	if (src_pan_present) {
		pos += 2;
	}
	uint8_t src_len = (src_mode == FCF_ADDR_SHORT)      ? 2
			  : (src_mode == FCF_ADDR_EXTENDED) ? 8
							    : 0;
	pos += src_len;

	/* Now at Security Control byte */
	if (pos >= psdu_len) {
		return false;
	}

	out->sec_hdr_offset = pos;
	uint8_t sec_ctrl = psdu[pos];

	out->sec_level = sec_ctrl & SEC_LEVEL_MASK;
	out->key_id_mode = (sec_ctrl & SEC_KEY_ID_MODE_MASK) >> SEC_KEY_ID_MODE_SHIFT;
	out->mic_len = efr32_mic_size(out->sec_level);

	/* Frame Counter at pos+1 */
	out->fc_offset = pos + SEC_CTRL_SIZE;

	/* Key source + key index */
	uint8_t key_src_len = efr32_key_source_size(out->key_id_mode);
	uint16_t key_id_offset = pos + SEC_CTRL_SIZE + SEC_FRAME_CTR_SIZE + key_src_len;

	if (out->key_id_mode == SEC_KEY_ID_MODE_1) {
		if (key_id_offset >= psdu_len) {
			return false;
		}
		out->key_id = psdu[key_id_offset];
	} else {
		out->key_id = 0;
	}

	/* Header ends after aux security header */
	uint16_t aux_hdr_len = SEC_CTRL_SIZE + SEC_FRAME_CTR_SIZE + key_src_len;
	if (out->key_id_mode != SEC_KEY_ID_MODE_0) {
		aux_hdr_len += 1; /* Key Index */
	}
	out->hdr_len = pos + aux_hdr_len;

	/* Payload = total - header - MIC (FCS not included in psdu_len) */
	if (psdu_len < out->hdr_len + out->mic_len) {
		return false;
	}
	out->payload_len = psdu_len - out->hdr_len - out->mic_len;

	return true;
}

/*
 * Construct a CCM* nonce per IEEE 802.15.4-2024 §9.3.2.1:
 * nonce = ext_addr (8 BE) || frame_counter (4 BE) || security_level (1)
 *
 * The ext_addr here is the source address in canonical (MSO-first) order;
 * see the efr32_ext_addr_on_air_to_canonical() contract above.
 *
 * Cross-references: the SiLabs OpenThread platform's
 * efr32PlatProcessTransmitAesCcm() (ieee802154-packet-utils.cpp)
 * builds the same 13-byte block. OT core's Mac::Frame::GenerateNonce()
 * is the byte-layout source of truth.
 */
static void efr32_ccm_nonce(const uint8_t *ext_addr, uint32_t frame_counter, uint8_t sec_level,
			    uint8_t nonce[CCM_NONCE_SIZE])
{
	memcpy(nonce, ext_addr, 8);
	nonce[8] = (frame_counter >> 24) & 0xFF;
	nonce[9] = (frame_counter >> 16) & 0xFF;
	nonce[10] = (frame_counter >> 8) & 0xFF;
	nonce[11] = frame_counter & 0xFF;
	nonce[12] = sec_level;
}

/*
 * AES-CCM* encrypt/authenticate in-place.
 *
 * hdr:     pointer to authenticated-only data (MAC header)
 * hdr_len: length of authenticated-only data
 * payload: pointer to plaintext (encrypted in-place)
 * pay_len: plaintext length
 * tag:     pointer to MIC output location
 * tag_len: MIC length (0/4/8/16)
 * key:     16-byte AES key
 * nonce:   13-byte CCM* nonce
 *
 * sli_aes_crypt_ecb_radio() drives RADIOAES, a separate AES accelerator
 * from the main-CPU SLAES used by mbedTLS/PSA. The two can run
 * concurrently — RADIOAES during the ISR Enhanced-ACK window, SLAES
 * during main-thread OT crypto. The Zephyr OT crypto terminator
 * (psa_cipher_encrypt per 16-byte block) does not meet the ~500 µs
 * Enhanced-ACK deadline; see ARCHITECTURE.md §7.
 *
 * Cross-references: the SiLabs OpenThread platform takes the same
 * register-level path in ieee802154-packet-utils.cpp
 * (efr32PlatProcessTransmitAesCcm). OT core's Crypto::AesCcm is the
 * byte-layout source of truth.
 */
static int efr32_ccm_encrypt(const uint8_t *hdr, uint16_t hdr_len, uint8_t *payload,
			     uint16_t pay_len, uint8_t *tag, uint8_t tag_len, const uint8_t *key,
			     const uint8_t *nonce)
{
	uint8_t block[AES_BLOCK_SIZE]; /* CBC-MAC accumulator */
	uint8_t ctr[AES_BLOCK_SIZE];   /* Counter block */
	uint8_t ctr_pad[AES_BLOCK_SIZE];
	uint8_t L;
	uint32_t len;
	uint16_t i;

	/* Compute L (length field size). RFC 3610 §2.2: nonce_len + L = 15
	 * (16-byte block minus 1 flags byte), and 802.15.4-2024 §9.4.3.2
	 * pins nonce_len = 13, so L is 2.
	 */
	L = 2;
	for (len = pay_len; len >> (8 * L); L++) {
		/* grow L until it can hold pay_len */
	}
	if (L < (15 - CCM_NONCE_SIZE)) {
		L = 15 - CCM_NONCE_SIZE;
	}

	/* B0 block: flags || nonce || length */
	memset(block, 0, AES_BLOCK_SIZE);
	block[0] = (uint8_t)(((hdr_len > 0) ? 0x40 : 0) |
			     (((tag_len > 0 ? tag_len - 2 : 0) >> 1) << 3) | (L - 1));
	memcpy(&block[1], nonce, CCM_NONCE_SIZE);

	/* Write payload length in last L bytes (big-endian) */
	len = pay_len;
	for (i = AES_BLOCK_SIZE - 1; i > CCM_NONCE_SIZE; i--) {
		block[i] = len & 0xFF;
		len >>= 8;
	}

	/* Encrypt B0 */
	sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, block, block);

	/* Process header (authenticated data) length encoding + data */
	uint16_t block_pos = 0;

	/* RFC 3610 §2.2 a-data length encoding: < 0xFF00 → 2-byte big-endian;
	 * ≥ 0xFF00 (and < 2^32) → 0xFF 0xFE prefix + 4-byte big-endian.
	 */
	if (hdr_len > 0) {
		if (hdr_len < (65536U - 256U)) {
			block[block_pos++] ^= (hdr_len >> 8) & 0xFF;
			block[block_pos++] ^= hdr_len & 0xFF;
		} else {
			block[block_pos++] ^= 0xFF;
			block[block_pos++] ^= 0xFE;
			block[block_pos++] ^= (hdr_len >> 24) & 0xFF;
			block[block_pos++] ^= (hdr_len >> 16) & 0xFF;
			block[block_pos++] ^= (hdr_len >> 8) & 0xFF;
			block[block_pos++] ^= hdr_len & 0xFF;
		}

		/* XOR header bytes into CBC-MAC blocks */
		for (i = 0; i < hdr_len; i++) {
			if (block_pos == AES_BLOCK_SIZE) {
				sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, block, block);
				block_pos = 0;
			}
			block[block_pos++] ^= hdr[i];
		}

		/* Pad and encrypt final header block */
		if (block_pos > 0) {
			sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, block, block);
			block_pos = 0;
		}
	}

	/* Initialize counter A0 */
	ctr[0] = L - 1;
	memcpy(&ctr[1], nonce, CCM_NONCE_SIZE);
	memset(&ctr[CCM_NONCE_SIZE + 1], 0, AES_BLOCK_SIZE - CCM_NONCE_SIZE - 1);

	uint16_t ctr_pos = AES_BLOCK_SIZE; /* force first counter encrypt */

	/* Process payload: CBC-MAC + CTR mode encryption */
	for (i = 0; i < pay_len; i++) {
		if (ctr_pos == AES_BLOCK_SIZE) {
			/* Increment counter */
			for (int j = AES_BLOCK_SIZE - 1; j > CCM_NONCE_SIZE; j--) {
				if (++ctr[j]) {
					break;
				}
			}
			sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, ctr, ctr_pad);
			ctr_pos = 0;
		}

		uint8_t plain = payload[i];

		/* CBC-MAC on plaintext */
		if (block_pos == AES_BLOCK_SIZE) {
			sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, block, block);
			block_pos = 0;
		}
		block[block_pos++] ^= plain;

		/* CTR mode encryption */
		payload[i] = plain ^ ctr_pad[ctr_pos++];
	}

	/* Finalize CBC-MAC */
	if (pay_len > 0 && block_pos > 0) {
		sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, block, block);
	}

	/* Generate tag: encrypt A0, XOR with CBC-MAC */
	if (tag_len > 0) {
		memset(&ctr[CCM_NONCE_SIZE + 1], 0, AES_BLOCK_SIZE - CCM_NONCE_SIZE - 1);
		sli_aes_crypt_ecb_radio(true, key, AES_KEY_BITS, ctr, ctr_pad);
		for (i = 0; i < tag_len; i++) {
			tag[i] = block[i] ^ ctr_pad[i];
		}
	}

	return 0;
}

/*
 * Select the MAC key slot for a given key_id. Returns pointer to the slot
 * (which carries both the 16-byte key and its per-slot frame counter),
 * or NULL if key_id doesn't match any stored key.
 *
 * Key slots are prev/current/next, indexed relative to the current key_id.
 * Slot-bound FC preserves the retiring key's FC epoch during rotation —
 * ACKs for in-flight frames from the previous epoch use slot[prev]'s FC,
 * not the new current slot's FC.
 *
 * Cross-references: IEEE 802.15.4-2024 §9.4.4 Key Identifier. The
 * SiLabs OpenThread platform's sMacKeys[iid] in radio.c has the same
 * prev/curr/next three-slot shape.
 */
static struct efr32_mac_key_slot *efr32_select_slot(struct efr32_mac_keys *mk, uint8_t key_id,
						    bool is_ack)
{
	uint8_t cur = mk->current_slot;

	if (!is_ack) {
		/* Data frames always use the current slot */
		return &mk->slots[cur];
	}

	/* ACK frames: match key_id to prev/current/next. Clamp to valid
	 * slot indices — do not reach off the array ends.
	 */
	if (key_id == mk->key_id) {
		return &mk->slots[cur];
	} else if (cur > 0 && key_id == (uint8_t)(mk->key_id - 1)) {
		return &mk->slots[cur - 1];
	} else if (cur + 1 < EFR32_MAC_KEY_COUNT && key_id == (uint8_t)(mk->key_id + 1)) {
		return &mk->slots[cur + 1];
	}

	return NULL; /* unknown key ID */
}

/*
 * Process TX security on a frame buffer in-place.
 * Called from tx() for data frames, and from ISR for Enhanced ACK frames.
 *
 * psdu:     points to FCF (first byte of PSDU, no PHR)
 * psdu_len: PSDU length excluding FCS
 * ext_addr: our EUI-64 (8 bytes, big-endian / network order)
 * mk:       pointer to driver's key storage
 * is_ack:   true if this is an ACK frame (key selected by incoming key_id)
 *
 * Returns 0 on success, negative errno on failure.
 *
 * Three layers are kept in-driver (frame parse, key select + FC write,
 * CCM compute) because the generic OT path
 * (Mac::Frame::ProcessTransmitAesCcm → Crypto::AesEcb →
 * otPlatCryptoAesEncrypt → psa_cipher_encrypt per 16-byte block) does
 * not meet the ~500 µs DATA_REQUEST_COMMAND → ACK-on-air budget. The
 * SiLabs OpenThread platform makes the same decomposition in
 * radioProcessTransmitSecurity() (radio.c).
 */
static int efr32_process_tx_security(uint8_t *psdu, uint16_t psdu_len, const uint8_t *ext_addr,
				     struct efr32_mac_keys *mk, bool is_ack)
{
	struct efr32_aux_sec_hdr aux;

	if (!efr32_parse_aux_sec(psdu, psdu_len, &aux)) {
		return -EINVAL;
	}

	if (aux.sec_level == SEC_LEVEL_NONE) {
		return 0; /* no security needed */
	}

	/*
	 * Reject SecurityLevel 4 (ENC only, no authenticity). Deprecated
	 * per IEEE 802.15.4-2024 §9.4.2.2 Table 9-6 ("shall not be used").
	 * Thread never emits this level; a malformed peer or fuzz input is
	 * the only way it reaches the CCM compute, where mic_len == 0 would
	 * otherwise produce a silently-encrypted unauthenticated frame.
	 */
	if (aux.sec_level == SEC_LEVEL_ENC) {
		return -EINVAL;
	}

	/* Select key slot (carries both key material and per-slot FC) */
	struct efr32_mac_key_slot *slot = efr32_select_slot(mk, aux.key_id, is_ack);

	if (!slot) {
		LOG_ERR("TX sec: unknown key_id=%u (current=%u)", aux.key_id, mk->key_id);
		return -ENOENT;
	}

	/* Write the slot's frame counter into the aux header */
	uint32_t fc = slot->frame_counter;

	psdu[aux.fc_offset + 0] = (fc >> 0) & 0xFF;
	psdu[aux.fc_offset + 1] = (fc >> 8) & 0xFF;
	psdu[aux.fc_offset + 2] = (fc >> 16) & 0xFF;
	psdu[aux.fc_offset + 3] = (fc >> 24) & 0xFF;

	/* Bump this slot's frame counter (per-slot, not shared) */
	slot->frame_counter++;

	/* Construct nonce */
	uint8_t nonce[CCM_NONCE_SIZE];

	efr32_ccm_nonce(ext_addr, fc, aux.sec_level, nonce);

	/*
	 * IEEE 802.15.4-2024 §9.3.3: header IEs are a-data (authenticated,
	 * not encrypted). Compute the actual a/m boundary by scanning the
	 * header IE chain when FCF has IE Present set.
	 *
	 * Without this, frames carrying a CSL IE would have those bytes
	 * "encrypted" by the driver but received as plaintext by the peer,
	 * causing MIC failures. Verified against Annex C §C.4.7 (ACK with IEs).
	 */
	uint16_t fcf_val = psdu[0] | ((uint16_t)psdu[1] << 8);
	uint16_t ie_area_len = 0;

	if (fcf_val & FCF_IE_PRESENT) {
		uint16_t region_end = aux.hdr_len + aux.payload_len;
		uint16_t ie_end = efr32_header_ies_end(psdu, aux.hdr_len, region_end);

		ie_area_len = ie_end - aux.hdr_len;
	}

	uint16_t a_len = aux.hdr_len + ie_area_len;
	uint16_t m_len = aux.payload_len - ie_area_len;

	/*
	 * For pre-2015 MAC Command frames (FV 0b00 or 0b01), the command ID
	 * byte is part of the MHR (authenticated, not encrypted). OT's
	 * FindPayloadIndex() advances past it before returning the payload
	 * start. Mirror that: add 1 to a_len, subtract 1 from m_len.
	 *
	 * For FV2 MAC Command frames, the command ID is payload (encrypted).
	 * Annex C §C.3.3.1 confirms this version-dependent treatment.
	 */
	uint8_t frame_type = fcf_val & FCF_FRAME_TYPE_MASK;
	uint8_t frame_ver = (fcf_val & FCF_FRAME_VER_MASK) >> FCF_FRAME_VER_SHIFT;

	if (frame_type == FCF_FRAME_TYPE_CMD && frame_ver < 2 && m_len >= 1) {
		a_len += 1;
		m_len -= 1;
	}

	return efr32_ccm_encrypt(psdu, a_len, &psdu[a_len], m_len, &psdu[a_len + m_len],
				 aux.mic_len, slot->key, nonce);
}

/*
 * Build an Enhanced ACK (Enh-Ack) frame for an incoming FV2 (Frame Version 2) packet.
 *
 * Called from ISR context during DATA_REQUEST_COMMAND with ~500µs deadline.
 * Constructs the ACK in `ack_buf` (which must be at least 64 bytes).
 * Returns total length including PHR, or 0 on failure.
 *
 * Enh-Ack format per IEEE 802.15.4-2024 §7.3.3:
 *   [PHR(1)] [FCF(2)] [SeqNum(0-1)] [DstPAN(0-2)] [DstAddr(0/2/8)]
 *   [AuxSecHdr (optional)] [Header IEs (optional)] [Payload IEs (optional)]
 *   [Frame Payload (empty for ACK)] [FCS(2/4)]
 *
 * Frame Version 0b10 (2) is required per §7.3.3: Imm-Ack frames use FV 0b00–0b01;
 * Enh-Ack frames use FV 0b10. Enhanced ACKs are used in Enh-ACK-capable MAC modes
 * to carry frame pending indication, CSL phase/period, and link metrics.
 *
 * Address swapping per §7.3.3: destination addressing mode of the ACK equals the
 * source addressing mode of the frame being acknowledged; ACK DstAddr = incoming
 * SrcAddr. Typically Thread uses dst-only (no source address).
 *
 * PAN ID selection per IEEE 802.15.4-2024 §7.2.2.6 and Table 7-2: prefer SrcPAN
 * from incoming frame if present; otherwise use DstPAN. This matches the "scope"
 * hierarchy (home PAN takes precedence).
 *
 * Security per §7.3.3: if Security Enabled in the incoming FCF, the Enh-Ack frame
 * is secured using the same SecurityLevel, KeyIdMode, KeySource, and KeyIndex.
 * SecurityLevel values (§9.4.2.2) range 0–7 (0=none, 1=MIC-32, ..., 7=ENC-MIC-128);
 * level 4 (ENC only) is deprecated and shall not be used. When security is applied,
 * an Auxiliary Security Header with placeholder frame counter is inserted; the caller
 * must invoke frame security processing to finalize the frame counter and MIC.
 *
 * Constraint validation: rejects frames that are not FV2, have invalid source address
 * length disagreements with FCF, or have invalid security levels.
 *
 * Cross-references: the SiLabs OpenThread platform builds the same
 * byte layout in writeIeee802154EnhancedAck() (radio.c), routed
 * through OT frame helpers. OT core's Mac::TxFrame::GenerateEnhAck()
 * enforces securityLevel == kSecurityEncMic32 (5) specifically —
 * stricter than our accept set because Thread mandates that one
 * level.
 */
static uint16_t efr32_build_enh_ack(const uint8_t *rx_buf, uint16_t rx_len, bool frame_pending,
				    uint8_t *ack_buf, uint8_t rx_sec_level, uint8_t rx_key_id,
				    const uint8_t *src_addr, uint8_t src_addr_len)
{
	/* rx_buf starts at PHR. FCF is at offset PHR_SIZE. */
	if (rx_len < PHR_SIZE + 2) {
		return 0; /* not enough data for FCF */
	}

	uint16_t rx_fcf = rx_buf[PHR_SIZE] | ((uint16_t)rx_buf[PHR_SIZE + 1] << 8);
	uint8_t rx_frame_ver = (rx_fcf & FCF_FRAME_VER_MASK) >> FCF_FRAME_VER_SHIFT;

	if (rx_frame_ver != FCF_FRAME_VER_2015) {
		return 0; /* not FV2 */
	}

	/*
	 * SecurityLevel reached here is the 3-bit field 0..7 from an incoming
	 * AuxSecHdr; the only range check worth making is against level 4,
	 * which IEEE 802.15.4-2024 §9.4.2.2 Table 9-6 marks deprecated
	 * (ENC-only, no authenticity). efr32_process_tx_security rejects it
	 * downstream so the ACK is never emitted; we tolerate it here to
	 * keep the level-0 fast path simple.
	 */

	uint8_t rx_dst_mode = (rx_fcf & FCF_DST_ADDR_MASK) >> FCF_DST_ADDR_SHIFT;
	uint8_t rx_src_mode = (rx_fcf & FCF_SRC_ADDR_MASK) >> FCF_SRC_ADDR_SHIFT;
	bool rx_pan_comp = (rx_fcf & FCF_PAN_ID_COMPRESSION) != 0;
	bool rx_seq_suppress = (rx_fcf & FCF_SEQ_NUM_SUPPRESS) != 0;

	/*
	 * Parse incoming frame to find source address fields.
	 * Frame layout after FCF: [SeqNum(0-1)] [DstPAN(0-2)] [DstAddr(0/2/8)]
	 *                         [SrcPAN(0-2)] [SrcAddr(0/2/8)] ...
	 *
	 * PAN ID presence for FV2 per Table 7-2 (simplified for Thread cases):
	 */
	uint16_t pos = PHR_SIZE + 2; /* after FCF */

	/* Sequence number (unless suppressed in FV2) */
	uint8_t seq_num = 0;

	if (!rx_seq_suppress) {
		if (rx_len <= pos) {
			return 0;
		}
		seq_num = rx_buf[pos++];
	}

	bool dst_pan_present;
	bool src_pan_present;

	/* Enhanced ACK is FV2-only (802.15.4-2024 §7.3.3): Imm-ACK uses
	 * FV0/FV1, Enh-ACK uses FV2. We've already short-circuited to 0
	 * for non-FV2 input above; the ACK we build is likewise FV2.
	 * Hardcode the version rather than re-parsing rx_fcf.
	 */
	efr32_pan_presence(FCF_FRAME_VER_2015, rx_dst_mode, rx_src_mode, rx_pan_comp,
			   &dst_pan_present, &src_pan_present);

	/* Skip DstPAN */
	uint16_t rx_dst_pan = 0;

	if (dst_pan_present) {
		if (rx_len < pos + 2) {
			return 0;
		}
		rx_dst_pan = rx_buf[pos] | ((uint16_t)rx_buf[pos + 1] << 8);
		pos += 2;
	}

	/* Skip DstAddr */
	uint8_t dst_addr_len = (rx_dst_mode == FCF_ADDR_SHORT)      ? 2
			       : (rx_dst_mode == FCF_ADDR_EXTENDED) ? 8
								    : 0;
	pos += dst_addr_len;

	/* PAN ID selection per 802.15.4-2024 §7.2.2.6 and Table 7-2: prefer
	 * SrcPAN (when present) over DstPAN. Source PAN is the device's home
	 * network and takes precedence when addressing is ambiguous.
	 */
	uint16_t rx_src_pan = 0;

	if (src_pan_present) {
		if (rx_len < pos + 2) {
			return 0;
		}
		rx_src_pan = rx_buf[pos] | ((uint16_t)rx_buf[pos + 1] << 8);
		pos += 2;
	} else if (dst_pan_present) {
		/* SrcPAN not present, fall back to DstPAN per scope hierarchy */
		rx_src_pan = rx_dst_pan;
	}

	/* SrcAddr (becomes the ACK's DstAddr) is supplied by the caller from
	 * sl_rail_ieee802154_get_address().  Reject if its length disagrees
	 * with the FCF SrcAddrMode — indicates a malformed frame.
	 */
	uint8_t fcf_src_addr_len = (rx_src_mode == FCF_ADDR_SHORT)      ? 2
				   : (rx_src_mode == FCF_ADDR_EXTENDED) ? 8
									: 0;

	if (src_addr_len != fcf_src_addr_len || src_addr_len == 0) {
		return 0;
	}

	/*
	 * Build Enhanced ACK frame.
	 * ACK: DstAddr = incoming SrcAddr, no SrcAddr.
	 */
	uint8_t ack_dst_mode = rx_src_mode; /* swap: ACK dst = incoming src */

	/* ACK FCF */
	uint16_t ack_fcf = FCF_FRAME_TYPE_ACK;
	ack_fcf |= (FCF_FRAME_VER_2015 << FCF_FRAME_VER_SHIFT);
	if (frame_pending) {
		ack_fcf |= FCF_FRAME_PENDING;
	}
	/* Dst address mode = incoming src addr mode */
	ack_fcf |= ((uint16_t)ack_dst_mode << FCF_DST_ADDR_SHIFT);
	/* Src address mode = none.
	 * Table 7-2: Dst=ext + Src=none + PanComp=1 → no PAN IDs.
	 * Dst=short + Src=none + PanComp=0 → DstPAN present.
	 */
	if (ack_dst_mode == FCF_ADDR_EXTENDED) {
		ack_fcf |= FCF_PAN_ID_COMPRESSION;
	}

	if (rx_sec_level > 0) {
		ack_fcf |= FCF_SECURITY_ENABLED;
	}

	uint16_t ack_pos = PHR_SIZE; /* skip PHR, write it last */

	/* FCF (2 bytes, little-endian) */
	ack_buf[ack_pos++] = (uint8_t)(ack_fcf & 0xFF);
	ack_buf[ack_pos++] = (uint8_t)(ack_fcf >> 8);

	/* Sequence number (not suppressed) */
	ack_buf[ack_pos++] = seq_num;

	/* DstPAN — only for short dst (ext dst uses PanComp=1, no PAN in ACK) */
	if (ack_dst_mode == FCF_ADDR_SHORT) {
		uint16_t pan = dst_pan_present ? rx_dst_pan : rx_src_pan;

		ack_buf[ack_pos++] = (uint8_t)(pan & 0xFF);
		ack_buf[ack_pos++] = (uint8_t)(pan >> 8);
	}

	/* DstAddr = incoming SrcAddr */
	memcpy(&ack_buf[ack_pos], src_addr, src_addr_len);
	ack_pos += src_addr_len;

	/* Aux security header: SecCtrl(1) + FrameCounter(4) + KeyIndex(1) */
	if (rx_sec_level > 0) {
		/* Security Control: same sec_level, Key ID Mode 1 */
		ack_buf[ack_pos++] = (rx_sec_level & SEC_LEVEL_MASK) |
				     (SEC_KEY_ID_MODE_1 << SEC_KEY_ID_MODE_SHIFT);
		/* Frame counter placeholder (filled by efr32_process_tx_security) */
		ack_buf[ack_pos++] = 0;
		ack_buf[ack_pos++] = 0;
		ack_buf[ack_pos++] = 0;
		ack_buf[ack_pos++] = 0;
		/* Key Index */
		ack_buf[ack_pos++] = rx_key_id;
	}

	/*
	 * PHR = frame length (everything after PHR) + FCS (2) + MIC.
	 * MIC is appended by the encryption step; we reserve space here.
	 */
	uint8_t mic_len = 0;

	if (rx_sec_level > 0) {
		mic_len = efr32_mic_size(rx_sec_level);
	}

	/*
	 * IE injection placeholder — IEs are inserted here by the caller
	 * after building the frame. We return ack_pos so the caller can
	 * append IE bytes at ack_buf[ack_pos], then we recalculate PHR.
	 * For now, just finalize the PHR.
	 */
	uint8_t frame_len = (ack_pos - PHR_SIZE) + mic_len + 2; /* +2 FCS */

	ack_buf[0] = frame_len;

	return ack_pos + mic_len; /* total bytes including PHR + MIC space */
}

/* ---------- RAIL event callback (ISR context) ---------- */

/* ---------- CSL helpers ---------- */

/*
 * Truncate a Zephyr net_time_t (nanoseconds) to microseconds.
 *
 * For callers that need to feed the result to RAIL: that works here only
 * because this driver's efr32_get_time() derives its ns value from
 * sl_rail_get_time() itself, and the Zephyr OT glue routes otPlatTimeGet
 * through radio_api->get_time. That makes net_time_t / 1000 a round-trip
 * back to the original RAIL µs timestamp (to µs precision). If that chain
 * ever changes — e.g. a different clock backs net_time_t — this helper's
 * output is no longer a valid RAIL .when.
 */
static inline uint32_t net_ns_to_us(net_time_t ns)
{
	/* RAIL APIs consume 32-bit microseconds; truncation to uint32_t is
	 * intentional and matches the RAIL timebase wrapping model.
	 */
	return (uint32_t)(ns / NSEC_PER_USEC);
}

/*
 * Calculate CSL phase: number of 10-symbol periods from the ACK's "start of
 * MHR" time to the next CSL sample window.
 *
 * Per ieee802154_radio.h (§CSL_PERIOD docs):
 *   cslAnchorPointNs = expected_rx_time + PHR_duration_ns
 *   cslPhase = (startOfMhrNs - cslAnchorPointNs) / (10 * symbol_period_ns) % cslPeriod
 *
 * ack_mhr_time_us: RAIL time when ACK MHR will be on air (end-of-SHR + PHR).
 *
 * IEEE 802.15.4-2024 §10.5.5.1 (CSL IE: phase + period, both LE16).
 * Cross-reference: OT core's Mac::TxFrame::ComputeCslPhase().
 */
static uint16_t efr32_csl_phase(struct efr32_802154_data *data, uint32_t ack_mhr_time_us)
{
	if (data->csl_period == 0) {
		return 0;
	}

	/* Anchor point in RAIL µs = expected_rx_time (ns→µs) + PHR duration (32µs) */
	uint32_t anchor_us = net_ns_to_us(data->csl_sample_time) + PHR_ONAIR_US;

	/* Distance from ACK MHR to next sample, in µs (wrapping-safe) */
	uint32_t delta_us = anchor_us - ack_mhr_time_us;

	/* Convert to 10-symbol units (160 µs each) and wrap by CSL period */
	uint32_t phase = (delta_us / USEC_PER_TEN_SYMBOLS) % data->csl_period;

	return (uint16_t)phase;
}

/*
 * Patch CSL phase in-place in an Enhanced ACK buffer that contains a CSL IE.
 * Scans for the CSL IE header (element ID 0x1a) and overwrites the phase field.
 * Returns true if patched.
 */
/*
 * Returns true if the ACK-IE entry's stored header identifies it as the
 * CSL IE (element ID 0x1a, header IE type), per IEEE 802.15.4-2024
 * §7.4.2.3.
 */
static bool efr32_ie_is_csl(const struct efr32_ack_ie_entry *entry)
{
	if (entry->ie_len < 2) {
		return false;
	}
	uint16_t hdr = entry->ie_data[0] | ((uint16_t)entry->ie_data[1] << 8);
	uint8_t id = (hdr >> 7) & 0x7F;
	bool type_bit = (hdr >> 15) & 1;

	return !type_bit && id == IEEE802154_HEADER_IE_ELEMENT_ID_CSL_IE;
}

/*
 * Scan for a CSL Reduced IE in the header IE chain starting at buf[ie_start].
 * Returns the byte offset of the CSL IE content (first byte after the 2-byte
 * descriptor), or -1 if not found.
 *
 * IEEE 802.15.4-2024 §7.4.2.3 / §10.5.5.1 (CSL IE). Cross-reference:
 * OT core's Mac::Frame::FindHeaderIe() walks the same chain.
 */
static int efr32_find_csl_ie(const uint8_t *buf, uint16_t len, uint16_t ie_start)
{
	uint16_t pos = ie_start;
	uint8_t ie_id, ie_len;
	bool ie_type;

	while (efr32_decode_ie_header(buf, pos, len, &ie_id, &ie_len, &ie_type)) {
		if (ie_type) {
			return -1;
		}
		if (ie_id == IEEE802154_HEADER_IE_ELEMENT_ID_CSL_IE && ie_len >= 4) {
			return (int)(pos + 2);
		}
		pos += 2 + ie_len;
	}
	return -1;
}

/*
 * Write CSL phase and period into the CSL Reduced IE in buf[ie_start..len).
 * Per IEEE 802.15.4-2024 §10.5.5.1, the content is: phase (2 bytes LE)
 * followed by period (2 bytes LE).
 *
 * Called for both Enhanced ACK frames (ISR context) and outgoing data frames
 * (TX path).
 *
 * Cross-references: OT core's Mac::TxFrame::SetCslIe() writes the
 * same two LE16 fields. The SiLabs OpenThread platform patches the
 * same bytes inside its ACK construction path (radio.c).
 */
static bool efr32_write_csl_ie(uint8_t *buf, uint16_t len, uint16_t ie_start, uint16_t csl_phase,
			       uint16_t csl_period)
{
	int content = efr32_find_csl_ie(buf, len, ie_start);

	if (content < 0) {
		return false;
	}
	sys_put_le16(csl_phase, &buf[content]);
	sys_put_le16(csl_period, &buf[content + 2]);
	return true;
}

/*
 * Yield the current RAIL scheduler task and immediately start a new RX task.
 *
 * RAIL_YieldRadio ends the current scheduler task, which drops the radio to
 * idle.  Without an immediate RX restart the radio sits idle — it cannot
 * receive frames, cannot auto-ACK, and subsequent TX calls hit
 * RAIL_STATUS_INVALID_STATE (0x2) because CSMA TX requires an active RX.
 *
 * The SiLabs OpenThread platform achieves the same result indirectly:
 * yield in the ISR, then the OT stack calls otPlatRadioReceive() →
 * RAIL_StartRx() from thread context. The Zephyr L2 contract has no
 * such "restart RX after TX" callback, so we restart RX right here
 * instead.
 */
static inline void efr32_yield_and_rx(sl_rail_handle_t rail_handle, struct efr32_802154_data *data)
{
	sl_rail_yield_radio(rail_handle);

	if (data->started && data->rx_on_when_idle && data->channel != EFR32_NO_CHANNEL) {
		sl_rail_scheduler_info_t rx_sched = {
			.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
			.slip_time = 0,
			.transaction_time = 0,
		};

		(void)sl_rail_start_rx(rail_handle, data->channel, &rx_sched);
	}
}

/* Complete a TX operation and wake the blocked TX caller.
 *
 * Exactly one call per submitted TX: tx_submitted (ticked in efr32_tx) and
 * tx_finalized (ticked here) stay in lock-step, and the semaphore is
 * k_sem_give'd exactly once per outcome. Callers must gate on any TX-outcome
 * bit being set and must not call this more than once per callback
 * invocation.
 */
static inline void efr32_finish_tx(sl_rail_handle_t rail_handle, struct efr32_802154_data *data,
				   int result)
{
	data->tx_result = result;
	EFR32_DEBUG_INC(data, tx_finalized);
	efr32_yield_and_rx(rail_handle, data);
	k_sem_give(&data->tx_done);
}

static void efr32_rail_event_cb(sl_rail_handle_t rail_handle, sl_rail_events_t events)
{
	struct efr32_802154_data *data = &efr32_data;

	/*
	 * Snapshot the AR=1 transaction marker once. The RX-side ACK closure
	 * below clears data->waiting_for_ack mid-callback; downstream branches
	 * that need to know "this was an ack-bound TX" must consult the
	 * snapshot, not the live flag.
	 */
	const bool ack_pending_at_entry = data->waiting_for_ack;

	/*
	 * --- DMP scheduler status (MUST be first, per RAIL docs) ---
	 *
	 * Fires when the scheduler rejects or preempts our radio task.
	 * Per RAIL training convention this fires as the sole event in its
	 * callback invocation; the early return below relies on that so the
	 * TX-completion dispatch below doesn't run with stale `events`.
	 * Without this handler, a rejected TX leaves tx_done unsignaled
	 * and the calling thread hangs on k_sem_take forever.
	 */
	if (events & SL_RAIL_EVENT_SCHEDULER_STATUS) {
		sl_rail_scheduler_status_t sched_st;
		sl_rail_status_t rail_st;

		sl_rail_get_scheduler_status(rail_handle, &sched_st, &rail_st);

		uint8_t task = sched_st & SL_RAIL_SCHEDULER_TASK_MASK;
		uint8_t error = sched_st & SL_RAIL_SCHEDULER_STATUS_MASK;

		EFR32_DEBUG_INC(data, sched_status_events);
#ifdef CONFIG_IEEE802154_EFR32_DEBUG
		data->debug_counters.last_sched_status = sched_st;
		data->debug_counters.last_sched_rail_status = rail_st;
#endif
		LOG_WRN("SCHEDULER_STATUS: task=0x%02x err=0x%02x rail=0x%x", task, error, rail_st);

		if (task == SL_RAIL_SCHEDULER_TASK_SINGLE_TX ||
		    task == SL_RAIL_SCHEDULER_TASK_SINGLE_CCA_CSMA_TX ||
		    task == SL_RAIL_SCHEDULER_TASK_SINGLE_CCA_LBT_TX) {
			/*
			 * TX rejected by scheduler. SCHEDULE_FAIL and
			 * EVENT_INTERRUPTED are transient (BLE won) → -EBUSY.
			 * TASK_FAIL / INTERNAL_ERROR → -EIO.
			 */
			int result;

			if (error == SL_RAIL_SCHEDULER_STATUS_SCHEDULE_FAIL ||
			    error == SL_RAIL_SCHEDULER_STATUS_EVENT_INTERRUPTED) {
				result = -EBUSY;
				EFR32_DEBUG_INC(data, sched_tx_fail);
			} else {
				result = -EIO;
				EFR32_DEBUG_INC(data, sched_tx_error);
			}
			data->waiting_for_ack = false;
			efr32_finish_tx(rail_handle, data, result);
		} else {
			/* RX or unknown task — yield and count */
			EFR32_DEBUG_INC(data, sched_other_fail);
			efr32_yield_and_rx(rail_handle, data);
		}

		return; /* SCHEDULER_STATUS is always the sole event */
	}

	/* --- RX events --- */

	if (events & SL_RAIL_EVENT_RX_PACKET_RECEIVED) {
		struct efr32_rx_entry *entry = k_fifo_get(&data->rx_free, K_NO_WAIT);

		if (entry == NULL) {
			EFR32_DEBUG_INC(data, rx_no_buffer);
			/* Packet auto-released when callback returns */
		} else {
			sl_rail_rx_packet_info_t pkt_info;

			sl_rail_get_rx_packet_info(rail_handle, SL_RAIL_RX_PACKET_HANDLE_NEWEST,
						   &pkt_info);

			/*
			 * RAIL includes the PHR (1 byte for 2.4 GHz) in the
			 * packet data. Strip it — Zephyr/OT expects PSDU only.
			 * The SiLabs OpenThread platform does the same via
			 * skipRxPacketLengthBytes().
			 */
			if (pkt_info.first_portion_bytes > 0 && pkt_info.packet_bytes > PHR_SIZE) {
				pkt_info.p_first_portion_data += PHR_SIZE;
				pkt_info.first_portion_bytes -= PHR_SIZE;
				pkt_info.packet_bytes -= PHR_SIZE;
			}

			sl_rail_copy_rx_packet(rail_handle, entry->data, &pkt_info);
			entry->len = pkt_info.packet_bytes;

			sl_rail_rx_packet_details_t details;

			details.time_received.time_position = SL_RAIL_PACKET_TIME_AT_SYNC_END;
			details.time_received.total_packet_bytes =
				entry->len + PHR_SIZE; /* original OTA len */
			sl_rail_get_rx_packet_details(rail_handle, SL_RAIL_RX_PACKET_HANDLE_NEWEST,
						      &details);
			sl_rail_get_rx_time_sync_word_end(rail_handle, &details);

			entry->rssi = details.rssi_dbm;
			entry->lqi = details.lqi;
			entry->timestamp = details.time_received.packet_time;
			entry->is_ack = details.is_ack;
			entry->ack_fpb = data->last_ack_fpb;
			data->last_ack_fpb = false;

			k_fifo_put(&data->rx_fifo, entry);
			EFR32_DEBUG_INC(data, rx_packets);

			/*
			 * Close an ack-bound TX transaction on the matching ACK.
			 * RAIL sets details.is_ack only for a "protocol-correct"
			 * ACK whose sync word landed inside ack_timeout_us of a
			 * WAIT_FOR_ACK transmit and whose sequence number matches
			 * (sl_rail_types.h). When that fires, RAIL has already
			 * torn down the ack-timeout so RX_ACK_TIMEOUT will not be
			 * posted for this transmit; ownership of the tx_done
			 * signal passes here. The SiLabs OpenThread platform takes
			 * the same is_ack-wins-the-race branch in radio.c.
			 */
			if (ack_pending_at_entry && details.is_ack) {
				data->waiting_for_ack = false;
				efr32_finish_tx(rail_handle, data, 0);
			}
		}
	}

	if (events & SL_RAIL_EVENT_RX_FRAME_ERROR) {
		EFR32_DEBUG_INC(data, rx_crc_error);
		if (data->event_handler) {
			enum ieee802154_rx_fail_reason reason = IEEE802154_RX_FAIL_INVALID_FCS;
			data->event_handler(efr32_get_device(), IEEE802154_EVENT_RX_FAILED,
					    (void *)&reason);
		}
	}

	if (events & SL_RAIL_EVENT_RX_ADDRESS_FILTERED) {
		EFR32_DEBUG_INC(data, rx_addr_filtered);
		if (data->event_handler) {
			enum ieee802154_rx_fail_reason reason = IEEE802154_RX_FAIL_ADDR_FILTERED;
			data->event_handler(efr32_get_device(), IEEE802154_EVENT_RX_FAILED,
					    (void *)&reason);
		}
	}

	/* --- TX completion events ---
	 *
	 * The five SL_RAIL_EVENTS_TX_COMPLETION bits are mutually exclusive
	 * within a single TX attempt ("events that determine the end of a
	 * transmitted packet" — rail-api/events). RX_ACK_TIMEOUT is not in
	 * that mask: when we sent AR=1 and no ACK arrived, the same callback
	 * can carry TX_PACKET_SENT | RX_ACK_TIMEOUT. To keep the
	 * tx_submitted == tx_finalized invariant, count each per-bit counter
	 * independently but dispatch exactly one efr32_finish_tx() by
	 * errno precedence (most severe first).
	 */
	if (events & SL_RAIL_EVENT_TX_PACKET_SENT) {
		EFR32_DEBUG_INC(data, tx_packets);
	}
	if (events & SL_RAIL_EVENT_TX_ABORTED) {
		EFR32_DEBUG_INC(data, tx_aborted);
	}
	if (events & SL_RAIL_EVENT_TX_UNDERFLOW) {
		EFR32_DEBUG_INC(data, tx_underflow);
	}
	if (events & SL_RAIL_EVENT_TX_BLOCKED) {
		EFR32_DEBUG_INC(data, tx_blocked);
	}
	if (events & SL_RAIL_EVENT_TX_CHANNEL_BUSY) {
		EFR32_DEBUG_INC(data, tx_channel_busy);
	}
	if (events & SL_RAIL_EVENT_RX_ACK_TIMEOUT) {
		EFR32_DEBUG_INC(data, ack_timeout);
	}
	if (events & SL_RAIL_EVENT_TX_SCHEDULED_TX_MISSED) {
		EFR32_DEBUG_INC(data, tx_sched_missed);
	}

	if (events & (SL_RAIL_EVENT_TX_ABORTED | SL_RAIL_EVENT_TX_UNDERFLOW |
		      SL_RAIL_EVENT_TX_BLOCKED | SL_RAIL_EVENT_TX_SCHEDULED_TX_MISSED)) {
		data->waiting_for_ack = false;
		efr32_finish_tx(rail_handle, data, -EIO);
	} else if (events & SL_RAIL_EVENT_TX_CHANNEL_BUSY) {
		data->waiting_for_ack = false;
		efr32_finish_tx(rail_handle, data, -EBUSY);
	} else if (events & SL_RAIL_EVENT_RX_ACK_TIMEOUT) {
		/*
		 * ack_timeout_us elapsed without a protocol-correct ACK.
		 * The is_ack RX branch above wins the race when both bits
		 * coalesce in one callback (the SiLabs OpenThread platform
		 * notes the same coalesce in its ackTimeoutCallback);
		 * only finalize here if it didn't.
		 */
		if (data->waiting_for_ack) {
			data->waiting_for_ack = false;
			efr32_finish_tx(rail_handle, data, -ENOMSG);
		}
	} else if (events & SL_RAIL_EVENT_TX_PACKET_SENT) {
		/*
		 * AR=0: TX_PACKET_SENT == transaction complete (no ACK
		 * window follows). AR=1: the frame is on-air-end but RAIL
		 * is now in its ack_timeout_us RX window with the LBT bit
		 * still asserted; signaling tx_done here would let the L2
		 * caller submit the next TX inside that window and earn
		 * SL_STATUS_INVALID_STATE. Defer — closure is owned by the
		 * is_ack RX branch (success) or RX_ACK_TIMEOUT (failure).
		 * Mirrors packetSentCallback() in the SiLabs OpenThread
		 * platform's radio.c.
		 */
		if (!ack_pending_at_entry) {
			efr32_finish_tx(rail_handle, data, 0);
		}
	}

	if (events & SL_RAIL_EVENT_TX_STARTED) {
		if (data->event_handler) {
			data->event_handler(efr32_get_device(), IEEE802154_EVENT_TX_STARTED, NULL);
		}
		EFR32_DEBUG_INC(data, tx_started);
	}

	/* --- TXACK events --- */

	if (events & SL_RAIL_EVENT_TXACK_PACKET_SENT) {
		EFR32_DEBUG_INC(data, ack_tx);
		/*
		 * Release the TX-ACK scheduler task and restart RX.
		 *
		 * In DMP, yielding lets BLE reclaim the radio between the ACK
		 * and any subsequent data frame TX.  The immediate RX restart
		 * ensures the radio keeps listening — without it the radio
		 * sits idle until the next efr32_tx() call, unable to receive
		 * or auto-ACK further frames.
		 */
		efr32_yield_and_rx(rail_handle, data);
	}
	if (events & SL_RAIL_EVENT_TXACK_ABORTED) {
		EFR32_DEBUG_INC(data, ack_tx_aborted);
	}
	if (events & SL_RAIL_EVENT_TXACK_BLOCKED) {
		EFR32_DEBUG_INC(data, ack_tx_blocked);
	}
	if (events & SL_RAIL_EVENT_TXACK_UNDERFLOW) {
		EFR32_DEBUG_INC(data, ack_tx_underflow);
	}

	/* --- DMP scheduling events (counter-only, no thread wake) --- */

	if (events & SL_RAIL_EVENT_CONFIG_UNSCHEDULED) {
		EFR32_DEBUG_INC(data, dmp_unscheduled);
	}
	if (events & SL_RAIL_EVENT_CONFIG_SCHEDULED) {
		EFR32_DEBUG_INC(data, dmp_scheduled);
	}

	/* --- CSL scheduled RX/TX events --- */

	if (events & SL_RAIL_EVENT_RX_SCHEDULED_RX_END) {
		EFR32_DEBUG_INC(data, rx_slot_end);
		efr32_yield_and_rx(rail_handle, data);
		if (data->event_handler) {
			data->event_handler(efr32_get_device(), IEEE802154_EVENT_RX_OFF, NULL);
		}
	}

	if (events & SL_RAIL_EVENT_RX_SCHEDULED_RX_MISSED) {
		EFR32_DEBUG_INC(data, rx_slot_missed);
		efr32_yield_and_rx(rail_handle, data);
		if (data->event_handler) {
			data->event_handler(efr32_get_device(), IEEE802154_EVENT_RX_OFF, NULL);
		}
	}

	/* --- Calibration --- */

	if (events & SL_RAIL_EVENT_CAL_NEEDED) {
		data->cal_needed = true;
	}

	/* --- Data request (frame pending + Enhanced ACK) --- */

	if (events & SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND) {
		EFR32_DEBUG_INC(data, data_requests);

		/* Capture timestamp immediately — RAIL fires this callback at
		 * a version-dependent position (after address fields or after
		 * AuxSecHdr). Capturing here minimises drift vs. actual RX.
		 */
		uint32_t rx_callback_us = sl_rail_get_time(rail_handle);

		/*
		 * Read what's in the FIFO so far to extract FCF (frame
		 * version drives Imm-ACK vs Enh-ACK) and, for FV2, the MHR
		 * fields needed to build the Enhanced ACK (SeqNum, DstPAN,
		 * DstAddr, SrcPAN, optional AuxSecHdr).
		 *
		 * SrcAddr is NOT taken from this buffer — see below.
		 *
		 * Max bytes needed: PHR(1) + FCF(2) + SeqNum(1) + DstPAN(2)
		 * + DstAddr(8) + SrcPAN(2) + SrcAddr(8) + SecHdr(14) = 38
		 */
		uint8_t pkt_buf[40];
		sl_rail_rx_packet_info_t pkt_info;

		sl_rail_get_rx_incoming_packet_info(rail_handle, &pkt_info);

		/*
		 * Preserve the un-clamped byte count for timing. The ACK CSL
		 * phase formula rewinds over every byte already on air at
		 * callback time; using the 40-byte scratch cap here would
		 * skew the phase by (real - 40) × 32 µs for longer
		 * DATA_REQUEST frames.
		 */
		uint16_t rx_bytes_onair = pkt_info.packet_bytes;
		uint16_t avail = pkt_info.packet_bytes;

		if (avail > sizeof(pkt_buf)) {
			avail = sizeof(pkt_buf);
			if (pkt_info.first_portion_bytes > avail) {
				pkt_info.first_portion_bytes = avail;
				pkt_info.p_last_portion_data = NULL;
			}
			pkt_info.packet_bytes = avail;
		}

		sl_rail_copy_rx_packet(rail_handle, pkt_buf, &pkt_info);

		uint8_t frame_ver = 0;

		if (avail >= PHR_SIZE + 2) {
			uint16_t fcf = pkt_buf[PHR_SIZE] | ((uint16_t)pkt_buf[PHR_SIZE + 1] << 8);
			frame_ver = (fcf & FCF_FRAME_VER_MASK) >> FCF_FRAME_VER_SHIFT;
#ifdef CONFIG_IEEE802154_EFR32_DEBUG
			data->debug_counters.last_data_req_fcf = fcf;
			data->debug_counters.last_data_req_avail = avail;
			data->debug_counters.last_data_req_fv = frame_ver;
			memcpy(data->debug_counters.last_data_req_bytes, pkt_buf, MIN(avail, 8));
#endif
		}

		/* SrcAddr for both FPB source match and Enh-ACK DstAddr.
		 * In DATA_REQUEST_COMMAND context the getter reads RAIL's
		 * parser-owned state, which has already consumed SrcAddr
		 * into internal registers — it is the authoritative source.
		 */
		sl_rail_ieee802154_address_t rail_src;
		uint8_t parsed_src_addr[8];
		uint8_t parsed_src_addr_len = 0;
		bool src_ok =
			(sl_rail_ieee802154_get_address(rail_handle, &rail_src) == SL_STATUS_OK);

		if (src_ok) {
			if (rail_src.address_length == SL_RAIL_IEEE802154_LONG_ADDRESS) {
				memcpy(parsed_src_addr, rail_src.long_address,
				       sizeof(rail_src.long_address));
				parsed_src_addr_len = sizeof(rail_src.long_address);
			} else if (rail_src.address_length == SL_RAIL_IEEE802154_SHORT_ADDRESS) {
				sys_put_le16(rail_src.short_address, parsed_src_addr);
				parsed_src_addr_len = sizeof(rail_src.short_address);
			} else {
				src_ok = false;
			}
		}

		bool fp_set = false;

		if (src_ok && data->src_match.enabled &&
		    efr32_src_match_lookup(&data->src_match, &rail_src)) {
			fp_set = true;
		}

		if (frame_ver == FCF_FRAME_VER_2015) {
			uint8_t ack_buf[80]; /* room for sec header + MIC */
			uint16_t ack_len;

			/*
			 * Check if incoming frame is secured — if so, ACK
			 * must also be secured (same sec level, matching key).
			 */
			uint8_t rx_sec_level = 0;
			uint8_t rx_key_id = 0;

			if (avail >= PHR_SIZE + 2) {
				uint16_t rx_fcf =
					pkt_buf[PHR_SIZE] | ((uint16_t)pkt_buf[PHR_SIZE + 1] << 8);
				if (rx_fcf & FCF_SECURITY_ENABLED) {
					struct efr32_aux_sec_hdr rx_aux;

					if (efr32_parse_aux_sec(&pkt_buf[PHR_SIZE],
								avail - PHR_SIZE, &rx_aux)) {
						rx_sec_level = rx_aux.sec_level;
						rx_key_id = rx_aux.key_id;
					}
				}
			}
			ack_len = efr32_build_enh_ack(pkt_buf, avail, fp_set, ack_buf, rx_sec_level,
						      rx_key_id, parsed_src_addr,
						      parsed_src_addr_len);

			bool enh_ack_skipped = (ack_len == 0);

			if (enh_ack_skipped) {
				EFR32_DEBUG_INC(data, enh_ack_skip);
			}

			/* IE injection: match the ACK's DstAddr (= incoming
			 * SrcAddr as reported by the RAIL getter) against the
			 * ack_ie_table.
			 */
			bool ie_matched = false;
			bool ie_table_has_entries = false;
			uint16_t ie_area_start = 0;

			if (ack_len > 0) {
				uint8_t mic = efr32_mic_size(rx_sec_level);
				/* IE insertion point = ack_len - mic */
				ie_area_start = ack_len - mic;
				uint16_t ie_pos = ie_area_start;

				for (int ie_i = 0; ie_i < EFR32_ACK_IE_MAX_PEERS; ie_i++) {
					const struct efr32_ack_ie_entry *ie =
						&data->ack_ie_table[ie_i];
					if (!ie->in_use || ie->ie_len == 0) {
						continue;
					}
					ie_table_has_entries = true;

					bool match = false;

					if (parsed_src_addr_len == 2) {
						/* Frame buffer: LE. IE table short_addr:
						 * CPU byte order (from Zephyr API).
						 */
						uint16_t short_addr =
							parsed_src_addr[0] |
							((uint16_t)parsed_src_addr[1] << 8);
						match = (ie->short_addr == short_addr);
					} else if (parsed_src_addr_len == 8) {
						/* Frame buffer: LE (802.15.4 OTA).
						 * IE table ext_addr: BE (Zephyr API).
						 * Compare byte-reversed.
						 */
						match = true;
						for (int b = 0; b < 8; b++) {
							if (ie->ext_addr[b] !=
							    parsed_src_addr[7 - b]) {
								match = false;
								break;
							}
						}
					}
					if (!match) {
						continue;
					}

					if (ie_pos + ie->ie_len + mic <= sizeof(ack_buf)) {
						/* Shift MIC space to make room */
						if (mic > 0) {
							memmove(&ack_buf[ie_pos + ie->ie_len],
								&ack_buf[ie_pos], mic);
						}
						memcpy(&ack_buf[ie_pos], ie->ie_data, ie->ie_len);
						ie_pos += ie->ie_len;
						ack_len += ie->ie_len;
						/* Set IE Present bit in FCF */
						ack_buf[PHR_SIZE] |=
							(uint8_t)(FCF_IE_PRESENT & 0xFF);
						ack_buf[PHR_SIZE + 1] |=
							(uint8_t)(FCF_IE_PRESENT >> 8);
						/* Update PHR */
						ack_buf[0] += ie->ie_len;
						ie_matched = true;
					}
				}
			}

			if (ie_matched) {
				EFR32_DEBUG_INC(data, ie_injected);
				/*
				 * CSL phase patching: if the injected IE is a
				 * CSL IE, patch its phase field with a freshly
				 * calculated value.  ie_area_start is the exact
				 * byte offset of the IE area so we don't
				 * accidentally scan the MAC header bytes.
				 */
				if (data->csl_period > 0) {
					/*
					 * ACK MHR on-air time using the SiLabs
					 * OpenThread platform's ackShrDoneTime
					 * formula (radio.c), re-anchored to
					 * rx_callback_us (captured at the top of
					 * this handler).
					 *
					 *   rewind over bytes already clocked in
					 *   (avail) + add the full incoming frame
					 *   (PHR + PHR-value bytes) + RX→TX turn +
					 *   outgoing SHR + PHR. efr32_csl_phase's
					 *   anchor offset adds the trailing PHR.
					 */
					uint8_t frame_len = (avail >= 1) ? pkt_buf[0] : 0;
					uint32_t ack_mhr_us =
						rx_callback_us -
						((uint32_t)rx_bytes_onair *
						 BYTE_ONAIR_US) /* rewind to incoming SHR-end */
						+ PHR_ONAIR_US  /* incoming PHR */
						+ ((uint32_t)frame_len *
						   BYTE_ONAIR_US) /* incoming payload+FCS */
						+ RX_TO_TX_US + PHR_ONAIR_US /* ACK PHR */
						+ SHR_DURATION_US            /* ACK SHR */
						+ PHR_ONAIR_US; /* csl_phase anchor offset */
					uint16_t phase = efr32_csl_phase(data, ack_mhr_us);

					if (efr32_write_csl_ie(ack_buf, ack_len, ie_area_start,
							       phase, (uint16_t)data->csl_period)) {
						EFR32_DEBUG_INC(data, csl_phase_updates);
					} else {
						EFR32_DEBUG_INC(data, csl_patch_scan_fail);
					}
				} else {
					EFR32_DEBUG_INC(data, csl_patch_no_period);
				}
			} else if (ie_table_has_entries) {
				/* SrcAddr didn't match any IE entry —
				 * byte-order bug or stale IE table entry.
				 */
				EFR32_DEBUG_INC(data, ie_no_match);
			} else if (!ie_matched) {
				EFR32_DEBUG_INC(data, enh_ack_ie_empty);
			}

			/* Encrypt the Enhanced ACK if secured */
			if (ack_len > 0 && rx_sec_level > 0) {
				uint8_t mic = efr32_mic_size(rx_sec_level);
				uint16_t psdu_len = ack_len - PHR_SIZE - mic;

				int sec_ret = efr32_process_tx_security(&ack_buf[PHR_SIZE],
									psdu_len + mic, data->mac,
									&data->mac_keys, true);
				if (sec_ret != 0) {
					EFR32_DEBUG_INC(data, enh_ack_fail);
					ack_len = 0;
				}
			}
			if (ack_len > 0) {
				sl_rail_status_t ack_st;

				ack_st = sl_rail_ieee802154_write_enh_ack(rail_handle, ack_buf,
									  ack_len);
				if (ack_st == SL_STATUS_OK) {
					EFR32_DEBUG_INC(data, enh_ack_sent);
				} else {
					EFR32_DEBUG_INC(data, enh_ack_fail);
				}
				if (fp_set) {
					EFR32_DEBUG_INC(data, ack_tx_fp_set);
				}
			} else if (!enh_ack_skipped) {
				/* Real failure (e.g. security encrypt failed,
				 * ack_len set to 0 mid-pipeline). Don't count
				 * graceful skips — those are enh_ack_skip.
				 */
				EFR32_DEBUG_INC(data, enh_ack_fail);
			}
		} else {
			/* FV0/1: Immediate ACK — toggle FPB if matched */
			if (fp_set) {
				sl_rail_ieee802154_toggle_frame_pending(rail_handle);
				EFR32_DEBUG_INC(data, ack_tx_fp_set);
			}
		}

		/*
		 * Propagate FP decision to the RX entry that will be
		 * created when RX_PACKET_RECEIVED fires for this frame.
		 * OT reads mAckedWithFramePending to trigger indirect TX.
		 */
		data->last_ack_fpb = fp_set;
	}
}

/* ---------- RX thread ---------- */

static inline void efr32_rx_fill_pkt_common(struct net_pkt *pkt, const struct efr32_rx_entry *entry,
					    uint64_t rx_ts_ns)
{
	net_pkt_write(pkt, entry->data, entry->len);
#if defined(CONFIG_IEEE802154_L2_PKT_INCL_FCS)
	/* Append dummy FCS (already validated by RAIL). */
	static const uint8_t dummy_fcs[IEEE802154_FCS_LENGTH] = {0, 0};

	net_pkt_write(pkt, dummy_fcs, IEEE802154_FCS_LENGTH);
#endif
	net_pkt_set_ieee802154_lqi(pkt, entry->lqi);
	net_pkt_set_ieee802154_rssi_dbm(pkt, entry->rssi);
	net_pkt_set_timestamp_ns(pkt, rx_ts_ns);
}

static void efr32_rx_thread(void *p1, void *p2, void *p3)
{
	struct efr32_802154_data *data = &efr32_data;

	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (1) {
		struct efr32_rx_entry *entry = k_fifo_get(&data->rx_fifo, K_FOREVER);

		if (data->iface == NULL) {
			goto recycle;
		}

		/* Handle calibration when RX thread wakes */
		if (data->cal_needed) {
			data->cal_needed = false;
			sl_rail_calibrate(data->rail_handle, NULL, SL_RAIL_CAL_ALL_PENDING);
			EFR32_DEBUG_INC(data, calibrations);
		}

		/*
		 * RAIL strips FCS. If the L2 expects FCS in the packet
		 * (CONFIG_IEEE802154_L2_PKT_INCL_FCS), we append 2 dummy
		 * FCS bytes so the frame length matches what OT expects.
		 */
		uint16_t deliver_len = entry->len;
#if defined(CONFIG_IEEE802154_L2_PKT_INCL_FCS)
		deliver_len += IEEE802154_FCS_LENGTH;
#endif

		/*
		 * Convert RAIL RX timestamp (µs) to nanoseconds for OT.
		 * OT stores this in the neighbor's CSL state via ProcessCsl
		 * (mac.cpp) so the CSL TX scheduler can anchor scheduled TX
		 * to the observed sample time. Without a valid timestamp the
		 * CSL TX scheduler fires into the dark.
		 */
		const uint64_t rx_ts_ns = (uint64_t)entry->timestamp * NSEC_PER_USEC;

		/* ACKs: deliver via ieee802154_handle_ack */
		if (entry->is_ack) {
			struct net_pkt *ack_pkt = net_pkt_rx_alloc_with_buffer(
				data->iface, deliver_len, AF_UNSPEC, 0, K_NO_WAIT);
			if (ack_pkt) {
				efr32_rx_fill_pkt_common(ack_pkt, entry, rx_ts_ns);
				if (ieee802154_handle_ack(data->iface, ack_pkt) != NET_OK) {
					net_pkt_unref(ack_pkt);
				}
			}
			goto recycle;
		}

		/* Normal frames: deliver to net stack */
		struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(data->iface, deliver_len,
								   AF_UNSPEC, 0, K_NO_WAIT);

		if (pkt == NULL) {
			LOG_WRN("RX: failed to allocate net_pkt");
			EFR32_DEBUG_INC(data, rx_fail);
			goto recycle;
		}

		efr32_rx_fill_pkt_common(pkt, entry, rx_ts_ns);
		net_pkt_set_ieee802154_ack_fpb(pkt, entry->ack_fpb);

		if (net_recv_data(data->iface, pkt) != 0) {
			LOG_WRN("RX: net_recv_data failed");
			net_pkt_unref(pkt);
			EFR32_DEBUG_INC(data, rx_fail);
		}

recycle:
		k_fifo_put(&data->rx_free, entry);
	}
}

/* ---------- IEEE 802.15.4 radio API ---------- */

static enum ieee802154_hw_caps efr32_get_capabilities(const struct device *dev)
{
	ARG_UNUSED(dev);

	return IEEE802154_HW_FCS | IEEE802154_HW_FILTER | IEEE802154_HW_TX_RX_ACK |
	       IEEE802154_HW_CSMA | IEEE802154_HW_ENERGY_SCAN | IEEE802154_HW_TXTIME |
	       IEEE802154_HW_RXTIME | IEEE802154_HW_SLEEP_TO_TX | /* deprecated (#63670) but OT
								     platform still gates on it */
	       IEEE802154_RX_ON_WHEN_IDLE |
	       IEEE802154_HW_TX_SEC | 0;
}

static int efr32_cca(const struct device *dev)
{
	struct efr32_802154_data *data = dev->data;
	int16_t rssi;

	rssi = sl_rail_get_rssi(data->rail_handle, 1);
	if (rssi == SL_RAIL_RSSI_INVALID) {
		return -EIO;
	}

	/* RAIL returns quarter-dBm; CCA threshold is -75 dBm */
	if ((rssi / 4) > -75) {
		return -EBUSY;
	}

	return 0;
}

static int efr32_set_channel(const struct device *dev, uint16_t channel)
{
	struct efr32_802154_data *data = dev->data;

	if (channel < 11 || channel > 26) {
		return -EINVAL;
	}

	data->channel = (uint8_t)channel;
	LOG_DBG("channel=%u", channel);
	return 0;
}

static int efr32_filter(const struct device *dev, bool set, enum ieee802154_filter_type type,
			const struct ieee802154_filter *filter)
{
	struct efr32_802154_data *data = dev->data;

	if (!set) {
		return -ENOTSUP;
	}

	switch (type) {
	case IEEE802154_FILTER_TYPE_IEEE_ADDR:
		/* Two distinct forms of the local extended address:
		 *
		 *   filter->ieee_addr  — on-air / transmission order per
		 *     IEEE 802.15.4-2024 §4 (rightmost-octet-first). Zephyr's
		 *     radio API (ieee802154_radio.h) hands us the address in
		 *     this form, and RAIL's sl_rail_ieee802154_set_long_address()
		 *     expects the same on-air order (matches the SiLabs
		 *     OpenThread platform's radio.c, which passes m8 without
		 *     reversal). Pass through unchanged.
		 *
		 *   data->mac  — canonical / big-endian (MSO-first) form, the
		 *     invariant established by efr32_iface_init() from the
		 *     factory EUI. This is the form consumed by efr32_ccm_nonce
		 *     as the CCM* nonce source-address per §9.3.2.1 / Annex C.
		 *     Byte-reverse filter->ieee_addr to preserve that invariant
		 *     after OT reconfigures the EUI-64 (e.g. NVS restore).
		 */
		sl_rail_ieee802154_set_long_address(data->rail_handle, filter->ieee_addr, 0);
		efr32_ext_addr_on_air_to_canonical(data->mac, filter->ieee_addr);
		LOG_DBG("filter: ext_addr %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			filter->ieee_addr[0], filter->ieee_addr[1], filter->ieee_addr[2],
			filter->ieee_addr[3], filter->ieee_addr[4], filter->ieee_addr[5],
			filter->ieee_addr[6], filter->ieee_addr[7]);
		break;
	case IEEE802154_FILTER_TYPE_SHORT_ADDR:
		sl_rail_ieee802154_set_short_address(data->rail_handle, filter->short_addr, 0);
		LOG_DBG("filter: short_addr 0x%04x", filter->short_addr);
		break;
	case IEEE802154_FILTER_TYPE_PAN_ID:
		sl_rail_ieee802154_set_pan_id(data->rail_handle, filter->pan_id, 0);
		LOG_DBG("filter: pan_id 0x%04x", filter->pan_id);
		break;
	default:
		return -ENOTSUP;
	}

	return 0;
}

static int efr32_set_txpower(const struct device *dev, int16_t dbm)
{
	struct efr32_802154_data *data = dev->data;
	sl_rail_status_t status;

	/* RAIL uses deci-dBm */
	status = sl_rail_set_tx_power_dbm(data->rail_handle, (sl_rail_tx_power_t)(dbm * 10));
	if (status != SL_STATUS_OK) {
		LOG_ERR("set_tx_power_dbm failed: 0x%x", status);
		return -EIO;
	}

	data->tx_power = dbm * 10;
	return 0;
}

static int efr32_start(const struct device *dev)
{
	struct efr32_802154_data *data = dev->data;
	sl_rail_status_t status;

	if (data->started) {
		return -EALREADY;
	}

	if (data->channel == EFR32_NO_CHANNEL) {
		return -EINVAL;
	}

	sl_rail_scheduler_info_t sched_info = {
		.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
		.slip_time = 0,
		.transaction_time = 0,
	};

	status = sl_rail_start_rx(data->rail_handle, data->channel, &sched_info);
	if (status != SL_STATUS_OK) {
		LOG_ERR("sl_rail_start_rx failed: 0x%x", status);
		return -EIO;
	}

	data->started = true;
	LOG_DBG("RX started on channel %u", data->channel);
	return 0;
}

static int efr32_stop(const struct device *dev)
{
	struct efr32_802154_data *data = dev->data;

	if (!data->started) {
		return -EALREADY;
	}

	sl_rail_idle(data->rail_handle, SL_RAIL_IDLE, true);
	sl_rail_yield_radio(data->rail_handle);

	data->started = false;
	LOG_DBG("stopped");
	return 0;
}

static int efr32_tx(const struct device *dev, enum ieee802154_tx_mode mode, struct net_pkt *pkt,
		    struct net_buf *frag)
{
	struct efr32_802154_data *data = dev->data;
	sl_rail_status_t status;

	__ASSERT(data->channel != EFR32_NO_CHANNEL, "Channel not set");

	if (mode != IEEE802154_TX_MODE_DIRECT && mode != IEEE802154_TX_MODE_CSMA_CA &&
	    mode != IEEE802154_TX_MODE_TXTIME_CCA) {
		return -ENOTSUP;
	}

	/*
	 * RAIL requires the radio to be in RX for CSMA TX (it handles the
	 * RX→TX transition internally).  efr32_yield_and_rx() normally
	 * restarts RX after every transaction, but verify here in case the
	 * scheduler preempted us or the restart was lost.
	 */
	sl_rail_radio_state_t radio_state = sl_rail_get_radio_state(data->rail_handle);
	if (!(radio_state & SL_RAIL_RF_STATE_RX)) {
		sl_rail_scheduler_info_t rx_sched = {
			.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
			.slip_time = 0,
			.transaction_time = 0,
		};
		sl_rail_status_t rx_st =
			sl_rail_start_rx(data->rail_handle, data->channel, &rx_sched);
		if (rx_st != SL_STATUS_OK) {
			LOG_ERR("pre-TX RX restart failed: 0x%x", rx_st);
			return -EIO;
		}
	}

	/* Compute total PSDU length */
	uint16_t total_len = 0;

	for (struct net_buf *f = frag; f != NULL; f = f->frags) {
		total_len += f->len;
	}

	/*
	 * TX security: if frame is not yet secured, encrypt in-place.
	 * Linearize the PSDU into efr32_tx_buf, encrypt, then write to
	 * the RAIL FIFO.  tx_buf lives in the driver struct (not on the
	 * stack) because this runs on the ot_radio_workq whose stack is
	 * already tight under DMP — see Kconfig.efr32.
	 */
	bool need_sec = !net_pkt_ieee802154_frame_secured(pkt) && (total_len >= 2) &&
			(frag->data[0] & FCF_SECURITY_ENABLED);

	/*
	 * Scheduled-TX action time (SHR on-air anchor, RAIL µs).
	 *
	 *   TXTIME_CCA:  OT supplies mTxDelayBaseTime + mTxDelay via
	 *                net_pkt_timestamp_ns — that's the action time.
	 *   CSMA + CSL:  force a scheduled TX using now + SCHEDULE_TX_DELAY_US
	 *                so the CSL phase anchor is trustworthy (mirrors
	 *                SiLabs radio.c mTxDelay=0 / csl_period>0 path).
	 *   other:       0, falls through to unscheduled TX below.
	 */
	uint32_t action_time_us = 0;

	if (mode == IEEE802154_TX_MODE_TXTIME_CCA) {
		action_time_us = net_ns_to_us(net_pkt_timestamp_ns(pkt));
	} else if (mode == IEEE802154_TX_MODE_CSMA_CA && data->csl_period > 0) {
		action_time_us = sl_rail_get_time(data->rail_handle) + SCHEDULE_TX_DELAY_US;
	}

	if (need_sec) {
		if (total_len > sizeof(efr32_tx_buf)) {
			LOG_ERR("TX security buffer too small: len=%u max=%u", total_len,
				(uint16_t)sizeof(efr32_tx_buf));
			return -EMSGSIZE;
		}

		/* Linearize into efr32_tx_buf */
		uint16_t off = 0;

		for (struct net_buf *f = frag; f != NULL; f = f->frags) {
			memcpy(&efr32_tx_buf[off], f->data, f->len);
			off += f->len;
		}

		/*
		 * CSL IE writer: OT core defers security when a CSL IE is
		 * present (mac.cpp:908); the driver fills phase+period before
		 * encryption so the MIC covers the correct IE bytes. Same
		 * role as otMacFrameSetCslIe() + radioProcessTransmitSecurity()
		 * in SiLabs radio.c:1847-1851.
		 *
		 * Anchor: ack_mhr_us = action_time + SHR + PHR.
		 * action_time was computed above for both scheduled variants.
		 */
		uint16_t tx_fcf = efr32_tx_buf[0] | ((uint16_t)efr32_tx_buf[1] << 8);

		if (data->csl_period > 0 && (tx_fcf & FCF_IE_PRESENT) && action_time_us != 0) {
			struct efr32_aux_sec_hdr aux;

			if (efr32_parse_aux_sec(efr32_tx_buf, total_len, &aux)) {
				uint32_t tx_mhr_us =
					action_time_us + SHR_DURATION_US + PHR_ONAIR_US;
				uint16_t phase = efr32_csl_phase(data, tx_mhr_us);

				efr32_write_csl_ie(efr32_tx_buf, total_len, aux.hdr_len, phase,
						   (uint16_t)data->csl_period);
			}
		}

		int sec_ret = efr32_process_tx_security(efr32_tx_buf, total_len, data->mac,
							&data->mac_keys, false);
		if (sec_ret != 0) {
			LOG_ERR("TX security failed: %d", sec_ret);
			return sec_ret;
		}

		/* Write PHR + encrypted PSDU to FIFO */
		uint8_t phr = (uint8_t)(total_len + IEEE802154_FCS_LENGTH);

		sl_rail_write_tx_fifo(data->rail_handle, &phr, 1, true);
		sl_rail_write_tx_fifo(data->rail_handle, efr32_tx_buf, total_len, false);

		/* Mark as secured so OT/retransmit won't re-encrypt */
		net_pkt_set_ieee802154_frame_secured(pkt, true);
		net_pkt_set_ieee802154_mac_hdr_rdy(pkt, true);

		/*
		 * Copy back so L2 layer sees encrypted frame on retransmit
		 * or frame counter propagation.
		 */
		off = 0;
		for (struct net_buf *f = frag; f != NULL; f = f->frags) {
			memcpy(f->data, &efr32_tx_buf[off], f->len);
			off += f->len;
		}
	} else {
		/* No security needed: write fragments directly to FIFO */
		uint8_t phr = (uint8_t)(total_len + IEEE802154_FCS_LENGTH);

		sl_rail_write_tx_fifo(data->rail_handle, &phr, 1, true);

		for (struct net_buf *f = frag; f != NULL; f = f->frags) {
			sl_rail_write_tx_fifo(data->rail_handle, f->data, f->len, false);
		}
	}

	/* Reset TX semaphore */
	k_sem_reset(&data->tx_done);

	/* TX options: check ACK Request bit in frame control */
	sl_rail_tx_options_t tx_opts = SL_RAIL_TX_OPTIONS_DEFAULT;

	if (total_len >= 1 && (frag->data[0] & (uint8_t)FCF_ACK_REQUEST)) {
		/* AR bit is bit 5 of first FCF byte */
		tx_opts |= SL_RAIL_TX_OPTION_WAIT_FOR_ACK;
	}

	/*
	 * Arm the ack-bound transaction marker before submitting. The event
	 * callback consults this to decide whether TX_PACKET_SENT closes the
	 * TX (AR=0) or merely marks frame on-air-end inside an open ACK
	 * window (AR=1, closure deferred to is_ack RX or RX_ACK_TIMEOUT).
	 */
	data->waiting_for_ack = (tx_opts & SL_RAIL_TX_OPTION_WAIT_FOR_ACK) != 0;

	/*
	 * DMP scheduler info — priority escalates on retransmit.
	 * Fresh TX: 100 (lowest TX prio). Each retry: -2. Floor: 80.
	 * Lower number = higher priority, so retransmits win over BLE.
	 * Values from the SiLabs OpenThread platform's
	 * sl_802154_radio_priority_config.h.
	 */
	uint8_t tx_prio = CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_BASE;

	if (data->tx_retry_count > 0) {
		uint16_t step = (uint16_t)data->tx_retry_count *
				CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_STEP;
		uint16_t range = CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_BASE -
				 CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_MAX;

		tx_prio =
			(step >= range)
				? CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_MAX
				: (CONFIG_IEEE802154_EFR32_SCHEDULER_TX_PRIO_BASE - (uint8_t)step);
	}

	sl_rail_scheduler_info_t sched_info = {
		.priority = tx_prio,
		.slip_time = CONFIG_IEEE802154_EFR32_SCHEDULER_TX_SLIP_TIME_US,
		.transaction_time =
			(uint32_t)(total_len + IEEE802154_FCS_LENGTH) * BYTE_ONAIR_US + 1000,
	};

	if (action_time_us != 0) {
		/*
		 * Scheduled TX, unified path for both TXTIME_CCA (CSL FTD:
		 * mTxDelayBaseTime = RX sync-word timestamp, mTxDelay = offset)
		 * and forced-CSMA+CSL (CSL SSED: mTxDelayBaseTime = now,
		 * mTxDelay = SCHEDULE_TX_DELAY_US). Per the SiLabs OpenThread
		 * platform's radio.c, both cases use:
		 *
		 *   .when = action_time - SHR_DURATION_US - CSL_CSMA_BACKOFF_US
		 *   csma_cfg = SINGLE_CCA, cca_backoff_us = CSL_CSMA_BACKOFF_US
		 *
		 * action_time is the SHR on-air target; RAIL starts the CCA
		 * warmup early enough that the SHR lands there.
		 */
		sl_rail_csma_config_t csma_cfg = SL_RAIL_CSMA_CONFIG_SINGLE_CCA;

		csma_cfg.cca_backoff_us = CSL_CSMA_BACKOFF_US;

		sl_rail_scheduled_tx_config_t sched_tx = {
			.when = action_time_us - SHR_DURATION_US - CSL_CSMA_BACKOFF_US,
			.mode = SL_RAIL_TIME_ABSOLUTE,
			.tx_during_rx = SL_RAIL_SCHEDULED_TX_DURING_RX_POSTPONE_TX,
		};

		status = sl_rail_start_scheduled_cca_csma_tx(data->rail_handle, data->channel,
							     tx_opts, &sched_tx, &csma_cfg,
							     &sched_info);
	} else if (mode == IEEE802154_TX_MODE_CSMA_CA) {
		sl_rail_csma_config_t csma_cfg =
			SL_RAIL_CSMA_CONFIG_802_15_4_2003_2P4_GHZ_OQPSK_CSMA;

		status = sl_rail_start_cca_csma_tx(data->rail_handle, data->channel, tx_opts,
						   &csma_cfg, &sched_info);
	} else {
		status = sl_rail_start_tx(data->rail_handle, data->channel, tx_opts, &sched_info);
	}

	if (status != SL_STATUS_OK) {
		LOG_ERR("TX start failed: 0x%x", status);
		EFR32_DEBUG_INC(data, tx_start_rejected);
		data->waiting_for_ack = false;
		efr32_yield_and_rx(data->rail_handle, data);
		if (data->tx_retry_count < 255) {
			data->tx_retry_count++;
		}
		return -EIO;
	}

	EFR32_DEBUG_INC(data, tx_submitted);

	/* Block until RAIL event callback signals completion */
	k_sem_take(&data->tx_done, K_FOREVER);

	/* Track retransmits for DMP priority escalation */
	if (data->tx_result == 0) {
		data->tx_retry_count = 0;
	} else if (data->tx_retry_count < 255) {
		data->tx_retry_count++;
	}

	return data->tx_result;
}

/* ---------- Energy detection scan ---------- */

/*
 * ED scan timer callback — runs in ISR context every 128us.
 * Samples RSSI and tracks peak. When duration expires, tears down the
 * scan and invokes the done callback with the peak value.
 */
static void efr32_scan_timer_cb(sl_rail_multi_timer_t *p_tmr, sl_rail_time_t expected_time,
				void *cb_arg)
{
	struct efr32_802154_data *data = cb_arg;

	/* Sample RSSI (quarter-dBm). On the first call of a scan the receiver
	 * may still be settling from the start_rx in efr32_ed_scan(), so wait
	 * for a valid reading; once any valid sample lands, fall through to
	 * NO_WAIT so we don't block subsequent ticks. Matches the SiLabs
	 * OpenThread platform's efr32ScanTimerHandler() (radio.c).
	 */
	sl_rail_time_t wait = (data->scan_max_rssi == SL_RAIL_RSSI_INVALID)
				      ? SL_RAIL_GET_RSSI_WAIT_WITHOUT_TIMEOUT
				      : SL_RAIL_GET_RSSI_NO_WAIT;
	int16_t rssi = sl_rail_get_rssi(data->rail_handle, wait);

	if (rssi != SL_RAIL_RSSI_INVALID && rssi > data->scan_max_rssi) {
		data->scan_max_rssi = rssi;
	}

	/* Check if scan duration has elapsed */
	uint32_t now = sl_rail_get_time(data->rail_handle);
	uint32_t elapsed = now - data->scan_start_us; /* wrapping-safe */

	if (elapsed >= data->scan_duration_us) {
		/* Scan complete — tear down */
		sl_rail_idle(data->rail_handle, SL_RAIL_IDLE, true);

		/* Restore frame detection */
		sl_rail_config_rx_options(data->rail_handle,
					  SL_RAIL_RX_OPTION_DISABLE_FRAME_DETECTION,
					  SL_RAIL_RX_OPTIONS_NONE);

		/* Resume normal RX on the stored channel */
		if (data->started && data->channel != EFR32_NO_CHANNEL) {
			sl_rail_scheduler_info_t sched = {
				.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
				.slip_time = 0,
				.transaction_time = 0,
			};
			sl_rail_start_rx(data->rail_handle, data->channel, &sched);
		}

		/* Report result: convert quarter-dBm to integer dBm */
		int16_t result_dbm = (data->scan_max_rssi == SL_RAIL_RSSI_INVALID)
					     ? SL_RAIL_RSSI_INVALID_DBM
					     : (data->scan_max_rssi / 4);

		data->scan_done_cb(efr32_get_device(), result_dbm);
		data->scan_done_cb = NULL;
		return;
	}

	/* Reschedule for another 128us sample */
	sl_rail_set_multi_timer(data->rail_handle, &data->scan_timer, ED_SCAN_SAMPLE_US,
				SL_RAIL_TIME_DELAY, efr32_scan_timer_cb, data);
}

/*
 * Energy detection scan over the current channel: report the peak RSSI
 * (in dBm) seen during `duration` ms via `done_cb`.
 *
 * Architecture: timer-driven polled-max. Each ED_SCAN_SAMPLE_US tick we
 * call sl_rail_get_rssi() and keep the running max in
 * data->scan_max_rssi until the scan window elapses. RAIL also exposes
 * sl_rail_start_average_rssi(), but it returns the *arithmetic mean*
 * over a single window — wrong shape for ED scan (see motivation
 * below).
 *
 * Spec / API motivation:
 *   - IEEE 802.15.4-2024 §11.2.6 "Receiver ED": one ED measurement is
 *     the received power averaged over eight symbol periods.
 *     ED_SCAN_SAMPLE_US = 128 µs is exactly 8 symbols × 16 µs/symbol on
 *     2.4 GHz O-QPSK, so each tick is a spec-conformant ED *unit*.
 *   - OpenThread otPlatRadioEnergyScanDone() takes
 *     `int8_t aEnergyScanMaxRssi` ("the maximum RSSI encountered on
 *     the scanned channel") — peak of the per-tick units, not their
 *     mean.
 *   - Zephyr energy_scan_done_cb_t signals `int16_t max_ed`; the
 *     in-tree nRF5 reference driver forwards
 *     nrf_802154_energy_detected_t.ed_dbm ("Maximum detected ED in
 *     dBm"). Same peak contract.
 *
 * Same shape as the SiLabs OpenThread platform's
 * efr32StartEnergyScan() / efr32ScanTimerHandler() in radio.c, which
 * tracks sEnergyReadsMax for the same reasons.
 */
static int efr32_ed_scan(const struct device *dev, uint16_t duration, energy_scan_done_cb_t done_cb)
{
	struct efr32_802154_data *data = dev->data;

	if (data->scan_done_cb != NULL) {
		return -EBUSY; /* scan already in progress */
	}

	if (done_cb == NULL) {
		return -EINVAL;
	}

	data->scan_done_cb = done_cb;
	data->scan_max_rssi = SL_RAIL_RSSI_INVALID;
	data->scan_duration_us = (uint32_t)duration * USEC_PER_MSEC;

	/* Stop current RX */
	sl_rail_idle(data->rail_handle, SL_RAIL_IDLE, true);

	/* Disable frame detection — keep RF on for RSSI only */
	sl_rail_config_rx_options(data->rail_handle, SL_RAIL_RX_OPTION_DISABLE_FRAME_DETECTION,
				  SL_RAIL_RX_OPTION_DISABLE_FRAME_DETECTION);

	/* Start RX on current channel for RSSI measurement */
	sl_rail_scheduler_info_t sched = {
		.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
		.slip_time = 0,
		.transaction_time = 0,
	};

	sl_rail_status_t status = sl_rail_start_rx(data->rail_handle, data->channel, &sched);
	if (status != SL_STATUS_OK) {
		LOG_ERR("ed_scan: start_rx failed: 0x%x", status);
		/* Restore frame detection */
		sl_rail_config_rx_options(data->rail_handle,
					  SL_RAIL_RX_OPTION_DISABLE_FRAME_DETECTION,
					  SL_RAIL_RX_OPTIONS_NONE);
		data->scan_done_cb = NULL;
		return -EIO;
	}

	/* Record scan start time */
	data->scan_start_us = sl_rail_get_time(data->rail_handle);

	/* Start periodic RSSI sampling every 128us */
	sl_rail_set_multi_timer(data->rail_handle, &data->scan_timer, ED_SCAN_SAMPLE_US,
				SL_RAIL_TIME_DELAY, efr32_scan_timer_cb, data);

	return 0;
}

static net_time_t efr32_get_time(const struct device *dev)
{
	struct efr32_802154_data *data = dev->data;
	k_spinlock_key_t key = k_spin_lock(&data->time_lock);

	uint32_t now = sl_rail_get_time(data->rail_handle);
	uint32_t delta = now - data->last_rail_time; /* wrapping-safe */

	data->base_ns += (uint64_t)delta * 1000ULL;
	data->last_rail_time = now;

	net_time_t result = (net_time_t)data->base_ns;

	k_spin_unlock(&data->time_lock, key);
	return result;
}

static uint8_t efr32_get_sch_acc(const struct device *dev)
{
	ARG_UNUSED(dev);
	return CONFIG_IEEE802154_EFR32_XTAL_ACCURACY;
}

/* ---------- Source match table helpers ---------- */

static int efr32_src_match_update(struct efr32_802154_data *data,
				  const struct ieee802154_config *config)
{
	struct efr32_src_match *sm = &data->src_match;

	if (config->ack_fpb.addr == NULL && !config->ack_fpb.enabled) {
		/* Clear all entries */
		sm->short_count = 0;
		sm->ext_count = 0;
		return 0;
	}

	if (config->ack_fpb.addr == NULL) {
		return -EINVAL;
	}

	if (!config->ack_fpb.extended) {
		uint16_t addr;

		memcpy(&addr, config->ack_fpb.addr, sizeof(addr));

		if (config->ack_fpb.enabled) {
			/* Add short address */
			for (int i = 0; i < sm->short_count; i++) {
				if (sm->short_addrs[i] == addr) {
					return 0; /* already present */
				}
			}
			if (sm->short_count >= CONFIG_IEEE802154_EFR32_SRC_MATCH_SHORT_MAX) {
				return -ENOMEM;
			}
			sm->short_addrs[sm->short_count++] = addr;
		} else {
			/* Remove short address */
			for (int i = 0; i < sm->short_count; i++) {
				if (sm->short_addrs[i] == addr) {
					sm->short_addrs[i] = sm->short_addrs[--sm->short_count];
					return 0;
				}
			}
		}
	} else {
		/* Extended address */
		if (config->ack_fpb.enabled) {
			/* Add extended address */
			for (int i = 0; i < sm->ext_count; i++) {
				if (memcmp(sm->ext_addrs[i], config->ack_fpb.addr, 8) == 0) {
					return 0; /* already present */
				}
			}
			if (sm->ext_count >= CONFIG_IEEE802154_EFR32_SRC_MATCH_EXT_MAX) {
				return -ENOMEM;
			}
			memcpy(sm->ext_addrs[sm->ext_count++], config->ack_fpb.addr, 8);
		} else {
			/* Remove extended address */
			for (int i = 0; i < sm->ext_count; i++) {
				if (memcmp(sm->ext_addrs[i], config->ack_fpb.addr, 8) == 0) {
					memcpy(sm->ext_addrs[i], sm->ext_addrs[--sm->ext_count], 8);
					return 0;
				}
			}
		}
	}

	return 0;
}

/* Look up address in source match table. Returns true if found. */
static bool efr32_src_match_lookup(const struct efr32_src_match *sm,
				   const sl_rail_ieee802154_address_t *addr)
{
	if (addr->address_length == SL_RAIL_IEEE802154_SHORT_ADDRESS) {
		for (int i = 0; i < sm->short_count; i++) {
			if (sm->short_addrs[i] == addr->short_address) {
				return true;
			}
		}
	} else if (addr->address_length == SL_RAIL_IEEE802154_LONG_ADDRESS) {
		for (int i = 0; i < sm->ext_count; i++) {
			if (memcmp(sm->ext_addrs[i], addr->long_address, 8) == 0) {
				return true;
			}
		}
	}
	return false;
}

static int efr32_configure(const struct device *dev, enum ieee802154_config_type type,
			   const struct ieee802154_config *config)
{
	struct efr32_802154_data *data = dev->data;

	switch (type) {
	case IEEE802154_CONFIG_EVENT_HANDLER:
		data->event_handler = config->event_handler;
		return 0;
	case IEEE802154_CONFIG_PROMISCUOUS:
		sl_rail_ieee802154_set_promiscuous_mode(data->rail_handle, config->promiscuous);
		return 0;
	case IEEE802154_CONFIG_AUTO_ACK_FPB:
		data->src_match.enabled =
			(config->auto_ack_fpb.mode == IEEE802154_FPB_ADDR_MATCH_THREAD) &&
			config->auto_ack_fpb.enabled;
		return 0;
	case IEEE802154_CONFIG_ACK_FPB: {
		unsigned int key = irq_lock();
		int ret = efr32_src_match_update(data, config);
		irq_unlock(key);
		return ret;
	}
	case IEEE802154_CONFIG_MAC_KEYS: {
		struct efr32_mac_keys *mk = &data->mac_keys;
		const struct ieee802154_key *keys = config->mac_keys;

		/*
		 * Snapshot the retiring "current" slot's FC before overwrite.
		 * Zephyr's API delivers per-key frame counters (see
		 * struct ieee802154_key::key_frame_counter), and OT populates
		 * them with the epoch FC for each key. If the caller does not
		 * supply an FC for slot 0 (prev) on rotation, carry the
		 * retiring current-slot FC into slot 0 so ACKs under the
		 * retiring key continue in their own FC epoch. This mirrors
		 * the SiLabs OpenThread platform's sMacKeys rotation.
		 */
		uint32_t old_curr_fc = mk->slots[mk->current_slot].frame_counter;

		memset(mk->slots, 0, sizeof(mk->slots));
		mk->key_id = 0;

		for (int i = 0; i < EFR32_MAC_KEY_COUNT && keys->key_value; i++, keys++) {
			memcpy(mk->slots[i].key, keys->key_value, 16);
			mk->slots[i].frame_counter = keys->key_frame_counter;
			if (i == 1) {
				/* Second entry = "current" key — extract key ID */
				if (keys->key_id) {
					mk->key_id = keys->key_id[0];
				}
			}
		}

		/* Carry old current-slot FC into slot 0 if caller didn't */
		if (mk->slots[0].frame_counter == 0) {
			mk->slots[0].frame_counter = old_curr_fc;
		}
		mk->current_slot = 1;

		LOG_DBG("MAC keys updated, key_id=%u", mk->key_id);
		return 0;
	}
	case IEEE802154_CONFIG_FRAME_COUNTER: {
		uint32_t curr_fc = data->mac_keys.slots[data->mac_keys.current_slot].frame_counter;

		/*
		 * Per Zephyr API (ieee802154_radio.h:742): MUST reject
		 * values not strictly greater than the current counter.
		 * Exception: accept 0 when counter is 0 (initial state
		 * after key reset — MAC_KEYS resets counter to 0).
		 */
		if (config->frame_counter <= curr_fc &&
		    !(config->frame_counter == 0 && curr_fc == 0)) {
			return -EINVAL;
		}
		data->mac_keys.slots[data->mac_keys.current_slot].frame_counter =
			config->frame_counter;
		LOG_DBG("frame_counter=%u", config->frame_counter);
		return 0;
	}
	case IEEE802154_CONFIG_FRAME_COUNTER_IF_LARGER: {
		uint32_t *curr_fc =
			&data->mac_keys.slots[data->mac_keys.current_slot].frame_counter;

		if (config->frame_counter > *curr_fc) {
			*curr_fc = config->frame_counter;
		}
		return 0;
	}
	case IEEE802154_CONFIG_RX_ON_WHEN_IDLE:
		data->rx_on_when_idle = config->rx_on_when_idle;
		if (config->rx_on_when_idle) {
			if (!data->started && data->channel != EFR32_NO_CHANNEL) {
				efr32_start(dev);
			}
		} else {
			if (data->started) {
				efr32_stop(dev);
			}
		}
		return 0;
	case IEEE802154_CONFIG_ENH_ACK_HEADER_IE: {
		struct efr32_ack_ie_entry *table = data->ack_ie_table;

		/* Purge all IEs */
		if (config->ack_ie.purge_ie) {
			for (int i = 0; i < EFR32_ACK_IE_MAX_PEERS; i++) {
				table[i].in_use = false;
			}
			EFR32_DEBUG_INC(data, ie_cfg_purged);
			return 0;
		}

		/* Find existing entry or free slot */
		int free_slot = -1;

		for (int i = 0; i < EFR32_ACK_IE_MAX_PEERS; i++) {
			if (!table[i].in_use) {
				if (free_slot < 0) {
					free_slot = i;
				}
				continue;
			}
			/* Match by ext_addr if provided, else short_addr */
			if (config->ack_ie.ext_addr &&
			    memcmp(table[i].ext_addr, config->ack_ie.ext_addr, 8) == 0) {
				free_slot = i;
				break;
			}
			if (table[i].short_addr == config->ack_ie.short_addr) {
				free_slot = i;
				break;
			}
		}

		if (free_slot < 0) {
			return -ENOMEM;
		}

		/* Remove or update? */
		if (config->ack_ie.header_ie == NULL || config->ack_ie.header_ie->length == 0) {
			table[free_slot].in_use = false;
			EFR32_DEBUG_INC(data, ie_cfg_removed);
			return 0;
		}

		uint8_t ie_total_len =
			config->ack_ie.header_ie->length + IEEE802154_HEADER_IE_HEADER_LENGTH;

		if (ie_total_len > EFR32_ACK_IE_MAX_DATA) {
			return -ENOMEM;
		}

		memcpy(table[free_slot].ie_data, config->ack_ie.header_ie, ie_total_len);
		table[free_slot].ie_len = ie_total_len;
		table[free_slot].short_addr = config->ack_ie.short_addr;
		if (config->ack_ie.ext_addr) {
			memcpy(table[free_slot].ext_addr, config->ack_ie.ext_addr, 8);
		} else {
			memset(table[free_slot].ext_addr, 0, 8);
		}
		table[free_slot].in_use = true;
		EFR32_DEBUG_INC(data, ie_cfg_added);
		if (data->csl_period == 0) {
			EFR32_DEBUG_INC(data, cfg_ie_when_csl_zero);
		}
		return 0;
	}
	case IEEE802154_CONFIG_CSL_PERIOD:
		/*
		 * On CSL_PERIOD(0), evict CSL IE entries from the ACK-IE
		 * table.  OT removes per-peer IEs via ENH_ACK_HEADER_IE some
		 * time later, leaving a window where we would otherwise
		 * inject a stale CSL IE into Enh-ACKs with no phase patch
		 * (since the ISR gates phase patching on csl_period > 0).
		 * Per IEEE 802.15.4-2024 §10.5.5.1 the CSL IE is only
		 * required in Enh-ACKs when macLeEnabled is TRUE, so
		 * dropping CSL IEs when the period goes to zero is correct;
		 * non-CSL IE entries are preserved.
		 */
		if (config->csl_period == 0) {
			bool had_csl_ie = false;

			for (int i = 0; i < EFR32_ACK_IE_MAX_PEERS; i++) {
				struct efr32_ack_ie_entry *e = &data->ack_ie_table[i];

				if (e->in_use && efr32_ie_is_csl(e)) {
					e->in_use = false;
					had_csl_ie = true;
				}
			}
			if (had_csl_ie) {
				EFR32_DEBUG_INC(data, cfg_csl_zero_with_ie);
			}
		}
		data->csl_period = config->csl_period;
		LOG_DBG("CSL period=%u (10-sym units)", config->csl_period);
		return 0;
	case IEEE802154_CONFIG_EXPECTED_RX_TIME:
		data->csl_sample_time = config->expected_rx_time;
		LOG_DBG("CSL expected_rx_time=%lld ns", config->expected_rx_time);
		return 0;
	case IEEE802154_CONFIG_RX_SLOT: {
		if (config->rx_slot.start == IEEE802154_CONFIG_RX_SLOT_NONE) {
			/* Cancel any scheduled RX, idle the radio */
			sl_rail_idle(data->rail_handle, SL_RAIL_IDLE_ABORT, false);
			sl_rail_yield_radio(data->rail_handle);
			/*
			 * PITFALL: only restart continuous RX if rx_on_when_idle.
			 * An SSED should stay idle after slot cancellation.
			 */
			if (data->rx_on_when_idle && data->started &&
			    data->channel != EFR32_NO_CHANNEL) {
				sl_rail_scheduler_info_t rx_sched = {
					.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
					.slip_time = 0,
					.transaction_time = 0,
				};
				(void)sl_rail_start_rx(data->rail_handle, data->channel, &rx_sched);
			}
			return 0;
		}

		if (config->rx_slot.start == IEEE802154_CONFIG_RX_SLOT_OFF ||
		    config->rx_slot.duration == 0) {
			/* Disable RX immediately */
			sl_rail_idle(data->rail_handle, SL_RAIL_IDLE_ABORT, false);
			sl_rail_yield_radio(data->rail_handle);
			return 0;
		}

		/* Schedule an RX window */
		uint32_t start_us = net_ns_to_us(config->rx_slot.start);
		uint32_t dur_us = net_ns_to_us(config->rx_slot.duration);

		sl_rail_scheduled_rx_config_t rx_cfg = {
			.start = start_us,
			.start_mode = SL_RAIL_TIME_ABSOLUTE,
			.end = start_us + dur_us,
			.end_mode = SL_RAIL_TIME_ABSOLUTE,
			.rx_transition_end_schedule = 0,
			.hard_window_end = 1,
		};
		sl_rail_scheduler_info_t rx_sched = {
			.priority = CONFIG_IEEE802154_EFR32_SCHEDULER_RX_PRIORITY,
			.slip_time = 0,
			.transaction_time = dur_us,
		};

		sl_rail_status_t rx_st = sl_rail_start_scheduled_rx(
			data->rail_handle, config->rx_slot.channel, &rx_cfg, &rx_sched);
		if (rx_st != SL_STATUS_OK) {
			LOG_ERR("scheduled RX failed: 0x%x", rx_st);
			return -EIO;
		}
		return 0;
	}
	default:
		return -ENOTSUP;
	}
}

static int efr32_attr_get(const struct device *dev, enum ieee802154_attr attr,
			  struct ieee802154_attr_value *value)
{
	ARG_UNUSED(dev);

	if (attr == IEEE802154_ATTR_PHY_SUPPORTED_CHANNEL_RANGES) {
		static const struct ieee802154_phy_channel_range ranges[] = {
			{
				.from_channel = 11,
				.to_channel = 26,
			},
		};
		static const struct ieee802154_phy_supported_channels chans = {
			.ranges = ranges,
			.num_ranges = 1,
		};

		value->phy_supported_channels = &chans;
		return 0;
	}

	return -ENOTSUP;
}

/* ---------- iface_init ---------- */

static void efr32_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct efr32_802154_data *data = dev->data;

	data->iface = iface;

	/* Read EUI-64 from hardware */
	uint64_t unique = SYSTEM_GetUnique();

	/*
	 * SYSTEM_GetUnique() returns little-endian on ARM.
	 * Byte-reverse to network order (MSB at mac[0]).
	 */
	uint8_t *src = (uint8_t *)&unique;

	for (int i = 0; i < 8; i++) {
		data->mac[i] = src[7 - i];
	}

	/* Set the link address */
	net_if_set_link_addr(iface, data->mac, sizeof(data->mac), NET_LINK_IEEE802154);

	/* Initialize the IEEE 802.15.4 L2 context — REQUIRED by all drivers */
	ieee802154_init(iface);

	LOG_INF("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", data->mac[0], data->mac[1],
		data->mac[2], data->mac[3], data->mac[4], data->mac[5], data->mac[6], data->mac[7]);
}

/* ---------- Device init ---------- */

static int efr32_init(const struct device *dev)
{
	struct efr32_802154_data *data = dev->data;
	int ret;

	/* Initialize driver state */
	data->channel = EFR32_NO_CHANNEL;
	data->tx_power = 0;
	data->started = false;
	data->cal_needed = false;
	data->event_handler = NULL;
	data->last_ack_fpb = false;
	data->rx_on_when_idle = true;
	data->csl_period = 0;
	data->csl_sample_time = 0;
	data->base_ns = 0;

	k_sem_init(&data->tx_done, 0, 1);
	k_fifo_init(&data->rx_fifo);
	k_fifo_init(&data->rx_free);

	/* Pre-populate RX free buffer pool */
	for (int i = 0; i < CONFIG_IEEE802154_EFR32_RX_BUF_COUNT; i++) {
		k_fifo_put(&data->rx_free, &efr32_rx_entries[i]);
	}

	/* Start the RX processing thread */
	k_thread_create(&data->rx_thread, efr32_rx_stack, CONFIG_IEEE802154_EFR32_RX_STACK_SIZE,
			efr32_rx_thread, NULL, NULL, NULL, K_PRIO_COOP(2), 0, K_NO_WAIT);
	k_thread_name_set(&data->rx_thread, "efr32_802154_rx");

	/* Initialize RAIL */
	ret = efr32_rail_init(data);
	if (ret != 0) {
		return ret;
	}

	LOG_INF("IEEE 802.15.4 EFR32 driver initialized");
	return 0;
}

/* ---------- PM device action ---------- */

#if defined(CONFIG_PM_DEVICE)
/* Zephyr PM device hook. The system PM subsystem calls SUSPEND before
 * dropping the CPU into EM2, and RESUME after it wakes. In a sleepy
 * role the stack has already idled the radio (stop / RX_SLOT end), so
 * SUSPEND just idles RAIL and yields it — matching the SiLabs
 * OpenThread platform's radioSetIdle sequence in radio.c and the RAIL
 * sleep documentation's "the radio must be idle for the device to
 * enter EM2 or lower energy mode" constraint. The PM_DEVICE gate
 * matches Zephyr's STM32WBA 802.15.4 driver — the standard pattern is
 * to expose the PM action whenever PM_DEVICE is on.
 *
 * If the radio is still actively receiving a frame we refuse the
 * suspend with -EBUSY — RAIL will wake the system out of EM2 on its
 * own when that frame finishes, and the next PM tick will try again.
 * RESUME is a no-op: the next rx_slot / start from OT restarts RX if
 * that's wanted, and we must NOT force RX on here (that would be
 * wrong for an SSED between CSL windows).
 */
static int efr32_pm_action(const struct device *dev, enum pm_device_action action)
{
	struct efr32_802154_data *data = dev->data;

	switch (action) {
	case PM_DEVICE_ACTION_SUSPEND: {
		sl_rail_radio_state_t state = sl_rail_get_radio_state(data->rail_handle);

		/* SL_RAIL_RF_STATE_RX_ACTIVE is a *composite* enum value
		 * (RX | ACTIVE = 3), not a single bit — a bitmask test
		 * against it flags any state with RX or ACTIVE set, which
		 * catches idle listening (state=RX=2). We only want to
		 * refuse when mid-frame, so match the composite as a set.
		 */
		if ((state & SL_RAIL_RF_STATE_RX_ACTIVE) == SL_RAIL_RF_STATE_RX_ACTIVE) {
			EFR32_DEBUG_INC(data, pm_suspend_blocked);
			return -EBUSY;
		}

		sl_rail_idle(data->rail_handle, SL_RAIL_IDLE, true);
		sl_rail_yield_radio(data->rail_handle);
		EFR32_DEBUG_INC(data, pm_suspend_count);
		return 0;
	}
	case PM_DEVICE_ACTION_RESUME:
		EFR32_DEBUG_INC(data, pm_resume_count);
		return 0;
	default:
		return -ENOTSUP;
	}
}

PM_DEVICE_DT_INST_DEFINE(0, efr32_pm_action);
#endif /* CONFIG_PM_DEVICE */

/* ---------- Device instantiation ---------- */

static const struct ieee802154_radio_api efr32_radio_api = {
	.iface_api.init = efr32_iface_init,

	.get_capabilities = efr32_get_capabilities,
	.cca = efr32_cca,
	.set_channel = efr32_set_channel,
	.filter = efr32_filter,
	.set_txpower = efr32_set_txpower,
	.start = efr32_start,
	.stop = efr32_stop,
	.tx = efr32_tx,
	.ed_scan = efr32_ed_scan,
	.get_time = efr32_get_time,
	.get_sch_acc = efr32_get_sch_acc,
	.configure = efr32_configure,
	.attr_get = efr32_attr_get,
};

/*
 * L2 layer selection for NET_DEVICE_DT_INST_DEFINE.
 *
 * NET_DEVICE_DT_INST_DEFINE takes three L2-related parameters: the L2
 * identity (e.g. IEEE802154_L2), the L2 context type (a struct that Zephyr
 * allocates per-interface to hold L2 state), and the MTU.
 *
 * Which L2 we bind to depends on which networking stack is enabled:
 *  - IEEE802154_L2:  raw 802.15.4 with 6LoWPAN (ctx = ieee802154_context)
 *  - OPENTHREAD_L2:  OpenThread manages the radio (ctx = openthread_context)
 *  - CUSTOM_IEEE802154_L2: user-provided L2 layer
 *
 * The macro NET_L2_GET_CTX_TYPE(X) expands to X##_CTX_TYPE — a per-L2
 * typedef convention (e.g. IEEE802154_L2_CTX_TYPE = struct ieee802154_context).
 * NET_L2_DATA_INIT (called inside Z_NET_DEVICE_INIT) uses this type to
 * statically allocate the L2 context struct attached to the net_if.
 *
 * The MTU differs: 802.15.4 L2 uses IEEE802154_MTU (127 - header overhead),
 * while OpenThread uses 1280 (IPv6 minimum MTU — OT handles fragmentation).
 */
#if defined(CONFIG_NET_L2_IEEE802154)
#define L2          IEEE802154_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(IEEE802154_L2)
#define MTU         IEEE802154_MTU
#elif defined(CONFIG_NET_L2_OPENTHREAD)
#define L2          OPENTHREAD_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(OPENTHREAD_L2)
#define MTU         1280
#elif defined(CONFIG_NET_L2_CUSTOM_IEEE802154)
#define L2          CUSTOM_IEEE802154_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(CUSTOM_IEEE802154_L2)
#define MTU         CONFIG_NET_L2_CUSTOM_IEEE802154_MTU
#endif

/* PM_DEVICE_DT_INST_GET(0) expands to NULL when CONFIG_PM_DEVICE=n, so
 * this works as a single expression without a Kconfig wrapper.
 */
#if defined(CONFIG_NET_L2_PHY_IEEE802154)
NET_DEVICE_DT_INST_DEFINE(0, efr32_init, PM_DEVICE_DT_INST_GET(0), &efr32_data, NULL,
			  CONFIG_IEEE802154_EFR32_INIT_PRIO, &efr32_radio_api, L2, L2_CTX_TYPE,
			  MTU);
#else
DEVICE_DT_INST_DEFINE(0, efr32_init, PM_DEVICE_DT_INST_GET(0), &efr32_data, NULL, POST_KERNEL,
		      CONFIG_IEEE802154_EFR32_INIT_PRIO, &efr32_radio_api);
#endif
