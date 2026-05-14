/*
 * Copyright (c) 2026 LeafLabs, LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IEEE802154_EFR32_H_
#define IEEE802154_EFR32_H_

#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/kernel.h>

#include <sl_rail.h>
#include <sl_rail_ieee802154.h>

/* Must match the DTS binding compatible string with commas→underscores */
#define DT_DRV_COMPAT silabs_efr32_ieee802154

/* Sentinel: channel not yet configured */
#define EFR32_NO_CHANNEL 0xFF

/*
 * RX buffer entry — lives in a free pool, ISR moves to rx_fifo,
 * RX thread processes and returns to free pool.
 */
struct efr32_rx_entry {
	void *fifo_reserved; /* k_fifo linkage — must be first */
	uint8_t data[128];   /* max 802.15.4 PSDU (PHR/FCS excluded by RAIL) */
	uint8_t len;         /* PSDU length (without FCS) */
	int8_t rssi;         /* dBm (integer) */
	uint8_t lqi;
	uint32_t timestamp; /* RAIL microseconds */
	bool is_ack;
	bool ack_fpb; /* ACK for this frame had frame pending set */
};

/* ---------- Debug counters (compiled out when DEBUG disabled) ---------- */

#ifdef CONFIG_IEEE802154_EFR32_DEBUG

struct efr32_debug_counters {
	/* TX */
	uint32_t tx_packets;
	uint32_t tx_started;
	uint32_t tx_aborted;
	uint32_t tx_blocked;
	uint32_t tx_underflow;
	uint32_t tx_channel_busy;
	/* Per-TX pairing invariant: tx_submitted ticks once per successful
	 * sl_rail_start_*_tx(); tx_finalized ticks once inside
	 * efr32_finish_tx() which is called exactly once per callback that
	 * carries any TX-outcome bit. Equal counts mean every submitted TX
	 * got exactly one k_sem_give on tx_done — drift is a stuck or
	 * spurious wake.
	 */
	uint32_t tx_submitted;
	uint32_t tx_finalized;
	uint32_t tx_scheduled_missed;
	/*
	 * sl_rail_start_*_tx() returned non-OK. Any radio-state mismatch at
	 * submission time ticks this once, before RAIL queues the TX. Stays
	 * at 0 in healthy operation; useful for diagnosing scheduler conflicts
	 * (DMP/BLE) and ack-window-overlap regressions.
	 */
	uint32_t tx_start_rejected;
	/* ACK TX */
	uint32_t ack_tx;
	uint32_t ack_tx_aborted;
	uint32_t ack_tx_blocked;
	uint32_t ack_tx_underflow;
	uint32_t ack_tx_fp_set;
	uint32_t ack_tx_fp_fail;
	uint32_t ack_tx_fp_addr_fail;
	uint32_t ack_timeout;
	uint32_t enh_ack_sent;
	uint32_t enh_ack_fail;
	uint32_t enh_ack_skip; /* FV2 but build_enh_ack returned 0 (insufficient bytes) */
	uint32_t ie_injected;  /* IE matched peer and was inserted into Enhanced ACK */
	uint32_t ie_no_match;  /* IE lookup found no matching peer address */
	/* Debug: last FCF seen in DATA_REQUEST_COMMAND handler */
	uint16_t last_data_req_fcf;
	uint16_t last_data_req_avail;
	uint8_t last_data_req_fv;
	uint8_t last_data_req_bytes[8]; /* first 8 bytes of packet */
	/* RX */
	uint32_t rx_packets;
	uint32_t rx_crc_error;
	uint32_t rx_frame_error;
	uint32_t rx_addr_filtered;
	uint32_t rx_overflow;
	uint32_t rx_no_buffer;
	uint32_t rx_fail;
	/* Misc */
	uint32_t calibrations;
	uint32_t data_requests;
	uint32_t cca_start;
	uint32_t cca_retry;
	uint32_t cca_success;
	uint32_t events_missed;
	/* DMP scheduling */
	uint32_t dmp_unscheduled;
	uint32_t dmp_scheduled;
	/* DMP scheduler errors */
	uint32_t sched_status_events;
	uint32_t sched_tx_fail;
	uint32_t sched_tx_error;
	uint32_t sched_other_fail;
	uint8_t last_sched_status;
	uint32_t last_sched_rail_status;
	/* CSL */
	uint32_t rx_slot_end;
	uint32_t rx_slot_missed;
	uint32_t tx_sched_missed;
	/*
	 * IEEE802154_CONFIG_RX_SLOT called with an absolute start time
	 * already in the past relative to sl_rail_get_time(). The driver
	 * skips the RAIL call; OT computes the next window from
	 * anchor + N * period regardless. Non-zero here is informational —
	 * RAIL would have rejected the call anyway.
	 */
	uint32_t rx_slot_sched_skip;
	/*
	 * sl_rail_start_scheduled_rx() returned non-OK for reasons other
	 * than the start-in-past pre-skip (e.g., scheduler busy, channel
	 * config error). The window is lost but the driver keeps running;
	 * OT will reschedule the next slot.
	 */
	uint32_t rx_slot_sched_fail;
	uint32_t csl_phase_updates;
	uint32_t csl_patch_no_period; /* ie_matched but csl_period==0 */
	uint32_t csl_patch_scan_fail; /* csl_period>0 but patch scan failed */
	/* IE config tracking */
	uint32_t ie_cfg_added;   /* IEEE802154_CONFIG_ENH_ACK_HEADER_IE added entry */
	uint32_t ie_cfg_removed; /* ENH_ACK_HEADER_IE removed entry (header_ie=NULL) */
	uint32_t ie_cfg_purged;  /* IE table purged (csl_period=0 or purge_ie=true) */
	/* CSL/IE ordering observability — tracks whether the upper layer
	 * sequenced CSL_PERIOD updates and ENH_ACK_HEADER_IE table edits
	 * coherently with one another.
	 */
	uint32_t cfg_csl_zero_with_ie; /* CSL_PERIOD(0) while IE table had in_use entries */
	uint32_t cfg_ie_when_csl_zero; /* ENH_ACK_HEADER_IE add/populate while csl_period==0 */
	/* Enhanced ACK IE path diagnostics */
	uint32_t enh_ack_ie_empty; /* Enhanced ACK but IE table has no in_use entries */
	/* Power management (SED) */
	uint32_t pm_suspend_count;   /* Successful PM SUSPEND callbacks (radio idled) */
	uint32_t pm_resume_count;    /* PM RESUME callbacks */
	uint32_t pm_suspend_blocked; /* SUSPEND refused because RX was actively receiving */
};

#define EFR32_DEBUG_INC(data, counter) ((data)->debug_counters.counter++)

#else /* !CONFIG_IEEE802154_EFR32_DEBUG */

#define EFR32_DEBUG_INC(data, counter) ((void)0)

#endif /* CONFIG_IEEE802154_EFR32_DEBUG */

/* ---------- MAC key storage ---------- */

/* Number of MAC keys: prev(0), current(1), next(2) */
#define EFR32_MAC_KEY_COUNT 3

/*
 * Per-slot frame counter. Zephyr's ieee802154_radio IEEE802154_CONFIG_MAC_KEYS
 * delivers struct ieee802154_key entries with key_frame_counter, one per slot.
 * Storing the counter alongside its slot keeps the retiring key's epoch
 * intact during rotation: ACKs generated for in-flight frames from the
 * previous epoch use the previous slot's FC, not the current slot's.
 * A shared counter would let a rotation consume FC space from a slot that
 * the peer has already stopped listening for.
 */
struct efr32_mac_key_slot {
	uint8_t key[16];        /* AES-128 key material */
	uint32_t frame_counter; /* Per-slot TX/ACK frame counter */
};

struct efr32_mac_keys {
	struct efr32_mac_key_slot slots[EFR32_MAC_KEY_COUNT]; /* prev/curr/next */
	uint8_t current_slot; /* index of "current" — always 1 in Thread */
	uint8_t key_id;       /* matches slots[current_slot] */
};

/* ---------- Enhanced ACK IE storage ---------- */

/* Max IE data bytes per entry (CSL IE = 6 bytes, vendor specific up to ~20) */
#define EFR32_ACK_IE_MAX_DATA  32
/* Max number of per-peer IE entries */
#define EFR32_ACK_IE_MAX_PEERS 4

struct efr32_ack_ie_entry {
	uint8_t ext_addr[8];                    /* Peer extended address (big-endian) */
	uint16_t short_addr;                    /* Peer short address (CPU byte order) */
	uint8_t ie_data[EFR32_ACK_IE_MAX_DATA]; /* Raw IE bytes (header + content) */
	uint8_t ie_len;                         /* Length of ie_data */
	bool in_use;
};

/* ---------- Source match table ---------- */

struct efr32_src_match {
	uint16_t short_addrs[CONFIG_IEEE802154_EFR32_SRC_MATCH_SHORT_MAX];
	uint8_t ext_addrs[CONFIG_IEEE802154_EFR32_SRC_MATCH_EXT_MAX][8];
	uint8_t short_count;
	uint8_t ext_count;
	bool enabled;
};

/* ---------- Driver data ---------- */

struct efr32_802154_data {
	/* RAIL handle — assigned by sl_rail_init() */
	sl_rail_handle_t rail_handle;

	/* Network interface */
	struct net_if *iface;

	/* MAC address (EUI-64, network byte order) */
	uint8_t mac[8];

	/* Radio configuration */
	uint8_t channel;       /* current channel (11-26), or EFR32_NO_CHANNEL */
	int16_t tx_power;      /* deci-dBm */
	volatile bool started; /* RX active */
	bool rx_on_when_idle;  /* FTD/MTD=true, SED/SSED=false */

	/* CSL state */
	uint32_t csl_period;        /* 10-symbol units, 0 = CSL disabled */
	net_time_t csl_sample_time; /* nanoseconds, expected RX time anchor */

	/* TX synchronization */
	struct k_sem tx_done;
	int tx_result;          /* errno from TX completion event */
	uint8_t tx_retry_count; /* consecutive failures, for DMP priority */
	/*
	 * Set in efr32_tx() when SL_RAIL_TX_OPTION_WAIT_FOR_ACK is requested,
	 * before submission. Indicates the radio is in a TX-bound transaction
	 * that runs from CSMA through frame on-air through the ack_timeout_us
	 * RX window. RAIL fires TX_PACKET_SENT at frame-on-air-end (still well
	 * inside the transaction), so for AR=1 the driver must ignore that
	 * event and close on RX_PACKET_RECEIVED with details.is_ack=true (the
	 * RAIL-protocol-correct ACK match) or RX_ACK_TIMEOUT. Cleared on any
	 * closure path.
	 */
	volatile bool waiting_for_ack;

	/* RX path */
	struct k_fifo rx_fifo;
	struct k_fifo rx_free;
	struct k_thread rx_thread;
	volatile bool last_ack_fpb; /* ISR sets when ACK has FP; RX consumes */

	/* Calibration */
	volatile bool cal_needed;

	/* Event handler callback (set via configure()) */
	ieee802154_event_cb_t event_handler;

	/* Energy detection scan */
	energy_scan_done_cb_t scan_done_cb;
	int16_t scan_max_rssi;     /* quarter-dBm, track peak */
	uint32_t scan_start_us;    /* RAIL time at scan start */
	uint32_t scan_duration_us; /* total scan duration */
	sl_rail_multi_timer_t scan_timer;

	/* Source match table for frame pending bit */
	struct efr32_src_match src_match;

	/* MAC key storage for TX security */
	struct efr32_mac_keys mac_keys;

	/* Enhanced ACK IE storage */
	struct efr32_ack_ie_entry ack_ie_table[EFR32_ACK_IE_MAX_PEERS];

	/* get_time() 64-bit extension */
	struct k_spinlock time_lock;
	uint64_t base_ns;
	uint32_t last_rail_time;

#ifdef CONFIG_IEEE802154_EFR32_DEBUG
	struct efr32_debug_counters debug_counters;
#endif
};

#endif /* IEEE802154_EFR32_H_ */
