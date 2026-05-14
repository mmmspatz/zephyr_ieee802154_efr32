/*
 * Copyright (c) 2026 LeafLabs, LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Debug shell commands for the EFR32 IEEE 802.15.4 driver.
 * Only compiled when CONFIG_IEEE802154_EFR32_DEBUG=y.
 */

#include <zephyr/shell/shell.h>
#include <zephyr/device.h>

#include <sl_rail.h>
#include <sl_rail_ieee802154.h>

#include "ieee802154_efr32.h"

static struct efr32_802154_data *get_data(void)
{
	const struct device *dev = DEVICE_DT_INST_GET(0);

	return (struct efr32_802154_data *)dev->data;
}

static int cmd_counters(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();
	struct efr32_debug_counters *c = &data->debug_counters;

	shell_print(sh, "--- TX ---");
	shell_print(sh, "  tx_packets:       %u", c->tx_packets);
	shell_print(sh, "  tx_started:       %u", c->tx_started);
	shell_print(sh, "  tx_aborted:       %u", c->tx_aborted);
	shell_print(sh, "  tx_blocked:       %u", c->tx_blocked);
	shell_print(sh, "  tx_underflow:     %u", c->tx_underflow);
	shell_print(sh, "  tx_channel_busy:  %u", c->tx_channel_busy);
	shell_print(sh, "  tx_submitted:     %u", c->tx_submitted);
	shell_print(sh, "  tx_finalized:     %u", c->tx_finalized);
	shell_print(sh, "  tx_sched_missed:  %u", c->tx_scheduled_missed);
	shell_print(sh, "  tx_start_rejected:%u", c->tx_start_rejected);

	shell_print(sh, "--- ACK TX ---");
	shell_print(sh, "  ack_tx:           %u", c->ack_tx);
	shell_print(sh, "  ack_tx_aborted:   %u", c->ack_tx_aborted);
	shell_print(sh, "  ack_tx_blocked:   %u", c->ack_tx_blocked);
	shell_print(sh, "  ack_tx_underflow: %u", c->ack_tx_underflow);
	shell_print(sh, "  ack_tx_fp_set:    %u", c->ack_tx_fp_set);
	shell_print(sh, "  ack_tx_fp_fail:   %u", c->ack_tx_fp_fail);
	shell_print(sh, "  ack_tx_fp_addr_f: %u", c->ack_tx_fp_addr_fail);
	shell_print(sh, "  ack_timeout:      %u", c->ack_timeout);
	shell_print(sh, "  enh_ack_sent:     %u", c->enh_ack_sent);
	shell_print(sh, "  enh_ack_fail:     %u", c->enh_ack_fail);
	shell_print(sh, "  enh_ack_skip:     %u", c->enh_ack_skip);
	shell_print(sh, "  ie_injected:      %u", c->ie_injected);
	shell_print(sh, "  ie_no_match:      %u", c->ie_no_match);
	shell_print(sh, "  last_dreq_fcf:    0x%04x (fv=%u, avail=%u)", c->last_data_req_fcf,
		    c->last_data_req_fv, c->last_data_req_avail);
	shell_print(sh, "  last_dreq_bytes:  %02x %02x %02x %02x %02x %02x %02x %02x",
		    c->last_data_req_bytes[0], c->last_data_req_bytes[1], c->last_data_req_bytes[2],
		    c->last_data_req_bytes[3], c->last_data_req_bytes[4], c->last_data_req_bytes[5],
		    c->last_data_req_bytes[6], c->last_data_req_bytes[7]);

	shell_print(sh, "--- RX ---");
	shell_print(sh, "  rx_packets:       %u", c->rx_packets);
	shell_print(sh, "  rx_crc_error:     %u", c->rx_crc_error);
	shell_print(sh, "  rx_frame_error:   %u", c->rx_frame_error);
	shell_print(sh, "  rx_addr_filtered: %u", c->rx_addr_filtered);
	shell_print(sh, "  rx_overflow:      %u", c->rx_overflow);
	shell_print(sh, "  rx_no_buffer:     %u", c->rx_no_buffer);
	shell_print(sh, "  rx_fail:          %u", c->rx_fail);

	shell_print(sh, "--- Misc ---");
	shell_print(sh, "  calibrations:     %u", c->calibrations);
	shell_print(sh, "  data_requests:    %u", c->data_requests);
	shell_print(sh, "  cca_start:        %u", c->cca_start);
	shell_print(sh, "  cca_retry:        %u", c->cca_retry);
	shell_print(sh, "  cca_success:      %u", c->cca_success);
	shell_print(sh, "  events_missed:    %u", c->events_missed);
	shell_print(sh, "  dmp_unscheduled:  %u", c->dmp_unscheduled);
	shell_print(sh, "  dmp_scheduled:    %u", c->dmp_scheduled);
	shell_print(sh, "  sched_status:     %u", c->sched_status_events);
	shell_print(sh, "  sched_tx_fail:    %u", c->sched_tx_fail);
	shell_print(sh, "  sched_tx_error:   %u", c->sched_tx_error);
	shell_print(sh, "  sched_other_fail: %u", c->sched_other_fail);
	shell_print(sh, "  last_sched_st:    0x%02x (rail=0x%x)", c->last_sched_status,
		    c->last_sched_rail_status);

	shell_print(sh, "--- CSL ---");
	shell_print(sh, "  rx_slot_end:      %u", c->rx_slot_end);
	shell_print(sh, "  rx_slot_missed:   %u", c->rx_slot_missed);
	shell_print(sh, "  rx_slot_sched_skip: %u", c->rx_slot_sched_skip);
	shell_print(sh, "  rx_slot_sched_fail: %u", c->rx_slot_sched_fail);
	shell_print(sh, "  tx_sched_missed:  %u", c->tx_sched_missed);
	shell_print(sh, "  csl_phase_upd:    %u", c->csl_phase_updates);
	shell_print(sh, "  csl_no_period:    %u", c->csl_patch_no_period);
	shell_print(sh, "  csl_scan_fail:    %u", c->csl_patch_scan_fail);
	shell_print(sh, "--- IE cfg ---");
	shell_print(sh, "  ie_cfg_added:     %u", c->ie_cfg_added);
	shell_print(sh, "  ie_cfg_removed:   %u", c->ie_cfg_removed);
	shell_print(sh, "  ie_cfg_purged:    %u", c->ie_cfg_purged);
	shell_print(sh, "  csl0_with_ie:     %u", c->cfg_csl_zero_with_ie);
	shell_print(sh, "  ie_when_csl0:     %u", c->cfg_ie_when_csl_zero);
	shell_print(sh, "  enh_ack_ie_empty: %u", c->enh_ack_ie_empty);
	shell_print(sh, "--- PM (SED) ---");
	shell_print(sh, "  pm_suspend:       %u", c->pm_suspend_count);
	shell_print(sh, "  pm_resume:        %u", c->pm_resume_count);
	shell_print(sh, "  pm_sus_blocked:   %u", c->pm_suspend_blocked);

	return 0;
}

static int cmd_reset(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();

	memset(&data->debug_counters, 0, sizeof(data->debug_counters));
	shell_print(sh, "Counters reset");
	return 0;
}

static int cmd_state(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();
	sl_rail_handle_t handle = data->rail_handle;

	sl_rail_radio_state_t radio_state = sl_rail_get_radio_state(handle);
	bool ieee_enabled = sl_rail_ieee802154_is_enabled(handle);

	const char *state_str;

	/* Note: SL_RAIL_RF_STATE_ACTIVE == SL_RAIL_RF_STATE_IDLE (both 0x01) */
	switch (radio_state) {
	case SL_RAIL_RF_STATE_INACTIVE:
		state_str = "INACTIVE";
		break;
	case SL_RAIL_RF_STATE_IDLE:
		state_str = "IDLE";
		break;
	case SL_RAIL_RF_STATE_RX:
		state_str = "RX";
		break;
	case SL_RAIL_RF_STATE_TX:
		state_str = "TX";
		break;
	case SL_RAIL_RF_STATE_RX_ACTIVE:
		state_str = "RX_ACTIVE";
		break;
	case SL_RAIL_RF_STATE_TX_ACTIVE:
		state_str = "TX_ACTIVE";
		break;
	default:
		state_str = "UNKNOWN";
		break;
	}

	shell_print(sh, "radio_state:      %s (0x%02x)", state_str, radio_state);
	shell_print(sh, "ieee802154_enabled: %s", ieee_enabled ? "yes" : "no");
	shell_print(sh, "channel:          %u",
		    data->channel == EFR32_NO_CHANNEL ? 0 : data->channel);
	shell_print(sh, "tx_power:         %d deci-dBm", data->tx_power);
	shell_print(sh, "started:          %s", data->started ? "yes" : "no");
	shell_print(sh, "rx_on_when_idle:  %s", data->rx_on_when_idle ? "yes" : "no");
	shell_print(sh, "cal_needed:       %s", data->cal_needed ? "yes" : "no");
	shell_print(sh, "tx_retry_count:   %u", data->tx_retry_count);
	shell_print(sh, "csl_period:       %u", data->csl_period);
	shell_print(sh, "csl_sample_time:  %lld ns", data->csl_sample_time);

	return 0;
}

static int cmd_srcmatch(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();
	struct efr32_src_match *sm = &data->src_match;

	shell_print(sh, "src_match enabled: %s", sm->enabled ? "yes" : "no");
	shell_print(sh, "short addresses (%u):", sm->short_count);
	for (int i = 0; i < sm->short_count; i++) {
		shell_print(sh, "  [%d] 0x%04x", i, sm->short_addrs[i]);
	}
	shell_print(sh, "extended addresses (%u):", sm->ext_count);
	for (int i = 0; i < sm->ext_count; i++) {
		shell_print(sh, "  [%d] %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", i,
			    sm->ext_addrs[i][0], sm->ext_addrs[i][1], sm->ext_addrs[i][2],
			    sm->ext_addrs[i][3], sm->ext_addrs[i][4], sm->ext_addrs[i][5],
			    sm->ext_addrs[i][6], sm->ext_addrs[i][7]);
	}

	return 0;
}

static int cmd_mac_keys(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();
	struct efr32_mac_keys *mk = &data->mac_keys;

	shell_print(sh, "current_slot: %u", mk->current_slot);
	shell_print(sh, "key_id:       %u", mk->key_id);
	for (int i = 0; i < EFR32_MAC_KEY_COUNT; i++) {
		/* Print only first 4 bytes as a fingerprint — confirm presence,
		 * do not leak key material into logs.
		 */
		shell_print(sh, "slot[%d]: fc=%u  fp=%02x%02x%02x%02x..", i,
			    mk->slots[i].frame_counter, mk->slots[i].key[0], mk->slots[i].key[1],
			    mk->slots[i].key[2], mk->slots[i].key[3]);
	}
	return 0;
}

/*
 * Print just the OT-level CSL period the driver currently has
 * configured. Separate from `efr32_radio state` so a tight polling
 * caller doesn't drag the rest of the state dump along with it —
 * and, crucially, doesn't take the sl_rail_get_radio_state() path,
 * which serialises with the RAIL event ISR and can destabilise a
 * live CSL child when polled tightly.
 */
static int cmd_csl_period(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct efr32_802154_data *data = get_data();

	shell_print(sh, "csl_period: %u", data->csl_period);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	efr32_radio_cmds, SHELL_CMD(counters, NULL, "Dump debug counters", cmd_counters),
	SHELL_CMD(reset, NULL, "Reset debug counters", cmd_reset),
	SHELL_CMD(state, NULL, "Print radio state", cmd_state),
	SHELL_CMD(srcmatch, NULL, "Dump source match table", cmd_srcmatch),
	SHELL_CMD(mac_keys, NULL, "Dump MAC key slots (current/id + per-slot FC + fingerprint)",
		  cmd_mac_keys),
	SHELL_CMD(csl_period, NULL, "Print OT-level CSL period (no RAIL state read)",
		  cmd_csl_period),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(efr32_radio, &efr32_radio_cmds, "EFR32 802.15.4 radio debug commands", NULL);
