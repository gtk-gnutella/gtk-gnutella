/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
 *
 * Common GUI functions for displaying node information.
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#include "gui.h"
#include "nodes_gui_common.h"
#include "gui_property_priv.h"

RCSID("$Id$");

static gchar gui_tmp[4096];

/*
 * nodes_gui_common_status_str
 *
 * Compute info string for node.
 * Returns pointer to static data.
 */
const gchar *nodes_gui_common_status_str(
	const gnet_node_status_t *n, time_t now)
{
	const gchar *a;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_NODE_HELLO_SENT:
		a = "Hello sent";
		break;

	case GTA_NODE_WELCOME_SENT:
		a = "Welcome sent";
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received) {
			gint slen = 0;

			if (!node_show_detailed_info) {
				gm_snprintf(gui_tmp, sizeof(gui_tmp),
					"TX=%d RX=%d Q=%d,%d%% %s",
					n->sent, n->received,
					n->mqueue_count, n->mqueue_percent_used,
					n->in_tx_swift_control ? " [SW]" :
					n->in_tx_flow_control ? " [FC]" : "");
				a = gui_tmp;
				break;
			}

			if (n->tx_compressed && show_gnet_info_txc)
				slen += gm_snprintf(gui_tmp, sizeof(gui_tmp), "TXc=%d,%d%%",
					n->sent, (gint) (n->tx_compression_ratio * 100));
			else
				slen += gm_snprintf(gui_tmp, sizeof(gui_tmp), "TX=%d", n->sent);

			if (show_gnet_info_tx_speed)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" (%.1f k/s)", n->tx_bps);

			if (n->rx_compressed && show_gnet_info_rxc)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RXc=%d,%d%%",
					n->received, (gint) (n->rx_compression_ratio * 100));
			else
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RX=%d", n->received);

			if (show_gnet_info_rx_speed)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" (%.1f k/s)", n->rx_bps);

			if (
				show_gnet_info_tx_queries || show_gnet_info_rx_queries ||
				show_gnet_info_gen_queries || show_gnet_info_sq_queries
			) {
				gboolean is_first = TRUE;

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Query(" /* ')' */);

				if (show_gnet_info_gen_queries) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"Gen=%d", n->squeue_sent);
					is_first = FALSE;
				}
				if (show_gnet_info_sq_queries) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sQ=%d", is_first ? "" : ", ", n->squeue_count);
					is_first = FALSE;
				}
				if (show_gnet_info_tx_queries) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sTX=%u", is_first ? "" : ", ", n->tx_queries);
					is_first = FALSE;
				}
				if (show_gnet_info_rx_queries)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_queries);

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (show_gnet_info_tx_hits || show_gnet_info_rx_hits) {
				gboolean is_first = TRUE;

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" QHit(" /* ')' */);

				if (show_gnet_info_tx_hits) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TX=%u", n->tx_qhits);
					is_first = FALSE;
				}
				if (show_gnet_info_rx_hits)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_qhits);

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (show_gnet_info_tx_dropped || show_gnet_info_rx_dropped) {
				gboolean is_first = TRUE;

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Drop(" /* ')' */);

				if (show_gnet_info_tx_dropped) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TX=%u", n->tx_dropped);
					is_first = FALSE;
				}
				if (show_gnet_info_rx_dropped)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_dropped);

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (show_gnet_info_shared_size || show_gnet_info_shared_files) {
				gboolean is_first = TRUE;

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Lib(" /* ')' */);

				if (show_gnet_info_shared_size && n->gnet_info_known) {
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s", compact_kb_size(
							n->gnet_files_count ? n->gnet_kbytes_count : 0));
					is_first = FALSE;
				}
				if (show_gnet_info_shared_files && n->gnet_info_known)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s#=%u", is_first ? "" : ", ", n->gnet_files_count);

				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ "%s)", n->gnet_info_known ? "" : "?");
			}

			if (show_gnet_info_qrp_stats) {
				if (n->has_qrp)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						" QRP=%u%%",
						(guint) (n->qrp_efficiency * 100.0));

				if (n->qrt_slots != 0)
					slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						" QRT(%s, g=%d, f=%d%%, t=%d%%, e=%d%%)",
						compact_size(n->qrt_slots), n->qrt_generation,
						n->qrt_fill_ratio, n->qrt_pass_throw,
						(guint) (n->qrp_efficiency * 100.0));
			}

			if (show_gnet_info_dbw)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Dup=%d Bad=%d W=%d", n->n_dups, n->n_bad, n->n_weird);

			if (show_gnet_info_rt)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" RT(avg=%d, last=%d)", n->rt_avg, n->rt_last);

			slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Q=%d,%d%% %s",
				n->mqueue_count, n->mqueue_percent_used,
				n->in_tx_swift_control ? " [SW]" :
				n->in_tx_flow_control ? " [FC]" : "");
			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_NODE_SHUTDOWN:
		{
			gm_snprintf(gui_tmp, sizeof(gui_tmp),
				"Closing: %s [Stop in %ds] RX=%d Q=%d,%d%%",
				n->message, n->shutdown_remain, n->received,
				n->mqueue_count, n->mqueue_percent_used);
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a =  *n->message ? n->message : "Removing";
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = "Receiving hello";
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	return a;
}

/*
 * nodes_gui_common_flags_str
 *
 * Display a summary of the node flags:
 *
 *    012345678 (offset)
 *    NIrwqTRPFh
 *    ^^^^^^^^^^
 *    |||||||||+ hops flow triggerd (h), or total query flow control (f)
 *    ||||||||+  flow control (F), or pending data in queue (d)
 *    |||||||+   indicates whether we're a push proxy (P) / node is proxy (p)
 *    ||||||+    indicates whether RX is compressed
 *    |||||+     indicates whether TX is compressed
 *    ||||+      indicates whether we sent/received a QRT, or send/receive one
 *    |||+       indicates whether node is writable
 *    ||+        indicates whether node is readable
 *    |+         indicates connection type (Incoming, Outgoing, Ponging)
 *    +          indicates peer mode (Normal, Ultra, Leaf)
 */
const gchar *nodes_gui_common_flags_str(const gnet_node_flags_t *flags)
{
	static gchar status[] = "NIrwqTRPFh";

	switch (flags->peermode) {
		case NODE_P_UNKNOWN:	status[0] = '-'; break;
		case NODE_P_ULTRA:		status[0] = 'U'; break;
		case NODE_P_NORMAL:		status[0] = 'N'; break;
		case NODE_P_LEAF:		status[0] = 'L'; break;
		case NODE_P_CRAWLER:	status[0] = 'C'; break;
		default:				g_assert(0); break;
	}

	status[1] = flags->incoming ? 'I' : 'O';
	status[2] = flags->readable ? 'r' : '-';
	status[3] = flags->writable ? 'w' : '-';

	switch (flags->qrt_state) {
		case QRT_S_SENT: case QRT_S_RECEIVED:		status[4] = 'Q'; break;
		case QRT_S_SENDING: case QRT_S_RECEIVING:	status[4] = 'q'; break;
		case QRT_S_PATCHING:						status[4] = 'p'; break;
		default:									status[4] = '-';
	}

	status[5] = flags->tx_compressed ? 'T' : '-';
	status[6] = flags->rx_compressed ? 'R' : '-';

	if (flags->is_push_proxied)  status[7] = 'P';
	else if (flags->is_proxying) status[7] = 'p';
	else status[7] = '-';

	if (flags->in_tx_swift_control) status[8]     = 'S';
	else if (flags->in_tx_flow_control) status[8] = 'F';
	else if (!flags->mqueue_empty) status[8]      = 'd';
	else status[8]                                = '-';

	if (flags->hops_flow == 0)
		status[9] = 'f';
	else if (flags->hops_flow < GTA_NORMAL_TTL)
		status[9] = 'h';
	else
		status[9] = '-';

	status[sizeof(status) - 1] = '\0';
	return status;
}

