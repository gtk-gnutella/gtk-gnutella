/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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
			if (n->tx_compressed)
				slen += gm_snprintf(gui_tmp, sizeof(gui_tmp), "TXc=%d,%d%%",
					n->sent, (gint) (n->tx_compression_ratio * 100));
			else
				slen += gm_snprintf(gui_tmp, sizeof(gui_tmp), "TX=%d", n->sent);

			slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" (%.1f k/s)", n->tx_bps);

			if (n->rx_compressed)
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RXc=%d,%d%%",
					n->received, (gint) (n->rx_compression_ratio * 100));
			else
				slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RX=%d", n->received);

			slen += gm_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" (%.1f k/s)"
				" Query(TX=%d, Q=%d) Drop(TX=%d, RX=%d)"
				" Dup=%d Bad=%d W=%d RT(avg=%d, last=%d) Q=%d,%d%% %s",
				n->rx_bps,
				n->squeue_sent, n->squeue_count,
				n->tx_dropped, n->rx_dropped, n->n_dups, n->n_bad, n->n_weird,
				n->rt_avg, n->rt_last, n->mqueue_count, n->mqueue_percent_used,
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
 *    NIrwqTRFh
 *    ^^^^^^^^^
 *    ||||||||+ hops flow triggerd (h), or total query flow control (f)
 *    |||||||+  flow control (F), or pending data in queue (d)
 *    ||||||+   indicates whether RX is compressed
 *    |||||+    indicates whether TX is compressed
 *    ||||+     indicates whether we sent/received a QRT, or send/receive one
 *    |||+      indicates whether node is writable
 *    ||+       indicates whether node is readable
 *    |+        indicates connection type (Incoming, Outgoing, Ponging)
 *    +         indicates peer mode (Normal, Ultra, Leaf)
 */
const gchar *nodes_gui_common_flags_str(const gnet_node_flags_t *flags)
{
	static gchar status[] = "NIrwqTRFh";

	switch (flags->peermode) {
		case NODE_P_UNKNOWN:	status[0] = '-'; break;
		case NODE_P_ULTRA:		status[0] = 'U'; break;
		case NODE_P_NORMAL:		status[0] = 'N'; break;
		case NODE_P_LEAF:		status[0] = 'L'; break;
		case NODE_P_CRAWLER:	status[0] = 'C'; break;
		default:				g_assert(0); break;
	}

	status[1] = flags->incoming ? 'I' : 'O';
	if (flags->temporary)
		status[1] = 'P';
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

	if (flags->in_tx_flow_control) status[7] = 'F';
	else if (!flags->mqueue_empty) status[7] = 'd';
	else status[7] = '-';

	if (flags->hops_flow == 0)
		status[8] = 'f';
	else if (flags->hops_flow < GTA_NORMAL_TTL)
		status[8] = 'h';
	else
		status[8] = '-';

	status[sizeof(status) - 1] = '\0';
	return status;
}

