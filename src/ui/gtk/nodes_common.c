/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

/**
 * @ingroup gtk
 * @file
 *
 * Common GUI functions for displaying node information.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

#include "gtk-gnutella.h"

#include "nodes_common.h"
#include "settings.h"

#include "gtk/statusbar.h"

#include "if/bridge/ui2c.h"
#include "if/core/nodes.h"
#include "if/core/sockets.h"
#include "if/gui_property_priv.h"

#include "lib/ascii.h"
#include "lib/parse.h"
#include "lib/random.h"
#include "lib/str.h"

#include "lib/halloc.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

#define UPDATE_MIN	60		/**< Update screen every minute at least */

GtkMenu *
nodes_gui_get_popup_menu(void)
{
	return GTK_MENU(gui_popup_nodes());
}

/**
 * Compute info string for node.
 *
 * @return pointer to static data.
 */
const gchar *
nodes_gui_common_status_str(const gnet_node_status_t *n)
{
	static gchar gui_tmp[4096];
	const gchar *a;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		a = _("Connecting...");
		break;

	case GTA_NODE_HELLO_SENT:
		a = _("Hello sent");
		break;

	case GTA_NODE_WELCOME_SENT:
		a = _("Welcome sent");
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received) {
			size_t slen = 0;

			if (!GUI_PROPERTY(node_show_detailed_info)) {
				str_bprintf(gui_tmp, sizeof(gui_tmp),
					"TX=%u RX=%u Q=%u,%u%% %s",
					n->sent, n->received,
					n->mqueue_count, n->mqueue_percent_used,
					n->in_tx_swift_control ? " [SW]" :
					n->in_tx_flow_control ? " [FC]" : "");
				a = gui_tmp;
				break;
			}

			if (n->tx_compressed && GUI_PROPERTY(show_gnet_info_txc))
				slen += str_bprintf(gui_tmp, sizeof(gui_tmp), "TXc=%u,%d%%",
						n->sent, (int) (n->tx_compression_ratio * 100.0));
			else
				slen += str_bprintf(gui_tmp, sizeof(gui_tmp), "TX=%u",
						n->sent);

			if (
				GUI_PROPERTY(show_gnet_info_tx_speed) ||
				GUI_PROPERTY(show_gnet_info_tx_wire)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" (" /* ')' */);

				if (GUI_PROPERTY(show_gnet_info_tx_wire)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					"%s", compact_size(n->tx_written, show_metric_units()));
					is_first = FALSE;
				}

				if (GUI_PROPERTY(show_gnet_info_tx_speed))
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s%s", is_first ? "" : ", ",
						compact_rate(n->tx_bps, show_metric_units()));

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (n->rx_compressed && GUI_PROPERTY(show_gnet_info_rxc))
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RXc=%u,%d%%",
					n->received, (int) (n->rx_compression_ratio * 100.0));
			else
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" RX=%u", n->received);

			if (
				GUI_PROPERTY(show_gnet_info_rx_speed) ||
				GUI_PROPERTY(show_gnet_info_rx_wire)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" (" /* ')' */);

				if (GUI_PROPERTY(show_gnet_info_rx_wire)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s", compact_size(n->rx_given, show_metric_units()));
					is_first = FALSE;
				}

				if (GUI_PROPERTY(show_gnet_info_rx_speed))
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s%s", is_first ? "" : ", ",
						compact_rate(n->rx_bps, show_metric_units()));

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (
				GUI_PROPERTY(show_gnet_info_tx_queries) ||
				GUI_PROPERTY(show_gnet_info_rx_queries) ||
				GUI_PROPERTY(show_gnet_info_gen_queries) ||
				GUI_PROPERTY(show_gnet_info_sq_queries)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Query(" /* ')' */);

				if (GUI_PROPERTY(show_gnet_info_gen_queries)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"Gen=%u", n->squeue_sent);
					is_first = FALSE;
				}
				if (GUI_PROPERTY(show_gnet_info_sq_queries)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sQ=%u", is_first ? "" : ", ", n->squeue_count);
					is_first = FALSE;
				}
				if (GUI_PROPERTY(show_gnet_info_tx_queries)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sTX=%u", is_first ? "" : ", ", n->tx_queries);
					is_first = FALSE;
				}
				if (GUI_PROPERTY(show_gnet_info_rx_queries))
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_queries);

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (
				GUI_PROPERTY(show_gnet_info_tx_hits) ||
				GUI_PROPERTY(show_gnet_info_rx_hits)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" QHit(" /* ')' */);

				if (GUI_PROPERTY(show_gnet_info_tx_hits)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TX=%u", n->tx_qhits);
					is_first = FALSE;
				}
				if (GUI_PROPERTY(show_gnet_info_rx_hits))
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_qhits);

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (
				GUI_PROPERTY(show_gnet_info_tx_dropped) ||
				GUI_PROPERTY(show_gnet_info_rx_dropped)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Drop(" /* ')' */);

				if (GUI_PROPERTY(show_gnet_info_tx_dropped)) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TX=%u", n->tx_dropped);
					is_first = FALSE;
				}
				if (GUI_PROPERTY(show_gnet_info_rx_dropped))
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%sRX=%u", is_first ? "" : ", ", n->rx_dropped);

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ ")");
			}

			if (
				GUI_PROPERTY(show_gnet_info_shared_size) ||
				GUI_PROPERTY(show_gnet_info_shared_files)
			) {
				gboolean is_first = TRUE;

				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					" Lib(" /* ')' */);

				if (
					GUI_PROPERTY(show_gnet_info_shared_size) &&
					n->gnet_info_known
				) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s",
						compact_kb_size(n->gnet_files_count
							? n->gnet_kbytes_count : 0, show_metric_units()));
					is_first = FALSE;
				}
				if (
					GUI_PROPERTY(show_gnet_info_shared_files) &&
					n->gnet_info_known
				) {
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"%s#=%u", is_first ? "" : ", ", n->gnet_files_count);
				}
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* '(' */ "%s)", n->gnet_info_known ? "" : "?");
			}

			if (GUI_PROPERTY(show_gnet_info_qrp_stats)) {
				if (n->has_qrp)
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						" QRP=%u%%",
						(guint) (n->qrp_efficiency * 100.0));

				if (n->qrt_slots != 0)
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						" QRT(%s, g=%u, f=%u%%, t=%u%%, e=%u%%)",
						compact_size(n->qrt_slots, show_metric_units()),
						n->qrt_generation,
						n->qrt_fill_ratio, n->qrt_pass_throw,
						(guint) (n->qrp_efficiency * 100.0));
			}

			if (GUI_PROPERTY(show_gnet_info_dbw))
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Dup=%u Bad=%u W=%u H=%u S=%u E=%u",
				n->n_dups, n->n_bad, n->n_weird,
				n->n_hostile, n->n_spam, n->n_evil);

			if (GUI_PROPERTY(show_gnet_info_rt)) {
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" RT(avg=%u, last=%u", n->rt_avg, n->rt_last);	/* ) */
				if (n->tcp_rtt)
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						", tcp=%u", n->tcp_rtt);
				if (n->udp_rtt)
					slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						", udp=%u", n->udp_rtt);
				slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					/* ( */ ")");
			}

			slen += str_bprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				" Q=%u,%u%% %s",
				n->mqueue_count, n->mqueue_percent_used,
				n->in_tx_swift_control ? " [SW]" :
				n->in_tx_flow_control ? " [FC]" : "");
			a = gui_tmp;
		} else if (n->is_pseudo) {
			a = _("No UDP traffic yet");
		} else {
			a = _("Connected");
		}
		break;

	case GTA_NODE_SHUTDOWN:
		{
			str_bprintf(gui_tmp, sizeof(gui_tmp),
				_("Closing: %s [Stop in %us] RX=%u Q=%u,%u%%"),
				n->message, n->shutdown_remain, n->received,
				n->mqueue_count, n->mqueue_percent_used);
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a =  *n->message ? n->message : _("Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = _("Receiving hello");
		break;

	default:
		a = _("UNKNOWN STATUS");
	}

	return a;
}

struct add_node_context {
	guint32 flags;
	guint16 port;
	bool g2;
};

static void
add_node_helper(const host_addr_t *addrs, size_t n, gpointer data)
{
	struct add_node_context *ctx = data;

	g_assert(addrs);
	g_assert(ctx);
	g_assert(0 != ctx->port);

	if (n > 0) {
		const host_addr_t addr = addrs[random_value(n - 1)];
		if (ctx->g2) {
			guc_node_g2_add(addr, ctx->port, ctx->flags);
		} else {
			guc_node_add(addr, ctx->port, ctx->flags);
		}
	}

	WFREE(ctx);
}

/**
 * Try to connect to the list of nodes given by in following form:
 *
 * list = <node> | <node>, 1*<node>
 * port = 1..65535
 * hostname = 1*[a-zA-Z0-9.-]
 * node = hostname [":" <port>]
 *       | <IPv4 address>[":" <port>]
 *		 | <IPv6 address>
 *		 | "[" <IPv6 address> "]:" <port>
 * peer = ["tls:"]["g2:"]<node>
 *
 * If the port is omitted, the default port (GTA_PORT: 6346) is used.
 * The case-insensitive prefix "tls:" requests a TLS (encrypted) connection.
 */
void
nodes_gui_common_connect_by_name(const gchar *line)
{
	const gchar *q;

    g_assert(line);

	q = line;
	while ('\0' != *q) {
		const gchar *endptr, *hostname;
		size_t hostname_len;
		host_addr_t addr;
		guint32 flags;
    	guint16 port;
		bool g2;

		q = skip_ascii_spaces(q);
		if (',' == *q) {
			q++;
			continue;
		}

		addr = zero_host_addr;
		port = GTA_PORT;
		flags = SOCK_F_FORCE;
		endptr = NULL;
		hostname = NULL;
		hostname_len = 0;

		endptr = is_strcaseprefix(q, "tls:");
		if (endptr) {
			flags |= SOCK_F_TLS;
			q = endptr;
		}

		endptr = is_strcaseprefix(q, "g2:");
		if (endptr) {
			g2 = TRUE;
			q = endptr;
		} else {
			g2 = FALSE;
		}

		if (!string_to_host_or_addr(q, &endptr, &addr)) {
			g_message("expected hostname or IP address");
			break;
		}

		if (!is_host_addr(addr)) {
			hostname = q;
			hostname_len = endptr - q;
		}

		q = endptr;

		if (':' == *q) {
			gint error;

			port = parse_uint16(&q[1], &endptr, 10, &error);
			if (error || 0 == port) {
				g_message("cannot parse port");
				break;
			}

			q = skip_ascii_spaces(endptr);
		} else {
			q = skip_ascii_spaces(endptr);
			if ('\0' != *q && ',' != *q) {
				g_message("expected \",\" or \":\"");
				break;
			}
		}

		if (!hostname) {
			if (g2) {
				guc_node_g2_add(addr, port, flags);
			} else {
				guc_node_add(addr, port, flags);
			}
		} else {
			struct add_node_context *ctx;
			gchar *p;

			if ('\0' == hostname[hostname_len])	{
				p = NULL;
			} else {
				size_t n = 1 + hostname_len;

				g_assert(n > hostname_len);
				p = halloc(n);
				g_strlcpy(p, hostname, n);
				hostname = p;
			}

			WALLOC(ctx);
			ctx->port = port;
			ctx->flags = flags;
			ctx->g2 = g2;
			guc_adns_resolve(hostname, add_node_helper, ctx);

			HFREE_NULL(p);
		}
	}
}

static gboolean
nodes_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_network == main_gui_notebook_get_page();
}

void
nodes_gui_timer(time_t now)
{
    static time_t last_update;

    if (last_update == now)
        return;

	/*
	 * Usually don't perform updates if nobody is watching.  However,
	 * we do need to perform periodic cleanup of dead entries or the
	 * memory usage will grow.  Perform an update every UPDATE_MIN minutes
	 * at least.
	 *		--RAM, 28/12/2003
	 */

	if (
		nodes_gui_is_visible() ||
		delta_time(now, last_update) >= UPDATE_MIN
	) {
    	last_update = now;
		nodes_gui_update_display(now);
	}
}

/* vi: set ts=4 sw=4 cindent: */
