/*
 * Copyright (c) 2002-2003, Richard Eckart
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup shell
 * @file
 *
 * The "status" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "cmd.h"

#include "core/sockets.h"
#include "core/settings.h"
#include "core/nodes.h"

#include "if/gnet_property_priv.h"

#include "if/core/net_stats.h"
#include "if/core/share.h"
#include "if/dht/dht.h"

#include "lib/concat.h"
#include "lib/host_addr.h"
#include "lib/glib-missing.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static char dashes[] =
	"-----------------------------------------------------------------------";
static char equals[] =
	"=======================================================================";
static char space[] = " ";
static char empty[] = "";

/**
 * Displays assorted status information
 */
enum shell_reply
shell_exec_status(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *cur;
	const option_t options[] = {
		{ "i", &cur },
	};
	int parsed;
	char buf[2048];
	time_t now;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;	/* args[0] is first command argument */
	argc -= parsed;	/* counts only command arguments now */

	now = tm_time();

	/* Leading flags */
	{
		char flags[47];
		const char *fw;
		const char *fd;
		const char *pmp;
		const char *dht;

		/*
		 * The flags are displayed as followed:
		 *
		 * UMP          port mapping configured via UPnP
		 * NMP          port mapping configured via NAT-PMP
		 * pmp          port mapping available (UPnP or NAT-PMP), un-configured
		 * CLK			clock, GTKG expired
		 * !FD or FD	red or yellow bombs for fd shortage
		 * STL			upload stalls
		 * gUL/yUL/rUL  green, yellow or red upload early stalling levels
		 * CPU			cpu overloaded
		 * MOV			file moving
		 * SHA			SHA-1 rebuilding or verifying
		 * TTH			TTH rebuilding or verifying
		 * LIB			library rescan
		 * :FW or FW	indicates whether hole punching is possible
		 * udp or UDP	indicates UDP firewalling (lowercased for hole punching)
		 * TCP			indicates TCP-firewalled
		 * -			the happy face: no firewall
		 * sDH/lDH/bDH  seeded, own KUID looking or bootstrapping DHT
		 * A or P       active or passive DHT mode
		 * UP or LF		ultrapeer or leaf mode
		 */

		pmp = (GNET_PROPERTY(upnp_possible) || GNET_PROPERTY(natpmp_possible))
			? "pmp " : empty;
		if (
			(GNET_PROPERTY(enable_upnp) || GNET_PROPERTY(enable_natpmp)) &&
			GNET_PROPERTY(port_mapping_successful)
		) {
			pmp = GNET_PROPERTY(enable_natpmp) ? "NMP " : "UMP ";
		}

		if (dht_enabled()) {
			dht = empty;
			switch ((enum dht_bootsteps) GNET_PROPERTY(dht_boot_status)) {
			case DHT_BOOT_NONE:
			case DHT_BOOT_SHUTDOWN:
				break;
			case DHT_BOOT_SEEDED:
				dht = "sDH ";
				break;
			case DHT_BOOT_OWN:
				dht = "lDH ";
				break;
			case DHT_BOOT_COMPLETING:
				dht = "bDH ";
				break;
			case DHT_BOOT_COMPLETED:
				dht = dht_is_active() ? "A " : "P ";
				break;
			case DHT_BOOT_MAX_VALUE:
				g_assert_not_reached();
			}
		} else {
			dht = empty;
		}

		if (GNET_PROPERTY(is_firewalled) && GNET_PROPERTY(is_udp_firewalled)) {
			fw = GNET_PROPERTY(recv_solicited_udp) ? ":FW " : "FW ";
		} else if (GNET_PROPERTY(is_firewalled)) {
			fw = "TCP ";
		} else if (GNET_PROPERTY(is_udp_firewalled)) {
			fw = GNET_PROPERTY(recv_solicited_udp) ? "udp " : "UDP ";
		} else {
			fw = "- ";
		}

		if (GNET_PROPERTY(file_descriptor_runout)) {
			fd = "!FD ";
		} else if (GNET_PROPERTY(file_descriptor_shortage)) {
			fd = "FD ";
		} else {
			fd = empty;
		}

		gm_snprintf(flags, sizeof flags,
			"<%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s>",
			pmp,
			GNET_PROPERTY(download_queue_frozen) ? "DFZ " : empty,
			GNET_PROPERTY(ancient_version) ? "CLK " : empty,
			fd,
			GNET_PROPERTY(uploads_stalling) ? "STL " : empty,
			GNET_PROPERTY(uploads_bw_ignore_stolen) ? "gUL " : empty,
			GNET_PROPERTY(uploads_bw_uniform) ? "yUL " : empty,
			GNET_PROPERTY(uploads_bw_no_stealing) ? "rUL " : empty,
			GNET_PROPERTY(overloaded_cpu) ? "CPU " : empty,
			GNET_PROPERTY(file_moving) ? "MOV " : empty,
			(GNET_PROPERTY(sha1_rebuilding) || GNET_PROPERTY(sha1_verifying)) ?
				"SHA " : empty,
			(GNET_PROPERTY(tth_rebuilding) || GNET_PROPERTY(tth_verifying)) ?
				"TTH " : empty,
			GNET_PROPERTY(library_rebuilding) ? "LIB " : empty,
			fw, dht,
			settings_is_ultra() ? "UP" : "LF");

		gm_snprintf(buf, sizeof buf,
			"+%s+\n"
			"| %-18s%51s |\n"
			"|%s|\n",
			dashes, "Status", flags, equals);
		shell_write(sh, buf);
	}

	/* General status */ 
	{
		const char *blackout;
		short_string_t leaf_switch;
		short_string_t ultra_check;
	
		leaf_switch = timestamp_get_string(
						GNET_PROPERTY(node_last_ultra_leaf_switch));
		ultra_check = timestamp_get_string(
						GNET_PROPERTY(node_last_ultra_check));

		if (GNET_PROPERTY(is_firewalled) && GNET_PROPERTY(is_udp_firewalled)) {
			blackout =
				GNET_PROPERTY(recv_solicited_udp) ?  "TCP,udp" : "TCP,UDP";
		} else if (GNET_PROPERTY(is_firewalled)) {
			blackout = "TCP";
		} else if (GNET_PROPERTY(is_udp_firewalled)) {
			blackout = GNET_PROPERTY(recv_solicited_udp) ? "udp" : "UDP";
		} else {
			blackout = "None";
		}

		gm_snprintf(buf, sizeof buf,
			"|   Mode: %-9s                   Last Switch: %-19s%2s|\n"
			"| Uptime: %-9s                    Last Check: %-19s%2s|\n"
			"|   Port: %-9u                      Blackout: %-7s%14s|\n"
			"|%s|\n",
			GNET_PROPERTY(online_mode)
				? node_peermode_to_string(GNET_PROPERTY(current_peermode))
				: "offline",
			GNET_PROPERTY(node_last_ultra_leaf_switch)
				? leaf_switch.str : "never", space,
			short_time(delta_time(now, GNET_PROPERTY(start_stamp))),
			GNET_PROPERTY(node_last_ultra_check)
				? ultra_check.str : "never", space,
			socket_listen_port(), blackout, space,
			equals);
		shell_write(sh, buf);
	}

	/* IPv4 info */ 
	switch (GNET_PROPERTY(network_protocol)) {
	case NET_USE_BOTH:
	case NET_USE_IPV4:
		gm_snprintf(buf, sizeof buf,
			"| IPv4: %-44s Since: %-12s|\n",
			host_addr_to_string(listen_addr()),
			short_time(delta_time(now, GNET_PROPERTY(current_ip_stamp))));
		shell_write(sh, buf);
	}

	/* IPv6 info */ 
	switch (GNET_PROPERTY(network_protocol)) {
	case NET_USE_BOTH:
		gm_snprintf(buf, sizeof buf, "|%s|\n", dashes);
		shell_write(sh, buf);
		/* FALL THROUGH */
	case NET_USE_IPV6:
		gm_snprintf(buf, sizeof buf,
			"| IPv6: %-44s Since: %-12s|\n",
			host_addr_to_string(listen_addr6()),
			short_time(delta_time(now, GNET_PROPERTY(current_ip6_stamp))));
		shell_write(sh, buf);
	}

	/* Node counts */
	gm_snprintf(buf, sizeof buf,
		"|%s|\n"
		"| Peers: %-7u Ultra %4u/%-7u  Leaf %4u/%-6u  Legacy %4u/%-4u |\n"
		"|            Downloads %4u/%-4u  Uploads %4u/%-7u Browse %4u/%-4u |\n"
		"|%s|\n",
		equals,
		GNET_PROPERTY(node_ultra_count)
			+ GNET_PROPERTY(node_leaf_count)
			+ GNET_PROPERTY(node_normal_count),
		GNET_PROPERTY(node_ultra_count),
		settings_is_ultra() ?
			GNET_PROPERTY(max_connections) : GNET_PROPERTY(max_ultrapeers),
		GNET_PROPERTY(node_leaf_count),
		GNET_PROPERTY(max_leaves),
		GNET_PROPERTY(node_normal_count),
		GNET_PROPERTY(normal_connections),
		GNET_PROPERTY(dl_active_count), GNET_PROPERTY(dl_running_count),
		GNET_PROPERTY(ul_running), GNET_PROPERTY(ul_registered),
		GNET_PROPERTY(html_browse_served) + GNET_PROPERTY(qhits_browse_served),
		GNET_PROPERTY(html_browse_count) + GNET_PROPERTY(qhits_browse_count),
		equals);
	shell_write(sh, buf);

	/* Bandwidths */
	{	
		const bool metric = GNET_PROPERTY(display_metric_units);
		short_string_t gnet_in, http_in, leaf_in, gnet_out, http_out, leaf_out;
		short_string_t dht_in, dht_out;
		gnet_bw_stats_t bw_stats, bw2_stats;
		const char *bwtype = cur ? "(cur)" : "(avg)";

		gnet_get_bw_stats(BW_GNET_IN, &bw_stats);
		gnet_get_bw_stats(BW_GNET_UDP_IN, &bw2_stats);
		gnet_in = short_rate_get_string(
			cur ? bw_stats.current + bw2_stats.current
				: bw_stats.average + bw2_stats.average, metric);

		gnet_get_bw_stats(BW_GNET_OUT, &bw_stats);
		gnet_get_bw_stats(BW_GNET_UDP_OUT, &bw2_stats);
		gnet_out = short_rate_get_string(
			cur ? bw_stats.current + bw2_stats.current
				: bw_stats.average + bw2_stats.average, metric);
		
		gnet_get_bw_stats(BW_HTTP_IN, &bw_stats);
		http_in = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);
		
		gnet_get_bw_stats(BW_HTTP_OUT, &bw_stats);
		http_out = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);
		
		gnet_get_bw_stats(BW_LEAF_IN, &bw_stats);
		leaf_in = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);

		gnet_get_bw_stats(BW_LEAF_OUT, &bw_stats);
		leaf_out = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);

		gnet_get_bw_stats(BW_DHT_IN, &bw_stats);
		dht_in = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);

		gnet_get_bw_stats(BW_DHT_OUT, &bw_stats);
		dht_out = short_rate_get_string(
			cur ? bw_stats.current : bw_stats.average, metric);

		gm_snprintf(buf, sizeof buf,
			"| %-70s|\n"
			"|%71s|\n"
			"| %5s  In:  %13s %13s %13s %13s   |\n"
			"| %5s Out:  %13s %13s %13s %13s   |\n",
			"Bandwidth:"
				"       Gnutella          Leaf          HTTP           DHT",
			dashes,
			bwtype, gnet_in.str, leaf_in.str, http_in.str, dht_in.str,
			bwtype, gnet_out.str, leaf_out.str, http_out.str, dht_out.str);
		shell_write(sh, buf);
	}
	
	{
		char line[128];
		bool metric = GNET_PROPERTY(display_metric_units);

		gm_snprintf(buf, sizeof buf, "|%s|\n", equals);
		shell_write(sh, buf);
		concat_strings(line, sizeof line,
			"Shares ",
			uint64_to_string(shared_files_scanned()),
			" file",
			shared_files_scanned() == 1 ? "" : "s",
			" ",
			short_kb_size(shared_kbytes_scanned(), metric),
			" total",
			(void *) 0);
		gm_snprintf(buf, sizeof buf,
			"| %-35s Up: %-11s Down: %-11s |\n",
			line,
			short_byte_size(GNET_PROPERTY(ul_byte_count), metric),
			short_byte_size2(GNET_PROPERTY(dl_byte_count), metric));
		shell_write(sh, buf);
		gm_snprintf(buf, sizeof buf, "+%s+\n", dashes);
		shell_write(sh, buf);
	}

	return REPLY_READY;
}

const char *
shell_summary_status(void)
{
	return "Display general status";
}

const char *
shell_help_status(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);
	
	return "status [-i]\n"
		"Display status pane summary\n"
		"-i : display instantaneous bandwidth instead of average\n"
		"Upper-right corner flags mimic status icons in the GUI:\n"
		"(from left to right in lightening order)\n"
		"  UMP           port mapping configured via UPnP\n"
		"  NMP           port mapping configured via NAT-PMP\n"
		"  pmp           port mapping available (UPnP or NAT-PMP)\n"
		"  DFZ           download queue is frozen\n"
		"  CLK           clock, GTKG expired\n"
		"  !FD or FD     red or yellow bombs for fd shortage\n"
		"  STL           upload stalls\n"
		"  gUL, yUL, rUL green, yellow or red upload early stalling levels\n"
		"  CPU           cpu overloaded\n"
		"  MOV           file moving\n"
		"  SHA           SHA-1 rebuilding or verifying\n"
		"  TTH           TTH rebuilding or verifying\n"
		"  LIB           library rescan\n"
		"  FW or :FW     indicates firewalled status or hole punching ability\n"
		"  UDP or udp    is UDP-firewalled only (lowercased = hole punching)\n"
		"  TCP           is TCP-firewalled only\n"
		"  -             the happy face: no firewall\n"
		"  sDH, lDH, bDH seeded, own KUID looking or bootstrapping DHT\n"
		"  A or P        active or passive DHT mode\n"
		"  UP or LF      ultrapeer or leaf mode\n";
}

/* vi: set ts=4 sw=4 cindent: */
