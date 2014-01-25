/*
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "gtk/notebooks.h"

#include "gnet_stats_common.h"
#include "settings.h"

#include "if/core/net_stats.h"
#include "if/bridge/ui2c.h"

#include "lib/str.h"
#include "lib/stringify.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Gets the string associated with the message type.
 */
const gchar *
msg_type_str(gint value)
{
	static const char * const strs[] = {
		N_("Unknown"),
		N_("Ping"),
		N_("Pong"),
		N_("Bye"),
		N_("QRP"),
		N_("HSEP"),
		N_("RUDP"),
		N_("Vendor spec."),
		N_("Vendor std."),
		N_("Push"),
		N_("Query"),
		N_("Query hit"),
		N_("DHT (truncated)"),
		N_("DHT Ping"),
		N_("DHT Pong"),
		N_("DHT Store"),
		N_("DHT Store Ack"),
		N_("DHT Find Node"),
		N_("DHT Found Node"),
		N_("DHT Find Value"),
		N_("DHT Value"),
		N_("Total"),
	};

	STATIC_ASSERT(G_N_ELEMENTS(strs) == MSG_TYPE_COUNT);

	if ((guint) value >= G_N_ELEMENTS(strs)) {
		g_carp("%s(): requested general_type_str %d is invalid",
			G_STRFUNC, value);
		return "";
	}

	return _(strs[value]);
}

gint
msg_type_str_size(void)
{
	return MSG_TYPE_COUNT;
}

/**
 * Gets the string associated with the drop reason.
 */
const gchar *
msg_drop_str(gint value)
{
	g_return_val_if_fail(UNSIGNED(value) < MSG_DROP_REASON_COUNT, "");
	return _(guc_gnet_stats_drop_reason_to_string(value));
}

/**
 * Gets the string associated with the general message.
 */
const gchar *
general_type_str(gint value)
{
	static const char * const strs[] = {
		N_("Routing errors"),
		N_("Routing table chunks"),
		N_("Routing table message capacity"),
		N_("Routing table message count"),
		N_("Routing through transient node avoided"),
		N_("Duplicates with higher TTL"),
		N_("SPAM SHA1 database hits"),
		N_("SPAM filename and size hits"),
		N_("SPAM fake hits"),
		N_("SPAM duplicate hits"),
		N_("SPAM dynamically caught hostile IP addresses"),
		N_("SPAM dynamically caught hostile IP held"),
		N_("SPAM spotted spamming IP addresses held"),
		N_("Searches to local DB"),
		N_("Hits on local DB"),
		N_("Hits on local partial files"),
		N_("Hits on \"what's new?\" queries"),
		N_("Query hits received for local queries"),
		N_("Query hits received for OOB-proxied queries"),
		N_("Queries requesting OOB hit delivery"),
		N_("Stripped OOB flag on queries"),
		N_("Ignored OOB queries due to unclaimed hits"),
		N_("Duplicate OOB-proxied queries"),
		N_("OOB hits received for OOB-proxied queries"),
		N_("OOB hits bearing alien IP address"),
		N_("OOB hits ignored due to identified spamming address"),
		N_("OOB hits ignored due to unsecure promise from known secure host"),
		N_("Unclaimed locally-generated OOB hits"),
		N_("Partially claimed locally-generated OOB hits"),
		N_("Spurious OOB hit claiming received"),
		N_("Unrequested OOB hits received"),
		N_("Received query hits for untracked queries"),
		N_("Tracked query MUIDs"),
		N_("Compacted queries"),
		N_("Bytes saved by compacting"),
		N_("UTF8 queries"),
		N_("SHA1 queries"),
		N_("\"What's New?\" queries"),
		N_("GUESS queries"),
		N_("GUESS queries (0.2)"),
		N_("GUESS link cache size"),
		N_("GUESS cached query keys held"),
		N_("GUESS cached 0.2 hosts held"),
		N_("GUESS locally generated queries"),
		N_("GUESS currently running queries"),
		N_("GUESS hits received for locally generated queries"),
		N_("GUESS hosts queried"),
		N_("GUESS hosts sending back an acknowledgment"),
		N_("Broadcasted push messages"),
		N_("Push-proxy UDP relayed messages"),
		N_("Push-proxy TCP relayed messages"),
		N_("Push-proxy TCP for FW<->FW transfers"),
		N_("Push-proxy broadcasted messages"),
		N_("Push-proxy found un-proxied local route"),
		N_("Push-proxy lookup failures"),
		N_("Push relayed via local route"),
		N_("Push relayed via routing table"),
		N_("Locally generated dynamic queries"),
		N_("Leaf-generated dynamic queries"),
		N_("OOB-proxied leaf queries"),
		N_("Fully completed dynamic queries"),
		N_("Partially completed dynamic queries"),
		N_("Dynamic queries ended with no results"),
		N_("Fully completed dynamic queries getting late results"),
		N_("Dynamic queries with partial late results"),
		N_("Dynamic queries completed by late results"),
		N_("Queries seen from GTKG"),
		N_("Queries seen from GTKG that were re-queries"),
		N_("Queries advertising support of GGEP \"H\""),
		N_("Queries advertising support of semi-reliable UDP"),
		N_("GIV callbacks received"),
		N_("GIV discarded due to no suitable download"),
		N_("QUEUE callbacks received"),
		N_("QUEUE discarded due to no suitable download"),
		N_("File descriptors banned running count"),
		N_("UDP read-ahead datagram running count"),
		N_("UDP read-ahead datagram running bytes"),
		N_("UDP read-ahead datagram \"old\" processed"),
		N_("UDP read-ahead datagram max count"),
		N_("UDP read-ahead datagram max bytes"),
		N_("UDP read-ahead datagram max delay"),
		N_("UDP push messages received for FW<->FW connections"),
		N_("UDP push messages requesting FW<->FW connection with ourselves"),
		N_("UDP push messages patched for FW<->FW connections"),
		N_("UDP UHC pings received"),
		N_("UDP UHC pongs sent"),
		N_("UDP messages with bogus source IP"),
		N_("UDP truncated incoming messages"),
		N_("Alien UDP messages (non-Gnutella)"),
		N_("Unprocessed UDP Gnutella messages"),
		N_("Compressed UDP messages enqueued"),
		N_("Compressed UDP messages received"),
		N_("Uncompressed UDP messages due to no gain"),
		N_("Ambiguous UDP messages received"),
		N_("Ambiguous UDP messages inspected more deeply"),
		N_("Ambiguous UDP messages handled as semi-reliable UDP"),
		N_("Semi-reliable UDP total messages given for transmission"),
		N_("Semi-reliable UDP total messages deflated"),
		N_("Semi-reliable UDP total messages unsent"),
		N_("Semi-reliable UDP total messages dropped due to temporary ban"),
		N_("Semi-reliable UDP total messages sent to known responsive hosts"),
		N_("Semi-reliable UDP total messages partially sent due to clogging"),
		N_("Semi-reliable UDP reliable messages given for transmission"),
		N_("Semi-reliable UDP reliable messages correctly transmited"),
		N_("Semi-reliable UDP reliable messages not fully acknowledged"),
		N_("Semi-reliable UDP fragments sent"),
		N_("Semi-reliable UDP fragments resent"),
		N_("Semi-reliable UDP fragment sendings avoided"),
		N_("Semi-reliable UDP fragments sent too many times"),
		N_("Semi-reliable UDP total acknowledgments received"),
		N_("Semi-reliable UDP cumulative acknowledgments received"),
		N_("Semi-reliable UDP extended acknowledgments received"),
		N_("Semi-reliable UDP spurious acknowledgments received"),
		N_("Semi-reliable UDP invalid acknowledgments received"),
		N_("Semi-reliable UDP EARs sent"),
		N_("Semi-reliable UDP too many EARs sent"),
		N_("Semi-reliable UDP EAR negative acknowledgments received"),
		N_("Semi-reliable UDP acknowledgments received after sending EARs"),
		N_("Semi-reliable UDP fragments received"),
		N_("Semi-reliable UDP duplicate fragments received"),
		N_("Semi-reliable UDP unreliable fragments received"),
		N_("Semi-reliable UDP dropped received fragments"),
		N_("Semi-reliable UDP fragments received whilst lingering"),
		N_("Semi-reliable UDP messages expired before re-assembly"),
		N_("Semi-reliable UDP messages re-assembled completely"),
		N_("Semi-reliable UDP messages inflated successfully"),
		N_("Semi-reliable UDP messages inflated incorrectly"),
		N_("Semi-reliable UDP unreliable messages received"),
		N_("Semi-reliable UDP empty messages received"),
		N_("Semi-reliable UDP total acknowledgments sent"),
		N_("Semi-reliable UDP cumulative acknowledgments sent"),
		N_("Semi-reliable UDP extended acknowledgments sent"),
		N_("Semi-reliable UDP avoided acknowledgment sendings"),
		N_("Semi-reliable UDP EARs received"),
		N_("Semi-reliable UDP EARs received for unknown message"),
		N_("Semi-reliable UDP EARs received whilst lingering"),
		N_("Semi-reliable UDP fragments from hostile IP addresses"),
		N_("Consolidated servers (after GUID and IP address linking)"),
		N_("Duplicate downloads found during server consolidation"),
		N_("Discovered server GUIDs"),
		N_("Changed server GUIDs"),
		N_("Detected GUID collisions"),
		N_("Detected collisions with our own GUID"),
		N_("GUID dynamically banned"),
		N_("Firewalled node info for known hosts received in upload requests"),
		N_("Revitalized PUSH routes"),
		N_("Collected new PUSH proxies from other query hits"),
		N_("Attempted download resource switching on completion"),
		N_("Attempted download resource switching after error"),
		N_("Successful download resource switching (all kind)"),
		N_("Successful download resource switching between plain files"),
		N_("Successful download resource switching after error"),
		N_("Actively queued after resource switching attempt"),
		N_("Sunk HTTP reply data on error codes"),
		N_("Ignored downloaded data"),
		N_("Ignoring requested after data mismatch"),
		N_("Ignoring requested to preserve connection"),
		N_("Ignoring requested due to aggressive swarming"),
		N_("Ignoring refused (data too large or server too slow)"),
		N_("Client resource switching (all detected)"),
		N_("Client resource switching between plain files"),
		N_("Client follow-up request after HTTP error was returned"),
		N_("PARQ client resource switching in slots (SHA-1 based)"),
		N_("PARQ client retry-after violation"),
		N_("PARQ client kicked out after too many retry-after violations"),
		N_("PARQ upload slot limit overrides"),
		N_("PARQ quick upload slots granted"),
		N_("PARQ QUEUE sending attempts"),
		N_("PARQ QUEUE messages sent"),
		N_("PARQ QUEUE follow-up requests received"),
		N_("Launched SHA-1 file verifications"),
		N_("Launched TTH file verifications"),
		N_("Bitzi tickets held"),
		N_("Re-seeding of orphan downloads through query hits"),
		N_("Re-seeding of orphan downloads through upload requests"),
		N_("RUDP sent bytes"),
		N_("RUDP received bytes"),
		N_("DHT estimated amount of nodes"),
		N_("DHT standard error of estimated amount of nodes"),
		N_("DHT k-ball theoretical frontier (bits)"),
		N_("DHT k-ball furthest frontier (bits)"),
		N_("DHT k-ball closeest frontier (bits)"),
		N_("DHT routing table buckets"),
		N_("DHT routing table leaves"),
		N_("DHT routing table maximum depth"),
		N_("DHT routing table good nodes"),
		N_("DHT routing table stale nodes"),
		N_("DHT routing table pending nodes"),
		N_("DHT routing table evicted nodes"),
		N_("DHT routing table evicted firewalled nodes"),
		N_("DHT routing table evicted nodes due to quota"),
		N_("DHT routing table promoted pending nodes"),
		N_("DHT routing table pinged promoted nodes"),
		N_("DHT routing table rejected node due to bucket network quota"),
		N_("DHT routing table rejected node due to global network quota"),
		N_("DHT completed bucket refreshes"),
		N_("DHT forced bucket refreshes"),
		N_("DHT forced bucket merges"),
		N_("DHT denied non-splitable bucket refresh"),
		N_("DHT initiated bucket alive checks"),
		N_("DHT alive pings sent to good nodes"),
		N_("DHT alive pings sent to stale nodes"),
		N_("DHT alive pings sent to shutdowning nodes"),
		N_("DHT alive pings avoided"),
		N_("DHT alive pings skipped"),
		N_("DHT revitalized stale nodes on RPC reply"),
		N_("DHT value store rejected on IP/network quota grounds"),
		N_("DHT value store rejected on creator validation grounds"),
		N_("DHT nodes rejected during lookup based on network quota"),
		N_("DHT nodes rejected during lookup based on suspicious proximity"),
		N_("DHT nodes rejected during lookup based on frequency divergence"),
		N_("DHT node contact IP addresses fixed during lookup"),
		N_("DHT keys held"),
		N_("DHT cached keys held"),
		N_("DHT values held"),
		N_("DHT cached KUID targets held"),
		N_("DHT cached closest root nodes"),
		N_("DHT cached roots exact hits"),
		N_("DHT cached roots approximate hits"),
		N_("DHT cached roots misses"),
		N_("DHT cached roots lookups within k-ball"),
		N_("DHT cached roots contact address refreshed"),
		N_("DHT cached security tokens held"),
		N_("DHT cached security tokens hits"),
		N_("DHT stable node information held"),
		N_("DHT local hits on value lookups"),
		N_("DHT local hits returning values from cached keys"),
		N_("DHT returned expanded values"),
		N_("DHT returned values as secondary keys"),
		N_("DHT claimed values via secondary keys"),
		N_("DHT returned cached expanded values"),
		N_("DHT returned cached values as secondary-keys"),
		N_("DHT claimed cached values via secondary keys"),
		N_("DHT successfully received value publications"),
		N_("DHT successfully received value removals"),
		N_("DHT replication of stale value avoided"),
		N_("DHT replication of held values"),
		N_("DHT republishing of held values"),
		N_("DHT secondary-key value fetch issued"),
		N_("DHT duplicate values returned in lookups"),
		N_("DHT detected KUID collisions"),
		N_("DHT detected collisions with our own KUID"),
		N_("DHT caching attempts"),
		N_("DHT caching ended successfully"),
		N_("DHT caching partially completed"),
		N_("DHT key-offloading checks after discovering new closest node"),
		N_("DHT keys selected for offloading"),
		N_("DHT key-offloading attempts"),
		N_("DHT key-offloading ended successfully"),
		N_("DHT key-offloading partially completed"),
		N_("DHT values successfully offloaded"),
		N_("DHT incoming messages"),
		N_("DHT incoming messages with UDP-matching contact address"),
		N_("DHT incoming messages with contact address fixed"),
		N_("DHT incoming messages from hostile addresses"),
		N_("DHT incoming messages with hostile contact address"),
		N_("DHT RPC messages prepared"),
		N_("DHT RPC messages cancelled"),
		N_("DHT RPC timed out"),
		N_("DHT RPC replies received"),
		N_("DHT RPC replies with contact address fixed"),
		N_("DHT RPC late replies received"),
		N_("DHT RPC detected KUID mismatches on reply"),
		N_("DHT RPC recent nodes held"),
		N_("DHT node verifications"),
		N_("DHT publishing attempts"),
		N_("DHT publishing ended successfully (all roots)"),
		N_("DHT publishing partially completed (root subset only)"),
		N_("DHT publishing ending with proper value presence"),
		N_("DHT value republishing occurring too late (after expiry)"),
		N_("DHT publishing to self"),
		N_("DHT background publishing completion attempts"),
		N_("DHT background publishing completion showing improvements"),
		N_("DHT background publishing completion successful (all roots)"),
		N_("DHT SHA1 data type collisions"),
		N_("DHT lookup path passively protected against attack"),
		N_("DHT lookup path actively protected against attack"),
		N_("DHT alt-loc lookups issued"),
		N_("DHT push-proxy lookups issued"),
		N_("DHT successful alt-loc lookups"),
		N_("DHT successful push-proxy lookups"),
		N_("DHT successful node push-entry lookups"),
		N_("DHT re-seeding of orphan downloads"),
	};

	STATIC_ASSERT(G_N_ELEMENTS(strs) == GNR_TYPE_COUNT);

	if ((guint) value >= G_N_ELEMENTS(strs)) {
		g_carp("%s(): requested general_type_str %d is invalid",
			G_STRFUNC, value);
		return "";
	}

	return _(strs[value]);
}

/**
 * @returns the cell contents for the horizon stats table.
 *
 * @warning
 * NB: The static buffers for each column are disjunct.
 */
const gchar *
horizon_stat_str(gint row, c_horizon_t column)
{
    switch (column) {
    case c_horizon_hops:
		{
    		static gchar buf[UINT64_DEC_BUFLEN];

			str_bprintf(buf, sizeof(buf), "%d", row);
           	return buf;
		}
    case c_horizon_nodes:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_NODES);
		}
    case c_horizon_files:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_FILES);
		}
    case c_horizon_size:
		{
           	return guc_hsep_get_static_str(row, HSEP_IDX_KIB);
		}
    case num_c_horizon:
		g_assert_not_reached();
    }

    return NULL;
}

/**
 * Updates the horizon statistics in the statusbar.
 *
 * This is an event-driven callback called from the HSEP code
 * using the event listener framework. In addition to taking into account
 * the HSEP information, the number of established non-HSEP nodes and
 * their library size (if provided) are added to the values displayed.
 */
void
gnet_stats_gui_horizon_update(hsep_triple *table, guint32 triples)
{
	const guint32 hops = 4U;      /* must be <= HSEP_N_MAX */
	guint64 val;
	hsep_triple other;

	if (triples <= hops)     /* should not happen */
	    return;
	g_assert((gint32) triples > 0);

	guc_hsep_get_non_hsep_triple(&other);

	/*
	 * Update the 3 labels in the statusbar with the horizon values for a
	 * distance of 'hops' hops.
	 */

	val = table[hops][HSEP_IDX_NODES] + other[HSEP_IDX_NODES];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_node_count")),
		"%s %s", uint64_to_string(val), NG_("node", "nodes", val));

	val = table[hops][HSEP_IDX_FILES] + other[HSEP_IDX_FILES];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_file_count")),
		"%s %s", uint64_to_string(val), NG_("file", "files", val));

	val = table[hops][HSEP_IDX_KIB] + other[HSEP_IDX_KIB];
	gtk_label_printf(GTK_LABEL(
			gui_main_window_lookup("label_statusbar_horizon_kb_count")),
		"%s", short_kb_size(val, show_metric_units()));
}

/**
 * Stringify value of the general stats to buffer.
 *
 * @param dst		destination buffer
 * @param size		length of destination buffer
 * @param stats		the statistics array
 * @param idx		the index within the general statistics of value to format
 */
void
gnet_stats_gui_general_to_string_buf(char *dst, size_t size,
	const gnet_stats_t *stats, int idx)
{
	const uint64 value = stats->general[idx];

	if (0 == value)
		g_strlcpy(dst, "-", size);
	else {
		switch (idx) {
		case GNR_QUERY_COMPACT_SIZE:
		case GNR_IGNORED_DATA:
		case GNR_SUNK_DATA:
		case GNR_UDP_READ_AHEAD_BYTES_SUM:
		case GNR_UDP_READ_AHEAD_BYTES_MAX:
		case GNR_RUDP_TX_BYTES:
		case GNR_RUDP_RX_BYTES:
			g_strlcpy(dst, compact_size(value, show_metric_units()), size);
			break;
		case GNR_UDP_READ_AHEAD_DELAY_MAX:
			g_strlcpy(dst, compact_time(value), size);
			break;
		default:
			uint64_to_string_buf(value, dst, size);
		}
	}
}

static gboolean
gnet_stats_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_stats == main_gui_notebook_get_page();
}

void
gnet_stats_gui_timer(time_t now)
{
	static time_t last_update;

	if (last_update != now && gnet_stats_gui_is_visible()) {
		last_update = now;
		gnet_stats_gui_update_display(now);
	}
}

/* vi: set ts=4 sw=4 cindent: */
