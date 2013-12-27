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

/**
 * @ingroup core
 * @file
 *
 * Collection of Gnutella / DHT statistics.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

#include "gnet_stats.h"
#include "gmsg.h"

#include "if/dht/kademlia.h"
#include "if/gnet_property_priv.h"

#include "lib/crc.h"
#include "lib/event.h"
#include "lib/gnet_host.h"
#include "lib/random.h"
#include "lib/spinlock.h"
#include "lib/thread.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static uint8 stats_lut[256];

static gnet_stats_t gnet_stats;
static gnet_stats_t gnet_tcp_stats;
static gnet_stats_t gnet_udp_stats;

/*
 * Thread-safe locks.
 *
 * The general stats accounting code is protected because there is no guarantee
 * the routines updating these stats will always be called from the main thread.
 *
 * However, the routines updating the traffic statistics are NOT protected
 * because they are always called from the main thread, the one where the
 * I/O event loop is installed.  An assertion verifies this assumption.
 */
static spinlock_t gnet_stats_slk = SPINLOCK_INIT;

#define GNET_STATS_LOCK		spinlock_hidden(&gnet_stats_slk)
#define GNET_STATS_UNLOCK	spinunlock_hidden(&gnet_stats_slk)

/***
 *** Public functions
 ***/

const char *
gnet_stats_drop_reason_to_string(msg_drop_reason_t reason)
{
	static const char * const msg_drop_reasons[] = {
		N_("Bad size"),						 /**< MSG_DROP_BAD_SIZE */
		N_("Too small"),					 /**< MSG_DROP_TOO_SMALL */
		N_("Too large"),					 /**< MSG_DROP_TOO_LARGE */
		N_("Way too large"),				 /**< MSG_DROP_WAY_TOO_LARGE */
		N_("Too old"),					 	 /**< MSG_DROP_TOO_OLD */
		N_("Unknown message type"),			 /**< MSG_DROP_UNKNOWN_TYPE */
		N_("Unexpected message"),			 /**< MSG_DROP_UNEXPECTED */
		N_("Message sent with TTL = 0"),	 /**< MSG_DROP_TTL0 */
		N_("Improper hops/ttl combination"), /**< MSG_DROP_IMPROPER_HOPS_TTL */
		N_("Max TTL exceeded"),				 /**< MSG_DROP_MAX_TTL_EXCEEDED */
		N_("Message throttle"),				 /**< MSG_DROP_THROTTLE */
		N_("Message matched limits"),		 /**< MSG_DROP_LIMIT */
		N_("Transient node"),				 /**< MSG_DROP_TRANSIENT */
		N_("Unusable Pong"),				 /**< MSG_DROP_PONG_UNUSABLE */
		N_("Hard TTL limit reached"),		 /**< MSG_DROP_HARD_TTL_LIMIT */
		N_("Max hop count reached"),		 /**< MSG_DROP_MAX_HOP_COUNT */
		N_("Route lost"),					 /**< MSG_DROP_ROUTE_LOST */
		N_("No route"),						 /**< MSG_DROP_NO_ROUTE */
		N_("Duplicate message"),			 /**< MSG_DROP_DUPLICATE */
		N_("Message to banned GUID"),		 /**< MSG_DROP_TO_BANNED */
		N_("Message from banned GUID"),		 /**< MSG_DROP_FROM_BANNED */
		N_("Node shutting down"),			 /**< MSG_DROP_SHUTDOWN */
		N_("TX flow control"),				 /**< MSG_DROP_FLOW_CONTROL */
		N_("Query text had no trailing NUL"),/**< MSG_DROP_QUERY_NO_NUL */
		N_("Query text too short"),			 /**< MSG_DROP_QUERY_TOO_SHORT */
		N_("Query had unnecessary overhead"),/**< MSG_DROP_QUERY_OVERHEAD */
		N_("Query had bad URN"),			 /**< MSG_DROP_BAD_URN */
		N_("Message with malformed SHA1"),	 /**< MSG_DROP_MALFORMED_SHA1 */
		N_("Message with malformed UTF-8"),	 /**< MSG_DROP_MALFORMED_UTF_8 */
		N_("Malformed Query Hit"),			 /**< MSG_DROP_BAD_RESULT */
		N_("Bad return address"),			 /**< MSG_DROP_BAD_RETURN_ADDRESS */
		N_("Hostile IP address"),			 /**< MSG_DROP_HOSTILE_IP */
		N_("Bogus result from Morpheus"),	 /**< MSG_DROP_MORPHEUS_BOGUS */
		N_("Spam"),							 /**< MSG_DROP_SPAM */
		N_("Evil filename"),				 /**< MSG_DROP_EVIL */
		N_("Improper media type"),			 /**< MSG_DROP_MEDIA */
		N_("Payload inflating error"),		 /**< MSG_DROP_INFLATE_ERROR */
		N_("Unknown header flags present"),/**< MSG_DROP_UNKNOWN_HEADER_FLAGS */
		N_("Own search results"),			 /**< MSG_DROP_OWN_RESULT */
		N_("Own queries"),			 		 /**< MSG_DROP_OWN_QUERY */
		N_("Ancient query format"),			 /**< MSG_DROP_ANCIENT_QUERY */
		N_("Blank Servent ID"),				 /**< MSG_DROP_BLANK_SERVENT_ID */
		N_("GUESS Query missing token"), /**< MSG_DROP_GUESS_MISSING_TOKEN */
		N_("GUESS Invalid query token"), /**< MSG_DROP_GUESS_INVALID_TOKEN */
		N_("DHT Invalid security token"),	 /**< MSG_DROP_DHT_INVALID_TOKEN */
		N_("DHT Too many STORE requests"),	 /**< MSG_DROP_DHT_TOO_MANY_STORE */
		N_("DHT Malformed message"),		 /**< MSG_DROP_DHT_UNPARSEABLE */
	};

	STATIC_ASSERT(G_N_ELEMENTS(msg_drop_reasons) == MSG_DROP_REASON_COUNT);
	g_return_val_if_fail(UNSIGNED(reason) < G_N_ELEMENTS(msg_drop_reasons),
		NULL);
	return msg_drop_reasons[reason];
}

const char *
gnet_stats_general_to_string(gnr_stats_t type)
{
	/* Do NOT translate any of these strings */

	static const char * const type_string[] = {
		"routing_errors",
		"routing_table_chunks",
		"routing_table_capacity",
		"routing_table_count",
		"routing_transient_avoided",
		"dups_with_higher_ttl",
		"spam_sha1_hits",
		"spam_name_hits",
		"spam_fake_hits",
		"spam_dup_hits",
		"spam_caught_hostile_ip",
		"spam_caught_hostile_held",
		"spam_ip_held",
		"local_searches",
		"local_hits",
		"local_partial_hits",
		"local_whats_new_hits",
		"local_query_hits",
		"oob_proxied_query_hits",
		"oob_queries",
		"oob_queries_stripped",
		"oob_queries_ignored",
		"query_oob_proxied_dups",
		"oob_hits_for_proxied_queries",
		"oob_hits_with_alien_ip",
		"oob_hits_ignored_on_spammer_hit",
		"oob_hits_ignored_on_unsecure_hit",
		"unclaimed_oob_hits",
		"partially_claimed_oob_hits",
		"spurious_oob_hit_claim",
		"unrequested_oob_hits",
		"query_hit_for_untracked_query",
		"query_tracked_muids",
		"query_compact_count",
		"query_compact_size",
		"query_utf8",
		"query_sha1",
		"query_whats_new",
		"query_guess",
		"query_guess_02",
		"guess_link_cache",
		"guess_cached_query_keys_held",
		"guess_cached_02_hosts_held",
		"guess_local_queries",
		"guess_local_running",
		"guess_local_query_hits",
		"guess_hosts_queried",
		"guess_hosts_acknowledged",
		"broadcasted_pushes",
		"push_proxy_udp_relayed",
		"push_proxy_tcp_relayed",
		"push_proxy_tcp_fw2fw",
		"push_proxy_broadcasted",
		"push_proxy_route_not_proxied",
		"push_proxy_failed",
		"push_relayed_via_local_route",
		"push_relayed_via_table_route",
		"local_dyn_queries",
		"leaf_dyn_queries",
		"oob_proxied_queries",
		"dyn_queries_completed_full",
		"dyn_queries_completed_partial",
		"dyn_queries_completed_zero",
		"dyn_queries_linger_extra",
		"dyn_queries_linger_results",
		"dyn_queries_linger_completed",
		"gtkg_total_queries",
		"gtkg_requeries",
		"queries_with_ggep_h",
		"queries_with_sr_udp",
		"giv_callbacks",
		"giv_discarded",
		"queue_callbacks",
		"queue_discarded",
		"banned_fds_total",
		"udp_read_ahead_count_sum",
		"udp_read_ahead_bytes_sum",
		"udp_read_ahead_old_sum",
		"udp_read_ahead_count_max",
		"udp_read_ahead_bytes_max",
		"udp_read_ahead_delay_max",
		"udp_fw2fw_pushes",
		"udp_fw2fw_pushes_to_self",
		"udp_fw2fw_pushes_patched",
		"udp_uhc_pings",
		"udp_uhc_pongs",
		"udp_bogus_source_ip",
		"udp_rx_truncated",
		"udp_alien_message",
		"udp_unprocessed_message",
		"udp_tx_compressed",
		"udp_rx_compressed",
		"udp_larger_hence_not_compressed",
		"udp_ambiguous",
		"udp_ambiguous_deeper_inspection",
		"udp_ambiguous_as_semi_reliable",
		"udp_sr_tx_messages_given",
		"udp_sr_tx_messages_deflated",
		"udp_sr_tx_messages_unsent",
		"udp_sr_tx_messages_banned",
		"udp_sr_tx_messages_clogging",
		"udp_sr_tx_reliable_messages_given",
		"udp_sr_tx_reliable_messages_sent",
		"udp_sr_tx_reliable_messages_unsent",
		"udp_sr_tx_fragments_sent",
		"udp_sr_tx_fragments_resent",
		"udp_sr_tx_fragments_sending_avoided",
		"udp_sr_tx_fragments_oversent",
		"udp_sr_tx_total_acks_received",
		"udp_sr_tx_cumulative_acks_received",
		"udp_sr_tx_extended_acks_received",
		"udp_sr_tx_spurious_acks_received",
		"udp_sr_tx_invalid_acks_received",
		"udp_sr_tx_ears_sent",
		"udp_sr_tx_ears_oversent",
		"udp_sr_tx_ear_nacks_received",
		"udp_sr_tx_ear_followed_by_acks",
		"udp_sr_rx_fragments_received",
		"udp_sr_rx_fragments_duplicate",
		"udp_sr_rx_fragments_unreliable",
		"udp_sr_rx_fragments_dropped",
		"udp_sr_rx_fragments_lingering",
		"udp_sr_rx_messages_expired",
		"udp_sr_rx_messages_received",
		"udp_sr_rx_messages_inflated",
		"udp_sr_rx_messages_inflation_error",
		"udp_sr_rx_messages_unreliable",
		"udp_sr_rx_messages_empty",
		"udp_sr_rx_total_acks_sent",
		"udp_sr_rx_cumulative_acks_sent",
		"udp_sr_rx_extended_acks_sent",
		"udp_sr_rx_avoided_acks",
		"udp_sr_rx_ears_received",
		"udp_sr_rx_ears_for_unknown_message",
		"udp_sr_rx_ears_for_lingering_message",
		"udp_sr_rx_from_hostile_ip",
		"consolidated_servers",
		"dup_downloads_in_consolidation",
		"discovered_server_guid",
		"changed_server_guid",
		"guid_collisions",
		"own_guid_collisions",
		"banned_guid_held",
		"received_known_fw_node_info",
		"revitalized_push_routes",
		"collected_push_proxies",
		"attempted_resource_switching",
		"attempted_resource_switching_after_error",
		"successful_resource_switching",
		"successful_plain_resource_switching",
		"successful_resource_switching_after_error",
		"queued_after_switching",
		"sunk_data",
		"ignored_data",
		"ignoring_after_mismatch",
		"ignoring_to_preserve_connection",
		"ignoring_during_aggressive_swarming",
		"ignoring_refused",
		"client_resource_switching",
		"client_plain_resource_switching",
		"client_followup_after_error",
		"parq_slot_resource_switching",
		"parq_retry_after_violation",
		"parq_retry_after_kick_out",
		"parq_slot_limit_overrides",
		"parq_quick_slots_granted",
		"parq_queue_sending_attempts",
		"parq_queue_sent",
		"parq_queue_follow_ups",
		"sha1_verifications",
		"tth_verifications",
		"bitzi_tickets_held",
		"qhit_seeding_of_orphan",
		"upload_seeding_of_orphan",
		"rudp_tx_bytes",
		"rudp_rx_bytes",
		"dht_estimated_size",
		"dht_estimated_size_stderr",
		"dht_kball_theoretical",
		"dht_kball_furthest",
		"dht_kball_closest",
		"dht_routing_buckets",
		"dht_routing_leaves",
		"dht_routing_max_depth",
		"dht_routing_good_nodes",
		"dht_routing_stale_nodes",
		"dht_routing_pending_nodes",
		"dht_routing_evicted_nodes",
		"dht_routing_evicted_firewalled_nodes",
		"dht_routing_evicted_quota_nodes",
		"dht_routing_promoted_pending_nodes",
		"dht_routing_pinged_promoted_nodes",
		"dht_routing_rejected_node_bucket_quota",
		"dht_routing_rejected_node_global_quota",
		"dht_completed_bucket_refresh",
		"dht_forced_bucket_refresh",
		"dht_forced_bucket_merge",
		"dht_denied_unsplitable_bucket_refresh",
		"dht_bucket_alive_check",
		"dht_alive_pings_to_good_nodes",
		"dht_alive_pings_to_stale_nodes",
		"dht_alive_pings_to_shutdowning_nodes",
		"dht_alive_pings_avoided",
		"dht_alive_pings_skipped",
		"dht_revitalized_stale_nodes",
		"dht_rejected_value_on_quota",
		"dht_rejected_value_on_creator",
		"dht_lookup_rejected_node_on_net_quota",
		"dht_lookup_rejected_node_on_proximity",
		"dht_lookup_rejected_node_on_divergence",
		"dht_lookup_fixed_node_contact",
		"dht_keys_held",
		"dht_cached_keys_held",
		"dht_values_held",
		"dht_cached_kuid_targets_held",
		"dht_cached_roots_held",
		"dht_cached_roots_exact_hits",
		"dht_cached_roots_approximate_hits",
		"dht_cached_roots_misses",
		"dht_cached_roots_kball_lookups",
		"dht_cached_roots_contact_refreshed",
		"dht_cached_tokens_held",
		"dht_cached_tokens_hits",
		"dht_stable_nodes_held",
		"dht_fetch_local_hits",
		"dht_fetch_local_cached_hits",
		"dht_returned_expanded_values",
		"dht_returned_secondary_keys",
		"dht_claimed_secondary_keys",
		"dht_returned_expanded_cached_values",
		"dht_returned_cached_secondary_keys",
		"dht_claimed_cached_secondary_keys",
		"dht_published",
		"dht_removed",
		"dht_stale_replication",
		"dht_replication",
		"dht_republish",
		"dht_secondary_key_fetch",
		"dht_dup_values",
		"dht_kuid_collisions",
		"dht_own_kuid_collisions",
		"dht_caching_attempts",
		"dht_caching_successful",
		"dht_caching_partially_successful",
		"dht_key_offloading_checks",
		"dht_keys_selected_for_offloading",
		"dht_key_offloading_attempts",
		"dht_key_offloading_successful",
		"dht_key_offloading_partially_successful",
		"dht_values_offloaded",
		"dht_msg_received",
		"dht_msg_matching_contact_address",
		"dht_msg_fixed_contact_address",
		"dht_msg_from_hostile_address",
		"dht_msg_from_hostile_contact_address",
		"dht_rpc_msg_prepared",
		"dht_rpc_msg_cancelled",
		"dht_rpc_timed_out",
		"dht_rpc_replies_received",
		"dht_rpc_replies_fixed_contact",
		"dht_rpc_late_replies_received",
		"dht_rpc_kuid_reply_mismatch",
		"dht_rpc_recent_nodes_held",
		"dht_node_verifications",
		"dht_publishing_attempts",
		"dht_publishing_successful",
		"dht_publishing_partially_successful",
		"dht_publishing_satisfactory",
		"dht_republished_late",
		"dht_publishing_to_self",
		"dht_publishing_bg_attempts",
		"dht_publishing_bg_improvements",
		"dht_publishing_bg_successful",
		"dht_sha1_data_type_collisions",
		"dht_passively_protected_lookup_path",
		"dht_actively_protected_lookup_path",
		"dht_alt_loc_lookups",
		"dht_push_proxy_lookups",
		"dht_successful_alt_loc_lookups",
		"dht_successful_push_proxy_lookups",
		"dht_successful_node_push_entry_lookups",
		"dht_seeding_of_orphan",
	};

	STATIC_ASSERT(G_N_ELEMENTS(type_string) == GNR_TYPE_COUNT);
	g_return_val_if_fail(UNSIGNED(type) < G_N_ELEMENTS(type_string),
		NULL);
	return type_string[type];
}

G_GNUC_COLD void
gnet_stats_init(void)
{
	uint i;

	/* Guarantees that our little hack below can succeed */
	STATIC_ASSERT(
		UNSIGNED(KDA_MSG_MAX_ID + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut));

	for (i = 0; i < G_N_ELEMENTS(stats_lut); i++) {
		uchar m = MSG_UNKNOWN;

		/*
		 * To keep the look-up table small enough, we cheat a little
		 * bit to be able to stuff both Gnutella and Kademlia messages.
		 *
		 * We use the fact that the space from 0xd0 and onwards is unused
		 * by Gnutella to stuff the DHT messages there.  And 0xd0 starts
		 * with a 'D', so it's not a total hack.
		 *		--RAM, 2010-11-01.
		 */

		if (i > MSG_DHT_BASE) {
			switch ((enum kda_msg) (i - MSG_DHT_BASE)) {
			case KDA_MSG_PING_REQUEST:		m = MSG_DHT_PING; break;
			case KDA_MSG_PING_RESPONSE:		m = MSG_DHT_PONG; break;
			case KDA_MSG_STORE_REQUEST:		m = MSG_DHT_STORE; break;
			case KDA_MSG_STORE_RESPONSE:	m = MSG_DHT_STORE_ACK; break;
			case KDA_MSG_FIND_NODE_REQUEST:	m = MSG_DHT_FIND_NODE; break;
			case KDA_MSG_FIND_NODE_RESPONSE:m = MSG_DHT_FOUND_NODE; break;
			case KDA_MSG_FIND_VALUE_REQUEST:	m = MSG_DHT_FIND_VALUE; break;
			case KDA_MSG_FIND_VALUE_RESPONSE:	m = MSG_DHT_VALUE; break;
			case KDA_MSG_STATS_REQUEST:
			case KDA_MSG_STATS_RESPONSE:
				/* deprecated, not supported */
				break;
			}
		} else {
			switch ((enum gta_msg) i) {
			case GTA_MSG_INIT:           m = MSG_INIT; break;
			case GTA_MSG_INIT_RESPONSE:  m = MSG_INIT_RESPONSE; break;
			case GTA_MSG_SEARCH:         m = MSG_SEARCH; break;
			case GTA_MSG_SEARCH_RESULTS: m = MSG_SEARCH_RESULTS; break;
			case GTA_MSG_PUSH_REQUEST:   m = MSG_PUSH_REQUEST; break;
			case GTA_MSG_RUDP:			 m = MSG_RUDP; break;
			case GTA_MSG_VENDOR:		 m = MSG_VENDOR; break;
			case GTA_MSG_STANDARD:		 m = MSG_STANDARD; break;
			case GTA_MSG_QRP:            m = MSG_QRP; break;
			case GTA_MSG_HSEP_DATA:		 m = MSG_HSEP; break;
			case GTA_MSG_BYE:      		 m = MSG_BYE; break;
			case GTA_MSG_DHT:            m = MSG_DHT; break;
				break;
			}
		}
		stats_lut[i] = m;
	}

#undef CASE
		
    ZERO(&gnet_stats);
    ZERO(&gnet_udp_stats);
}

/**
 * Use unpredictable events to collect random data.
 */
static void
gnet_stats_randomness(const gnutella_node_t *n, uint8 type, uint32 val)
{
	tm_t now;
	gnet_host_t host;
	uint32 crc32;

	tm_now(&now);
	gnet_host_set(&host, n->addr, n->port);

	crc32 = crc32_update(0, &now, sizeof now);
	crc32 = crc32_update(crc32, &host, gnet_host_length(&host));
	crc32 = crc32_update(crc32, &type, sizeof type);
	crc32 = crc32_update(crc32, &val, sizeof val);

	random_pool_append(&crc32, sizeof crc32);
}

/**
 * Called when Gnutella header has been read.
 */
void
gnet_stats_count_received_header(gnutella_node_t *n)
{
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	uint i;
	gnet_stats_t *stats;

	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

    n->received++;

    gnet_stats.pkg.received[MSG_TOTAL]++;
    gnet_stats.pkg.received[t]++;
    gnet_stats.byte.received[MSG_TOTAL] += GTA_HEADER_SIZE;
    gnet_stats.byte.received[t] += GTA_HEADER_SIZE;

    stats->pkg.received[MSG_TOTAL]++;
    stats->pkg.received[t]++;
    stats->byte.received[MSG_TOTAL] += GTA_HEADER_SIZE;
    stats->byte.received[t] += GTA_HEADER_SIZE;

	i = MIN(gnutella_header_get_ttl(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_ttl[i][MSG_TOTAL]++;
    stats->pkg.received_ttl[i][t]++;

	i = MIN(gnutella_header_get_hops(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_hops[i][MSG_TOTAL]++;
    stats->pkg.received_hops[i][t]++;
}

/**
 * Called to transform Gnutella header counting into Kademlia header counting.
 *
 * @param n		the node receiving the message
 * @param kt
 */
static void
gnet_stats_count_kademlia_header(const gnutella_node_t *n, uint kt)
{
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	uint i;
	gnet_stats_t *stats;

	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

    gnet_stats.pkg.received[t]--;
    gnet_stats.pkg.received[kt]++;
    gnet_stats.byte.received[t] -= GTA_HEADER_SIZE;
    gnet_stats.byte.received[kt] += GTA_HEADER_SIZE;

    stats->pkg.received[t]--;
    stats->pkg.received[kt]++;
    stats->byte.received[t] -= GTA_HEADER_SIZE;
    stats->byte.received[kt] += GTA_HEADER_SIZE;

	i = MIN(gnutella_header_get_ttl(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_ttl[i][MSG_TOTAL]--;
    stats->pkg.received_ttl[i][t]--;

	i = MIN(gnutella_header_get_hops(&n->header), STATS_RECV_COLUMNS - 1);
    stats->pkg.received_hops[i][MSG_TOTAL]--;
    stats->pkg.received_hops[i][t]--;

	/* DHT messages have no hops nor ttl, use 0 */

    stats->pkg.received_ttl[0][MSG_TOTAL]++;
    stats->pkg.received_ttl[0][kt]++;
    stats->pkg.received_hops[0][MSG_TOTAL]++;
    stats->pkg.received_hops[0][kt]++;
}

/**
 * Called when Gnutella payload has been read.
 *
 * The actual payload size (effectively read) is expected to be found
 * in n->size.
 */
void
gnet_stats_count_received_payload(const gnutella_node_t *n, const void *payload)
{
	uint8 f = gnutella_header_get_function(&n->header);
	uint t = stats_lut[f];
	uint i;
	gnet_stats_t *stats;
    uint32 size;
	uint8 hops, ttl;

	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/*
	 * Size is NOT read in the Gnutella header but in n->size, which
	 * reflects how much data we have in the payload, as opposed to the
	 * size in the header which may be wrong, or have highest bits set
	 * because they indicate flags.
	 *
	 * In particular, broken DHT messages often come with an invalid size in
	 * the header.
	 *		--RAM, 2010-10-30
	 */

	size = n->size;
	hops = gnutella_header_get_hops(&n->header);
	ttl = gnutella_header_get_ttl(&n->header);

	gnet_stats_randomness(n, f, size);

	/*
	 * If we're dealing with a Kademlia message, we need to do two things:
	 *
	 * We counted the Gnutella header for the GTA_MSG_DHT message, but we
	 * now need to undo that and count it as a Kademlia message.
	 *
	 * To access the proper entry in the array, we need to offset the
	 * Kademlia OpCode from the header with MSG_DHT_BASE to get the entry
	 * in the statistics that are associated with that particular message.
	 *		--RAM, 2010-11-01
	 */

	if (GTA_MSG_DHT == f && size + GTA_HEADER_SIZE >= KDA_HEADER_SIZE) {
		uint8 opcode = peek_u8(payload);	/* Kademlia Opcode */

		if (UNSIGNED(opcode + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
			gnet_stats_count_kademlia_header(n, t);
		}
	}

    gnet_stats.byte.received[MSG_TOTAL] += size;
    gnet_stats.byte.received[t] += size;

    stats->byte.received[MSG_TOTAL] += size;
    stats->byte.received[t] += size;

	i = MIN(ttl, STATS_RECV_COLUMNS - 1);
    stats->byte.received_ttl[i][MSG_TOTAL] += size;
    stats->byte.received_ttl[i][t] += size;

	i = MIN(hops, STATS_RECV_COLUMNS - 1);
    stats->byte.received_hops[i][MSG_TOTAL] += size;
    stats->byte.received_hops[i][t] += size;
}

void
gnet_stats_count_queued(const gnutella_node_t *n,
	uint8 type, const void *base, uint32 size)
{
	uint64 *stats_pkg;
	uint64 *stats_byte;
	uint t = stats_lut[type];
	gnet_stats_t *stats;
	uint8 hops;

	g_assert(t != MSG_UNKNOWN);
	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == type && size >= KDA_HEADER_SIZE) {
		uint8 opcode = kademlia_header_get_function(base);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		}
		hops = 0;
	} else {
		hops = gnutella_header_get_hops(base);
	}

	gnet_stats_randomness(n, t & 0xff, size);

	stats_pkg = hops ? gnet_stats.pkg.queued : gnet_stats.pkg.gen_queued;
	stats_byte = hops ? gnet_stats.byte.queued : gnet_stats.byte.gen_queued;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;

	stats_pkg = hops ? stats->pkg.queued : stats->pkg.gen_queued;
	stats_byte = hops ? stats->byte.queued : stats->byte.gen_queued;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;
}

void
gnet_stats_count_sent(const gnutella_node_t *n,
	uint8 type, const void *base, uint32 size)
{
	uint64 *stats_pkg;
	uint64 *stats_byte;
	uint t = stats_lut[type];
	gnet_stats_t *stats;
	uint8 hops;

	g_assert(t != MSG_UNKNOWN);
	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == type && size >= KDA_HEADER_SIZE) {
		uint8 opcode = kademlia_header_get_function(base);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		}
		hops = 0;
	} else {
		hops = gnutella_header_get_hops(base);
	}

	gnet_stats_randomness(n, t & 0xff, size);

	stats_pkg = hops ? gnet_stats.pkg.relayed : gnet_stats.pkg.generated;
	stats_byte = hops ? gnet_stats.byte.relayed : gnet_stats.byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;

	stats_pkg = hops ? stats->pkg.relayed : stats->pkg.generated;
	stats_byte = hops ? stats->byte.relayed : stats->byte.generated;

    stats_pkg[MSG_TOTAL]++;
    stats_pkg[t]++;
    stats_byte[MSG_TOTAL] += size;
    stats_byte[t] += size;
}

void
gnet_stats_count_expired(const gnutella_node_t *n)
{
    uint32 size = n->size + sizeof(n->header);
	uint t = stats_lut[gnutella_header_get_function(&n->header)];
	gnet_stats_t *stats;

	g_assert(thread_is_main());

	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

    gnet_stats.pkg.expired[MSG_TOTAL]++;
    gnet_stats.pkg.expired[t]++;
    gnet_stats.byte.expired[MSG_TOTAL] += size;
    gnet_stats.byte.expired[t] += size;

    stats->pkg.expired[MSG_TOTAL]++;
    stats->pkg.expired[t]++;
    stats->byte.expired[MSG_TOTAL] += size;
    stats->byte.expired[t] += size;
}

#define DROP_STATS(gs,t,s) do {							\
    if (												\
        (reason == MSG_DROP_ROUTE_LOST) ||				\
        (reason == MSG_DROP_NO_ROUTE)					\
    )													\
        gnet_stats.general[GNR_ROUTING_ERRORS]++;		\
														\
    gnet_stats.drop_reason[reason][MSG_TOTAL]++;		\
    gnet_stats.drop_reason[reason][t]++;				\
    gnet_stats.pkg.dropped[MSG_TOTAL]++;				\
    gnet_stats.pkg.dropped[t]++;						\
    gnet_stats.byte.dropped[MSG_TOTAL] += (s);			\
    gnet_stats.byte.dropped[t] += (s);					\
    gs->pkg.dropped[MSG_TOTAL]++;						\
    gs->pkg.dropped[t]++;								\
    gs->byte.dropped[MSG_TOTAL] += (s);					\
    gs->byte.dropped[t] += (s);							\
} while (0)

void
gnet_stats_count_dropped(gnutella_node_t *n, msg_drop_reason_t reason)
{
	uint32 size;
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(thread_is_main());

    size = n->size + sizeof(n->header);
	type = stats_lut[gnutella_header_get_function(&n->header)];
	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	gnet_stats_randomness(n, type & 0xff, size);

	DROP_STATS(stats, type, size);
	node_inc_rxdrop(n);

	switch (reason) {
	case MSG_DROP_HOSTILE_IP: n->n_hostile++; break;
	case MSG_DROP_SPAM: n->n_spam++; break;
	case MSG_DROP_EVIL: n->n_evil++; break;
	default: ;
	}

	if (GNET_PROPERTY(log_dropped_gnutella))
		gmsg_log_split_dropped(&n->header, n->data, n->size,
			"from %s: %s", node_infostr(n),
			gnet_stats_drop_reason_to_string(reason));
}

/**
 * Account for dropped Kademlia message of specified opcode from node ``n''.
 */
void
gnet_dht_stats_count_dropped(gnutella_node_t *n, kda_msg_t opcode,
	msg_drop_reason_t reason)
{
	uint32 size;
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(opcode <= KDA_MSG_MAX_ID);
	g_assert(UNSIGNED(opcode + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut));
	g_assert(thread_is_main());

    size = n->size + sizeof(n->header);
	type = stats_lut[opcode + MSG_DHT_BASE];
	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	gnet_stats_randomness(n, type & 0xff, size);

	DROP_STATS(stats, type, size);
	node_inc_rxdrop(n);
}

/**
 * Update the general stats counter by given signed delta.
 */
void
gnet_stats_count_general(gnr_stats_t type, int delta)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i] += delta;
	GNET_STATS_UNLOCK;
}

/**
 * Increment the general stats counter by 1.
 */
void
gnet_stats_inc_general(gnr_stats_t type)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i]++;
	GNET_STATS_UNLOCK;
}

/**
 * Decrement the general stats counter by 1.
 */
void
gnet_stats_dec_general(gnr_stats_t type)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i]--;
	GNET_STATS_UNLOCK;
}

/**
 * Update the general stats counter to keep the maximum value.
 */
void
gnet_stats_max_general(gnr_stats_t type, uint64 value)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
	if (value > gnet_stats.general[i])
		gnet_stats.general[i] = value;
	GNET_STATS_UNLOCK;
}

/**
 * Set the general stats counter to the given value.
 */
void
gnet_stats_set_general(gnr_stats_t type, uint64 value)
{
	size_t i = type;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
    gnet_stats.general[i] = value;
	GNET_STATS_UNLOCK;
}

/**
 * Get the general stats counter.
 */
uint64
gnet_stats_get_general(gnr_stats_t type)
{
	size_t i = type;
	uint64 value;

	g_assert(i < GNR_TYPE_COUNT);

	GNET_STATS_LOCK;
	value = gnet_stats.general[i];
	GNET_STATS_UNLOCK;

	return value;
}

void
gnet_stats_count_dropped_nosize(
	const gnutella_node_t *n, msg_drop_reason_t reason)
{
	uint type;
	gnet_stats_t *stats;

	g_assert(UNSIGNED(reason) < MSG_DROP_REASON_COUNT);
	g_assert(thread_is_main());

	type = stats_lut[gnutella_header_get_function(&n->header)];
	stats = NODE_USES_UDP(n) ? &gnet_udp_stats : &gnet_tcp_stats;

	/* Data part of message not read */
	DROP_STATS(stats, type, sizeof(n->header));

	if (GNET_PROPERTY(log_dropped_gnutella))
		gmsg_log_split_dropped(&n->header, n->data, 0,
			"from %s: %s", node_infostr(n),
			gnet_stats_drop_reason_to_string(reason));
}

void
gnet_stats_count_flowc(const void *head, bool head_only)
{
	uint t;
	uint i;
	uint16 size = gmsg_size(head) + GTA_HEADER_SIZE;
	uint8 function = gnutella_header_get_function(head);
	uint8 ttl = gnutella_header_get_ttl(head);
	uint8 hops = gnutella_header_get_hops(head);

	g_assert(thread_is_main());

	if (GNET_PROPERTY(node_debug) > 3)
		g_debug("FLOWC function=%d ttl=%d hops=%d", function, ttl, hops);

	/*
	 * Adjust for Kademlia messages.
	 */

	if (GTA_MSG_DHT == function && size >= KDA_HEADER_SIZE && !head_only) {
		uint8 opcode = kademlia_header_get_function(head);

		if (UNSIGNED(opcode + MSG_DHT_BASE) < G_N_ELEMENTS(stats_lut)) {
			t = stats_lut[opcode + MSG_DHT_BASE];
		} else {
			t = stats_lut[function];		/* Invalid opcode? */
		}
		hops = 0;
		ttl = 0;
	} else {
		t = stats_lut[function];
	}

	i = MIN(hops, STATS_FLOWC_COLUMNS - 1);
	gnet_stats.pkg.flowc_hops[i][t]++;
	gnet_stats.pkg.flowc_hops[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_hops[i][t] += size;
	gnet_stats.byte.flowc_hops[i][MSG_TOTAL] += size;

	i = MIN(ttl, STATS_FLOWC_COLUMNS - 1);

	/* Cannot send a message with TTL=0 (DHT messages are not Gnutella) */
	g_assert(function == GTA_MSG_DHT || i != 0);

	gnet_stats.pkg.flowc_ttl[i][t]++;
	gnet_stats.pkg.flowc_ttl[i][MSG_TOTAL]++;
	gnet_stats.byte.flowc_ttl[i][t] += size;
	gnet_stats.byte.flowc_ttl[i][MSG_TOTAL] += size;
}

/***
 *** Public functions (gnet.h)
 ***/

void
gnet_stats_get(gnet_stats_t *s)
{
    g_assert(s != NULL);

	GNET_STATS_LOCK;
    *s = gnet_stats;
	GNET_STATS_UNLOCK;
}

void
gnet_stats_tcp_get(gnet_stats_t *s)
{
    g_assert(s != NULL);
	g_assert(thread_is_main());

    *s = gnet_tcp_stats;
}

void
gnet_stats_udp_get(gnet_stats_t *s)
{
    g_assert(s != NULL);
	g_assert(thread_is_main());

    *s = gnet_udp_stats;
}

/* vi: set ts=4 sw=4 cindent: */
