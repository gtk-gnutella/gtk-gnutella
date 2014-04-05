/*
 * Generated on Sat Apr  5 12:09:15 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl drop.lst
 */

#include "common.h"

#include "msg_drop.h"

#include "lib/str.h"
#include "lib/override.h"	/* Must be the last header included */

/*
 * Symbolic descriptions for msg_drop_reason_t.
 */
static const char *msg_drop_reasons[] = {
	"bad_size",
	"too_small",
	"too_large",
	"way_too_large",
	"too_old",
	"unknown_type",
	"unexpected",
	"ttl0",
	"improper_hops_ttl",
	"max_ttl_exceeded",
	"throttle",
	"limit",
	"transient",
	"pong_unusable",
	"hard_ttl_limit",
	"max_hop_count",
	"route_lost",
	"no_route",
	"duplicate",
	"oob_proxy_conflict",
	"to_banned",
	"from_banned",
	"shutdown",
	"flow_control",
	"query_no_nul",
	"query_too_short",
	"query_overhead",
	"bad_urn",
	"malformed_sha1",
	"malformed_utf_8",
	"bad_result",
	"bad_return_address",
	"hostile_ip",
	"shunned_ip",
	"morpheus_bogus",
	"spam",
	"evil",
	"media",
	"inflate_error",
	"unknown_header_flags",
	"own_result",
	"own_query",
	"ancient_query",
	"blank_servent_id",
	"guess_missing_token",
	"guess_invalid_token",
	"dht_invalid_token",
	"dht_too_many_store",
	"dht_unparseable",
	"g2_unexpected",
	"network_crossing",
};

/**
 * @return the symbolic description of the enum value.
 */
const char *
gnet_stats_drop_reason_name(msg_drop_reason_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= G_N_ELEMENTS(msg_drop_reasons)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid msg_drop_reason_t code: %d", (int) x);
		return str_2c(s);
	}

	return msg_drop_reasons[x];
}

/*
 * English descriptions for msg_drop_reason_t.
 */
static const char *msg_drop_reason_text[] = {
	N_("Bad size"),
	N_("Too small"),
	N_("Too large"),
	N_("Way too large"),
	N_("Too old"),
	N_("Unknown message type"),
	N_("Unexpected message"),
	N_("Message sent with TTL = 0"),
	N_("Improper hops/ttl combination"),
	N_("Max TTL exceeded"),
	N_("Message throttle"),
	N_("Message matched limits"),
	N_("Transient node"),
	N_("Unusable Pong"),
	N_("Hard TTL limit reached"),
	N_("Max hop count reached"),
	N_("Route lost"),
	N_("No route"),
	N_("Duplicate message"),
	N_("OOB Proxy MUID Conflict"),
	N_("Message to banned GUID"),
	N_("Message from banned GUID"),
	N_("Node shutting down"),
	N_("TX flow control"),
	N_("Query text had no trailing NUL"),
	N_("Query text too short"),
	N_("Query had unnecessary overhead"),
	N_("Query had bad URN"),
	N_("Message with malformed SHA1"),
	N_("Message with malformed UTF-8"),
	N_("Malformed Query Hit"),
	N_("Bad return address"),
	N_("Hostile IP address"),
	N_("Shunned IP address"),
	N_("Bogus result from Morpheus"),
	N_("Spam"),
	N_("Evil filename"),
	N_("Improper media type"),
	N_("Payload inflating error"),
	N_("Unknown header flags present"),
	N_("Own search results"),
	N_("Own queries"),
	N_("Ancient query format"),
	N_("Blank Servent ID"),
	N_("GUESS Query missing token"),
	N_("GUESS Invalid query token"),
	N_("DHT Invalid security token"),
	N_("DHT Too many STORE requests"),
	N_("DHT Malformed message"),
	N_("G2 Unexpected message"),
	N_("Cannot cross networks"),
};

/**
 * @return the English description of the enum value.
 */
const char *
gnet_stats_drop_reason_to_string(msg_drop_reason_t x)
{
	if G_UNLIKELY(UNSIGNED(x) >= G_N_ELEMENTS(msg_drop_reason_text)) {
		str_t *s = str_private(G_STRFUNC, 80);
		str_printf(s, "Invalid msg_drop_reason_t code: %d", (int) x);
		return str_2c(s);
	}

	return msg_drop_reason_text[x];
}

/* vi: set ts=4 sw=4 cindent: */
