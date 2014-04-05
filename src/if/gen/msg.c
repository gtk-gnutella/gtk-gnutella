/*
 * Generated on Sat Apr  5 10:43:36 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl msg.lst msg.dsc
 */

#include "common.h"

#include "msg.h"

#include "lib/override.h"

/*
 * English descriptions for msg_type_t.
 */
static const char *msg_type_description[] = {
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
	N_("G2 Crawl Request"),
	N_("G2 Hub Advertisement"),
	N_("G2 Hub List"),
	N_("G2 Hub List Req"),
	N_("G2 Hub List Ack"),
	N_("G2 Local Node Info"),
	N_("G2 Ping"),
	N_("G2 Pong"),
	N_("G2 Push"),
	N_("G2 Query Key Ack"),
	N_("G2 Query Key Req"),
	N_("G2 Query"),
	N_("G2 Query Ack"),
	N_("G2 Query Hit"),
	N_("G2 Query Hash Table"),
	N_("G2 User Profile Check"),
	N_("G2 User Profile Data"),
	N_("Total"),
};

/**
 * @return the English description of the enum value, NULL if out of bounds.
 */
const char *
gnet_msg_type_description(msg_type_t x)
{
	g_return_val_if_fail(
		UNSIGNED(x) < G_N_ELEMENTS(msg_type_description), NULL);

	return msg_type_description[x];
}

/* vi: set ts=4 sw=4 cindent: */
