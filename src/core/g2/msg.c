/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 message utilities.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "msg.h"

#include "frame.h"

#include "lib/patricia.h"
#include "lib/once.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Message names, in English.
 * This table is indexed by the G2_MSG_* constants defined by enum g2_msg.
 */
static const char *
g2_msg_english_names[] = {
	"Crawler Answer",					/**< G2_MSG_CRAWLA */
	"Crawler Request",					/**< G2_MSG_CRAWLR */
	"Hub Advertisement Walker",			/**< G2_MSG_HAW */
	"Known Hub List",					/**< G2_MSG_KHL */
	"Known Hub List Request",			/**< G2_MSG_KHLR */
	"Known Hub List Acknowledgment",	/**< G2_MSG_KHLA */
	"Local Node Information",			/**< G2_MSG_LNI */
	"Ping",								/**< G2_MSG_PI */
	"Pong",								/**< G2_MSG_PO */
	"Push",								/**< G2_MSG_PUSH */
	"Query Key Acknowledgement",		/**< G2_MSG_QKA */
	"Query Key Request",				/**< G2_MSG_QKR */
	"Query",							/**< G2_MSG_Q2 */
	"Query Acknowledgment",				/**< G2_MSG_QA */
	"Query Hit",						/**< G2_MSG_QH2 */
	"Query Hash Table",					/**< G2_MSG_QHT */
	"User Profile Challenge",			/**< G2_MSG_UPROC */
	"User Profile Delivery",			/**< G2_MSG_UPROD */
};

/**
 * Message names, symbolic.
 * This table is indexed by the G2_MSG_* constants defined by enum g2_msg.
 */
static const char *
g2_msg_symbolic_names[] = {
	"CRAWLA",			/**< G2_MSG_CRAWLA */
	"CRAWLR",			/**< G2_MSG_CRAWLR */
	"HAW",				/**< G2_MSG_HAW */
	"KHL",				/**< G2_MSG_KHL */
	"KHLR",				/**< G2_MSG_KHLR */
	"KHLA",				/**< G2_MSG_KHLA */
	"LNI",				/**< G2_MSG_LNI */
	"PI",				/**< G2_MSG_PI */
	"PO",				/**< G2_MSG_PO */
	"PUSH",				/**< G2_MSG_PUSH */
	"QKA",				/**< G2_MSG_QKA */
	"QKR",				/**< G2_MSG_QKR */
	"Q2",				/**< G2_MSG_Q2 */
	"QA",				/**< G2_MSG_QA */
	"QH2",				/**< G2_MSG_QH2 */
	"QHT",				/**< G2_MSG_QHT */
	"UPROC",			/**< G2_MSG_UPROC */
	"UPROD",			/**< G2_MSG_UPROD */
};

static patricia_t *g2_msg_pt;	/* Maps a name into a G2_MSG_* constant */
static once_flag_t g2_msg_pt_created;

/**
 * Build the PATRICIA that maps a message name string into our internal
 * message ID.
 */
static void
g2_msg_build_map(void)
{
	uint i;
	size_t maxlen;

	STATIC_ASSERT(G2_MSG_MAX == G_N_ELEMENTS(g2_msg_english_names));
	STATIC_ASSERT(G2_MSG_MAX == G_N_ELEMENTS(g2_msg_symbolic_names));

	g_assert(NULL == g2_msg_pt);

	for (i = 0, maxlen = 0; i < G_N_ELEMENTS(g2_msg_symbolic_names); i++) {
		size_t len = strlen(g2_msg_symbolic_names[i]);
		maxlen = MAX(maxlen, len);
	}

	g2_msg_pt = patricia_create(maxlen * 8);		/* Size is in bits */

	for (i = 0; i < G_N_ELEMENTS(g2_msg_symbolic_names); i++) {
		const char *key = g2_msg_symbolic_names[i];
		size_t len = strlen(key);

		patricia_insert_k(g2_msg_pt, key, len * 8, int_to_pointer(i));
	}
}

/**
 * Initialize the PATRICIA map.
 */
static inline ALWAYS_INLINE void
g2_msg_init(void)
{
	ONCE_FLAG_RUN(g2_msg_pt_created, g2_msg_build_map);
}

/**
 * Get the type of message intuited from the start of a G2 packet.
 *
 * @param start		start of message
 * @param len		amount of consecutive bytes we have so far
 *
 * @return the message type if we can intuit it, G2_MSG_MAX otherwise.
 */
enum g2_msg
g2_msg_type(const void *start, size_t len)
{
	const char *name;
	size_t namelen;
	bool known;
	void *val;
	int type;

	g2_msg_init();

	name = g2_frame_name(start, len, &namelen);
	if (NULL == name)
		return G2_MSG_MAX;

	known = patricia_lookup_extended_k(g2_msg_pt, name, namelen*8, NULL, &val);

	if (!known)
		return G2_MSG_MAX;

	type = pointer_to_int(val);

	g_assert((uint) type < UNSIGNED(G2_MSG_MAX));

	return type;
}

/**
 * Get the message symbolic name, intuited from the start of a G2 packet.
 *
 * @param start		start of message
 * @param len		amount of consecutive bytes we have so far
 *
 * @return the message symbolic name if we can intuit it, "UNKNOWN" otherwise.
 */
const char *
g2_msg_name(const void *start, size_t len)
{
	enum g2_msg m;

	m = g2_msg_type(start, len);

	if (G2_MSG_MAX == m)
		return "UNKNOWN";

	return g2_msg_symbolic_names[m];
}

/**
 * Get the message English name, intuited from the start of a G2 packet.
 *
 * @param start		start of message
 * @param len		amount of consecutive bytes we have so far
 *
 * @return the message symbolic name if we can intuit it, "UNKNOWN" otherwise.
 */
const char *
g2_msg_full_name(const void *start, size_t len)
{
	enum g2_msg m;

	m = g2_msg_type(start, len);

	if (G2_MSG_MAX == m)
		return "UNKNOWN";

	return g2_msg_english_names[m];
}

/* vi: set ts=4 sw=4 cindent: */
