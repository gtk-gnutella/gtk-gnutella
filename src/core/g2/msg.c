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
#include "tree.h"

#include "core/guid.h"

#include "lib/buf.h"			/* For buf_private() */
#include "lib/constants.h"
#include "lib/misc.h"			/* For clamp_strncpy() */
#include "lib/once.h"
#include "lib/patricia.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For plural */
#include "lib/unsigned.h"		/* For size_is_xxx() predicates */

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

	STATIC_ASSERT(G2_MSG_MAX == G_N_ELEMENTS(g2_msg_english_names));
	STATIC_ASSERT(G2_MSG_MAX == G_N_ELEMENTS(g2_msg_symbolic_names));

	g_assert(NULL == g2_msg_pt);

	/*
	 * We must be prepared to handle all the possible packet names, not just
	 * the ones we know.  Therefore, the PATRICIA key size is computed to be
	 * able to handle the maximum architected size.
	 */

	g2_msg_pt = patricia_create(G2_FRAME_NAME_LEN_MAX * 8);	/* Size in bits */

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
 * Get the raw message name present at the start of a G2 packet.
 *
 * @param start		start of message
 * @param len		amount of consecutive bytes we have so far
 *
 * @return the message name if we can intuit it, an empty string otherwise.
 */
const char *
g2_msg_raw_name(const void *start, size_t len)
{
	const char *name;
	size_t namelen;
	char buf[G2_FRAME_NAME_LEN_MAX + 1];

	name = g2_frame_name(start, len, &namelen);
	if (NULL == name)
		return "";

	clamp_strncpy(buf, sizeof buf, name, namelen);
	return constant_str(buf);
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

/**
 * Convert a message type to a symbolic name.
 *
 * @param type		the G2 message type
 *
 * @return the message symbolic name if we can intuit it, "UNKNOWN" otherwise.
 */
const char *
g2_msg_type_name(const enum g2_msg type)
{
	if G_UNLIKELY((uint) type >= UNSIGNED(G2_MSG_MAX))
		return "UNKNOWN";

	return g2_msg_symbolic_names[type];
}

/**
 * Convert a message name to a type.
 *
 * @param name		the G2 message name (root packet name)
 */
enum g2_msg
g2_msg_name_type(const char *name)
{
	size_t namelen;
	bool known;
	void *val;
	int type;

	g2_msg_init();

	namelen = strlen(name);
	known = patricia_lookup_extended_k(g2_msg_pt, name, namelen*8, NULL, &val);

	if (!known)
		return G2_MSG_MAX;

	type = pointer_to_int(val);

	g_assert((uint) type < UNSIGNED(G2_MSG_MAX));

	return type;
}

/**
 * Fetch the MUID in the message, if any is architected.
 *
 * @param t		the message tree
 * @param buf	the buffer to fill with a copy of the MUID
 *
 * @return a pointer to `buf' if OK and we filled the MUID, NULL if there is
 * no valid MUID in the message or the message is not carrying any MUID.
 */
guid_t *
g2_msg_get_muid(const g2_tree_t *t, guid_t *buf)
{
	enum g2_msg m;
	const void *payload;
	size_t paylen;
	size_t offset;

	g_assert(t != NULL);
	g_assert(buf != NULL);

	m = g2_msg_name_type(g2_tree_name(t));

	switch (m) {
	case G2_MSG_Q2:
	case G2_MSG_QA:
		offset = 0;
		break;
	case G2_MSG_QH2:
		offset = 1;			/* First payload byte is the hop count */
		break;
	default:
		return NULL;		/* No MUID in message */
	}

	payload = g2_tree_node_payload(t, &paylen);

	if (NULL == payload || paylen < GUID_RAW_SIZE + offset)
		return NULL;

	/*
	 * Copy the MUID in the supplied buffer for alignment purposes, since
	 * the MUID is offset by 1 byte in /QH2 messages, and return that aligned
	 * pointer.
	 */

	memcpy(buf, const_ptr_add_offset(payload, offset), GUID_RAW_SIZE);

	return buf;
}

/**
 * Fetch the query text from a /Q2 message.
 *
 * @param mb		a message block containing a serialized /Q2
 *
 * @return a pointer to the search text string (as static data), NULL if
 * is no text in the query or the message is not a /Q2.
 */
const char *
g2_msg_search_get_text(const pmsg_t *mb)
{
	str_t *s = str_private(G_STRFUNC, 64);
	const g2_tree_t *t;

	t = g2_frame_deserialize(
			pmsg_start(mb), pmsg_written_size(mb), NULL, FALSE);

	if (NULL == t) {
		return NULL;
	} else {
		const char *payload;
		size_t paylen;

		payload = g2_tree_payload(t, "/Q2/DN", &paylen);

		if (NULL == payload) {
			g2_tree_free_null_const(&t);
			return NULL;
		}

		str_cpy_len(s, payload, paylen);
	}

	g2_tree_free_null_const(&t);
	return str_2c(s);
}

/**
 * Fill supplied buffer with the formatted string describing the message.
 *
 * @param data		start of the G2 message
 * @param len		length of the message
 * @param buf		buffer where formatted string is written
 * @param buflen	length of the destination buffer
 *
 * @return the amount of bytes written.
 */
size_t
g2_msg_infostr_to_buf(const void *data, size_t len, char *buf, size_t buflen)
{
	enum g2_msg m;
	const guid_t *muid = NULL;

	g_assert(size_is_non_negative(len));
	g_assert(size_is_non_negative(buflen));

	/*
	 * Check whether we need to decompile the packet to access the GUID, which
	 * is the payload of the root element in the tree.  Given the way things
	 * are serialized, that would be the last 16 bytes of the message, so
	 * we don't have to deserialize everything just to access it.
	 */

	m = g2_msg_type(data, len);

	switch (m) {
	case G2_MSG_Q2:
	case G2_MSG_QA:
	case G2_MSG_QH2:
		if (len > GUID_RAW_SIZE)
			muid = const_ptr_add_offset(data, len - GUID_RAW_SIZE);
		/* FALL THROUGH */
	default:
		break;
	}

	return str_bprintf(buf, buflen,
		"/%s (%zu byte%s)%s%s",
		g2_msg_type_name(m), len, plural(len),
		NULL == muid ? "" : " #",
		NULL == muid ? "" : guid_hex_str(muid));
}

/**
 * Pretty-print the message information.
 *
 * @param data		start of the G2 message
 * @param len		length of the message
 *
 * @return formatted static string.
 */
const char *
g2_msg_infostr(const void *data, size_t len)
{
	buf_t *b = buf_private(G_STRFUNC, 64);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = g2_msg_infostr_to_buf(data, len, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Log dropped message.
 */
static void
g2_msg_log_dropped(const void *data, size_t len, const char *fmt, va_list args)
{
	char rbuf[256];

	if (fmt != NULL) {
		rbuf[0] = ':';
		rbuf[1] = ' ';
		str_vbprintf(&rbuf[2], sizeof rbuf - 2, fmt, args);
		va_end(args);
	} else {
		rbuf[0] = '\0';
	}

	g_debug("DROP G2 %s%s", g2_msg_infostr(data, len), rbuf);
}

/**
 * Log a dropped message.
 */
void
g2_msg_log_dropped_pmsg(const pmsg_t *mb, const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list args;
		va_start(args, fmt);
		g2_msg_log_dropped(pmsg_start(mb), pmsg_size(mb), fmt, args);
		va_end(args);
	} else {
		g2_msg_log_dropped(pmsg_start(mb), pmsg_size(mb), NULL, NULL);
	}
}

/**
 * Log a dropped message.
 */
void
g2_msg_log_dropped_data(const void *data, size_t len, const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list args;
		va_start(args, fmt);
		g2_msg_log_dropped(data, len, fmt, args);
		va_end(args);
	} else {
		g2_msg_log_dropped(data, len, NULL, NULL);
	}
}

/* vi: set ts=4 sw=4 cindent: */
