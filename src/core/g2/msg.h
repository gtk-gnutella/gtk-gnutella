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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _core_g2_msg_h_
#define _core_g2_msg_h_

#include "lib/pmsg.h"

/**
 * Known G2 messages -- the IDs are just for internal use (i.e. arbitrary).
 */
enum g2_msg {
	G2_MSG_CRAWLA = 0,	/**< Crawler Answer */
	G2_MSG_CRAWLR,		/**< Crawler Request */
	G2_MSG_HAW,			/**< Hub Advertisement Walker */
	G2_MSG_KHL,			/**< Known Hub List */
	G2_MSG_KHLR,		/**< Known Hub List Request */
	G2_MSG_KHLA,		/**< Known Hub List Acknowledgment */
	G2_MSG_LNI,			/**< Local Node Information */
	G2_MSG_PI,			/**< Ping */
	G2_MSG_PO,			/**< Pong */
	G2_MSG_PUSH,		/**< Push */
	G2_MSG_QKA,			/**< Query Key Acknowledgement */
	G2_MSG_QKR,			/**< Query Key Request */
	G2_MSG_Q2,			/**< Query */
	G2_MSG_QA,			/**< Query Acknowledgment */
	G2_MSG_QH2,			/**< Query Hit */
	G2_MSG_QHT,			/**< Query Hash Table */
	G2_MSG_UPROC,		/**< User Profile Challenge */
	G2_MSG_UPROD,		/**< User Profile Delivery */

	G2_MSG_MAX
};

/*
 * Public interface.
 */

struct guid;
struct g2_tree;

enum g2_msg g2_msg_type(const void *start, size_t len);
const char *g2_msg_name(const void *start, size_t len);
const char *g2_msg_full_name(const void *start, size_t len);
const char *g2_msg_type_name(const enum g2_msg type);
const char *g2_msg_raw_name(const void *start, size_t len);
enum g2_msg g2_msg_name_type(const char *name);

struct guid *g2_msg_get_muid(const struct g2_tree *t, struct guid *buf);
const char *g2_msg_search_get_text(const pmsg_t *mb);

const char *g2_msg_infostr(const void *data, size_t len);
size_t g2_msg_infostr_to_buf(const void *data, size_t len,
	char *buf, size_t buf_size);

void g2_msg_log_dropped_pmsg(const pmsg_t *mb, const char *fmr, ...)
	G_PRINTF(2, 3);
void g2_msg_log_dropped_data(const void *data, size_t len, const char *fmt, ...)
	G_PRINTF(3, 4);

/**
 * @return the string name to use as packet name for x.
 *
 * This makes sure we don't introduce a typo, as could be the case if we
 * simply hardwired the string for x: here G2_NAME(x) stands for "x" only
 * when x is a valid name (otherwise it's a compilation error).
 */
#define G2_NAME(x)		g2_msg_type_name(G2_MSG_ ## x)

/**
 * Convenience shortcut for getting the G2 message info from a pmsg_t.
 */
static inline const char *
g2_msg_infostr_mb(const pmsg_t *mb)
{
	return g2_msg_infostr(pmsg_phys_base(mb), pmsg_written_size(mb));
}

/**
 * Convenience shortcut for getting the G2 message type from a pmsg_t.
 */
static inline enum g2_msg
g2_msg_type_mb(const pmsg_t *mb)
{
	return g2_msg_type(pmsg_phys_base(mb), pmsg_written_size(mb));
}

#endif /* _core_g2_msg_h_ */

/* vi: set ts=4 sw=4 cindent: */
