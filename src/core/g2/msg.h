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

#ifndef _core_g2_msg_h_
#define _core_g2_msg_h_

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

enum g2_msg g2_msg_type(const void *start, size_t len);
const char *g2_msg_name(const void *start, size_t len);
const char *g2_msg_full_name(const void *start, size_t len);
const char *g2_msg_type_name(const enum g2_msg type);
const char *g2_msg_raw_name(const void *start, size_t len);

#endif /* _core_g2_msg_h_ */

/* vi: set ts=4 sw=4 cindent: */
