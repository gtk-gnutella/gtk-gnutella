/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef _gnutella_h_
#define _gnutella_h_

#include <arpa/inet.h>	/* For ntohl(), htonl() */

#include "gnet.h"
#include "gnet_property_priv.h"

/*
 * Macros
 */

#define READ_GUINT16_LE(a,v) G_STMT_START { \
    memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); \
} G_STMT_END

#define WRITE_GUINT16_LE(v,a) G_STMT_START { \
    guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); \
} G_STMT_END

#define READ_GUINT32_LE(a,v) G_STMT_START { \
    memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); \
} G_STMT_END

#define READ_GUINT32_BE(a,v) G_STMT_START { \
    memcpy(&v, a, 4); v = ntohl(v); \
} G_STMT_END

#define WRITE_GUINT32_LE(v,a) G_STMT_START { \
    guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); \
} G_STMT_END

#define WRITE_GUINT32_BE(v,a) G_STMT_START { \
    guint32 _v = htonl(v); memcpy(a, &_v, 4); \
} G_STMT_END

/*
 * Constants
 */

#define GTA_MSG_INIT					0x00
#define GTA_MSG_INIT_RESPONSE			0x01
#define GTA_MSG_BYE						0x02
#define GTA_MSG_QRP						0x30
#define GTA_MSG_VENDOR					0x31	/* Vendor-specific */
#define GTA_MSG_STANDARD				0x32	/* Standard vendor-specific */
#define GTA_MSG_PUSH_REQUEST			0x40
#define GTA_MSG_SEARCH					0x80
#define GTA_MSG_SEARCH_RESULTS			0x81

#define GTA_MSGV_QRP_RESET				0x00
#define GTA_MSGV_QRP_PATCH				0x01

/*
 * Structures
 */

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(p)
#endif

/* Messages structures */

struct gnutella_header {
	guchar muid[16];
	guchar function;
	guchar ttl;
	guchar hops;
	guchar size[4];
} __attribute__((__packed__));

struct gnutella_msg_init {
	struct gnutella_header header;
} __attribute__((__packed__));

struct gnutella_init_response {
	guchar host_port[2];
	guchar host_ip[4];
	guchar files_count[4];
	guchar kbytes_count[4];
} __attribute__((__packed__));

struct gnutella_msg_init_response {
	struct gnutella_header header;
	struct gnutella_init_response response;
} __attribute__((__packed__));

struct gnutella_search {
	guchar speed[2];
	guchar query[0];
} __attribute__((__packed__));

struct gnutella_search_results {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];
	guchar records[0];

	/* Last 16 bytes = client_id */
} __attribute__((__packed__));

struct gnutella_msg_search {
	struct gnutella_header header;
	struct gnutella_search search;
} __attribute__((__packed__));

struct gnutella_push_request {
	guchar guid[16];
	guchar file_id[4];
	guchar host_ip[4];
	guchar host_port[2];
} __attribute__((__packed__));

struct gnutella_msg_push_request {
	struct gnutella_header header;
	struct gnutella_push_request request;
} __attribute__((__packed__));

struct gnutella_bye {
	guchar code[2];
	guchar message[0];
} __attribute__((__packed__));

struct gnutella_qrp_reset {
	guchar variant;			/* 0x00 */
	guchar table_length[4];	/* little endian */
	guchar infinity;
} __attribute__((__packed__));

struct gnutella_msg_qrp_reset {
	struct gnutella_header header;
	struct gnutella_qrp_reset data;
} __attribute__((__packed__));

struct gnutella_qrp_patch {
	guchar variant;			/* 0x01 */
	guchar seq_no;
	guchar seq_size;
	guchar compressor;
	guchar entry_bits;
} __attribute__((__packed__));

struct gnutella_msg_qrp_patch {
	struct gnutella_header header;
	struct gnutella_qrp_patch data;
} __attribute__((__packed__));

struct gnutella_vendor {
	guchar vendor[4];		/* E.g. "GTKG" */
	guchar selector_id[2];	/* Message selector ID, little endian */
	guchar version[2];		/* Message version number, little endian */
	/* payload follows */
} __attribute__((__packed__));

struct gnutella_msg_vendor {
	struct gnutella_header header;
	struct gnutella_vendor data;
} __attribute__((__packed__));

/* main.c */

extern struct gnutella_socket *s_listen;
extern gchar *start_rfc822_date;

#endif							/* _gnutella_h_ */

/* vi: set ts=4: */
