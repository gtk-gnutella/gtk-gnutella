/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _core_gnutella_h_
#define _core_gnutella_h_

#include "if/core/gnutella.h"

/*
 * Constants
 */

#define GTA_MSGV_QRP_RESET				0x00
#define GTA_MSGV_QRP_PATCH				0x01

/*
 * Structures
 */

/* Messages structures */

/**
 * NOTE: Types with a gnutella_msg_ prefix include gnutella_header_t
 *       whereas other gnutella_*_t types exclude the header and refer
 *       to the packet type specific data after the generic header.
 */

/**
 * NOTE: The structures are only shown for documentation and readability
 *       purposes. Unfortunately, there is no portable way (i.e., without
 *		 resorting to compiler-specific extensions) to map any kind of
 *		 structure directly to binary packets as structures may contain
 *       padding between members and at the end even if a structure
 *       consists of nothing but char arrays.
 *		 Therefore, accessor functions are used instead to guarantee
 *		 that the correct bytes of a packet are read and written.
 */

/* The logic layout of the PING message is as follows:
 *
 *  struct gnutella_msg_init_ {
 *		gnutella_header_t header;
 *
 *		GGEP data may follow
 * };
 *
 */

typedef guint8 gnutella_msg_init_t[GTA_HEADER_SIZE];

/* The logic layout of the PONG message specific layout is as follows:
 *
 * struct gnutella_init_response_ {
 *		guint16 host_port;
 *		guint32 host_ip;
 *		guint32 files_count;
 *		guint32 kbytes_count;
 * };
 *
 */

typedef guint8 gnutella_init_response_t[14];

static inline guint16
gnutella_init_response_get_host_port(const void *data)
{
	const guint8 *u8 = data;
	return peek_le16(&u8[0]);
}

static inline guint32
gnutella_init_response_get_host_ip(const void *data)
{
	const guint8 *u8 = data;
	return peek_be32(&u8[2]);
}

static inline guint32
gnutella_init_response_get_files_count(const void *data)
{
	const guint8 *u8 = data;
	return peek_le32(&u8[6]);
}


static inline guint32
gnutella_init_response_get_kbytes_count(const void *data)
{
	const guint8 *u8 = data;
	return peek_le32(&u8[10]);
}

/* The logic layout of the PONG message is as follows:
 *
 * struct gnutella_msg_init_response_ {
 *
 *		gnutella_header_t header;
 *		gnutella_init_response_t response;
 *
 *		GGEP data may follow
 * };
 *
 */

typedef	guint8 gnutella_msg_init_response_t[GTA_HEADER_SIZE + sizeof(gnutella_init_response_t)];

static inline gnutella_header_t *
gnutella_msg_init_response_header(gnutella_msg_init_response_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_init_response_set_host_port(gnutella_msg_init_response_t *msg,
	guint16 port)
{
	guint8 *u8 = (void *) msg;
	poke_le16(&u8[GTA_HEADER_SIZE], port);
}

static inline void
gnutella_msg_init_response_set_host_ip(gnutella_msg_init_response_t *msg,
	guint32 ip)
{
	guint8 *u8 = (void *) msg;
	poke_be32(&u8[GTA_HEADER_SIZE + 2], ip);
}

static inline void
gnutella_msg_init_response_set_files_count(gnutella_msg_init_response_t *msg,
	guint32 files_count)
{
	guint8 *u8 = (void *) msg;
	poke_le32(&u8[GTA_HEADER_SIZE + 6], files_count);
}

static inline void
gnutella_msg_init_response_set_kbytes_count(gnutella_msg_init_response_t *msg,
	guint32 kbytes_count)
{
	guint8 *u8 = (void *) msg;
	poke_le32(&u8[GTA_HEADER_SIZE + 10], kbytes_count);
}

/* The logic layout of the QHIT message specific payload is as follows:
 *
 * struct gnutella_search_results_ {
 *	guint8 num_recs;
 *	guint16 host_port;
 *	guint32 host_ip;
 *	guint32 host_speed;
 *
 *	record data follows
 *  ...
 *
 *	Last 16 bytes = client_id
 * };
 *
 */

typedef	guint8 gnutella_search_results_t[11];

static inline guint8
gnutella_search_results_get_num_recs(const void *data)
{
	const guint8 *u8 = data;
	return u8[0];
}

static inline guint16
gnutella_search_results_get_host_port(const void *data)
{
	const guint8 *u8 = data;
	return peek_le16(&u8[1]);
}

static inline guint32
gnutella_search_results_get_host_ip(const void *data)
{
	const guint8 *u8 = data;
	return peek_be32(&u8[3]);
}

static inline guint32
gnutella_search_results_get_host_speed(const void *data)
{
	const guint8 *u8 = data;
	return peek_le32(&u8[7]);
}

/* The logic layout of the QHIT message is as follows:
 *
 * struct gnutella_msg_search_results_ {
 *		gnutella_header_t header;
 *		gnutella_search_results_t results;
 * };
 *
 */

typedef guint8 gnutella_msg_search_results_t[GTA_HEADER_SIZE + sizeof(gnutella_search_results_t)];

static inline gnutella_header_t *
gnutella_msg_search_results_header(gnutella_msg_search_results_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_search_results_set_num_recs(gnutella_msg_search_results_t *msg,
	guint8 num_recs)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE] = num_recs;
}

static inline void
gnutella_msg_search_results_set_host_port(gnutella_msg_search_results_t *msg,
	guint16 port)
{
	guint8 *u8 = (void *) msg;
	poke_le16(&u8[GTA_HEADER_SIZE + 1], port);
}

static inline void
gnutella_msg_search_results_set_host_ip(gnutella_msg_search_results_t *msg,
	guint32 ip)
{
	guint8 *u8 = (void *) msg;
	poke_be32(&u8[GTA_HEADER_SIZE + 3], ip);
}

static inline void
gnutella_msg_search_results_set_host_speed(gnutella_msg_search_results_t *msg,
	guint32 speed)
{
	guint8 *u8 = (void *) msg;
	poke_le32(&u8[GTA_HEADER_SIZE + 7], speed);
}

/* The logic layout of the QUERY message specific payload is as follows:
 *
 * struct gnutella_search_ {
 *		guint16 speed;
 *
 *		query string follows
 * };
 *
 */

typedef	guint8 gnutella_search_t[2];
	
/* The logic layout of the QUERY message is as follows:
 *
 *  struct gnutella_msg_search_ {
 *		gnutella_header_t header;
 *		gnutella_search_t search;
 * };
 *
 */

typedef	guint8 gnutella_msg_search_t[GTA_HEADER_SIZE + sizeof(gnutella_search_t)];

static inline gnutella_header_t *
gnutella_msg_search_header(gnutella_msg_search_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_search_set_speed(gnutella_msg_search_t *msg, guint16 speed)
{
	guint8 *u8 = (void *) msg;
	poke_le16(&u8[GTA_HEADER_SIZE], speed);
}

/*
 * Compute start of search string (which is NUL terminated) in query.
 * The "+2" skips the "speed" field in the query.
 */
static inline const gchar *
gnutella_msg_search_get_text(const void *data)
{
	const guint8 *u8 = data;
	return (const gchar *) &u8[GTA_HEADER_SIZE + 2];
}

/* The logic layout of the PUSH message specific payload is as follows:
 *
 * struct gnutella_push_request_ {
 *		guint8 guid[16];
 *		guint32 file_id;
 *		guint32 host_ip;
 *		guint16 host_port;
 * };
 *
 */

typedef	guint8 gnutella_push_request_t[26];

/* The logic layout of the PUSH message is as follows:
 *
 *  struct gnutella_msg_push_request_ {
 *		gnutella_header_t header;
 *		gnutella_push_request_t request;
 *
 *		GGEP data may follow
 *  };
 *
 */

typedef	guint8 gnutella_msg_push_request_t[GTA_HEADER_SIZE + sizeof(gnutella_push_request_t)];

static inline gnutella_header_t *
gnutella_msg_push_request_header(gnutella_msg_push_request_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_push_request_set_guid(gnutella_msg_push_request_t *msg,
	const gchar *guid)
{
	guint8 *u8 = (void *) msg;
	memcpy(&u8[GTA_HEADER_SIZE], guid, 16);	
}

static inline void
gnutella_msg_push_request_set_file_id(gnutella_msg_push_request_t *msg,
	guint32 file_id)
{
	guint8 *u8 = (void *) msg;
	poke_le32(&u8[GTA_HEADER_SIZE + 16], file_id);
}

static inline void
gnutella_msg_push_request_set_host_ip(gnutella_msg_push_request_t *msg,
	guint32 ip)
{
	guint8 *u8 = (void *) msg;
	poke_be32(&u8[GTA_HEADER_SIZE + 20], ip);
}

static inline void
gnutella_msg_push_request_set_host_port(gnutella_msg_push_request_t *msg,
	guint16 port)
{
	guint8 *u8 = (void *) msg;
	poke_le16(&u8[GTA_HEADER_SIZE + 24], port);
}

/* The logic layout of the BYE message specific payload is as follows:
 *
 * struct gnutella_bye_ {
 *		guint16 code;
 *
 *		message string follows
 * };
 *
 */

typedef guint8 gnutella_bye_t[2];

static inline void
gnutella_bye_set_code(void *data, guint16 code)
{
	guint8 *u8 = data;
	poke_le16(&u8[0], code);
};

/* The logic layout of the QRP RESET message specific payload is as follows:
 *
 * struct gnutella_qrp_reset_ {
 *		guint8 variant;		// 0x00
 *		guint32 table_length;
 *		guint8 infinity;
 * };
 *
 */

typedef guint8 gnutella_qrp_reset_t[6];

static inline guint8
gnutella_qrp_reset_get_variant(const void *data)
{
	const guint8 *u8 = data;
	return u8[0];
}

static inline guint32
gnutella_qrp_reset_get_table_length(const void *data)
{
	const guint8 *u8 = data;
	return peek_le32(&u8[1]);
}

static inline guint8
gnutella_qrp_reset_get_infinity(const void *data)
{
	const guint8 *u8 = data;
	return u8[5];
}

/* The logic layout of the QRP RESET message is as follows:
 *
 * struct gnutella_msg_qrp_reset_ {
 *		gnutella_header_t header;
 *		gnutella_qrp_reset_t qrp_reset;
 * };
 *
 */

typedef guint8 gnutella_msg_qrp_reset_t[GTA_HEADER_SIZE + sizeof(gnutella_qrp_reset_t)];

static inline gnutella_header_t *
gnutella_msg_qrp_reset_header(gnutella_msg_qrp_reset_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_qrp_reset_set_variant(gnutella_msg_qrp_reset_t *msg,
	guint8 variant)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE] = variant;
}

static inline void
gnutella_msg_qrp_reset_set_table_length(gnutella_msg_qrp_reset_t *msg,
	guint32 table_length)
{
	guint8 *u8 = (void *) msg;
	poke_le32(&u8[GTA_HEADER_SIZE + 1], table_length);
}

static inline void
gnutella_msg_qrp_reset_set_infinity(gnutella_msg_qrp_reset_t *msg,
	guint8 infinity)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE + 5] = infinity;
}

/* The logic layout of the QRP PATCH message specific payload is as follows:
 *
 * struct gnutella_qrp_patch_ {
 *		guint8 variant;			// 0x01
 *		guint8 seq_no;
 *		guint8 seq_size;
 *		guint8 compressor;
 *		guint8 entry_bits;
 * };
 *
 */

typedef guint8 gnutella_qrp_patch_t[5];
	
static inline guint8
gnutella_qrp_patch_get_variant(const void *data)
{
	const guint8 *u8 = data;
	return u8[0];
}

static inline guint8
gnutella_qrp_patch_get_seq_no(const void *data)
{
	const guint8 *u8 = data;
	return u8[1];
}

static inline guint8
gnutella_qrp_patch_get_seq_size(const void *data)
{
	const guint8 *u8 = data;
	return u8[2];
}

static inline guint8
gnutella_qrp_patch_get_compressor(const void *data)
{
	const guint8 *u8 = data;
	return u8[3];
}

static inline guint8
gnutella_qrp_patch_get_entry_bits(const void *data)
{
	const guint8 *u8 = data;
	return u8[4];
}

/* The logic layout of the QRP PATCH message is as follows:
 *
 * struct gnutella_msg_qrp_patch_ {
 *		gnutella_header_t header;
 *		gnutella_qrp_patch_t data;
 * };
 *
 */

typedef	guint8 gnutella_msg_qrp_patch_t[GTA_HEADER_SIZE + sizeof(gnutella_qrp_patch_t)];

static inline gnutella_header_t *
gnutella_msg_qrp_patch_header(gnutella_msg_qrp_patch_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_qrp_patch_set_variant(gnutella_msg_qrp_patch_t *msg,
	guint8 variant)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE] = variant;
}

static inline void
gnutella_msg_qrp_patch_set_seq_no(gnutella_msg_qrp_patch_t *msg,
	guint8 seq_no)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE + 1] = seq_no;
}

static inline void
gnutella_msg_qrp_patch_set_seq_size(gnutella_msg_qrp_patch_t *msg,
	guint8 seq_size)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE + 2] = seq_size;
}

static inline void
gnutella_msg_qrp_patch_set_compressor(gnutella_msg_qrp_patch_t *msg,
	guint8 compressor)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE + 3] = compressor;
}

static inline void
gnutella_msg_qrp_patch_set_entry_bits(gnutella_msg_qrp_patch_t *msg,
	guint8 entry_bits)
{
	guint8 *u8 = (void *) msg;
	u8[GTA_HEADER_SIZE + 4] = entry_bits;
}

/* The logic layout of the VENDOR message specific payload is as follows:
 *
 * struct gnutella_vendor_ {
 *		guint8[4] vendor;		// For example, "GTKG"
 *		guint16 selector_id;	// Message selector ID, little endian
 *		guint16 version;		// Message version number, little endian
 *
 *		payload follows
 * };
 *
 */

typedef guint8 gnutella_vendor_t[8];
	
static inline guint32
gnutella_vendor_get_code(const void *data)
{
	const guint8 *u8 = data;
	guint32 code;
	/* Keep the big-endian byte order */
	memcpy(&code, &u8[0], 4);
	return code;
}

static inline void
gnutella_vendor_set_code(gnutella_vendor_t *data, guint32 code)
{
	guint8 *u8 = (guint8 *) data;
	poke_be32(&u8[0], code);
}

static inline guint16
gnutella_vendor_get_selector_id(const void *data)
{
	const guint8 *u8 = data;
	return peek_le16(&u8[4]);
}

static inline void
gnutella_vendor_set_selector_id(gnutella_vendor_t *data, guint16 selector_id)
{
	guint8 *u8 = (guint8 *) data;
	poke_le16(&u8[4], selector_id);
}

static inline guint16
gnutella_vendor_get_version(const void *data)
{
	const guint8 *u8 = data;
	return peek_le16(&u8[6]);
}

static inline void
gnutella_vendor_set_version(gnutella_vendor_t *data, guint16 version)
{
	guint8 *u8 = (guint8 *) data;
	poke_le16(&u8[6], version);
}

/* The logic layout of the VENDOR message is as follows:
 *
 * struct gnutella_msg_vendor_ {
 *		gnutella_header_t header;
 *		gnutella_vendor_t data;
 * };
 *
 */

typedef guint8 gnutella_msg_vendor_[GTA_HEADER_SIZE + sizeof(gnutella_vendor_t)];

/* The logic layout of the HSEP message is as follows:
 *
 * struct gnutella_msg_hsep_ {
 *		gnutella_header_t header;
 *		guint64 triple[3];
 * };
 *
 */

typedef	guint8 gnutella_msg_hsep_t[GTA_HEADER_SIZE + 3 * 8];

static inline gnutella_header_t *
gnutella_msg_hsep_header(gnutella_msg_hsep_t *msg)
{
	return (gnutella_header_t *) msg;
}

static inline void
gnutella_msg_size_check(void)
{
	STATIC_ASSERT(23 == sizeof(gnutella_msg_init_t));

	STATIC_ASSERT(14 == sizeof(gnutella_init_response_t));
	STATIC_ASSERT(23 + 14 == sizeof(gnutella_msg_init_response_t));
	
	STATIC_ASSERT(11 == sizeof(gnutella_search_results_t));
	STATIC_ASSERT(23 + 11 == sizeof(gnutella_msg_search_results_t));
	
	STATIC_ASSERT(2 == sizeof(gnutella_search_t));
	STATIC_ASSERT(23 + 2 == sizeof(gnutella_msg_search_t));
	
	STATIC_ASSERT(26 == sizeof(gnutella_push_request_t));
	STATIC_ASSERT(23 + 26 == sizeof(gnutella_msg_push_request_t));

	STATIC_ASSERT(2 == sizeof(gnutella_bye_t));

	STATIC_ASSERT(6 == sizeof(gnutella_qrp_reset_t));
	STATIC_ASSERT(23 + 6 == sizeof(gnutella_msg_qrp_reset_t));
	
	STATIC_ASSERT(5 == sizeof(gnutella_qrp_patch_t));
	STATIC_ASSERT(23 + 5 == sizeof(gnutella_msg_qrp_patch_t));
	
	STATIC_ASSERT(8 == sizeof(gnutella_vendor_t));

	STATIC_ASSERT(23 + 24 == sizeof(gnutella_msg_hsep_t));
}

#endif /* _core_gnutella_h_ */

/* vi: set ts=4 sw=4 cindent: */
