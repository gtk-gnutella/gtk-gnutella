/*
 * Copyright (c) 2003, Raphael Manfredi
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

#ifndef _gtk_search_result_h_
#define _gtk_search_result_h_

struct guid;

typedef enum {
	RESULTS_SET_MAGIC = 0x244eb853U
} results_set_magic_t;

/**
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.  Each time the structure is dispatched,
 * the `refcount' is incremented, so that we don't free it and its content
 * until it has been "forgotten" that many times.
 *
 * @attention
 * NB: we reuse the pure data structure gnet_host_vec_t from the core.  It
 *     is purely descriptive anyway.
 */
typedef struct results_set {
	results_set_magic_t magic;
	int num_recs;

	const struct guid *guid;	/**< Servent's GUID (atom) */
	const char *version;		/**< Version information (atom) */
	const char *hostname;		/**< Optional: server's hostname (atom) */
	const char *query;			/**< Optional: original query (atom) */

	GSList *records;
    GSList *schl;
	struct gnet_host_vec *proxies;	/**< Optional: known push proxies */

	host_addr_t addr;
	host_addr_t last_hop;		/**< IP of delivering node */
	time_t  stamp;				/**< Reception time of the hit */

	guint32 vendor;				/**< Vendor code; host endian */
	guint32 status;				/**< Parsed status bits from trailer */
	guint16 country;			/**< Country code -- encoded ISO3166 */
	guint16 port;
	guint16 speed;
	guint8 hops;
	guint8 ttl;
	guint8 media;				/**< Optional: media type filtering */
} results_set_t;

typedef enum {
	RECORD_MAGIC = 0x3fb9c04e
} record_magic_t;

/**
 * Partial results.
 */
struct precord {
	filesize_t available;		/**< Available bytes, if partial file */
	time_t mod_time;			/**< Last modification time of partial file */
};

/**
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 *
 * When a record is kept in a search window for display, it is put into
 * a hash table and its `refcount' is incremented: since the parent structure
 * can be dispatched to various searches, each record can be inserted in so
 * many different hash tables (one per search).
 */
typedef struct record {
	record_magic_t magic;		/**< Magic ID */
	int refcount;				/**< Number of hash tables it has been put to */

	results_set_t *results_set;	/**< Parent, containing record */
	const char *name;			/**< Filename (atom) */
	const char *ext;			/**< File extension (atom) */
	const char *utf8_name;		/**< Path/Filename converted to UTF-8 (atom) */
	const char *charset;		/**< Detected charset of name (static const) */
	const struct sha1 *sha1;	/**< SHA1 URN (binary form, atom) */
	const struct tth *tth;		/**< TTH URN (binary form, atom) */
	const char *xml;			/**< Optional XML data string (atom) */
	const char *tag;			/**< Optional tag data string (atom) */
	const char *info;			/**< Short version of tag (atom) */
	const char *path;			/**< Optional path (atom) */
	struct precord *partial;	/**< Optional: partial record information */
	struct gnet_host_vec *alt_locs;	/**< Optional alternate locations */
	filesize_t size;			/**< Size of file, in bytes */
	time_t  create_time;		/**< Create Time of file; zero if unknown */
	guint32 file_index;			/**< Index for GET command */
    guint32 flags;              /**< same flags as in gnet_record_t */
} record_t;

static inline void
record_check(const struct record * const rc)
{
	g_assert(rc);
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0);
	g_assert(rc->refcount < INT_MAX);
}

static inline void
results_set_check(const results_set_t * const rs)
{
	g_assert(rs);
	g_assert(rs->magic == RESULTS_SET_MAGIC);
	g_assert(rs->num_recs >= 0);
	g_assert(rs->num_recs < INT_MAX);
}

#endif /* _gtk_search_result_h_ */

/* vi: set ts=4 sw=4 cindent: */
