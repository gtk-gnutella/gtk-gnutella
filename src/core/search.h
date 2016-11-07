/*
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

/**
 * @ingroup core
 * @file
 *
 * Search handling (core side).
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_search_h_
#define _core_search_h_

#include "common.h"

#include "nodes.h"
#include "gnutella.h"
#include "lib/sectoken.h"

#include "if/core/search.h"		/* For query_type_t */

/*
 * Query flags used in queries (big-endian); formerly used as "speed" indicator.
 */

#define QUERY_F_MARK		0x8000	/**< Field is special: not a speed */
#define QUERY_F_FIREWALLED	0x4000	/**< Issuing servent is firewalled */
#define QUERY_F_XML			0x2000	/**< Supports XML in result set */
#define QUERY_F_LEAF_GUIDED	0x1000	/**< Leaf-guided query */
#define QUERY_F_GGEP_H		0x0800	/**< Recipient understands GGEP "H" */
#define QUERY_F_OOB_REPLY	0x0400	/**< Out-of-band reply possible */
#define QUERY_F_FW_TO_FW	0x0200	/**< Can do fw to fw transfers */
/**
 * NOTE: At this point all of the bits are exhausted. 0x0100 is not available
 * 		 because the next 9 bits are not available for flags but were reserved
 *       to specify the maximum amout of hits wanted (0 = unlimited).
 *
 * On 2012-10-07, we are stealing one bit from the reserved set to indicate
 * support for semi-reliable UDP, with the "GTA" tag.  If interpreted by a
 * legacy servent, this will seem to request 256 hits, at least, which should
 * not create a problem in practice.
 */
#define QUERY_F_SR_UDP		0x0100	/**< Accepts semi-reliable UDP, "GTA" tag */
#define QUERY_F_MAX_HITS	0x00ff	/**< Lowest 8 bits indicate max # of hits */

/**
 * This special file index (2^32 - 3) signals that the sender wishes to
 * establish a firewalled-to-firewalled transfer using RUDP.
 */
#define QUERY_FW2FW_FILE_INDEX	0x7FFFFFFD	/**< Magic index for fw-fw reqs */

/*
 * The version of GUESS we support.
 *
 * LimeWire defined 0.1 but we support 0.2 because OOB queries are both sent
 * (when running as a client) and accepted (as a server).  Also we implement
 * anti cache-poisoning features to limit malicious nodes in the cache.
 * Finally, gtk-gnutella understands the combination of PK & SCP in pings as
 * a requesst for query keys plus a set of GUESS ultrapeers to be sent back
 * packed in "IPP".
 */

#define SEARCH_GUESS_MAJOR 0
#define SEARCH_GUESS_MINOR 2

/**
 * Amount of (kept) search results we're aiming for when querying.
 */
#define SEARCH_MAX_RESULTS	150

struct search_request_info;
typedef struct search_request_info search_request_info_t;

struct download;
struct guid;
struct nid;

#ifdef SEARCH_SOURCES

#include "extensions.h"		/* For MAX_EXTVEC */

enum search_request_info_magic { SEARCH_REQUEST_INFO_MAGIC = 0x030c7005 };

/**
 * Gathered query information.
 */
struct search_request_info {
	enum search_request_info_magic magic;
	struct {
		struct sha1 sha1;
		bool matched;
	} exv_sha1[MAX_EXTVEC];
	host_addr_t addr;				/**< Reply address for OOB */
	const char *extended_query;		/**< String in GGEP "XQ" */
	int exv_sha1cnt;				/**< Amount of SHA1 to search for */
	size_t search_len;				/**< Length of query string */
	uint32 media_types;				/**< Media types from GGEP "M" */
	uint16 flags;					/**< Query flags */
	uint16 port;					/**< Reply port for OOB */
	filesize_t minsize, maxsize;	/**< Min & max file sizes limits */
	unsigned oob:1;					/**< Wants out-of-band hit delivery */
	unsigned secure_oob:1;			/**< OOB v3 used? */
	unsigned whats_new:1;			/**< This ia a "What's New?" query */
	unsigned skip_file_search:1;	/**< Should we skip library searching? */
	unsigned may_oob_proxy:1;		/**< Can we OOB-proxy the query? */
	unsigned partials:1;			/**< Do they want partial results? */
	unsigned duplicate:1;			/**< Known duplicate, with higher TTL */
	unsigned ipv6:1;				/**< Do they support IPv6? */
	unsigned ipv6_only:1;			/**< Do they support IPv6 only? */
	unsigned sr_udp:1;				/**< Do they support semi-reliable UDP? */
	unsigned size_restrictions:1;	/**< Whether to check min/max file size */
	unsigned g2_query:1;			/**< Whether we're processing a G2 query */
	unsigned g2_wants_url:1;		/**< Do they want URL in hits? */
	unsigned g2_wants_dn:1;			/**< Do they want DN in hits? */
	unsigned g2_wants_alt:1;		/**< Do they want ALT in hits? */
};

static inline void
search_request_info_check(const struct search_request_info * const sri)
{
	g_assert(sri != NULL);
	g_assert(SEARCH_REQUEST_INFO_MAGIC == sri->magic);
}

#endif	/* SEARCH_SOURCES */

/*
 * Global Functions
 */

void search_init(void);
void search_shutdown(void);

search_request_info_t *search_request_info_alloc(void);
void search_request_info_free_null(search_request_info_t **sri_ptr);

void
search_request_listener_emit(
	query_type_t type, const char *query, const host_addr_t addr, uint16 port);

struct g2_tree;

bool search_is_valid(gnutella_node_t *n, uint8 h, search_request_info_t *sri);
bool search_oob_is_allowed(
	gnutella_node_t *n, const search_request_info_t *sri);
bool search_results(gnutella_node_t *n, int *results);
void search_g2_results(gnutella_node_t *n, const struct g2_tree *t);
bool search_query_allowed(gnet_search_t sh);
void search_starting(gnet_search_t sh);
void search_notify_sent(gnet_search_t sh, const struct nid *node_id);
void search_query_sent(gnet_search_t sh);
bool search_get_kept_results_by_muid(const struct guid *m, uint32 *kept);
bool search_running_guess(const struct guid *muid);
uint32 search_get_kept_results_by_handle(gnet_search_t sh);
void search_oob_pending_results(gnutella_node_t *n, const struct guid *muid,
	int hits, bool udp_firewalled, bool secure);

void search_dissociate_browse(gnet_search_t sh, struct download *d);
void search_browse_results(gnutella_node_t *n, gnet_search_t sh,
	const struct g2_tree *t);

bool search_request_preprocess(struct gnutella_node *n,
	search_request_info_t *sri, bool isdup);
void search_request(struct gnutella_node *n,
	const search_request_info_t *sri, struct query_hashvec *qhv);
bool search_apply_limits(const struct shared_file *sf,
	const search_request_info_t *sri);

size_t compact_query(char *search);
void search_compact(struct gnutella_node *n);
void query_strip_oob_flag(struct gnutella_node *n, char *data);
void query_set_oob_flag(const struct gnutella_node *n, char *data);
bool query_utf8_decode(const char *text, uint *retoff);

void record_query_string(const struct guid *muid,
	const char *query, unsigned media_mask);

void search_query_key_generate(sectoken_t *tok, host_addr_t addr, uint16 port);

gnutella_msg_search_t *build_guess_search_msg(const struct guid *muid,
	const char *query, unsigned mtype,
	uint32 *size, const void *query_key, uint8 length);

const char *lazy_safe_search(const char *search);

#endif /* _core_search_h_ */

/* vi: set ts=4 sw=4 cindent: */
