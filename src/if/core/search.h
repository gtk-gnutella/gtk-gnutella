/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_search_h_
#define _if_core_search_h_

#include "common.h"

#include "lib/misc.h"
#include "lib/vendors.h"
#include "if/core/nodes.h"

/***
 *** Searches
 ***/
typedef guint32 gnet_search_t;

/*
 * Flags for search_new()
 */
enum {
	SEARCH_F_PASSIVE 	= 1 << 0,	/**< Start a passive ssearch */
	SEARCH_F_ENABLED 	= 1 << 1,	/**< Start an enabled search */
	SEARCH_F_BROWSE		= 1 << 2,	/**< Start a browse-host search */
	SEARCH_F_LITERAL	= 1 << 3,	/**< Don't parse the query string */
	SEARCH_F_LOCAL		= 1 << 4	/**< Search in local files */
};

/*
 * Host vectors held in query hits.
 */
typedef struct gnet_host_vec {
	gnet_host_t *hvec;		/**< Vector of alternate locations */
	gint hvcnt;				/**< Amount of hosts in vector */
} gnet_host_vec_t;

/*
 * Result sets `status' flags.
 */
enum {
	 ST_FW2FW				= (1 << 15), /**< Firewall-to-Firewall support */
	 ST_HOSTILE				= (1 << 14), /**< From an hostile host */
	 ST_UNREQUESTED			= (1 << 13), /**< Unrequested (OOB) result */
	 ST_EVIL				= (1 << 12), /**< Carries evil filename */
	 ST_SPAM				= (1 << 11), /**< Carries spam */
	 ST_TLS					= (1 << 10), /**< Indicated support for TLS */
	 ST_BH					= (1 << 9),	 /**< Browse Host support */
	 ST_KNOWN_VENDOR		= (1 << 8),	 /**< Found known vendor code */
	 ST_PARSED_TRAILER		= (1 << 7),	 /**< Was able to parse trailer */
	 ST_UDP					= (1 << 6),	 /**< Got hit via UDP */
	 ST_BOGUS				= (1 << 5),	 /**< Bogus IP address */
	 ST_PUSH_PROXY			= (1 << 4),	 /**< Listed some push proxies */
	 ST_GGEP				= (1 << 3),	 /**< Trailer has a GGEP extension */
	 ST_UPLOADED			= (1 << 2),	 /**< Is "stable", people downloaded */
	 ST_BUSY				= (1 << 1),	 /**< Has currently no slots */
	 ST_FIREWALL			= (1 << 0)	 /**< Is behind a firewall */
};

/*
 * Processing of ignored files.
 */
enum {
	SEARCH_IGN_DISPLAY_AS_IS,	/**< Display normally */
	SEARCH_IGN_DISPLAY_MARKED,	/**< Display marked (lighter color) */
	SEARCH_IGN_NO_DISPLAY,		/**< Don't display */
};

/**
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.
 */
typedef struct gnet_results_set {
	host_addr_t addr;
	host_addr_t last_hop;		/**< IP of delivering node */

	gchar *guid;				/**< Servent's GUID (atom) */
	gchar *hostname;			/**< Optional: server's hostname */
	gchar *version;				/**< Version information (atom) */
	gchar *query;				/**< Optional: Original query string (atom) */
	gnet_host_vec_t *proxies;	/**< Optional: known push proxies */
	GSList *records;
	time_t  stamp;				/**< Reception time of the hit */

	gint country;				/**< Country code -- encoded ISO3166 */
	union vendor_code vcode;	/**< Vendor code */
	guint32 speed;
	guint32 num_recs;
	
	guint32 status;				/**< Parsed status bits from trailer */
    flag_t  flags;
	guint16 port;
	guint8 hops;
	guint8 ttl;
} gnet_results_set_t;

/*
 * Result record flags
 */
enum {
	SR_DOWNLOADED	= (1 << 0),
	SR_IGNORED		= (1 << 1),
	SR_DONT_SHOW	= (1 << 2),
	SR_SPAM			= (1 << 3),
	SR_SHARED		= (1 << 4),
	SR_OWNED		= (1 << 5),
	SR_PARTIAL		= (1 << 6)
};

/**
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 */
typedef struct gnet_record {
	gchar  *name;				/**< File name */
	gchar  *sha1;				/**< SHA1 URN (binary form, atom) */
	gchar  *tag;				/**< Optional tag data string (atom) */
	gchar  *xml;				/**< Optional XML data string (atom) */
	gchar  *path;				/**< Optional path (atom) */
	gnet_host_vec_t *alt_locs;	/**< Optional: known alternate locations */
	filesize_t size;			/**< Size of file, in bytes */
	guint32 file_index;			/**< Index for GET command */
    flag_t  flags;
} gnet_record_t;


/**
 * Search callbacks
 */
typedef void (*search_got_results_listener_t)
    (GSList *, const gnet_results_set_t *);

/*
 * Search public interface, visible only from the bridge.
 */

#ifdef CORE_SOURCES

gnet_search_t search_new(const gchar *, time_t create_time, guint lifetime,
		guint32 timeout, flag_t flags);
void search_close(gnet_search_t sh);

void search_start(gnet_search_t sh);
void search_stop(gnet_search_t sh);

/*  search_is_stopped doesn't exist yet!
gboolean search_is_stopped(gnet_search_t sh);
*/

void search_reissue(gnet_search_t sh);
void search_add_kept(gnet_search_t sh, guint32 kept);

gboolean search_is_passive(gnet_search_t sh);
gboolean search_is_active(gnet_search_t sh);
gboolean search_is_frozen(gnet_search_t sh);
gboolean search_is_expired(gnet_search_t sh);

void search_set_reissue_timeout(gnet_search_t sh, guint32 timeout);
guint32 search_get_reissue_timeout(gnet_search_t sh);
guint search_get_lifetime(gnet_search_t sh);
time_t search_get_create_time(gnet_search_t sh);
void search_set_create_time(gnet_search_t sh, time_t t);

void search_free_alt_locs(gnet_record_t *rc);

void search_update_items(gnet_search_t sh, guint32 items);

gboolean search_browse(gnet_search_t sh,
	const gchar *hostname, host_addr_t addr, guint16 port,
	const gchar *guid, const gnet_host_vec_t *proxies, guint32 flags);
gboolean search_locally(gnet_search_t sh, const gchar *query);

#endif /* CORE_SOURCES */
#endif /* _if_core_search_h_ */

/* vi: set ts=4 sw=4 cindent: */
