/*
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

#ifndef _gnet_search_h_
#define _gnet_search_h_

#include "common.h"

/***
 *** Searches
 ***/
typedef guint32 gnet_search_t;

/* 
 * Flags for search_new()
 */
#define SEARCH_PASSIVE	 0x01 /* start a passive ssearch */
#define SEARCH_ENABLED	 0x02 /* start an enabled search */

/*
 * Host vectors held in query hits.
 */
typedef struct gnet_host_vec {
	gnet_host_t *hvec;		/* Vector of alternate locations */
	gint hvcnt;				/* Amount of hosts in vector */
} gnet_host_vec_t;

/*
 * Result sets `status' flags.
 */
#define ST_KNOWN_VENDOR			0x8000		/* Found known vendor code */
#define ST_PARSED_TRAILER		0x4000		/* Was able to parse trailer */
#define ST_PUSH_PROXY			0x0010		/* Listed some push proxies */
#define ST_GGEP					0x0008		/* Trailer has a GGEP extension */
#define ST_UPLOADED				0x0004		/* Is "stable", people downloaded */
#define ST_BUSY					0x0002		/* Has currently no slots */
#define ST_FIREWALL				0x0001		/* Is behind a firewall */

/*
 * Processing of ignored files.
 */
#define SEARCH_IGN_DISPLAY_AS_IS	0		/* Display normally */
#define SEARCH_IGN_DISPLAY_MARKED	1		/* Display marked (lighter color) */
#define SEARCH_IGN_NO_DISPLAY		2		/* Don't display */

/*
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.
 */
typedef struct gnet_results_set {
	gchar *guid;				/* Servent's GUID (atom) */
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint32 speed;
	time_t  stamp;				/* Reception time of the hit */
	guchar  vendor[4];			/* Vendor code */
	gchar *version;				/* Version information (atom) */
    flag_t  flags;
	gnet_host_vec_t *proxies;	/* Optional: known push proxies */
	gchar *hostname;			/* Optional: server's hostname */

	GSList *records;
	guint32 num_recs;
} gnet_results_set_t;

/*
 * Result record flags
 */
#define SR_DOWNLOADED	0x0001
#define SR_IGNORED		0x0002
#define SR_DONT_SHOW	0x0004

/*
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 */
typedef struct gnet_record {
	gchar  *name;				/* File name */
	guint32 size;				/* Size of file, in bytes */
	guint32 index;				/* Index for GET command */
	gchar  *sha1;				/* SHA1 URN (binary form, atom) */
	gchar  *tag;				/* Optional tag data string (atom) */
	gnet_host_vec_t *alt_locs;	/* Optional: known alternate locations */
    flag_t  flags;
} gnet_record_t;

/*
 * Search callbacks
 */
typedef void (*search_got_results_listener_t) 
    (GSList *, const gnet_results_set_t *);

void search_add_got_results_listener(search_got_results_listener_t l);
void search_remove_got_results_listener(search_got_results_listener_t l);

/*
 * Search public interface
 */
gnet_search_t search_new
    (const gchar *, guint16 min_speed, guint32 timeout, flag_t flags);
void search_close(gnet_search_t sh);

void search_start(gnet_search_t sh);
void search_stop(gnet_search_t sh);
gboolean search_is_stopped(gnet_search_t sh);
void search_reissue(gnet_search_t sh);

gboolean search_is_passive(gnet_search_t sh);
gboolean search_is_frozen(gnet_search_t sh);

void search_set_reissue_timeout(gnet_search_t sh, guint32 timeout);
guint32 search_get_reissue_timeout(gnet_search_t sh);

void search_free_alt_locs(gnet_record_t *rc);
void search_free_proxies(gnet_results_set_t *rs);

#endif /* _gnet_search_h_ */
