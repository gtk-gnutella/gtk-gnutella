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

#include "gnutella.h"

#include "extensions.h"
#include "gmsg.h"
#include "huge.h"
#include "nodes.h"
#include "routing.h"
#include "downloads.h"
#include "gnet_stats.h"
#include "ignore.h"
#include "ggep_type.h"
#include "version.h"
#include "qrp.h"
#include "search.h"
#include "hostiles.h"
#include "dmesh.h"
#include "fileinfo.h"
#include "guid.h"

#include <ctype.h>

RCSID("$Id$");

#ifdef USE_GTK2
#define g_hash_table_freeze(x) /* The function is deprecated. It does nothing */
#define g_hash_table_thaw(x) /* The function is deprecated. It does nothing */
#endif

#define MUID_SIZE	16
#define MUID_MAX	4			/* Max amount of MUID we keep per search */

struct sent_node_data {
	guint32 ip;
	guint16 port;
};

/* 
 * Structure for search results 
 */
typedef struct search_ctrl {
    gnet_search_t search_handle; /* Search handle */

	/* no more "speed" field -- use marked field now --RAM, 06/07/2003 */

	gchar  *query;				/* The search query */
	time_t  time;				/* Time when this search was started */
	GSList *muids;				/* Message UIDs of this search */
	GHashTable *h_muids;		/* All known message UIDs of this search */

	gboolean passive;			/* Is this a passive search? */
	gboolean frozen;			/* True => don't update window */
	/* keep a record of nodes we've sent this search w/ this muid to. */
	GHashTable *sent_nodes;

	GHook *new_node_hook;
	guint reissue_timeout_id;
	guint reissue_timeout;		/* timeout per search, 0 = search stopped */
	guint query_emitted;		/* Amount of queries emitted since last retry */
} search_ctrl_t;

/*
 * List of searches.
 */
static GSList *sl_search_ctrl = NULL;

static zone_t *rs_zone = NULL;		/* Allocation of results_set */
static zone_t *rc_zone = NULL;		/* Allocation of record */

static idtable_t *search_handle_map = NULL;
static query_hashvec_t *query_hashvec = NULL;

#define search_find_by_handle(n) \
    (search_ctrl_t *) idtable_get_value(search_handle_map, n)

#define search_request_handle(n) \
    idtable_new_id(search_handle_map, n)

#define search_drop_handle(n) \
    idtable_free_id(search_handle_map, n);

guint32   search_passive  = 0;		/* Amount of passive searches */

static void search_check_results_set(gnet_results_set_t *rs);

/***
 *** Callbacks (private and public)
 ***/
static listeners_t search_got_results_listeners = NULL;

void search_add_got_results_listener(search_got_results_listener_t l)
{
    g_assert(l != NULL);

    search_got_results_listeners = 
        g_slist_append(search_got_results_listeners, (gpointer) l);
}

void search_remove_got_results_listener(search_got_results_listener_t l)
{
    g_assert(l != NULL);

    search_got_results_listeners = 
        g_slist_remove(search_got_results_listeners, (gpointer) l);
}

static void search_fire_got_results(
	GSList *sch_matched, const gnet_results_set_t *rs)
{
    GSList *sl;
    g_assert(rs != NULL);

    for (sl = search_got_results_listeners; sl != NULL; sl = g_slist_next(sl))
        (*(search_got_results_listener_t) sl->data)(sch_matched, rs);
}

/***
 *** Private functions
 ***/

static guint sent_node_hash_func(gconstpointer key)
{
	const struct sent_node_data *sd = (const struct sent_node_data *) key;

	/* ensure that we've got sizeof(gint) bytes of deterministic data */
	guint32 ip = sd->ip;
	guint32 port = sd->port;

	return ip ^ port;
}

static gint sent_node_compare(gconstpointer a, gconstpointer b)
{
	const struct sent_node_data *sa = (const struct sent_node_data *) a;
	const struct sent_node_data *sb = (const struct sent_node_data *) b;

	return sa->ip == sb->ip && sa->port == sb->port;
}

static gboolean search_free_sent_node(
	gpointer node, gpointer value, gpointer udata)
{
	wfree(node, sizeof(struct sent_node_data));
	return TRUE;
}

static void search_free_sent_nodes(search_ctrl_t *sch)
{
	g_hash_table_foreach_remove(sch->sent_nodes, search_free_sent_node, NULL);
	g_hash_table_destroy(sch->sent_nodes);
}

static void mark_search_sent_to_node(
	search_ctrl_t *sch, gnutella_node_t *n)
{
	struct sent_node_data *sd = walloc(sizeof(*sd));
	sd->ip = n->ip;
	sd->port = n->port;
	g_hash_table_insert(sch->sent_nodes, sd, GUINT_TO_POINTER(1));
}

static void mark_search_sent_to_connected_nodes(search_ctrl_t *sch)
{
	const GSList *sl;
	struct gnutella_node *n;

	g_hash_table_freeze(sch->sent_nodes);
	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		n = (struct gnutella_node *) sl->data;
		if (NODE_IS_WRITABLE(n))
			mark_search_sent_to_node(sch, n);
	}
	g_hash_table_thaw(sch->sent_nodes);
}

/*
 * search_already_sent_to_node
 *
 * Return TRUE if we already queried the given node for the given search.
 */
static gboolean search_already_sent_to_node(
	search_ctrl_t *sch, gnutella_node_t *n)
{
	struct sent_node_data sd;
	sd.ip = n->ip;
	sd.port = n->port;
	return NULL != g_hash_table_lookup(sch->sent_nodes, &sd);
}

/*
 * search_has_muid:
 *
 * Return TRUE if the muid list of the given search contains the
 * given muid.
 */
static gboolean search_has_muid(search_ctrl_t *sch, const gchar *muid)
{
	g_assert(sch->h_muids);

	return NULL != g_hash_table_lookup(sch->h_muids, muid);
}

/*
 * search_free_alt_locs
 *
 * Free the alternate locations held within a file record.
 */
void search_free_alt_locs(gnet_record_t *rc)
{
	gnet_host_vec_t *alt = rc->alt_locs;

	g_assert(alt != NULL);

	wfree(alt->hvec, alt->hvcnt * sizeof(*alt->hvec));
	wfree(alt, sizeof(*alt));

	rc->alt_locs = NULL;
}

/*
 * search_free_proxies
 *
 * Free the push proxies held within a result set.
 */
void search_free_proxies(gnet_results_set_t *rs)
{
	gnet_host_vec_t *v = rs->proxies;

	g_assert(v != NULL);

	wfree(v->hvec, v->hvcnt * sizeof(*v->hvec));
	wfree(v, sizeof(*v));

	rs->proxies = NULL;
}

/*
 * search_free_record
 *
 * Free one file record.
 */
static void search_free_record(gnet_record_t *rc)
{
	atom_str_free(rc->name);
	if (rc->tag != NULL)
		atom_str_free(rc->tag);
	if (rc->sha1 != NULL)
		atom_sha1_free(rc->sha1);
	if (rc->alt_locs != NULL)
		search_free_alt_locs(rc);
	zfree(rc_zone, rc);
}

/*
 * search_free_r_set
 *
 * Free one results_set.
 */
static void search_free_r_set(gnet_results_set_t *rs)
{
	GSList *m;

	for (m = rs->records; m; m = m->next)
		search_free_record((gnet_record_t *) m->data);

	if (rs->guid)
		atom_guid_free(rs->guid);

	if (rs->version)
		atom_str_free(rs->version);

	if (rs->proxies)
		search_free_proxies(rs);

	g_slist_free(rs->records);
	zfree(rs_zone, rs);
}

/*
 * get_results_set
 *
 * Parse Query Hit and extract the embedded records, plus the optional
 * trailing Query Hit Descritor (QHD).
 *
 * If `validate_only' is set, we only validate the results and don't wish
 * to permanently use the results, so don't allocate any memory for each
 * record.
 *
 * Returns a structure describing the whole result set, or NULL if we
 * were unable to parse it properly.
 */
static gnet_results_set_t *get_results_set(
	gnutella_node_t *n, gboolean validate_only)
{
	gnet_results_set_t *rs;
	gnet_record_t *rc = NULL;
	gchar *e, *s, *fname, *tag;
	guint32 nr = 0;
	guint32 size, idx, taglen;
	struct gnutella_search_results *r;
	GString *info = NULL;
	gint sha1_errors = 0;
	gint alt_errors = 0;
	gint alt_without_hash = 0;
	gchar *trailer = NULL;
	gboolean seen_ggep_h = FALSE;
	gboolean seen_ggep_alt = FALSE;
	gboolean seen_bitprint = FALSE;
	gboolean multiple_sha1 = FALSE;
	gint multiple_alt = 0;
	gchar *vendor = NULL;

	/* We shall try to detect malformed packets as best as we can */
	if (n->size < 27) {
		/* packet too small 11 header, 16 GUID min */
		g_warning("get_results_set(): given too small a packet (%d bytes)",
				  n->size);
        gnet_stats_count_dropped(n, MSG_DROP_TOO_SMALL);
		return NULL;
	}

	if (!validate_only)
		info = g_string_sized_new(80);

	rs = (gnet_results_set_t *) zalloc(rs_zone);

	rs->vendor[0] = '\0';
	rs->records   = NULL;
	rs->guid      = NULL;
	rs->version   = NULL;
    rs->status    = 0;
	rs->proxies   = NULL;

	r = (struct gnutella_search_results *) n->data;

	/* Transfer the Query Hit info to our internal results_set struct */

	rs->num_recs = (guint8) r->num_recs;		/* Number of hits */
	READ_GUINT32_BE(r->host_ip, rs->ip);		/* IP address */
	READ_GUINT16_LE(r->host_port, rs->port);	/* Port */
	READ_GUINT32_LE(r->host_speed, rs->speed);	/* Connection speed */

	/* Check for hostile IP addresses */

	if (hostiles_check(rs->ip)) {
		g_warning("dropping query hit from hostile IP %s", ip_to_gchar(rs->ip));
		gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
		goto bad_packet;
	}

	/* Now come the result set, and the servent ID will close the packet */

	s = (gchar *) r->records;	/* Start of the records */
	e = s + n->size - 11 - 16;	/* End of the records, less header, GUID */

	if (dbg > 7)
		dump_hex(stdout, "Query Hit Data", n->data, n->size);

	while (s < e && nr < rs->num_recs) {
		READ_GUINT32_LE(s, idx);
		s += 4;					/* File Index */
		READ_GUINT32_LE(s, size);
		s += 4;					/* File Size */

		/* Followed by file name, and termination (double NUL) */
		fname = s;

		while (s < e && *s)
			s++;				/* move s up to the next double NUL */

		if (s >= (e-1))	{		/* There cannot be two NULs: end of packet! */
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
			goto bad_packet;
        }

		/*
		 * `s' point to the first NUL of the double NUL sequence.
		 *
		 * Between the two NULs at the end of each record, servents may put
		 * some extra information about the file (a tag), but this information
		 * may not contain any NUL.
		 */

		tag = NULL;
		taglen = 0;

		if (s[1]) {
			/* Not a NUL, so we're *probably* within the tag info */

			s++;				/* Skip first NUL */
			tag = s;

			/*
			 * Inspect the tag, looking for next NUL.
			 */

			while (s < e) {		/* On the way to second NUL */
				if ('\0' == *s)
					break;		/* Reached second nul */
				s++;
				taglen++;
			}

			if (s >= e) {
                gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
				goto bad_packet;
            }

			s++;				/* Now points to next record */
		} else
			s += 2;				/* Skip double NUL */

		/*
		 * Okay, one more record
		 */

		nr++;

		if (!validate_only) {
			rc = (gnet_record_t *) zalloc(rc_zone);

			rc->sha1  = rc->tag = NULL;
			rc->index = idx;
			rc->size  = size;
			rc->name  = atom_str_get(fname);
            rc->flags = 0;
            rc->alt_locs = NULL;
		}

		/*
		 * If we have a tag, parse it for extensions.
		 */

		if (tag) {
			extvec_t exv[MAX_EXTVEC];
			gint exvcnt;
			gint i;
			gnet_host_t *hvec = NULL;		/* For GGEP "ALT" */
			gint hvcnt = 0;
			gboolean has_hash = FALSE;

			g_assert(taglen > 0);

			exvcnt = ext_parse(tag, taglen, exv, MAX_EXTVEC);

			if (exvcnt == MAX_EXTVEC) {
				g_warning("%s hit record has %d extensions!",
					gmsg_infostr(&n->header), exvcnt);
				if (dbg)
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
				if (dbg > 1)
					dump_hex(stderr, "Query Hit Tag", tag, taglen);
			}

			/*
			 * Look for a valid SHA1 or a tag string we can display.
			 */

			if (!validate_only)
				g_string_truncate(info, 0);

			for (i = 0; i < exvcnt; i++) {
				extvec_t *e = &exv[i];
				gchar sha1_digest[SHA1_RAW_SIZE];
				ggept_status_t ret;
				gboolean unknown = TRUE;
				gint urnlen;

				switch (e->ext_token) {
				case EXT_T_URN_BITPRINT:	/* first 32 chars is the SHA1 */
					seen_bitprint = TRUE;
					/* FALLTHROUGH */
				case EXT_T_URN_SHA1:		/* SHA1 URN, the HUGE way */
					has_hash = TRUE;
					urnlen = e->ext_paylen;
					if (e->ext_token == EXT_T_URN_BITPRINT)
						urnlen = MIN(urnlen, SHA1_BASE32_SIZE);
					if (
						huge_sha1_extract32(e->ext_payload,
								urnlen, sha1_digest, &n->header, TRUE)
					) {
						if (!validate_only) {
							if (rc->sha1 != NULL) {
								multiple_sha1 = TRUE;
								atom_sha1_free(rc->sha1);
							}
							rc->sha1 = atom_sha1_get(sha1_digest);
						}
					} else
						sha1_errors++;
					break;
				case EXT_T_GGEP_u:			/* HUGE URN, wihtout leading urn: */
					if (
						e->ext_paylen >= 9 &&
						(0 == strncasecmp(e->ext_payload, "sha1:", 5) ||
						 0 == strncasecmp(e->ext_payload, "bitprint:", 9))
					) {
						gchar *payload;

						has_hash = TRUE;

						/* Must NUL-terminate the payload first */
						payload = walloc(e->ext_paylen + 1);
						memcpy(payload, e->ext_payload, e->ext_paylen);
						payload[e->ext_paylen] = '\0';

						if (huge_extract_sha1_no_urn(payload, sha1_digest)) {
							if (!validate_only) {
								if (rc->sha1 != NULL) {
									multiple_sha1 = TRUE;
									atom_sha1_free(rc->sha1);
								}
								rc->sha1 = atom_sha1_get(sha1_digest);
							}
						} else
							sha1_errors++;
						wfree(payload, e->ext_paylen + 1);
					}
					break;
				case EXT_T_GGEP_H:			/* Expect SHA1 value only */
					ret = ggept_h_sha1_extract(e, sha1_digest, SHA1_RAW_SIZE);
					if (ret == GGEP_OK) {
						has_hash = TRUE;
						if (!validate_only) {
							if (rc->sha1 != NULL) {
								multiple_sha1 = TRUE;
								atom_sha1_free(rc->sha1);
							}
							rc->sha1 = atom_sha1_get(sha1_digest);
						}
						seen_ggep_h = TRUE;
					} else if (ret == GGEP_INVALID) {
						sha1_errors++;
						if (dbg) {
							g_warning("%s bad GGEP \"H\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					} else {
						if (dbg) {
							g_warning("%s GGEP \"H\" with no SHA1 (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_ALT:		/* Alternate locations */
					if (hvec != NULL) {		/* Already saw one for record! */
						multiple_alt++;
						break;
					}
					ret = ggept_alt_extract(e, &hvec, &hvcnt);
					if (ret == GGEP_OK)
						seen_ggep_alt = TRUE;
					else {
						alt_errors++;
						if (dbg) {
							g_warning("%s bad GGEP \"ALT\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_T:			/* Descriptive text */
					unknown = FALSE;		/* Disables ext_has_ascii_word() */
					/* FALLTHROUGH */
				case EXT_T_UNKNOWN:
					if (
						!validate_only &&
						e->ext_paylen &&
						(!unknown || ext_has_ascii_word(e))
					) {
						gchar *p = (gchar *) e->ext_payload + e->ext_paylen;
						gchar c = *p;

						if (info->len)
							g_string_append(info, "; ");

						*p = '\0';
						g_string_append(info, e->ext_payload);
						*p = c;
					}
					break;
				default:
					break;
				}
			}

			if (!validate_only && info->len)
				rc->tag = atom_str_get(info->str);

			if (hvec != NULL) {
				g_assert(hvcnt > 0);

				if (!has_hash)
					alt_without_hash++;

				/*
				 * GGEP "ALT" is only meaningful when there is a SHA1!
				 */

				if (!validate_only && rc->sha1 != NULL) {
					gnet_host_vec_t *alt = walloc(sizeof(*alt));

					alt->hvec = hvec;
					alt->hvcnt = hvcnt;
					rc->alt_locs = alt;
				} else
					wfree(hvec, hvcnt * sizeof(*hvec));
			}
		}

		if (!validate_only)
			rs->records = g_slist_prepend(rs->records, (gpointer) rc);
	}

	/*
	 * If we have not reached the end of the packet, then we have a trailer.
	 * It can be of any length, but bound by the maximum query hit packet
	 * size we configured for this node.
	 *
	 * The payload of the trailer is vendor-specific, but its "header" is
	 * somehow codified:
	 *
	 *	bytes 0..3: vendor code (4 letters)
	 *	byte 4	: open data size
	 *
	 * Followed by open data (flags usually), and opaque data.
	 */

	if (s < e) {
		guint32 tlen = e - s;			/* Trailer length, starts at `s' */
		guchar *x = (guchar *) s;

		if (tlen >= 5 && x[4] + 5 <= tlen)
			trailer = s;

		if (trailer)
			memcpy(rs->vendor, trailer, sizeof(rs->vendor));
		else {
			g_warning(
				"UNKNOWN %d-byte trailer in %s from %s (%u/%u records parsed)",
				tlen, gmsg_infostr(&n->header), node_ip(n), nr, rs->num_recs);
			if (dbg > 1)
				dump_hex(stderr, "Query Hit Data (non-empty UNKNOWN trailer?)",
					n->data, n->size);
		}
	}

	if (nr != rs->num_recs) {
        gnet_stats_count_dropped(n, MSG_DROP_BAD_RESULT);
		goto bad_packet;
    }

	/* We now have the guid of the node */

	rs->guid = atom_guid_get(e);
	rs->stamp = time(NULL);

	/*
	 * Compute status bits, decompile trailer info, if present
	 */

	if (trailer) {
		guint32 t;
		guint open_size = trailer[4];
		guint open_parsing_size = trailer[4];
		guint32 enabler_mask = (guint32) trailer[5];
		guint32 flags_mask = (guint32) trailer[6];

        vendor = lookup_vendor_name(rs->vendor);

        if ((vendor != NULL) && is_vendor_known(rs->vendor))
            rs->status |= ST_KNOWN_VENDOR;

		READ_GUINT32_BE(trailer, t);

		if (open_size == 4)
			open_parsing_size = 2;		/* We ignore XML data size */

		switch (t) {
		case T_NAPS:
			/*
			 * NapShare has a one-byte only flag: no enabler, just setters.
			 *		--RAM, 17/12/2001
			 */
			if (open_size == 1) {
				if (enabler_mask & 0x04) rs->status |= ST_BUSY;
				if (enabler_mask & 0x01) rs->status |= ST_FIREWALL;
				rs->status |= ST_PARSED_TRAILER;
			}
			break;
		default:
			if (open_parsing_size == 2) {
				guint32 status = enabler_mask & flags_mask;
				if (status & 0x04) rs->status |= ST_BUSY;
				if (status & 0x01) rs->status |= ST_FIREWALL;
				if (status & 0x08) rs->status |= ST_UPLOADED;
				if (status & 0x08) rs->status |= ST_UPLOADED;
				if (status & 0x20) rs->status |= ST_GGEP;
				rs->status |= ST_PARSED_TRAILER;
			} else if (rs->status  & ST_KNOWN_VENDOR) {
				if (dbg)
					g_warning("vendor %s changed # of open data bytes to %d",
							  vendor, open_size);
			} else if (vendor) {
				if (dbg)
					g_warning("ignoring %d open data byte%s from "
						"unknown vendor %s",
						open_size, open_size == 1 ? "" : "s", vendor);
			}
			break;
		}

		/*
		 * Now that we have the vendor, warn if the message has SHA1 errors.
		 * Then drop the packet!
		 */

		if (sha1_errors) {
			if (dbg) g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d SHA1 error%s over %u record%s",
				 gmsg_infostr(&n->header), vendor ? vendor : "????",
				 node_vendor(n), node_ip(n),
				 sha1_errors, sha1_errors == 1 ? "" : "s",
				 nr, nr == 1 ? "" : "s");
            gnet_stats_count_dropped(n, MSG_DROP_RESULT_SHA1_ERROR);
			goto bad_packet;		/* Will drop this bad query hit */
		}

		/*
		 * If we have bad ALT locations, or ALT without hashes, warn but
		 * do not drop.
		 */

		if (alt_errors && dbg) {
			g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d ALT error%s over %u record%s",
				 gmsg_infostr(&n->header), vendor ? vendor : "????",
				 node_vendor(n), node_ip(n),
				 alt_errors, alt_errors == 1 ? "" : "s",
				 nr, nr == 1 ? "" : "s");
		}

		if (alt_without_hash && dbg) {
			g_warning(
				"%s from %s (via \"%s\" at %s) "
				"had %d ALT extension%s with no hash over %u record%s",
				 gmsg_infostr(&n->header), vendor ? vendor : "????",
				 node_vendor(n), node_ip(n),
				 alt_without_hash, alt_without_hash == 1 ? "" : "s",
				 nr, nr == 1 ? "" : "s");
		}

		/*
		 * Parse trailer after the open data, if we have a GGEP extension.
		 */

		if (rs->status & ST_GGEP) {
			gchar *priv = &trailer[5] + open_size;
			gint privlen = e - priv;
			gint exvcnt = 0;
			extvec_t exv[MAX_EXTVEC];
			gboolean seen_ggep = FALSE;
			gint i;
			struct ggep_gtkgv1 info;

			if (privlen > 0)
				exvcnt = ext_parse(priv, privlen, exv, MAX_EXTVEC);

			for (i = 0; i < exvcnt; i++) {
				extvec_t *e = &exv[i];
				ggept_status_t ret;

				if (e->ext_type == EXT_GGEP)
					seen_ggep = TRUE;

				if (validate_only)
					continue;

				switch (e->ext_token) {
				case EXT_T_GGEP_GTKGV1:
					ret = ggept_gtkgv1_extract(e, &info);
					if (ret == GGEP_OK) {
						version_t ver;

						ver.major = info.major;
						ver.minor = info.minor;
						ver.patchlevel = info.patch;
						ver.tag = info.revchar;
						ver.taglevel = 0;
						ver.timestamp = info.revchar ? info.release : 0;

						rs->version = atom_str_get(version_str(&ver));
					} else if (ret == GGEP_INVALID) {
						if (dbg) {
							g_warning("%s bad GGEP \"GTKGV1\" (dumping)",
								gmsg_infostr(&n->header));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
					}
					break;
				case EXT_T_GGEP_PUSH:
					if (rs->proxies != NULL) {
						g_warning("%s has multiple GGEP \"PUSH\" (ignoring)",
							gmsg_infostr(&n->header));
						break;
					}
					if (!validate_only) {
						gnet_host_t *hvec;
						gint hvcnt = 0;

						ret = ggept_push_extract(e, &hvec, &hvcnt);

						if (ret == GGEP_OK) {
							gnet_host_vec_t *v = walloc(sizeof(*v));
							v->hvec = hvec;
							v->hvcnt = hvcnt;
							rs->proxies = v;
						} else {
							if (dbg) {
								g_warning("%s bad GGEP \"PUSH\" (dumping)",
									gmsg_infostr(&n->header));
								ext_dump(stderr, e, 1, "....", "\n", TRUE);
							}
						}
					}
					break;
				default:
					break;
				}
			}

			if (exvcnt == MAX_EXTVEC) {
				g_warning("%s from %s has %d trailer extensions!",
					gmsg_infostr(&n->header), vendor ? vendor : "????", exvcnt);
				if (dbg)
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
				if (dbg > 1)
					dump_hex(stderr, "Query Hit private data", priv, privlen);
			} else if (!seen_ggep) {
				g_warning("%s from %s claimed GGEP extensions in trailer, "
					"seen none",
					gmsg_infostr(&n->header), vendor ? vendor : "????");
			}
		}

		if (dbg) {
			if (seen_ggep_h)
				g_warning("%s from %s used GGEP \"H\" extension",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			if (seen_ggep_alt)
				g_warning("%s from %s used GGEP \"ALT\" extension",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			if (seen_bitprint)
				g_warning("%s from %s used urn:bitprint",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			if (multiple_sha1)
				g_warning("%s from %s had records with multiple SHA1",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			if (multiple_alt)
				g_warning("%s from %s had records with multiple ALT",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
		}

		/*
		 * If we're not only validating (i.e. we're going to peruse this hit),
		 * and if the server is marking its hits with the Push flag, check
		 * whether it is already known to wrongly set that bit.
		 *		--RAM, 18/08/2002.
		 */

		if (
			!validate_only && (rs->status & ST_FIREWALL) &&
			download_server_nopush(rs->guid, rs->ip, rs->port)
		)
			rs->status &= ~ST_FIREWALL;		/* Clear "Push" indication */
	}

	if (!validate_only)
		g_string_free(info, TRUE);
	return rs;

	/*
	 * Come here when we encounter bad packets (NUL chars not where expected,
	 * or missing).	The whole packet is ignored.
	 *				--RAM, 09/01/2001
	 */

  bad_packet:
	if (dbg) {
		g_warning(
			"BAD %s from %s (via \"%s\" at %s) -- %u/%u records parsed",
			 gmsg_infostr(&n->header), vendor ? vendor : "????",
			 node_vendor(n), node_ip(n), nr, rs->num_recs);
		if (dbg > 1)
			dump_hex(stderr, "Query Hit Data (BAD)", n->data, n->size);
	}

	search_free_r_set(rs);

	if (!validate_only)
		g_string_free(info, TRUE);

	return NULL;				/* Forget set, comes from a bad node */
}

/*
 * update_neighbour_info
 *
 * Called when we get a query hit from an immediate neighbour.
 */
static void update_neighbour_info(gnutella_node_t *n, gnet_results_set_t *rs)
{
	gchar *vendor;
	extern gint guid_eq(gconstpointer a, gconstpointer b);
	gint old_weird = n->n_weird;

	g_assert(n->header.hops == 1);

    vendor = lookup_vendor_name(rs->vendor);

	if (n->attrs & NODE_A_QHD_NO_VTAG) {	/* Known to have no tag */
		if (vendor) {
			if (dbg) g_warning(
				"node %s (%s) had no tag in its query hits, now has %s in %s",
				node_ip(n), node_vendor(n), vendor, gmsg_infostr(&n->header));
			n->n_weird++;
			n->attrs &= ~NODE_A_QHD_NO_VTAG;
		}
	} else {
		/*
		 * Use vendor tag if needed to guess servent vendor name.
		 */

		if (n->vendor == NULL && vendor) 
            node_set_vendor(n, vendor);

		if (vendor == NULL)
			n->attrs |= NODE_A_QHD_NO_VTAG;	/* No vendor tag */

		if (n->vcode[0] != '\0' && vendor == NULL) {
			if (dbg) g_warning(
				"node %s (%s) had tag %c%c%c%c in its query hits, "
				"now has none in %s",
				node_ip(n), node_vendor(n),
				n->vcode[0], n->vcode[1], n->vcode[2], n->vcode[3],
				gmsg_infostr(&n->header));
			n->n_weird++;
		}
	}

	/*
	 * Save vendor code if present.
	 */

	if (vendor != NULL) {
		g_assert(sizeof(n->vcode) == sizeof(rs->vendor));

		if (
			n->vcode[0] != '\0' &&
			0 != memcmp(n->vcode, rs->vendor, sizeof(n->vcode))
		) {
			if (dbg) g_warning(
				"node %s (%s) moved from tag %c%c%c%c to %c%c%c%c "
				"in %s",
				node_ip(n), node_vendor(n),
				n->vcode[0], n->vcode[1], n->vcode[2], n->vcode[3],
				rs->vendor[0], rs->vendor[1], rs->vendor[2], rs->vendor[3],
				gmsg_infostr(&n->header));
			n->n_weird++;
		}

		memcpy(n->vcode, rs->vendor, sizeof(n->vcode));
	} else
		n->vcode[0] = '\0';

	/*
	 * Save node's GUID.
	 */

	if (n->gnet_guid) {
		if (!guid_eq(n->gnet_guid, rs->guid)) {
			if (dbg) {
				gchar old[33];
				strncpy(old, guid_hex_str(n->gnet_guid), sizeof(old));

				g_warning(
					"node %s (%s) moved from GUID %s to %s in %s",
					node_ip(n), node_vendor(n),
					old, guid_hex_str(rs->guid), gmsg_infostr(&n->header));
			}
			atom_guid_free(n->gnet_guid);
			n->gnet_guid = NULL;
			n->n_weird++;
		}
	}

	if (n->gnet_guid == NULL)
		n->gnet_guid = atom_guid_get(rs->guid);

	/*
	 * We don't declare any weirdness if the address in the results matches
	 * the socket's peer address.
	 *
	 * Otherwise, make sure the address is a private IP one, or that the hit
	 * has the "firewalled" bit.  Otherwise, the IP must match the one the
	 * servent thinks it has, which we know from its previous query hits
	 * with hops=0. If we never got a query hit from that servent, check
	 * against last IP we saw in pong.
	 */

	if (
		n->ip != rs->ip &&					/* Not socket's address */
		!(rs->status & ST_FIREWALL) &&		/* Hit not marked "firewalled" */
		!is_private_ip(rs->ip)				/* Address not private */
	) {
		if (
			(n->gnet_qhit_ip && n->gnet_qhit_ip != rs->ip) ||
			(n->gnet_pong_ip && n->gnet_pong_ip != rs->ip)
		) {
			if (dbg) g_warning(
				"node %s (%s) advertised %s but now says Query Hits from %s",
				node_ip(n), node_vendor(n),
				ip_to_gchar(n->gnet_pong_ip ?
					n->gnet_pong_ip : n->gnet_qhit_ip),
				ip_port_to_gchar(rs->ip, rs->port));
			n->n_weird++;
		}
		n->gnet_qhit_ip = rs->ip;
	}

	if (dbg > 1 && old_weird != n->n_weird)
		dump_hex(stderr, "Query Hit Data (weird)", n->data, n->size);
}

/* Create and send a search request packet */

static void _search_send_packet(search_ctrl_t *sch, gnutella_node_t *n)
{
	struct gnutella_msg_search *m;
	guint32 size;
	gint plen;				/* Length of payload */
	gint qlen;				/* Length of query text */
	gboolean is_urn_search = FALSE;
	guint16 speed;
	query_hashvec_t *qhv;

    g_assert(sch != NULL);
    g_assert(!sch->passive);
	g_assert(!sch->frozen);

	/*
	 * We'll do query routing only if in ultra mode and we're going to
	 * broadcast the query (i.e. n == NULL).
	 *
	 * Otherwise, we're sending the query after the initial node connection,
	 * and this is our privilege as an ultra node to be able to query our
	 * own leaves directly the first time they connect.
	 *		--RAM, 17/01/2003
	 */

	if (current_peermode == NODE_P_ULTRA && n == NULL) {
		qhv = query_hashvec;
		qhvec_reset(qhv);
	} else
		qhv = NULL;

	/*
	 * Are we dealing with an URN search?
	 */

	if (0 == strncmp(sch->query, "urn:sha1:", 9)) {
		is_urn_search = TRUE;
	}

	if (is_urn_search) {
		/*
		 * We're sending an empty search text (NUL only), then the 9+32 bytes
		 * of the URN query, plus a trailing NUL.
		 */
		qlen = 0;
		size = sizeof(struct gnutella_msg_search) + 9+32 + 2;	/* 2 NULs */

		/*
		 * If query routing is on, hash the URN.
		 */

		if (qhv != NULL)
			qhvec_add(qhv, sch->query, QUERY_H_URN);
	} else {
		/*
		 * We're adding a trailing NUL after the query text.
		 *
		 * Starting 24/09/2002, we no longer send the trailing "urn:\0" as
		 * most servents will now send any SHA1 they have, unsollicited,
		 * as we always did ourselves.
		 */

		qlen = strlen(sch->query);
		size = sizeof(struct gnutella_msg_search) + qlen + 1;	/* 1 NUL */

		/*
		 * If query routing is on, hash each query word.
		 */

		if (qhv != NULL) {
			word_vec_t *wovec;
			guint i;
			guint wocnt;

			wocnt = query_make_word_vec(sch->query, &wovec);

			for (i = 0; i < wocnt; i++) {
				if (wovec[i].len >= QRP_MIN_WORD_LENGTH)
					qhvec_add(qhv, wovec[i].word, QUERY_H_WORD);
			}

			if (wocnt != 0)
				query_word_vec_free(wovec, wocnt);
		}
	}

	plen = size - sizeof(struct gnutella_header);	/* Payload length */

	if (plen > search_queries_forward_size) {
		g_warning("not sending query \"%s\": larger than max query size (%d)",
			sch->query, search_queries_forward_size);
		return;
	}

	m = (struct gnutella_msg_search *) walloc(size);

	/* Use the first one on the list */
	memcpy(m->header.muid, sch->muids->data, 16);

	m->header.function = GTA_MSG_SEARCH;
	m->header.ttl = my_ttl;
	m->header.hops = (hops_random_factor && current_peermode != NODE_P_LEAF) ?
		random_value(hops_random_factor) : 0;
	if (m->header.ttl + m->header.hops > hard_ttl_limit)
		m->header.ttl = hard_ttl_limit - m->header.hops;

	WRITE_GUINT32_LE(plen, m->header.size);

	/*
	 * The search speed is no longer used by most servents as a raw indication
	 * of speed.  There is now a special marking for the speed field in the
	 * upper byte, the lower byte being kept for speed indication, but not
	 * defined yet -> use zeros (since this is a min speed).
	 *
	 * It is too soon though, as GTKG before 0.92 did honour that field.
	 * The next major version will use a tailored speed field.
	 *		--RAM, 19/01/2003
	 *
	 * Starting today (06/07/2003), we're using marked speed fields and
	 * ignore the speed they specify in the searches from the GUI. --RAM
	 */

	speed = QUERY_SPEED_MARK;			/* Indicates: special speed field */
	if (is_firewalled)
		speed |= QUERY_SPEED_FIREWALLED;
	speed |= QUERY_SPEED_GGEP_H;		/* GTKG understands GGEP "H" in hits */
	speed |= QUERY_SPEED_NO_XML;		/* GTKG does not parse XML in hits */

	WRITE_GUINT16_LE(speed, m->search.speed);

	if (is_urn_search) {
		*m->search.query = '\0';
		strncpy(m->search.query + 1, sch->query, 9+32);	/* urn:sha1:32bytes */
		m->search.query[1+9+32] = '\0';
	} else
		strcpy(m->search.query, sch->query);

	message_add(m->header.muid, GTA_MSG_SEARCH, NULL);

	/*
	 * All the gmsg_search_xxx() routines include the search handle.
	 * In the search queue, we put entries pointing back to the search.
	 * When the search is put in the MQ, we increment a counter in the
	 * search if the target is not a leaf node.
	 *
	 * When the counter in the search reaches the node's outdegree, then we
	 * stop sending the query on the network, even though we continue to feed
	 * the SQ as usual when new connections are made.
	 *
	 * The "query emitted" counter is reset when the search retry timer expires.
	 *
	 *		--RAM, 04/04/2003
	 */

	if (n) {
		mark_search_sent_to_node(sch, n);
		gmsg_search_sendto_one(n, sch->search_handle, (gchar *) m, size);
	} else {
		mark_search_sent_to_connected_nodes(sch);
		if (qhv != NULL) {
			GSList *nodes = qrt_build_query_target(qhv, 0, NULL);
			gmsg_search_sendto_all(nodes, sch->search_handle,
				(gchar *) m, size);
			g_slist_free(nodes);
			gmsg_search_sendto_all_nonleaf(
				node_all_nodes(), sch->search_handle, (gchar *) m, size);
		} else
			gmsg_search_sendto_all(
				node_all_nodes(), sch->search_handle, (gchar *) m, size);
	}

	wfree(m, size);
}

/*
 * node_added_callback
 *
 * Called when we connect to a new node and thus can send it our searches.
 * FIXME: uses node_added which is a global variable in nodes.c. This
 *        should instead be contained with the argument to this call.
 */
static void node_added_callback(gpointer data)
{
	search_ctrl_t *sch = (search_ctrl_t *) data;
	g_assert(node_added != NULL);
	g_assert(data != NULL);
    g_assert(sch != NULL);
    g_assert(!sch->passive);

	if (
        !search_already_sent_to_node(sch, node_added) &&
        !sch->frozen
    ) {
		_search_send_packet(sch, node_added);
	}
}

static void search_reset_sent_nodes(search_ctrl_t *sch)
{
	search_free_sent_nodes(sch);
	sch->sent_nodes = g_hash_table_new(sent_node_hash_func, sent_node_compare);
}

/*
 * search_add_new_muid:
 *
 * Create a new muid and add it to the search's list of muids.
 */
static void search_add_new_muid(search_ctrl_t *sch, gchar *muid)
{
	guint count;

	if (sch->muids)				/* If this isn't the first muid */
		search_reset_sent_nodes(sch);

	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
	g_hash_table_insert(sch->h_muids, muid, muid);

	/*
	 * If we got more than MUID_MAX entries in the list, chop last items.
	 */

	count = g_slist_length(sch->muids);

	while (count-- > MUID_MAX) {
		GSList *last = g_slist_last(sch->muids);
		g_hash_table_remove(sch->h_muids, last->data);
		wfree(last->data, MUID_SIZE);
		sch->muids = g_slist_remove_link(sch->muids, last);
		g_slist_free_1(last);
	}
}

static void search_send_packet(search_ctrl_t *sch)
{
	_search_send_packet(sch, NULL);
}

/*
 * search_reissue_timeout_callback:
 *
 * Called when the reissue timer for any search is triggered. The
 * data given is the search to be reissued.
 */
static gboolean search_reissue_timeout_callback(gpointer data)
{
	search_ctrl_t *sch = (search_ctrl_t *) data;

	search_reissue(sch->search_handle);
	return TRUE;
}

/*
 * update_one_reissue_timeout:
 *
 * Make sure a timer is created/removed after a search was started/stopped.
 */
static void update_one_reissue_timeout(search_ctrl_t *sch)
{
    g_assert(sch != NULL);
    g_assert(!sch->passive);

    if (sch->reissue_timeout_id > 0)
        g_source_remove(sch->reissue_timeout_id);

    /*
     * When a search is frozen or the reissue_timout is zero, all we need 
     * to do is to remove the timer.
     */
    if (sch->frozen || (sch->reissue_timeout == 0))
        return;

	if (dbg > 3)
		printf("updating search %s with timeout %d.\n", sch->query,
		   sch->reissue_timeout * 1000);

    /*
     * Otherwise we also add a new timer. If the search was stopped, this
     * will restart the search, otherwise is will simply reset the timer
     * and set a new timer with the searches's reissue_timeout.
     */
    sch->reissue_timeout_id = g_timeout_add(
        sch->reissue_timeout * 1000, 
        search_reissue_timeout_callback,
        sch);
}

/*
 * search_dequeue_all_nodes
 *
 * Signal to all search queues that search was closed.
 */
static void search_dequeue_all_nodes(gnet_search_t sh)
{
	const GSList *sl;

	for (sl = node_all_nodes(); sl; sl = g_slist_next(sl)) {
		struct gnutella_node *n = (struct gnutella_node *) sl->data;
		squeue_t *sq = NODE_SQUEUE(n);

		if (sq)
			sq_search_closed(sq, sh);
	}
}

/***
 *** Public functions
 ***/

void search_init(void)
{
    printf("search_init\n");
	rs_zone = zget(sizeof(gnet_results_set_t), 1024);
	rc_zone = zget(sizeof(gnet_record_t), 1024);
    
    search_handle_map = idtable_new(32,32);
	query_hashvec = qhvec_alloc(128);	/* Max: 128 unique words / URNs! */
}

void search_shutdown(void)
{
    while (sl_search_ctrl != NULL) {
        g_warning("force-closing search left over by GUI: %s", 
            ((search_ctrl_t *)sl_search_ctrl->data)->query);
        search_close(((search_ctrl_t *)sl_search_ctrl->data)->search_handle);
    }

    g_assert(idtable_ids(search_handle_map) == 0);

    idtable_destroy(search_handle_map);
    search_handle_map = NULL;
	qhvec_free(query_hashvec);

	zdestroy(rs_zone);
	zdestroy(rc_zone);
	rs_zone = rc_zone = NULL;
}

/*
 * search_results
 *
 * This routine is called for each Query Hit packet we receive.
 * Returns whether the message should be dropped, i.e. FALSE if OK.
 */
gboolean search_results(gnutella_node_t *n)
{
	gnet_results_set_t *rs;
	GSList *selected_searches = NULL;
	GSList *sl;
	gboolean drop_it = FALSE;

	/*
	 * Look for all the searches, and put the ones we need to possibly
	 * dispatch the results to into the selected_searches list.
	 */

	for (sl = sl_search_ctrl; sl != NULL; sl = g_slist_next(sl)) {
		search_ctrl_t *sch = (search_ctrl_t *) sl->data;

		/*
		 * Candidates are all non-frozen searches that are either
         * passive or for which we sent a query bearing the message 
         * ID of the reply.
		 */

		if (
            !sch->frozen && 
			(sch->passive || search_has_muid(sch, n->header.muid))
        ) {
			selected_searches = g_slist_prepend
                (selected_searches, GUINT_TO_POINTER(sch->search_handle));
        }
	}

	/*
	 * Parse the packet.
	 *
	 * If we're not going to dispatch it to any search or auto-download files
	 * based on the SHA1, the packet is only parsed for validation.
	 */

	rs = get_results_set(n,
		selected_searches == NULL
		&& !auto_download_identical
		&& !auto_feed_download_mesh);

	if (rs == NULL) {
        /*
         * get_results_set takes care of telling the stats that
         * the message was dropped.
         */
		drop_it = TRUE;				/* Don't forward bad packets */
		goto final_cleanup;
	}

	/*
	 * If we're handling a message from our immediate neighbour, grab the
	 * vendor code from the QHD.  This is useful for 0.4 handshaked nodes
	 * to determine and display their vendor ID.
	 *
	 * NB: route_message() increases hops by 1 for messages we handle.
	 */

	if (n->header.hops == 1)
		update_neighbour_info(n, rs);

    /*
     * Look for records that match entries in the download queue.
	 */

    if (auto_download_identical)
		search_check_results_set(rs);

	/*
	 * Look for records whose SHA1 matches files we own and add
	 * those entries to the mesh.
     */

	if (auto_feed_download_mesh)
		dmesh_check_results_set(rs);

    /*
     * Look for records that should be ignored.
     */

    if (mark_ignored) {
        for (sl = rs->records; sl != NULL; sl = g_slist_next(sl)) {
            gnet_record_t *rc = (gnet_record_t *) sl->data;
            enum ignore_val ival;

            ival = ignore_is_requested(rc->name, rc->size, rc->sha1);
            if (ival != IGNORE_FALSE)
                set_flags(rc->flags, SR_IGNORED);
		}
	}

	/*
	 * Dispatch the results to the selected searches.
	 */

     if (selected_searches != NULL)
        search_fire_got_results(selected_searches, rs);
		
    search_free_r_set(rs);

final_cleanup:
	g_slist_free(selected_searches);

	if (drop_it && n->header.hops == 1)
		n->n_weird++;

	return drop_it;
}

/*
 * search_query_allowed
 *
 * Check whether we can send another query for this search.
 * Returns TRUE if we can send, with the emitted counter incremented, or FALSE
 * if the query should just be ignored.
 */
gboolean search_query_allowed(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_assert(sch);

	/*
	 * We allow the query to be sent once more than our outdegree.
	 *
	 * This is because "sending" here means putting the message in
	 * the message queue, not physically sending.  We might never get
	 * a chance to send that message.
	 */

	if (sch->query_emitted > node_outdegree())
		return FALSE;

	sch->query_emitted++;
	return TRUE;
}

/*
 * search_check_alt_locs
 *
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
static void search_check_alt_locs(
	gnet_results_set_t *rs, gnet_record_t *rc, struct dl_file_info *fi)
{
	gint i;
	gnet_host_vec_t *alt = rc->alt_locs;
	gint ignored = 0;

	g_assert(alt != NULL);

	for (i = alt->hvcnt - 1; i >= 0; i--) {
		struct gnutella_host *h = &alt->hvec[i];

		if (!host_is_valid(h->ip, h->port)) {
			ignored++;
			continue;
		}

		download_auto_new(rc->name, rc->size, URN_INDEX, h->ip,
			h->port, blank_guid, rc->sha1, rs->stamp, FALSE, fi, rs->proxies);

		if (rs->proxies != NULL)
			search_free_proxies(rs);
	}

	search_free_alt_locs(rc);

	if (ignored) {
    	gchar *vendor = lookup_vendor_name(rs->vendor);
		g_warning("ignored %d invalid alt-loc%s in hits from %s (%s)",
			ignored, ignored == 1 ? "" : "s",
			ip_port_to_gchar(rs->ip, rs->port), vendor ? vendor : "????");
	}
}

/*
 * search_check_results_set
 *
 * Check a results_set for matching entries in the download queue,
 * and generate new entries if we find a match.
 */
static void search_check_results_set(gnet_results_set_t *rs)
{
	GSList *sl;
	struct dl_file_info *fi;

	for (sl = rs->records; sl; sl = g_slist_next(sl)) {
		gnet_record_t *rc = (gnet_record_t *) sl->data;

		fi = file_info_has_identical(rc->name, rc->size, rc->sha1);

		if (fi) {
			gboolean need_push = (rs->status & ST_FIREWALL) ||
				!host_is_valid(rs->ip, rs->port);

			download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					rs->guid, rc->sha1, rs->stamp, need_push, fi, rs->proxies);


			if (rs->proxies != NULL)
				search_free_proxies(rs);

            set_flags(rc->flags, SR_DOWNLOADED);

			/*
			 * If there are alternate sources for this download in the query
			 * hit, enqueue the downloads as well, then remove the sources
			 * from the record.
			 *		--RAM, 15/07/2003.
			 */

			if (rc->alt_locs != NULL)
				search_check_alt_locs(rs, rc, fi);

			g_assert(rc->alt_locs == NULL);
		}
	}
}

/***
 *** Public functions accessible through gnet.h
 ***/

/* 
 * search_close:
 *
 * Remove the search from the list of searches and free all 
 * associated ressources.
 */
void search_close(gnet_search_t sh)
{
	GSList *m;
    search_ctrl_t *sch = search_find_by_handle(sh);

	g_return_if_fail(sch);

    /*
     * We remove the search immeditaly from the list of searches,
     * because some of the following calls (may) depend on 
     * "searches" holding only the remaining searches. 
     * We may not free any ressources of "sch" yet, because 
     * the same calls may still need them!.
     *      --BLUE 26/05/2002
     */

	sl_search_ctrl = g_slist_remove(sl_search_ctrl, (gpointer) sch);
    search_drop_handle(sch->search_handle);

	if (!sch->passive) {
		g_hook_destroy_link(&node_added_hook_list, sch->new_node_hook);
		sch->new_node_hook = NULL;

		/* we could have stopped the search already, must test the ID */
		if (sch->reissue_timeout_id)
			g_source_remove(sch->reissue_timeout_id);

		for (m = sch->muids; m; m = m->next)
			wfree(m->data, MUID_SIZE);

		g_slist_free(sch->muids);
		g_hash_table_destroy(sch->h_muids);

		search_free_sent_nodes(sch);
		search_dequeue_all_nodes(sh);
	} else {
		search_passive--;
	}

	atom_str_free(sch->query);
	g_free(sch);
}

/*
 * search_reissue:
 *
 * Force a reissue of the given search. Restart reissue timer.
 */
void search_reissue(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);
	gchar *muid;

    if (sch->frozen) {
        g_warning("trying to reissue a frozen search, aborted");
        return;
    }

	if (dbg)
		printf("reissuing search \"%s\" (queries broadcasted: %d)\n",
			sch->query, sch->query_emitted);

	muid = walloc(MUID_SIZE);
	guid_query_muid(muid, FALSE);

	sch->query_emitted = 0;
	search_add_new_muid(sch, muid);
	search_send_packet(sch);
	update_one_reissue_timeout(sch);
}

/*
 * search_set_reissue_timeout:
 *
 * Set the reissue timeout of a search.
 */
void search_set_reissue_timeout(gnet_search_t sh, guint32 timeout)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    if (sch->passive) {
        g_error("Can't set reissue timeout on a passive search");
        return;
    }

    if (timeout < 600)
        timeout = 600;

    sch->reissue_timeout = timeout;
    update_one_reissue_timeout(sch);
}

/*
 * search_get_reissue_timeout:
 *
 * Get the reissue timeout of a search.
 */
guint32 search_get_reissue_timeout(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sch->reissue_timeout;
}

/*
 * search_new:
 *
 * Create a new suspended search and return a handle which identifies it.
 */
gnet_search_t search_new(
    const gchar *query, guint16 minimum_speed, guint32 reissue_timeout,
    flag_t flags)
{
	search_ctrl_t *sch;
	gchar *qdup;
	gint qlen;
	gint utf8_len;
	extern guint compact_query(gchar *search, gint utf8_len);

	sch = g_new0(search_ctrl_t, 1);
	sch->search_handle = search_request_handle(sch);

	/*
	 * Canonicalize the query we're sending.
	 */

	qdup = g_strdup(query);
	qlen = strlen(qdup);

	utf8_len = utf8_is_valid_string(qdup, qlen);
	if (utf8_len && utf8_len == qlen)
		utf8_len = 0;						/* Uses ASCII only */

	compact_query(qdup, utf8_len);

	sch->query = atom_str_get(qdup);
	sch->frozen = TRUE;

	g_free(qdup);

	if (flags & SEARCH_PASSIVE) {
		sch->passive = TRUE;
		search_passive++;
	} else {
		sch->new_node_hook = g_hook_alloc(&node_added_hook_list);
		sch->new_node_hook->data = (gpointer) sch;
		sch->new_node_hook->func = (gpointer) node_added_callback;
		g_hook_prepend(&node_added_hook_list, sch->new_node_hook);

		sch->reissue_timeout = reissue_timeout;
	}

	sl_search_ctrl = g_slist_prepend(sl_search_ctrl, (gpointer) sch);

	return sch->search_handle;
}

/*
 * search_start:
 *
 * Start a newly created start or resume stopped search.
 */
void search_start(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch->frozen);			/* Coming from search_new(), or resuming */

    sch->frozen = FALSE;

    if (!sch->passive) {
		/*
		 * If we just created the search with search_new(), there will be
		 * no message ever sent, and sch->muids will be NULL.
		 */

		if (sch->muids == NULL) {
			gchar *muid = walloc(MUID_SIZE);
			extern guint guid_hash(gconstpointer key);
			extern gint guid_eq(gconstpointer a, gconstpointer b);

			sch->h_muids = g_hash_table_new(guid_hash, guid_eq);

			guid_query_muid(muid, TRUE);
			search_add_new_muid(sch, muid);

			sch->sent_nodes =
				g_hash_table_new(sent_node_hash_func, sent_node_compare);

			search_send_packet(sch);		/* Send initial query */
		}

        update_one_reissue_timeout(sch);
	}
}

/*
 * search_stop:
 *
 * Stop search. Cancel reissue timer and don't return any results anymore.
 */
void search_stop(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
    g_assert(!sch->frozen);

    sch->frozen = TRUE;

    if (!sch->passive)
        update_one_reissue_timeout(sch);
}

gboolean search_is_frozen(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
    
    return sch->frozen;
}

gboolean search_is_passive(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);
    
    return sch->passive;
}

