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

#include "gnutella.h"

#include "extensions.h"
#include "gmsg.h"
#include "huge.h"
#include "nodes.h"
#include "routing.h"
#include "downloads.h"
#include "guid.h"
#include "gnet_stats.h"
#include "utf8.h"
#include "vendors.h"
#include "ignore.h"
#include "ggep.h"

#include <ctype.h>

struct sent_node_data {
	guint32 ip;
	guint16 port;
};

/* 
 * Structure for search results 
 */
typedef struct search_ctrl {
    gnet_search_t search_handle; /* Search handle */

	gchar  *query;				/* The search query */
	guint16 speed;				/* Minimum speed for the results of query */
	time_t  time;				/* Time when this search was started */
	GSList *muids;				/* Message UID's of this search */

	gboolean passive;			/* Is this a passive search? */
	gboolean frozen;			/* True => don't update window */
	/* keep a record of nodes we've sent this search w/ this muid to. */
	GHashTable *sent_nodes;

	GHook *new_node_hook;
	guint reissue_timeout_id;
	guint reissue_timeout;		/* timeout per search, 0 = search stopped */
} search_ctrl_t;

/*
 * List of searches.
 */
static GSList *sl_search_ctrl = NULL;

static zone_t *rs_zone;		/* Allocation of results_set */
static zone_t *rc_zone;		/* Allocation of record */

static idtable_t *search_handle_map = NULL;

#define search_find_by_handle(n) \
    (search_ctrl_t *) idtable_get_value(search_handle_map, n)

#define search_request_handle(n) \
    idtable_new_id(search_handle_map, n)

#define search_drop_handle(n) \
    idtable_free_id(search_handle_map, n);

guint32   search_passive  = 0;		/* Amount of passive searches */

/* 
 * Didn't find a better place to put this, since downloads.h
 * doesn't know about the struct results_set. --vidar, 20020802 
 * FIXME: this is declared in fileinfo.c, but not in fileinfo.h!
 */
gboolean file_info_check_results_set(gnet_results_set_t *rs);


/***
 *** Callbacks (private and public)
 ***/
static listeners_t search_got_results_listeners = NULL;

void search_add_got_results_listener(search_got_results_listener_t l)
{
    g_assert(l != NULL);

    search_got_results_listeners = 
        g_slist_append(search_got_results_listeners, l);
}

void search_remove_got_results_listener(search_got_results_listener_t l)
{
    g_assert(l != NULL);

    search_got_results_listeners = 
        g_slist_remove(search_got_results_listeners, l);
}

static void search_fire_got_results
    (GSList *sch_matched, const gnet_results_set_t *rs)
{
    GSList *l;
    g_assert(rs != NULL);

    for (
        l = search_got_results_listeners; 
        l != NULL; 
        l = g_slist_next(l)
    ) {
        search_got_results_listener_t fn = 
            (search_got_results_listener_t) l->data;

        (*fn)(sch_matched, rs);
    }
}

/***
 *** Private functions
 ***/

static guint sent_node_hash_func(gconstpointer key)
{
	struct sent_node_data *sd = (struct sent_node_data *) key;

	/* ensure that we've got sizeof(gint) bytes of deterministic data */
	gint ip = sd->ip;
	gint port = sd->port;

	return g_int_hash(&ip) ^ g_int_hash(&port);
}

static gint sent_node_compare(gconstpointer a, gconstpointer b)
{
	struct sent_node_data *sa = (struct sent_node_data *) a;
	struct sent_node_data *sb = (struct sent_node_data *) b;

	return sa->ip == sb->ip && sa->port == sb->port;
}

static gboolean search_free_sent_node(
	gpointer node, gpointer value, gpointer udata)
{
	g_free(node);
	return TRUE;
}

static void search_free_sent_nodes(search_ctrl_t *sch)
{
	g_hash_table_foreach_remove(sch->sent_nodes, search_free_sent_node, NULL);
	g_hash_table_destroy(sch->sent_nodes);
}

static void mark_search_sent_to_node
    (search_ctrl_t *sch, gnutella_node_t *n)
{
	struct sent_node_data *sd = g_new(struct sent_node_data, 1);
	sd->ip = n->ip;
	sd->port = n->port;
	g_hash_table_insert(sch->sent_nodes, sd, (void *) 1);
}

void mark_search_sent_to_connected_nodes(search_ctrl_t *sch)
{
	GSList *l;
	struct gnutella_node *n;

	g_hash_table_freeze(sch->sent_nodes);
	for (l = sl_nodes; l; l = l->next) {
		n = (struct gnutella_node *) l->data;
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
static gboolean search_already_sent_to_node
    (search_ctrl_t *sch, gnutella_node_t *n)
{
	struct sent_node_data sd;
	sd.ip = n->ip;
	sd.port = n->port;
	return (gboolean) g_hash_table_lookup(sch->sent_nodes, &sd);
}

/*
 * search_has_muid:
 *
 * Return TRUE if the muid list of the given search contains the
 * given muid.
 */
static gboolean search_has_muid(search_ctrl_t *sch, const guchar *muid)
{
	GSList *m;

	for (m = sch->muids; m; m = m->next)
		if (!memcmp(muid, (guchar *) m->data, 16))
			return TRUE;
	return FALSE;
}

/*
 * search_free_record
 *
 * Free one file record.
 */
static void search_free_record(gnet_record_t *rc)
{
	atom_str_free(rc->name);
	if (rc->tag)
		atom_str_free(rc->tag);
	if (rc->sha1)
		atom_sha1_free(rc->sha1);
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
	guint32 nr, size, index, taglen;
	struct gnutella_search_results *r;
	GString *info = NULL;
	gint sha1_errors = 0;
	guchar *trailer = NULL;
	gboolean seen_ggep_h = FALSE;
	gboolean seen_bitprint = FALSE;

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
    rs->status    = 0;

	r = (struct gnutella_search_results *) n->data;

	/* Transfer the Query Hit info to our internal results_set struct */

	rs->num_recs = (guint8) r->num_recs;		/* Number of hits */
	READ_GUINT32_BE(r->host_ip, rs->ip);		/* IP address */
	READ_GUINT16_LE(r->host_port, rs->port);	/* Port */
	READ_GUINT32_LE(r->host_speed, rs->speed);	/* Connection speed */

	/* Now come the result set, and the servent ID will close the packet */

	s = r->records;				/* Start of the records */
	e = s + n->size - 11 - 16;	/* End of the records, less header, GUID */
	nr = 0;

	if (dbg > 7)
		dump_hex(stdout, "Query Hit Data", n->data, n->size);

	while (s < e && nr < rs->num_recs) {
		READ_GUINT32_LE(s, index);
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
				guchar c = *s;
				if (!c)
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
			rc->index = index;
			rc->size  = size;
			rc->name  = atom_str_get(fname);
            rc->flags = 0;
		}

		/*
		 * If we have a tag, parse it for extensions.
		 */

		if (tag) {
			extvec_t exv[MAX_EXTVEC];
			gint exvcnt;
			gint i;

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

				switch (e->ext_token) {
				case EXT_T_URN_BITPRINT:	/* first 32 chars is the SHA1 */
					seen_bitprint = TRUE;
					/* FALLTHROUGH */
				case EXT_T_URN_SHA1:
					if (
						huge_sha1_extract32(e->ext_payload, e->ext_paylen,
							sha1_digest, &n->header, TRUE)
					) {
						if (!validate_only)
							rc->sha1 = atom_sha1_get(sha1_digest);
					} else
						sha1_errors++;
					break;
				case EXT_T_GGEP_H:
					ret = ggept_h_sha1_extract(e, sha1_digest, SHA1_RAW_SIZE);
					if (ret == GGEP_OK) {
						if (!validate_only)
							rc->sha1 = atom_sha1_get(sha1_digest);
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
				case EXT_T_UNKNOWN:
					if (
						!validate_only &&
						e->ext_paylen && ext_has_ascii_word(e)
					) {
						guchar *p = e->ext_payload + e->ext_paylen;
						guchar c = *p;

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
		gchar *vendor;
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
				"%s (%s) from %s (%s) had %d SHA1 error%s over %u record%s",
				 gmsg_infostr(&n->header), vendor ? vendor : "????",
				 node_ip(n), n->vendor ? n->vendor : "????",
				 sha1_errors, sha1_errors == 1 ? "" : "s",
				 nr, nr == 1 ? "" : "s");
            gnet_stats_count_dropped(n, MSG_DROP_RESULT_SHA1_ERROR);
			goto bad_packet;		/* Will drop this bad query hit */
		}

		/*
		 * Parse trailer after the open data, if we have a GGEP extension.
		 */

		if (rs->status & ST_GGEP) {
			guchar *priv = &trailer[5] + open_size;
			gint privlen = (guchar *) e - priv;
			gint exvcnt;
			extvec_t exv[MAX_EXTVEC];
			gboolean seen_ggep = FALSE;
			gint i;

			exvcnt = ext_parse(priv, privlen, exv, MAX_EXTVEC);

			// XXX for now we don't do anything with the information we
			// XXX collected: we just validate it

			for (i = 0; i < exvcnt; i++) {
				if (exv[i].ext_type == EXT_GGEP)
					seen_ggep = TRUE;
			}

			if (exvcnt == MAX_EXTVEC) {
				g_warning("%s has %d extensions!",
					gmsg_infostr(&n->header), exvcnt);
				if (dbg)
					ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
				if (dbg > 1)
					dump_hex(stderr, "Query Hit private data", priv, privlen);
			} else if (!seen_ggep) {
				g_warning("%s claimed GGEP extensions in trailer, seen none",
					gmsg_infostr(&n->header));
			}
		}

		if (dbg) {
			if (seen_ggep_h) {
				gchar *vendor = lookup_vendor_name(rs->vendor);
				g_warning("%s from %s used GGEP \"H\" extension",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			}
			if (seen_bitprint) {
				gchar *vendor = lookup_vendor_name(rs->vendor);
				g_warning("%s from %s used urn:bitprint",
					 gmsg_infostr(&n->header), vendor ? vendor : "????");
			}
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
			"BAD %s from %s (%u/%u records parsed)",
			 gmsg_infostr(&n->header), node_ip(n), nr, rs->num_recs);
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
				node_ip(n), n->vendor ? n->vendor : "", vendor,
				gmsg_infostr(&n->header));
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
				node_ip(n), n->vendor ? n->vendor : "",
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
				node_ip(n), n->vendor ? n->vendor : "",
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
					node_ip(n), n->vendor ? n->vendor : "",
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
				node_ip(n), n->vendor ? n->vendor : "",
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

static void __search_send_packet(search_ctrl_t *sch, gnutella_node_t *n)
{
	struct gnutella_msg_search *m;
	guint32 size;
	gint plen;				/* Length of payload */
	gint qlen;				/* Length of query text */
	gboolean is_urn_search = FALSE;

    g_assert(sch != NULL);
    g_assert(!sch->passive);
    g_assert(!sch->frozen);

	/*
	 * Don't send on a temporary connection.
	 * Although gmsg_sendto_one() is protected, it's useless to go through all
	 * the message building only to discard the message at the end.
	 * Moreover, we don't want to record the search being sent to this IP/port.
	 *		--RAM, 13/01/2002
	 */

	if (n && NODE_IS_PONGING_ONLY(n))
		return;

	/*
	 * Are we dealing with an URN search?
	 */

	if (0 == strncmp(sch->query, "urn:sha1:", 9))
		is_urn_search = TRUE;

	if (is_urn_search) {
		/*
		 * We're sending an empty search text (NUL only), then the 9+32 bytes
		 * of the URN query, plus a trailing NUL.
		 */
		qlen = 0;
		size = sizeof(struct gnutella_msg_search) + 9+32 + 2;	/* 2 NULs */
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
	m->header.hops = hops_random_factor ? random_value(hops_random_factor) : 0;
	if (m->header.ttl + m->header.hops > hard_ttl_limit)
		m->header.ttl = hard_ttl_limit - m->header.hops;

	WRITE_GUINT32_LE(plen, m->header.size);
	WRITE_GUINT16_LE(sch->speed, m->search.speed);

	if (is_urn_search) {
		*m->search.query = '\0';
		strncpy(m->search.query + 1, sch->query, 9+32);	/* urn:sha1:32bytes */
		m->search.query[1+9+32] = '\0';
	} else
		strcpy(m->search.query, sch->query);

	message_add(m->header.muid, GTA_MSG_SEARCH, NULL);

	if (n) {
		mark_search_sent_to_node(sch, n);
		gmsg_search_sendto_one(n, (guchar *) m, size);
	} else {
		mark_search_sent_to_connected_nodes(sch);
		gmsg_search_sendto_all(sl_nodes, (guchar *) m, size);
	}

	wfree(m, size);
}

/*
 * node_added_callback:
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
		__search_send_packet(sch, node_added);
	}
}

static void search_reset_sent_nodes(search_ctrl_t *sch)
{
	search_free_sent_nodes(sch);
	sch->sent_nodes =
		g_hash_table_new(sent_node_hash_func, sent_node_compare);
}

/*
 * search_add_new_muid:
 *
 * Create a new muid and add it to the search's list of muids.
 */
static void search_add_new_muid(search_ctrl_t *sch, guchar *muid)
{
	if (sch->muids)				/* If this isn't the first muid */
		search_reset_sent_nodes(sch);
	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
}

static void search_send_packet(search_ctrl_t *sch)
{
	__search_send_packet(sch, NULL);
}

/*
 * search_reissue_timeout_callback:
 *
 * Called when the reissue timer for any search is triggered. The
 * data given is the search to be reissued.
 */
static gboolean search_reissue_timeout_callback(gpointer data)
{
	search_reissue(((search_ctrl_t *)data)->search_handle);
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
 * Signal to all search queues that search for `qtext' was closed.
 */
static void search_dequeue_all_nodes(gchar *qtext)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;
		squeue_t *sq = NODE_SQUEUE(n);

		if (sq)
			sq_search_closed(sq, qtext);
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
                (selected_searches, (gpointer) sch->search_handle);
        }
	}

	/*
	 * Parse the packet.
	 *
	 * If we're not going to dispatch it to any search, the packet is only
	 * parsed for validation.
	 */

	rs = get_results_set(n, selected_searches == NULL);
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
        file_info_check_results_set(rs);


    /*
     * Look for records that match entries in the download queue.
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
			g_free(m->data);

		g_slist_free(sch->muids);
		search_free_sent_nodes(sch);
		search_dequeue_all_nodes(sch->query);
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
	guchar *muid;

    if (sch->frozen) {
        g_warning("trying to reissue a frozen search, aborted");
        return;
    }

	if (dbg)
		printf("reissuing search %s.\n", sch->query);

	muid = (guchar *) g_malloc(16);
	guid_query_muid(muid, FALSE);

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
 * search_set_minimum_speed:
 *
 * Set the minimum speed of a search.
 */
void search_set_minimum_speed(gnet_search_t sh, guint16 speed)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    sch->speed = speed;
}


/*
 * search_get_minimum_speed:
 *
 * Get the minimum speed of a search.
 */
guint16 search_get_minimum_speed(gnet_search_t sh)
{
    search_ctrl_t *sch = search_find_by_handle(sh);

    g_assert(sch != NULL);

    return sch->speed;
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
	sch->speed = minimum_speed;
    sch->frozen = TRUE;

	g_free(qdup);

	if (flags & SEARCH_PASSIVE) {
		sch->passive = TRUE;
		search_passive++;
	} else {
		sch->new_node_hook = g_hook_alloc(&node_added_hook_list);
		sch->new_node_hook->data = sch;
		sch->new_node_hook->func = node_added_callback;
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

    g_assert(sch->frozen);

    sch->frozen = FALSE;

    if (!sch->passive) {
		/*
		 * If we just created the search with search_new(), there will be
		 * no message ever sent, and sch->muids will be NULL.
		 */

		if (sch->muids == NULL) {
			guchar *muid = (guchar *) g_malloc(16);

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

