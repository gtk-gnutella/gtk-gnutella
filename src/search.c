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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <ctype.h>
#include <sys/stat.h>

/* Handle searches */

#include "gnutella.h"
#include "misc.h"
#include "search.h"
#include "downloads.h"
#include "hosts.h"				/* For check_valid_host() */
#include "nodes.h"				/* For NODE_IS_PONGING_ONLY() */
#include "callbacks.h" // FIXME: remove this dependency
#include "routing.h"
#include "gmsg.h"
#include "filter.h"
#include "atoms.h"
#include "extensions.h"
#include "base32.h"
#include "sq.h"
#include "walloc.h"
#include "zalloc.h"

#include "gnet_property_priv.h"
#include "gui_property_priv.h" // FIXME: for search_max_results. Remove this.
#include "search_gui.h" // FIXME: remove this dependency
#include "nodes_gui.h" // FIXME: remove this dependency
#include "settings.h"

#ifdef USE_SEARCH_XML
# include "search_xml.h"
# include "libxml/parser.h"
#endif

#define MAKE_CODE(a,b,c,d) ( \
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

#define T_BEAR	MAKE_CODE('B','E','A','R')
#define T_CULT	MAKE_CODE('C','U','L','T')
#define T_FIRE	MAKE_CODE('F','I','R','E')
#define T_FISH	MAKE_CODE('F','I','S','H')
#define T_GNEW	MAKE_CODE('G','N','E','W')
#define T_GNOT	MAKE_CODE('G','N','O','T')
#define T_GNUC	MAKE_CODE('G','N','U','C')
#define T_GNUT	MAKE_CODE('G','N','U','T')
#define T_GTKG	MAKE_CODE('G','T','K','G')
#define T_HSLG	MAKE_CODE('H','S','L','G')
#define T_LIME	MAKE_CODE('L','I','M','E')
#define T_MACT	MAKE_CODE('M','A','C','T')
#define T_MMMM	MAKE_CODE('M','M','M','M')
#define T_MNAP	MAKE_CODE('M','N','A','P')
#define T_MRPH	MAKE_CODE('M','R','P','H')
#define T_MUTE	MAKE_CODE('M','U','T','E')
#define T_NAPS	MAKE_CODE('N','A','P','S')
#define T_OCFG	MAKE_CODE('O','C','F','G')
#define T_OPRA	MAKE_CODE('O','P','R','A')
#define T_PHEX	MAKE_CODE('P','H','E','X')
#define T_QTEL	MAKE_CODE('Q','T','E','L')
#define T_RAZA	MAKE_CODE('R','A','Z','A')
#define T_SNUT	MAKE_CODE('S','N','U','T')
#define T_SWAP	MAKE_CODE('S','W','A','P')
#define T_SWFT	MAKE_CODE('S','W','F','T')
#define T_TOAD	MAKE_CODE('T','O','A','D')
#define T_XOLO	MAKE_CODE('X','O','L','O')
#define T_XTLA	MAKE_CODE('X','T','L','A')
#define T_ZIGA	MAKE_CODE('Z','I','G','A')

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

#define find_search(s) ((search_t *) s)
#define search_new_handle(s) ((gnet_search_t) s)

static gchar stmp_2[4096];

GList *searches = NULL;		/* List of search structs */

/* Need to remove this dependency on GUI further --RAM */
extern GtkWidget *default_search_clist;
extern GtkWidget *default_scrolled_window;

search_t *search_selected = NULL;
search_t *current_search = NULL;	/*	The search currently displayed */
guint32 search_passive = 0;				/* Amount of passive searches */

static gchar *search_file = "searches";	/* File where searches are saved */

static zone_t *rs_zone;		/* Allocation of results_set */
static zone_t *rc_zone;		/* Allocation of record */

/*
 * Private function prototypes
 */
static void search_send_packet(search_t *);
static void search_add_new_muid(search_t *sch);
static guint sent_node_hash_func(gconstpointer key);
static gint sent_node_compare(gconstpointer a, gconstpointer b);
static void search_free_sent_nodes(search_t *sch);
static gboolean search_reissue_timeout_callback(gpointer data);
static void update_one_reissue_timeout(search_t *sch);
static struct results_set *get_results_set(
	struct gnutella_node *n, gboolean validate_only);
static gboolean search_retrieve_old(void);

#ifndef USE_SEARCH_XML
    static void search_store_old(void);
#endif /* USE_SEARCH_XML */

static void search_dispose_results(struct results_set *rs);

/* Didn't find a better place to put this, since downloads.h
 * doesn't know about the struct results_set. --vidar, 20020802 */
gboolean file_info_check_results_set(struct results_set *rs);

/*
 * Human readable translation of servent trailer open flags.
 * Decompiled flags are listed in the order of the table.
 */
static struct {
	guint32 flag;
	gchar *status;
} open_flags[] = {
	{ ST_BUSY,		"busy" },
	{ ST_UPLOADED,	"stable" },		/* Allows uploads -> stable */
	{ ST_FIREWALL,	"push" },
};

/* ----------------------------------------- */

void search_reissue(search_t *sch)
{
	search_add_new_muid(sch);
	search_send_packet(sch);
	update_one_reissue_timeout(sch);
}

void search_restart(search_t *sch)
{
	search_reissue(sch);
	gtk_clist_clear(GTK_CLIST(sch->clist));
	sch->items = sch->unseen_items = 0;
	gui_search_update_items(sch);
}

void search_init(void)
{
	rs_zone = zget(sizeof(struct results_set), 1024);
	rc_zone = zget(sizeof(struct record), 1024);

	search_gui_init();
#ifdef USE_SEARCH_XML
    LIBXML_TEST_VERSION
	if (search_retrieve_old()) {
       	g_snprintf(stmp_2, sizeof(stmp_2), "%s/%s", config_dir, search_file);
        g_warning(
            "Found old searches file. Loaded it.\n"
            "On exit the searches will be saved in the new XML format\n"
            "and the old file will be renamed.");
    } else {
        search_retrieve_xml();
    }
#else
    search_retrieve_old();
#endif /* USE_SEARCH_XML */
}

/*
 * search_free_record
 *
 * Free one file record.
 *
 * Those records may be inserted into some `dups' tables, at which time they
 * have their refcount increased.  They may later be removed from those tables
 * and they will have their refcount decreased.
 *
 * To ensure some level of sanity, we ask our callers to explicitely check
 * for a refcount to be zero before calling us.
 */
static void search_free_record(struct record *rc)
{
	g_assert(rc->refcount == 0);

	atom_str_free(rc->name);
	if (rc->tag)
		atom_str_free(rc->tag);
	if (rc->sha1)
		atom_sha1_free(rc->sha1);
	zfree(rc_zone, rc);
}

/*
 * search_unref_record
 *
 * Remove one reference to a file record.
 *
 * If the record has no more references, remove it from its parent result
 * set and free the record physically.
 */
static void search_unref_record(struct record *rc)
{
	struct results_set *rs;

	g_assert(rc->refcount > 0);

	if (--(rc->refcount) > 0)
		return;

	/*
	 * Free record, and remove it from the parent's list.
	 */

	rs = rc->results_set;
	search_free_record(rc);

	rs->records = g_slist_remove(rs->records, rc);
	rs->num_recs--;

	g_assert(rs->num_recs || rs->records == NULL);

	/*
	 * We can't free the results_set structure right now if it does not
	 * hold anything because we don't know which searches reference it.
	 */

	if (rs->num_recs == 0)
		search_dispose_results(rs);
}

/*
 * search_clean_r_set
 *
 * This routine must be called when the results_set has been dispatched to
 * all the opened searches.
 *
 * All the records that have not been used by a search are removed.
 */
static void search_clean_r_set(struct results_set *rs)
{
	GSList *m;

	g_assert(rs->refcount);		/* If not dispatched, should be freed */

again:
	for (m = rs->records; m; m = m->next) {
		struct record *rc = (struct record *) m->data;

		if (rc->refcount)
			continue;

		search_free_record(rc);
		rs->records = g_slist_remove(rs->records, rc);
		rs->num_recs--;

		goto again;				/* Need to restart from the beginning */
	}
}

/*
 * search_free_r_set
 *
 * Free one results_set.
 *
 * Those records may be shared between several searches.  So while the refcount
 * is positive, we just decrement it and return without doing anything.
 */
static void search_free_r_set(struct results_set *rs)
{
	GSList *m;

	/*
	 * It is conceivable that some records were used solely by the search
	 * dropping the result set.  Therefore, if the refcount is not 0,  we
	 * pass through search_clean_r_set().
	 */

	if (--(rs->refcount) > 0) {
		search_clean_r_set(rs);
		return;
	}

	/*
	 * Because noone refers to us any more, we know that our embedded records
	 * cannot be held in the hash table anymore.  Hence we may call the
	 * search_free_record() safely, because rc->refcount must be zero.
	 */

	for (m = rs->records; m; m = m->next)
		search_free_record((struct record *) m->data);

	if (rs->guid)
		atom_guid_free(rs->guid);

	g_slist_free(rs->records);
	zfree(rs_zone, rs);
}

/*
 * search_dispose_results
 *
 * Dispose of an empty search results, whose records have all been
 * unreferenced by the searches.  The results_set is therefore an
 * empty shell, useless.
 */
static void search_dispose_results(struct results_set *rs)
{
	gint refs = 0;
	GList *l;

	g_assert(rs->num_recs == 0);
	g_assert(rs->refcount > 0);

	/*
	 * A results_set does not point back to the searches that still
	 * reference it, so we have to do that manually.
	 */

	for (l = searches; l; l = l->next) {
		GSList *link;
		search_t *sch = (search_t *) l->data;

		link = g_slist_find(sch->r_sets, rs);
		if (link == NULL)
			continue;

		refs++;			/* Found one more reference to this search */

		sch->r_sets = g_slist_remove_link(sch->r_sets, link);
	}

	g_assert(rs->refcount == refs);		/* Found all the searches */

	rs->refcount = 1;
	search_free_r_set(rs);
}

/* Free all the results_set's of a search */

static void search_free_r_sets(search_t *sch)
{
	GSList *l;

	g_return_if_fail(sch);
	g_assert(sch->dups);
	g_assert(g_hash_table_size(sch->dups) == 0); /* All records were cleaned */

	for (l = sch->r_sets; l; l = l->next)
		search_free_r_set((struct results_set *) l->data);

	g_slist_free(sch->r_sets);
	sch->r_sets = NULL;
}

/*
 * dec_records_refcount
 *
 * Decrement refcount of hash table key entry.
 */
static gboolean dec_records_refcount(gpointer key, gpointer value, gpointer x)
{
	struct record *rc = (struct record *) key;

	g_assert(rc->refcount > 0);

	rc->refcount--;
	return TRUE;
}

/*
 * search_clear
 *
 * Clear all results from search.
 */
void search_clear(search_t *sch)
{
	g_assert(sch);
	g_assert(sch->dups);

	/*
	 * Before invoking search_free_r_sets(), we must iterate on the
	 * hash table where we store records and decrement the refcount of
	 * each record, and remove them from the hash table.
	 *
	 * Otherwise, we will violate the pre-condition of search_free_record(),
	 * which is there precisely for that reason!
	 */

	g_hash_table_foreach_remove(sch->dups, dec_records_refcount, NULL);
	search_free_r_sets(sch);

	sch->items = sch->unseen_items = 0;
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

/* 
 * search_close:
 *
 * Remove the search from the list of searches and free all 
 * associated ressources (including filter and gui stuff).
 */
void search_close(search_t *sch)
{
	GSList *m;

	g_return_if_fail(sch);

    /*
     * We remove the search immeditaly from the list of searches,
     * because some of the following calls (may) depend on 
     * "searches" holding only the remaining searches. 
     * We may not free any ressources of "sch" yet, because 
     * the same calls may still need them!.
     *      --BLUE 26/05/2002
     */
	searches = g_list_remove(searches, (gpointer) sch);

    search_gui_remove_search(sch);
	filter_close_search(sch);

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

	search_clear(sch);
	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;

	atom_str_free(sch->query);
	g_free(sch);
}

static gboolean search_free_sent_node(
	gpointer node, gpointer value, gpointer udata)
{
	g_free(node);
	return TRUE;
}

static void search_free_sent_nodes(search_t *sch)
{
	g_hash_table_foreach_remove(sch->sent_nodes, search_free_sent_node, NULL);
	g_hash_table_destroy(sch->sent_nodes);
}

static void search_reset_sent_nodes(search_t *sch)
{
	search_free_sent_nodes(sch);
	sch->sent_nodes =
		g_hash_table_new(sent_node_hash_func, sent_node_compare);
}

struct sent_node_data {
	guint32 ip;
	guint16 port;
};

static void mark_search_sent_to_node(search_t *sch,
									 struct gnutella_node *n)
{
	struct sent_node_data *sd = g_new(struct sent_node_data, 1);
	sd->ip = n->ip;
	sd->port = n->port;
	g_hash_table_insert(sch->sent_nodes, sd, (void *) 1);
}

void mark_search_sent_to_connected_nodes(search_t *sch)
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

/* Create and send a search request packet */

static void __search_send_packet(search_t *sch, struct gnutella_node *n)
{
	struct gnutella_msg_search *m;
	guint32 size;
	gint plen;				/* Length of payload */
	gint qlen;				/* Length of query text */
	gboolean is_urn_search = FALSE;

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
		size = sizeof(struct gnutella_msg_search) + 9+32 + 2;		/* 2 NULs */
	} else {
		/*
		 * We're adding "urn:" after the NUL to request the SHA1 hash
		 * (4 chars), and terminate that string with a NUL.
		 *		-- RAM, 05/06/2002
		 */

		qlen = strlen(sch->query);
		size = sizeof(struct gnutella_msg_search) + qlen + 4 + 2;	/* 2 NULs */
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
	WRITE_GUINT16_LE(minimum_speed, m->search.speed);

	if (is_urn_search) {
		*m->search.query = '\0';
		strncpy(m->search.query + 1, sch->query, 9+32);	/* urn:sha1:32bytes */
	} else {
		strcpy(m->search.query, sch->query);
		strcpy(m->search.query + qlen + 1, "urn:");
	}

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

static void search_add_new_muid(search_t *sch)
{
	guchar *muid = (guchar *) g_malloc(16);

	generate_new_muid(muid, TRUE);

	if (sch->muids)				/* If this isn't the first muid */
		search_reset_sent_nodes(sch);
	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
}

static void search_send_packet(search_t *sch)
{
	__search_send_packet(sch, NULL);
}

static guint search_hash_func(gconstpointer key)
{
	struct record *rc = (struct record *) key;
	/* Must use same fields as search_hash_key_compare() --RAM */
	return
		g_str_hash(rc->name) ^
		g_int_hash(&rc->size) ^
		g_int_hash(&rc->results_set->ip) ^
		g_int_hash(&rc->results_set->port) ^
		g_int_hash(&rc->results_set->guid[0]) ^
		g_int_hash(&rc->results_set->guid[4]) ^
		g_int_hash(&rc->results_set->guid[8]) ^
		g_int_hash(&rc->results_set->guid[12]);
}

static gint search_hash_key_compare(gconstpointer a, gconstpointer b)
{
	struct record *rc1 = (struct record *) a;
	struct record *rc2 = (struct record *) b;

	/* Must compare same fields as search_hash_func() --RAM */
	return rc1->size == rc2->size
		&& rc1->results_set->ip == rc2->results_set->ip
		&& rc1->results_set->port == rc2->results_set->port
		&& 0 == memcmp(rc1->results_set->guid, rc2->results_set->guid, 16)
		&& 0 == strcmp(rc1->name, rc2->name);
}


search_t *search_new(gchar *query, guint16 speed)
{
	return search_new_full
        (query, speed, search_reissue_timeout, 0);
}

search_t *search_new_passive(gchar *query, guint16 speed)
{
	return search_new_full
        (query, speed, search_reissue_timeout, SEARCH_PASSIVE);
}


void search_stop(search_t *sch)
{
	if (sch->passive) {
		g_assert(!sch->frozen);
		sch->frozen = TRUE;
	} else {
		g_assert(sch->reissue_timeout_id);
		g_assert(sch->reissue_timeout); /* not already stopped */

        printf("search_stop: reissue_timeout = 0\n");
    
		sch->reissue_timeout = 0;
		update_one_reissue_timeout(sch);

		g_assert(sch->reissue_timeout_id == 0);
	}
}

void search_resume(search_t *sch)
{
	if (sch->passive) {
		g_assert(sch->frozen);
		sch->frozen = FALSE;
	} else {
		g_assert(sch->reissue_timeout == 0);	/* already stopped */

		sch->reissue_timeout = search_reissue_timeout;
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	}
}

static gboolean search_already_sent_to_node(search_t *sch,
											struct gnutella_node *n)
{
	struct sent_node_data sd;
	sd.ip = n->ip;
	sd.port = n->port;
	return (gboolean) g_hash_table_lookup(sch->sent_nodes, &sd);
}

static void node_added_callback(gpointer data)
{
	search_t *sch = (search_t *) data;
	g_assert(node_added);
	g_assert(data);
	if (!search_already_sent_to_node(sch, node_added)) {
		__search_send_packet(sch, node_added);
	}
}

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

static gboolean search_reissue_timeout_callback(gpointer data)
{
	search_t *sch = (search_t *) data;

	if (dbg)
		printf("reissuing search %s.\n", sch->query);
	search_reissue(sch);

	return TRUE;
}

static void update_one_reissue_timeout(search_t *sch)
{
	g_source_remove(sch->reissue_timeout_id);
	if (sch->reissue_timeout > 0) {
		if (dbg > 3)
			printf("updating search %s with timeout %d.\n", sch->query,
				   sch->reissue_timeout * 1000);
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	} else {
        printf("update_one_reissue_timeout: reissue_timeout = 0\n");
		sch->reissue_timeout_id = 0;
		if (dbg)
			printf("canceling search %s reissue timeout.\n", sch->query);
	}
}

void search_update_reissue_timeout(search_t *sch, guint32 timeout)
{
  	if (timeout > 0 && timeout < 600)	/* v == 0 means: no reissue */
        timeout = 600; /* Have to be reasonable -- RAM, 30/12/2001 */

    if (sch && !sch->passive) {
		if (sch->reissue_timeout > 0)	/* Not stopped */
			sch->reissue_timeout = timeout;
		if (sch->reissue_timeout_id)
			update_one_reissue_timeout(sch);
    }
}

/*
 * search_remove_r_set
 *
 * Remove reference to results in our search.
 * Last one to remove it will trigger a free.
 */
static void search_remove_r_set(search_t *sch, struct results_set *rs)
{
	sch->r_sets = g_slist_remove(sch->r_sets, rs);
	search_free_r_set(rs);
}


/* Start a new search */

search_t *search_new_full
    (gchar *query, guint16 speed, guint32 reissue_timeout, guint flags)
{
	search_t *sch;
	GList *glist;
    gchar *titles[3];
    gint row;

    GtkWidget *combo_searches = lookup_widget(main_window, "combo_searches");
    GtkWidget *clist_search = lookup_widget(main_window, "clist_search");
    GtkWidget *notebook_search_results = 
        lookup_widget(main_window, "notebook_search_results");
    GtkWidget *button_search_close = 
        lookup_widget(main_window, "button_search_close");
    GtkWidget *entry_search = lookup_widget(main_window, "entry_search");

	sch = (search_t *) g_malloc0(sizeof(search_t));

	sch->query = atom_str_get(query);
	sch->speed = speed;

  	filter_new_for_search(sch);

	if (flags & SEARCH_PASSIVE) {
		sch->passive = 1;
		search_passive++;
	} else {
		search_add_new_muid(sch);
		sch->sent_nodes =
			g_hash_table_new(sent_node_hash_func, sent_node_compare);
		search_send_packet(sch);

		sch->new_node_hook = g_hook_alloc(&node_added_hook_list);
		sch->new_node_hook->data = sch;
		sch->new_node_hook->func = node_added_callback;
		g_hook_prepend(&node_added_hook_list, sch->new_node_hook);

		sch->reissue_timeout = reissue_timeout;
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	}

	/* Create the list item */

	sch->list_item = gtk_list_item_new_with_label(sch->query);

	gtk_widget_show(sch->list_item);

	glist = g_list_prepend(NULL, (gpointer) sch->list_item);

	gtk_list_prepend_items(GTK_LIST(GTK_COMBO(combo_searches)->list),
						   glist);

    titles[c_sl_name] = sch->query;
    titles[c_sl_hit] = "0";
    titles[c_sl_new] = "0";
    row = gtk_clist_append(GTK_CLIST(clist_search), titles);
    gtk_clist_set_row_data(GTK_CLIST(clist_search), row, sch);

	/* Create a new CList if needed, or use the default CList */

	if (searches) {
		/* We have to create a new clist for this search */
		gui_search_create_clist(&sch->scrolled_window, &sch->clist);

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);

		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
								 sch->scrolled_window, NULL);

		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_search_results),
							  gtk_notebook_page_num(GTK_NOTEBOOK
													(notebook_search_results),
													sch->scrolled_window));
	} else {
		/* There are no searches currently, we can use the default clist */

		if (default_scrolled_window && default_search_clist) {
			sch->scrolled_window = default_scrolled_window;
			sch->clist = default_search_clist;

			default_search_clist = default_scrolled_window = NULL;
		} else
			g_warning
				("new_search(): No current search but no default clist !?\n");

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);
	}

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(tab_update_time * 1000,
										(GtkFunction)
										gui_search_update_tab_label, sch);

	sch->dups =
		g_hash_table_new(search_hash_func, search_hash_key_compare);
	if (!sch->dups)
		g_error("new_search: unable to allocate hash table.\n");

    if (!searches) {
        GtkWidget * w = gtk_notebook_get_nth_page( 
            GTK_NOTEBOOK(notebook_search_results), 0);
    
		gtk_notebook_set_tab_label_text(
            GTK_NOTEBOOK(notebook_search_results),
            w, "(no search)");
    }

	gtk_signal_connect(GTK_OBJECT(sch->list_item), "select",
					   GTK_SIGNAL_FUNC(on_search_selected),
					   (gpointer) sch);

	search_gui_view_search(sch);

	gtk_widget_set_sensitive(combo_searches, TRUE);
	gtk_widget_set_sensitive(button_search_close, TRUE);

    gtk_entry_set_text(GTK_ENTRY(entry_search),"");

	searches = g_list_append(searches, (gpointer) sch);

	return sch;
}

/* Searches results */

gint search_compare(gint sort_col, record_t *r1, record_t *r2)
{
    struct results_set *rs1;
	struct results_set *rs2;
    gint result = 0;

    if (r1 == r2)
        result = 0;
    else if (r1 == NULL)
        result = -1;
    else if (r2 == NULL)
        result = +1;
    else {
        rs1 = r1->results_set;
        rs2 = r2->results_set;

        g_assert(rs1 != NULL);
        g_assert(rs2 != NULL);

        switch (sort_col) {
        case c_sr_filename:
            result = strcmp(r1->name, r2->name);
            break;
        case c_sr_size:
            result = (r1->size == r2->size) ? 0 :
                (r1->size > r2->size) ? +1 : -1;
            break;
        case c_sr_speed:
            result = (rs1->speed == rs2->speed) ? 0 :
                (rs1->speed > rs2->speed) ? +1 : -1;
            break;
        case c_sr_host:
            result = (rs1->ip == rs2->ip) ?  
                (gint) rs1->port - (gint) rs2->port :
                (rs1->ip > rs2->ip) ? +1 : -1;
            break;
        case c_sr_info:
			result = memcmp(rs1->vendor, rs2->vendor, sizeof(rs1->vendor));
			if (result)
				break;
            if (rs1->status == rs2->status)
                result = 0;
            else
                result = (rs1->status > rs2->status) ? +1 : -1;
            break;
        case c_sr_urn:
            if (r1->sha1 == r2->sha1)
                result = 0;
            else if (r1->sha1 == NULL)
                result = -1;
            else if (r2->sha1 == NULL)
                result = +1;
            else
                result =  memcmp(r1->sha1, r2->sha1, SHA1_RAW_SIZE);  
            break;
        default:
            g_assert_not_reached();
        }
    }

	return result;
}

/*
 * extract_vendor_name
 *
 * Extract vendor name from the results set's trailer, and return the name.
 * If we can't understand the name, return NULL.
 * Otherwise returns the name as a pointer to static data.
 *
 * As a side effect, set the ST_KNOWN_VENDOR in the status flags when the
 * vendor is known.
 */
static gchar *extract_vendor_name(struct results_set * rs)
{
	static gchar temp[5];
	gchar *vendor = NULL;
	guint32 t;
	gint i;

	if (rs->vendor[0] == '\0')
		return NULL;

	READ_GUINT32_BE(rs->vendor, t);
	rs->status |= ST_KNOWN_VENDOR;

	switch (t) {
	case T_BEAR: vendor = "Bear";			break;
	case T_CULT: vendor = "Cultiv8r";		break;
	case T_FIRE: vendor = "FireFly";		break;
	case T_FISH: vendor = "PEERahna";		break;
	case T_GNEW: vendor = "Gnewtellium";	break;
	case T_GNOT: vendor = "Gnotella";		break;
	case T_GNUC: vendor = "Gnucleus";		break;
	case T_GNUT: vendor = "Gnut";			break;
	case T_GTKG: vendor = "Gtk-Gnut";		break;
	case T_HSLG: vendor = "Hagelslag";		break;
	case T_LIME: vendor = "Lime";			break;
	case T_MACT: vendor = "Mactella";		break;
	case T_MNAP: vendor = "MyNapster";		break;
	case T_MMMM: vendor = "Morpheus-v2";	break;
	case T_MRPH: vendor = "Morpheus";		break;
	case T_MUTE: vendor = "Mutella";		break;
	case T_NAPS: vendor = "NapShare";		break;
	case T_OCFG: vendor = "OpenCola";		break;
	case T_OPRA: vendor = "Opera";			break;
	case T_PHEX: vendor = "Phex";			break;
	case T_QTEL: vendor = "Qtella";			break;
	case T_RAZA: vendor = "Shareaza";		break;
	case T_SNUT: vendor = "SwapNut";		break;
	case T_SWAP: vendor = "Swapper";		break;
	case T_SWFT: vendor = "Swift";			break;
	case T_TOAD: vendor = "ToadNode";		break;
	case T_XOLO: vendor = "Xolox";			break;
	case T_XTLA: vendor = "Xtella";			break;
	case T_ZIGA: vendor = "Ziga";			break;
	default:
		/* Unknown type, look whether we have all printable ASCII */
		rs->status &= ~ST_KNOWN_VENDOR;
		for (i = 0; i < sizeof(rs->vendor); i++) {
			guchar c = rs->vendor[i];
			if (isascii(c) && isprint(c))
				temp[i] = c;
			else {
				temp[0] = '\0';
				break;
			}
		}
		temp[4] = '\0';
		vendor = temp[0] ? temp : NULL;
		break;
	}

	return vendor;
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
static struct results_set *get_results_set(
	struct gnutella_node *n, gboolean validate_only)
{
	struct results_set *rs;
	struct record *rc = NULL;
	gchar *e, *s, *fname, *tag;
	guint32 nr, size, index, taglen;
	struct gnutella_search_results *r;
	GString *info = NULL;
	gint sha1_errors = 0;
	guchar *trailer = NULL;

	/* We shall try to detect malformed packets as best as we can */
	if (n->size < 27) {
		/* packet too small 11 header, 16 GUID min */
		g_warning("get_results_set(): given too small a packet (%d bytes)",
				  n->size);
		return NULL;
	}

	if (!validate_only)
		info = g_string_sized_new(80);

	rs = (struct results_set *) zalloc(rs_zone);

	rs->vendor[0] = '\0';
	rs->refcount = 0;
	rs->records = NULL;
	rs->guid = NULL;

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
		tag = NULL;

		while (s < e && *s)
			s++;				/* move s up to the next double NUL */

		if (s >= (e-1))			/* There cannot be two NULs: end of packet! */
			goto bad_packet;

		/*
		 * `s' point to the first NUL of the double NUL sequence.
		 *
		 * Between the two NULs at the end of each record, servents may put
		 * some extra information about the file (a tag), but this information
		 * may not contain any NUL.
		 */

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

			if (s >= e)
				goto bad_packet;

			s++;				/* Now points to next record */
		} else
			s += 2;				/* Skip double NUL */

		/*
		 * Okay, one more record
		 */

		nr++;

		if (!validate_only) {
			rc = (struct record *) zalloc(rc_zone);

			rc->refcount = 0;
			rc->sha1 = rc->tag = NULL;
			rc->index = index;
			rc->size = size;
			rc->name = atom_str_get(fname);
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

				switch (e->ext_token) {
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

		if (!validate_only) {
			rc->results_set = rs;
			rs->records = g_slist_prepend(rs->records, (gpointer) rc);
		}
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
		guint32 tlen = e - s;
		guchar *x = (guchar *) s;

		if (tlen >= 5 && x[4] + 5 <= tlen)
			trailer = s;

		if (trailer)
			memcpy(rs->vendor, trailer, sizeof(rs->vendor));

		// XXX parse trailer after the open data
	}

	if (nr != rs->num_recs)
		goto bad_packet;

	/* We now have the guid of the node */

	rs->guid = atom_guid_get(e);
	rs->stamp = time(NULL);

	/*
	 * Compute status bits, decompile trailer info, if present
	 */

	if (trailer) {
		gchar *vendor = extract_vendor_name(rs);
		guint32 t;

		READ_GUINT32_BE(trailer, t);

		switch (t) {
		case T_NAPS:
			/*
			 * NapShare has a one-byte only flag: no enabler, just setters.
			 *		--RAM, 17/12/2001
			 */
			if (trailer[4] == 1) {
				if (trailer[5] & 0x04) rs->status |= ST_BUSY;
				if (trailer[5] & 0x01) rs->status |= ST_FIREWALL;
				rs->status |= ST_PARSED_TRAILER;
			}
			break;
		case T_LIME:
		case T_SWAP:
		case T_RAZA:
			if (trailer[4] == 4)
				trailer[4] = 2;			/* We ignore XML data size */
				/* Fall through */
		default:
			if (trailer[4] == 2) {
				guint32 status =
					((guint32) trailer[5]) & ((guint32) trailer[6]);
				if (status & 0x04) rs->status |= ST_BUSY;
				if (status & 0x01) rs->status |= ST_FIREWALL;
				if (status & 0x08) rs->status |= ST_UPLOADED;
				rs->status |= ST_PARSED_TRAILER;
			} else if (rs->status  & ST_KNOWN_VENDOR) {
				if (dbg)
					g_warning("vendor %s changed # of open data bytes to %d",
							  vendor, trailer[4]);
			} else if (vendor) {
				if (dbg)
					g_warning("ignoring %d open data byte%s from "
						"unknown vendor %s",
						trailer[4], trailer[4] == 1 ? "" : "s", vendor);
			}
			break;
		}

		/*
		 * Now that we have the vendor, warn if the message has SHA1 errors.
		 */

		if (dbg && sha1_errors) {
			g_warning(
				"%s (%s) from %s (%s) had %d SHA1 error%s over %u record%s",
				 gmsg_infostr(&n->header), vendor ? vendor : "????",
				 node_ip(n), n->vendor ? n->vendor : "????",
				 sha1_errors, sha1_errors == 1 ? "" : "s",
				 nr, nr == 1 ? "" : "s");
			if (dbg > 1)
				dump_hex(stderr, "Query Hit Data (BAD)", n->data, n->size);
			goto bad_packet;		/* Will drop this bad query hit */
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
 * search_result_is_dup
 *
 * Check to see whether we already have a record for this file.
 * If we do, make sure that the index is still accurate,
 * otherwise inform the interested parties about the change.
 *
 * Returns true if the record is a duplicate.
 */
gboolean search_result_is_dup(search_t * sch, struct record * rc)
{
	struct record *old_rc;
	gpointer dummy;
	gboolean found;

	found = g_hash_table_lookup_extended(sch->dups, rc,
		(gpointer *) &old_rc, &dummy);

	if (!found)
		return FALSE;

	/*
	 * Actually, if the index is the only thing that changed,
	 * we want to overwrite the old one (and if we've
	 * got the download queue'd, replace it there too.
	 *		--RAM, 17/12/2001 from a patch by Vladimir Klebanov
	 *
	 * XXX needs more care: handle is_old, and use GUID for patching.
	 * XXX the client may change its GUID as well, and this must only
	 * XXX be used in the hash table where we record which downloads are
	 * XXX queued from whom.
	 * XXX when the GUID changes for a download in push mode, we have to
	 * XXX change it.  We have a new route anyway, since we just got a match!
	 */

	if (rc->index != old_rc->index) {
		if (dbg) g_warning(
			"Index changed from %u to %u at %s for %s",
			old_rc->index, rc->index, guid_hex_str(rc->results_set->guid),
			rc->name);
		download_index_changed(
			rc->results_set->ip,		/* This is for optimizing lookups */
			rc->results_set->port,
			rc->results_set->guid,		/* This is for formal identification */
			old_rc->index,
			rc->index);
		old_rc->index = rc->index;
	}

	return TRUE;		/* yes, it's a duplicate */
}

static void search_gui_add_record
    (search_t *sch, record_t *rc, GString *vinfo, GdkColor *fg, GdkColor *bg)
{
  	GString *info = g_string_sized_new(80);
  	gchar *titles[6];
	guint32 row;
    struct results_set *rs = rc->results_set;

	titles[c_sr_filename] = rc->name;
	titles[c_sr_size] = short_size(rc->size);
	g_snprintf(stmp_2, sizeof(stmp_2), "%u", rs->speed);
	titles[c_sr_speed] = stmp_2;
	titles[c_sr_host] = ip_port_to_gchar(rs->ip, rs->port);
    titles[c_sr_urn] = (rc->sha1 != NULL) ? sha1_base32(rc->sha1) : "";

	if (rc->tag) {
		guint len = strlen(rc->tag);

		/*
		 * We want to limit the length of the tag shown, but we don't
		 * want to loose that information.	I imagine to have a popup
		 * "show file info" one day that will give out all the
		 * information.
		 *				--RAM, 09/09/2001
		 */

		if (len > MAX_TAG_SHOWN) {
            gchar saved = rc->tag[MAX_TAG_SHOWN];
			rc->tag[MAX_TAG_SHOWN] = '\0';
			g_string_append(info, rc->tag);
			rc->tag[MAX_TAG_SHOWN] = saved;
		} else
			g_string_append(info, rc->tag);
	}
	if (vinfo->len) {
		if (info->len)
			g_string_append(info, "; ");
		g_string_append(info, vinfo->str);
	}
	titles[c_sr_info] = info->str;

    if (!sch->sort) {
		row = gtk_clist_append(GTK_CLIST(sch->clist), titles);
	} else {
		/*
		 * gtk_clist_set_auto_sort() can't work for row data based sorts!
		 * Too bad. The problem is, that our compare callback wants to
         * extract the record from the row data. But since we have not
         * yet added neither the row nor the row data, this does not
         * work.
		 * So we need to find the place to put the result by ourselves.
		 */

        GList *work;
		row = 0;

        switch (sch->sort_order) {
        case SORT_ASC:
            for (
                work = GTK_CLIST(sch->clist)->row_list;
                work != NULL;
                work = work->next )
            {
                record_t *rec = (record_t *)GTK_CLIST_ROW(work)->data;

                if (search_compare(sch->sort_col, rc, rec) < 0)
                    break;
				row++;
			}
            break;
        case SORT_DESC:
            for (
                work = GTK_CLIST(sch->clist)->row_list;
                work != NULL;
                work = work->next )
            {
                record_t *rec = (record_t *)GTK_CLIST_ROW(work)->data;
    
                if (search_compare(sch->sort_col, rc, rec) > 0)
                    break;
				row++;
			}
        }
		gtk_clist_insert(GTK_CLIST(sch->clist), row, titles);
    }

    if (fg != NULL)
        gtk_clist_set_foreground(GTK_CLIST(sch->clist), row, fg);

    if (bg != NULL)
        gtk_clist_set_background(GTK_CLIST(sch->clist), row, bg);

    gtk_clist_set_row_data(GTK_CLIST(sch->clist), row, (gpointer) rc);
	g_string_free(info, TRUE);
}

void search_matched(search_t *sch, struct results_set *rs)
{
	guint32 old_items = sch->items;
   	gboolean need_push;			/* Would need a push to get this file? */
	gboolean skip_records;		/* Shall we skip those records? */
	GString *vinfo = g_string_sized_new(40);
	gchar *vendor;
    GdkColor *mark_color;
    GdkColor *download_color;
    extern gboolean is_firewalled;
    GSList *l;
    gboolean list_frozen = FALSE;
	gint i;

    g_assert(sch != NULL);
    g_assert(rs != NULL);

    mark_color = &(gtk_widget_get_style(GTK_WIDGET(sch->clist))
        ->bg[GTK_STATE_INSENSITIVE]);

    download_color =  &(gtk_widget_get_style(GTK_WIDGET(sch->clist))
        ->fg[GTK_STATE_ACTIVE]);

    vendor = extract_vendor_name(rs);

   	if (vendor)
		g_string_append(vinfo, vendor);

	for (i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); i++) {
		if (rs->status & open_flags[i].flag) {
			if (vinfo->len)
				g_string_append(vinfo, ", ");
			g_string_append(vinfo, open_flags[i].status);
		}
	}

	if (vendor && !(rs->status & ST_PARSED_TRAILER)) {
		if (vinfo->len)
			g_string_append(vinfo, ", ");
		g_string_append(vinfo, "<unparsed>");
	}

	/*
	 * If we're firewalled, or they don't want to send pushes, then don't
	 * bother displaying results if they need a push request to succeed.
	 *		--RAM, 10/03/2002
	 */
	need_push = (rs->status & ST_FIREWALL) ||
		!check_valid_host(rs->ip, rs->port);
	skip_records = (!send_pushes || is_firewalled) && need_push;

	if (dbg > 6)
		printf("search_matched: [%s] got hit with %d record%s (from %s) "
			"need_push=%d, skipping=%d\n",
			sch->query, rs->num_recs, rs->num_recs == 1 ? "" : "s",
			ip_port_to_gchar(rs->ip, rs->port), need_push, skip_records);

  	for (l = rs->records; l && !skip_records; l = l->next) {
		struct record *rc = (struct record *) l->data;
        filter_result_t *flt_result;
        gboolean mark;
        gboolean downloaded = FALSE;

        if (dbg > 7)
            printf("search_matched: [%s] considering %s (%s)\n",
				sch->query, rc->name, vinfo->str);

        /*
	     * If the size is zero bytes,
		 * or we don't send pushes and it's a private IP,
		 * or if this is a duplicate search result,
		 *
		 * Note that we pass ALL records through search_result_is_dup(), to
		 * be able to update the index/GUID of our records correctly, when
		 * we detect a change.
		 */

       	if (
			search_result_is_dup(sch, rc)    ||
			skip_records                     ||
			rc->size == 0
		)
			continue;
        
        flt_result = filter_record(sch, rc);

        /*
         * Now we check for the different filter result properties.
         */

        /*
         * Check for FILTER_PROP_DOWNLOAD:
         */
        if (flt_result->props[FILTER_PROP_DOWNLOAD].state ==
            FILTER_PROP_STATE_DO) {
            download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
                rs->guid, rc->sha1, rs->stamp, need_push);
            downloaded = TRUE;
        }
    
        /*
         * We start with FILTER_PROP_DISPLAY:
         */
        if (!((flt_result->props[FILTER_PROP_DISPLAY].state == 
                FILTER_PROP_STATE_DONT) &&
            (flt_result->props[FILTER_PROP_DISPLAY].user_data == 0)) &&
            (sch->items < search_max_results))
        {
            sch->items++;
            g_hash_table_insert(sch->dups, rc, (void *) 1);
            rc->refcount++;

            mark = (flt_result->props[FILTER_PROP_DISPLAY].state == 
                    FILTER_PROP_STATE_DONT) &&
                (flt_result->props[FILTER_PROP_DISPLAY].user_data == 
                    (gpointer) 1);
            
            if (!list_frozen) {
                list_frozen = TRUE;
                gtk_clist_freeze(GTK_CLIST(sch->clist));
            }

            search_gui_add_record(sch, rc, vinfo, 
                downloaded ? download_color :  NULL,
                mark ? mark_color : NULL);
        }

        filter_free_result(flt_result);
    }

    if (list_frozen)
        gtk_clist_thaw(GTK_CLIST(sch->clist));

	/* Adds the set to the list */
	sch->r_sets = g_slist_prepend(sch->r_sets, (gpointer) rs);
	rs->refcount++;

	if (old_items == 0 && sch == current_search && sch->items > 0) {
        GtkWidget *button_search_clear =
            lookup_widget(main_window, "button_search_clear");
        GtkWidget *popup_search_clear_results = 
            lookup_widget(popup_search, "popup_search_clear_results");

		gtk_widget_set_sensitive(button_search_clear, TRUE);
		gtk_widget_set_sensitive(popup_search_clear_results, TRUE);
	}

	if (sch == current_search) {
		gui_search_update_items(sch);
	} else {
		sch->unseen_items += sch->items - old_items;
	}

	if (time(NULL) - sch->last_update_time < tab_update_time)
		gui_search_update_tab_label(sch);

	if (sch->reissue_timeout_id) {
		update_one_reissue_timeout(sch);
	}

  	g_string_free(vinfo, TRUE);
}

gboolean search_has_muid(search_t *sch, guchar * muid)
{
	GSList *m;

	for (m = sch->muids; m; m = m->next)
		if (!memcmp(muid, (guchar *) m->data, 16))
			return TRUE;
	return FALSE;
}

/*
 * update_neighbour_info
 *
 * Called when we get a query hit from an immediate neighbour.
 */
static void update_neighbour_info(
	struct gnutella_node *n, struct results_set *rs)
{
	gchar *vendor = extract_vendor_name(rs);
	extern gint guid_eq(gconstpointer a, gconstpointer b);
	gint old_weird = n->n_weird;

	g_assert(n->header.hops == 1);

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

/*
 * search_results
 *
 * This routine is called for each Query Hit packet we receive.
 * Returns whether the message should be dropped, i.e. FALSE if OK.
 */
gboolean search_results(struct gnutella_node *n)
{
	struct results_set *rs;
	GList *selected_searches = NULL;
	GList *l;
	gboolean drop_it = FALSE;

	/*
	 * Look for all the searches, and put the ones we need to possibly
	 * dispatch the results to into the selected_searches list.
	 */

	for (l = searches; l; l = l->next) {
		search_t *sch = (search_t *) l->data;

		/*
		 * Candidates are all non-frozen passive searches, and searches
		 * for which we sent a query bearing the message ID of the reply.
		 */

		if (
			(sch->passive && !sch->frozen) ||
			search_has_muid(sch, n->header.muid)
		)
			selected_searches = g_list_append(selected_searches, sch);
	}

	/*
	 * Parse the packet.
	 *
	 * If we're not going to dispatch it to any search, the packet is only
	 * parsed for validation.
	 */

	rs = get_results_set(n, selected_searches == NULL);
	if (rs == NULL) {
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
	 * Dispatch the results to the selected searches.
	 */

	for (l = selected_searches; l; l = l->next) {
		search_t *sch = (search_t *) l->data;
		search_matched(sch, rs);
	}

	g_assert(selected_searches == NULL || rs->refcount > 0);

	/*
	 * Some of the records might have not been used by searches, and need
	 * to be freed.  If no more records remain, we request that the
	 * result set be removed from all the dispatched searches, the last one
	 * removing it will cause its destruction.
	 */

	if (selected_searches == NULL)
		search_free_r_set(rs);			/* Not dispatched to any search */
	else
		search_clean_r_set(rs);

	if (rs->num_recs == 0) {
		for (l = selected_searches; l; l = l->next) {
			search_t *sch = (search_t *) l->data;
			search_remove_r_set(sch, rs);
		}
	}
		
final_cleanup:
	g_list_free(selected_searches);

	if (drop_it && n->header.hops == 1)
		n->n_weird++;

	return drop_it;
}

/*
 * search_extract_host
 *
 * Extract IP/port information out of the Query Hit into `ip' and `port'.
 */
void search_extract_host(struct gnutella_node *n, guint32 *ip, guint16 *port)
{
	guint32 hip;
	guint16 hport;
	struct gnutella_search_results *r =
		(struct gnutella_search_results *) n->data;

	/* Read Query Hit info */

	READ_GUINT32_BE(r->host_ip, hip);		/* IP address */
	READ_GUINT16_LE(r->host_port, hport);	/* Port */

	*ip = hip;
	*port = hport;
}

#ifndef USE_SEARCH_XML
/*
 * search_store_old
 *
 * Store pending non-passive searches.
 */
static void search_store_old(void)
{
	GList *l;
	FILE *out;
	time_t now = time((time_t *) NULL);

	g_snprintf(stmp_2, sizeof(stmp_2), "%s/%s", config_dir, search_file);
	out = fopen(stmp_2, "w");

	if (!out) {
		g_warning("Unable to create %s to persist serach: %s",
			stmp_2, g_strerror(errno));
		return;
	}

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n", out);
	fprintf(out, "#\n# Searches saved on %s#\n\n", ctime(&now));

	for (l = searches; l; l = l->next) {
		struct search *sch = (struct search *) l->data;
		if (!sch->passive)
			fprintf(out, "%s\n", sch->query);
	}

	if (0 != fclose(out))
		g_warning("Could not flush %s: %s", stmp_2, g_strerror(errno));
}
#endif /* USE_SEARCH_XML */

/*
 * search_retrieve_old
 *
 * Retrieve search list and restart searches.
 * The searches are normally retrieved from ~/.gtk-gnutella/searches.
 */
static gboolean search_retrieve_old(void)
{
	FILE *in;
	struct stat buf;
	gint line;				/* File line number */

	g_snprintf(stmp_2, sizeof(stmp_2), "%s/%s", config_dir, search_file);
	if (-1 == stat(stmp_2, &buf))
		return FALSE;

	in = fopen(stmp_2, "r");

	if (!in) {
		g_warning("Unable to open %s to retrieve searches: %s",
			stmp_2, g_strerror(errno));
		return FALSE;
	}

	/*
	 * Retrieval of each searches.
	 */

	line = 0;

	while (fgets(stmp_2, sizeof(stmp_2) - 1, in)) {	/* Room for trailing NUL */
		line++;

		if (stmp_2[0] == '#')
			continue;				/* Skip comments */

		if (stmp_2[0] == '\n')
			continue;				/* Allow arbitrary blank lines */

		(void) str_chomp(stmp_2, 0);	/* The search string */

		search_new(stmp_2, minimum_speed);
		stmp_2[0] = 0;
	}

	fclose(in);

    return TRUE;
}

/*
 * search_store
 *
 * Persist searches to disk.
 */
void search_store(void)
{
#ifdef USE_SEARCH_XML
	search_store_xml();
    
  	g_snprintf(stmp_2, sizeof(stmp_2), "%s/%s", config_dir, search_file);
    if (file_exists(stmp_2)) {
        gchar filename[1024];

      	g_snprintf(filename, sizeof(filename), "%s.old", stmp_2);

        g_warning(
            "Found old searches file. The search information has been\n"
            "stored in the new XML format and the old file is renamed to\n"
            "%s", filename);
        if (-1 == rename(stmp_2, filename))
          	g_warning("could not rename %s as %s: %s\n"
                "The XML file will not be used unless this problem is resolved",
                stmp_2, filename, g_strerror(errno));
    }
#else
    search_store_old();
#endif
}

void search_shutdown(void)
{
	search_store();

    while (searches != NULL)
        search_close((search_t *)searches->data);

	zdestroy(rs_zone);
	zdestroy(rc_zone);
	rs_zone = rc_zone = NULL;
}

/* ----------------------------------------- */


static void download_selection_of_clist(GtkCList * c)
{
	struct results_set *rs;
	struct record *rc;
	gboolean need_push;
	GList *l;
    gint row;

    gtk_clist_freeze(c);

	for (l = c->selection; l; 
         l = c->selection) {

        /* make it visibile that we already selected this for download */
		gtk_clist_set_foreground
            (c, (gint) l->data, 
			 &gtk_widget_get_style(GTK_WIDGET(c))->fg[GTK_STATE_ACTIVE]);

		rc = (struct record *) gtk_clist_get_row_data(c, (gint) l->data);
        
        if (!rc) {
			g_warning("download_selection_of_clist(): row %d has NULL data\n",
			          (gint) l->data);
		    continue;
        }

		rs = rc->results_set;
		need_push =
			(rs->status & ST_FIREWALL) || !check_valid_host(rs->ip, rs->port);
		download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					 rs->guid, rc->sha1, rs->stamp, need_push);

        /*
         * I'm not totally sure why we have to determine the row again,
         * but without this, it does not seem to work.
         *     --BLUE, 01/05/2002
         */
        row = gtk_clist_find_row_from_data(c, rc);

        if (search_remove_downloaded) {
            gtk_clist_remove(c, row);
            current_search->items--;

			/*
			 * Remove one reference to this record.
			 */

			g_hash_table_remove(current_search->dups, rc);
			search_unref_record(rc);

        } else
            gtk_clist_unselect_row(c, row, 0);
	}
    
    gtk_clist_thaw(c);

    gui_search_force_update_tab_label(current_search);
    gui_search_update_items(current_search);
}



void search_download_files(void)
{
    GtkWidget *notebook_main;
    GtkWidget *ctree_menu;

    notebook_main = lookup_widget(main_window, "notebook_main");
    ctree_menu = lookup_widget(main_window, "ctree_menu");

	/* Download the selected files */

	if (jump_to_downloads) {
		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main),
            nb_main_page_downloads);
        // FIXME: should convert to ctree here. Expand nodes if necessary.
		gtk_clist_select_row(GTK_CLIST(ctree_menu),
            nb_main_page_downloads, 0);
	}

	if (current_search) {
		download_selection_of_clist(GTK_CLIST(current_search->clist));
		gtk_clist_unselect_all(GTK_CLIST(current_search->clist));
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}
}


/*
 * search_get_info:
 *
 * Fetches information about a given search. The returned information must
 * be freed manually by the caller using the search_free_info call.
 *
 * O(1):
 * Since the gnet_search_t is actually a pointer to the search
 * struct, this call is O(1). It would be safer to have gnet_search_t be
 * an index in a list or a number, but depending on the underlying
 * containerstructure of sl_nodes, that would have O(log(n)) (balanced tree)
 * or O(n) (list) runtime.
 */
gnet_search_info_t *search_get_info(const gnet_search_t s)
{
    search_t *search = find_search(s);
    gnet_search_info_t *info = g_new(gnet_search_info_t, 1);

    info->search_handle = s;
    info->query = g_strdup(search->query);
    info->speed = search->speed;
    info->time  = search->time;
    info->items = search->items;

    info->last_update_time  = search->last_update_time;
    info->last_update_items = search->last_update_items;
    
    info->passive = search->passive;
    info->frozen  = search->frozen;

    info->reissue_timeout = search->reissue_timeout;

    return info;
}



void search_free_info(gnet_search_info_t *info)
{
    g_assert(info != NULL);

    g_free(info->query);
    g_free(info);
}




/* vi: set ts=4: */
