/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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

#include "gui.h"

/* GUI includes  */
#include "search_gui.h"
#include "search_cb2.h"
#include "gtk-missing.h"
#include "gui_property.h"
#include "gui_property_priv.h"
#include "settings_gui.h"

#ifdef USE_SEARCH_XML
# include "search_xml.h"
# include <libxml/parser.h>
#endif


/* System includes */
#include <ctype.h>
#include <gtk/gtk.h>

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

static gchar tmpstr[4096];

GList *searches = NULL;		/* List of search structs */

/* Need to remove this dependency on GUI further --RAM */
extern GtkWidget *default_search_tree_view;
extern GtkWidget *default_scrolled_window;

static search_t *current_search  = NULL; /*	The search currently displayed */
search_t *search_selected = NULL;

static gchar *search_file = "searches";	/* File where searches are saved */

static zone_t *rs_zone;		/* Allocation of results_set */
static zone_t *rc_zone;		/* Allocation of record */

time_t tab_update_time = 5;

static GList *sl_search_history = NULL;


/*
 * Private function prototypes
 */
static search_t *find_search(gnet_search_t sh);
static record_t *create_record(results_set_t *rs, gnet_record_t *r);
static results_set_t *create_results_set(const gnet_results_set_t *r_set);
static GtkTreeViewColumn *add_column(
	GtkTreeView *treeview, gchar *name, gint id, gint width);
static void add_search_column(
	GtkTreeView *treeview, gchar *name, gint id, gint width);
#ifndef USE_SEARCH_XML
    static void search_store_old(void);
#endif /* USE_SEARCH_XML */

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

/*
 * If no search are currently allocated 
 */
GtkWidget *default_search_tree_view = NULL;
GtkWidget *default_scrolled_window = NULL;


/* ----------------------------------------- */

void search_gui_restart_search(search_t *sch)
{
	search_reissue(sch->search_handle);
	gtk_list_store_clear(GTK_LIST_STORE(
			gtk_tree_view_get_model(GTK_TREE_VIEW(sch->tree_view))));
	sch->items = sch->unseen_items = 0;
	gui_search_update_items(sch);
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
static void search_free_record(record_t *rc)
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
 * search_clean_r_set
 *
 * This routine must be called when the results_set has been dispatched to
 * all the opened searches.
 *
 * All the records that have not been used by a search are removed.
 */
static void search_clean_r_set(results_set_t *rs)
{
	GSList *m;
    GSList *sl_remove = NULL;

	g_assert(rs->refcount);		/* If not dispatched, should be freed */

    /*
     * Collect empty searches.
     */
    for (m = rs->records; m != NULL; m = m->next) {
		record_t *rc = (record_t *) m->data;

		if (rc->refcount == 0)
			sl_remove = g_slist_prepend(sl_remove, (gpointer) rc);
    }

    /*
     * Remove empty searches from record set.
     */
	for (m = sl_remove; m != NULL; m = g_slist_next(m)) {
		record_t *rc = (record_t *) m->data;

		search_free_record(rc);
		rs->records = g_slist_remove(rs->records, rc);
		rs->num_recs--;
	}

    g_slist_free(sl_remove);
}

/*
 * search_free_r_set
 *
 * Free one results_set.
 *
 * Those records may be shared between several searches.  So while the refcount
 * is positive, we just decrement it and return without doing anything.
 */
static void search_free_r_set(results_set_t *rs)
{
	GSList *m;

    g_assert(rs != NULL);

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

	for (m = rs->records; m != NULL; m = m->next)
		search_free_record((record_t *) m->data);

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
static void search_dispose_results(results_set_t *rs)
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
    
        // FIXME: I have the strong impression that there is a memory leak
        //        here. We find the link and unlink it from r_sets, but
        //        then it does become a self-contained list and it is not
        //        freed anywhere, does it?
	}

	g_assert(rs->refcount == refs);		/* Found all the searches */

	rs->refcount = 1;
	search_free_r_set(rs);
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

/* Free all the results_set's of a search */

static void search_free_r_sets(search_t *sch)
{
	GSList *l;

	g_assert(sch != NULL);
	g_assert(sch->dups != NULL);
	g_assert(g_hash_table_size(sch->dups) == 0); /* All records were cleaned */

	for (l = sch->r_sets; l; l = l->next)
		search_free_r_set((results_set_t *) l->data);

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
void search_gui_clear_search(search_t *sch)
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
 * search_gui_close_search:
 *
 * Remove the search from the list of searches and free all 
 * associated ressources (including filter and gui stuff).
 */
void search_gui_close_search(search_t *sch)
{
    g_assert(sch != NULL);

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
	search_gui_clear_search(sch);
	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;

    search_close(sch->search_handle);
	atom_str_free(sch->query);

	G_FREE_NULL(sch);
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

/*
 * search_remove_r_set
 *
 * Remove reference to results in our search.
 * Last one to remove it will trigger a free.
 */
static void search_remove_r_set(search_t *sch, results_set_t *rs)
{
	sch->r_sets = g_slist_remove(sch->r_sets, rs);
	search_free_r_set(rs);
}

/*
 * search_gui_new_search:
 * 
 * Create a new search and start it. Use default reissue timeout.
 */
gboolean search_gui_new_search(
	const gchar *query, flag_t flags, search_t **search)
{
    guint32 search_reissue_timeout;
    guint32 minimum_speed;
    
    gnet_prop_get_guint32(
        PROP_SEARCH_REISSUE_TIMEOUT,
        &search_reissue_timeout, 0, 1);

    gui_prop_get_guint32(
        PROP_DEFAULT_MINIMUM_SPEED,
        &minimum_speed, 0, 1);

	return search_gui_new_search_full(
        query, minimum_speed, search_reissue_timeout, flags, search);
}

/* 
 * search_new_full:
 *
 * Create a new search and start it.
 * Returns TRUE if search was sucessfully created and FALSE if an error
 * happened. If the "search" argument is not NULL a pointer to the new
 * search is stored there.
 */
gboolean search_gui_new_search_full(
	const gchar *querystr, guint16 speed, guint32 reissue_timeout, flag_t flags,
    search_t **search)
{
	search_t *sch;
	GList *glist;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar query[512];
	gchar *name;

    GtkWidget *combo_searches = lookup_widget(main_window, "combo_searches");
    GtkWidget *tree_view_search = lookup_widget(main_window, "tree_view_search");
    GtkWidget *notebook_search_results = 
        lookup_widget(main_window, "notebook_search_results");
    GtkWidget *button_search_close = 
        lookup_widget(main_window, "button_search_close");
    GtkWidget *entry_search = lookup_widget(main_window, "entry_search");


	g_snprintf(query, sizeof(query), "%s", querystr);

	/*
	 * If the text is a magnet link we extract the SHA1 urn
	 * and put it back into the search field string so that the
	 * code for urn searches below can handle it.
	 *		--DBelius   11/11/2002
	 */

	if (0 == strncasecmp(query, "magnet:", 7)) {
		guchar raw[SHA1_RAW_SIZE];

		if (huge_extract_sha1(query, raw)) {
			g_snprintf(query, sizeof(query), "urn:sha1:%s", sha1_base32(raw));
		} else {
			return FALSE;		/* Entry refused */
		}
	}

	/*
	 * If string begins with "urn:sha1:", then it's an URN search.
	 * Validate the base32 representation, and if not valid, beep
	 * and refuse the entry.
	 *		--RAM, 28/06/2002
	 */

	if (0 == strncasecmp(query, "urn:sha1:", 9)) {
		guchar raw[SHA1_RAW_SIZE];
		gchar *b = query + 9;

		if (strlen(b) < SHA1_BASE32_SIZE)
			goto refused;

		if (base32_decode_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw)))
			goto validated;

		/*
		 * If they gave us an old base32 representation, convert it to
		 * the new one on the fly.
		 */
		if (base32_decode_old_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw))) {
			guchar b32[SHA1_BASE32_SIZE];
			base32_encode_into(raw, sizeof(raw), b32, sizeof(b32));
			memcpy(b, b32, SHA1_BASE32_SIZE);
			goto validated;
		}

		/*
		 * Entry refused.
		 */
	refused:
		return FALSE;

	validated:
		b[SHA1_BASE32_SIZE] = '\0';		/* Truncate to end of URN */

		/* FALL THROUGH */
	}

	sch = g_new0(search_t, 1);

	sch->query = atom_str_get(query);
    sch->search_handle = search_new(query, speed, reissue_timeout, flags);
    sch->passive = flags & SEARCH_PASSIVE;
	sch->dups =
		g_hash_table_new(search_hash_func, search_hash_key_compare);
	if (!sch->dups)
		g_error("new_search: unable to allocate hash table.\n");
    
  	filter_new_for_search(sch);

	/* Create the list item */

	sch->list_item = gtk_list_item_new_with_label(sch->query);

	gtk_widget_show(sch->list_item);

	glist = g_list_prepend(NULL, (gpointer) sch->list_item);

	gtk_list_prepend_items(GTK_LIST(GTK_COMBO(combo_searches)->list),
						   glist);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view_search));
	name = g_locale_to_utf8(sch->query, -1, NULL, NULL, NULL);
	gtk_list_store_append (GTK_LIST_STORE (model), &iter);
	gtk_list_store_set (GTK_LIST_STORE (model), &iter,
		c_sl_name, name,
		c_sl_hit, GINT_TO_POINTER(0),
		c_sl_new, GINT_TO_POINTER(0), 
		c_sl_sch, sch,
		-1);

	G_FREE_NULL(name);

	/* Create a new CList if needed, or use the default CList */

	if (searches) {
		/* We have to create a new clist for this search */
		gui_search_create_tree_view(&sch->scrolled_window, &sch->tree_view);

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);

		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
								 sch->scrolled_window, NULL);
	} else {
		/* There are no searches currently, we can use the default clist */

		if (default_scrolled_window && default_search_tree_view) {
			sch->scrolled_window = default_scrolled_window;
			sch->tree_view = default_search_tree_view;

			default_search_tree_view = default_scrolled_window = NULL;
		} else
			g_warning
				("new_search(): No current search but no default tree_view !?\n");

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);
	}

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(tab_update_time * 1000,
        (GtkFunction)gui_search_update_tab_label, sch);

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

	search_gui_set_current_search(sch);

	gtk_widget_set_sensitive(combo_searches, TRUE);
	gtk_widget_set_sensitive(button_search_close, TRUE);

    gtk_entry_set_text(GTK_ENTRY(entry_search),"");

	searches = g_list_append(searches, (gpointer) sch);

    search_start(sch->search_handle);

	if (search)
		*search = sch;
	return TRUE;
}

/* Searches results */

gint search_gui_compare_records(gint sort_col, record_t *r1, record_t *r2)
{
    results_set_t *rs1;
	results_set_t *rs2;
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
		if (gui_debug) g_warning(
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

static void search_gui_add_record(
	search_t *sch, record_t *rc, GString *vinfo, GdkColor *fg, GdkColor *bg)
{
  	GString *info = g_string_sized_new(80);
  	gchar *titles[c_sr_num];
    struct results_set *rs = rc->results_set;
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW (sch->tree_view);
	GtkTreeModel *model = gtk_tree_view_get_model (tree_view);
	GError	*error = NULL;

	titles[c_sr_filename] = 
		g_locale_to_utf8(rc->name, -1, NULL, NULL, &error);
	if (NULL != error) {
		g_warning("g_locale_to_utf8 failed in %s: %s", __FUNCTION__,
			error->message);
		g_clear_error(&error);
		titles[c_sr_filename] = g_strdup("<Filename cannot be viewed>");
	}
	titles[c_sr_size] = short_size(rc->size);
	titles[c_sr_speed] = GUINT_TO_POINTER((guint)rs->speed);
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

	gtk_list_store_append(GTK_LIST_STORE (model), &iter);
	gtk_list_store_set(GTK_LIST_STORE (model), &iter,
		      c_sr_filename, titles[c_sr_filename],
		      c_sr_size, titles[c_sr_size],
		      c_sr_speed, titles[c_sr_speed],
		      c_sr_host, titles[c_sr_host],
		      c_sr_urn, titles[c_sr_urn],
		      c_sr_info, titles[c_sr_info],
		      c_sr_record, rc,
		      -1);

	G_FREE_NULL(titles[c_sr_filename]);


/*    if (!sch->sort) {
		row = gtk_clist_append(GTK_CLIST(sch->clist), titles);
	} else {*/
		/*
		 * gtk_clist_set_auto_sort() can't work for row data based sorts!
		 * Too bad. The problem is, that our compare callback wants to
         * extract the record from the row data. But since we have not
         * yet added neither the row nor the row data, this does not
         * work.
		 * So we need to find the place to put the result by ourselves.
		 */
/*
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

                if (search_gui_compare_records(sch->sort_col, rc, rec) < 0)
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
    
                if (search_gui_compare_records(sch->sort_col, rc, rec) > 0)
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

    gtk_clist_set_row_data(GTK_CLIST(sch->clist), row, (gpointer) rc);*/
	g_string_free(info, TRUE);
}

void search_matched(search_t *sch, results_set_t *rs)
{
	guint32 old_items = sch->items;
   	gboolean need_push;			/* Would need a push to get this file? */
	gboolean skip_records;		/* Shall we skip those records? */
	GString *vinfo = g_string_sized_new(40);
	gchar *vendor;
    GdkColor *download_color;
    GdkColor *ignore_color;
    GdkColor *mark_color;
    GSList *l;
    gboolean send_pushes;
    gboolean is_firewalled;
	gint i;

    g_assert(sch != NULL);
    g_assert(rs != NULL);

    mark_color = &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->bg[GTK_STATE_INSENSITIVE]);

    ignore_color = &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->fg[GTK_STATE_INSENSITIVE]);

    download_color =  &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->fg[GTK_STATE_ACTIVE]);

    vendor = lookup_vendor_name(rs->vendor);

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
    gnet_prop_get_boolean(PROP_SEND_PUSHES, &send_pushes, 0, 1);
    gnet_prop_get_boolean(PROP_IS_FIREWALLED, &is_firewalled, 0, 1);

	need_push = (rs->status & ST_FIREWALL) ||
		!host_is_valid(rs->ip, rs->port);
	skip_records = (!send_pushes || is_firewalled) && need_push;

	if (gui_debug > 6)
		printf("search_matched: [%s] got hit with %d record%s (from %s) "
			"need_push=%d, skipping=%d\n",
			sch->query, rs->num_recs, rs->num_recs == 1 ? "" : "s",
			ip_port_to_gchar(rs->ip, rs->port), need_push, skip_records);

  	for (l = rs->records; l && !skip_records; l = l->next) {
		record_t *rc = (record_t *) l->data;
        filter_result_t *flt_result;
        gboolean downloaded = FALSE;

        if (gui_debug > 7)
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
         * Check wether this record was already scheduled for
         * download by the backend.
         */
        downloaded = rc->flags & SR_DOWNLOADED;
        
        /*
         * Now we check for the different filter result properties.
         */

        /*
         * Check for FILTER_PROP_DOWNLOAD:
         */
        if (!downloaded &&
            (flt_result->props[FILTER_PROP_DOWNLOAD].state ==
            FILTER_PROP_STATE_DO)) {
            download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
                rs->guid, rc->sha1, rs->stamp, need_push, NULL);
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
            GdkColor *fg_color = NULL;
            gboolean mark;
            sch->items++;
            g_hash_table_insert(sch->dups, rc, (void *) 1);
            rc->refcount++;

            mark = 
                (flt_result->props[FILTER_PROP_DISPLAY].state == 
                    FILTER_PROP_STATE_DONT) &&
                (flt_result->props[FILTER_PROP_DISPLAY].user_data == 
                    (gpointer) 1);

            if (rc->flags & SR_IGNORED) {
                /*
                 * Check wether this record will be ignored by the backend.
                 */
                fg_color = ignore_color;
            } else if (downloaded) {
                fg_color = download_color;
            } else {
                fg_color = NULL;
            }

            search_gui_add_record(sch, rc, vinfo, 
                fg_color,
                mark ? mark_color : NULL);
        }

        filter_free_result(flt_result);
    }

    /*
     * A result set may not be added more then once to a search!
     */
    // FIXME: expensive assert
    g_assert(g_slist_find(sch->r_sets, rs) == NULL);

	/* Adds the set to the list */
	sch->r_sets = g_slist_prepend(sch->r_sets, (gpointer) rs);
	rs->refcount++;

	if (old_items == 0 && sch == current_search && sch->items > 0) {
		GtkWidget *button_search_clear =
		 	lookup_widget(main_window, "button_search_clear");
		gtk_widget_set_sensitive(button_search_clear, TRUE);
	}

	/*
	 *	FIXME:	unseen_items is not for current_search increased even if
	 *			we're not at the search pane.
	 */
		
	if (sch == current_search)
		gui_search_update_items(sch);
	else
		sch->unseen_items += sch->items - old_items;


	if (time(NULL) - sch->last_update_time < tab_update_time)
		gui_search_update_tab_label(sch);

  	g_string_free(vinfo, TRUE);
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

	g_snprintf(tmpstr, sizeof(tmpstr), "%s/%s", gui_config_dir, search_file);
	out = fopen(tmpstr, "w");

	if (!out) {
		g_warning("Unable to create %s to persist serach: %s",
			tmpstr, g_strerror(errno));
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
		g_warning("Could not flush %s: %s", tmpstr, g_strerror(errno));
}
#endif /* USE_SEARCH_XML */

/*
 * search_store
 *
 * Persist searches to disk.
 */
void search_gui_store_searches(void)
{
#ifdef USE_SEARCH_XML
	search_store_xml();
    
  	g_snprintf(tmpstr, sizeof(tmpstr), "%s/%s", gui_config_dir, search_file);
    if (file_exists(tmpstr)) {
        gchar filename[1024];

      	g_snprintf(filename, sizeof(filename), "%s.old", tmpstr);

        g_warning(
            "Found old searches file. The search information has been\n"
            "stored in the new XML format and the old file is renamed to\n"
            "%s", filename);
        if (-1 == rename(tmpstr, filename))
          	g_warning("could not rename %s as %s: %s\n"
                "The XML file will not be used unless this problem is resolved",
                tmpstr, filename, g_strerror(errno));
    }
#else
    search_store_old();
#endif
}

/* ----------------------------------------- */



static void download_selected_file(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	struct results_set *rs;
	struct record *rc;
	gboolean need_push;

	gtk_tree_model_get(model, iter, c_sr_record, &rc, -1);

	rs = rc->results_set;
	need_push =
		(rs->status & ST_FIREWALL) || !host_is_valid(rs->ip, rs->port);
	download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
		rs->guid, rc->sha1, rs->stamp, need_push, NULL);

	if (data != NULL) {
		GSList	**iter_list = (GSList **)data;

		*iter_list = g_slist_append(*iter_list, gtk_tree_iter_copy(iter));
	}
}

static void remove_selected_file(
	gpointer data, gpointer user_data)
{
	GtkTreeModel *model = user_data;
	GtkTreeIter *iter = data;
	
	gtk_list_store_remove(GTK_LIST_STORE(model), iter);
	current_search->items--;
	gtk_tree_iter_free(iter);
}

static void download_selection_of_tree_view(GtkTreeView * tree_view)
{
    gboolean search_remove_downloaded;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GSList	*iter_list = NULL;

	selection = gtk_tree_view_get_selection(tree_view);
	model = gtk_tree_view_get_model(tree_view);

    gnet_prop_get_boolean(
        PROP_SEARCH_REMOVE_DOWNLOADED,
        &search_remove_downloaded, 0, 1);

	gtk_tree_selection_selected_foreach(
		selection, 
		download_selected_file, 
		!search_remove_downloaded ? &iter_list : NULL);

	if (!search_remove_downloaded) {
		g_slist_foreach(
			iter_list,
			remove_selected_file,
			model);

		g_slist_free(iter_list);
	}

//    gtk_clist_freeze(c);
/*
	for (l = c->selection; l; 
         l = c->selection) {
*/
        /* make it visibile that we already selected this for download */
/*		gtk_clist_set_foreground
            (t, (gint) l->data, 
			 &gtk_widget_get_style(GTK_WIDGET(c))->fg[GTK_STATE_ACTIVE]);

		rc = (struct record *) gtk_clist_get_row_data(c, (gint) l->data);
        
        if (!rc) {
			g_warning("download_selection_of_clist(): row %d has NULL data\n",
			          (gint) l->data);
		    continue;
        }

		rs = rc->results_set;
		need_push =
			(rs->status & ST_FIREWALL) || !host_is_valid(rs->ip, rs->port);
		download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					 rs->guid, rc->sha1, rs->stamp, need_push, NULL);
*/
        /*
         * I'm not totally sure why we have to determine the row again,
         * but without this, it does not seem to work.
         *     --BLUE, 01/05/2002
         */
/*        row = gtk_clist_find_row_from_data(c, rc);

        if (search_remove_downloaded) {
            gtk_clist_remove(c, row);
            current_search->items--;
*/
			/*
			 * Remove one reference to this record.
			 */
/*
			g_hash_table_remove(current_search->dups, rc);
			search_unref_record(rc);

        } else
            gtk_clist_unselect_row(c, row, 0);
	}
*/    
 //   gtk_clist_thaw(c);

    gui_search_force_update_tab_label(current_search);
    gui_search_update_items(current_search);
}



void search_gui_download_files(void)
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
		download_selection_of_tree_view(
			GTK_TREE_VIEW(current_search->tree_view));
		gtk_tree_selection_unselect_all(
			GTK_TREE_SELECTION(gtk_tree_view_get_selection(
				GTK_TREE_VIEW(current_search->tree_view))));
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}
}



/***
 *** Callbacks
 ***/

void search_gui_got_results(GSList *schl, const gnet_results_set_t *r_set)
{
    GSList *l;
    results_set_t *rs;

    /*
     * Copy the data we got from the backend.
     */
    rs = create_results_set(r_set);

    if (gui_debug >= 12)
        printf("got incoming results...\n");

    for (l = schl; l != NULL; l = g_slist_next(l))
        search_matched(find_search((gnet_search_t)l->data), rs);

   	/*
	 * Some of the records might have not been used by searches, and need
	 * to be freed.  If no more records remain, we request that the
	 * result set be removed from all the dispatched searches, the last one
	 * removing it will cause its destruction.
	 */
    if (gui_debug >= 15)
        printf("cleaning phase\n");

    if (rs->refcount == 0) {
        search_free_r_set(rs);
        return;
    }

    search_clean_r_set(rs);

    if (gui_debug >= 15)
        printf("trash phase\n");
    /*
     * If the record set does not contain any records after the cleansing,
     * we have only an empty shell left which we can safely remove from 
     * all the searches.
     */
	if (rs->num_recs == 0) {
		for (l = schl; l; l = l->next) {
			search_t *sch = find_search((gnet_search_t) l->data);
			search_remove_r_set(sch, rs);
		}
	}

}

/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_widths_changed(property_t prop)
{
    guint32 *val;
    GtkTreeView *tree_view;

    if ((current_search == NULL) && (default_search_tree_view == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, NULL, 0, 0);

    tree_view = GTK_TREE_VIEW((current_search != NULL) ? 
        current_search->tree_view : default_search_tree_view);

/*    if (tree_view != NULL) {
        gint i;

        for (i = 0; i < tree_view->columns; i ++)
            gtk_clist_set_column_width(clist, i, val[i]);
    }
*/
    G_FREE_NULL(val);
    return FALSE;
}

/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_visible_changed(property_t prop)
{
    guint32 *val;
    GtkTreeView *tree_view;

    if ((current_search == NULL) && (default_search_tree_view == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_VISIBLE, NULL, 0, 0);

    tree_view = GTK_TREE_VIEW((current_search != NULL) ? 
        current_search->tree_view : default_search_tree_view);
/*
    if (tree_view != NULL) {
        gint i;
    
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility(clist, i, val[i]);
    }
*/
    G_FREE_NULL(val);
    return FALSE;
}




/***
 *** Private functions
 ***/

/*
 * find_search:
 *
 * Returns a pointer to gui_search_t from gui_searches which has
 * sh as search_handle. If none is found, return NULL.
 */
static search_t *find_search(gnet_search_t sh) 
{
    GList *l;
    
    for (l = searches; l != NULL; l = g_list_next(l)) {
        if (((search_t *)l->data)->search_handle == sh) {
            if (gui_debug >= 15)
                printf("search [%s] matched handle %x\n", (
                    (search_t *)l->data)->query, sh);

            return (search_t *)l->data;
        }
    }

    return NULL;
}


static record_t *create_record(results_set_t *rs, gnet_record_t *r) 
{
    record_t *rc;

    g_assert(r != NULL);
    g_assert(rs != NULL);

    rc = (record_t *) zalloc(rc_zone);

    rc->results_set = rs;
    rc->refcount = 0;

    rc->name = atom_str_get(r->name);
    rc->size = r->size;
    rc->index = r->index;
    rc->sha1 = (r->sha1 != NULL) ? atom_sha1_get(r->sha1) : NULL;
    rc->tag = (r->tag != NULL) ? atom_str_get(r->tag) : NULL;
    rc->flags = r->flags;

    return rc;
}

static results_set_t *create_results_set(const gnet_results_set_t *r_set)
{
    results_set_t *rs;
    GSList *sl;
    
    rs = (results_set_t *) zalloc(rs_zone);

    rs->refcount = 0;

    rs->guid = atom_guid_get(r_set->guid);
    rs->ip = r_set->ip;
    rs->port = r_set->port;
    rs->status = r_set->status;
    rs->speed = r_set->speed;
    rs->stamp = r_set->stamp;
    memcpy(rs->vendor, r_set->vendor, sizeof(rs->vendor));

    rs->num_recs = 0;
    rs->records = NULL;
    
    for (sl = r_set->records; sl != NULL; sl = g_slist_next(sl)) {
        record_t *rc = create_record(rs, (gnet_record_t *) sl->data);

        rs->records = g_slist_prepend(rs->records, rc);
        rs->num_recs ++;
    }

    g_assert(rs->num_recs == r_set->num_recs);

    return rs;
}

/*
 * search_retrieve_old
 *
 * Retrieve search list and restart searches.
 * The searches are normally retrieved from ~/.gtk-gnutella/searches.
 */
static gboolean search_retrieve_old(void)
{
	FILE *in;
	gint line;				/* File line number */

	g_snprintf(tmpstr, sizeof(tmpstr), "%s/%s", gui_config_dir, search_file);
	in = fopen(tmpstr, "r");

	if (!in) {
		if (ENOENT != errno)
			g_warning("Unable to open %s to retrieve searches: %s",
				tmpstr, g_strerror(errno));
		return FALSE;
	}

	/*
	 * Retrieval of each searches.
	 */

	line = 0;

	while (fgets(tmpstr, sizeof(tmpstr) - 1, in)) {	/* Room for trailing NUL */
		line++;

		if (tmpstr[0] == '#')
			continue;				/* Skip comments */

		if (tmpstr[0] == '\n')
			continue;				/* Allow arbitrary blank lines */

		(void) str_chomp(tmpstr, 0);	/* The search string */

		search_gui_new_search(tmpstr, 0, NULL);
		tmpstr[0] = 0;
	}

	fclose(in);

    return TRUE;
}


/***
 *** Public functions
 ***/

void search_gui_init(void)
{
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
        (lookup_widget(main_window, "combo_searches"));
    GtkTreeView *tree_view_search = GTK_TREE_VIEW
        (lookup_widget(main_window, "tree_view_search"));
    GtkListStore *list_store;


	rs_zone = zget(sizeof(results_set_t), 1024);
	rc_zone = zget(sizeof(record_t), 1024);

	list_store = gtk_list_store_new(
		c_sl_num,
		G_TYPE_STRING,
		G_TYPE_INT,
		G_TYPE_INT,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(tree_view_search, GTK_TREE_MODEL(list_store));
	add_search_column(tree_view_search, "Search", c_sl_name, 80);
	add_search_column(tree_view_search, "Hits", c_sl_hit, 40);
	add_search_column(tree_view_search, "New", c_sl_new, 40);
	g_signal_connect(G_OBJECT(tree_view_search), 
		"cursor-changed",
		G_CALLBACK(on_tree_view_search_select_row),
		NULL);

	gui_search_create_tree_view(&default_scrolled_window, 
		&default_search_tree_view);
    gtk_notebook_remove_page(notebook_search_results, 0);
	gtk_notebook_set_scrollable(notebook_search_results, TRUE);
	gtk_notebook_append_page
        (notebook_search_results, default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text
        (notebook_search_results, default_scrolled_window, "(no search)");
    
	g_signal_connect(GTK_OBJECT(combo_searches->popwin), "hide", 
		G_CALLBACK(on_search_popdown_switch), NULL);
	g_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
		G_CALLBACK(on_search_notebook_switch), NULL);
	g_signal_connect(GTK_OBJECT(notebook_search_results), "focus_tab",
		G_CALLBACK(on_search_notebook_focus_tab), NULL);

    /*
     * Now we restore the column visibility
     */
/*    {
        gint i;
        GtkTreeView *tree_view;

        tree_view = (current_search != NULL) ? 
                GTK_TREE_VIEW(current_search->tree_view) : 
                GTK_TREE_VIEW(default_search_tree_view);
         
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility
                (tree_view, i, (gboolean) search_results_col_visible[i]);
    }
*/
#ifdef USE_SEARCH_XML
    LIBXML_TEST_VERSION
	if (search_retrieve_old()) {
       	g_snprintf(tmpstr, sizeof(tmpstr), "%s/%s", 
            gui_config_dir, search_file);
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

    search_add_got_results_listener(search_gui_got_results);
}

void search_gui_shutdown(void)
{
    search_remove_got_results_listener(search_gui_got_results);

	search_gui_store_searches();

    while (searches != NULL)
        search_gui_close_search((search_t *)searches->data);

	zdestroy(rs_zone);
	zdestroy(rc_zone);
	rs_zone = rc_zone = NULL;
}

static void selection_counter_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	gint *counter = data;
	*counter += 1;
}

static gint selection_counter(GtkTreeView *tree_view)
{
	GtkTreeSelection *selection = NULL;
	gint rows = 0;

	if (tree_view != NULL)
 		selection = gtk_tree_view_get_selection(tree_view);
	if (selection != NULL)
		gtk_tree_selection_selected_foreach(
				selection, 
				selection_counter_helper,
				&rows);

	return rows;
}

static gboolean tree_view_search_remove(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	gpointer sch;

    gtk_tree_model_get(model, iter, c_sl_sch, &sch, -1);
 	if (sch == data) {
    	gtk_list_store_remove(GTK_LIST_STORE(model), iter);
		return TRUE;
	}

	return FALSE;
}

/*
 * search_gui_remove_search:
 *
 * Remove the search from the gui and update all widget accordingly.
 */
void search_gui_remove_search(search_t * sch)
{
    GList *glist;
    gboolean sensitive;
	GtkTreeModel *model;
    GtkTreeView *tree_view_search = GTK_TREE_VIEW
        (lookup_widget(main_window, "tree_view_search"));
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
         (lookup_widget(main_window, "combo_searches"));

    g_assert(sch != NULL);

   	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_remove_items(GTK_LIST(combo_searches->list), glist);

	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(
		GTK_TREE_VIEW(sch->tree_view))));

	model = gtk_tree_view_get_model(tree_view_search);
    gtk_tree_model_foreach(model, tree_view_search_remove, sch);

    gtk_timeout_remove(sch->tab_updating);

    /* remove column header arrow if it exists */
/*    if (sch->arrow != NULL) { 
        gtk_widget_destroy(sch->arrow);
        sch->arrow = NULL;
    }     
*/
    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results, 
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */
        GtkWidget *spinbutton_minimum_speed =
            lookup_widget(main_window, "spinbutton_minimum_speed");

		gtk_list_store_clear(GTK_LIST_STORE(
				gtk_tree_view_get_model(GTK_TREE_VIEW(sch->tree_view))));

		default_search_tree_view = sch->tree_view;
		default_scrolled_window = sch->scrolled_window;

        search_selected = current_search = NULL;

		gui_search_update_items(NULL);

		gtk_entry_set_text
            (GTK_ENTRY(lookup_widget(main_window, "combo_entry_searches")), "");

        gtk_notebook_set_tab_label_text
            (notebook_search_results, default_scrolled_window, "(no search)");

		gtk_widget_set_sensitive
            (lookup_widget(main_window, "button_search_clear"), FALSE);
        gtk_widget_set_sensitive(spinbutton_minimum_speed, FALSE);
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_minimum_speed), 0);
	}
    
    sensitive = searches != NULL;
	gtk_widget_set_sensitive(GTK_WIDGET(combo_searches), sensitive);
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_close"), sensitive);

	if (current_search != NULL)
		sensitive = sensitive && 
			selection_counter(GTK_TREE_VIEW(current_search->tree_view)) > 0;

    gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
}

void search_gui_set_current_search(search_t *sch) 
{
	search_t *old_sch = current_search;
    GtkCTreeNode * node;
    GtkWidget *spinbutton_minimum_speed;
    GtkWidget *spinbutton_reissue_timeout;
    GtkTreeView *tree_view_search;
    static gboolean locked = FALSE;
    gboolean passive;
    gboolean frozen;
    guint32 reissue_timeout;
    guint16 minimum_speed;

	g_assert(sch != NULL);

    if (locked)
		return;

    locked = TRUE;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);

    passive = search_is_passive(sch->search_handle);
    frozen = search_is_frozen(sch->search_handle);
    reissue_timeout = search_get_reissue_timeout(sch->search_handle);
    minimum_speed = search_get_minimum_speed(sch->search_handle);

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */
/*    if (current_search != NULL) {
        gint i;
        GtkCList *list;
        
        list = GTK_CLIST(current_search->clist);

        for (i = 0; i < list->columns; i ++) {
            gtk_clist_set_column_visibility
                (GTK_CLIST(sch->clist), i, list->column[i].visible);
            gtk_clist_set_column_width
                (GTK_CLIST(sch->clist), i, list->column[i].width);
        }
    }
*/
	current_search = sch;
	sch->unseen_items = 0;

    spinbutton_minimum_speed = lookup_widget
        (main_window, "spinbutton_minimum_speed");
    spinbutton_reissue_timeout= lookup_widget
        (main_window, "spinbutton_search_reissue_timeout");
    tree_view_search = GTK_TREE_VIEW
            (lookup_widget(main_window, "tree_view_search"));

    if (sch != NULL) {
        gui_search_force_update_tab_label(sch);
        gui_search_update_items(sch);

/*        gtk_clist_select_row(
            clist_search, 
            gtk_clist_find_row_from_data(clist_search, sch), 
            0);*/
        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_minimum_speed), minimum_speed);
        gtk_widget_set_sensitive(spinbutton_minimum_speed, TRUE);
        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_reissue_timeout), reissue_timeout);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, !passive);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_download"), 
			selection_counter(GTK_TREE_VIEW(sch->tree_view)) > 0);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_clear"), 
            sch->items != 0);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_restart"), !passive);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_duplicate"), !passive);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), !frozen);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"),frozen);

        /*
         * Combo "Active searches"
         */
        gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));
    } else {
        gtk_tree_selection_unselect_all(
			gtk_tree_view_get_selection(tree_view_search));
        gtk_widget_set_sensitive(spinbutton_minimum_speed, FALSE);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_download"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_clear"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_restart"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_duplicate"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"), FALSE);
    }

    /*
     * Search results notebook
     */
    {
        GtkNotebook *notebook_search_results = GTK_NOTEBOOK
            (lookup_widget(main_window, "notebook_search_results"));

        gtk_notebook_set_current_page(notebook_search_results,
  			  gtk_notebook_page_num(notebook_search_results,
                  sch->scrolled_window));
    }

    /*
     * Tree menu
     */
    {
        GtkCTree *ctree_menu = GTK_CTREE
            (lookup_widget(main_window, "ctree_menu"));

        node = gtk_ctree_find_by_row_data(
            ctree_menu,
            gtk_ctree_node_nth(ctree_menu,0),
            (gpointer) nb_main_page_search);
    
        if (node != NULL)
            gtk_ctree_select(ctree_menu,node);
    }

    locked = FALSE;
}

search_t *search_gui_get_current_search(void)
{
    return current_search;
}

GtkTreeModel *create_model (void)
{
  GtkListStore *store;

  /* create list store */
  store = gtk_list_store_new(
	c_sr_num,
	G_TYPE_STRING,	/* File */
	G_TYPE_STRING,	/* Size */
	G_TYPE_UINT,		/* Speed */
	G_TYPE_STRING,	/* Host */
	G_TYPE_STRING,	/* urn:sha1 */
	G_TYPE_STRING,	/* Info */
	G_TYPE_POINTER);	/* (record_t *) */

  return GTK_TREE_MODEL(store);
}

static GtkTreeViewColumn *add_column(
	GtkTreeView *treeview, gchar *name, gint id, gint width)
{
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes(name, renderer,
        "text", id, NULL);
    gtk_tree_view_column_set_sort_column_id(column, id);
    gtk_tree_view_column_set_fixed_width(column, width);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_append_column(treeview, column);

	return column;
}

gint search_gui_compare_records_cb(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer data)
{
    record_t    *rec_a, *rec_b;

    gtk_tree_model_get(model, a, c_sr_record, &rec_a, -1);
    gtk_tree_model_get(model, b, c_sr_record, &rec_b, -1);
    return search_gui_compare_records(GPOINTER_TO_INT(data), rec_a, rec_b);
}
static void add_results_column(
	GtkTreeView *treeview, gchar *name, gint id, gint width) 
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(treeview);
	column = add_column(treeview, name, id, width);
	gtk_tree_sortable_set_sort_func(
		GTK_TREE_SORTABLE(model), id, (gpointer) search_gui_compare_records_cb,
		GINT_TO_POINTER(id), NULL);

	g_signal_connect(
		GTK_OBJECT(column),
		"clicked",
		G_CALLBACK(on_tree_view_search_results_click_column),
		treeview);
}

void add_results_columns (GtkTreeView *treeview)
{
  add_results_column(treeview, "File", c_sr_filename, 300);
  add_results_column(treeview, "Size", c_sr_size, 40);
  add_results_column(treeview, "Speed", c_sr_speed, 40);
  add_results_column(treeview, "Host", c_sr_host, 60);
  add_results_column(treeview, "urn:sha1", c_sr_urn, 80);
  add_results_column(treeview, "Info", c_sr_info, 60);
}

static void add_search_column(
	GtkTreeView *treeview, gchar *name, gint id, gint width) 
{
    GtkTreeViewColumn *column;

	column = add_column(treeview, name, id, width);
}

/* Create a new GtkTreeView for search results */

void gui_search_create_tree_view(GtkWidget ** sw, GtkWidget ** tv)
{
	GtkTreeModel	*tree_model = create_model();
	GtkTreeSelection	*tree_selection;
	GtkTreeView	*tree_view;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

	tree_view = GTK_TREE_VIEW(gtk_tree_view_new_with_model(tree_model));
	*tv = GTK_WIDGET(tree_view);
	g_object_unref(tree_model);

	tree_selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_set_mode(tree_selection, GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_reorderable(tree_view, TRUE);
	gtk_tree_view_set_headers_visible(tree_view, TRUE);
	gtk_tree_view_set_headers_clickable(tree_view, TRUE);
	gtk_tree_view_set_enable_search(tree_view, TRUE);
	gtk_tree_view_set_rules_hint(tree_view, TRUE);

      /* add columns to the tree view */
	add_results_columns(tree_view);

	gtk_container_add(GTK_CONTAINER(*sw), *tv);
	gtk_tree_view_expand_all(tree_view);

	if (!GTK_WIDGET_VISIBLE (*sw))
		gtk_widget_show_all(*sw);

	g_signal_connect(GTK_OBJECT(tree_view), "cursor-changed",
				   G_CALLBACK(on_tree_view_search_results_select_row),
				   tree_view);
	g_signal_connect(GTK_OBJECT(tree_view), "button_press_event",
					   G_CALLBACK
					   (on_tree_view_search_results_button_press_event), NULL);
/*	g_signal_connect(GTK_OBJECT(tree_view), "column-changed",
					   G_CALLBACK
					   (on_tree_view_search_results_resize_column), NULL);*/
    g_signal_connect(GTK_OBJECT(tree_view), "key_press_event",
                       G_CALLBACK
                       (on_tree_view_search_results_key_press_event), NULL);
}

void gui_search_update_items(struct search *sch)
{
    if (sch) {
        gchar *str = sch->passive ? "(passive search) " : "";
    
        if (sch->items)
            g_snprintf(tmpstr, sizeof(tmpstr), "%s%u item%s found", 
                str, sch->items, (sch->items > 1) ? "s" : "");
        else
            g_snprintf(tmpstr, sizeof(tmpstr), "%sNo items found", str);
    } else
        g_snprintf(tmpstr, sizeof(tmpstr), "No search");

	gtk_label_set(
        GTK_LABEL(lookup_widget(main_window, "label_items_found")), 
        tmpstr);
}


static gboolean tree_view_search_update(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	search_t *sch;

    gtk_tree_model_get(model, iter, c_sl_sch, &sch, -1);
 	if ((gpointer)sch == data) {
		gtk_list_store_set(GTK_LIST_STORE(model), iter, 
			c_sl_hit, GINT_TO_POINTER(sch->items), 
			c_sl_new, GINT_TO_POINTER(sch->unseen_items),
			-1);
		return TRUE;
	}

	return FALSE;
}

/* Like search_update_tab_label but always update the label */
void gui_search_force_update_tab_label(struct search *sch)
{
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkTreeView *tree_view_search = GTK_TREE_VIEW
        (lookup_widget(main_window, "tree_view_search"));
    search_t *current_search;
	GtkTreeModel *model;

    current_search = search_gui_get_current_search();

	if (sch == current_search || sch->unseen_items == 0)
		g_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d)", sch->query,
				   sch->items);
	else
		g_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text
        (notebook_search_results, sch->scrolled_window, tmpstr);

	model = gtk_tree_view_get_model(tree_view_search);
	gtk_tree_model_foreach(model, tree_view_search_update, sch);


 /*   if (sch->unseen_items > 0) {
        gtk_clist_set_background(
            clist_search, row, 
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->bg[GTK_STATE_ACTIVE]);
    } else {
        gtk_clist_set_background(clist_search, row, NULL);
    }
*/
	sch->last_update_time = time(NULL);
}

/* Doesn't update the label if nothing's changed or if the last update was
   recent. */
gboolean gui_search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (time(NULL) - sch->last_update_time < tab_update_time)
		return TRUE;

	gui_search_force_update_tab_label(sch);

	return TRUE;
}

void gui_search_clear_results(void)
{
	search_t *current_search;

	current_search = search_gui_get_current_search();
	gtk_list_store_clear(GTK_LIST_STORE(
		gtk_tree_view_get_model(GTK_TREE_VIEW(current_search->tree_view))));
	search_gui_clear_search(current_search);
	gui_search_force_update_tab_label(current_search);
	gui_search_update_items(current_search);
}

/*
 * gui_search_history_add:
 *
 * Adds a search string to the search history combo. Makes
 * sure we do not get more than 10 entries in the history.
 * Also makes sure we don't get duplicate history entries.
 * If a string is already in history and it's added again,
 * it's moved to the beginning of the history list.
 */
void gui_search_history_add(gchar * s)
{
    GList *new_hist = NULL;
    GList *cur_hist = sl_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if ((n < 9) && (g_ascii_strcasecmp(s,cur_hist->data) != 0)) {
            /* copy up to the first 9 items */
            new_hist = g_list_append(new_hist, cur_hist->data);
            n ++;
        } else {
            /* and free the rest */
            G_FREE_NULL(cur_hist->data);
        }
        cur_hist = cur_hist->next;
    }
    /* put the new item on top */
    new_hist = g_list_prepend(new_hist, g_strdup(s));

    /* set new history */
    gtk_combo_set_popdown_strings(
        GTK_COMBO(lookup_widget(main_window, "combo_search")),
        new_hist);

    /* free old list structure */
    g_list_free(sl_search_history);
    
    sl_search_history = new_hist;
}


