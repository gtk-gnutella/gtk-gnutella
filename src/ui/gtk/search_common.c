/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * Common GUI search routines.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "gui.h"

RCSID("$Id$");

#include "search.h"
#include "settings.h"
#include "gtk-missing.h"

#include "search_xml.h"
#include <libxml/parser.h>

#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/core/downloads.h"
#include "if/core/guid.h"
#include "if/core/sockets.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/fuzzy.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/vendors.h"
#include "lib/tm.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/zalloc.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

static search_t *current_search  = NULL; /**< The search currently displayed */

static zone_t *rs_zone;		/**< Allocation of results_set */
static zone_t *rc_zone;		/**< Allocation of record */

static const gchar search_file[] = "searches"; /**< "old" file to searches */

static GSList *accumulated_rs = NULL;
static GList *list_search_history = NULL;

static GtkLabel *label_items_found = NULL;
static GtkLabel *label_search_expiry = NULL;

/**
 * Human readable translation of servent trailer open flags.
 * Decompiled flags are listed in the order of the table.
 */
static struct {
	guint32 flag;
	const gchar *status;
} open_flags[] = {
	{ ST_BUSY,			N_("busy") },
	{ ST_UPLOADED,		N_("stable") },		/**< Allows uploads -> stable */
	{ ST_FIREWALL,		N_("push") },
	{ ST_PUSH_PROXY,	N_("proxy") },
	{ ST_BOGUS,			N_("bogus") },		/**< Bogus IP address */
};

search_t *search_gui_get_current_search(void)	{ return current_search; }
void search_gui_forget_current_search(void)		{ current_search = NULL; }

static void
on_option_menu_menu_item_activate(GtkMenuItem *unused_item, gpointer udata)
{
	GtkOptionMenu *option_menu;

	(void) unused_item;

	option_menu = GTK_OPTION_MENU(udata);
	search_gui_set_current_search(option_menu_get_selected_data(option_menu));
}

void
search_gui_option_menu_searches_update(void)
{
	GtkOptionMenu *option_menu;
	GtkMenu *menu;
	const GList *iter;

	option_menu = GTK_OPTION_MENU(lookup_widget(main_window,
						"option_menu_searches"));	
	menu = GTK_MENU(gtk_menu_new());

	iter = g_list_last(deconstify_gpointer(search_gui_get_searches()));
	for (/* NOTHING */; iter != NULL; iter = g_list_previous(iter)) {
		GtkWidget *item;
		search_t *s = iter->data;

		item = gtk_menu_item_new_with_label(lazy_utf8_to_ui_string(s->query));
		gtk_widget_show(item);
		gtk_object_set_user_data(GTK_OBJECT(item), s);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(menu), item);
#ifdef USE_GTK1
		gtk_signal_connect(GTK_OBJECT(item), "activate",
			on_option_menu_menu_item_activate, option_menu);
#endif /* USE_GTK1 */
#ifdef USE_GTK2
		g_signal_connect(GTK_OBJECT(item), "activate",
			G_CALLBACK(on_option_menu_menu_item_activate), option_menu);
#endif /* USE_GTK2 */

	}
	gtk_option_menu_set_menu(option_menu, GTK_WIDGET(menu));
}

void
search_gui_option_menu_searches_select(const search_t *sch)
{
	option_menu_select_item_by_data(
		GTK_OPTION_MENU(lookup_widget(main_window, "option_menu_searches")),
		sch);
}

void
search_gui_current_search(search_t *sch)
{
	search_gui_option_menu_searches_select(sch);
   	current_search = sch;
}

/**
 * Create a new search and start it. Use default reissue timeout.
 */
gboolean
search_gui_new_search(const gchar *query, flag_t flags, search_t **search)
{
    guint32 timeout;
	gboolean ret;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

	if (!(SEARCH_PASSIVE & flags))
		query = lazy_ui_string_to_utf8(query);

    ret = search_gui_new_search_full(query, tm_time(), search_lifetime, timeout,
			search_sort_default_column, search_sort_default_order,
			flags | SEARCH_ENABLED, search);

	return ret;
}


/**
 * Free the alternate locations held within a file record.
 */
void
search_gui_free_alt_locs(record_t *rc)
{
	gnet_host_vec_t *alt = rc->alt_locs;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
	g_assert(alt != NULL);

	{
		gint i;

		for (i = 0; i < alt->hvcnt; i++)
			g_assert(host_addr_initialized(alt->hvec[i].addr));
	}

	wfree(alt->hvec, alt->hvcnt * sizeof *alt->hvec);
	wfree(alt, sizeof *alt);

	rc->alt_locs = NULL;
}

/**
 * Free the push proxies held within a result set.
 */
void
search_gui_free_proxies(results_set_t *rs)
{
	gnet_host_vec_t *v = rs->proxies;

	g_assert(v != NULL);

	wfree(v->hvec, v->hvcnt * sizeof *v->hvec);
	wfree(v, sizeof *v);

	rs->proxies = NULL;
}

/**
 * Free one file record.
 *
 * Those records may be inserted into some `dups' tables, at which time they
 * have their refcount increased.  They may later be removed from those tables
 * and they will have their refcount decreased.
 *
 * To ensure some level of sanity, we ask our callers to explicitely check
 * for a refcount to be zero before calling us.
 */
static void
search_gui_free_record(record_t *rc)
{
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount == 0);
	g_assert(NULL == rc->results_set);

	atom_str_free(rc->name);
	atom_str_free(rc->utf8_name);
	if (rc->ext != NULL)
        atom_str_free(rc->ext);
	if (rc->tag != NULL)
		atom_str_free(rc->tag);
	if (rc->info != NULL)
		atom_str_free(rc->info);
	if (rc->sha1 != NULL)
		atom_sha1_free(rc->sha1);
	if (rc->xml != NULL)
		atom_str_free(rc->xml);
	if (rc->alt_locs != NULL)
		search_gui_free_alt_locs(rc);
	rc->refcount = -1;
	rc->magic = 0xBAD;
	rc->sha1 = GUINT_TO_POINTER(1U);
	zfree(rc_zone, rc);
}

/**
 * Tries to extract the extenstion of a file from the filename.
 * The return value is only valid until the function is called again.
 */
const gchar *
search_gui_extract_ext(const gchar *filename)
{
    static gchar ext[32];
	const gchar *p;
	size_t rw = 0;

    g_assert(NULL != filename);

    ext[0] = '\0';
    p = strrchr(filename, '.');

	rw = g_strlcpy(ext, p ? ++p : "", sizeof ext);
	if (rw >= sizeof ext) {
		/* If the guessed extension is really this long, assume the
		 * part after the dot isn't an extension at all. */
		ext[0] = '\0';
	} else {
		/* Using g_utf8_strdown() (for GTK2) would be cleaner but it
         * allocates a new string which is ugly. Nobody uses such file
         * extensions anyway. */
		ascii_strlower(ext, ext);
	}

    return ext;
}

/**
 * This routine must be called when the results_set has been dispatched to
 * all the opened searches.
 *
 * All the records that have not been used by a search are removed.
 */
void
search_gui_clean_r_set(results_set_t *rs)
{
	GSList *sl;
    GSList *sl_remove = NULL;

	g_assert(rs->refcount > 0);		/* If not dispatched, should be freed */

    /*
     * Collect empty searches.
     */
    for (sl = rs->records; sl != NULL; sl = g_slist_next(sl)) {
		record_t *rc = (record_t *) sl->data;

		g_assert(rc->results_set == rs);
		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
		if (rc->refcount == 0)
			sl_remove = g_slist_prepend(sl_remove, (gpointer) rc);
    }

    /*
     * Remove empty searches from record set.
     */
	for (sl = sl_remove; sl != NULL; sl = g_slist_next(sl)) {
		record_t *rc = (record_t *) sl->data;

		rc->results_set = NULL;
		search_gui_free_record(rc);
		rs->records = g_slist_remove(rs->records, rc);
		g_assert(rs->num_recs > 0);
		rs->num_recs--;
	}

    g_slist_free(sl_remove);
}

/**
 * Free one results_set.
 *
 * Those records may be shared between several searches.  So while the refcount
 * is positive, we just decrement it and return without doing anything.
 */
void
search_gui_free_r_set(results_set_t *rs)
{
	GSList *sl;

    g_assert(rs != NULL);


	/*
	 * It is conceivable that some records were used solely by the search
	 * dropping the result set.  Therefore, if the refcount is not 0,  we
	 * pass through search_clean_r_set().
	 */

	if (--(rs->refcount) > 0) {
		search_gui_clean_r_set(rs);
		return;
	}

    /*
     * Free list of searches set was intended for.
     */

    if (rs->schl) {
        g_slist_free(rs->schl);
        rs->schl = NULL;
    }

	/*
	 * Because noone refers to us any more, we know that our embedded records
	 * cannot be held in the hash table anymore.  Hence we may call the
	 * search_free_record() safely, because rc->refcount must be zero.
	 */

	g_assert(rs->num_recs == g_slist_length(rs->records));
	for (sl = rs->records; sl != NULL; sl = g_slist_next(sl)) {
		record_t *rc = (record_t *) sl->data;

		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->results_set == rs);
		rc->results_set = NULL;
		search_gui_free_record(rc);
		g_assert(rs->num_recs > 0);
		rs->num_recs--;
	}

    if (rs->guid)
		atom_guid_free(rs->guid);
	if (rs->version)
		atom_str_free(rs->version);
	if (rs->proxies)
		search_gui_free_proxies(rs);
	if (rs->hostname)
		atom_str_free(rs->hostname);

	g_slist_free(rs->records);
	zfree(rs_zone, rs);
}

/**
 * Dispose of an empty search results, whose records have all been
 * unreferenced by the searches.  The results_set is therefore an
 * empty shell, useless.
 */
void
search_gui_dispose_results(results_set_t *rs)
{
	gint refs = 0;
	const GList *l;

	g_assert(rs->num_recs == 0);
	g_assert(rs->refcount > 0);

	/*
	 * A results_set does not point back to the searches that still
	 * reference it, so we have to do that manually.
	 */

	for (l = search_gui_get_searches(); NULL != l; l = g_list_next(l)) {
		search_t *sch = (search_t *) l->data;

		if (NULL != sch->r_sets && hash_list_contains(sch->r_sets, rs)) {
			refs++;			/* Found one more reference to this search */
			hash_list_remove(sch->r_sets, rs);
		}
	}

	g_assert(rs->refcount == refs);		/* Found all the searches */

	rs->refcount = 1;
	search_gui_free_r_set(rs);
}

/**
 * Add a reference to the record but don't dare to redeem it!
 */
void
search_gui_ref_record(record_t *rc)
{
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
	rc->refcount++;
}

/**
 * Remove one reference to a file record.
 *
 * If the record has no more references, remove it from its parent result
 * set and free the record physically.
 */
void
search_gui_unref_record(record_t *rc)
{
	results_set_t *rs;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount > 0 && rc->refcount < INT_MAX);

	if (--(rc->refcount) > 0)
		return;

	/*
	 * Free record, and remove it from the parent's list.
	 */
	rs = rc->results_set;
	rc->results_set = NULL;
	search_gui_free_record(rc);

	rs->records = g_slist_remove(rs->records, rc);
	g_assert(rs->num_recs > 0);
	rs->num_recs--;

	g_assert((rs->num_recs > 0) ^ (rs->records == NULL));

	/*
	 * We can't free the results_set structure right now if it does not
	 * hold anything because we don't know which searches reference it.
	 */

	if (rs->num_recs == 0)
		search_gui_dispose_results(rs);
}

/**
 * Free all the results_set's of a search
 */
static inline void
free_r_sets_helper(gpointer data, gpointer unused_udata)
{
	results_set_t *rs = data;

	(void) unused_udata;

	search_gui_free_r_set(rs);
}

void
search_gui_free_r_sets(search_t *sch)
{
	g_assert(sch != NULL);
	g_assert(sch->dups != NULL);
	g_assert(g_hash_table_size(sch->dups) == 0); /* All records were cleaned */

	if (NULL != sch->r_sets) {
		hash_list_foreach(sch->r_sets, free_r_sets_helper, NULL);
		hash_list_free(sch->r_sets);
		sch->r_sets = NULL;
	}
}

guint
search_gui_hash_func(gconstpointer p)
{
	const record_t *rc = p;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);

	/* Must use same fields as search_hash_key_compare() --RAM */
	return
		GPOINTER_TO_UINT(rc->sha1) ^	/* atom! (may be NULL) */
		GPOINTER_TO_UINT(rc->results_set->guid) ^	/* atom! */
		(NULL != rc->sha1 ? 0 : g_str_hash(rc->name)) ^
		rc->size ^
		host_addr_hash(rc->results_set->addr) ^
		rc->results_set->port;
}

gint
search_gui_hash_key_compare(gconstpointer a, gconstpointer b)
{
	const record_t *rc1 = a, *rc2 = b;

	/* Must compare same fields as search_hash_func() --RAM */
	return rc1->size == rc2->size
		&& host_addr_equal(rc1->results_set->addr, rc2->results_set->addr)
		&& rc1->results_set->port == rc2->results_set->port
		&& rc1->results_set->guid == rc2->results_set->guid	/* atom! */
		&& (rc1->sha1 != NULL /* atom! */
				? rc1->sha1 == rc2->sha1 : (0 == strcmp(rc1->name, rc2->name)));
}

/**
 * Remove reference to results in our search.
 * Last one to remove it will trigger a free.
 */
void
search_gui_remove_r_set(search_t *sch, results_set_t *rs)
{
	hash_list_remove(sch->r_sets, rs);
	search_gui_free_r_set(rs);
}

/**
 * Check to see whether we already have a record for this file.
 * If we do, make sure that the index is still accurate,
 * otherwise inform the interested parties about the change.
 *
 * @returns true if the record is a duplicate.
 */
gboolean
search_gui_result_is_dup(search_t *sch, record_t *rc)
{
	union {
		record_t *rc;
		gpointer ptr;
	} old;
	gpointer dummy;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);

	if (!g_hash_table_lookup_extended(sch->dups, rc, &old.ptr, &dummy))
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

	if (rc->index != old.rc->index) {
		if (gui_debug)
			g_warning("Index changed from %u to %u at %s for %s",
				old.rc->index, rc->index, guid_hex_str(rc->results_set->guid),
				rc->name);
		guc_download_index_changed(
			rc->results_set->addr,		/* This is for optimizing lookups */
			rc->results_set->port,
			rc->results_set->guid,		/* This is for formal identification */
			old.rc->index,
			rc->index);
		old.rc->index = rc->index;
	}

	return TRUE;		/* yes, it's a duplicate */
}

/**
 * @returns a pointer to gui_search_t from gui_searches which has
 * sh as search_handle. If none is found, return NULL.
 */
search_t *
search_gui_find(gnet_search_t sh)
{
    const GList *l;

    for (l = search_gui_get_searches(); l != NULL; l = g_list_next(l)) {
		search_t *s = l->data;

        if (s->search_handle == sh) {
            if (gui_debug >= 15)
                printf("search [%s] matched handle %x\n", s->query, sh);

            return s;
        }
    }

    return NULL;
}

/**
 * Extract the filename extensions - if any - from the given UTF-8
 * encoded filename and convert it to lowercase. If the extension
 * exceeds a certain length, it is assumed that it's no extension
 * but just a non-specific dot inside a filename.
 *
 * @return NULL if there's no filename extension, otherwise a pointer
 *         to a static string holding the lowercased extension.
 */
gchar *
search_gui_get_filename_extension(const gchar *filename_utf8)
{
	const gchar *p = strrchr(filename_utf8, '.');
	static gchar ext[32];

	if (!p || utf8_strlower(ext, &p[1], sizeof ext) >= sizeof ext) {
		/* If the guessed extension is really this long, assume the
		 * part after the dot isn't an extension at all. */
		return NULL;
	}
	return ext;
}

/**
 * Create a new GUI record within `rs' from a Gnutella record.
 */
record_t *
search_gui_create_record(results_set_t *rs, gnet_record_t *r)
{
    record_t *rc;

    g_assert(r != NULL);
    g_assert(rs != NULL);

    rc = (record_t *) zalloc(rc_zone);

	rc->magic = RECORD_MAGIC;
    rc->results_set = rs;
    rc->refcount = 0;

    rc->ext = NULL;
	rc->name = atom_str_get(r->name);
	rc->utf8_name = atom_str_get(lazy_unknown_to_utf8_normalized(r->name,
						UNI_NORM_GUI, &rc->charset));
    rc->size = r->size;
    rc->index = r->index;
    rc->sha1 = r->sha1 != NULL ? atom_sha1_get(r->sha1) : NULL;
    rc->xml = r->xml != NULL ? atom_str_get(r->xml) : NULL;
    rc->tag = r->tag != NULL ? atom_str_get(r->tag) : NULL;
	rc->info = NULL;
   	rc->flags = r->flags;
	rc->alt_locs = NULL;

	if (NULL != r->alt_locs) {
		{
			gint i;

			for (i = 0; i < r->alt_locs->hvcnt; i++)
				g_assert(host_addr_initialized(r->alt_locs->hvec[i].addr));
		}

		rc->alt_locs = wcopy(r->alt_locs, sizeof *r->alt_locs);
		rc->alt_locs->hvec = wcopy(r->alt_locs->hvec,
								r->alt_locs->hvcnt * sizeof *r->alt_locs->hvec);
	}

    return rc;
}

/**
 * Create a new GUI result set from a Gnutella one.
 */
results_set_t *
search_gui_create_results_set(GSList *schl, const gnet_results_set_t *r_set)
{
    results_set_t *rs;
    GSList *sl;
	gint ignored = 0;

    rs = zalloc(rs_zone);

    rs->refcount = 0;
    rs->schl = g_slist_copy(schl);

    rs->guid = atom_guid_get(r_set->guid);
    rs->addr = r_set->addr;
    rs->port = r_set->port;
    rs->status = r_set->status;
    rs->speed = r_set->speed;
    rs->stamp = r_set->stamp;
    rs->vcode = r_set->vcode;
	rs->version = r_set->version ? atom_str_get(r_set->version) : NULL;
	rs->hostname = r_set->hostname ? atom_str_get(r_set->hostname) : NULL;
	rs->country = r_set->country;
	rs->udp_addr = r_set->udp_addr;

    rs->num_recs = 0;
    rs->records = NULL;
	rs->proxies = NULL;

    for (sl = r_set->records; sl != NULL; sl = g_slist_next(sl)) {
        record_t *rc;
		gnet_record_t *grc = (gnet_record_t *) sl->data;

		if (!(grc->flags & SR_DONT_SHOW)) {
			rc = search_gui_create_record(rs, grc);
			rs->records = g_slist_prepend(rs->records, rc);
			rs->num_recs ++;
		} else
			ignored++;
    }

    g_assert(rs->num_recs + ignored == r_set->num_recs);

    return rs;
}

void
on_search_entry_activate(GtkWidget *unused_widget, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;
	search_gui_new_search_entered();
}

void
on_option_menu_search_changed(GtkOptionMenu *option_menu, gpointer unused_udata)
{
	(void) unused_udata;
	search_gui_set_current_search(option_menu_get_selected_data(option_menu));
}

/**
 * Initialize common structures.
 */
void
search_gui_common_init(void)
{
	rs_zone = zget(sizeof(results_set_t), 1024);
	rc_zone = zget(sizeof(record_t), 1024);

	label_items_found = GTK_LABEL(
		lookup_widget(main_window, "label_items_found"));
	label_search_expiry = GTK_LABEL(
		lookup_widget(main_window, "label_search_expiry"));
}

/**
 * Destroy common structures.
 */
void
search_gui_common_shutdown(void)
{
	zdestroy(rs_zone);
	zdestroy(rc_zone);

	rs_zone = rc_zone = NULL;

    g_list_free(list_search_history);
    list_search_history = NULL;
}

/**
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
void
search_gui_check_alt_locs(results_set_t *rs, record_t *rc)
{
	gnet_host_vec_t *alt = rc->alt_locs;
	gint i;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
	g_assert(alt != NULL);
	g_assert(rs->proxies == NULL);	/* Since we downloaded record already */

	for (i = 0; i < alt->hvcnt; i++) {
		gnet_host_t *h = &alt->hvec[i];

		g_assert(host_addr_initialized(h->addr));
		if (h->port == 0 || !host_addr_is_routable(h->addr))
			continue;

		guc_download_auto_new(rc->name, rc->size, URN_INDEX,
			h->addr, h->port, blank_guid, rs->hostname,
			rc->sha1, rs->stamp, FALSE, TRUE, NULL, NULL, 0);
	}

	search_gui_free_alt_locs(rc);
}

/**
 * Makes the sort column and order of the current search the default settings.
 */
void
search_gui_set_sort_defaults(void)
{
	const search_t *sch;
	
	sch = current_search;
	if (sch) {
		gui_prop_set_guint32_val(PROP_SEARCH_SORT_DEFAULT_COLUMN,
			sch->sort_col);
		gui_prop_set_guint32_val(PROP_SEARCH_SORT_DEFAULT_ORDER,
			sch->sort_order);
	}
}

/**
 * Persist searches to disk.
 */
void
search_gui_store_searches(void)
{
	char *path;

	search_store_xml();

	path = make_pathname(settings_gui_config_dir(), search_file);
	g_return_if_fail(NULL != path);

    if (file_exists(path)) {
		char *path_old;

      	path_old = g_strdup_printf("%s.old", path);
		if (NULL != path_old) {
        	g_warning(
            	_("Found old searches file. The search information has been\n"
            	"stored in the new XML format and the old file is renamed to\n"
            	"%s"), path_old);
        	if (-1 == rename(path, path_old))
          		g_warning(_("could not rename %s as %s: %s\n"
                	"The XML file will not be used "
					"unless this problem is resolved."),
                path, path_old, g_strerror(errno));
			G_FREE_NULL(path_old);
		}
    }
	G_FREE_NULL(path);
}

/**
 * Retrieve searches from disk.
 */
void
search_gui_retrieve_searches(void)
{
	LIBXML_TEST_VERSION

    search_retrieve_xml();
}

/**
 * Called to dispatch results to the search window.
 */
void
search_matched(search_t *sch, results_set_t *rs)
{
	guint32 old_items = sch->items;
   	gboolean need_push;			/* Would need a push to get this file? */
	gboolean skip_records;		/* Shall we skip those records? */
	GString *vinfo = g_string_sized_new(40);
	const gchar *vendor;
    GdkColor *download_color;
    GdkColor *ignore_color;
    GdkColor *mark_color;
    GSList *l;
    gboolean send_pushes;
    gboolean is_firewalled;
	guint i;
	guint32 flags = 0, results_kept = 0;

    g_assert(sch != NULL);
    g_assert(rs != NULL);

	gui_search_get_colors(sch, &mark_color, &ignore_color, &download_color);

    vendor = lookup_vendor_name(rs->vcode);

   	if (vendor) {
		g_string_append(vinfo, vendor);
		if (rs->version) {
			g_string_append(vinfo, "/");
			g_string_append(vinfo, rs->version);
		}
	}

	for (i = 0; i < G_N_ELEMENTS(open_flags); i++) {
		if (rs->status & open_flags[i].flag) {
			if (vinfo->len)
				g_string_append(vinfo, ", ");
			g_string_append(vinfo, _(open_flags[i].status));
		}
	}

	if (vendor && !(rs->status & ST_PARSED_TRAILER)) {
		if (vinfo->len)
			g_string_append(vinfo, ", ");
		g_string_append(vinfo, _("<unparsed>"));
	}

	if (rs->status & ST_UDP) {
		sch->udp_qhits++;
		if (vinfo->len)
			g_string_append(vinfo, ", ");
		if (host_addr_equal(rs->addr, rs->udp_addr))
			g_string_append(vinfo, _("udp"));
		else {
			g_string_append(vinfo, _("udp "));
			g_string_append(vinfo, host_addr_to_string(rs->udp_addr));
		}
	} else
		sch->tcp_qhits++;

	if (rs->status & ST_TLS)
		g_string_append(vinfo, vinfo->len ? ", TLS" : "TLS");
	if (rs->status & ST_BH)
		g_string_append(vinfo, vinfo->len ? _(", browsable") : _("browsable"));
	flags = (rs->status & ST_TLS) ? CONNECT_F_TLS : 0;

	/*
	 * If we're firewalled, or they don't want to send pushes, then don't
	 * bother displaying results if they need a push request to succeed.
	 *		--RAM, 10/03/2002
	 */
    gnet_prop_get_boolean
		(PROP_SEND_PUSHES, &send_pushes, 0, 1);
    gnet_prop_get_boolean(PROP_IS_FIREWALLED, &is_firewalled, 0, 1);

	need_push = (rs->status & ST_FIREWALL) != 0;
	skip_records = (!send_pushes || is_firewalled) && need_push;

	if (gui_debug > 6)
		printf("search_matched: [%s] got hit with %d record%s (from %s) "
			"need_push=%d, skipping=%d\n",
			sch->query, rs->num_recs, rs->num_recs == 1 ? "" : "s",
			host_addr_port_to_string(rs->addr, rs->port),
			need_push, skip_records);

  	for (l = rs->records; l && !skip_records; l = l->next) {
		record_t *rc = (record_t *) l->data;
        filter_result_t *flt_result;
        gboolean downloaded = FALSE;
		gboolean is_dup;

		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->refcount >= 0);

        if (gui_debug > 7)
            printf("search_matched: [%s] considering %s (%s)\n",
				sch->query, rc->name, vinfo->str);

        if (rc->flags & SR_DOWNLOADED)
			sch->auto_downloaded++;

        /*
	     * If the size is zero bytes,
		 * or we don't send pushes and it's a private IP,
		 * or if this is a duplicate search result,
		 *
		 * Note that we pass ALL records through search_gui_result_is_dup(),
		 * to be able to update the index/GUID of our records correctly, when
		 * we detect a change.
		 */


		g_assert(rc->refcount >= 0);
		is_dup = search_gui_result_is_dup(sch, rc);
		g_assert(rc->refcount >= 0);

		if (is_dup) {
			sch->duplicates++;
			continue;
		}

       	if (skip_records) {
			sch->skipped++;
			continue;
		}

		if (rc->size == 0) {
			sch->ignored++;
			continue;
		}

		g_assert(rc->refcount >= 0);
        flt_result = filter_record(sch, rc);
		g_assert(rc->refcount >= 0);

        /*
         * Check whether this record was already scheduled for
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
				FILTER_PROP_STATE_DO)
		) {
            guc_download_auto_new(rc->name, rc->size, rc->index,
				rs->addr, rs->port, rs->guid, rs->hostname, rc->sha1,
				rs->stamp, need_push, TRUE, NULL, rs->proxies, flags);

			if (rs->proxies != NULL)
				search_gui_free_proxies(rs);

            downloaded = TRUE;
			sch->auto_downloaded++;
        }

		/*
		 * Don't show something we downloaded if they don't want it.
		 */

		if (downloaded && search_hide_downloaded) {
            filter_free_result(flt_result);
			results_kept++;
			sch->hidden++;
			continue;
        }

        /*
         * We start with FILTER_PROP_DISPLAY:
         */
        if (!(flt_result->props[FILTER_PROP_DISPLAY].state ==
                FILTER_PROP_STATE_DONT &&
            flt_result->props[FILTER_PROP_DISPLAY].user_data == 0) &&
			(int) results_kept++ >= 0 && /* Count as kept even if max results */
            sch->items < search_max_results
		) {
            GdkColor *fg_color = NULL;
            gboolean mark;

            sch->items++;
			g_assert(rc->refcount >= 0);
            g_hash_table_insert(sch->dups, rc, GINT_TO_POINTER(1));
			g_assert(rc->refcount >= 0);
            search_gui_ref_record(rc);
			g_assert(rc->refcount >= 1);

            mark =
                (flt_result->props[FILTER_PROP_DISPLAY].state ==
                    FILTER_PROP_STATE_DONT) &&
                (flt_result->props[FILTER_PROP_DISPLAY].user_data ==
					GINT_TO_POINTER(1));

            if (rc->flags & SR_IGNORED) {
                /*
                 * Check whether this record will be ignored by the backend.
                 */
                fg_color = ignore_color;
            } else if (downloaded)
                fg_color = download_color;
            else
                fg_color = NULL;

            search_gui_add_record(sch, rc, vinfo, fg_color,
                mark ? mark_color : NULL);
        } else
			sch->ignored++;

        filter_free_result(flt_result);
    }

    /*
     * A result set may not be added more then once to a search!
     */

	if (NULL != sch->r_sets)
    	g_assert(!hash_list_contains(sch->r_sets, rs));
	else
		sch->r_sets = hash_list_new();

	/* Adds the set to the list */
	hash_list_prepend(sch->r_sets, (gpointer) rs);
	rs->refcount++;
   	g_assert(hash_list_contains(sch->r_sets, rs));
	g_assert(hash_list_first(sch->r_sets) == rs);

	if (old_items == 0 && sch == current_search && sch->items > 0)
		search_gui_set_clear_button_sensitive(TRUE);

	/*
	 * Update counters in the core-side of the search.
	 *
	 * NB: we need to call guc_search_add_kept() even if we kept nothing,
	 * that is required for proper dynamic querying support by leaf nodes.
	 */

	guc_search_update_items(sch->search_handle, sch->items);
	guc_search_add_kept(sch->search_handle, results_kept);

	/*
	 * Disable search when the maximum amount of items is shown: they need
	 * to make some room to allow the search to continue.
	 */

	if (sch->items >= search_max_results && !sch->passive)
		gui_search_set_enabled(sch, FALSE);

	/*
	 * XXX When not for current_search, unseen_items is increased even if
	 * XXX we're not at the search pane.  Is this a problem?
	 */

	if (sch == current_search)
		search_gui_update_items(sch);
	else
		sch->unseen_items += sch->items - old_items;

	if (delta_time(tm_time(), sch->last_update_time) > TAB_UPDATE_TIME)
		gui_search_update_tab_label(sch);

  	g_string_free(vinfo, TRUE);
}

/**
 * Update the label string showing search stats.
 */
void
search_gui_update_items(const struct search *sch)
{
    if (sch) {
		gtk_label_printf(label_items_found, _("%u %s "
			"(%u skipped, %u ignored, %u hidden, %u auto-d/l, %u %s)"
			" Hits: %u (%u TCP, %u UDP)"),
			sch->items, NG_("item", "items", sch->items),
			sch->skipped, sch->ignored, sch->hidden, sch->auto_downloaded,
			sch->duplicates, NG_("dupe", "dupes", sch->duplicates),
			sch->tcp_qhits + sch->udp_qhits, sch->tcp_qhits, sch->udp_qhits);
    } else {
       gtk_label_printf(label_items_found, "%s", _("No search"));
	}
}

gboolean
search_gui_is_expired(const struct search *sch)
{
	gboolean expired = FALSE;
	
	if (sch && !sch->passive) {
		time_t ct, start;
		guint lt;
		
		gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);
		ct = guc_search_get_create_time(sch->search_handle);
		lt = 3600 * guc_search_get_lifetime(sch->search_handle);

		if (lt) {
			gint d;

			d = delta_time(tm_time(), ct);
			d = MAX(0, d);
			
			if ((guint) d >= lt)
					expired = TRUE;
		} else if (delta_time(start, ct) > 0) {
			expired = TRUE;
		}
	}

	return expired;
}
	
gboolean
search_gui_update_expiry(const struct search *sch)
{
	gboolean expired = FALSE;

    if (sch) {
		if (sch->passive) {
   			gtk_label_printf(label_search_expiry, "%s", _("Passive search"));
		} else if (sch->enabled) {
			time_t ct, start;
			guint lt;

			gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);
			ct = guc_search_get_create_time(sch->search_handle);
			lt = 3600 * guc_search_get_lifetime(sch->search_handle);

			if (lt) {
				gint d;
				d = delta_time(tm_time(), ct);
				d = MAX(0, d);
				if ((guint) d < lt) {
					gtk_label_printf(label_search_expiry,
						_("Expires in %s"), short_time(lt - d));
				} else {
					expired = TRUE;
					gtk_label_printf(label_search_expiry,
						_("Expired after %s"), short_time(lt));
				}
			} else if (delta_time(start, ct) > 0) {
				expired = TRUE;
        		gtk_label_printf(label_search_expiry, "%s", _("Expired"));
			} else {
        		gtk_label_printf(label_search_expiry, "%s",
					_("Expires with this session"));
			}
		} else {
        	gtk_label_printf(label_search_expiry, "%s", _("[stopped]"));
		}
    } else {
        gtk_label_printf(label_search_expiry, "%s", _("No search"));
	}

	return expired;
}

/***
 *** Callbacks
 ***/

/**
 * Called when the core has finished parsing the result set, and the results
 * need to be dispatched to the searches listed in `schl'.
 */
void
search_gui_got_results(GSList *schl, const gnet_results_set_t *r_set)
{
    results_set_t *rs;

    /*
     * Copy the data we got from the backend.
     */
    rs = search_gui_create_results_set(schl, r_set);

    if (gui_debug >= 12)
        printf("got incoming results...\n");

    g_assert(!g_slist_find(accumulated_rs, rs));

    accumulated_rs = g_slist_prepend(accumulated_rs, rs);
}

/**
 * Periodic timer to flush the accumulated hits during the period and
 * dispatch them to the GUI.
 */
void
search_gui_flush(time_t now)
{
    GSList *sl;
    GSList *curs;
    static time_t last = 0;
	guint32 period;
    GSList *frozen = NULL;

	gui_prop_get_guint32_val(PROP_SEARCH_ACCUMULATION_PERIOD, &period);
    if (last && difftime(now, last) < period)
        return;

    last = now;

    if (accumulated_rs && (gui_debug >= 6)) {
        guint32 recs = 0;
        guint32 rscount = 0;

        for (sl = accumulated_rs; sl != NULL; sl = g_slist_next(sl)) {
            recs += ((results_set_t *)sl->data)->num_recs;
            rscount ++;
        }

        printf("flushing %d rsets (%d recs, %d recs avg)...\n",
            rscount, recs, recs / rscount);
    }

    for (curs = accumulated_rs; curs != NULL; curs = g_slist_next(curs)) {
        results_set_t *rs = curs->data;
        GSList *schl = g_slist_copy(rs->schl);

        /*
         * Dispatch to all searches and freeze display where necessary
         * remembering what was frozen.
         */
        for (sl = schl; sl != NULL; sl = g_slist_next(sl)) {
            search_t *sch;

            sch = search_gui_find((gnet_search_t) GPOINTER_TO_UINT(sl->data));

            /*
             * Since we keep results around for a while, the search may have
             * been closed until they get dispatched... so we need to check
             * that.
             *     --BLUE, 4/1/2004
             */

            if (sch) {
                search_gui_start_massive_update(sch);
                frozen = g_slist_prepend(frozen, sch);
                search_matched(sch, rs);
            } else if (gui_debug >= 6) printf(
				"no search for cached search result while dispatching\n");
        }

        /*
         * Some of the records might have not been used by searches, and need
         * to be freed.  If no more records remain, we request that the
         * result set be removed from all the dispatched searches, the last one
         * removing it will cause its destruction.
         */

        if (gui_debug >= 15)
            printf("cleaning phase\n");

        if (rs->refcount == 0) {
            search_gui_free_r_set(rs);
			g_slist_free(schl);
            continue;
        }

        search_gui_clean_r_set(rs);

        if (gui_debug >= 15)
            printf("trash phase\n");

        /*
         * If the record set does not contain any records after the cleansing,
         * we have only an empty shell left which we can safely remove from
         * all the searches.
         */

        if (rs->num_recs == 0) {
            for (sl = schl; sl; sl = sl->next) {
                search_t *sch = search_gui_find(
                    (gnet_search_t) GPOINTER_TO_UINT(sl->data));

                /*
                 * Since we keep results around for a while, the search may
                 * have been closed until they get dispatched... so we need to
                 * check that.
                 * --BLUE, 4/1/2004
                 */

                if (sch)
                    search_gui_remove_r_set(sch, rs);
                else if (gui_debug >= 6) printf(
					"no search for cached search result while cleaning\n");
            }
        }
		g_slist_free(schl);
    }

    /*
     * Unfreeze all we have frozen before.
     */
    for (sl = frozen; sl != NULL; sl = g_slist_next(sl)) {
		search_gui_end_massive_update((search_t *) sl->data);
    }
    g_slist_free(frozen);

    g_slist_free(accumulated_rs);
    accumulated_rs = NULL;
}

/**
 * Creates a new search based on the filename found and adds a filter
 * to it based on the sha1 hash if it has one or the exact filename if
 * it hasn't.
 *
 * @author Andrew Meredith <andrew@anvil.org>
 */
void
search_gui_add_targetted_search(gpointer data, gpointer unused_udata)
{
	const record_t *rec = data;
    search_t *new_search;
    rule_t *rule;

	(void) unused_udata;
    g_assert(rec != NULL);
    g_assert(rec->utf8_name != NULL);

    /* create new search item with search string set to filename */
    search_gui_new_search(rec->utf8_name, 0, &new_search);
    g_assert(new_search != NULL);

    if (rec->sha1) {
        rule = filter_new_sha1_rule(rec->sha1, rec->utf8_name,
            		filter_get_download_target(), RULE_FLAG_ACTIVE);
    } else {
        rule = filter_new_text_rule(rec->utf8_name, RULE_TEXT_EXACT, TRUE,
            		filter_get_download_target(), RULE_FLAG_ACTIVE);
    }
    g_assert(rule != NULL);

    filter_append_rule(new_search->filter, rule);
}

/**
 * Restart a search from scratch, clearing all existing content.
 */
void
search_gui_restart_search(search_t *sch)
{
	if (!sch->enabled)
		gui_search_set_enabled(sch, TRUE);
	search_gui_reset_search(sch);
	sch->items = sch->unseen_items = sch->hidden = 0;
	sch->tcp_qhits = sch->udp_qhits = 0;
	sch->skipped = sch->ignored = sch->auto_downloaded = sch->duplicates = 0;

	search_gui_update_items(sch);
	guc_search_set_create_time(sch->search_handle, tm_time());
	guc_search_update_items(sch->search_handle, sch->items);
	guc_search_reissue(sch->search_handle);
	search_gui_update_expiry(sch);
}

struct query {
	gchar *text;
	GList *neg;
};

/**
 *
 */
static void
search_gui_parse_text_query(const gchar *s, struct query *query)
{
	static const struct query zero_query;
	const gchar *p, *q;
	gchar *dst;

	g_assert(s);
	g_assert(query);

	*query = zero_query;
	dst = query->text = g_strdup(s);

	for (p = s; *p != '\0'; p = q) {
		gboolean neg;
		gint n;

		q = strchr(p, ' ');
		if (!q)
			q = strchr(p, '\0');

		/* Treat word after '-' (if preceded by a blank) as negative pattern */
		neg = *p == '-' && (p != s && ' ' == *(p - 1)) && p[1] != '-';
		if (neg)
			p++;

		n = q - p;
		g_assert(n >= 0);
		if (neg) {
			if (*p != '\0') {
				gchar *w;

				w = g_strndup(p, n + 1);
				g_strchomp(w);
				if (gui_debug)
					g_message("neg: \"%s\"", w);
				query->neg = g_list_prepend(query->neg, w);
			}
		} else {
			if (dst != query->text)
				*dst++ = ' ';

			g_strlcpy(dst, p, n + 1);
			if (gui_debug)
				g_message("pos: \"%s\"", dst);
			dst += n;
		}

		if (*q != '\0')
			q = skip_ascii_blanks(++q);
	}

	query->neg = g_list_reverse(query->neg);
}

/**
 * Parses a query string as entered by the user.
 *
 * @param	querystr must point to the query string.
 * @param	**rules
 * @param	*error will point to an descriptive error message on failure.
 * @return	NULL if the query was not valid. Otherwise, the decoded query
 *			is returned.
 */
const gchar *
search_gui_parse_query(const gchar *querystr, GList **rules,
	const gchar **error)
{
	static const gchar urnsha1[] = "urn:sha1:";
	static gchar query[512];
	struct query qs;

	g_assert(querystr != NULL);
	g_assert(error != NULL);

	*error = NULL;
	if (rules)
		*rules = NULL;

	if (!utf8_is_valid_string(querystr)) {
		*error = _("The query string is not UTF-8 encoded");
		return NULL;
	}
	
	/*
	 * If the text is a magnet link we extract the SHA1 urn
	 * and put it back into the search field string so that the
	 * code for urn searches below can handle it.
	 *		--DBelius   11/11/2002
	 */

	if (utf8_strlcpy(query, querystr, sizeof query) >= sizeof query) {
		*error = _("The entered query is too long");
		return NULL;
	}

	if (is_strcaseprefix(query, "magnet:")) {
		const gchar *s;

		/* FIXME: strcasestr() is a hack, parse this properly */
		s = ascii_strcasestr(query, urnsha1);
		if (NULL != s) {
			gchar raw[SHA1_RAW_SIZE];

			if (urn_get_sha1(s, raw)) {
				concat_strings(query, sizeof query,
					urnsha1, sha1_base32(raw), (void *) 0);
				return query;
			} else {
				*error = _("The SHA1 of the magnet is not validly encoded");
				return NULL;		/* Entry refused */
			}
		}

		*error = _("Cannot parse magnet");
		return NULL;
	} else if (is_strcaseprefix(query, urnsha1)) {
		gchar raw[SHA1_RAW_SIZE];
		gchar *b = is_strcaseprefix(query, urnsha1);

		/*
		 * If string begins with "urn:sha1:", then it's an URN search.
		 * Validate the base32 representation, and if not valid, beep
		 * and refuse the entry.
		 *		--RAM, 28/06/2002
		 */

		if (strlen(b) >= SHA1_BASE32_SIZE) {

			if (base32_decode_into(b, SHA1_BASE32_SIZE, raw, sizeof raw))
				return query;

			/*
		 	 * If they gave us an old base32 representation, convert it to
		 	 * the new one on the fly.
		 	 */
			if (base32_decode_old_into(b, SHA1_BASE32_SIZE, raw, sizeof raw)) {
				gchar b32[SHA1_BASE32_SIZE + 1];

				base32_encode_into(raw, sizeof raw, b32, sizeof b32);
				b32[sizeof b32 - 1] = '\0';
				concat_strings(query, sizeof query, urnsha1, b32, (void *) 0);
				return query;
			}

		}

		/*
	 	 * Entry refused.
	 	 */
		*error = _("The SHA1 query is not validly encoded");
		return NULL;
	}

	search_gui_parse_text_query(query, &qs);
	g_assert(qs.text != NULL);
	g_strlcpy(query, qs.text, sizeof query);
	if (qs.neg) {
		filter_t *target;
		GList *l;

		target = filter_get_drop_target();
		g_assert(target != NULL);
		for (l = qs.neg; l != NULL; l = g_list_next(l)) {
			gchar *w;

			w = l->data;
			g_assert(w != NULL);
			if (rules) {
				/* recycle this list */
				l->data = filter_new_text_rule(w, RULE_TEXT_WORDS, FALSE,
							target, RULE_FLAG_ACTIVE);
			}
			G_FREE_NULL(w);
		}
	}

	if (rules)
		*rules = qs.neg;
	else
		g_list_free(qs.neg);

	G_FREE_NULL(qs.text);

	return query;
}

/**
 * Initializes a new filter for the search ``sch'' and adds the rules
 * from the rule list ``rules'' (if any).
 *
 * @param sch a new search
 * @param rules a GList with items of type (rule_t *). ``rules'' may be NULL.
 */
void
search_gui_filter_new(search_t *sch, GList *rules)
{
	GList *l;

	g_assert(sch != NULL);

  	filter_new_for_search(sch);
	g_assert(sch->filter != NULL);

	for (l = rules; l != NULL; l = g_list_next(l)) {
		rule_t *r;

		r = l->data;
		g_assert(r != NULL);
		filter_append_rule(sch->filter, r);
	}
}

/**
 * Adds some indendation to XML-like text. The input text is assumed to be
 * "flat" and well-formed. If these assumptions fail, the output might look
 * worse than the input.
 *
 * @param s the string to format.
 * @return a newly allocated string.
 */
gchar *
search_xml_indent(const gchar *s)
{
	GString *gs;
	const gchar *p, *q;
	guint i, depth = 0;
	gchar *res;

	gs = g_string_new("");

	q = s;
	for (;;) {

		q = skip_ascii_spaces(q);

		/* Find the start of the tag */
		p = strchr(q, '<');
		if (!p)
			p = strchr(q, '\0');

		/* Append the text between the previous and the current tag, if any */
		if (p != q)
			gs = g_string_append_len(gs, q, p - q);
		if ('\0' == *p)
			break;

		/* Find the end of the tag */
		q = strchr(p, '>');
		if (!q)
			q = strchr(p, '\0');

		if (p[1] != '/') {
			/* Something like <start> */

			for (i = 0; i < depth; i++)
				gs = g_string_append_c(gs, '\t');
			gs = g_string_append_len(gs, p, (q - p) + 1);

			/* Check for tags like <tag/> */
			if ('/' != *(q - 1)) {
				depth++;
			}
		} else {
			/* Something like </end> */

			if (depth > 0) {
				depth--;
			}

			for (i = 0; i < depth; i++)
				gs = g_string_append_c(gs, '\t');
			gs = g_string_append_len(gs, p, (q - p) + 1);
		}
		gs = g_string_append(gs, "\n");

		if ('>' == *q)
			q++;
	}

	res = gs->str;
	g_string_free(gs, FALSE);		/* glib1.x returns nothing here */

	return res;
}

/**
 * Adds a search string to the search history combo. Makes
 * sure we do not get more than 10 entries in the history.
 * Also makes sure we don't get duplicate history entries.
 * If a string is already in history and it's added again,
 * it's moved to the beginning of the history list.
 */
static void
search_gui_history_add(const gchar *s)
{
    GList *new_hist = NULL, *cur_hist = list_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if (n < 9 && 0 != g_ascii_strcasecmp(s, cur_hist->data)) {
            /* copy up to the first 9 items */
            new_hist = g_list_prepend(new_hist, cur_hist->data);
            n++;
        } else {
            /* and free the rest */
            G_FREE_NULL(cur_hist->data);
        }
        cur_hist = g_list_next(cur_hist);
    }
	new_hist = g_list_reverse(new_hist);

    /* put the new item on top */
    new_hist = g_list_prepend(new_hist, g_strdup(s));

    /* set new history */
    gtk_combo_set_popdown_strings(
        GTK_COMBO(lookup_widget(main_window, "combo_search")),
        new_hist);

    /* free old list structure */
    g_list_free(list_search_history);

    list_search_history = new_hist;
}

void
search_gui_new_search_entered(void)
{
	GtkWidget *widget;
	gchar *text;
	
    widget = lookup_widget(main_window, "entry_search");
   	text = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(widget), 0, -1));
    g_strstrip(text);
    if ('\0' != text[0]) {
        filter_t *default_filter;
        search_t *search;
        gboolean res;

        /*
         * It's important gui_search_history_add is called before
         * new_search, otherwise the search entry will not be
         * cleared.
         *      --BLUE, 04/05/2002
         */
        search_gui_history_add(text);

        /*
         * We have to capture the selection here already, because
         * new_search will trigger a rebuild of the menu as a
         * side effect.
         */
        default_filter = option_menu_get_selected_data(GTK_OPTION_MENU(
					lookup_widget(main_window, "optionmenu_search_filter")));

		res = search_gui_new_search(text, 0, &search);

        /*
         * If we should set a default filter, we do that.
         */
        if (res && (default_filter != NULL)) {
            rule_t *rule;
		   
			rule = filter_new_jump_rule(default_filter, RULE_FLAG_ACTIVE);

            /*
             * Since we don't want to distrub the shadows and
             * do a "force commit" without the user having pressed
             * the "ok" button in the dialog, we add the rule
             * manually.
             */
            search->filter->ruleset =
					g_list_append(search->filter->ruleset, rule);
            rule->target->refcount++;
        }

        if (!res)
        	gdk_beep();
    }

	gtk_widget_grab_focus(widget);
	G_FREE_NULL(text);
}


/* vi: set ts=4 sw=4 cindent: */
