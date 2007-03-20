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

RCSID("$Id$")

#include "search.h"
#include "settings.h"
#include "gtk-missing.h"

#include "search_xml.h"
#include <libxml/parser.h>

#include "gtk/statusbar.h"

#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/core/downloads.h"
#include "if/core/guid.h"
#include "if/core/sockets.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/base16.h"
#include "lib/base32.h"
#include "lib/file.h"
#include "lib/fuzzy.h"
#include "lib/glib-missing.h"
#include "lib/magnet.h"
#include "lib/slist.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/zalloc.h"
#include "lib/override.h"	/* Must be the last header included */

static search_t *current_search  = NULL; /**< The search currently displayed */

static zone_t *rs_zone;		/**< Allocation of results_set */
static zone_t *rc_zone;		/**< Allocation of record */

static const gchar search_file[] = "searches"; /**< "old" file to searches */

static slist_t *accumulated_rs = NULL;
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

static struct {
	const gchar * const spec;
	const enum gui_color id;
	GdkColor color;
} colors[] = {
	{ "#000000",	GUI_COLOR_DEFAULT,		{ 0, 0, 0, 0 } },
	{ "#326732",	GUI_COLOR_DOWNLOADING,	{ 0, 0, 0, 0 } },
	{ "#5F007F",	GUI_COLOR_HOSTILE,		{ 0, 0, 0, 0 } },
	{ "#7F7F7F",	GUI_COLOR_IGNORED,		{ 0, 0, 0, 0 } },
	{ "#001F7F",	GUI_COLOR_MARKED, 		{ 0, 0, 0, 0 } },
	{ "#FC000D",	GUI_COLOR_MAYBE_SPAM, 	{ 0, 0, 0, 0 } },
	{ "#7f0000",	GUI_COLOR_SPAM, 		{ 0, 0, 0, 0 } },
	{ "#7E5029",	GUI_COLOR_UNREQUESTED,	{ 0, 0, 0, 0 } },
};

GdkColor *
gui_color_get(const enum gui_color id)
{
	g_assert((guint) id <= NUM_GUI_COLORS);
	return &colors[(guint) id].color;
}

void
gui_color_set(const enum gui_color id, GdkColor *color)
{
	g_assert((guint) id <= NUM_GUI_COLORS);
	g_return_if_fail(color);
	colors[(guint) id].color = *color;
}

void
gui_color_init(GtkWidget *widget)
{
    GdkColormap *cmap;
	guint i;

	STATIC_ASSERT(NUM_GUI_COLORS == G_N_ELEMENTS(colors));
	cmap = gdk_colormap_get_system();
    g_assert(cmap);

	for (i = 0; i < NUM_GUI_COLORS; i++) {
		GdkColor color;

		g_assert(colors[i].id == i);
		gdk_color_parse(colors[i].spec, &color);
		gdk_colormap_alloc_color(cmap, &color, FALSE, TRUE);
		gui_color_set(colors[i].id, &color);
	}
	if (widget) {
		gui_color_set(GUI_COLOR_DEFAULT,
			&gtk_widget_get_style(GTK_WIDGET(widget))->fg[GTK_STATE_NORMAL]);
	}
}

search_t *
search_gui_get_current_search(void)
{
	return current_search;
}

void
search_gui_forget_current_search(void)
{
	current_search = NULL;
}

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
	guint idx = 0, n = 0;

	option_menu = GTK_OPTION_MENU(
					gui_main_window_lookup("option_menu_searches"));	
	menu = GTK_MENU(gtk_menu_new());

	iter = g_list_last(deconstify_gpointer(search_gui_get_searches()));
	for (/* NOTHING */; iter != NULL; n++, iter = g_list_previous(iter)) {
		search_t *search = iter->data;
		const gchar *query;
		GtkWidget *item;
		gchar *name;

		if (search_gui_get_current_search() == search) {
			idx = n;
		}
		query = search_gui_query(search);
		if (search_gui_is_browse(search)) {
			name = g_strconcat("browse:", query, (void *) 0);
		} else if (search_gui_is_passive(search)) {
			name = g_strconcat("passive:", query, (void *) 0);
		} else if (search_gui_is_local(search)) {
			name = g_strconcat("local:", query, (void *) 0);
		} else {
			name = g_strdup(query);
		}

		/*
		 * Limit the title length of the menu item to a certain amount
		 * of characters (not bytes) because overlong query strings
		 * would cause a very wide menu.
		 */
		{
			static const size_t max_chars = 41; /* Long enough for urn:sha1: */
			const gchar ellipse[] = "[...]";
			gchar title[max_chars * 4 + sizeof ellipse];
			const gchar *ui_query;
			size_t title_size;

			ui_query = lazy_utf8_to_ui_string(name);
			title_size = sizeof title - sizeof ellipse;
			utf8_strcpy_max(title, title_size, ui_query, max_chars);
			if (strlen(title) < strlen(ui_query)) {
				strncat(title, ellipse, CONST_STRLEN(ellipse));
			}

			item = gtk_menu_item_new_with_label(title);
		}
		G_FREE_NULL(name);
	
		gtk_widget_show(item);
		gtk_object_set_user_data(GTK_OBJECT(item), search);
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

	if (n > 0) {
		idx = n - idx - 1;
		gtk_option_menu_set_history(option_menu, idx);
	}
}

void
search_gui_option_menu_searches_select(const search_t *sch)
{
	option_menu_select_item_by_data(
		GTK_OPTION_MENU(gui_main_window_lookup("option_menu_searches")),
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
 *
 * @note `*search' may be set to NULL even on success. You have to check this
 *		 explicitely.
 */
gboolean
search_gui_new_search(const gchar *query, flag_t flags, search_t **search)
{
    guint32 timeout;
	gboolean ret;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

	if (!(SEARCH_F_PASSIVE & flags))
		query = lazy_ui_string_to_utf8(query);

    ret = search_gui_new_search_full(query, tm_time(), search_lifetime, timeout,
			search_sort_default_column, search_sort_default_order,
			flags | SEARCH_F_ENABLED, search);

	return ret;
}


/**
 * Free the alternate locations held within a file record.
 */
static void
search_gui_free_alt_locs(record_t *rc)
{
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);

	gnet_host_vec_free(&rc->alt_locs);
}

/**
 * Clone the proxies list given by the core.
 */
gnet_host_vec_t *
search_gui_proxies_clone(gnet_host_vec_t *v)
{
	return v ? gnet_host_vec_copy(v) : NULL;
}

/**
 * Free the cloned vector of host.
 */
static void
search_gui_host_vec_free(gnet_host_vec_t *v)
{
	g_assert(v != NULL);
	gnet_host_vec_free(&v);
}

/**
 * Free the push proxies held within a result set.
 */
void
search_gui_free_proxies(results_set_t *rs)
{
	g_assert(rs);

	if (rs->proxies) {
		search_gui_host_vec_free(rs->proxies);
		rs->proxies = NULL;
	}
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

	atom_str_free_null(&rc->name);
	atom_str_free_null(&rc->utf8_name);
    atom_str_free_null(&rc->ext);
	atom_str_free_null(&rc->tag);
	atom_str_free_null(&rc->xml);
	atom_str_free_null(&rc->info);
	atom_sha1_free_null(&rc->sha1);
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
	if (p) {
		p++;
	}

	rw = g_strlcpy(ext, p ? p : "", sizeof ext);
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
		record_t *rc = sl->data;

		g_assert(rc->results_set == rs);
		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
		if (rc->refcount == 0)
			sl_remove = g_slist_prepend(sl_remove, rc);
    }

    /*
     * Remove empty searches from record set.
     */
	for (sl = sl_remove; sl != NULL; sl = g_slist_next(sl)) {
		record_t *rc = sl->data;

		rc->results_set = NULL;
		rs->records = g_slist_remove(rs->records, rc);
		search_gui_free_record(rc);
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
		record_t *rc = sl->data;

		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->results_set == rs);
		rc->results_set = NULL;
		search_gui_free_record(rc);
		g_assert(rs->num_recs > 0);
		rs->num_recs--;
	}

	atom_guid_free_null(&rs->guid);
	atom_str_free_null(&rs->version);
	atom_str_free_null(&rs->hostname);
	search_gui_free_proxies(rs);

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
		search_t *sch = l->data;

		if (NULL != sch->r_sets && hash_list_contains(sch->r_sets, rs, NULL)) {
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
	rs->records = g_slist_remove(rs->records, rc);
	search_gui_free_record(rc);
	g_assert(rs->num_recs > 0);
	rs->num_recs--;

	g_assert((rs->num_recs > 0) ^ (!rs->records));

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
		hash_list_free(&sch->r_sets);
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
	gpointer orig_key, dummy;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);

	if (g_hash_table_lookup_extended(sch->dups, rc, &orig_key, &dummy)) {
		record_t *old_rc = orig_key;

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
		 * XXX change it.  We have a new route anyway, since we just got a
		 * XXX match!
		 */

		if (rc->file_index != old_rc->file_index) {
			if (gui_debug) {
				g_warning("Index changed from %u to %u at %s for %s",
					old_rc->file_index, rc->file_index,
					guid_hex_str(rc->results_set->guid), rc->name);
			}

			guc_download_index_changed(
				rc->results_set->addr,	/* This is for optimizing lookups */
				rc->results_set->port,
				rc->results_set->guid,	/* This is for formal identification */
				old_rc->file_index,
				rc->file_index);
			old_rc->file_index = rc->file_index;
		}

		return TRUE;		/* yes, it's a duplicate */
	} else {
		return FALSE;
	}
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
            if (gui_debug >= 15) {
                g_message("search [%s] matched handle %x",
					search_gui_query(s), sh);
			}
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

static const gchar *
search_gui_get_info(const record_t *rc, const gchar *vinfo)
{
  	gchar info[1024];
	size_t rw = 0;

	info[0] = '\0';

	if (rc->tag) {
		const size_t MAX_TAG_SHOWN = 60; /**< Show only first chars of tag */
		size_t size;

		/*
		 * We want to limit the length of the tag shown, but we don't
		 * want to loose that information.	I imagine to have a popup
		 * "show file info" one day that will give out all the
		 * information.
		 *				--RAM, 09/09/2001
		 */

		size = 1 + strlen(rc->tag);
		size = MIN(size, MAX_TAG_SHOWN + 1);
		size = MIN(size, sizeof info);
		rw = utf8_strlcpy(info, lazy_unknown_to_ui_string(rc->tag), size);
	}
	if (vinfo) {
		g_assert(rw < sizeof info);
		rw += gm_snprintf(&info[rw], sizeof info - rw, "%s%s",
				info[0] != '\0' ? "; " : "", vinfo);
	}

	if (rc->alt_locs != NULL) {
		gint count = gnet_host_vec_count(rc->alt_locs);
		g_assert(rw < sizeof info);
		rw += gm_snprintf(&info[rw], sizeof info - rw, "%salt",
			info[0] != '\0' ? ", " : "");
		if (count > 1)
			rw += gm_snprintf(&info[rw], sizeof info - rw, "(%d)", count);
	}

	return info[0] != '\0' ? atom_str_get(info) : NULL;
}

/**
 * Create a new GUI record within `rs' from a Gnutella record.
 */
record_t *
search_gui_create_record(results_set_t *rs, gnet_record_t *r)
{
    static const record_t zero_record;
    record_t *rc;

    g_assert(r != NULL);
    g_assert(rs != NULL);

    rc = zalloc(rc_zone);

	*rc = zero_record;
	rc->magic = RECORD_MAGIC;
    rc->results_set = rs;

    rc->size = r->size;
    rc->file_index = r->file_index;
	if (r->sha1) {
    	rc->sha1 = atom_sha1_get(r->sha1);
	}
	if (r->xml) {
    	rc->xml = atom_str_get(r->xml);
	}
	if (r->tag) {
    	rc->tag = atom_str_get(r->tag);
	}
   	rc->flags = r->flags;
   	rc->create_time = r->create_time;
	rc->name = atom_str_get(r->name);
	
	{
		const gchar *utf8_name, *name;
		gchar *to_free;

		if (r->path) {
			to_free = make_pathname(r->path, r->name);
			name = to_free;
		} else {
			to_free = NULL;
			name = r->name;
		}
		if (ST_LOCAL & rs->status) {
			utf8_name = name;
		} else {
			utf8_name = lazy_unknown_to_utf8_normalized(name,
							UNI_NORM_GUI, &rc->charset);
			if (utf8_name == name || 0 == strcmp("UTF-8", rc->charset)) {
				rc->charset = NULL;
			}
		}
		rc->utf8_name = atom_str_get(utf8_name);
		G_FREE_NULL(to_free);
	}

	{
		const gchar *ext = search_gui_get_filename_extension(rc->utf8_name);
		rc->ext = ext ? atom_str_get(ext) : NULL;
	}

	if (NULL != r->alt_locs) {
		rc->alt_locs = gnet_host_vec_copy(r->alt_locs);
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
	rs->query = r_set->query ? atom_str_get(r_set->query) : NULL;
	rs->country = r_set->country;
	rs->last_hop = r_set->last_hop;
	rs->hops = r_set->hops;
	rs->ttl = r_set->ttl;

    rs->num_recs = 0;
    rs->records = NULL;
	rs->proxies = search_gui_proxies_clone(r_set->proxies);

    for (sl = r_set->records; sl != NULL; sl = g_slist_next(sl)) {
		gnet_record_t *grc = sl->data;

		if (grc->flags & SR_DONT_SHOW) {
			ignored++;
		} else {
        	record_t *rc;
		   
			rc = search_gui_create_record(rs, grc);
			rs->records = g_slist_prepend(rs->records, rc);
			rs->num_recs++;
		}
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
	accumulated_rs = slist_new();

	label_items_found = GTK_LABEL(
		gui_main_window_lookup("label_items_found"));
	label_search_expiry = GTK_LABEL(
		gui_main_window_lookup("label_search_expiry"));
	
    gtk_combo_set_case_sensitive(
        GTK_COMBO(gui_main_window_lookup("combo_search")), TRUE);
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
	
	/* Discard pending accumulated search results */
    search_gui_flush(tm_time(), TRUE);
}

/**
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
void
search_gui_check_alt_locs(results_set_t *rs, record_t *rc)
{
	gnet_host_vec_t *alt = rc->alt_locs;
	gint i, n;

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
	g_assert(alt != NULL);
	g_assert(rs->proxies == NULL);	/* Since we downloaded record already */

	n = gnet_host_vec_count(alt);
	for (i = 0; i < n; i++) {
		gnet_host_t host;
		host_addr_t addr;
		guint16 port;

		host = gnet_host_vec_get(alt, i);
		addr = gnet_host_get_addr(&host);
		port = gnet_host_get_port(&host);
		if (port > 0 && host_addr_is_routable(addr)) {
			guc_download_auto_new(rc->name, rc->size, URN_INDEX,
				addr, port, blank_guid, rs->hostname,
				rc->sha1, rs->stamp, TRUE, NULL, NULL, 0);
		}
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
 * @return a string showing the route information for the given
 *         result record. The return string uses a static buffer.
 * @note   If the result is from a local search or browse host, NULL
 *		   is returned.
 */
const gchar *
search_gui_get_route(const record_t *rc)
{
	const results_set_t *rs;
	
	g_assert(rc);
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0 && rc->refcount < INT_MAX);
	
	rs = rc->results_set;
	g_assert(rs);

	if ((ST_LOCAL | ST_BROWSE) & rs->status) {
		return NULL;
	} else {
		static gchar addr_buf[128];
		size_t n;
		
		n = host_addr_to_string_buf(rs->last_hop, addr_buf, sizeof addr_buf);
		if ((ST_GOOD_TOKEN & rs->status) && n < sizeof addr_buf) {
			g_strlcpy(&addr_buf[n], "+", sizeof addr_buf - n);
		}
		return addr_buf;
	}
}

enum gui_color
search_gui_color_for_record(const record_t * const rc)
{
	const results_set_t *rs = rc->results_set;
	
	if (SR_SPAM & rc->flags) {
		return GUI_COLOR_SPAM;
	} else if (ST_HOSTILE & rs->status) {
		return GUI_COLOR_HOSTILE;
	} else if (
		(SR_SPAM & rc->flags) ||
		((ST_SPAM & rs->status) && !(ST_BROWSE & rs->status))
	) {
		return GUI_COLOR_MAYBE_SPAM;
	} else if (rs->status & ST_UNREQUESTED) {
		return GUI_COLOR_UNREQUESTED;
	} else if (rc->flags & (SR_IGNORED | SR_OWNED | SR_SHARED)) {
		return GUI_COLOR_IGNORED;
	} else if (rc->flags & (SR_DOWNLOADED | SR_PARTIAL)) {
		return GUI_COLOR_DOWNLOADING;
	} else {
		return GUI_COLOR_DEFAULT;
	}
}

/**
 * Called to dispatch results to the search window.
 */
static void
search_matched(search_t *sch, results_set_t *rs)
{
	guint32 old_items = sch->items;
	gboolean skip_records;		/* Shall we skip those records? */
	GString *vinfo = g_string_sized_new(40);
    GSList *sl;
    gboolean send_pushes;
    gboolean is_firewalled;
	guint i;
	guint32 flags = 0, results_kept = 0;
	guint32 max_results;

    g_assert(sch != NULL);
    g_assert(rs != NULL);

	max_results = search_gui_is_browse(sch)
		? browse_host_max_results : search_max_results;

	for (i = 0; i < G_N_ELEMENTS(open_flags); i++) {
		if (rs->status & open_flags[i].flag) {
			if (vinfo->len)
				g_string_append(vinfo, ", ");
			g_string_append(vinfo, _(open_flags[i].status));
		}
	}

	if (!(rs->status & ST_PARSED_TRAILER)) {
		if (vinfo->len)
			g_string_append(vinfo, ", ");
		g_string_append(vinfo, _("<unparsed>"));
	}

	if (rs->status & ST_UDP) {
		sch->udp_qhits++;
	} else {
		sch->tcp_qhits++;
	}

	if (rs->status & ST_TLS) {
		g_string_append(vinfo, vinfo->len ? ", TLS" : "TLS");
	}
	if (rs->status & ST_BH) {
		if (vinfo->len > 0) {
			g_string_append(vinfo, ", ");
		}
		g_string_append(vinfo, _("browsable"));
	}
	
	flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;

	/*
	 * If we're firewalled, or they don't want to send pushes, then don't
	 * bother displaying results if they need a push request to succeed.
	 *		--RAM, 10/03/2002
	 */
    gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
    gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &is_firewalled);

	flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
	if (ST_LOCAL & rs->status) {
		skip_records = FALSE;
	} else {
		skip_records = (!send_pushes || is_firewalled) && (flags & SOCK_F_PUSH);
	}

	if (gui_debug > 6)
		printf("search_matched: [%s] got hit with %d record%s (from %s) "
			"need_push=%d, skipping=%d\n",
			search_gui_query(sch), rs->num_recs, rs->num_recs == 1 ? "" : "s",
			host_addr_port_to_string(rs->addr, rs->port),
			(flags & SOCK_F_PUSH), skip_records);

  	for (sl = rs->records; sl && !skip_records; sl = g_slist_next(sl)) {
		record_t *rc = sl->data;
		enum gui_color color;

		g_assert(rc->magic == RECORD_MAGIC);
		g_assert(rc->refcount >= 0);

        if (gui_debug > 7)
            printf("search_matched: [%s] considering %s (%s)\n",
				search_gui_query(sch), rc->name, vinfo->str);

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
	
		if (search_gui_result_is_dup(sch, rc)) {
			sch->duplicates++;
			continue;
		}

		color = GUI_COLOR_DEFAULT;
		if (0 == (ST_LOCAL & rs->status)) {
			enum filter_prop_state filter_state, filter_download;
			gpointer filter_udata;
			gboolean is_hostile;
			gint spam_score;

			if (skip_records) {
				sch->skipped++;
				continue;
			}

			is_hostile = ST_HOSTILE & rs->status;
			spam_score = ST_SPAM & rs->status ? 1 : 0;
			spam_score |= SR_SPAM & rc->flags ? 2 : 0;

			if (
				rc->size == 0 ||
				(!rc->sha1 && search_discard_hashless) ||
				((spam_score > 1 || is_hostile) && search_discard_spam)
			) {
				sch->ignored++;
				continue;
			}

			g_assert(rc->refcount >= 0);
			{
        		filter_result_t *flt_result;
				
				flt_result = filter_record(sch, rc);
				filter_state = flt_result->props[FILTER_PROP_DISPLAY].state;
				filter_udata = flt_result->props[FILTER_PROP_DISPLAY].user_data;
				filter_download = flt_result->props[FILTER_PROP_DOWNLOAD].state;
				filter_free_result(flt_result);
			}
			g_assert(rc->refcount >= 0);

			/*
			 * Check for FILTER_PROP_DOWNLOAD:
			 */
			if (
				!(SR_DOWNLOADED & rc->flags) && 
				!is_hostile &&
				0 == spam_score &&
				FILTER_PROP_STATE_DO == filter_download
		   ) {
				guc_download_auto_new(rc->name, rc->size, rc->file_index,
						rs->addr, rs->port, rs->guid, rs->hostname, rc->sha1,
						rs->stamp, TRUE, NULL, rs->proxies, flags);

				search_gui_free_proxies(rs);

				rc->flags |= SR_DOWNLOADED;
				sch->auto_downloaded++;
			}

			/*
			 * Don't show something we downloaded if they don't want it.
			 */

			if ((SR_DOWNLOADED & rc->flags) && search_hide_downloaded) {
				results_kept++;
				sch->hidden++;
				continue;
			}

			/*
			 * We start with FILTER_PROP_DISPLAY:
			 */
			if (FILTER_PROP_STATE_DONT == filter_state && !filter_udata) {
				sch->ignored++;
				continue;
			}

			/* Count as kept even if max results but not spam */
			if (0 == spam_score && !is_hostile) {
				results_kept++;
			}

			if (sch->items >= max_results) {
				sch->ignored++;
				continue;
			}
			
			if (
				FILTER_PROP_STATE_DONT == filter_state &&
				GINT_TO_POINTER(1) == filter_udata
			) {
				color = GUI_COLOR_MARKED;
			}
		}
		sch->items++;

		g_assert(rc->refcount >= 0);
		g_hash_table_insert(sch->dups, rc, GINT_TO_POINTER(1));
		g_assert(rc->refcount >= 0);
		search_gui_ref_record(rc);
		g_assert(rc->refcount >= 1);

		if (0 == (ST_LOCAL & rs->status)) {
			rc->info = search_gui_get_info(rc,
								vinfo->len ? vinfo->str : NULL);
		}
		if (GUI_COLOR_MARKED != color) {
			color = search_gui_color_for_record(rc);
		}
		search_gui_add_record(sch, rc, color);
	}

    /*
     * A result set may not be added more then once to a search!
     */

	if (NULL != sch->r_sets)
    	g_assert(!hash_list_contains(sch->r_sets, rs, NULL));
	else
		sch->r_sets = hash_list_new(NULL, NULL);

	/* Adds the set to the list */
	hash_list_prepend(sch->r_sets, rs);
	rs->refcount++;
   	g_assert(hash_list_contains(sch->r_sets, rs, NULL));
	g_assert(hash_list_head(sch->r_sets) == rs);

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

	if (sch->items >= max_results && !search_gui_is_passive(sch))
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
	
	if (sch && !search_gui_is_passive(sch))
		expired = guc_search_is_expired(sch->search_handle);

	return expired;
}

gboolean
search_gui_update_expiry(const struct search *sch)
{
	gboolean expired = FALSE;

    if (sch) {
		if (search_gui_is_passive(sch)) {
   			gtk_label_printf(label_search_expiry, "%s", _("Passive search"));
		} else if (search_gui_is_enabled(sch)) {
			expired = search_gui_is_expired(sch);
			
			if (expired) {
        		gtk_label_printf(label_search_expiry, "%s", _("Expired"));
			} else {
				guint lt;

				lt = 3600 * guc_search_get_lifetime(sch->search_handle);
				if (lt) {
					time_t ct, start;
					gint d;
					
					gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);
					ct = guc_search_get_create_time(sch->search_handle);
					
					d = delta_time(tm_time(), ct);
					d = MAX(0, d);
					d = (guint) d < lt ? lt - d : 0;
					gtk_label_printf(label_search_expiry,
						_("Expires in %s"), short_time(d));
				} else {
        			gtk_label_printf(label_search_expiry, "%s",
						_("Expires with this session"));
				}
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

#if 0
	/* XXX: Use a hash list or remove the assertion? */
    g_assert(!slist_contains_identical(accumulated_rs, rs));
#endif

    slist_append(accumulated_rs, rs);
}

static void
search_gui_flush_info(void)
{
    guint rs_count = slist_length(accumulated_rs);

    if (gui_debug >= 6 && rs_count > 0) {
        const results_set_t *rs;
		slist_iter_t *iter;
        guint recs = 0;

		iter = slist_iter_before_head(accumulated_rs);
		while (NULL != (rs = slist_iter_next(iter))) {
            recs += rs->num_recs;
        }
		slist_iter_free(&iter);

        g_message("flushing %u rsets (%u recs, %u recs avg)...",
            rs_count, recs, recs / rs_count);
    }
}

/**
 * Periodic timer to flush the accumulated hits during the period and
 * dispatch them to the GUI.
 */
void
search_gui_flush(time_t now, gboolean force)
{
    static time_t last;
	slist_iter_t *iter;
    GSList *frozen = NULL, *sl;
	tm_t t0, t1, dt;

	if (force) {
		guint32 period;

		gui_prop_get_guint32_val(PROP_SEARCH_ACCUMULATION_PERIOD, &period);
		if (last && delta_time(now, last) < (time_delta_t) period)
			return;
	}
    last = now;
	
	search_gui_flush_info();
	tm_now_exact(&t0);

	iter = slist_iter_on_head(accumulated_rs);
	while (slist_iter_has_item(iter)) {
        results_set_t *rs;
        GSList *schl;

        rs = slist_iter_current(iter);
		slist_iter_remove(iter);
        schl = g_slist_copy(rs->schl);

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
				if (!g_slist_find(frozen, sch)) {
                	search_gui_start_massive_update(sch);
                	frozen = g_slist_prepend(frozen, sch);
				}
                search_matched(sch, rs);
            } else if (gui_debug >= 6) {
				g_message(
					"no search for cached search result while dispatching");
			}
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
            for (sl = schl; sl; sl = g_slist_next(sl)) {
                search_t *sch;
			   
				sch = search_gui_find(GPOINTER_TO_UINT(sl->data));

                /*
                 * Since we keep results around for a while, the search may
                 * have been closed until they get dispatched... so we need to
                 * check that.
                 * --BLUE, 4/1/2004
                 */

                if (sch) {
                    search_gui_remove_r_set(sch, rs);
				} else if (gui_debug >= 6) {
					g_message(
						"no search for cached search result while cleaning");
				}
            }
        }
		g_slist_free(schl);
    }
	slist_iter_free(&iter);

    /*
     * Unfreeze all we have frozen before.
     */
    for (sl = frozen; sl != NULL; sl = g_slist_next(sl)) {
		search_gui_end_massive_update(sl->data);
    }
    g_slist_free(frozen);
	frozen = NULL;

	if (gui_debug) {
		tm_now_exact(&t1);
		tm_elapsed(&dt, &t1, &t0);
		g_message("dispatching results took %lu ms", (gulong) tm2ms(&dt));
	}

	search_gui_flush_queues();
}

/**
 * Parse the given query text and looks for negative patterns. That means
 * "blah -zadda" will be converted to "blah" and a word filter is added
 * to discard results matching "zadda". A minus followed by a space or
 * another minus is always used literally.
 */
static void
search_gui_parse_text_query(const gchar *text, struct query *query)
{
	const gchar *p, *q;
	gchar *dst;

	g_assert(text);
	g_assert(query);
	g_assert(NULL == query->text);

	query->text = g_strdup(text);
	dst = query->text;

	for (p = text; *p != '\0'; p = q) {
		gboolean neg;
		size_t n;

		q = strchr(p, ' ');
		if (!q)
			q = strchr(p, '\0');

		/* Treat word after '-' (if preceded by a blank) as negative pattern */
		if (
			'-' == *p &&
			p != text &&
			is_ascii_blank(*(p - 1)) &&
			p[1] != '-' &&
			!is_ascii_blank(p[1])
		) {
			neg = TRUE;
			p++;
		} else {
			neg = FALSE;
		}

		n = q - p;
		if (neg && n > 0) {
			filter_t *target;
			gchar *word;

			word = g_strndup(p, n + 1);
			g_strchomp(word);
			if (gui_debug) {
				g_message("neg: \"%s\"", word);
			}

			target = filter_get_drop_target();
			g_assert(target != NULL);

			query->rules = g_list_prepend(query->rules,
								filter_new_text_rule(word, RULE_TEXT_WORDS,
									FALSE, target, RULE_FLAG_ACTIVE));
			G_FREE_NULL(word);
		} else {
			if (dst != query->text) {
				*dst++ = ' ';
			}
			g_strlcpy(dst, p, n + 1);
			if (gui_debug) {
				g_message("pos: \"%s\"", dst);
			}
			dst += n;
		}

		if (*q != '\0')
			q = skip_ascii_blanks(++q);
	}

	query->rules = g_list_reverse(query->rules);
}

gboolean
search_gui_handle_magnet(const gchar *url, const gchar **error_str)
{
	struct magnet_resource *res;

	res = magnet_parse(url, error_str);
	if (res) {
		guint n_downloads, n_searches;

		n_downloads = guc_download_handle_magnet(url);
		n_searches = guc_search_handle_magnet(url);

		if (n_downloads > 0 || n_searches > 0) {
			gchar msg_search[128], msg_download[128];

			gm_snprintf(msg_download, sizeof msg_download,
				NG_("%u download", "%u downloads", n_downloads), n_downloads);
			gm_snprintf(msg_search, sizeof msg_search,
				NG_("%u search", "%u searches", n_searches), n_searches);
			statusbar_gui_message(15, _("Handled magnet link (%s, %s)."),
				msg_download, msg_search);
		} else {
			statusbar_gui_message(15, _("Ignored unusable magnet link."));
		}

		magnet_resource_free(res);
		return TRUE;
	} else {
		if (error_str && *error_str) {
			statusbar_gui_warning(10, "%s", *error_str);
		}
		return FALSE;
	}
}

gboolean
search_gui_handle_http(const gchar *url, const gchar **error_str)
{
	gchar *magnet_url;
	gboolean success;

	g_return_val_if_fail(url, FALSE);
	g_return_val_if_fail(is_strcaseprefix(url, "http://"), FALSE);

	{
		struct magnet_resource *magnet;
		gchar *escaped_url;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':'.
		 */
		escaped_url = url_fix_escape(url);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		magnet_add_source_by_url(magnet, escaped_url);
		if (escaped_url != url) {
			G_FREE_NULL(escaped_url);
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(magnet);
	}
	
	success = search_gui_handle_magnet(magnet_url, error_str);
	G_FREE_NULL(magnet_url);

	return success;
}

gboolean
search_gui_handle_push(const gchar *url, const gchar **error_str)
{
	gchar *magnet_url;
	gboolean success;

	g_return_val_if_fail(url, FALSE);
	g_return_val_if_fail(is_strcaseprefix(url, "push://"), FALSE);

	{
		struct magnet_resource *magnet;
		gchar *escaped_url;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':'.
		 */
		escaped_url = url_fix_escape(url);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		magnet_add_source_by_url(magnet, escaped_url);
		if (escaped_url != url) {
			G_FREE_NULL(escaped_url);
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(magnet);
	}
	
	success = search_gui_handle_magnet(magnet_url, error_str);
	G_FREE_NULL(magnet_url);

	return success;
}

gboolean
search_gui_handle_urn(const gchar *urn, const gchar **error_str)
{
	gchar *magnet_url;
	gboolean success;

	g_return_val_if_fail(urn, FALSE);
	g_return_val_if_fail(is_strcaseprefix(urn, "urn:"), FALSE);

	{
		struct magnet_resource *magnet;
		gchar *escaped_urn;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':'.
		 */
		escaped_urn = url_fix_escape(urn);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		success = magnet_set_exact_topic(magnet, escaped_urn);
		if (escaped_urn != urn) {
			G_FREE_NULL(escaped_urn);
		}
		if (!success) {
			if (error_str) {
				*error_str = _("The given urn type is not supported.");
			}
			magnet_resource_free(magnet);
			return FALSE;
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(magnet);
	}
	
	success = search_gui_handle_magnet(magnet_url, error_str);
	G_FREE_NULL(magnet_url);

	return success;
}

gboolean
search_gui_handle_sha1(const gchar *text, const gchar **error_str)
{
	gchar sha1[SHA1_RAW_SIZE];
	size_t ret;

	g_return_val_if_fail(text, FALSE);

	text = is_strcaseprefix(text, "sha1:");
	g_return_val_if_fail(text, FALSE);

	if (!error_str) {
		static const gchar *error_dummy;
		error_str = &error_dummy;
	}

	if (
		strlen(text) >= SHA1_BASE16_SIZE &&
		!is_ascii_alnum(text[SHA1_BASE16_SIZE])
	) {
		ret = base16_decode(sha1, sizeof sha1, text, SHA1_BASE16_SIZE);
	} else {
		ret = (size_t) -1;
	}

	if (sizeof sha1 != ret) {
		*error_str = _("The given SHA-1 is not correctly encoded.");
		return FALSE;
	} else {
		static const gchar urnsha1[] = "urn:sha1:";
		gchar urn[SHA1_BASE32_SIZE + sizeof urnsha1];

		concat_strings(urn, sizeof urn, urnsha1, sha1_base32(sha1), (void *) 0);
		return search_gui_handle_urn(urn, error_str);
	}
}

gboolean
search_gui_handle_local(const gchar *query, const gchar **error_str)
{
	gboolean success, rebuilding;
	const gchar *text;

	g_return_val_if_fail(query, FALSE);

	text = is_strcaseprefix(query, "local:");
	g_return_val_if_fail(text, FALSE);

	if (!error_str) {
		static const gchar *error_dummy;
		error_str = &error_dummy;
	}

    gnet_prop_get_boolean_val(PROP_LIBRARY_REBUILDING, &rebuilding);
	if (rebuilding) {
		*error_str = _("The library is currently being rebuilt.");
		success = FALSE;	
	} else { 
		search_t *search;

		success = search_gui_new_search_full(text, tm_time(), 0, 0,
			 		search_sort_default_column, search_sort_default_order,
			 		SEARCH_F_LOCAL | SEARCH_F_LITERAL | SEARCH_F_ENABLED,
					&search);
		if (success && search) {
          	search_gui_start_massive_update(search);
			success = guc_search_locally(search->search_handle, text);
          	search_gui_end_massive_update(search);
		}
		*error_str = NULL;
	}

	return success;
}

struct browse_request {
	const gchar *host;	/**< atom */
	guint32 flags;		/**< socket flags */
	guint16 port;		/**< port to connect to */
};

static void
browse_request_free(struct browse_request **req_ptr)
{
	struct browse_request *req;
	
	g_assert(req_ptr);

	req = *req_ptr;
	if (req) {
		g_assert(req);

		atom_str_free_null(&req->host);
		wfree(req, sizeof *req);
		*req_ptr = NULL;
	}
}


/**
 * Called when we got a reply from the ADNS process.
 */
static void
search_gui_browse_helper(const host_addr_t *addrs, size_t n, gpointer user_data)
{
	struct browse_request *req = user_data;

	g_assert(addrs);
	g_assert(req);

	if (n > 0) {
		size_t i = random_raw() % n;

		search_gui_new_browse_host(req->host, addrs[i], req->port,
			NULL, NULL, req->flags);
	}
	browse_request_free(&req);
}

static void
search_gui_browse(const gchar *host, guint16 port, guint32 flags)
{
	struct browse_request *req;

	req = walloc(sizeof *req);

	req->host = atom_str_get(host);
	req->port = port;
	req->flags = flags;
	guc_adns_resolve(req->host, search_gui_browse_helper, req);
}

gboolean
search_gui_handle_browse(const gchar *s, const gchar **error_str)
{
	gboolean success = FALSE;
	host_addr_t addr;
	const gchar *endptr;
	guint32 flags = SOCK_F_FORCE;
	guint16 port;

	g_return_val_if_fail(s, FALSE);

	s = is_strcaseprefix(s, "browse:");
	g_return_val_if_fail(s, FALSE);
	
	if (!error_str) {
		static const gchar *dummy;
		error_str = &dummy;
	}
	*error_str = NULL;

	endptr = is_strprefix(s, "tls:");
	if (endptr) {
		s = endptr;
		flags |= SOCK_F_TLS;
	}

	if (string_to_host_or_addr(s, &endptr, &addr)) {
		gchar hostname[MAX_HOSTLEN + 1];
		size_t size;

		size = (endptr - s) + 1;
		size = MIN(size, sizeof hostname);
		g_strlcpy(hostname, s, size);

		if (':' == endptr[0]) {
			gint error;
			port = parse_uint16(&endptr[1], NULL, 10, &error);
		} else {
			port = 0;
		}
		if (port > 0) {
			search_gui_browse(hostname, port, flags);
			success = TRUE;
		} else {
			*error_str = _("Missing port number");
		}
	} else {
		*error_str = _("Could not parse host address");
	}

	return success;
}


/**
 * Frees a "struct query" and nullifies the given pointer.
 */
void
search_gui_query_free(struct query **query_ptr)
{
	g_assert(query_ptr);
	if (*query_ptr) {
		struct query *query = *query_ptr;

		G_FREE_NULL(query->text);	
		g_list_free(query->rules);
		query->rules = NULL;
		wfree(query, sizeof *query);
		*query_ptr = NULL;
	}
}

/**
 * Handles a query string as entered by the user. This does also handle
 * magnets and special search strings. These will be handled immediately
 * which means that multiple searches and downloads might have been
 * initiated when the functions returns.
 *
 * @param	query_str must point to the query string.
 * @param	flags Diverse SEARCH_F_* flags.
 * @param	error_str Will be set to NULL on success or point to an
 *          error message for the user on failure.
 * @return	NULL if no search should be created. This is not necessarily
 *			a failure condition, check error_str instead. If a search
 *			should be created, an initialized "struct query" is returned.
 */
struct query *
search_gui_handle_query(const gchar *query_str, flag_t flags,
	const gchar **error_str)
{
	gboolean parse;

	g_assert(query_str != NULL);
	if (!error_str) {
		static const gchar *dummy;
		error_str = &dummy;
	}
	*error_str = NULL;

	if (!utf8_is_valid_string(query_str)) {
		*error_str = _("The query string is not UTF-8 encoded");
		return NULL;
	}

	/*
	 * Prevent recursively parsing special search strings i.e., magnet links.
	 */
	parse = !((SEARCH_F_PASSIVE | SEARCH_F_BROWSE | SEARCH_F_LITERAL) & flags);
	if (parse && ':' == *skip_ascii_alnum(query_str)) {
		static const struct {
			const gchar *prefix;
			gboolean (*handler)(const gchar *, const gchar **);
		} tab[] = {
			{ "browse:",	search_gui_handle_browse },
			{ "http:",		search_gui_handle_http },
			{ "local:",		search_gui_handle_local },
			{ "magnet:",	search_gui_handle_magnet },
			{ "push:",		search_gui_handle_push },
			{ "sha1:",		search_gui_handle_sha1 },
			{ "urn:",		search_gui_handle_urn },
		};
		guint i;

		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (is_strcaseprefix(query_str, tab[i].prefix)) {
				tab[i].handler(query_str, error_str);
				return NULL;
			}
		}
		/*
		 * It is better to reject "blah:", so that the behaviour does not
		 * change for some strings in the future.
		 */
		*error_str = _("Unhandled search prefix.");
		return NULL;
	}

	{	
		static const struct query zero_query;
		struct query *query;

		query = walloc(sizeof *query);
		*query = zero_query;

		if (parse) {
			search_gui_parse_text_query(query_str, query);
		} else {
			query->text = g_strdup(query_str);
		}
		return query;
	}
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
	const gchar *p, *q;
	guint i, depth = 0;
	GString *gs;

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

	return gm_string_finalize(gs);
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
        GTK_COMBO(gui_main_window_lookup("combo_search")),
        new_hist);

    /* free old list structure */
    g_list_free(list_search_history);

    list_search_history = new_hist;
}

/**
 * Create a new search from a query entered by the user.
 */
void
search_gui_new_search_entered(void)
{
	GtkWidget *entry;
	gchar *text;
	
    entry = gui_main_window_lookup("entry_search");
   	text = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(entry), 0, -1));
    g_strstrip(text);
	
	if ('\0' != text[0]) {
        filter_t *default_filter;
        search_t *search;
        gboolean res;

        /*
         * We have to capture the selection here already, because
         * new_search will trigger a rebuild of the menu as a
         * side effect.
         */
        default_filter = option_menu_get_selected_data(GTK_OPTION_MENU(
					gui_main_window_lookup("optionmenu_search_filter")));

		res = search_gui_new_search(text, 0, &search);
        if (res) {
			if (search && default_filter) {
				rule_t *rule;

				rule = filter_new_jump_rule(default_filter, RULE_FLAG_ACTIVE);

				/*
				 * Since we don't want to distrub the shadows and
				 * do a "force commit" without the user having pressed
				 * the "ok" button in the dialog, we add the rule
				 * manually.
				 */

				g_assert(search->filter);
				search->filter->ruleset =
					g_list_append(search->filter->ruleset, rule);

				g_assert(rule);
				g_assert(rule->target);
				g_assert(rule->target->refcount >= 0);
				rule->target->refcount++;
			}

        	search_gui_history_add(text);
			gtk_entry_set_text(GTK_ENTRY(entry), "");
		} else {
        	gdk_beep();
		}
    }

	gtk_widget_grab_focus(entry);
	G_FREE_NULL(text);
}

/**
 * Create a new "browse host" type search.
 *
 * @param hostname	the DNS name of the host, or NULL if none known
 * @param addr		the IP address of the host to browse
 * @param port		the port to contact
 * @param guid		the GUID of the remote host
 * @param proxies	vector holding known push-proxies
 * @param flags		connection flags like SOCK_F_PUSH, SOCK_F_TLS etc.
 *
 * @return whether the browse host request could be launched.
 */
gboolean
search_gui_new_browse_host(
	const gchar *hostname, host_addr_t addr, guint16 port,
	const gchar *guid, const gnet_host_vec_t *proxies, guint32 flags)
{
	gchar *host_and_port;
	search_t *search;

	/*
	 * Browse Host (client-side) works thusly:
	 *
	 * We are going to issue a download to request "/" on the remote host.
	 * Once the HTTP connection is established, the remote servent will
	 * send back possibly compressed query hits listing all the shared files.
	 * Those hits will be displayed in the search results.
	 *
	 * The core side is responsible for managing the relationship between
	 * the HTTP packets and the search.  From a GUI standpoint, all we
	 * want to do is display the results.
	 *
	 * However, the "browse host" search is NOT persisted among the searches,
	 * so its lifetime is implicitely this session only.
	 */

	if (guid && (!is_host_addr(addr) || 0 == port)) {
		host_and_port = g_strdup(guid_to_string(guid));
		addr = ipv4_unspecified;
		port = 0;
	} else {
		host_and_port = g_strdup(host_port_to_string(hostname, addr, port));
	}

	(void) search_gui_new_search_full(host_and_port, tm_time(), 0, 0,
			 	search_sort_default_column, search_sort_default_order,
			 	SEARCH_F_BROWSE | SEARCH_F_ENABLED, &search);

	if (search) {
		if (
			guc_search_browse(search->search_handle, hostname, addr, port,
				guid, proxies, flags)
		) {
			statusbar_gui_message(15,
				_("Added search showing browsing results for %s"),
				host_and_port);
		} else {
			search_gui_close_search(search);
			search = NULL;
		}
	}
	if (!search) {
		statusbar_gui_message(10,
			_("Could not launch browse host for %s"), host_and_port);
	}
	G_FREE_NULL(host_and_port);
	return NULL != search;
}

gint
search_gui_cmp_sha1s(const gchar *a, const gchar *b)
{
	if (a && b) {
		return a == b ? 0 : memcmp(a, b, SHA1_RAW_SIZE);
	} else {
		return a ? 1 : (b ? -1 : 0);
	}
}

void
search_gui_duplicate_search(search_t *search)
{
    guint32 timeout;

	g_return_if_fail(search);
	g_return_if_fail(!search_gui_is_browse(search));

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */

	search_gui_new_search_full(search_gui_query(search),
		tm_time(), search_lifetime,
		timeout, search->sort_col, search->sort_order,
		search_gui_is_enabled(search) ? SEARCH_F_ENABLED : 0, NULL);
}

/**
 * Restart a search from scratch, clearing all existing content.
 */
void
search_gui_restart_search(search_t *search)
{
	if (!search_gui_is_enabled(search)) {
		gui_search_set_enabled(search, TRUE);
	}

	search_gui_reset_search(search);
	search->items = 0;
	search->unseen_items = 0;
	search->hidden = 0;
	search->tcp_qhits = 0;
	search->udp_qhits = 0;
	search->skipped = 0;
	search->ignored = 0;
	search->auto_downloaded = 0;
	search->duplicates = 0;

	search_gui_update_items(search);
	guc_search_set_create_time(search->search_handle, tm_time());
	guc_search_update_items(search->search_handle, search->items);
	guc_search_reissue(search->search_handle);
	search_gui_update_expiry(search);
}

void
search_gui_resume_search(search_t *search)
{
	g_return_if_fail(search);

	if (!search_gui_is_expired(search)) {
		gui_search_set_enabled(search, TRUE);
		search_gui_update_expiry(search);
	}
}

void
search_gui_stop_search(search_t *search)
{
	g_return_if_fail(search);

	gui_search_set_enabled(search, FALSE);
	search_gui_update_expiry(search);
}

void
on_popup_search_list_close_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_close_search(sl->data);
	}
	g_slist_free(searches);
}

void
on_popup_search_list_restart_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_restart_search(sl->data);
	}
	g_slist_free(searches);
}

void
on_popup_search_list_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_resume_search(sl->data);
	}
	g_slist_free(searches);
}

void
on_popup_search_list_clear_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_clear_search(sl->data);
	}
	g_slist_free(searches);
}

void
on_popup_search_list_stop_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_stop_search(sl->data);
	}
	g_slist_free(searches);
}

void
on_popup_search_list_duplicate_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_duplicate_search(sl->data);
	}
	g_slist_free(searches);
}

gboolean
on_search_list_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;

	switch (event->button) {
	case 1:
		search_gui_search_list_clicked(widget, event);
		break;
	case 3:
        /* right click section (popup menu) */
		if (search_gui_get_current_search()) {
			search_gui_refresh_popup();
			gtk_menu_popup(GTK_MENU(gui_popup_search_list()),
				NULL, NULL, NULL, NULL, event->button, event->time);
		}
		return TRUE;
    }

	return FALSE;
}

void
search_gui_refresh_popup(void)
{
	/*
	 * The following popup items are set insensitive if nothing is currently
	 * selected (actually if the cursor is unset).
	 */
	static const struct {
		const gchar *name;
	} menu[] = {
		{	"popup_search_drop" },
		{	"popup_search_drop_global" },
		{	"popup_search_metadata" },
		{	"popup_search_browse_host" },
#ifdef USE_GTK2
		{	"popup_search_download" },		/* FIXME: Add this to Gtk+ 1.2 */
		{	"popup_search_copy_magnet" },	/* FIXME: Add this to Gtk+ 1.2 */
#endif
	};
	search_t *search = search_gui_get_current_search();
	gboolean sensitive;
	guint i;

	sensitive = search && search_gui_has_selected_item(search);

	gtk_widget_set_sensitive(
		gui_main_window_lookup("button_search_download"),
		sensitive);

	for (i = 0; i < G_N_ELEMENTS(menu); i++) {
		GtkWidget *w = gui_popup_search_lookup(menu[i].name);
		if (w) {
			gtk_widget_set_sensitive(w, sensitive);
		}
	}

    if (search) {
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_stop"),
			!guc_search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_resume"),
			guc_search_is_frozen(search->search_handle)
				&& !search_gui_is_expired(search));
		if (search_gui_is_passive(search))
			gtk_widget_set_sensitive(
				gui_popup_search_lookup("popup_search_restart"),
				FALSE);
    } else {
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_stop"), FALSE);
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_resume"), FALSE);
    }
}

void
on_popup_search_close_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_close_search(search_gui_get_current_search());
}

void
on_popup_search_download_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_download_files();
}

void
on_popup_search_edit_filter_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    filter_open_dialog();
}

void
on_popup_search_duplicate_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_duplicate_search(search_gui_get_current_search());
}

void
on_popup_search_restart_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_restart_search(search_gui_get_current_search());
}

void
on_popup_search_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_resume_search(search_gui_get_current_search());
}

void
on_popup_search_stop_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_stop_search(search_gui_get_current_search());
}

void
on_popup_search_expand_all_activate (GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_expand_all();
}

void
on_popup_search_collapse_all_activate (GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_collapse_all();
}

const gchar *
search_gui_query(const search_t *search)
{
	g_assert(search);
	return guc_search_query(search->search_handle);
}

gboolean
search_gui_is_browse(const search_t *search)
{
	g_assert(search);
	return guc_search_is_browse(search->search_handle);
}

gboolean
search_gui_is_enabled(const search_t *search)
{
	g_assert(search);
	return !guc_search_is_frozen(search->search_handle);
}

gboolean
search_gui_is_local(const search_t *search)
{
	g_assert(search);
	return guc_search_is_local(search->search_handle);
}

gboolean
search_gui_is_passive(const search_t *search)
{
	g_assert(search);
	return guc_search_is_passive(search->search_handle);
}

/* vi: set ts=4 sw=4 cindent: */
