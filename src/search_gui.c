/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
#include "file.h"

/* GUI includes  */
#include "search_gui.h"
#include "search_cb.h"
#include "gtk-missing.h"
#include "gui_property.h"
#include "gui_property_priv.h"
#include "settings_gui.h"
#include "statusbar_gui.h"

/* System includes */
#include <ctype.h>
#include <gtk/gtk.h>
#include <sys/stat.h>

RCSID("$Id$");

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

static gchar tmpstr[4096];

GList *searches = NULL;		/* List of search structs */

/* Need to remove this dependency on GUI further --RAM */
extern GtkWidget *default_search_clist;

static search_t *current_search  = NULL; /*	The search currently displayed */
search_t *search_selected = NULL;

static time_t tab_update_time = 5;

static GList *list_search_history = NULL;

/*
 * Private function prototypes
 */
static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2);

/*
 * Human readable translation of servent trailer open flags.
 * Decompiled flags are listed in the order of the table.
 */
static struct {
	guint32 flag;
	const gchar *status;
} open_flags[] = {
	{ ST_BUSY,		N_("busy") },
	{ ST_UPLOADED,	N_("stable") },		/* Allows uploads -> stable */
	{ ST_FIREWALL,	N_("push") },
};

/*
 * If no search are currently allocated 
 */
GtkWidget *default_search_clist = NULL;
static GtkWidget *default_scrolled_window = NULL;


/* ----------------------------------------- */

void search_gui_restart_search(search_t *sch)
{
	search_reissue(sch->search_handle);
	gtk_clist_clear(GTK_CLIST(sch->clist));
	sch->items = sch->unseen_items = 0;
	gui_search_update_items(sch);
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
	search_gui_free_r_sets(sch);

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

	g_free(sch);
}

/*
 * search_gui_new_search:
 * 
 * Create a new search and start it. Use default reissue timeout.
 */
gboolean search_gui_new_search(
	const gchar *query, flag_t flags, search_t **search)
{
    guint32 timeout;
    gint sort_col = SORT_NO_COL, sort_order = SORT_NONE;
	
    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    return search_gui_new_search_full(query, 0, timeout,
		sort_col, sort_order, flags | SEARCH_ENABLED, search);
}

/* 
 * search_gui_new_search_full:
 *
 * Create a new search and start it.
 * Returns TRUE if search was sucessfully created and FALSE if an error
 * happened. If the "search" argument is not NULL a pointer to the new
 * search is stored there.
 */
gboolean search_gui_new_search_full(
	const gchar *querystr, guint16 speed,
	guint32 reissue_timeout, gint sort_col, 
	gint sort_order, flag_t flags, search_t **search)
{
    search_t *sch;
    GList *glist;
    gchar *titles[3];
    gint row;
    gchar query[512];

    GtkWidget *combo_searches = lookup_widget(main_window, "combo_searches");
    GtkWidget *clist_search = lookup_widget(main_window, "clist_search");
    GtkWidget *notebook_search_results = 
        lookup_widget(main_window, "notebook_search_results");
    GtkWidget *button_search_close = 
        lookup_widget(main_window, "button_search_close");
    GtkWidget *entry_search = lookup_widget(main_window, "entry_search");


	g_strlcpy(query, querystr, sizeof(query));

	/*
	 * If the text is a magnet link we extract the SHA1 urn
	 * and put it back into the search field string so that the
	 * code for urn searches below can handle it.
	 *		--DBelius   11/11/2002
	 */

	if (0 == strncasecmp(query, "magnet:", 7)) {
		gchar raw[SHA1_RAW_SIZE];

		if (huge_extract_sha1(query, raw)) {
			gm_snprintf(query, sizeof(query), "urn:sha1:%s", sha1_base32(raw));
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
		gchar raw[SHA1_RAW_SIZE];
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
			gchar b32[SHA1_BASE32_SIZE];
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

	sch->sort_col = sort_col;
	sch->sort_order = sort_order;
	
	sch->query = atom_str_get(query);
	sch->enabled = (flags & SEARCH_ENABLED) ? TRUE : FALSE;
    sch->search_handle = search_new(query, speed, reissue_timeout, flags);
    sch->passive = (flags & SEARCH_PASSIVE) ? TRUE : FALSE;
	sch->dups = g_hash_table_new((GHashFunc) search_gui_hash_func,
					(GCompareFunc) search_gui_hash_key_compare);
	if (!sch->dups)
		g_error("new_search: unable to allocate hash table.\n");
    
  	filter_new_for_search(sch);

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
        (GtkFunction)gui_search_update_tab_label, sch);

    if (!searches) {
        GtkWidget * w = gtk_notebook_get_nth_page( 
            GTK_NOTEBOOK(notebook_search_results), 0);
    
		gtk_notebook_set_tab_label_text(
            GTK_NOTEBOOK(notebook_search_results),
            w, _("(no search)"));
    }

	gtk_signal_connect(GTK_OBJECT(sch->list_item), "select",
					   GTK_SIGNAL_FUNC(on_search_selected),
					   (gpointer) sch);

	search_gui_sort_column(sch, sort_col);
	search_gui_set_current_search(sch);

	gtk_widget_set_sensitive(combo_searches, TRUE);
	gtk_widget_set_sensitive(button_search_close, TRUE);

    gtk_entry_set_text(GTK_ENTRY(entry_search),"");

	searches = g_list_append(searches, (gpointer) sch);

/* FIXME:	This might be suboptimal but if search_start() isn't called
 *			"search_handle"->sent_nodes will not be initialized and
 *			the function in search.c accessing this hashtable, will warn
 *			it's NULL (or raise a SIGSEGV in case of NODEBUG).
 */
	search_start(sch->search_handle);
	if (!sch->enabled)
		search_stop(sch->search_handle);

	if (search)
		*search = sch;
	return TRUE;
}

/* Searches results */

gint search_gui_compare_records(
	gint sort_col, const record_t *r1, const record_t *r2)
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
			/*
			 * Sort by size, then by identical SHA1.
			 */
			if (r1->size == r2->size)
            	result = (r1->sha1 == r2->sha1) ? 0 :
              		(r1->sha1 == NULL) ? -1 :
              		(r2->sha1 == NULL) ? +1 :
					memcmp(r1->sha1, r2->sha1, SHA1_RAW_SIZE);
			else
				result = (r1->size > r2->size) ? +1 : -1;
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
 * search_gui_sort_column
 *
 * Draws arrows for the given column of the GtkCList and 
 * sorts the contents of the GtkClist according to the 
 * sorting parameters set in search
 */
void search_gui_sort_column(search_t *search, gint column)
{
    GtkWidget * cw = NULL;

    /* set compare function */
	gtk_clist_set_compare_func
        (GTK_CLIST(search->clist), search_results_compare_func);

   /* destroy existing arrow */
    if (search->arrow != NULL) { 
        gtk_widget_destroy(search->arrow);
        search->arrow = NULL;
    }     

    /* set sort type and create arrow */
    switch (search->sort_order) {
    case SORT_ASC:
        search->arrow = create_pixmap(main_window, "arrow_up.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(search->clist),
            GTK_SORT_ASCENDING);
        break;  
    case SORT_DESC:
        search->arrow = create_pixmap(main_window, "arrow_down.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(search->clist),
            GTK_SORT_DESCENDING);
        break;
    case SORT_NONE:
        break;
    default:
        g_assert_not_reached();
    }

    /* display arrow if necessary and set sorting parameters*/
    if (search->sort_order != SORT_NONE) {
        cw = gtk_clist_get_column_widget
                 (GTK_CLIST(search->clist), column);
        if (cw != NULL) {
            gtk_box_pack_start(GTK_BOX(cw), search->arrow, 
                               FALSE, FALSE, 0);
            gtk_box_reorder_child(GTK_BOX(cw), search->arrow, 0);
            gtk_widget_show(search->arrow);
        }
        gtk_clist_set_sort_column(GTK_CLIST(search->clist), column);
        gtk_clist_sort(GTK_CLIST(search->clist));
        search->sort = TRUE;
    } else {
        search->sort = FALSE;
    }
}

static void search_gui_add_record(
	search_t *sch, record_t *rc, GString *vinfo, GdkColor *fg, GdkColor *bg)
{
  	GString *info = g_string_sized_new(80);
  	gchar *titles[6];
	guint32 row;
    struct results_set *rs = rc->results_set;

	titles[c_sr_filename] = rc->name;
	titles[c_sr_size] = short_size(rc->size);
	gm_snprintf(tmpstr, sizeof(tmpstr), "%u", rs->speed);
	titles[c_sr_speed] = tmpstr;
	titles[c_sr_host] = ip_port_to_gchar(rs->ip, rs->port);
    titles[c_sr_urn] = rc->sha1 != NULL ? sha1_base32(rc->sha1) : "";

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

    gtk_clist_set_row_data(GTK_CLIST(sch->clist), row, (gpointer) rc);
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

    mark_color = &(gtk_widget_get_style(GTK_WIDGET(sch->clist))
        ->bg[GTK_STATE_INSENSITIVE]);

    ignore_color = &(gtk_widget_get_style(GTK_WIDGET(sch->clist))
        ->fg[GTK_STATE_INSENSITIVE]);

    download_color =  &(gtk_widget_get_style(GTK_WIDGET(sch->clist))
        ->fg[GTK_STATE_ACTIVE]);

    vendor = lookup_vendor_name(rs->vendor);

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
			g_string_append(vinfo, gettext(open_flags[i].status));
		}
	}

	if (vendor && !(rs->status & ST_PARSED_TRAILER)) {
		if (vinfo->len)
			g_string_append(vinfo, ", ");
		g_string_append(vinfo, _("<unparsed>"));
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
		 * Note that we pass ALL records through search_gui_result_is_dup(),
		 * to be able to update the index/GUID of our records correctly, when
		 * we detect a change.
		 */

       	if (
			search_gui_result_is_dup(sch, rc)	||
			skip_records 	                    ||
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
				FILTER_PROP_STATE_DO)
		) {
            download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
                rs->guid, rc->sha1, rs->stamp, need_push, NULL, rs->proxies);

			if (rs->proxies != NULL)
				search_gui_free_proxies(rs);

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
            g_hash_table_insert(sch->dups, rc, GINT_TO_POINTER(1));
            rc->refcount++;

            mark = 
                (flt_result->props[FILTER_PROP_DISPLAY].state == 
                    FILTER_PROP_STATE_DONT) &&
                (flt_result->props[FILTER_PROP_DISPLAY].user_data == 
					GINT_TO_POINTER(1));

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
	if (NULL != sch->r_sets)
    	g_assert(!hash_list_contains(sch->r_sets, rs));
	else
		sch->r_sets = hash_list_new(); 

	/* Adds the set to the list */
	hash_list_prepend(sch->r_sets, (gpointer) rs);
	rs->refcount++;
   	g_assert(hash_list_contains(sch->r_sets, rs));
	g_assert(hash_list_first(sch->r_sets) == rs);

	if (old_items == 0 && sch == current_search && sch->items > 0) {
        GtkWidget *button_search_clear =
            lookup_widget(main_window, "button_search_clear");

		gtk_widget_set_sensitive(button_search_clear, TRUE);
	}

	if (sch == current_search) {
		gui_search_update_items(sch);
	} else {
		sch->unseen_items += sch->items - old_items;
	}

	if (time(NULL) - sch->last_update_time < tab_update_time)
		gui_search_update_tab_label(sch);

  	g_string_free(vinfo, TRUE);
}

/* ----------------------------------------- */

/*
 * download_selection_of_clist
 *
 * Create downloads for all the search results pointed at by the list.
 * Returns the amount of downloads actually created, and the amount of
 * items in the selection within `selected'.
 */
static guint download_selection_of_clist(GtkCList * c, guint *selected)
{
	struct results_set *rs;
	struct record *rc;
	gboolean need_push;
	GList *l;
    gint row;
    gboolean remove_downloaded;
	guint created = 0;
	guint count = 0;

    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED,
		&remove_downloaded);

    gtk_clist_freeze(c);

	for (l = c->selection; l; l = c->selection) {
		count++;

        /* make it visibile that we already selected this for download */
		gtk_clist_set_foreground(
			c, GPOINTER_TO_INT(l->data), 
			&gtk_widget_get_style(GTK_WIDGET(c))->fg[GTK_STATE_ACTIVE]);

		rc = (struct record *)
			gtk_clist_get_row_data(c, GPOINTER_TO_INT(l->data));
        
        if (!rc) {
			g_warning("download_selection_of_clist(): row %d has NULL data\n",
			          GPOINTER_TO_INT(l->data));
		    continue;
        }

		rs = rc->results_set;
		need_push =
			(rs->status & ST_FIREWALL) || !host_is_valid(rs->ip, rs->port);

		if (
			download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
				rs->guid, rc->sha1, rs->stamp, need_push, NULL, rs->proxies)
		)
			created++;

		if (rs->proxies != NULL)
			search_gui_free_proxies(rs);

		if (rc->alt_locs != NULL)
			search_gui_check_alt_locs(rs, rc);

        /*
         * I'm not totally sure why we have to determine the row again,
         * but without this, it does not seem to work.
         *     --BLUE, 01/05/2002
         */
        row = gtk_clist_find_row_from_data(c, rc);

        if (remove_downloaded) {
            gtk_clist_remove(c, row);
            current_search->items--;

			/*
			 * Remove one reference to this record.
			 */

			g_hash_table_remove(current_search->dups, rc);
			search_gui_unref_record(rc);

        } else
            gtk_clist_unselect_row(c, row, 0);
	}
    
    gtk_clist_thaw(c);

    gui_search_force_update_tab_label(current_search);
    gui_search_update_items(current_search);

	*selected = count;
	return created;
}


void search_gui_download_files(void)
{
    GtkWidget *notebook_main;
    GtkWidget *ctree_menu;
	GtkCTreeNode *ctree_node;
	
    notebook_main = lookup_widget(main_window, "notebook_main");
    ctree_menu = lookup_widget(main_window, "ctree_menu");

	/* Download the selected files */

	if (jump_to_downloads) {
		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main),
            nb_main_page_downloads);

		/*
		 * Get ctree node for "downloads" row.
		 * Start searching from root node (0th)
		 */
		ctree_node = gtk_ctree_find_by_row_data(GTK_CTREE(ctree_menu), 
			gtk_ctree_node_nth(GTK_CTREE(ctree_menu), 0), 
			GINT_TO_POINTER(nb_main_page_downloads));

		/*
		 * Select "downloads" row.
		 * May need additional code in the future to expand node,
		 * if necessary -- emile
		 */		
		gtk_ctree_select(GTK_CTREE(ctree_menu), ctree_node);
	}

	if (current_search) {
		guint selected;
		guint created;

		created = download_selection_of_clist(
			GTK_CLIST(current_search->clist), &selected);

		gtk_clist_unselect_all(GTK_CLIST(current_search->clist));

		statusbar_gui_message(15,
			"Created %u download%s from the %u selected item%s",
			created, created == 1 ? "" : "s",
			selected, selected == 1 ? "" : "s");
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}
}



/***
 *** Callbacks
 ***/

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
    GtkCList *clist;

    if ((current_search == NULL) && (default_search_clist == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, NULL, 0, 0);

    clist = GTK_CLIST((current_search != NULL) ? 
        current_search->clist : default_search_clist);

    if (clist != NULL) {
        gint i;
    
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_width(clist, i, val[i]);
    }

    g_free(val);
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
    GtkCList *clist;

    if ((current_search == NULL) && (default_search_clist == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_VISIBLE, NULL, 0, 0);

    clist = GTK_CLIST((current_search != NULL) ? 
        current_search->clist : default_search_clist);

    if (clist != NULL) {
        gint i;
    
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility(clist, i, val[i]);
    }

    g_free(val);
    return FALSE;
}




/***
 *** Private functions
 ***/

static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2)
{
    const record_t *s1 = (const record_t *) ((const GtkCListRow *) ptr1)->data;
	const record_t *s2 = (const record_t *) ((const GtkCListRow *) ptr2)->data;

    return search_gui_compare_records(clist->sort_column, s1, s2);
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

	search_gui_common_init();

	gui_search_create_clist(&default_scrolled_window, &default_search_clist);
    gtk_notebook_remove_page(notebook_search_results, 0);
	gtk_notebook_set_scrollable(notebook_search_results, TRUE);
	gtk_notebook_append_page
        (notebook_search_results, default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text
        (notebook_search_results, default_scrolled_window, _("(no search)"));
    
	gtk_signal_connect(GTK_OBJECT(combo_searches->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);

    /*
     * Now we restore the column visibility
     */
    {
        gint i;
        GtkCList *clist;

        clist = (current_search != NULL) ? 
                GTK_CLIST(current_search->clist) : 
                GTK_CLIST(default_search_clist);
         
        for (i = 0; i < clist->columns; i ++)
            gtk_clist_set_column_visibility
                (clist, i, (gboolean) search_results_col_visible[i]);
    }

	search_gui_retrieve_searches();
    search_add_got_results_listener(search_gui_got_results);
}

void search_gui_shutdown(void)
{
	GtkCList *clist;
	gint i;

    search_remove_got_results_listener(search_gui_got_results);
	search_gui_store_searches();

    clist = current_search != NULL
		? GTK_CLIST(current_search->clist) : GTK_CLIST(default_search_clist);

    for (i = 0; i < clist->columns; i ++)
        search_results_col_visible[i] = clist->column[i].visible;

    while (searches != NULL)
        search_gui_close_search((search_t *) searches->data);

	search_gui_common_shutdown();
}

const GList *search_gui_get_searches(void)
{
	return (const GList *) searches;
}

/*
 * search_gui_remove_search:
 *
 * Remove the search from the gui and update all widget accordingly.
 */
void search_gui_remove_search(search_t * sch)
{
    gint row;
    GList *glist;
    gboolean sensitive;
    GtkCList *clist_search = GTK_CLIST
        (lookup_widget(main_window, "clist_search"));
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
         (lookup_widget(main_window, "combo_searches"));

    g_assert(sch != NULL);

   	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_remove_items(GTK_LIST(combo_searches->list), glist);

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gtk_clist_remove(clist_search, row);

    gtk_timeout_remove(sch->tab_updating);

    /* remove column header arrow if it exists */
    if (sch->arrow != NULL) { 
        gtk_widget_destroy(sch->arrow);
        sch->arrow = NULL;
    }     

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results, 
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */

		gtk_clist_clear(GTK_CLIST(sch->clist));

		default_search_clist = sch->clist;
		default_scrolled_window = sch->scrolled_window;

        search_selected = current_search = NULL;

		gui_search_update_items(NULL);

		gtk_entry_set_text
            (GTK_ENTRY(lookup_widget(main_window, "combo_entry_searches")), "");

        gtk_notebook_set_tab_label_text
            (notebook_search_results, default_scrolled_window, _("(no search)"));

		gtk_widget_set_sensitive
            (lookup_widget(main_window, "button_search_clear"), FALSE);
	}
    
	gtk_widget_set_sensitive(GTK_WIDGET(combo_searches), searches != NULL);
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_close"), searches != NULL);

    sensitive = searches != NULL;

	if (current_search != NULL)
		sensitive = sensitive &&
			GTK_CLIST(current_search->clist)->selection;

    gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
}

void search_gui_set_current_search(search_t *sch) 
{
	search_t *old_sch = current_search;
    GtkCTreeNode * node;
    GtkWidget *spinbutton_reissue_timeout;
    GtkCList *clist_search;
    static gboolean locked = FALSE;
    gboolean passive;
    gboolean frozen;
    guint32 reissue_timeout;

	g_assert(sch != NULL);

    if (locked)
        return;

    locked = TRUE;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);

    passive = search_is_passive(sch->search_handle);
    frozen = search_is_frozen(sch->search_handle);
    reissue_timeout = search_get_reissue_timeout(sch->search_handle);

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */
    if (current_search != NULL) {
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

	current_search = sch;
	sch->unseen_items = 0;

    spinbutton_reissue_timeout= lookup_widget
        (main_window, "spinbutton_search_reissue_timeout");
    clist_search = GTK_CLIST
            (lookup_widget(main_window, "clist_search"));

    if (sch != NULL) {
        gui_search_force_update_tab_label(sch);
        gui_search_update_items(sch);

        gtk_clist_select_row(
            clist_search, 
            gtk_clist_find_row_from_data(clist_search, sch), 
            0);
        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_reissue_timeout), reissue_timeout);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, !passive);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_download"), 
            GTK_CLIST(sch->clist)->selection != NULL);
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
        gtk_clist_unselect_all(clist_search);
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

        gtk_notebook_set_page(notebook_search_results,
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
            GINT_TO_POINTER(nb_main_page_search));
    
        if (node != NULL)
            gtk_ctree_select(ctree_menu,node);
    }

    locked = FALSE;
}

search_t *search_gui_get_current_search(void)
{
    return current_search;
}

/* Create a new GtkCList for search results */

void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist)
{
	GtkWidget *label;
    GtkWidget *hbox;

	gint i;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

	*clist = gtk_clist_new(6);

	gtk_container_add(GTK_CONTAINER(*sw), *clist);
	for (i = 0; i < 6; i++)
		gtk_clist_set_column_width(GTK_CLIST(*clist), i,
								   search_results_col_widths[i]);
	gtk_clist_set_selection_mode(GTK_CLIST(*clist),
								 GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(GTK_CLIST(*clist));
    gtk_clist_set_column_justification(GTK_CLIST(*clist),
        c_sr_size, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(GTK_CLIST(*clist),
        c_sr_speed, GTK_JUSTIFY_RIGHT);

	label = gtk_label_new(_("File"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_filename, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 0, _("File"));

	label = gtk_label_new(_("Size"));
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_size, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 1, _("Size"));

	label = gtk_label_new(_("Speed"));
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_speed, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 2, _("Speed"));

	label = gtk_label_new(_("Host"));
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_host, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 3, _("Host"));

	label = gtk_label_new("urn:sha1");
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_urn, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 4, "urn:sha1");
    gtk_clist_set_column_visibility(GTK_CLIST(*clist), 4, FALSE);

	label = gtk_label_new(_("Info"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), c_sr_info, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*clist), 5, _("Info"));

	gtk_widget_show_all(*sw);

	gtk_signal_connect(GTK_OBJECT(*clist), "select_row",
					   GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "unselect_row",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_unselect_row), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "click_column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_click_column), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "button_press_event",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_button_press_event), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "resize-column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_resize_column), NULL);
    gtk_signal_connect(GTK_OBJECT(*clist), "key_press_event",
                       GTK_SIGNAL_FUNC
                       (on_clist_search_results_key_press_event), NULL);
}

void gui_search_update_items(struct search *sch)
{
    if (sch) {
        gchar *str = sch->passive ? "(passive search) " : "";
    
        if (sch->items)
            gm_snprintf(tmpstr, sizeof(tmpstr), _("%s%u item%s found"), 
                str, sch->items, (sch->items > 1) ? "s" : "");
        else
            gm_snprintf(tmpstr, sizeof(tmpstr), _("%sNo items found"), str);
    } else
        g_strlcpy(tmpstr, _("No search"), sizeof(tmpstr));

	gtk_label_set(
        GTK_LABEL(lookup_widget(main_window, "label_items_found")), 
        tmpstr);
}

/* Like search_update_tab_label but always update the label */
void gui_search_force_update_tab_label(struct search *sch)
{
    gint row;
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCList *clist_search = GTK_CLIST
        (lookup_widget(main_window, "clist_search"));
    search_t *current_search;

    current_search = search_gui_get_current_search();

	if (sch == current_search || sch->unseen_items == 0)
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d)", sch->query,
				   sch->items);
	else
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text
        (notebook_search_results, sch->scrolled_window, tmpstr);

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gm_snprintf(tmpstr, sizeof(tmpstr), "%u", sch->items);
    gtk_clist_set_text(clist_search, row, c_sl_hit, tmpstr);
    gm_snprintf(tmpstr, sizeof(tmpstr), "%u", sch->unseen_items);
    gtk_clist_set_text(clist_search, row, c_sl_new, tmpstr);

    if (sch->unseen_items > 0) {
        gtk_clist_set_background(
            clist_search, row, 
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->bg[GTK_STATE_ACTIVE]);
    } else {
        gtk_clist_set_background(clist_search, row, NULL);
    }

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
	gtk_clist_clear(GTK_CLIST(current_search->clist));
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
void gui_search_history_add(gchar *s)
{
    GList *new_hist = NULL;
    GList *cur_hist = list_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if (n < 9 && 0 != g_ascii_strcasecmp(s,cur_hist->data)) {
            /* copy up to the first 9 items */
            new_hist = g_list_append(new_hist, cur_hist->data);
            n ++;
        } else {
            /* and free the rest */
            g_free(cur_hist->data);
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
    g_list_free(list_search_history);
    
    list_search_history = new_hist;
}
