/*
 * $Id$
 *
 * Copyright (c) 2003, Richard Eckart
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
 * Displaying of file information in the GUI.
 *
 * @author Richard Eckart
 * @date 2003
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include "gtk/columns.h"
#include "gtk/downloads_common.h"
#include "gtk/drag.h"
#include "gtk/filter.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"
#include "gtk/visual_progress.h"

#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
#include "lib/url.h"
#include "lib/override.h"		/* Must be the last header included */

static gnet_fi_t last_shown = 0;
static gboolean  last_shown_valid = FALSE;
static GHashTable *fi_updates;
static gint download_details_selected_row = -1;
static gchar *selected_text;

/*
 * Together visible_fi and hidden_fi are a list of all fileinfo handles
 * the the gui knows about.
 */
static GSList *visible_fi;
static GSList *hidden_fi;

static regex_t filter_re;

static GtkCList *clist_fileinfo;		/* Cached lookup_widget() */

static gchar *
fi_gui_get_file_url(GtkWidget *unused_widget)
{
	(void) unused_widget;
	return last_shown_valid ? guc_file_info_get_file_url(last_shown) : NULL;
}

/* Cache for fi_gui_fill_info. This is global so it can be freed
 * when fi_gui_shutdown is called. */
static gnet_fi_info_t *last_fi = NULL;

/**
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 *
 * @warning
 * Returns pointer to global data: the gnet_fi_info_t structure
 * filled from the given `fih'.
 */
static gnet_fi_info_t *
fi_gui_fill_info(gnet_fi_t fih, const gchar *titles[c_fi_num])
{
    /* Clear info from last call. We keep this around so we don't
     * have to strdup entries from it when passing them to the
     * outside through titles[]. */

    if (last_fi != NULL)
        guc_fi_free_info(last_fi);

    /* Fetch new info */
    last_fi = guc_fi_get_info(fih);
    g_assert(last_fi != NULL);

    titles[c_fi_filename] = last_fi->filename;

	return last_fi;
}

/* TODO -- factorize this code with GTK2's one */
static void
fi_gui_fill_status(gnet_fi_t fih, const gchar *titles[c_fi_num])
{
    static gchar fi_sources[32];
    static gchar fi_done[SIZE_FIELD_MAX+10];
    static gchar fi_size[SIZE_FIELD_MAX];
    static gchar fi_progress[SIZE_FIELD_MAX];
    static gchar fi_uploaded[SIZE_FIELD_MAX];
    gnet_fi_status_t s;
	gboolean metric = show_metric_units();

    guc_fi_get_status(fih, &s);

    gm_snprintf(fi_sources, sizeof(fi_sources), "%d/%d/%d",
        s.recvcount, s.aqueued_count + s.pqueued_count, s.lifecount);
    titles[c_fi_sources] = fi_sources;

    if (s.done && s.size) {
        gm_snprintf(fi_progress, sizeof fi_progress,
			"%.1f%%", (1.0 * s.done / s.size) * 100.0);
        titles[c_fi_progress] = fi_progress;
    } else {
        titles[c_fi_progress] = "-";
    }

    if (s.done) {
		g_strlcpy(fi_done, short_size(s.done, metric), sizeof fi_done);
        titles[c_fi_done] = fi_done;
    } else {
        titles[c_fi_done] = "-";
    }

    g_strlcpy(fi_size, short_size(s.size, metric), sizeof fi_size);
    titles[c_fi_size] = fi_size;

    if (s.uploaded) {
    	g_strlcpy(fi_uploaded, short_size(s.uploaded, metric),
			sizeof fi_uploaded);
        titles[c_fi_uploaded] = fi_uploaded;
    } else {
        titles[c_fi_uploaded] = "-";
    }

	titles[c_fi_rx] = s.recvcount ? short_rate(s.recv_last_rate, metric) : "-";
	titles[c_fi_status] = guc_file_info_status_to_string(&s);
}

static void
fi_gui_set_aliases(gnet_fi_t handle)
{
    GtkCList *clist;
    gchar **aliases;
	guint i;

    clist = GTK_CLIST(gui_main_window_lookup("clist_fi_aliases"));
	g_return_if_fail(clist);

    gtk_clist_freeze(clist);
    gtk_clist_clear(clist);

    aliases = guc_fi_get_aliases(handle);
    for (i = 0; aliases[i] != NULL; i++) {
        gtk_clist_append(clist, &aliases[i]);
	}
    g_strfreev(aliases);

    gtk_clist_thaw(clist);
}

/**
 * Display details for the given fileinfo entry in the details pane.
 * It is expected, that the given handle is really used. If not, an
 * assertion will be triggered.
 */
static void
fi_gui_set_details(gnet_fi_t handle)
{
    gnet_fi_info_t *info;
    gnet_fi_status_t fis;

	info = guc_fi_get_info(handle);
    g_return_if_fail(info);

    guc_fi_get_status(handle, &fis);
	downloads_gui_set_details(info->filename, fis.size, info->sha1, info->tth);
    guc_fi_free_info(info);

	fi_gui_set_aliases(handle);

    last_shown = handle;
    last_shown_valid = TRUE;
	vp_draw_fi_progress(last_shown_valid, last_shown);

	gtk_widget_set_sensitive(gui_main_window_lookup("button_fi_purge"), TRUE);
}

/**
 * Clear the details pane.
 */
static void
fi_gui_clear_details(void)
{
    last_shown_valid = FALSE;

	downloads_gui_clear_details();
    gtk_clist_clear(GTK_CLIST(gui_main_window_lookup("clist_fi_aliases")));
    gtk_widget_set_sensitive(gui_main_window_lookup("button_fi_purge"), FALSE);

    vp_draw_fi_progress(last_shown_valid, last_shown);
}

/**
 * @return TRUE if the given string matches with the currntly set
 * row filter. Returns FALSE otherwise.
 */
static inline gboolean
fi_gui_match_filter(const gchar *s)
{
    gint n;

    n = regexec(&filter_re, s, 0, NULL, 0);

    if (n == REG_ESPACE) {
        g_warning("fi_gui_match_filter: regexp memory overflow");
    }

    return n == 0;
}

/**
 * Add a fileinfo entry to the list if it matches the currently set
 * row filter. visible_fi and hidden_fi are properly updated wether
 * the entry is displayed or not and no matter if the line was already
 * shown/hidden or is newly added.
 */
static void
fi_gui_add_row(gnet_fi_t fih)
{
    GtkCList *clist = clist_fileinfo;
    const gchar *titles[c_fi_num];
    gint row;
    guint n;
	gnet_fi_info_t *info;
	gboolean filter_match;
	GSList *l;

    memset(titles, 0, sizeof(titles));
    info = fi_gui_fill_info(fih, titles);

    /*
	 * If the entry doesn't match the filter, register it as hidden and
     * return.
	 */

	filter_match = fi_gui_match_filter(info->filename);

	for (l = info->aliases; !filter_match && l; l = g_slist_next(l)) {
		const gchar *alias = l->data;
		filter_match = fi_gui_match_filter(alias);
	}

    if (!filter_match) {
        if (!g_slist_find(hidden_fi, GUINT_TO_POINTER(fih))) {
            hidden_fi = g_slist_prepend(hidden_fi, GUINT_TO_POINTER(fih));
            visible_fi = g_slist_remove(visible_fi, GUINT_TO_POINTER(fih));
        }
        return;
    }

    visible_fi = g_slist_prepend(visible_fi, GUINT_TO_POINTER(fih));
    hidden_fi = g_slist_remove(hidden_fi, GUINT_TO_POINTER(fih));

    fi_gui_fill_status(fih, titles);

    for (n = 0; n < G_N_ELEMENTS(titles); n ++) {
        if (titles[n] == NULL)
            titles[n] = "";
    }

    row = gtk_clist_append(clist, deconstify_gpointer(titles));
    gtk_clist_set_row_data(clist, row, GUINT_TO_POINTER(fih));
}

/**
 * Remove a fileinfo entry from the list. If it is not displayed, then
 * nothing happens. If hide is TRUE, then the row is not unregistered
 * and only moved to the hidden_fi list.
 */
static void
fi_gui_remove_row(gnet_fi_t fih, gboolean hide)
{
    GtkCList *clist = clist_fileinfo;
    gint row;

    row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(fih));
    gtk_clist_remove(clist, row);

    if (hide) {
        visible_fi = g_slist_remove(visible_fi, GUINT_TO_POINTER(fih));
        hidden_fi  = g_slist_prepend(hidden_fi, GUINT_TO_POINTER(fih));
    } else {
        visible_fi = g_slist_remove(visible_fi, GUINT_TO_POINTER(fih));
        hidden_fi  = g_slist_remove(hidden_fi,  GUINT_TO_POINTER(fih));
    }
}

/**
 * Takes a string containing a regular expression updates the list to
 * only show files matching that expression.
 */
static void
fi_gui_set_filter_regex(gchar *s)
{
    GSList *sl, *old_hidden = g_slist_copy(hidden_fi);
    GtkCList *clist_fi;
    char *fallback_re = ".";
    gint err, flags, row;

    if (s == NULL) {
        s = fallback_re;
    }

    /* Recompile the row filter*/
	flags = REG_EXTENDED | REG_NOSUB;
	flags |= GUI_PROPERTY(fi_regex_case) ? 0 : REG_ICASE;
    err = regcomp(&filter_re, s, flags);
   	if (err) {
        gchar buf[1024];
		regerror(err, &filter_re, buf, sizeof buf);
        statusbar_gui_warning(15, "*** ERROR: %s", buf);

        /* If an error occurs turn filter off. If this doesn't work,
         * then we probably have a serious problem. */
        err = regcomp(&filter_re, fallback_re, REG_EXTENDED|REG_NOSUB);
        g_assert(!err);
    }

    clist_fi = clist_fileinfo;

    /* now really apply the filter */
    gtk_clist_unselect_all(clist_fi);
	gtk_clist_freeze(clist_fi);

    /* first remove non-matching from the list. */
    row = 0;
    while (row < clist_fi->rows) {
        gchar *text;

        if (!gtk_clist_get_text(clist_fi, row, c_fi_filename, &text)) {
            continue;
        }

        if (!fi_gui_match_filter(text)) {
            gnet_fi_t fih;

            fih = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist_fi, row));
            fi_gui_remove_row(fih, TRUE); /* decreases clist_fi->rows */
        } else {
            row ++;
        }
    }

    /* now add matching hidden to list */
    for (sl = old_hidden; NULL != sl; sl = g_slist_next(sl)) {
        /* We simply try to add all hidden rows. If they match
         * the new filter they will be unhidden */
        fi_gui_add_row(GPOINTER_TO_UINT(sl->data));
    }

    gtk_clist_thaw(clist_fi);
}

static void
fi_gui_update(gnet_fi_t fih, gboolean full)
{
    GtkCList *clist = clist_fileinfo;
	const gchar    *titles[c_fi_num];
    gint      row;
    guint     n;

    row = gtk_clist_find_row_from_data(clist, GUINT_TO_POINTER(fih));
    if (row == -1) {
        /* This can happen if we get an update event for a hidden row. */
        return;
    }

    memset(titles, 0, sizeof(titles));
    if (full)
        fi_gui_fill_info(fih, titles);
    fi_gui_fill_status(fih, titles);

    for (n = 0; n < G_N_ELEMENTS(titles); n ++) {
        if (titles[n] != NULL)
            gtk_clist_set_text(clist, row, n, titles[n]);
    }

    /*
     * If this entry is currently selected we should also update the progress
     */

	if (fih == last_shown)
		vp_draw_fi_progress(last_shown_valid, last_shown);
}

static void
fi_gui_fi_added(gnet_fi_t fih)
{
    fi_gui_add_row(fih);
}

static void
fi_gui_fi_removed(gnet_fi_t fih)
{
	g_hash_table_remove(fi_updates, GUINT_TO_POINTER(fih));
	if (fih == last_shown)
		last_shown_valid = FALSE;

    fi_gui_remove_row(fih, FALSE);
}

static void
fi_gui_fi_status_changed(gnet_fi_t fih)
{
	/*
	 * Buffer update, delaying GUI refresh.
	 */

	g_hash_table_insert(fi_updates, GUINT_TO_POINTER(fih), GINT_TO_POINTER(1));
}

static void
fi_gui_fi_status_changed_transient(gnet_fi_t fih)
{
	if (fih == last_shown)
		fi_gui_fi_status_changed(fih);
}

/**
 * Hash table iterator to update the display for each queued entry.
 */
/* XXX -- move to new fileinfo_common.c */
static gboolean
fi_gui_update_queued(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	gnet_fi_t fih = GPOINTER_TO_UINT(key);

	(void) unused_value;
	(void) unused_udata;

	fi_gui_update(fih, FALSE);
	return TRUE;	/* Remove the handle from the hashtable */
}

void
on_clist_fileinfo_select_row(GtkCList *clist, gint row, gint unused_column,
    GdkEvent *unused_event, gpointer unused_udata)
{
    gnet_fi_t fih;

	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
    fih = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));
    fi_gui_set_details(fih);
}

void
on_clist_fileinfo_unselect_row(GtkCList *clist, gint unused_row,
	gint unused_column, GdkEvent *unused_event, gpointer unused_udata)
{
	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
    if (clist->selection == NULL)
        fi_gui_clear_details();
}

void
on_button_fi_purge_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    GSList *sl_handles = NULL;
    GtkCList *clist = clist_fileinfo;

	(void) unused_button;
	(void) unused_udata;
	
    gtk_clist_freeze(clist);
    sl_handles = clist_collect_data(clist, TRUE, NULL);
    if (sl_handles) {
		GSList *sl;

		for (sl = sl_handles; sl != NULL; sl = g_slist_next(sl)) {
			if (GPOINTER_TO_UINT(sl->data) == last_shown) {
				last_shown_valid = FALSE;
				break;
			}
		}
        guc_fi_purge_by_handle_list(sl_handles);
    }
    g_slist_free(sl_handles);
    gtk_clist_thaw(clist);
}

void
on_entry_fi_regex_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *regex;

	(void) unused_udata;
    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
    if (regex) {
    	fi_gui_set_filter_regex(regex);
    	G_FREE_NULL(regex);
	}
}

static gchar * 
download_details_get_text(GtkWidget *widget)
{
	gchar *text = NULL;

	if (
		download_details_selected_row >= 0 &&
		gtk_clist_get_text(GTK_CLIST(widget), download_details_selected_row, 1,
			&text)
	) {
		return g_strdup(text);
	} else {
		return NULL;
	}
}

static void
on_clist_download_details_selection_get(GtkWidget *unused_widget,
	GtkSelectionData *data, guint unused_info,
	guint unused_eventtime, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_info;
	(void) unused_udata;
	(void) unused_eventtime;

    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
		8 /* CHAR_BIT */,
		(guchar *) selected_text,
		selected_text ? strlen(selected_text) : 0);
}

static gboolean
on_clist_download_details_key_press_event(GtkWidget *widget,
	GdkEventKey *event, gpointer unused_udata)
{
    g_assert(event != NULL);

	(void) unused_udata;

	switch (event->keyval) {
	guint modifier;
	case GDK_c:
		modifier = gtk_accelerator_get_default_mod_mask() & event->state;
		if (GDK_CONTROL_MASK == modifier) {
			if (gtk_selection_owner_set(widget,
					GDK_SELECTION_PRIMARY, GDK_CURRENT_TIME)
			) {
				G_FREE_NULL(selected_text);
				selected_text = download_details_get_text(widget);
			}
			return TRUE;
		}
		break;
	}
	return FALSE;
}

static gint
on_clist_download_details_selection_clear_event(GtkWidget *unused_widget,
	GdkEventSelection *unused_event)
{
	(void) unused_widget;
	(void) unused_event;
	G_FREE_NULL(selected_text);
    return TRUE;
}

static void
on_clist_download_details_select_row(GtkCList *unused_clist,
	gint row, gint unused_column, GdkEventButton *unused_event,
	gpointer unused_udata)
{
	(void) unused_clist;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
	download_details_selected_row = row;
}

static void
on_clist_download_details_unselect_row(GtkCList *unused_clist,
	gint unused_row, gint unused_column, GdkEventButton *unused_event,
	gpointer unused_udata)
{
	(void) unused_clist;
	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
	download_details_selected_row = -1;
}

void
fi_gui_init(void)
{
	fi_updates = g_hash_table_new(NULL, NULL);

    guc_fi_add_listener(fi_gui_fi_added, EV_FI_ADDED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_removed, EV_FI_REMOVED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed_transient,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);

	{
		guint i;

		clist_fileinfo = GTK_CLIST(gui_main_window_lookup("clist_fileinfo"));

		for (i = 0; i < c_fi_num; i++) {
			switch (i) {
			case c_fi_size:
			case c_fi_done:
			case c_fi_uploaded:
			case c_fi_progress:
			case c_fi_rx:
				gtk_clist_set_column_justification(clist_fileinfo,
					i, GTK_JUSTIFY_RIGHT);
				break;
			}
		}
		gtk_clist_column_titles_active(clist_fileinfo);
		clist_restore_widths(GTK_CLIST(clist_fileinfo),
			PROP_FILE_INFO_COL_WIDTHS);
		drag_attach(GTK_WIDGET(clist_fileinfo), fi_gui_get_file_url);
	}
	
    /* Initialize the row filter */
    fi_gui_set_filter_regex(NULL);

	{
		GtkCList *clist;
		
		clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		gui_signal_connect(clist, "select-row",
			on_clist_download_details_select_row, NULL);
		gui_signal_connect(clist, "unselect-row",
			on_clist_download_details_unselect_row, NULL);
		gui_signal_connect(clist, "key-press-event",
			on_clist_download_details_key_press_event, NULL);
		gui_signal_connect(clist, "selection_get",
			on_clist_download_details_selection_get, NULL);
  		gui_signal_connect(clist, "selection_clear_event",
			on_clist_download_details_selection_clear_event, NULL);

		gtk_selection_add_target(GTK_WIDGET(clist),
			GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);

		drag_attach(GTK_WIDGET(clist), download_details_get_text);
	}
}

void
fi_gui_shutdown(void)
{
	clist_save_widths(GTK_CLIST(clist_fileinfo), PROP_FILE_INFO_COL_WIDTHS);
    g_slist_free(hidden_fi);
    g_slist_free(visible_fi);

    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

    if (last_fi != NULL)
        guc_fi_free_info(last_fi);

	g_hash_table_destroy(fi_updates);
    regfree(&filter_re);
}

/**
 * Update all the fileinfo at the same time.
 */

static gboolean
fi_gui_is_visible(void)
{
	if (!main_gui_window_visible())
		return FALSE;

	{
		static GtkNotebook *notebook;

		if (notebook == NULL) {
			notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_main"));
		}
		if (nb_main_page_downloads != gtk_notebook_get_current_page(notebook))
			return FALSE;
	}

	{
		static GtkNotebook *notebook;

		if (notebook == NULL) {
			notebook = GTK_NOTEBOOK(
							gui_main_window_lookup("notebook_downloads"));
		}
		if (nb_downloads_page_all != gtk_notebook_get_current_page(notebook))
			return FALSE;
	}
	return TRUE;
}


/**
 * @bug
 * FIXME: We should remember for every node when it was last
 *        updated and only refresh every node at most once every
 *        second. This information should be kept in a struct pointed
 *        to by the row user_data and should be automatically freed
 *        when removing the row (see upload stats code).
 */
void
fi_gui_update_display(time_t now)
{
	if (!fi_gui_is_visible())
		return;

    gtk_clist_freeze(clist_fileinfo);
	g_hash_table_foreach_remove(fi_updates, fi_gui_update_queued, NULL);
    gtk_clist_thaw(clist_fileinfo);

#if 0
    static time_t last_update = 0;
	GtkCList *clist = clist_fileinfo;
	GList *l;
	gint row = 0;

    if (last_update == now)
        return;

    last_update = now;

    gtk_clist_freeze(clist);

	for (l = clist->row_list, row = 0; l; l = l->next, row++) {
        gchar *titles[c_fi_num];
		gnet_fi_t fih = (gnet_fi_t) GPOINTER_TO_UINT(
            ((GtkCListRow *) l->data)->data);

        memset(titles, 0, sizeof(titles));
        fi_gui_fill_status(fih, titles);
        fi_gui_update_row(clist, row, titles, G_N_ELEMENTS(titles));
    }
    gtk_clist_thaw(clist);
#else
	(void) now;
#endif
}

static inline guint
fi_gui_relative_done(const gnet_fi_status_t *s, gboolean percent)
{
	if (percent) {
		return filesize_per_100(s->size, s->done);
	} else {
		return filesize_per_1000(s->size, s->done);
	}
}

static inline guint
fi_gui_numeric_status(const gnet_fi_status_t *s)
{
	guint v;

	v = fi_gui_relative_done(s, TRUE);
	v |= (s->lifecount > 0)						? (1 <<  7) : 0;
	v |= (s->aqueued_count || s->pqueued_count)	? (1 <<  8) : 0;
	v |= (s->recvcount > 0)						? (1 <<  9) : 0;
	v |= (s->size > 0 && s->size == s->done)	? (1 << 10) : 0;

	return v;
}

static gint 
fi_gui_cmp_filename(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_info_t *a_fi, *b_fi;
    gnet_fi_t a, b;
	gint r;
   
	(void) unused_clist;
	a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

	a_fi = guc_fi_get_info(a);
	b_fi = guc_fi_get_info(b);
	r = strcmp(a_fi->filename, b_fi->filename);
	guc_fi_free_info(b_fi);
	guc_fi_free_info(a_fi);

	return r;
}

static gint 
fi_gui_cmp_size(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	return CMP(a.size, b.size);
}

static gint 
fi_gui_cmp_done(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	return CMP(a.done, b.done);
}

static gint 
fi_gui_cmp_progress(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;
	gint ret;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	ret = CMP(fi_gui_relative_done(&a, FALSE), fi_gui_relative_done(&b, FALSE));
	return 0 == ret ? CMP(a.done, b.done) : ret;
}

static gint 
fi_gui_cmp_rx(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	return CMP(a.recv_last_rate, b.recv_last_rate);
}

static gint 
fi_gui_cmp_uploaded(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	return CMP(a.uploaded, b.uploaded);
}

static gint 
fi_gui_cmp_sources(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;
	gint r;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	r = CMP(a.recvcount, b.recvcount);
	if (0 == r) {
		r = CMP(a.aqueued_count + a.pqueued_count,
				b.aqueued_count + b.pqueued_count);
		if (0 == r) {
			r = CMP(a.lifecount, b.lifecount);
		}
	}
	return r;
}

static gint 
fi_gui_cmp_status(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    gnet_fi_status_t a, b;
    gnet_fi_t fi_a, fi_b;

	(void) unused_clist;
	fi_a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    fi_b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);

    guc_fi_get_status(fi_a, &a);
    guc_fi_get_status(fi_b, &b);

	return CMP(fi_gui_numeric_status(&a), fi_gui_numeric_status(&b));
}

void
on_clist_fileinfo_click_column(GtkCList *clist, gint column,
	gpointer unused_udata)
{
	static gint sort_col = c_fi_num;
	static gboolean sort_invert;

	(void) unused_udata;
	
	g_assert(column >= 0 && column < c_fi_num);

	switch ((enum c_fi) column) {
#define CASE(x) case c_fi_ ## x : \
		gtk_clist_set_compare_func(clist, fi_gui_cmp_ ## x ); break;
	CASE(filename)
	CASE(size)
	CASE(progress)
	CASE(rx)
	CASE(done)
	CASE(uploaded)
	CASE(sources)
	CASE(status)
#undef CASE
	case c_fi_num:
		g_assert_not_reached();
	}

	sort_invert = sort_col == column && !sort_invert;
	sort_col = column;
	gtk_clist_set_sort_type(clist,
		sort_invert ? GTK_SORT_DESCENDING : GTK_SORT_ASCENDING);
	gtk_clist_sort(clist);
}

/* vi: set ts=4 sw=4 cindent: */
