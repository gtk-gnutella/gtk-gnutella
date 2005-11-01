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

/**
 * @ingroup gtk
 * @file
 *
 * GUI stuff used by 'share.c'.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

RCSID("$Id$");

#include "gtk-missing.h"
#include "settings_cb.h"
#include "settings.h"
#include "search.h"
#include "statusbar.h"

#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)                                            \
    gboolean CAT3(on_,a,_focus_out_event) (GtkWidget *widget,			\
			GdkEventFocus *unused_event, gpointer unused_udata)			\
    {                                                                   \
		(void) unused_event;											\
		(void) unused_udata;											\
        CAT3(on_,a,_activate)(GTK_EDITABLE(widget), NULL);              \
        return FALSE;                                                   \
    }

#define checkmenu_changed(pref,p, cb) do {                              \
        gboolean val = GTK_CHECK_MENU_ITEM(cb)->active;                 \
        CAT2(pref,_prop_set_boolean)(p, &val, 0, 1);                    \
    } while (0)

void
on_spinbutton_search_reissue_timeout_changed(GtkEditable *editable,
		gpointer unused_udata)
{
    static gboolean lock = FALSE;
    search_t *current_search;
    guint32 timeout_real;
    guint32 timeout;

	(void) unused_udata;

    if (lock)		/* Prevents recursion */
        return;

    lock = TRUE;

    current_search = search_gui_get_current_search();

    if (
		!current_search ||
		guc_search_is_passive(current_search->search_handle)
	) {
        lock = FALSE;
        return;
    }

    timeout = gtk_spin_button_get_value(GTK_SPIN_BUTTON(editable));

    guc_search_set_reissue_timeout
		(current_search->search_handle, timeout);
    timeout_real = guc_search_get_reissue_timeout
		(current_search->search_handle);

    if (timeout != timeout_real)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(editable), timeout_real);

    lock = FALSE;
}

static void
on_entry_config_proxy_hostname_activate_helper(const host_addr_t *addr,
		gpointer unused_udata)
{
	const gchar *s;

	(void) unused_udata;

	if (addr) {
		s = host_addr_to_string(*addr);
    	gnet_prop_set_string(PROP_PROXY_ADDR, s);
	}
}

void
on_entry_config_proxy_hostname_activate(GtkEditable *editable,
		gpointer unused_udata)
{
   	gchar *text = g_strstrip(STRTRACK(gtk_editable_get_chars(editable, 0, -1)));

	(void) unused_udata;
    gnet_prop_set_string(PROP_PROXY_HOSTNAME, text);
	if (text[0] != '\0') {
		guc_adns_resolve(text,
			on_entry_config_proxy_hostname_activate_helper, NULL);
	}
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_proxy_hostname)

void
on_entry_config_socks_username_activate(GtkEditable *editable,
		gpointer unused_udata)
{
   	gchar *text = g_strstrip(STRTRACK(gtk_editable_get_chars(editable, 0, -1)));

	(void) unused_udata;
    gnet_prop_set_string(PROP_SOCKS_USER, text);
    G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_socks_username)

void
on_entry_config_socks_password_activate(GtkEditable * editable,
		gpointer unused_udata)
{
   	gchar *text = g_strstrip(STRTRACK(gtk_editable_get_chars(editable, 0, -1)));

	(void) unused_udata;
    gnet_prop_set_string(PROP_SOCKS_PASS, text);
    G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_socks_password)

void
on_entry_config_extensions_activate(GtkEditable *editable, gpointer unused_data)
{
    gchar *ext;

	(void) unused_data;
    ext = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
    gnet_prop_set_string(PROP_SCAN_EXTENSIONS, ext);
    g_free(ext);
}
FOCUS_TO_ACTIVATE(entry_config_extensions)

#ifdef USE_GTK1
void
on_entry_config_path_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *path = STRTRACK(gtk_editable_get_chars(editable, 0, -1));

	(void) unused_udata;
    gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, path);
    g_free(path);
}
FOCUS_TO_ACTIVATE(entry_config_path)
#endif /* GTK1 */

#ifdef USE_GTK2
void
on_button_config_remove_dir_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GString *gs;

	(void) unused_button;
	(void) unused_udata;

	tv = GTK_TREE_VIEW(lookup_widget(dlg_prefs, "treeview_shared_dirs"));
	model = gtk_tree_view_get_model(tv);

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;

	/* Regenerate the string property holding a list of paths */
	selection = gtk_tree_view_get_selection(tv);
	gs = g_string_new("");

	do {
		gchar *dir = NULL;

		/* Skip items selected for removal */
		if (gtk_tree_selection_iter_is_selected(selection, &iter))
			continue;

		gtk_tree_model_get(model, &iter, 0, &dir, (-1));
		if ('\0' != gs->str[0])
			gs = g_string_append_c(gs, ':');
		gs = g_string_append(gs, dir);
		G_FREE_NULL(dir);
	} while (gtk_tree_model_iter_next(model, &iter));

	gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, gs->str);
	g_string_free(gs, TRUE);
}
#endif /* GTK2 */

void
on_entry_config_force_ip_activate(GtkEditable *unused_editable,
		gpointer unused_udata)
{
   	gchar *text;

	(void) unused_editable;
	(void) unused_udata;
	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(lookup_widget(dlg_prefs, "entry_config_force_ip")),
        0, -1));
	g_strstrip(text);
	gnet_prop_set_string(PROP_FORCED_LOCAL_IP, text);
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_force_ip)

void
on_entry_config_force_ip_changed(GtkEditable *editable, gpointer unused_udata)
{
    gchar *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));

	(void) unused_udata;
	g_strstrip(text);
	gtk_widget_set_sensitive(
        lookup_widget(dlg_prefs, "checkbutton_config_force_ip"),
        is_host_addr(string_to_host_addr(text, NULL)));
	G_FREE_NULL(text);
}

void
on_entry_server_hostname_activate(GtkEditable *unused_editable,
		gpointer unused_udata)
{
   	gchar *text;

	(void) unused_editable;
	(void) unused_udata;
	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(lookup_widget(dlg_prefs, "entry_server_hostname")),
        0, -1));
	g_strstrip(text);
	gnet_prop_set_string(PROP_SERVER_HOSTNAME, text);
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_server_hostname)

void
on_entry_server_hostname_changed(GtkEditable *editable, gpointer unused_udata)
{
    gchar *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));

	(void) unused_udata;
	
	g_strstrip(text);
	gtk_widget_set_sensitive(
        lookup_widget(dlg_prefs, "checkbutton_give_server_hostname"),
        strlen(text) > 3);		/* Minimum: "x.cx" */
	G_FREE_NULL(text);
}

#ifdef USE_GTK2
static tree_view_motion_t *tvm_dbg_property;

static void
update_tooltip(GtkTreeView *tv, GtkTreePath *path)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	property_t prop;
	guint u;

	g_assert(tv != NULL);

	if (!path) {
		GtkWidget *w;

		gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(tv),
			_("Move the cursor over a row to see details."), NULL);
		w = settings_gui_tooltips()->tip_window;
		if (w)
			gtk_widget_hide(w);

		return;
	}

	model = gtk_tree_view_get_model(tv);
	if (!gtk_tree_model_get_iter(model, &iter, path)) {
		g_warning("gtk_tree_model_get_iter() failed");
		return;
	}

	u = 0;
	gtk_tree_model_get(model, &iter, 3, &u, (-1));
	g_assert(0 != u);

	prop = (property_t) u;
	gtk_tooltips_set_tip(settings_gui_tooltips(),
		GTK_WIDGET(tv), gnet_prop_description(prop), NULL);
}

static gboolean
on_enter_notify(GtkWidget *widget, GdkEventCrossing *unused_event,
	gpointer data)
{
	GtkTreeView *tv;

	(void) unused_event;

	tv = GTK_TREE_VIEW(data);
	update_tooltip(GTK_TREE_VIEW(widget), NULL);
	tvm_dbg_property = tree_view_motion_set_callback(tv, update_tooltip, 400);
	return FALSE;
}

static gboolean
on_leave_notify(GtkWidget *widget, GdkEventCrossing *unused_event,
	gpointer data)
{
	GtkTreeView *tv;

	(void) unused_event;

	tv = GTK_TREE_VIEW(data);
	update_tooltip(GTK_TREE_VIEW(widget), NULL);
	if (tvm_dbg_property) {
		tree_view_motion_clear_callback(tv, tvm_dbg_property);
		tvm_dbg_property = NULL;
	}
	return FALSE;
}

static void
on_cell_edited(GtkCellRendererText *unused_renderer, const gchar *path_str,
	const gchar *text, gpointer unused_data)
{
	GtkTreeView *tv;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	property_t prop;
	guint u;

	(void) unused_renderer;
	(void) unused_data;

	tv = GTK_TREE_VIEW(lookup_widget(dlg_prefs, "treeview_dbg_property"));
	g_return_if_fail(NULL != tv);
	model = gtk_tree_view_get_model(tv);
	g_return_if_fail(NULL != model);

	path = gtk_tree_path_new_from_string(path_str);
	gtk_tree_model_get_iter(model, &iter, path);

	u = 0;
	gtk_tree_model_get(model, &iter, 3, &u, (-1));
	g_assert(0 != u);
	prop = (property_t) u;
	gnet_prop_set_from_string(prop,	text);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter,
		1, gnet_prop_to_string(prop),
		(-1));
}

static void
dbg_tree_init(void)
{
	static const struct {
		const gchar *title;
		gboolean editable;
	} columns[] = {
		{ N_("Property"),		FALSE },
		{ N_("Value"),			TRUE  },
		{ N_("Description"),	FALSE },
		{ NULL,					FALSE },
	};
	GtkListStore *store;
	GtkTreeView *tv;
	guint i;

	tv = GTK_TREE_VIEW(lookup_widget(dlg_prefs, "treeview_dbg_property"));
	store = GTK_LIST_STORE(gtk_list_store_new(G_N_ELEMENTS(columns),
				G_TYPE_STRING,
				G_TYPE_STRING,
				G_TYPE_STRING,
				G_TYPE_UINT));

	gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
	g_object_unref(store);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;

		if (!columns[i].title)
			continue;

		renderer = gtk_cell_renderer_text_new();

		if (columns[i].editable) {
			g_signal_connect(renderer, "edited",
					G_CALLBACK(on_cell_edited), NULL);
			g_object_set(renderer,
					"editable", TRUE,
					(void *) 0);
		}

		column = gtk_tree_view_column_new_with_attributes(
				_(columns[i].title), renderer,
				"text", i,
				(void *) 0);

		g_object_set(renderer,
				"xalign", 0.0,
				"xpad", GUI_CELL_RENDERER_XPAD,
				"ypad", GUI_CELL_RENDERER_YPAD,
				(void *) 0);
		g_object_set(column,
				"fixed-width", 200,
				"min-width", 1,
				"resizable", TRUE,
				"reorderable", FALSE,
				"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
				(void *) 0);

		gtk_tree_view_column_set_sort_column_id(column, i);
		gtk_tree_view_append_column(tv, column);
	}

	g_signal_connect(GTK_OBJECT(tv),
			"enter-notify-event", G_CALLBACK(on_enter_notify), tv);
	g_signal_connect(GTK_OBJECT(tv),
			"leave-notify-event", G_CALLBACK(on_leave_notify), tv);
}

void
dbg_property_show_list(const GSList *props)
{
	const GSList *sl;
	GtkTreeView *tv;
	GtkListStore *store;
	
	tv = GTK_TREE_VIEW(lookup_widget(dlg_prefs, "treeview_dbg_property"));
	if (!gtk_tree_view_get_model(tv))
		dbg_tree_init();
		
	store = GTK_LIST_STORE(gtk_tree_view_get_model(tv));
	gtk_list_store_clear(store);

	if (!props) {
		GtkLabel *label;
		
		label = GTK_LABEL(lookup_widget(dlg_prefs, "label_dbg_property_name"));
		gtk_label_set_text(GTK_LABEL(widget), _("<none selected>"));
	}

	for (sl = props; NULL != sl; sl = g_slist_next(sl)) {
		GtkTreeIter iter;
		property_t prop;

		prop = GPOINTER_TO_UINT(sl->data);

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
			0, gnet_prop_name(prop),
			1, gnet_prop_to_string(prop),
			2, gnet_prop_description(prop),
			3, (guint) prop,
			(-1));
	}
}
#endif /* USE_GTK2 */

#ifdef USE_GTK1
static void
dbg_property_set_row(GtkCList *clist, gint row, property_t prop)
{
	gint i;

	g_assert(clist);
	g_assert(row != -1);

	for (i = 0; i < 3; i++) {
		const gchar *text;
		switch (i) {
		case 0: text = gnet_prop_name(prop); break;
		case 1: text = gnet_prop_to_string(prop); break;
		case 2: text = gnet_prop_description(prop); break;
		default:
			g_assert_not_reached();
			text = "(null)";
		}
		gtk_clist_set_text(clist, row, i, text);
	}
   	gtk_clist_set_row_data(clist, row, GUINT_TO_POINTER(prop));
}

static void
dbg_property_show_list(const GSList *props)
{
	GtkCList *clist;
	const GSList *sl;

   	clist = GTK_CLIST(lookup_widget(dlg_prefs, "clist_dbg_property"));
	gtk_clist_freeze(clist);
	gtk_clist_clear(clist);

	for (sl = props; NULL != sl; sl = g_slist_next(sl)) {
		static const gchar * const titles[3] = { "", "", "" };
		property_t prop = GPOINTER_TO_UINT(sl->data);
		gint row;
		
    	row = gtk_clist_append(clist, deconstify_gpointer(titles));
		dbg_property_set_row(clist, row, prop);	
	}

	gtk_clist_thaw(clist);
}
#endif /* USE_GTK1 */

void
on_entry_dbg_property_pattern_activate(GtkEditable *unused_editable,
	gpointer unused_udata)
{
	static gchar old_pattern[1024];
   	gchar *text;

	(void) unused_editable;
	(void) unused_udata;

	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(lookup_widget(dlg_prefs, "entry_dbg_property_pattern")),
        0, -1));
	g_strstrip(text);

	if (0 != strcmp(text, old_pattern)) {
		GSList *props;

		g_strlcpy(old_pattern, text, sizeof old_pattern);
		props = gnet_prop_get_by_regex(text, NULL);
		if (!props)
			statusbar_gui_warning(10,
				_("No property name matches the pattern \"%s\"."), text);
		
		dbg_property_show_list(props);
		g_slist_free(props);
		props = NULL;
	}
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_dbg_property_pattern)
	
void
on_entry_dbg_property_value_activate(GtkEditable *editable,
	gpointer unused_udata)
{
	GtkCList *clist;

	(void) unused_udata;

   	clist = GTK_CLIST(lookup_widget(dlg_prefs, "clist_dbg_property"));

    if (clist->selection) {
   		gchar *text;
		property_t prop;
		gint row;

		text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
		row = GPOINTER_TO_INT(clist->selection->data);
		prop = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));
		gnet_prop_set_from_string(prop,	text);
		dbg_property_set_row(clist, row, prop);
		G_FREE_NULL(text);
	}
}

void
on_clist_dbg_property_select_row(GtkCList *clist, gint row, gint unused_column,
	GdkEvent *unused_event, gpointer unused_udata)
{
	GtkLabel *label;
	GtkEntry *entry;
	gpointer data;
	
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;
    g_assert(clist != NULL);

	label = GTK_LABEL(lookup_widget(dlg_prefs, "label_dbg_property_name"));
    entry = GTK_ENTRY(lookup_widget(dlg_prefs, "entry_dbg_property_value"));

    if (
		clist->selection &&
		NULL != (data = gtk_clist_get_row_data(clist, row))
	) {
		property_t prop = GPOINTER_TO_UINT(data);
		gtk_label_printf(label, "\"%s\"", gnet_prop_name(prop));
		gtk_entry_set_text(entry, gnet_prop_to_string(prop));
	} else {
		gtk_label_set_text(label, _("<none selected>"));
		gtk_entry_set_text(entry, "");
	}
}

void
on_menu_toolbar_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_TOOLBAR_VISIBLE, menuitem);
}

void
on_menu_statusbar_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_STATUSBAR_VISIBLE, menuitem);
}

void
on_menu_downloads_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_DOWNLOADS_VISIBLE, menuitem);
}

void
on_menu_uploads_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_UPLOADS_VISIBLE, menuitem);
}

void
on_menu_connections_visible_activate(GtkMenuItem *menuitem,
		gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_CONNECTIONS_VISIBLE, menuitem);
}

void
on_menu_bws_in_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_IN_VISIBLE, menuitem);
}

void
on_menu_bws_out_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_OUT_VISIBLE, menuitem);
}

void
on_menu_bws_gin_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GIN_VISIBLE, menuitem);
}

void
on_menu_bws_gout_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GOUT_VISIBLE, menuitem);
}

void
on_menu_bws_glin_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GLIN_VISIBLE, menuitem);
}

void
on_menu_bws_glout_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GLOUT_VISIBLE, menuitem);
}

void
on_menu_autohide_bws_gleaf_activate(GtkMenuItem *menuitem,
		gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_AUTOHIDE_BWS_GLEAF, menuitem);
}

void
on_popup_search_toggle_tabs_activate(GtkMenuItem *unused_menuitem,
		gpointer unused_udata)
{
    gboolean val;

	(void) unused_menuitem;
	(void) unused_udata;

    gui_prop_get_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS, &val);
    val = !val;
    gui_prop_set_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS, val);
}

/* vi: set ts=4 sw=4 cindent: */
