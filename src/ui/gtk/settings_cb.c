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

#ifdef USE_GTK2
#include "gtk2/column_sort.h"
#endif

#include "misc.h"
#include "settings_cb.h"
#include "settings.h"
#include "search.h"
#include "statusbar.h"

#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"	/* For g_strlcpy() */
#include "lib/halloc.h"
#include "lib/pslist.h"
#include "lib/str.h"
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

static void
on_entry_config_proxy_hostname_activate_helper(const host_addr_t *addrs,
		size_t n, gpointer unused_udata)
{
	(void) unused_udata;

	g_assert(addrs);
	if (n > 0) {
		/* Just pick the first address */
    	gnet_prop_set_ip_val(PROP_PROXY_ADDR, addrs[0]);
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
    G_FREE_NULL(ext);
}
FOCUS_TO_ACTIVATE(entry_config_extensions)

#ifdef USE_GTK1
void
on_entry_config_path_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *path = STRTRACK(gtk_editable_get_chars(editable, 0, -1));

	(void) unused_udata;
    gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, path);
    G_FREE_NULL(path);
}
FOCUS_TO_ACTIVATE(entry_config_path)
#endif /* USE_GTK1 */

#ifdef USE_GTK2
void
on_button_config_remove_dir_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeView *tv;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	pslist_t *sl, *pl_dirs = NULL;
	char *dirs;

	(void) unused_button;
	(void) unused_udata;

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_shared_dirs"));
	model = gtk_tree_view_get_model(tv);

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;

	/* Regenerate the string property holding a list of paths */
	selection = gtk_tree_view_get_selection(tv);

	do {
		char *pathname = NULL;

		/* Skip items selected for removal */
		if (gtk_tree_selection_iter_is_selected(selection, &iter))
			continue;

		gtk_tree_model_get(model, &iter, 0, &pathname, (-1));
		pl_dirs = pslist_prepend(pl_dirs, pathname);
	} while (gtk_tree_model_iter_next(model, &iter));

	dirs = dirlist_to_string(pl_dirs);
	gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, dirs);
	HFREE_NULL(dirs);

	PSLIST_FOREACH(pl_dirs, sl) {
		G_FREE_NULL(sl->data);
	}
	pslist_free_null(&pl_dirs);
}
#endif /* USE_GTK2 */

void
on_entry_config_force_ip_activate(GtkEditable *unused_editable,
		gpointer unused_udata)
{
   	gchar *text;
	host_addr_t addr;
	const gchar *endptr;

	(void) unused_editable;
	(void) unused_udata;
	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(gui_dlg_prefs_lookup("entry_config_force_ip")),
        0, -1));
	g_strstrip(text);
	if (string_to_host_addr(text, &endptr, &addr) && '\0' == endptr[0]) {
		gnet_prop_set_ip_val(PROP_FORCED_LOCAL_IP, addr);
	} else if (0 == strcmp(text, "") || 0 == strcmp(text, "<none>")) {
		gnet_prop_set_ip_val(PROP_FORCED_LOCAL_IP, zero_host_addr);
	}
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_force_ip)

void
on_entry_config_force_ip_changed(GtkEditable *editable, gpointer unused_udata)
{
    gchar *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	const gchar *endptr;
	gboolean sensitive;

	(void) unused_udata;
	g_strstrip(text);
	sensitive = string_to_host_addr(text, &endptr, NULL) && '\0' == endptr[0];
	gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("checkbutton_config_force_ip"),
		sensitive);
	gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("checkbutton_config_bind_ipv4"),
		sensitive);
	G_FREE_NULL(text);
}

void
on_entry_config_force_ipv6_activate(GtkEditable *unused_editable,
		gpointer unused_udata)
{
   	gchar *text;
	host_addr_t addr;
	const gchar *endptr;

	(void) unused_editable;
	(void) unused_udata;
	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(gui_dlg_prefs_lookup("entry_config_force_ipv6")),
        0, -1));
	g_strstrip(text);
	if (
		string_to_host_addr(text, &endptr, &addr)
			&& '\0' == endptr[0]
			&& host_addr_is_ipv6(addr)
	) {
		gnet_prop_set_ip_val(PROP_FORCED_LOCAL_IP6, addr);
	} else if (0 == strcmp(text, "") || 0 == strcmp(text, "<none>")) {
		gnet_prop_set_ip_val(PROP_FORCED_LOCAL_IP6, zero_host_addr);
	}
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_force_ipv6)

void
on_entry_config_force_ipv6_changed(GtkEditable *editable, gpointer unused_udata)
{
    gchar *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	const gchar *endptr;
	host_addr_t addr;
	gboolean sensitive;

	(void) unused_udata;
	g_strstrip(text);
	sensitive = string_to_host_addr(text, &endptr, &addr)
			&& '\0' == endptr[0]
			&& host_addr_is_ipv6(addr);
	gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("checkbutton_config_force_ipv6"),
		sensitive);
	gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("checkbutton_config_bind_ipv6"),
		sensitive);
	G_FREE_NULL(text);
}

void
on_entry_config_ipv6_trt_prefix_activate(GtkEditable *unused_editable,
		gpointer unused_udata)
{
	const gchar *endptr;
	host_addr_t addr;
   	gchar *text;

	(void) unused_editable;
	(void) unused_udata;
	text = STRTRACK(gtk_editable_get_chars(
        GTK_EDITABLE(gui_dlg_prefs_lookup("entry_config_ipv6_trt_prefix")),
        0, -1));
	g_strstrip(text);
	if (
		string_to_host_addr(text, &endptr, &addr)
			&& '\0' == endptr[0]
			&& host_addr_is_ipv6(addr)
	) {
		gnet_prop_set_ip_val(PROP_IPV6_TRT_PREFIX, addr);
	} else if (0 == strcmp(text, "") || 0 == strcmp(text, "<none>")) {
		gnet_prop_set_ip_val(PROP_IPV6_TRT_PREFIX, zero_host_addr);
	}
	G_FREE_NULL(text);
}
FOCUS_TO_ACTIVATE(entry_config_ipv6_trt_prefix)

void
on_entry_config_ipv6_trt_prefix_changed(GtkEditable *editable,
	gpointer unused_udata)
{
    gchar *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	const gchar *endptr;
	host_addr_t addr;
	gboolean sensitive;

	(void) unused_udata;
	g_strstrip(text);
	sensitive = string_to_host_addr(text, &endptr, &addr)
			&& '\0' == endptr[0]
			&& host_addr_is_ipv6(addr);
	gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("checkbutton_config_ipv6_trt_enable"),
		sensitive);
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
        GTK_EDITABLE(gui_dlg_prefs_lookup("entry_server_hostname")),
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
        gui_dlg_prefs_lookup("checkbutton_give_server_hostname"),
        strlen(text) > 3);		/* Minimum: "x.cx" */
	G_FREE_NULL(text);
}

enum dbg_cols {
	dbg_col_saved = 0,
	dbg_col_internal,
	dbg_col_type,
	dbg_col_name,
	dbg_col_value,

#ifdef USE_GTK2
	dbg_col_property,
#endif /* USE_GTK2 */

	num_dbg_cols
};

#ifdef USE_GTK2
static tree_view_motion_t *tvm_dbg_property;
static struct sorting_context dbg_column_sort;

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
	gtk_tree_model_get(model, &iter, dbg_col_property, &u, (-1));
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
	gpointer unused_data)
{
	(void) unused_event;
	(void) unused_data;

	update_tooltip(GTK_TREE_VIEW(widget), NULL);
	tree_view_motion_clear_callback(&tvm_dbg_property);
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

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_dbg_property"));
	g_return_if_fail(NULL != tv);
	model = gtk_tree_view_get_model(tv);
	g_return_if_fail(NULL != model);

	path = gtk_tree_path_new_from_string(path_str);
	gtk_tree_model_get_iter(model, &iter, path);

	u = 0;
	gtk_tree_model_get(model, &iter, dbg_col_property, &u, (-1));
	prop = (property_t) u;
	if (!gnet_prop_is_internal(prop))
		gnet_prop_set_from_string(prop,	text);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter,
		dbg_col_value, gnet_prop_to_string(prop),
		(-1));

	gtk_tree_path_free(path);
}

static gboolean
refresh_property(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer unused_data)
{
	property_t prop;
	guint u;

	(void) unused_data;
	(void) unused_path;

	u = 0;
	gtk_tree_model_get(model, iter, dbg_col_property, &u, (-1));
	prop = (property_t) u;
	gtk_list_store_set(GTK_LIST_STORE(model), iter,
		dbg_col_value, gnet_prop_to_string(prop),
		(-1));
	return FALSE;
}

void
on_button_dbg_property_refresh_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	GtkTreeModel *model;
	GtkTreeView *tv;

	(void) unused_button;
	(void) unused_udata;

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_dbg_property"));
	model = gtk_tree_view_get_model(tv);
	gtk_tree_model_foreach(GTK_TREE_MODEL(model), refresh_property, NULL);
}

static void
dbg_property_update_selection(void)
{
	GtkTreeView *tv;
	GtkTreeSelection *s;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;
	const gchar *text;

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_dbg_property"));
	s = gtk_tree_view_get_selection(tv);
	if (gtk_tree_selection_get_selected(s, &model, &iter)) {
		guint u = 0;

		gtk_tree_model_get(model, &iter, dbg_col_property, &u, (-1));
		text = gnet_prop_default_to_string((property_t) u);
	} else {
		text = _("<no property selected>");
	}

    widget = gui_dlg_prefs_lookup("label_dbg_property_default");
	gtk_label_set_text(GTK_LABEL(widget), text);
}

static void
on_cursor_changed(GtkTreeView *unused_tv, gpointer unused_udata)
{
	(void) unused_tv;
	(void) unused_udata;
	dbg_property_update_selection();
}

static void
on_dbg_column_clicked(GtkTreeViewColumn *column, void *udata)
{
	(void) udata;

	column_sort_tristate(column, &dbg_column_sort);
}

static inline const char *
dbg_get_data(GtkTreeModel *model, GtkTreeIter *iter, gint column)
{
	GValue value;

	ZERO(&value);
	gtk_tree_model_get_value(model, iter, column, &value);
	return g_value_get_string(&value);
}

static gint
dbg_column_cmp(
	GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer col)
{
	const char *sa, *sb;
	gint column = pointer_to_int(col);

	sa = dbg_get_data(model, a, column);
	sb = dbg_get_data(model, b, column);
	return strcmp(sa, sb);
}

static void
dbg_tree_init(void)
{
	static const struct {
		const gchar *title;
		const gint width;
		const gboolean editable;
		const enum dbg_cols id;
	} columns[] = {
		{ N_("Saved"),	 	  0, FALSE, dbg_col_saved },
		{ N_("Internal"), 	  0, FALSE, dbg_col_internal },
		{ N_("Type"),		  0, FALSE, dbg_col_type },
		{ N_("Property"),	  0, FALSE, dbg_col_name },
		{ N_("Value"),		200, TRUE,  dbg_col_value  },
		{ NULL,				  0, FALSE, dbg_col_property },	/* property_t */
	};
	GtkListStore *store;
	GtkTreeView *tv;
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(columns) == (guint) num_dbg_cols);

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_dbg_property"));
	store = GTK_LIST_STORE(gtk_list_store_new(G_N_ELEMENTS(columns),
				G_TYPE_STRING,		/* Saved? */
				G_TYPE_STRING,		/* Internal? */
				G_TYPE_STRING,		/* Type */
				G_TYPE_STRING,		/* Name */
				G_TYPE_STRING,		/* Value */
				G_TYPE_UINT));		/* property_t */

	gtk_tree_view_set_model(tv, GTK_TREE_MODEL(store));
	g_object_unref(store);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;

		/* Skip invisible column zero which holds the property_t */
		if (!columns[i].title)
			continue;

		renderer = gtk_cell_renderer_text_new();

		if (columns[i].editable) {
			gui_signal_connect(renderer, "edited", on_cell_edited, NULL);
			g_object_set(renderer,
					"editable", TRUE,
					NULL_PTR);
		}

		column = gtk_tree_view_column_new_with_attributes(
				_(columns[i].title), renderer,
				"text", i,
				NULL_PTR);

		g_object_set(renderer,
				"xalign", 0.0,
				"xpad", GUI_CELL_RENDERER_XPAD,
				"ypad", GUI_CELL_RENDERER_YPAD,
				NULL_PTR);
		g_object_set(column,
				"min-width", 1,
				"resizable", TRUE,
				"reorderable", FALSE,
				NULL_PTR);

		if (columns[i].width) {
			g_object_set(column,
				"fixed-width", columns[i].width,
				"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
				NULL_PTR);
		} else {
			g_object_set(column,
				"sizing", GTK_TREE_VIEW_COLUMN_AUTOSIZE,
				NULL_PTR);
		}


		gtk_tree_view_column_set_sort_column_id(column, i);
		gtk_tree_view_append_column(tv, column);

		gtk_tree_sortable_set_sort_func(
			GTK_TREE_SORTABLE(gtk_tree_view_get_model(tv)),
			i, dbg_column_cmp, uint_to_pointer(i), NULL);

		column_sort_tristate_register(column, on_dbg_column_clicked, NULL);
	}

	gui_signal_connect(tv, "enter-notify-event", on_enter_notify, tv);
	gui_signal_connect(tv, "leave-notify-event", on_leave_notify, tv);
	gui_signal_connect(tv, "cursor-changed", on_cursor_changed, tv);
}

static void
dbg_property_show_list(const pslist_t *props)
{
	const pslist_t *sl;
	GtkTreeView *tv;
	GtkListStore *store;

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_dbg_property"));
	if (!gtk_tree_view_get_model(tv))
		dbg_tree_init();

	store = GTK_LIST_STORE(gtk_tree_view_get_model(tv));
	gtk_list_store_clear(store);

	if (!props) {
		const gchar *text = _("<no property selected>");
		GtkWidget *widget;

		widget = gui_dlg_prefs_lookup("label_dbg_property_limits");
		gtk_label_set_text(GTK_LABEL(widget), text);
		/* Gtk+ 2.x has editable column cells */
#ifdef USE_GTK1
		widget = gui_dlg_prefs_lookup("label_dbg_property_name");
		gtk_label_set_text(GTK_LABEL(widget), text);
		widget = gui_dlg_prefs_lookup("entry_dbg_property_value");
		gtk_entry_set_text(GTK_ENTRY(widget), text);
		widget = gui_dlg_prefs_lookup("entry_dbg_property_default");
		gtk_entry_set_text(GTK_ENTRY(widget), text);
#endif /* USE_GTK1 */
#ifdef USE_GTK2
		widget = gui_dlg_prefs_lookup("label_dbg_property_default");
		gtk_label_set_text(GTK_LABEL(widget), text);
#endif /* USE_GTK2 */
	}

	PSLIST_FOREACH(props, sl) {
		GtkTreeIter iter;
		property_t prop;

		prop = GPOINTER_TO_UINT(sl->data);

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
			dbg_col_saved,     gnet_prop_is_saved(prop) ? _("Yes") : _("No"),
			dbg_col_internal,  gnet_prop_is_internal(prop) ? _("Yes") : _("No"),
			dbg_col_type,      gnet_prop_type_to_string(prop),
			dbg_col_name,      gnet_prop_name(prop),
			dbg_col_value,     gnet_prop_to_string(prop),
			dbg_col_property,  (guint) prop,
			(-1));
	}
}
#endif /* USE_GTK2 */

#ifdef USE_GTK1
static void
dbg_property_update_selection(void)
{
	const gchar *tip, *label_text, *def_text, *value_text;
	GtkCList *clist;
	GtkLabel *label;
	GtkEntry *value, *def;
	gpointer data;
	gint row;

   	clist = GTK_CLIST(gui_dlg_prefs_lookup("clist_dbg_property"));
	label = GTK_LABEL(gui_dlg_prefs_lookup("label_dbg_property_name"));
    value = GTK_ENTRY(gui_dlg_prefs_lookup("entry_dbg_property_value"));
    def = GTK_ENTRY(gui_dlg_prefs_lookup("entry_dbg_property_default"));

    if (
		clist->selection &&
		-1 != (row = GPOINTER_TO_INT(clist->selection->data)) &&
		NULL != (data = gtk_clist_get_row_data(clist, row))
	) {
		property_t prop = GPOINTER_TO_UINT(data);

		label_text = gnet_prop_name(prop);
		value_text = gnet_prop_to_string(prop);
		def_text = gnet_prop_default_to_string(prop);
		tip = gnet_prop_description(prop);
	} else {
		const gchar *none = _("<no property selected>");

		label_text = none;
		def_text = none;
		value_text = none;
		tip = _("Select a property to see its description.");
	}
	gtk_label_set_text(label, label_text);
	gtk_entry_set_text(def, def_text);
	gtk_entry_set_text(value, value_text);
	gtk_tooltips_set_tip(settings_gui_tooltips(), GTK_WIDGET(value), tip, NULL);
}

static void
dbg_property_set_row(GtkCList *clist, gint row, property_t prop)
{
	gint i;

	g_assert(clist);
	g_assert(row != -1);

	for (i = 0; i < (gint) num_dbg_cols; i++) {
		const gchar *text;
		switch ((enum dbg_cols) i) {
		case dbg_col_saved:
			text = gnet_prop_is_saved(prop) ? _("Yes") : _("No");
			break;
		case dbg_col_internal:
			text = gnet_prop_is_internal(prop) ? _("Yes") : _("No");
			break;
		case dbg_col_type:
			text = gnet_prop_type_to_string(prop);
			break;
		case dbg_col_name:
			text = gnet_prop_name(prop);
			break;
		case dbg_col_value:
			text = gnet_prop_to_string(prop);
			break;
		default:
			g_assert_not_reached();
			text = "(null)";
		}
		gtk_clist_set_text(clist, row, i, text);
	}
   	gtk_clist_set_row_data(clist, row, GUINT_TO_POINTER(prop));
}

static void
dbg_property_show_list(const pslist_t *props)
{
	GtkCList *clist;
	const pslist_t *sl;

   	clist = GTK_CLIST(gui_dlg_prefs_lookup("clist_dbg_property"));
	gtk_clist_freeze(clist);
	gtk_clist_clear(clist);

	PSLIST_FOREACH(props, sl) {
		static const char * const titles[num_dbg_cols] =
			{ "", "", "", "", "", };
		property_t prop = GPOINTER_TO_UINT(sl->data);
		gint row;

    	row = gtk_clist_append(clist, deconstify_gpointer(titles));
		dbg_property_set_row(clist, row, prop);
	}
	gtk_clist_sort(clist);
	gtk_clist_columns_autosize(clist);
	gtk_clist_thaw(clist);
}

void
on_entry_dbg_property_value_activate(GtkEditable *editable,
	gpointer unused_udata)
{
	GtkCList *clist;

	(void) unused_udata;

   	clist = GTK_CLIST(gui_dlg_prefs_lookup("clist_dbg_property"));

    if (clist->selection) {
   		gchar *text;
		property_t prop;
		gint row;

		row = GPOINTER_TO_INT(clist->selection->data);
		prop = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));

		if (!gnet_prop_is_internal(prop)) {
			char *text = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
			gnet_prop_set_from_string(prop,	text);
			dbg_property_set_row(clist, row, prop);
			G_FREE_NULL(text);
		}
	}
}

void
on_clist_dbg_property_select_row(GtkCList *unused_clist, gint unused_row,
	gint unused_column, GdkEvent *unused_event, gpointer unused_udata)
{

	(void) unused_clist;
	(void) unused_row;
	(void) unused_column;
	(void) unused_event;
	(void) unused_udata;

	dbg_property_update_selection();
}

static gboolean dbg_property_cmp_name_inverted = TRUE;
static gint
dbg_property_cmp_name(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    property_t a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    property_t b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);
	gint r;

	(void) unused_clist;
	r = strcmp(gnet_prop_name(a), gnet_prop_name(b));
	return dbg_property_cmp_name_inverted ? -r : r;
}

static gboolean dbg_property_cmp_type_inverted = TRUE;
static gint
dbg_property_cmp_type(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    property_t a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    property_t b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);
	gint r;

	(void) unused_clist;
	r = strcmp(gnet_prop_type_to_string(a), gnet_prop_type_to_string(b));
	return dbg_property_cmp_type_inverted ? -r : r;
}

static gboolean dbg_property_cmp_saved_inverted = TRUE;
static gint
dbg_property_cmp_saved(GtkCList *unused_clist,
	gconstpointer ptr1, gconstpointer ptr2)
{
    property_t a = GPOINTER_TO_UINT(((const GtkCListRow *) ptr1)->data);
    property_t b = GPOINTER_TO_UINT(((const GtkCListRow *) ptr2)->data);
	gint r;

	(void) unused_clist;
	r = CMP(gnet_prop_is_saved(a), gnet_prop_is_saved(b));
	return dbg_property_cmp_saved_inverted ? -r : r;
}


void
on_clist_dbg_property_click_column(GtkCList *clist, gint column,
	gpointer unused_udata)
{
	gboolean do_sort = FALSE;

	(void) unused_udata;

	g_assert(column >= 0 && column < num_dbg_cols);

	switch ((enum dbg_cols) column) {
	case dbg_col_saved:
		gtk_clist_set_compare_func(clist, dbg_property_cmp_saved);
		dbg_property_cmp_saved_inverted = !dbg_property_cmp_saved_inverted;
		do_sort = TRUE;
		break;
	case dbg_col_type:
		gtk_clist_set_compare_func(clist, dbg_property_cmp_type);
		dbg_property_cmp_type_inverted = !dbg_property_cmp_type_inverted;
		do_sort = TRUE;
		break;
	case dbg_col_name:
		gtk_clist_set_compare_func(clist, dbg_property_cmp_name);
		dbg_property_cmp_name_inverted = !dbg_property_cmp_name_inverted;
		do_sort = TRUE;
		break;
	case dbg_col_value:
		/* Don't sort by values */
		break;
	case num_dbg_cols:
		g_assert_not_reached();
	}

	if (do_sort)
		gtk_clist_sort(clist);
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
        GTK_EDITABLE(gui_dlg_prefs_lookup("entry_dbg_property_pattern")),
        0, -1));
	g_strstrip(text);

	if (0 != strcmp(text, old_pattern)) {
		pslist_t *props;

		g_strlcpy(old_pattern, text, sizeof old_pattern);
		props = gnet_prop_get_by_regex(text, NULL);
		if (!props)
			statusbar_gui_warning(10,
				_("No property name matches the pattern \"%s\"."), text);

		dbg_property_show_list(props);
		dbg_property_update_selection();
		pslist_free_null(&props);
	}
	G_FREE_NULL(text);
}

void
on_menu_searchbar_visible_activate(GtkMenuItem *menuitem,
	gpointer unused_udata)
{
	(void) unused_udata;

	checkmenu_changed(gui, PROP_SEARCHBAR_VISIBLE, menuitem);
}

void
on_menu_sidebar_visible_activate(GtkMenuItem *menuitem, gpointer unused_udata)
{
	(void) unused_udata;

	checkmenu_changed(gui, PROP_SIDEBAR_VISIBLE, menuitem);

	/*
	 * Gtk+ 2.x automagically moves the gutter when a child's
	 * visibility status changes.
	 */
#ifdef USE_GTK1
	{
		GtkPaned *paned;
		gboolean sidebar;

		gui_prop_get_boolean_val(PROP_SIDEBAR_VISIBLE, &sidebar);
		paned = GTK_PANED(gui_main_window_lookup("hpaned_main"));
		if (sidebar) {
			paned_restore_position(paned, PROP_MAIN_DIVIDER_POS);
		} else {
			paned_save_position(paned, PROP_MAIN_DIVIDER_POS);
			gtk_paned_set_position(paned, 0);
		}
	}
#endif /* USE_GTK1 */
}

void
on_menu_menubar_visible_activate(GtkMenuItem *menuitem,
	gpointer unused_udata)
{
	(void) unused_udata;

	checkmenu_changed(gui, PROP_MENUBAR_VISIBLE, menuitem);
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
on_menu_autohide_bws_dht_activate(GtkMenuItem *menuitem,
	gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_AUTOHIDE_BWS_DHT, menuitem);
}

void
on_menu_bws_dht_in_visible_activate(GtkMenuItem *menuitem,
	gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_DHT_IN_VISIBLE, menuitem);
}

void
on_menu_bws_dht_out_visible_activate(GtkMenuItem *menuitem,
	gpointer unused_udata)
{
	(void) unused_udata;
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_DHT_OUT_VISIBLE, menuitem);
}

/* vi: set ts=4 sw=4 cindent: */
