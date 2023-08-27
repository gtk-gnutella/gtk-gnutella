/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * Reflection of changes in backend or gui properties in the GUI.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

#include "columns.h"
#include "downloads_common.h"
#include "filter.h"
#include "html_view.h"
#include "misc.h"
#include "monitor.h"
#include "nodes_common.h"
#include "search.h"
#include "search_common.h"
#include "search_stats.h"
#include "settings.h"
#include "settings_cb.h"
#include "statusbar.h"

#include "if/gnet_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/dht/kuid.h"
#include "if/dht/routing.h"

#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/halloc.h"
#include "lib/hikset.h"
#include "lib/mempcpy.h"
#include "lib/product.h"
#include "lib/prop.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * This file has five parts:
 *
 * I.     General variables/defines used in this module
 * II.    Simple default callbacks
 * III.   Special case callbacks
 * IV.    Control functions.
 * V.     Property-to-callback map
 *
 * To add another property change listener, just define the callback
 * in the callback section (IV), or use a standard call like
 * update_spinbutton (from part III) and add an entry to
 * the property_map table. The rest will be done automatically.
 * If debugging is activated, you will get a list of unmapped and
 * ignored properties on startup.
 * To ignore a property, just set the cb, fn_toplevel and wid attributes
 * in the property_map to IGNORE_CB,
 * To create a listener which is not bound to a signle widget, set
 * the fn_toplevel and wid attributed of your property_map entry to
 * NULL.
 */

/***
 *** I. General variables/defines used in this module
 ***/

typedef GtkWidget *(*fn_toplevel_t)(void);

/**
 * The property maps contain informaiton about which widget should reflect
 * which property.
 */
typedef struct prop_map {
    const fn_toplevel_t fn_toplevel;  /**< get toplevel widget */
    const property_t prop;            /**< property handle */
    const prop_changed_listener_t cb; /**< callback function */
    const gboolean init;              /**< init widget with current value */
    const gchar *wid;                 /**< name of the widget for tooltip */
    enum frequency_type f_type;
    guint32 f_interval;

    /*
     * Automatic field filled in by settings_gui_init_prop_map
     */
    prop_type_t type;                 /**< property type */
    const prop_set_stub_t *stub;      /**< property set stub */
    gint *init_list;                  /**< init_list for reverse lookup */
} prop_map_t;

#define NOT_IN_MAP	(-1)
#define IGNORE_CB	NULL

static const prop_set_stub_t *gui_prop_set_stub;
static const prop_set_stub_t *gnet_prop_set_stub;

static gint gui_init_list[GUI_PROPERTY_NUM];
static gint gnet_init_list[GNET_PROPERTY_NUM];
static GtkTooltips* tooltips;

static gchar *home_dir;
static const gchar property_file[] = "config_gui";

static prop_set_t *properties;
static hikset_t *sensitive_changes;

#define SENSITIVE_DEFER		250		/**< ms: deferred sensitive widget change */

static prop_map_t * settings_gui_get_map_entry(property_t prop);

static const struct {
	const gchar *name;
	const property_t prop;
} panes[] = {
	{ "vpaned_fileinfo",	PROP_FILEINFO_DIVIDER_POS },
	{ "hpaned_main",		PROP_MAIN_DIVIDER_POS },
	{ "vpaned_results",		PROP_RESULTS_DIVIDER_POS },
};

/*
 * Callback declarations (only those whose pre-declaration is needed).
 */

static gboolean gnet_connections_changed(property_t prop);
static gboolean downloads_count_changed(property_t prop);
static gboolean dl_running_count_changed(property_t prop);
static void update_output_bw_display(void);
static void update_input_bw_display(void);

/***
 *** II. Simple default callbacks
 ***/

static gboolean
update_entry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    gtk_entry_set_text(GTK_ENTRY(w), stub->to_string(prop));

    return FALSE;
}

static gboolean
update_label(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    gtk_label_set_text(GTK_LABEL(w), stub->to_string(prop));

    return FALSE;
}


static gboolean
update_spinbutton(property_t prop)
{
    GtkWidget *w;
	uint32 val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GtkAdjustment *adj;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
	case PROP_TYPE_GUINT32:
		stub->guint32.get(prop, &val, 0, 1);
		break;
	default:
		val = 0;
		g_error("%s: incompatible type: %u", G_STRFUNC, (uint) map_entry->type);
    }

    adj = gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(w));
    gtk_adjustment_set_value(adj, val);

    return FALSE;
}

static gboolean
update_togglebutton(property_t prop)
{
    GtkWidget *w;
    gboolean val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
	case PROP_TYPE_BOOLEAN:
		stub->boolean.get(prop, &val, 0, 1);
		break;
	default:
		val = 0;
		g_error("%s: incompatible type: %u", G_STRFUNC, (uint) map_entry->type);
    }

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    return FALSE;
}

static gboolean
update_multichoice(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GList *l_iter;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
	case PROP_TYPE_MULTICHOICE:
		stub->guint32.get(prop, &val, 0, 1);
		break;
	default:
		val = 0;
		g_error("%s: incompatible type: %u", G_STRFUNC, (uint) map_entry->type);
    }

	if (GTK_IS_COMBO(w)) {
		l_iter = GTK_LIST(GTK_COMBO(w)->list)->children;
		for (/* NOTHING */; NULL != l_iter; l_iter = g_list_next(l_iter)) {
			gpointer cur = gtk_object_get_user_data(GTK_OBJECT(l_iter->data));

			if (GPOINTER_TO_UINT(cur) == val) {
				gtk_list_item_select(GTK_LIST_ITEM(l_iter->data));
				break;
			}
		}
	} else if (GTK_IS_OPTION_MENU(w)) {
		option_menu_select_item_by_data(GTK_OPTION_MENU(w),
			GUINT_TO_POINTER(val));
	} else {
		g_assert_not_reached();
	}

    return FALSE;
}

static gboolean
update_entry_duration(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    guint32 value = 0;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	stub->guint32.get(prop, &value, 0, 1);
    gtk_entry_set_text(GTK_ENTRY(w), short_time(value));

    return FALSE;
}

static gboolean
update_size_entry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
	guint64 value = 0;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	stub->guint64.get(prop, &value, 0, 1);
    gtk_entry_set_text(GTK_ENTRY(w), short_kb_size(value, show_metric_units()));

    return FALSE;
}

#ifdef USE_GTK2
static gint
str_cmp_func(gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

static GtkTreeModel *
get_shared_dirs_model(void)
{
	GtkTreeView *tv;
	GtkTreeModel *model;

	tv = GTK_TREE_VIEW(gui_dlg_prefs_lookup("treeview_shared_dirs"));
	model = gtk_tree_view_get_model(tv);

	if (!model) {
		GtkTreeSelection *selection;
    	GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;

		model = GTK_TREE_MODEL(gtk_list_store_new(2,
									G_TYPE_STRING, G_TYPE_STRING));

		gtk_tree_view_set_model(tv, model);
		g_object_unref(model);

		selection = gtk_tree_view_get_selection(tv);
		gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
		renderer = gtk_cell_renderer_text_new();
		column = gtk_tree_view_column_new_with_attributes(NULL, renderer,
					"text", 1, NULL_PTR);

		g_object_set(renderer,
			"xalign", 0.0,
			"xpad", GUI_CELL_RENDERER_XPAD,
			"ypad", GUI_CELL_RENDERER_YPAD,
			NULL_PTR);
		g_object_set(column,
			"fixed-width", 200,
			"min-width", 1,
			"resizable", TRUE,
			"reorderable", FALSE,
			"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
			NULL_PTR);

   		gtk_tree_view_append_column(tv, column);
	}

	return model;
}

static gboolean
update_shared_dirs(property_t prop)
{
	GtkTreeModel *model;
	pslist_t *sl_dirs, *sl;
	char *dirs;

	model = get_shared_dirs_model();
	gtk_list_store_clear(GTK_LIST_STORE(model));

	/* Convert the string to a list of strings for sorting */
  	dirs = gnet_prop_get_string(prop, NULL, 0);
	sl_dirs = dirlist_parse(dirs);

	/* Feed the sorted list of directories to the GtkListStore */
	sl_dirs = pslist_sort(sl_dirs, str_cmp_func);
	PSLIST_FOREACH(sl_dirs, sl) {
		GtkTreeIter iter;
		char *dir_utf8;

		dir_utf8 = filename_to_utf8_normalized(sl->data, UNI_NORM_GUI);
		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		gtk_list_store_set(GTK_LIST_STORE(model), &iter,
			0, sl->data,/* The actual pathname, not necessarily UTF-8 encoded */
			1, dir_utf8, /* The best effort UTF-8 conversion for viewing */
			(-1));

		/*
		 * gtk_list_store_set() makes copies of the strings, thus
		 * free the originals here.
		 */

		if (sl->data != dir_utf8) {
			G_FREE_NULL(dir_utf8);
		}
		HFREE_NULL(sl->data);
	}
	pslist_free_null(&sl_dirs);
	G_FREE_NULL(dirs);

    return FALSE;
}
#endif /* USE_GTK2 */

static gboolean
update_window_geometry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = top;

    if (!w->window) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: top level window not available (NULL)", G_STRFUNC);
        return FALSE;
    }

    switch (map_entry->type) {
	case PROP_TYPE_GUINT32:
		{
			guint32 geo[4];

			stub->guint32.get(prop, geo, 0, 4);
			gdk_window_move_resize(w->window, geo[0], geo[1], geo[2], geo[3]);

		}
		break;
	default:
		g_error("%s: incompatible type: %u", G_STRFUNC, (uint) map_entry->type);
	}

    return FALSE;
}

/**
 * This is not really a generic updater.
 *
 * It's just here because it's used by all bandwidths spinbuttons. It
 * divides the property value by 1024 before setting the value to the
 * widget, just like the callbacks of those widget multiply the widget
 * value by 1024 before setting the property.
 */
static gboolean
update_bandwidth_spinbutton(property_t prop)
{
    GtkWidget *w;
    uint64 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
	case PROP_TYPE_GUINT64:
		stub->guint64.get(prop, &val, 0, 1);
		break;
	default:
		val = 0;
		g_error("%s: incompatible type %u", G_STRFUNC, (uint) map_entry->type);
	}

    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), (float) val / 1024.0);

    return FALSE;
}

/***
 *** III. Special case callbacks
 ***/

static gboolean current_display_metric_units;

static gboolean
display_metric_units_changed(property_t prop)
{
	GtkWidget *widget;

    widget = gui_dlg_prefs_lookup("checkbutton_config_metric");
    gnet_prop_get_boolean_val(prop, &current_display_metric_units);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget),
		current_display_metric_units);
    return FALSE;
}

gboolean
show_metric_units(void)
{
	return current_display_metric_units;
}

static gboolean
bw_gnet_lin_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_glin");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_glin");

    gnet_prop_get_boolean_val(prop, &val);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean
bw_gnet_lout_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_glout");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_glout");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_output_bw_display();

    return FALSE;
}

static gboolean
bw_http_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_in");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_in");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean
bw_gnet_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_gin");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_gin");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean
bw_gnet_out_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_gout");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_gout");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_output_bw_display();

    return FALSE;
}

static gboolean
bw_dht_out_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = gui_dlg_prefs_lookup("checkbutton_config_bws_dht_out");
    s = gui_dlg_prefs_lookup("spinbutton_config_bws_dht_out");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_output_bw_display();

    return FALSE;
}

static gboolean
bw_ul_usage_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;
    gboolean val2;

    gnet_prop_get_boolean_val(prop, &val);
    gnet_prop_get_boolean_val(PROP_BW_HTTP_OUT_ENABLED, &val2);

    w = gui_dlg_prefs_lookup("checkbutton_config_bw_ul_usage_enabled");
    s = gui_dlg_prefs_lookup("spinbutton_config_ul_usage_min_percentage");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val && val2);

    return FALSE;
}

static gboolean
bw_http_out_enabled_changed(property_t prop)
{
    gboolean val, val2;

    gnet_prop_get_boolean_val(prop, &val);
    gnet_prop_get_boolean_val(PROP_BW_UL_USAGE_ENABLED, &val2);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(gui_dlg_prefs_lookup("checkbutton_config_bws_out")),
		val);

    gtk_widget_set_sensitive(
		gui_dlg_prefs_lookup("spinbutton_config_bws_out"), val);
    gtk_widget_set_sensitive(
		gui_dlg_prefs_lookup("checkbutton_config_bw_ul_usage_enabled"), val);
    gtk_widget_set_sensitive(
		gui_dlg_prefs_lookup("spinbutton_config_ul_usage_min_percentage"),
		val && val2);
	update_output_bw_display();

    return FALSE;
}

/**
 * Hide the "frame_status_images" frame and show it again, to be able
 * to shrink it back to its minimal size when an icon is removed.
 */
static void
shrink_frame_status(void)
{
	gui_shrink_widget_named("frame_status_images");
}

static GtkWidget *
get_push_button(void)
{
	return gui_popup_sources_lookup("popup_sources_push");
}

static gboolean
is_firewalled_changed(property_t unused_prop)
{
	GtkWidget *icon_firewall;
	GtkWidget *icon_firewall_punchable;
	GtkWidget *icon_tcp_firewall;
	GtkWidget *icon_udp_firewall;
	GtkWidget *icon_udp_firewall_punchable;
	GtkWidget *icon_open;
	gboolean is_tcp_firewalled;
	gboolean is_udp_firewalled;
	gboolean recv_solicited_udp;
	gboolean send_pushes;
	gboolean enable_udp;

	(void) unused_prop;

    icon_firewall = gui_main_window_lookup("eventbox_image_firewall");
    icon_firewall_punchable =
		gui_main_window_lookup("eventbox_image_firewall_punchable");
    icon_tcp_firewall = gui_main_window_lookup("eventbox_image_tcp_firewall");
    icon_udp_firewall = gui_main_window_lookup("eventbox_image_udp_firewall");
    icon_udp_firewall_punchable =
		gui_main_window_lookup("eventbox_image_firewall_udp_punchable");
	icon_open = gui_main_window_lookup("eventbox_image_no_firewall");

    gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &is_tcp_firewalled);
    gnet_prop_get_boolean_val(PROP_IS_UDP_FIREWALLED, &is_udp_firewalled);
    gnet_prop_get_boolean_val(PROP_RECV_SOLICITED_UDP, &recv_solicited_udp);
    gnet_prop_get_boolean_val(PROP_ENABLE_UDP, &enable_udp);

	gtk_widget_hide(icon_open);
	gtk_widget_hide(icon_tcp_firewall);
	gtk_widget_hide(icon_udp_firewall);
	gtk_widget_hide(icon_udp_firewall_punchable);
	gtk_widget_hide(icon_firewall);
	gtk_widget_hide(icon_firewall_punchable);

	if (!enable_udp)
		is_udp_firewalled = FALSE;	/* Ignore firewalled status if no UDP */

	if (is_tcp_firewalled && is_udp_firewalled) {
		if (recv_solicited_udp)
			gtk_widget_show(icon_firewall_punchable);
		else
			gtk_widget_show(icon_firewall);
	} else if (is_tcp_firewalled)
		gtk_widget_show(icon_tcp_firewall);
	else if (is_udp_firewalled) {
		if (recv_solicited_udp)
			gtk_widget_show(icon_udp_firewall_punchable);
		else
			gtk_widget_show(icon_udp_firewall);
	} else {
		gtk_widget_show(icon_open);
	}
	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
	send_pushes = send_pushes && !is_tcp_firewalled;

	gtk_widget_set_sensitive(get_push_button(), send_pushes);

	return FALSE;
}

static gboolean
dht_boot_status_changed(property_t prop)
{
    static GtkWidget *icon_none;
    static GtkWidget *icon_seeded;
    static GtkWidget *icon_own_kuid;
    static GtkWidget *icon_completing;
    static GtkWidget *icon_active;
    static GtkWidget *icon_passive;
	guint32 status;

	if G_UNLIKELY(NULL == icon_none) {
    	icon_none = gui_main_window_lookup("eventbox_image_dht_none");
    	icon_seeded = gui_main_window_lookup("eventbox_image_dht_seeded");
    	icon_own_kuid = gui_main_window_lookup("eventbox_image_dht_own_kuid");
    	icon_completing =
			gui_main_window_lookup("eventbox_image_dht_completing");
    	icon_active = gui_main_window_lookup("eventbox_image_dht_active");
    	icon_passive = gui_main_window_lookup("eventbox_image_dht_passive");
	}

	gtk_widget_hide(icon_none);
	gtk_widget_hide(icon_seeded);
	gtk_widget_hide(icon_own_kuid);
	gtk_widget_hide(icon_completing);
	gtk_widget_hide(icon_active);
	gtk_widget_hide(icon_passive);

	if (!guc_dht_enabled())
		goto done;

    gnet_prop_get_guint32_val(prop, &status);

	switch ((enum dht_bootsteps) status) {
	case DHT_BOOT_NONE:
	case DHT_BOOT_SHUTDOWN:
		gtk_widget_show(icon_none);
		break;
	case DHT_BOOT_SEEDED:
		gtk_widget_show(icon_seeded);
		break;
	case DHT_BOOT_OWN:
		gtk_widget_show(icon_own_kuid);
		break;
	case DHT_BOOT_COMPLETING:
		gtk_widget_show(icon_completing);
		break;
	case DHT_BOOT_COMPLETED:
		{
			guint32 mode;
			gnet_prop_get_guint32_val(PROP_DHT_CURRENT_MODE, &mode);

			if (DHT_MODE_ACTIVE == mode) {
				gtk_widget_show(icon_active);
			} else {
				gtk_widget_show(icon_passive);
			}
		}
		break;
	case DHT_BOOT_MAX_VALUE:
		g_assert_not_reached();
	}

done:
	shrink_frame_status();
	return FALSE;
}

static gboolean
dht_current_mode_changed(property_t unused_prop)
{
	(void) unused_prop;

	return dht_boot_status_changed(PROP_DHT_BOOT_STATUS);
}

static gboolean
enable_dht_changed(property_t prop)
{
	gboolean changed;
	gboolean enabled;

	gnet_prop_get_boolean_val(prop, &enabled);

	changed = update_togglebutton(prop);
	(void) dht_boot_status_changed(PROP_DHT_BOOT_STATUS);

	return changed;
}

static gboolean
enable_udp_changed(property_t prop)
{
	gboolean changed;
	gboolean enabled;

	gnet_prop_get_boolean_val(prop, &enabled);

	changed = update_togglebutton(prop);
	(void) is_firewalled_changed(prop);
	(void) dht_boot_status_changed(PROP_DHT_BOOT_STATUS);

	return changed;
}

static gboolean
plug_icon_changed(property_t unused_prop)
{
	GtkWidget *image_online;
	GtkWidget *image_offline;
	GtkWidget *tb;
	gboolean val_is_connected;
	gboolean val_online_mode;

	(void) unused_prop;

    image_online = gui_main_window_lookup("image_online");
	image_offline = gui_main_window_lookup("image_offline");
	tb = gui_main_window_lookup("togglebutton_online");

    gnet_prop_get_boolean_val(PROP_IS_INET_CONNECTED, &val_is_connected);
    gnet_prop_get_boolean_val(PROP_ONLINE_MODE, &val_online_mode);

	if (val_is_connected && val_online_mode) {
		gtk_widget_show(image_online);
		gtk_widget_hide(image_offline);
	} else {
		gtk_widget_hide(image_online);
		gtk_widget_show(image_offline);
	}

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tb), val_online_mode);

	return FALSE;
}

static gboolean
update_byte_size_entry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
	guint64 value;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	gnet_prop_get_guint64_val(prop, &value);
    gtk_entry_printf(GTK_ENTRY(w), "%s (%s)",
		short_size(value, show_metric_units()), stub->to_string(prop));

    return FALSE;
}

static gboolean
update_toggle_remove_on_mismatch(property_t prop)
{
    gboolean value;
    gboolean ret;

    ret = update_togglebutton(prop);
    gnet_prop_get_boolean_val(prop, &value);

    gtk_widget_set_sensitive(
		gui_main_window_lookup("spinbutton_mismatch_backout"),
		value ? FALSE : TRUE);

    return ret;
}

static gboolean
update_toggle_node_show_detailed_info(property_t prop)
{
	GtkWidget *frame = gui_dlg_prefs_lookup("frame_gnet_detailed_traffic");
	gboolean value;
	gboolean ret;

	ret = update_togglebutton(prop);
	gui_prop_get_boolean_val(prop, &value);

	if (value)
		gtk_widget_show(frame);
	else
		gtk_widget_hide(frame);

	return ret;
}

static gboolean
update_label_date(property_t prop)
{
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    GtkWidget *top = map_entry->fn_toplevel();
    GtkWidget *w;
	time_t t;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	gnet_prop_get_timestamp_val(prop, &t);
	if (t == 0) {
		gtk_label_set_text(GTK_LABEL(w), _("Never"));
	} else {
		static const gchar date_fmt[] = "%Y-%m-%d %H:%M:%S";
		gchar buf[128];
		size_t len;

		len = strftime(ARYLEN(buf), date_fmt, localtime(&t));
		buf[len] = '\0';
		gtk_label_set_text(GTK_LABEL(w), buf);
	}

    return FALSE;
}

static gboolean
update_label_duration(property_t prop)
{
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GtkWidget *w;
	guint32 val;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	stub->guint32.get(prop, &val, 0, 1);
	gtk_label_set_text(GTK_LABEL(w), short_time(val));

    return FALSE;
}

static gboolean
update_label_yes_or_no(property_t prop)
{
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GtkWidget *w;
	gboolean val;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    if (w == NULL) {
		if (GUI_PROPERTY(gui_debug))
			g_warning("%s: widget not found: [%s]", G_STRFUNC, map_entry->wid);
        return FALSE;
    }

	stub->boolean.get(prop, &val, 0, 1);
    gtk_label_set_text(GTK_LABEL(w), val ? _("Yes") : _("No"));

    return FALSE;
}

static gboolean
update_toggle_node_watch_similar_queries(property_t prop)
{
	GtkWidget *spin = gui_dlg_prefs_lookup("spinbutton_node_queries_half_life");
	gboolean value;
	gboolean ret;

	ret = update_togglebutton(prop);
	gnet_prop_get_boolean_val(prop, &value);

	gtk_widget_set_sensitive(spin, value);

	return ret;
}

static gboolean
configured_peermode_changed(property_t prop)
{
	GtkWidget *frame = gui_dlg_prefs_lookup("frame_gnet_can_become_ultra");
	GtkWidget *qrp_frame1 = gui_dlg_prefs_lookup("frame_qrp_statistics");
	GtkWidget *qrp_frame2 = gui_dlg_prefs_lookup("frame_qrp_table_info");
	GtkWidget *qrp_frame3 = gui_dlg_prefs_lookup("frame_qrp_patch_info");
	guint32 mode;
	gboolean ret;

	ret = update_multichoice(prop);
    gnet_prop_get_guint32_val(prop, &mode);

	if (mode == NODE_P_AUTO)
		gtk_widget_show(frame);
	else
		gtk_widget_hide(frame);

	if (mode == NODE_P_NORMAL) {
		gtk_widget_hide(qrp_frame1);
		gtk_widget_hide(qrp_frame2);
		gtk_widget_hide(qrp_frame3);
	} else {
		gtk_widget_show(qrp_frame1);
		gtk_widget_show(qrp_frame2);
		gtk_widget_show(qrp_frame3);
	}

	return ret;
}

static gboolean
current_peermode_changed(property_t prop)
{
	GtkWidget *hbox_normal_ultrapeer =
		gui_main_window_lookup("hbox_normal_or_ultrapeer");
	GtkWidget *hbox_leaf = gui_main_window_lookup("hbox_leaf");
    GtkWidget *icon_ultra = gui_main_window_lookup("eventbox_image_ultra");
	GtkWidget *icon_leaf = gui_main_window_lookup("eventbox_image_leaf");
	GtkWidget *icon_legacy = gui_main_window_lookup("eventbox_image_legacy");
	guint32 mode;

    gnet_prop_get_guint32_val(prop, &mode);
	gtk_widget_hide(icon_ultra);
	gtk_widget_hide(icon_leaf);
	gtk_widget_hide(icon_legacy);

	switch (mode) {
	case NODE_P_ULTRA:
		gtk_widget_show(icon_ultra);
		gtk_widget_show(hbox_leaf);
		gtk_widget_show(hbox_normal_ultrapeer);
		break;
	case NODE_P_LEAF:
		gtk_widget_show(icon_leaf);
		gtk_widget_show(hbox_leaf);
		gtk_widget_show(hbox_normal_ultrapeer);
		break;
	case NODE_P_NORMAL:
		gtk_widget_show(icon_legacy);
		gtk_widget_show(hbox_normal_ultrapeer);
		gtk_widget_hide(hbox_leaf);
		break;
	default:
		g_assert_not_reached();
	}

    /*
	 * We need to update the bw stats because leaf bw autohiding may be on.
	 */
    gui_update_stats_frames();

	return FALSE;
}

static gboolean
monitor_enabled_changed(property_t prop)
{
    GtkWidget *w = gui_main_window_lookup("checkbutton_monitor_enable");
    gboolean val;

	g_return_val_if_fail(PROP_MONITOR_ENABLED == prop, FALSE);

    gui_prop_get_boolean_val(prop, &val);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    monitor_gui_enable_monitor(val);

    return FALSE;
}

static void
set_host_progress(const gchar *w, guint32 cur, guint32 max)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR(gui_main_window_lookup(w));
	gchar buf[256];
    guint frac;

    frac = MIN(cur, max) * 100;
	frac = max ? (frac / max) : 0;

	str_bprintf(ARYLEN(buf),
		NG_("%u/%u host (%u%%)", "%u/%u hosts (%u%%)", max),
		cur, max, frac);

    gtk_progress_bar_set_text(pg, buf);
    gtk_progress_bar_set_fraction(pg, frac / 100.0);
}

static gboolean
hosts_in_catcher_changed(property_t unused_prop)
{
    guint32 hosts_in_catcher;
    guint32 max_hosts_cached;

	(void) unused_prop;
    gnet_prop_get_guint32_val(PROP_HOSTS_IN_CATCHER, &hosts_in_catcher);
    gnet_prop_get_guint32_val(PROP_MAX_HOSTS_CACHED, &max_hosts_cached);

    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_host_catcher_clear"),
        hosts_in_catcher != 0);

    set_host_progress(
        "progressbar_hosts_in_catcher",
        hosts_in_catcher,
        max_hosts_cached);

    return FALSE;
}

static gboolean
hosts_in_ultra_catcher_changed(property_t unused_prop)
{
    guint32 hosts;
    guint32 max_hosts;

	(void) unused_prop;
    gnet_prop_get_guint32_val(PROP_HOSTS_IN_ULTRA_CATCHER, &hosts);
    gnet_prop_get_guint32_val(PROP_MAX_ULTRA_HOSTS_CACHED, &max_hosts);

    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_ultra_catcher_clear"),
        hosts != 0);

    set_host_progress(
        "progressbar_hosts_in_ultra_catcher",
        hosts,
        max_hosts);

    return FALSE;
}

static gboolean
hosts_in_g2hub_catcher_changed(property_t unused_prop)
{
    guint32 hosts;
    guint32 max_hosts;

	(void) unused_prop;
    gnet_prop_get_guint32_val(PROP_HOSTS_IN_G2HUB_CATCHER, &hosts);
    gnet_prop_get_guint32_val(PROP_MAX_G2HUB_HOSTS_CACHED, &max_hosts);

    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_g2hub_catcher_clear"),
        hosts != 0);

    set_host_progress(
        "progressbar_hosts_in_g2hub_catcher",
        hosts,
        max_hosts);

    return FALSE;
}

static gboolean
hosts_in_bad_catcher_changed(property_t unused_prop)
{
    guint32 hosts;
    guint32 max_hosts;

	(void) unused_prop;
    gnet_prop_get_guint32_val(PROP_HOSTS_IN_BAD_CATCHER, &hosts);
    gnet_prop_get_guint32_val(PROP_MAX_BAD_HOSTS_CACHED, &max_hosts);

    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_hostcache_clear_bad"),
        hosts != 0);

    /*
     * Multiply by 3 because the three bad hostcaches can't steal slots
     * from each other.
     */
    set_host_progress("progressbar_hosts_in_bad_catcher",
		hosts, max_hosts * 3);
    return FALSE;
}

static gboolean
reading_hostfile_changed(property_t prop)
{
    static statusbar_msgid_t id = {0, 0};
    gboolean state;

	g_return_val_if_fail(PROP_READING_HOSTFILE == prop, FALSE);

    gnet_prop_get_boolean_val(prop, &state);
    if (state) {
        GtkProgressBar *pg = GTK_PROGRESS_BAR
            (gui_main_window_lookup("progressbar_hosts_in_catcher"));
        gtk_progress_bar_set_text(pg, _("loading..."));
        id = statusbar_gui_message(0, _("Reading host cache..."));
    } else {
    	hosts_in_catcher_changed(PROP_HOSTS_IN_CATCHER);
		if (0 != id.scid)
       		statusbar_gui_remove(id);
    }
    return FALSE;
}

static gboolean
reading_ultrafile_changed(property_t prop)
{
    static statusbar_msgid_t id = {0, 0};
    gboolean state;

	g_return_val_if_fail(PROP_READING_ULTRAFILE == prop, FALSE);

    gnet_prop_get_boolean_val(prop, &state);
    if (state) {
        GtkProgressBar *pg = GTK_PROGRESS_BAR
            (gui_main_window_lookup("progressbar_hosts_in_ultra_catcher"));
        gtk_progress_bar_set_text(pg, _("loading..."));
        id = statusbar_gui_message(0, _("Reading ultra cache..."));
    } else {
    	hosts_in_catcher_changed(PROP_HOSTS_IN_ULTRA_CATCHER);
		if (0 != id.scid)
       		statusbar_gui_remove(id);
    }
    return FALSE;
}

static gboolean
hostcache_size_changed(property_t prop)
{
    update_spinbutton(prop);
    switch (prop) {
    case PROP_MAX_HOSTS_CACHED:
        hosts_in_catcher_changed(PROP_HOSTS_IN_CATCHER);
        break;
    case PROP_MAX_ULTRA_HOSTS_CACHED:
        hosts_in_ultra_catcher_changed(PROP_HOSTS_IN_ULTRA_CATCHER);
        break;
    case PROP_MAX_BAD_HOSTS_CACHED:
        hosts_in_bad_catcher_changed(PROP_HOSTS_IN_BAD_CATCHER);
        break;
	case PROP_MAX_G2HUB_HOSTS_CACHED:
		hosts_in_g2hub_catcher_changed(PROP_HOSTS_IN_G2HUB_CATCHER);
		break;
	default:
        g_error("%s: unknown hostcache property %d", G_STRFUNC, prop);
    }

    return FALSE;
}

static void
ancient_version_dialog(gboolean show)
{
	static struct html_view *ancient_html_view;

	if (show) {
		static const gchar msg[] = N_(
			"<html>"
			"<head>"
			"<title>Ancient version detected!</title>"
			"</head>"
			"<body>"
			"<h1>Warning</h1>"
			"<p>"
			"This version of gtk-gnutella is pretty old. Please visit "
			"<a href=\"https://gtk-gnutella.sourceforge.io/\">"
			"https://gtk-gnutella.sourceforge.io/</a> and "
			"update your copy of gtk-gnutella."
			"</p>"
			"</body>"
			"</html>"
		);

		html_view_free(&ancient_html_view);
		ancient_html_view = html_view_load_memory(
				gui_dlg_ancient_lookup("textview_ancient"),
				array_from_string(msg));
		gtk_widget_show(gui_dlg_ancient());
		if (gui_dlg_ancient()->window) {
			gdk_window_raise(gui_dlg_ancient()->window);
		}
	} else {
		html_view_free(&ancient_html_view);
		if (gui_dlg_ancient()) {
			gtk_widget_hide(gui_dlg_ancient());
		}
	}
}

void
ancient_version_dialog_show(void)
{
	if (!main_gui_ancient_is_disabled())
		ancient_version_dialog(TRUE);
}

void
ancient_version_dialog_hide(void)
{
	if (!main_gui_ancient_is_disabled())
		ancient_version_dialog(FALSE);
}

static gboolean
ancient_version_changed(property_t prop)
{
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GtkWidget *w;
    gboolean b;

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
		ancient_version_dialog_show();
        statusbar_gui_message(15, _("*** RUNNING AN OLD VERSION! ***"));
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
overloaded_cpu_changed(property_t prop)
{
    gboolean b;
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
        statusbar_gui_message(15,
			_("*** CPU OVERLOADED -- TRYING TO SAVE CYCLES ***"));
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
net_buffer_shortage_changed(property_t prop)
{
    gboolean b;
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
        statusbar_gui_message(15,
			_("*** KERNEL BUFFER SHORTAGE -- LIMITING TCP CONNECTIONS ***"));
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
tcp_no_listening_changed(property_t prop)
{
    gboolean b;
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
        statusbar_gui_message(15,
			_("*** NO LISTENING TCP SOCKET -- NO INBOUND CONNECTIONS ***"));
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
uploads_stalling_changed(property_t prop)
{
    gboolean b;
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
        statusbar_gui_warning(15,
			_("*** UPLOADS STALLING, BANDWIDTH SHORTAGE? ***"));
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
uploads_early_stalling_changed(property_t prop)
{
    gboolean b;
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    w = lookup_widget(top, map_entry->wid);
    stub->boolean.get(prop, &b, 0, 1);

    if (b) {
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
		shrink_frame_status();
    }

    return FALSE;
}

static gboolean
port_mapping_update(property_t unused_prop)
{
	static GtkWidget *icon_possible;
	static GtkWidget *icon_upnp_successful;
	static GtkWidget *icon_natpmp_successful;
	gboolean pm_successful;
	gboolean upnp, natpmp, upnp_enabled, natpmp_enabled;

	(void) unused_prop;

	if G_UNLIKELY(NULL == icon_possible) {
		icon_possible =
			gui_main_window_lookup("eventbox_port_mapping_possible");
		icon_upnp_successful =
			gui_main_window_lookup("eventbox_upnp_port_mapping_successful");
		icon_natpmp_successful =
			gui_main_window_lookup("eventbox_natpmp_port_mapping_successful");
	}

    gnet_prop_get_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL, &pm_successful);
    gnet_prop_get_boolean_val(PROP_UPNP_POSSIBLE, &upnp);
    gnet_prop_get_boolean_val(PROP_NATPMP_POSSIBLE, &natpmp);
    gnet_prop_get_boolean_val(PROP_ENABLE_UPNP, &upnp_enabled);
    gnet_prop_get_boolean_val(PROP_ENABLE_NATPMP, &natpmp_enabled);

	gtk_widget_hide(icon_possible);
	gtk_widget_hide(icon_upnp_successful);
	gtk_widget_hide(icon_natpmp_successful);

	if (pm_successful) {
		if (natpmp && natpmp_enabled)
			gtk_widget_show(icon_natpmp_successful);
		else if (upnp && upnp_enabled)
			gtk_widget_show(icon_upnp_successful);
		else
			gtk_widget_show(icon_possible);
	} else if (upnp || natpmp) {
		gtk_widget_show(icon_possible);
	}

	gui_shrink_widget_named("hbox_port_mapping");

	return FALSE;
}

static gboolean
file_descriptor_warn_changed(property_t prop)
{
	GtkWidget *icon_shortage;
	GtkWidget *icon_runout;
	gboolean fd_shortage;
	gboolean fd_runout;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);

    icon_shortage = gui_main_window_lookup("eventbox_image_fd_shortage");
    icon_runout = gui_main_window_lookup("eventbox_image_fd_runout");

    gnet_prop_get_boolean_val(PROP_FILE_DESCRIPTOR_SHORTAGE, &fd_shortage);
    gnet_prop_get_boolean_val(PROP_FILE_DESCRIPTOR_RUNOUT, &fd_runout);

	gtk_widget_hide(icon_shortage);
	gtk_widget_hide(icon_runout);

	if (fd_runout) {
		gtk_widget_show(icon_runout);
		if (map_entry->prop == PROP_FILE_DESCRIPTOR_RUNOUT)
			statusbar_gui_warning(15,
				_("*** FILE DESCRIPTORS HAVE RUN OUT! ***"));
	} else if (fd_shortage) {
		gtk_widget_show(icon_shortage);
		if (map_entry->prop == PROP_FILE_DESCRIPTOR_SHORTAGE)
			statusbar_gui_warning(15,
				_("*** FILE DESCRIPTORS RUNNING LOW! ***"));
	} else
		shrink_frame_status();

    return FALSE;
}

static gboolean
ancient_version_left_days_changed(property_t prop)
{
    guint32 remain;

    gnet_prop_get_guint32_val(prop, &remain);

	if (remain == 0)
		statusbar_gui_message(15, _("*** Please update gtk-gnutella ***"));
	else
		statusbar_gui_message(15,
			NG_("*** VERSION WILL BECOME OLD IN %d DAY! ***",
				"*** VERSION WILL BECOME OLD IN %d DAYS! ***", remain),
			remain);

    return FALSE;
}

static gboolean
new_version_str_changed(property_t prop)
{
    gchar *str;

	g_return_val_if_fail(PROP_NEW_VERSION_STR == prop, FALSE);

    str = gnet_prop_get_string(prop, NULL, 0);
   	statusbar_gui_set_default("%s%s", product_website(), str ? str : "");
	G_FREE_NULL(str);

    return FALSE;
}

static gboolean
send_pushes_changed(property_t prop)
{
    gboolean val;
	gboolean is_firewalled;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);
    gnet_prop_get_boolean(PROP_IS_FIREWALLED, &is_firewalled, 0, 1);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(lookup_widget(top, map_entry->wid)), !val);

	val = val && !is_firewalled;
	gtk_widget_set_sensitive(get_push_button(), val);

    return FALSE;
}

static gboolean
searchbar_visible_changed(property_t prop)
{
	GtkWidget *widget;
	GtkWidget *viewport, *entry;
	gboolean visible;

	gui_prop_get_boolean_val(prop, &visible);

	viewport = gui_main_window_lookup("viewport_searchbar");
	entry = gui_main_window_lookup("entry_search");

	if (visible) {
		gtk_widget_show(viewport);
	} else {
		gtk_widget_hide(viewport);
	}

	widget = gui_main_window_lookup("menu_searchbar_visible");
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), visible);
	if (visible && !GTK_WIDGET_HAS_FOCUS(entry)) {
		gtk_widget_grab_focus(entry);
	}
	return FALSE;
}

static gboolean
sidebar_visible_changed(property_t prop)
{
	GtkWidget *widget;
    gboolean visible;

    gui_prop_get_boolean_val(prop, &visible);

#if !GTK_CHECK_VERSION(2,0,0)
	widget = gui_main_window_lookup("hpaned_main");
	gtk_paned_set_gutter_size(GTK_PANED(widget), visible ? 10 : 0);
#endif	/* Gtk+ < 2.x */

	widget = gui_main_window_lookup("menu_sidebar_visible");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), visible);

	widget = gui_main_window_lookup("vbox_sidebar");
	if (visible) {
		gtk_widget_show(widget);
	} else {
		gtk_widget_hide(widget);
	}
    return FALSE;
}

static gboolean
menubar_visible_changed(property_t prop)
{
	GtkWidget *widget;
    gboolean visible;

	widget = gui_main_window_lookup("menu_menubar_visible");
    gui_prop_get_boolean_val(prop, &visible);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(widget), visible);
	widget = gui_main_window_lookup("menubar_main");
	/*
	 * The menubar is not hidden but shrunk to a single pixel in height
	 * so that the accelerator keys (like Control-Q) are still functional.
	 */
	if (visible) {
		gtk_widget_set_size_request(widget, -1, -1);
	} else {
		/* 1 pixel is the smallest size, 0 means "as small as possible" */
		gtk_widget_set_size_request(widget, -1, 1);
	}
    return FALSE;
}

static gboolean
statusbar_visible_changed(property_t prop)
{
	GtkWidget *widget;
    gboolean visible;

    gui_prop_get_boolean_val(prop, &visible);
    gtk_check_menu_item_set_active(
        GTK_CHECK_MENU_ITEM
            (gui_main_window_lookup("menu_statusbar_visible")),
        visible);

	widget = gui_main_window_lookup("hbox_statusbar");
   	if (visible) {
		gtk_widget_show(widget);
	} else {
		gtk_widget_hide(widget);
	}

    return FALSE;
}

/**
 * Change the menu item cm and show/hide the widget w to reflect the
 * value of val. val = TRUE means w should be visible.
 */
static void
update_stats_visibility(GtkCheckMenuItem *cm, GtkWidget *w, gboolean val)
{
    gtk_check_menu_item_set_state(cm, val);

    if (val) {
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
    }

    gui_update_stats_frames();
}

static gboolean
progressbar_bws_in_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_in");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_in_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_out_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_out");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_out_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_gin_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_gin");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_gin_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_gout_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_gout");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_gout_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_glin_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_lin");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_glin_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_glout_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_lout");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_glout_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_dht_in_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_dht_in");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_dht_in_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_bws_dht_out_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("progressbar_bws_dht_out");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_bws_dht_out_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
autohide_bws_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_check_menu_item_set_state(
		GTK_CHECK_MENU_ITEM(lookup_widget(top, map_entry->wid)), val);

    /* The actual evaluation of the property takes place in
       gui_update_stats_frames() */
    gui_update_stats_frames();

    return FALSE;
}

static gboolean
progressbar_downloads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("hbox_stats_downloads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_downloads_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_uploads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("hbox_stats_uploads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_uploads_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
progressbar_connections_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = gui_main_window_lookup("hbox_stats_connections");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (gui_main_window_lookup("menu_connections_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean
autoclear_completed_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(lookup_widget(top, map_entry->wid)), val);

    if (val)
        guc_download_clear_stopped(TRUE, FALSE, FALSE, FALSE, TRUE);

    return FALSE;
}

static gboolean
autoclear_failed_downloads_changed(property_t prop)
{
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    gboolean val;

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(lookup_widget(top, map_entry->wid)), val);

    if (val)
        guc_download_clear_stopped(FALSE, TRUE, FALSE, FALSE, TRUE);

    return FALSE;
}

static gboolean
autoclear_unavailable_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(lookup_widget(top, map_entry->wid)), val);

    if (val)
        guc_download_clear_stopped(FALSE, FALSE, TRUE, FALSE, TRUE);

    return FALSE;
}

static gboolean
autoclear_finished_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(lookup_widget(top, map_entry->wid)), val);

    if (val)
        guc_download_clear_stopped(FALSE, FALSE, FALSE, TRUE, TRUE);

    return FALSE;
}

static gboolean
traffic_stats_mode_changed(property_t unused_prop)
{
	(void) unused_prop;
    gui_update_traffic_stats();

    return FALSE;
}

static gboolean
compute_connection_speed_changed(property_t prop)
{
    gboolean b;

    gnet_prop_get_boolean_val(prop, &b);
    update_togglebutton(prop);
    gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("spinbutton_config_speed"), !b);

    return FALSE;
}

static gboolean
min_dup_ratio_changed(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    const prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    stub->guint32.get(prop, &val, 0, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), (float) val / 100.0);

    return FALSE;
}

static gboolean
update_address_information(void)
{
    static host_addr_t old_address;
    static host_addr_t old_v6_address;
    static guint16 old_port = 0;
	host_addr_t addr, addr_v6;
    guint16 port;

	port = guc_listen_port();
	addr = guc_listen_addr(NET_TYPE_IPV4);
	addr_v6 = guc_listen_addr(NET_TYPE_IPV6);

	if (
		old_port != port ||
		!host_addr_equiv(old_address, addr) ||
		!host_addr_equiv(old_v6_address, addr_v6)
	) {
		gchar addr_buf[HOST_ADDR_PORT_BUFLEN];
		gchar addr_v6_buf[HOST_ADDR_PORT_BUFLEN];
		gchar buf[256];

		if (is_host_addr(addr)) {
			host_addr_port_to_string_buf(addr, port, ARYLEN(addr_buf));
		} else {
			addr_buf[0] = '\0';
		}
		if (is_host_addr(addr_v6)) {
			host_addr_port_to_string_buf(addr_v6, port, ARYLEN(addr_v6_buf));
		} else {
			addr_v6_buf[0] = '\0';
		}
		concat_strings(ARYLEN(buf),
			addr_buf,
			'\0' != addr_buf[0] && '\0' != addr_v6_buf[0] ? ", " : "",
			addr_v6_buf, NULL_PTR);

        old_address = addr;
        old_v6_address = addr_v6;
        old_port = port;

        statusbar_gui_message(15, _("Address/port changed to: %s"), buf);
        gtk_label_set_text(
            GTK_LABEL(gui_dlg_prefs_lookup("label_current_port")), buf);

#ifdef USE_GTK2
        gtk_label_set_text(
			GTK_LABEL(gui_main_window_lookup("label_nodes_ip")), buf);
#else
        gtk_entry_set_text(
			GTK_ENTRY(gui_main_window_lookup("entry_nodes_ip")), buf);
#endif /* USE_GTK2 */
    }

    return FALSE;
}

static void
update_input_bw_display(void)
{
	gboolean enabled;
	uint64 val = 0;
	uint64 bw;
	uint64 http = MAX_INT_VAL(uint64);

	gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_GNET_LIN, &bw);
		val += bw;
	}
	gnet_prop_get_boolean_val(PROP_BW_HTTP_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_HTTP_IN, &http);
		val += http;
		/* Leaf bandwidth is taken from HTTP traffic, when enabled */
		gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_IN_ENABLED, &enabled);
		if (enabled) {
			gnet_prop_get_guint64_val(PROP_BW_GNET_LIN, &bw);
			val -= bw;
			if (bw > http) {
				http = 0;
			} else {
				http -= bw;
			}
		}
	}
	gnet_prop_get_boolean_val(PROP_BW_GNET_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_GNET_IN, &bw);
		val += bw;
	}

	gtk_label_printf(
		GTK_LABEL(gui_dlg_prefs_lookup("label_input_bw_limit")),
		"%.2f", val / 1024.0);
	gtk_label_printf(
		GTK_LABEL(gui_dlg_prefs_lookup("label_http_in_avail")),
		"%.2f", http / 1024.0);
}

static gboolean
spinbutton_input_bw_changed(property_t prop)
{
	gboolean ret;

	ret = update_bandwidth_spinbutton(prop);
	update_input_bw_display();
	return ret;
}

static void
update_output_bw_display(void)
{
	gboolean enabled;
	uint64 val = 0;
	uint64 bw;
	uint64 http = MAX_INT_VAL(uint64);

	gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_GNET_LOUT, &bw);
		val += bw;
	}
	gnet_prop_get_boolean_val(PROP_BW_HTTP_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_HTTP_OUT, &http);
		val += http;
		/* Leaf bandwidth is taken from HTTP traffic, when enabled */
		gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_OUT_ENABLED, &enabled);
		if (enabled) {
			gnet_prop_get_guint64_val(PROP_BW_GNET_LOUT, &bw);
			val -= bw;
			if (bw > http) {
				http = 0;
			} else {
				http -= bw;
			}
		}
	}
	gnet_prop_get_boolean_val(PROP_BW_GNET_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_GNET_OUT, &bw);
		val += bw;
	}

	gnet_prop_get_boolean_val(PROP_BW_DHT_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint64_val(PROP_BW_DHT_OUT, &bw);
		val += bw;
	}

	gtk_label_printf(
		GTK_LABEL(gui_dlg_prefs_lookup("label_output_bw_limit")),
		"%.2f", val / 1024.0);
	gtk_label_printf(
		GTK_LABEL(gui_dlg_prefs_lookup("label_http_out_avail")),
		"%.2f", http / 1024.0);
}

static gboolean
spinbutton_output_bw_changed(property_t prop)
{
	gboolean ret;

	ret = update_bandwidth_spinbutton(prop);
	update_output_bw_display();
	return ret;
}

static gboolean
network_protocol_changed(property_t prop)
{
    update_multichoice(prop);
    update_address_information();
    return FALSE;
}

static gboolean
force_local_addr_changed(property_t prop)
{
    update_togglebutton(prop);
    update_address_information();
    return FALSE;
}

static gboolean
listen_port_changed(property_t prop)
{
    update_spinbutton(prop);
    update_address_information();
	(void) dht_boot_status_changed(PROP_DHT_BOOT_STATUS);
    return FALSE;
}

static gboolean
local_address_changed(property_t prop)
{
	(void) prop;
    update_address_information();
    return FALSE;
}

static gboolean
use_netmasks_changed(property_t prop)
{
    gboolean b;

    gnet_prop_get_boolean_val(prop, &b);
    update_togglebutton(prop);
    gtk_widget_set_sensitive(
        gui_dlg_prefs_lookup("entry_config_netmasks"), b);

    return FALSE;
}

static gboolean
guid_changed(property_t prop)
{
    struct guid guid_buf;

    gnet_prop_get_storage(prop, VARLEN(guid_buf));

#ifdef USE_GTK2
	{
		GtkLabel *label;
		gchar buf[64];

	   	label = GTK_LABEL(gui_main_window_lookup("label_nodes_guid"));
		concat_strings(ARYLEN(buf),
			"<tt>", guid_hex_str(&guid_buf), "</tt>", NULL_PTR);
		gtk_label_set_use_markup(label, TRUE);
		gtk_label_set_markup(label, buf);
	}
#else
    gtk_entry_set_text(
        GTK_ENTRY(gui_main_window_lookup("entry_nodes_guid")),
        guid_hex_str(&guid_buf));
#endif /* USE_GTK2 */

    return FALSE;
}

static gboolean
kuid_changed(property_t prop)
{
    kuid_t kuid_buf;

    gnet_prop_get_storage(prop, VARLEN(kuid_buf));

#ifdef USE_GTK2
	{
		GtkLabel *label;
		gchar buf[64];

	   	label = GTK_LABEL(gui_main_window_lookup("label_nodes_kuid"));
		concat_strings(ARYLEN(buf),
			"<tt>", kuid_to_hex_string(&kuid_buf), "</tt>", NULL_PTR);
		gtk_label_set_use_markup(label, TRUE);
		gtk_label_set_markup(label, buf);
	}
#else
    gtk_entry_set_text(
        GTK_ENTRY(gui_main_window_lookup("entry_nodes_kuid")),
        kuid_to_hex_string(&kuid_buf));
#endif /* USE_GTK2 */

    return FALSE;
}

static gboolean
update_monitor_unstable_ip(property_t prop)
{
	gboolean b;

	gnet_prop_get_boolean_val(prop, &b);

	gtk_widget_set_sensitive(
		gui_dlg_prefs_lookup("checkbutton_gnet_monitor_servents"), b);

	return update_togglebutton(prop);
}

static gboolean
show_tooltips_changed(property_t prop)
{
	GtkTooltips *tips;
    gboolean b;

	tips = GTK_TOOLTIPS(gtk_object_get_data(
							GTK_OBJECT(gui_main_window()), "tooltips"));

    update_togglebutton(prop);
    gui_prop_get_boolean_val(prop, &b);
    if (b) {
        gtk_tooltips_enable(tooltips);
        gtk_tooltips_enable(tips);
    } else {
        gtk_tooltips_disable(tooltips);
        gtk_tooltips_disable(tips);
    }

    return FALSE;
}

static gboolean
search_display_guess_stats_changed(property_t prop)
{
    gboolean b;

    gui_prop_get_boolean_val(prop, &b);
    update_togglebutton(prop);
	search_gui_current_search_refresh();

    return FALSE;
}

static gboolean
expert_mode_changed(property_t prop)
{
    static const gchar *expert_widgets_main[] = {
        "button_search_passive",
        "frame_expert_node_info",
	};
	static const gchar *expert_widgets_prefs[] = {
        "frame_expert_nw_local",
        "frame_expert_nw_misc",
        "frame_expert_nw_port_mapping",
        "frame_expert_gnet_timeout",
        "frame_expert_gnet_ttl",
        "frame_expert_gnet_quality",
        "frame_expert_gnet_connections",
        "frame_expert_gnet_other",
        "frame_expert_gnet_dht",
        "frame_expert_dl_timeout",
        "frame_expert_ul_timeout",
        "frame_expert_dl_source_quality",
        "frame_expert_unmapped",
        "frame_expert_rx_buffers",
        "frame_expert_gnet_message_size",
        "frame_expert_search_queue",
        "frame_expert_share_statistics",
        "frame_expert_oob_queries",
    };
    gboolean expert;
	GtkWidget *w;
    guint i;

    update_togglebutton(prop);
    gui_prop_get_boolean_val(prop, &expert);

	/* Enable/Disable main_window expert widgets */
    for (i = 0; i < N_ITEMS(expert_widgets_main); i++) {
       w = gui_main_window_lookup(expert_widgets_main[i]);
       if (w == NULL)
			continue;

        if (expert)
            gtk_widget_show(w);
        else
            gtk_widget_hide(w);
    }

	/* Enable/Disable preferences dialog expert widgets */
    for (i = 0; i < N_ITEMS(expert_widgets_prefs); i++) {
       w = gui_dlg_prefs_lookup(expert_widgets_prefs[i]);
       if (w == NULL)
			continue;

        if (expert)
            gtk_widget_show(w);
        else
            gtk_widget_hide(w);
    }

    w = gui_main_window_lookup("hbox_expert_search_timeout");
    if (expert)
      gtk_widget_show(w);
    else
      gtk_widget_hide(w);

    return FALSE;
}

static gboolean
search_stats_mode_changed(property_t prop)
{
    guint32 val;

    gui_prop_get_guint32_val(prop, &val);
    update_multichoice(prop);
    search_stats_gui_set_type(val);
    search_stats_gui_reset();

    return FALSE;
}

struct widget_change {
	cevent_t *ev;			/* Event to change widget */
	const char *name;		/* Widget name */
	GtkWidget *widget;		/* The widget in the main window */
	bool sensitive;			/* Whether widget will become sensitive */
};

static void
widget_sensitive_event(cqueue_t *cq, void *data)
{
	struct widget_change *wc = data;

    gtk_widget_set_sensitive(wc->widget, wc->sensitive);
	cq_zero(cq, &wc->ev);
}

static gboolean
widget_set_sensitive(const gchar *name, property_t prop)
{
	gboolean val;
	struct widget_change *wc;

	/*
	 * A widget sensitivity can change quickly, leading to GUI flickering.
	 * In order to limit that, we record the changes in a hash table and
	 * install a callback to delay the actual sensitivity change.
	 *
	 * If another visibility change occurs before the callback fires, we may
	 * cancel the event if it goes in the opposite direction, or do nothing
	 * if it still goes in the same direction (i.e. making it sensitive if
	 * it is already recorded as such).
	 *
	 * We give priority to "lighting" the widget, and defer the "shadowing".
	 */

    gnet_prop_get_boolean_val(prop, &val);
	wc = hikset_lookup(sensitive_changes, name);

	if G_UNLIKELY(NULL == wc) {
		WALLOC(wc);
		wc->name = name;		/* Known to be a static string */
		wc->widget = gui_main_window_lookup(name);
		wc->sensitive = val;
		wc->ev = cq_main_insert(SENSITIVE_DEFER, widget_sensitive_event, wc);
		hikset_insert_key(sensitive_changes, &wc->name);
	} else if (wc->sensitive != val) {
		wc->sensitive = val;
		if (val) {
			cq_cancel(&wc->ev);
			gtk_widget_set_sensitive(wc->widget, wc->sensitive);
		} else if (NULL == wc->ev) {
			wc->ev = cq_main_insert(SENSITIVE_DEFER,
				widget_sensitive_event, wc);
		} else {
			cq_resched(wc->ev, SENSITIVE_DEFER);
		}
	}

	return FALSE;
}

static gboolean
sha1_rebuilding_changed(property_t prop)
{
	return widget_set_sensitive("image_sha", prop);
}

static gboolean
sha1_verifying_changed(property_t prop)
{
	return widget_set_sensitive("image_shav", prop);
}

static gboolean
tth_rebuilding_changed(property_t prop)
{
	return widget_set_sensitive("image_tth", prop);
}

static gboolean
tth_verifying_changed(property_t prop)
{
	return widget_set_sensitive("image_tthv", prop);
}

static gboolean
library_rebuilding_changed(property_t prop)
{
	return widget_set_sensitive("image_lib", prop);
}

static gboolean
file_moving_changed(property_t prop)
{
	return widget_set_sensitive("image_save", prop);
}

static gboolean
dl_running_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    if (val == 0)
        gtk_label_printf(
            GTK_LABEL(gui_main_window_lookup("label_dl_running_count")),
            _("no sources"));
	else
        gtk_label_printf(
            GTK_LABEL(gui_main_window_lookup("label_dl_running_count")),
            NG_("%u source", "%u sources", val), val);

	downloads_count_changed(prop);

	return FALSE;
}

static gboolean
dl_active_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(gui_main_window_lookup("label_dl_active_count")),
		_("%u active"), val);

	downloads_count_changed(prop);

	return FALSE;
}

static gboolean
dl_http_latency_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(gui_dlg_prefs_lookup("label_dl_http_latency")),
		"%.3f", val / 1000.0);

	return FALSE;
}

static gboolean
dl_aqueued_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(gui_main_window_lookup("label_dl_aqueued_count")),
		_("%u queued"), val);

	return FALSE;
}

static gboolean
update_spinbutton_ultranode(property_t prop)
{
	gboolean ret;
	guint32 current_peermode;

	ret = update_spinbutton(prop);

	/*
	 * In ultra mode, update the max connection display.
	 */

    gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &current_peermode);
	if (current_peermode == NODE_P_ULTRA)
		gnet_connections_changed(prop);		/* `prop' will be unused here */

	return ret;
}

static gboolean
gnet_connections_changed(property_t unused_prop)
{
    GtkProgressBar *pg;
	gchar buf[128];
    guint32 leaf_count, normal_count, ultra_count, g2_count;
    guint32 max_connections, max_leaves, max_normal, max_ultrapeers, max_g2;
    guint32 cnodes;
    guint32 nodes = 0;
    guint32 peermode;

	(void) unused_prop;

    pg = GTK_PROGRESS_BAR(gui_main_window_lookup("progressbar_connections"));
    gnet_prop_get_guint32_val(PROP_NODE_LEAF_COUNT, &leaf_count);
    gnet_prop_get_guint32_val(PROP_NODE_NORMAL_COUNT, &normal_count);
    gnet_prop_get_guint32_val(PROP_NODE_ULTRA_COUNT, &ultra_count);
    gnet_prop_get_guint32_val(PROP_NODE_G2_COUNT, &g2_count);
    gnet_prop_get_guint32_val(PROP_MAX_CONNECTIONS, &max_connections);
    gnet_prop_get_guint32_val(PROP_MAX_LEAVES, &max_leaves);
    gnet_prop_get_guint32_val(PROP_MAX_ULTRAPEERS, &max_ultrapeers);
    gnet_prop_get_guint32_val(PROP_MAX_G2_HUBS, &max_g2);
    gnet_prop_get_guint32_val(PROP_NORMAL_CONNECTIONS, &max_normal);
    gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &peermode);

    cnodes = leaf_count + normal_count + ultra_count + g2_count;

    switch (peermode) {
    case NODE_P_LEAF: /* leaf */
    case NODE_P_NORMAL: /* normal */
        nodes = g2_count + ((peermode == NODE_P_NORMAL) ?
            max_connections : max_ultrapeers);
		str_bprintf(ARYLEN(buf),
            "%u/%uU | %u/%uH",
			ultra_count, max_ultrapeers,
			g2_count, max_g2);
        break;
    case NODE_P_ULTRA: /* ultra */
        nodes = max_connections + max_leaves + max_normal + max_g2;
        str_bprintf(ARYLEN(buf),
            "%u/%uU | %u/%uH | %u/%uL",
            ultra_count,
			max_connections < max_normal ? 0 : max_connections - max_normal,
            g2_count, max_g2,
            leaf_count, max_leaves);
        break;
    default:
        g_assert_not_reached();
    }

    gtk_progress_bar_set_text(pg, buf);
    gtk_progress_bar_set_fraction(pg,
    	nodes ? (1.0 * MIN(cnodes, nodes) / nodes) : 0.0);

    return FALSE;
}

static gboolean
uploads_count_changed(property_t unused_prop)
{
    GtkProgressBar *pg;
	gchar buf[128];
	guint32 registered;
	guint32 running;

	(void) unused_prop;

    pg = GTK_PROGRESS_BAR(gui_main_window_lookup("progressbar_uploads"));
    gnet_prop_get_guint32_val(PROP_UL_REGISTERED, &registered);
    gnet_prop_get_guint32_val(PROP_UL_RUNNING, &running);

	str_bprintf(ARYLEN(buf),
		NG_("%u/%u upload", "%u/%u uploads", registered),
		running, registered);

    gtk_progress_bar_set_text(pg, buf);
    gtk_progress_bar_set_fraction(pg,
		registered ? (1.0 * MIN(running, registered) / registered) : 0.0);

	return FALSE;
}

static gboolean
downloads_count_changed(property_t unused_prop)
{
    GtkProgressBar *pg;
	gchar buf[128];
    guint32 active;
    guint32 running;

	(void) unused_prop;

    pg = GTK_PROGRESS_BAR(gui_main_window_lookup("progressbar_downloads"));
    gnet_prop_get_guint32_val(PROP_DL_ACTIVE_COUNT, &active);
    gnet_prop_get_guint32_val(PROP_DL_RUNNING_COUNT, &running);

	str_bprintf(ARYLEN(buf),
		NG_("%u/%u download", "%u/%u downloads", running),
		active, running);

    gtk_progress_bar_set_text(pg, buf);
    gtk_progress_bar_set_fraction(pg,
		running ? (1.0 * MIN(active, running) / running) : 0.0);

    return FALSE;
}

static gboolean
clock_skew_changed(property_t prop)
{
    guint32 val;
	gint32 sval;
	char buf[128];

    gnet_prop_get_guint32_val(prop, &val);
	sval = val;
	str_bprintf(ARYLEN(buf), "%c%s",
		sval < 0 ? '-' : '+', short_time(ABS(sval)));
    gtk_label_set_text(GTK_LABEL(gui_dlg_prefs_lookup("label_clock_skew")),
		buf);
    return FALSE;
}

/**
 *	Checks if the download queue is frozen, if so update the freeze queue
 *  widgets and display a message on the statusbar
 */
static gboolean
update_queue_frozen(property_t prop)
{
	static gboolean was_frozen;
	gboolean is_frozen;
    static GtkWidget *icon;

	if G_UNLIKELY(NULL == icon) {
		icon = gui_main_window_lookup("eventbox_image_download_queue_frozen");
	}

	(void) prop;

	is_frozen = guc_download_queue_is_frozen();
	if (was_frozen != is_frozen) {
    	static statusbar_msgid_t id;
    	GtkWidget *button;

		if (is_frozen) {
			gtk_widget_hide(gui_main_window_lookup("vbox_queue_freeze"));
			gtk_widget_show(gui_main_window_lookup("vbox_queue_thaw"));
			id = statusbar_gui_message(0, _("Queue frozen"));
			gtk_widget_show(icon);
		} else {
			gtk_widget_show(gui_main_window_lookup("vbox_queue_freeze"));
			gtk_widget_hide(gui_main_window_lookup("vbox_queue_thaw"));
			statusbar_gui_remove(id);
			gtk_widget_hide(icon);
		}

		button = gui_main_window_lookup("togglebutton_queue_freeze");
		gtk_signal_handler_block_by_func(GTK_OBJECT(button),
			GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled), NULL);

		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), is_frozen);

		gtk_signal_handler_unblock_by_func(GTK_OBJECT(button),
			GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled), NULL);
	}
	was_frozen = is_frozen;

    return FALSE;
}

/***
 *** IV.  Control functions.
 ***/

/**
 * This callbacks is called when a GtkSpinbutton which is referenced in
 * the property_map changed. It reacts to the "value_changed" signal of
 * the GtkAdjustement associated with the GtkSpinbutton.
 */
static void
spinbutton_adjustment_value_changed(GtkAdjustment *adj, gpointer user_data)
{
    prop_map_t *map_entry = (prop_map_t *) user_data;
    const prop_set_stub_t *stub = map_entry->stub;
    uint32 val = adj->value;

    /*
     * Special handling for the special cases.
     */
    if (stub == gnet_prop_set_stub) {
        /*
         * Bandwidth spinbuttons need the value multiplied by 1024
		 * Also they are 64-bit values.
         */
        if (
            (map_entry->prop == PROP_BW_HTTP_IN) ||
            (map_entry->prop == PROP_BW_HTTP_OUT) ||
            (map_entry->prop == PROP_BW_GNET_LIN) ||
            (map_entry->prop == PROP_BW_GNET_LOUT) ||
            (map_entry->prop == PROP_BW_GNET_IN) ||
            (map_entry->prop == PROP_BW_GNET_OUT) ||
			(map_entry->prop == PROP_BW_DHT_OUT) ||
			(map_entry->prop == PROP_BW_DHT_LOOKUP_IN) ||
			(map_entry->prop == PROP_BW_DHT_LOOKUP_OUT) ||
			(map_entry->prop == PROP_BW_GUESS_OUT)
        ) {
            uint64 value = val * 1024;
			stub->guint64.set(map_entry->prop, &value, 0, 1);
			return;
        }

        /*
         * Some spinbuttons need the multiplied by 100
         */
        if (
            (map_entry->prop == PROP_MIN_DUP_RATIO)
        ) {
            val *= 100;
        }
    }

    stub->guint32.set(map_entry->prop, &val, 0, 1);
}

/**
 * This function is called when the state of a GtkToggleButton that
 * is managed by the property_map. It is bound during initialization
 * when the property_map is processed.
 * GtkToggleButtons are normally bound directly to thier associated
 * properties. Special cases are handled here.
 */
static void
togglebutton_state_changed(GtkToggleButton *tb, gpointer user_data)
{
    prop_map_t *map_entry = (prop_map_t *) user_data;
    const prop_set_stub_t *stub = map_entry->stub;
    gboolean val = gtk_toggle_button_get_active(tb);

    /*
     * Special handling for the special cases.
     */
    if (stub == gnet_prop_set_stub) {
        /*
         * PROP_SEND_PUSHES needs widget value inversed.
         */
        if (map_entry->prop == PROP_SEND_PUSHES) {
            val = !val;
        }
    }

    stub->boolean.set(map_entry->prop, &val, 0, 1);
}

static void
multichoice_item_selected(GtkItem *i, gpointer data)
{
    prop_map_t *map_entry = data;
    const prop_set_stub_t *stub = map_entry->stub;
    guint32 val = GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(i)));

    stub->guint32.set(map_entry->prop, &val, 0, 1);
}

/**
 * Set up tooltip and constraints where applicable.
 */
static void
settings_gui_config_widget(prop_map_t *map, prop_def_t *def)
{
    g_assert(map != NULL);
    g_assert(def != NULL);

    if (map->cb != IGNORE_CB) {
        if (GUI_PROPERTY(gui_debug) >= 8)
            printf("settings_gui_config_widget: %s\n", def->name);

        /*
         * Set tooltip/limits
         */
        if (map->wid != NULL) {
            GtkWidget *top = NULL;
            GtkWidget *w;

            /*
             * If can't determine the toplevel widget or the target
             * widget we abort.
             */
            top = map->fn_toplevel();
            if (top == NULL)
                return;

            w = lookup_widget(top, map->wid);
            if (w == NULL)
                return;

            /*
             * Set tooltip.
             */
#ifdef USE_GTK2
			if (!GTK_IS_TREE_VIEW(w))
#endif /* USE_GTK2 */
			{
            	gtk_tooltips_set_tip(tooltips, w, def->desc, "");
				if (GUI_PROPERTY(gui_debug) >= 9)
					printf("\t...added tooltip\n");
			}

            /*
             * If the widget is a spinbutton, configure the bounds
             */
            if (top && GTK_IS_SPIN_BUTTON(w)) {
                GtkAdjustment *adj =
                    gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(w));
                gdouble divider = 1.0;

				g_assert_log(
					PROP_TYPE_GUINT64 == def->type ||
					PROP_TYPE_GUINT32 == def->type,
					"%s: property \"%s\" not a uint32 or uint64",
					G_STRFUNC, def->name);

                /*
                 * Bandwidth spinbuttons need the value divided by
                 * 1024.
                 */
                if (
                    (map->stub == gnet_prop_set_stub) && (
                        (map->prop == PROP_BW_HTTP_IN) ||
                        (map->prop == PROP_BW_HTTP_OUT) ||
                        (map->prop == PROP_BW_GNET_LIN) ||
                        (map->prop == PROP_BW_GNET_LOUT) ||
                        (map->prop == PROP_BW_GNET_IN) ||
                        (map->prop == PROP_BW_GNET_OUT) ||
                        (map->prop == PROP_BW_DHT_OUT) ||
                        (map->prop == PROP_BW_DHT_LOOKUP_IN) ||
                        (map->prop == PROP_BW_DHT_LOOKUP_OUT) ||
                        (map->prop == PROP_BW_GUESS_OUT)
                    )
                ) {
                    divider = 1024.0;
                }

                /*
                 * Some others need the value divided by 100.
                 */
                if (
                    (map->stub == gnet_prop_set_stub) && (
                        (map->prop == PROP_MIN_DUP_RATIO)
                    )
                ) {
                    divider = 100.0;
                }

				if (PROP_TYPE_GUINT64 == def->type) {
					adj->lower = def->data.guint64.min / divider,
					adj->upper = def->data.guint64.max / divider;
				} else {
					adj->lower = def->data.guint32.min / divider;
					adj->upper = def->data.guint32.max / divider;
				}

                gtk_adjustment_changed(adj);

                gui_signal_connect_after(adj,
					"value_changed", spinbutton_adjustment_value_changed, map);

				if (GUI_PROPERTY(gui_debug) >= 9)
					printf("\t...adjusted lower=%f, upper=%f\n",
						adj->lower, adj->upper);
            }

            if (top && GTK_IS_TOGGLE_BUTTON(w)) {
                g_assert(def->type == PROP_TYPE_BOOLEAN);

                gui_signal_connect(w,
					"toggled", togglebutton_state_changed, map);

				if (GUI_PROPERTY(gui_debug) >= 9)
					printf("\t...connected toggle signal\n");
            }

            if (top && (GTK_IS_COMBO(w) || GTK_IS_OPTION_MENU(w))) {
                g_assert(def->type == PROP_TYPE_MULTICHOICE);

                widget_init_choices(w,
                    GTK_SIGNAL_FUNC(multichoice_item_selected),
                    def, map);

				if (GUI_PROPERTY(gui_debug) >= 9)
					printf("\t...connected multichoice signal\n");
			}
        }
        if (GUI_PROPERTY(gui_debug) >= 8)
            printf("\t...all done for %s.\n", def->name);
    }
}

/**
 * Save GUI settings if dirty.
 */
void
settings_gui_save_if_dirty(void)
{
    prop_save_to_file_if_dirty(
		properties, settings_gui_config_dir(), property_file);
}

const gchar *
settings_gui_config_dir(void)
{
	return guc_settings_config_dir();
}

/***
 *** V. Property-to-callback map
 ***/

#define PROP_ENTRY(widget, prop, handler, init, name, freq, interval)		\
	{																		\
		(widget), (prop), (handler) , (init) , (name), (freq), (interval), 	\
		0, NULL , NULL														\
	}																		\

/* FIXME:
 * move to separate file and autogenerate from high-level description.
 */
static prop_map_t property_map[] = {
    PROP_ENTRY(
        gui_main_window,
        PROP_MONITOR_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_monitor_items",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MONITOR_ENABLED,
        monitor_enabled_changed,
        TRUE,
        "checkbutton_monitor_enable",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCHBAR_VISIBLE,
        searchbar_visible_changed,
        TRUE,
        "menu_searchbar_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MENUBAR_VISIBLE,
        menubar_visible_changed,
        TRUE,
        "menu_menubar_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SIDEBAR_VISIBLE,
        sidebar_visible_changed,
        TRUE,
        "menu_sidebar_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_STATUSBAR_VISIBLE,
        statusbar_visible_changed,
        TRUE,
        "menu_statusbar_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_IN_VISIBLE,
        progressbar_bws_in_visible_changed,
        TRUE,
        "menu_bws_in_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_OUT_VISIBLE,
        progressbar_bws_out_visible_changed,
        TRUE,
        "menu_bws_out_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_GIN_VISIBLE,
        progressbar_bws_gin_visible_changed,
        TRUE,
        "menu_bws_gin_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_GOUT_VISIBLE,
        progressbar_bws_gout_visible_changed,
        TRUE,
        "menu_bws_gout_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOHIDE_BWS_GLEAF,
        autohide_bws_changed,
        TRUE,
        "menu_autohide_bws_gleaf",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOHIDE_BWS_DHT,
        autohide_bws_changed,
        TRUE,
        "menu_autohide_bws_dht",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_GLIN_VISIBLE,
        progressbar_bws_glin_visible_changed,
        TRUE,
        "menu_bws_glin_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_GLOUT_VISIBLE,
        progressbar_bws_glout_visible_changed,
        TRUE,
        "menu_bws_glout_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_DHT_IN_VISIBLE,
        progressbar_bws_dht_in_visible_changed,
        TRUE,
        "menu_bws_dht_in_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_BWS_DHT_OUT_VISIBLE,
        progressbar_bws_dht_out_visible_changed,
        TRUE,
        "menu_bws_dht_out_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_DOWNLOADS_VISIBLE,
        progressbar_downloads_visible_changed,
        TRUE,
        "menu_downloads_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_UPLOADS_VISIBLE,
        progressbar_uploads_visible_changed,
        TRUE,
        "menu_uploads_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PROGRESSBAR_CONNECTIONS_VISIBLE,
        progressbar_connections_visible_changed,
        TRUE,
        "menu_connections_visible",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UP_CONNECTIONS,
        update_spinbutton,
        TRUE,
        "spinbutton_up_connections",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_CONNECTIONS,
        update_spinbutton_ultranode,
        TRUE,
        "spinbutton_max_connections",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_ULTRAPEERS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_ultrapeers",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_G2_HUBS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_g2_hubs",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_QUICK_CONNECT_POOL_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_quick_connect_pool_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NODE_LEAF_COUNT,
        gnet_connections_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NODE_NORMAL_COUNT,
        gnet_connections_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NODE_ULTRA_COUNT,
        gnet_connections_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NODE_G2_COUNT,
        gnet_connections_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UL_RUNNING,
        uploads_count_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UL_REGISTERED,
        uploads_count_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_downloads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_HOST_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_host_downloads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_SIMULTANEOUS_DOWNLOADS_PER_FILE,
        update_spinbutton,
        TRUE,
        "spinbutton_max_file_downloads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_UPLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_UPLOADS_IP,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads_ip",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROXY_HOSTNAME,
        update_entry,
        TRUE,
        "entry_config_proxy_hostname",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MAX_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_maxttl",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MY_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_myttl",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROXY_PORT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_proxy_port",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UL_USAGE_MIN_PERCENTAGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ul_usage_min_percentage",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONNECTION_SPEED,
        update_spinbutton,
        TRUE,
        "spinbutton_config_speed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_COMPUTE_CONNECTION_SPEED,
		compute_connection_speed_changed,
        TRUE,
        "checkbutton_compute_connection_speed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QUERY_RESPONSE_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_items",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_REISSUE_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_reissue_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MAX_HIGH_TTL_RADIUS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_radius",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MAX_HIGH_TTL_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_msg",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_HARD_TTL_LIMIT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hard_ttl_limit",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_OVERLAP_RANGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_overlap_range",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_MAX_RETRIES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_max_retries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_STOPPED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_stopped_delay",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_REFUSED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_refused_delay",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_BUSY_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_busy_delay",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_TIMEOUT_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_delay",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MAX,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_max",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MIN,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_min",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connecting_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connected_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_PUSH_SENT_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_push_sent_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_TX_FLOWC_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_tx_flowc_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connecting_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connected_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UPLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connecting_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UPLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connected_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SOCKS_USER,
        update_entry,
        TRUE,
        "entry_config_socks_username",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SOCKS_PASS,
        update_entry,
        TRUE,
        "entry_config_socks_password",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_REMOVE_DOWNLOADED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_remove_downloaded",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_BROWSE_COPIED_TO_PASSIVE,
        update_togglebutton,
        TRUE,
        "checkbutton_browse_copied_to_passive",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_REMOVE_FILE_ON_MISMATCH,
        update_toggle_remove_on_mismatch,
        TRUE,
        "checkbutton_dl_remove_file_on_mismatch",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_MISMATCH_BACKOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_mismatch_backout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_GIVE_SERVER_HOSTNAME,
        update_togglebutton,
        TRUE,
        "checkbutton_give_server_hostname",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SERVER_HOSTNAME,
        update_entry,
        TRUE,
        "entry_server_hostname",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PFSP_SERVER,
        update_togglebutton,
        TRUE,
        "checkbutton_pfsp_server",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PFSP_RARE_SERVER,
        update_togglebutton,
        TRUE,
        "checkbutton_pfsp_rare_server",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_SMART_STOP,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_smart_stop",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_RESTART_WHEN_PENDING,
        update_togglebutton,
        TRUE,
        "checkbutton_search_restart_when_pending",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QUERY_REQUEST_PARTIALS,
        update_togglebutton,
        TRUE,
        "checkbutton_config_query_request_partials",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QUERY_ANSWER_PARTIALS,
        update_togglebutton,
        TRUE,
        "checkbutton_config_query_answer_partials",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QUERY_ANSWER_WHATS_NEW,
        update_togglebutton,
        TRUE,
        "checkbutton_config_query_answer_whats_new",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PFSP_FIRST_CHUNK,
        update_spinbutton,
        TRUE,
        "spinbutton_pfsp_first_chunk",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PFSP_LAST_CHUNK,
        update_spinbutton,
        TRUE,
        "spinbutton_pfsp_last_chunk",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PFSP_MINIMUM_FILESIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_pfsp_minimum_filesize",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_HIDE_DOWNLOADED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_hide_downloaded",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DOWNLOAD_DELETE_ABORTED,
        update_togglebutton,
        TRUE,
        "checkbutton_download_delete_aborted",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_HTTP_IN_ENABLED,
        bw_http_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_in",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_HTTP_OUT_ENABLED,
        bw_http_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_out",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_IN_ENABLED,
        bw_gnet_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gin",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_OUT_ENABLED,
        bw_gnet_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_DHT_OUT_ENABLED,
        bw_dht_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_dht_out",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_HTTP_IN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_in",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_HTTP_OUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_out",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_IN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_gin",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_OUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_gout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_DHT_OUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_dht_out",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_UL_USAGE_ENABLED,
        bw_ul_usage_enabled_changed,
        TRUE,
        "checkbutton_config_bw_ul_usage_enabled",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_ANCIENT_VERSION,
        ancient_version_changed,
        TRUE,
		/* need eventbox because image has no tooltip */
        "eventbox_image_ancient",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_ANCIENT_VERSION_LEFT_DAYS,
        ancient_version_left_days_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NEW_VERSION_STR,
        new_version_str_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEND_PUSHES,
        send_pushes_changed,
        TRUE,
        "checkbutton_downloads_never_push",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_COMPLETED_UPLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_uploads_auto_clear_complete",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_FAILED_UPLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_uploads_auto_clear_failed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_COMPLETED_DOWNLOADS,
        autoclear_completed_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_complete",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_FAILED_DOWNLOADS,
        autoclear_failed_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_failed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_UNAVAILABLE_DOWNLOADS,
        autoclear_unavailable_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_unavailable",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_AUTOCLEAR_FINISHED_DOWNLOADS,
        autoclear_finished_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_finished",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_FORCE_LOCAL_IP,
        force_local_addr_changed,
        TRUE,
        "checkbutton_config_force_ip",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_FORCE_LOCAL_IP6,
        force_local_addr_changed,
        TRUE,
        "checkbutton_config_force_ipv6",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROXY_AUTH,
        update_togglebutton,
        TRUE,
        "checkbutton_config_proxy_auth",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_TOTAL_DOWNLOADS,
        update_entry,
        TRUE,
        "entry_count_downloads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_TOTAL_UPLOADS,
        update_entry,
        TRUE,
        "entry_count_uploads",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_STATS_MODE,
        search_stats_mode_changed,
        FALSE, /* search_stats_gui_init takes care of that */
        "option_menu_search_stats_type",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_STATS_UPDATE_INTERVAL,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_update_interval",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_STATS_DELCOEF,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_delcoef",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_USE_NETMASKS,
        use_netmasks_changed,
        TRUE,
        "checkbutton_config_use_netmasks",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_LOCAL_NETMASKS_STRING,
        update_entry,
        TRUE,
        "entry_config_netmasks",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ALLOW_PRIVATE_NETWORK_CONNECTION,
        update_togglebutton,
        TRUE,
        "checkbutton_config_no_rfc1918",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
		gui_dlg_prefs,
		PROP_USE_IP_TOS,
		update_togglebutton,
		TRUE,
		"checkbutton_config_use_ip_tos",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_FORCED_LOCAL_IP,
        update_entry,
        TRUE,
        "entry_config_force_ip",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_FORCED_LOCAL_IP6,
        update_entry,
        TRUE,
        "entry_config_force_ipv6",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_LISTEN_PORT,
        listen_port_changed,
        TRUE,
        "spinbutton_config_port",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SCAN_EXTENSIONS,
        update_entry,
        TRUE,
        "entry_config_extensions",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SCAN_IGNORE_SYMLINK_DIRS,
        update_togglebutton,
        TRUE,
        "checkbutton_scan_ignore_symlink_dirs",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PARQ_OPTIMISTIC,
        update_togglebutton,
        TRUE,
        "checkbutton_parq_optimistic",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PARQ_SIZE_ALWAYS_CONTINUE,
        update_spinbutton,
        TRUE,
        "spinbutton_parq_min_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PARQ_TIME_ALWAYS_CONTINUE,
        update_spinbutton,
        TRUE,
        "spinbutton_parq_min_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SCAN_IGNORE_SYMLINK_REGFILES,
        update_togglebutton,
        TRUE,
        "checkbutton_scan_ignore_symlink_regfiles",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SAVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_save_path",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MOVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_move_path",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BAD_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_bad_path",
        FREQ_UPDATES, 0
    ),
#ifdef USE_GTK1
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHARED_DIRS_PATHS,
        update_entry,
        TRUE,
        "entry_config_path",
        FREQ_UPDATES, 0
    ),
#endif /* USE_GTK1 */
#ifdef USE_GTK2
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHARED_DIRS_PATHS,
        update_shared_dirs,
        TRUE,
        "treeview_shared_dirs",
        FREQ_UPDATES, 0
    ),
#endif /* USE_GTK2 */
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MIN_DUP_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_min_dup_msg",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MIN_DUP_RATIO,
        min_dup_ratio_changed,
        TRUE,
        "spinbutton_config_min_dup_ratio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PREFER_COMPRESSED_GNET,
        update_togglebutton,
        TRUE,
        "checkbutton_prefer_compressed_gnet",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DL_MINCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_minchunksize",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DL_MAXCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_maxchunksize",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DL_PIPELINE_MAXCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_pipeline_maxchunksize",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_BUFFER_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_download_buffer_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_AUTO_DOWNLOAD_IDENTICAL,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_alternate_sources",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_STRICT_SHA1_MATCHING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_strict_sha1_matching",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_TTH_AUTO_DISCOVERY,
        update_togglebutton,
        TRUE,
        "checkbutton_config_tth_auto_discovery",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_USE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_swarming",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_USE_AGGRESSIVE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_aggressive_swarming",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_HTTP_PIPELINING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_enable_http_pipelining",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_HOPS_RANDOM_FACTOR,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hops_random_factor",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_QUERIES_FORWARD_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_search_queries_forward_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_QUERIES_KICK_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_search_queries_kick_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_ANSWERS_FORWARD_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_search_answers_forward_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_ANSWERS_KICK_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_search_answers_kick_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_OTHER_MESSAGES_KICK_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_other_messages_kick_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_SHOW_DETAILED_INFO,
        update_toggle_node_show_detailed_info,
        TRUE,
        "checkbutton_node_show_detailed_info",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TXC,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_txc",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RXC,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rxc",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TX_SPEED,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_tx_speed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RX_SPEED,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rx_speed",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TX_WIRE,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_tx_wire",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RX_WIRE,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rx_wire",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TX_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_tx_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RX_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rx_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TX_HITS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_tx_hits",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RX_HITS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rx_hits",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_GEN_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_gen_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_SQ_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_sq_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_TX_DROPPED,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_tx_dropped",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RX_DROPPED,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rx_dropped",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_QRP_STATS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_qrp_stats",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_DBW,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_dbw",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_RT,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_rt",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_SHARED_SIZE,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_shared_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_GNET_INFO_SHARED_FILES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_info_shared_files",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_LAST_ULTRA_CHECK,
        update_label_date,
        TRUE,
        "label_node_last_ultracheck",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_LAST_ULTRA_LEAF_SWITCH,
        update_label_date,
        TRUE,
        "label_last_ultra_leaf_switch",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_AVG_SERVENT_UPTIME,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_avg_servent_uptime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_AVG_IP_UPTIME,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_avg_ip_uptime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_NODE_UPTIME,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_node_uptime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_NOT_FIREWALLED,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_not_firewalled",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_ENOUGH_CONN,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_enough_conn",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_ENOUGH_FD,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_enough_fd",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_ENOUGH_MEM,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_enough_mem",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_ENOUGH_BW,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_enough_bw",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UP_REQ_GOOD_UDP,
        update_label_yes_or_no,
        TRUE,
        "label_up_req_good_udp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BROWSE_HOST_ENABLED,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_browse_host",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_RESULTS_EXPOSE_RELATIVE_PATHS,
        update_togglebutton,
        TRUE,
        "checkbutton_expose_relative_paths",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_SHELL,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_remote_shell",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_QUEUE_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_search_queue_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_QUEUE_SPACING,
        update_spinbutton,
        TRUE,
        "spinbutton_search_queue_spacing",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_WATCH_SIMILAR_QUERIES,
        update_toggle_node_watch_similar_queries,
        TRUE,
        "checkbutton_node_watch_similar_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_QUERIES_HALF_LIFE,
        update_spinbutton,
        TRUE,
        "spinbutton_node_queries_half_life",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_MUID_TRACK_AMOUNT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_muid_track_amount",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_REQUERY_THRESHOLD,
        update_spinbutton,
        TRUE,
        "spinbutton_node_requery_threshold",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENTRY_REMOVAL_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_entry_removal_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_ACCUMULATION_PERIOD,
        update_spinbutton,
        TRUE,
        "spinbutton_search_accumulation_period",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_IN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_OUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_GIN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_GOUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_GLIN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_PROGRESSBAR_BWS_GLOUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_NODE_SENDQUEUE_SIZE,
        IGNORE_CB,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    ),
#ifdef USE_GTK2
    PROP_ENTRY(
        gui_main_window,
        PROP_SERVENT_GUID,
        guid_changed,
        TRUE,
        "label_nodes_guid",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_KUID,
        kuid_changed,
        TRUE,
        "label_nodes_kuid",
        FREQ_UPDATES, 0
    ),
#endif /* USE_GTK2 */
#ifdef USE_GTK1
    PROP_ENTRY(
        gui_main_window,
        PROP_SERVENT_GUID,
        guid_changed,
        TRUE,
        "entry_nodes_guid",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_KUID,
        kuid_changed,
        TRUE,
        "entry_nodes_kuid",
        FREQ_UPDATES, 0
    ),
#endif /* USE_GTK1 */
    PROP_ENTRY(
        NULL,
        PROP_LOCAL_IP,
        local_address_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_LOCAL_IP6,
        local_address_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_IS_FIREWALLED,
        is_firewalled_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_IS_UDP_FIREWALLED,
        is_firewalled_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_RECV_SOLICITED_UDP,
        is_firewalled_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_WINDOW_COORDS,
        update_window_geometry,
        TRUE,
        NULL, /* uses fn_toplevel as widget */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_filter_dialog,
        PROP_FILTER_DLG_COORDS,
        update_window_geometry,
        TRUE,
        NULL, /* uses fn_toplevel as widget */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        NULL,
        PROP_IS_INET_CONNECTED,
        plug_icon_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_ONLINE_MODE,
        plug_icon_changed,
        TRUE,
        "togglebutton_online",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MEDIA_TYPE_AUDIO,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_media_type_audio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MEDIA_TYPE_VIDEO,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_media_type_video",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MEDIA_TYPE_DOCUMENT,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_media_type_document",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MEDIA_TYPE_IMAGE,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_media_type_image",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MEDIA_TYPE_ARCHIVE,
        update_togglebutton,
        TRUE,
        "checkbutton_config_search_media_type_archive",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONFIRM_QUIT,
        update_togglebutton,
        TRUE,
        "checkbutton_config_confirm_quit",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SHOW_TOOLTIPS,
        show_tooltips_changed,
        TRUE,
        "checkbutton_config_show_tooltips",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_EXPERT_MODE,
        expert_mode_changed,
        TRUE,
        "checkbutton_expert_mode",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_BYTES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_bytes",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_PERC,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_perc",
        FREQ_UPDATES, 0
    ),
#ifdef USE_GTK2
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_HOPS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_hops",
        FREQ_UPDATES, 0
    ),
#endif /* USE_GTK2 */
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_WITH_HEADERS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_with_headers",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_SOURCE,
        update_multichoice,
        TRUE,
        "option_menu_gnet_stats_source",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_main_window,
        PROP_GNET_STATS_DROP_REASONS_TYPE,
        update_multichoice,
        TRUE,
        "option_menu_gnet_stats_type",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_LIFETIME,
        update_multichoice,
        TRUE,
        "option_menu_search_lifetime",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NETWORK_PROTOCOL,
        network_protocol_changed,
        TRUE,
        "option_menu_config_network_protocol",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_GNET_COMPACT_QUERY,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_compact_query",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_OPTIMISTIC_START,
        update_togglebutton,
        TRUE,
        "checkbutton_config_download_optimistic_start",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_LIBRARY_REBUILDING,
        library_rebuilding_changed,
        TRUE,
        "eventbox_image_lib", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SHA1_REBUILDING,
        sha1_rebuilding_changed,
        TRUE,
        "eventbox_image_sha", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SHA1_VERIFYING,
        sha1_verifying_changed,
        TRUE,
        "eventbox_image_shav", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_TTH_REBUILDING,
        tth_rebuilding_changed,
        TRUE,
        "eventbox_image_tth", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_TTH_VERIFYING,
        tth_verifying_changed,
        TRUE,
        "eventbox_image_tthv", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_FILE_MOVING,
        file_moving_changed,
        TRUE,
        "eventbox_image_save", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_REQUIRE_URN,
        update_togglebutton,
        TRUE,
        "checkbutton_config_req_urn",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_REQUIRE_SERVER_NAME,
        update_togglebutton,
        TRUE,
        "checkbutton_config_req_srv_name",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_AUTO_FEED_DOWNLOAD_MESH,
        update_togglebutton,
        TRUE,
        "checkbutton_auto_feed_dmesh",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONFIGURED_PEERMODE,
        configured_peermode_changed,
        TRUE,
        "option_menu_config_peermode",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DHT_CONFIGURED_MODE,
        update_multichoice,
        TRUE,
        "option_menu_config_dht_mode",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DHT_STORAGE_IN_MEMORY,
        update_togglebutton,
        TRUE,
        "checkbutton_config_dht_storage_in_memory",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SPAM_LUT_IN_MEMORY,
        update_togglebutton,
        TRUE,
        "checkbutton_config_spam_lut_in_memory",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_HANDLE_IGNORED_FILES,
        update_multichoice,
        TRUE,
        "option_menu_search_handle_ignored_files",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DHT_BOOT_STATUS,
        dht_boot_status_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DHT_CURRENT_MODE,
        dht_current_mode_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_CURRENT_PEERMODE,
        current_peermode_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BAN_RATIO_FDS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ban_ratio_fds",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BAN_MAX_FDS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ban_max_fds",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BANNED_COUNT,
        update_label,
        TRUE,
        "label_banned_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_USE_GLOBAL_HOSTILES_TXT,
        update_togglebutton,
        TRUE,
        "checkbutton_use_global_hostiles",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROXY_PROTOCOL,
        update_multichoice,
        TRUE,
        "option_menu_config_proxy_protocol",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_ALLOW_STEALING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_bw_allow_stealing",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HOSTS_IN_CATCHER,
        hosts_in_catcher_changed,
        TRUE,
        "progressbar_hosts_in_catcher",
        FREQ_SECS, 5
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HOSTS_IN_ULTRA_CATCHER,
        hosts_in_ultra_catcher_changed,
        TRUE,
        "progressbar_hosts_in_ultra_catcher",
        FREQ_SECS, 5
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HOSTS_IN_BAD_CATCHER,
        hosts_in_bad_catcher_changed,
        TRUE,
        "progressbar_hosts_in_bad_catcher",
        FREQ_SECS, 5
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HOSTS_IN_G2HUB_CATCHER,
        hosts_in_g2hub_catcher_changed,
        TRUE,
        "progressbar_hosts_in_g2hub_catcher",
        FREQ_SECS, 5
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_READING_HOSTFILE,
        reading_hostfile_changed,
        TRUE,
        NULL,
        FREQ_SECS, 1
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_READING_ULTRAFILE,
        reading_ultrafile_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_HOSTS_CACHED,
        hostcache_size_changed,
        TRUE,
        "spinbutton_max_hosts_cached",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_ULTRA_HOSTS_CACHED,
        hostcache_size_changed,
        TRUE,
        "spinbutton_max_ultra_hosts_cached",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_G2HUB_HOSTS_CACHED,
        hostcache_size_changed,
        TRUE,
        "spinbutton_max_g2hub_hosts_cached",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_MAX_BAD_HOSTS_CACHED,
        hostcache_size_changed,
        TRUE,
        "spinbutton_max_bad_hosts_cached",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UL_BYTE_COUNT,
        update_byte_size_entry,
        TRUE,
        "entry_ul_byte_count",
        FREQ_SECS, 1
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_BYTE_COUNT,
        update_byte_size_entry,
        TRUE,
        "entry_dl_byte_count",
        FREQ_SECS, 1
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_QUEUE_COUNT,
        update_label,
        TRUE,
        "label_dl_queue_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_QALIVE_COUNT,
        update_label,
        TRUE,
        "label_dl_qalive_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_PQUEUED_COUNT,
        update_label,
        TRUE,
        "label_dl_pqueued_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_RUNNING_COUNT,
        dl_running_count_changed,
        TRUE,
        "label_dl_running_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_ACTIVE_COUNT,
        dl_active_count_changed,
        TRUE,
        "label_dl_active_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DL_AQUEUED_COUNT,
        dl_aqueued_count_changed,
        TRUE,
        "label_dl_aqueued_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_FI_ALL_COUNT,
        update_label,
        TRUE,
        "label_fi_all_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_FI_WITH_SOURCE_COUNT,
        update_label,
        TRUE,
        "label_fi_with_source_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DL_HTTP_LATENCY,
        dl_http_latency_changed,
        TRUE,
        "label_dl_http_latency",
        FREQ_SECS, 1
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_MAX_RESULTS,
        update_spinbutton,
        TRUE,
        "spinbutton_search_max_results",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PASSIVE_SEARCH_MAX_RESULTS,
        update_spinbutton,
        TRUE,
        "spinbutton_passive_search_max_results",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_WHATS_NEW_SEARCH_MAX_RESULTS,
        update_spinbutton,
        TRUE,
        "spinbutton_whats_new_search_max_results",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_BROWSE_HOST_MAX_RESULTS,
        update_spinbutton,
        TRUE,
        "spinbutton_browse_host_max_results",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DISPLAY_METRIC_UNITS,
        display_metric_units_changed,
        TRUE,
        "checkbutton_config_metric",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_LEAF_IN_ENABLED,
        bw_gnet_lin_enabled_changed,
        TRUE,
        "checkbutton_config_bws_glin",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_LEAF_OUT_ENABLED,
        bw_gnet_lout_enabled_changed,
        TRUE,
        "checkbutton_config_bws_glout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_LIN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_glin",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GNET_LOUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_glout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MAX_LEAVES,
        update_spinbutton_ultranode,
        TRUE,
        "spinbutton_config_max_leaves",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_MAX_BANNED_FD,
        update_entry,
        TRUE,
        "entry_config_max_banned_fd",
        FREQ_UPDATES, 1
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_INCOMING_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_incoming_connecting_timeout",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_RX_FLOWC_RATIO,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_rx_flowc_ratio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NORMAL_CONNECTIONS,
        update_spinbutton_ultranode,
        TRUE,
        "spinbutton_normal_connections",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_AVERAGE_IP_UPTIME,
        update_entry_duration,
        TRUE,
        "entry_average_ip_uptime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_AVERAGE_SERVENT_UPTIME,
        update_entry_duration,
        TRUE,
        "entry_average_servent_uptime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_AVERAGE_SERVENT_DOWNTIME,
        update_entry_duration,
        TRUE,
        "entry_average_servent_downtime",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SYS_PHYSMEM,
        update_size_entry,
        TRUE,
        "entry_sys_physmem",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CLOCK_SKEW,
        clock_skew_changed,
        TRUE,
        "label_clock_skew",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_HOST_RUNS_NTP,
        update_togglebutton,
        TRUE,
        "checkbutton_host_runs_ntp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_MONITOR_UNSTABLE_IP,
        update_monitor_unstable_ip,
        TRUE,
        "checkbutton_gnet_monitor_ip",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_MONITOR_UNSTABLE_SERVENTS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_monitor_servents",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_RESERVE_GTKG_NODES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_reserve_gtkg_nodes",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UNIQUE_NODES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_unique_nodes",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_DOWNLOAD_RX_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_download_rx_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_NODE_RX_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_node_rx_size",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_LIBRARY_RESCAN_STARTED,
        update_label_date,
        TRUE,
        "label_library_rescan_timestamp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_LIBRARY_RESCAN_DURATION,
        update_label_duration,
        TRUE,
        "label_library_rescan_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_INDEXING_STARTED,
        update_label_date,
        TRUE,
        "label_qrp_indexing_timestamp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_INDEXING_DURATION,
        update_label_duration,
        TRUE,
        "label_qrp_indexing_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_TIMESTAMP,
        update_label_date,
        TRUE,
        "label_qrp_timestamp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_COMPUTATION_TIME,
        update_label_duration,
        TRUE,
        "label_qrp_computation_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_PATCH_TIMESTAMP,
        update_label_date,
        TRUE,
        "label_qrp_patch_timestamp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_PATCH_COMPUTATION_TIME,
        update_label_duration,
        TRUE,
        "label_qrp_patch_computation_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_GENERATION,
        update_label,
        TRUE,
        "label_qrp_generation",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_SLOTS,
        update_label,
        TRUE,
        "label_qrp_slots",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_SLOTS_FILLED,
        update_label,
        TRUE,
        "label_qrp_slots_filled",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_FILL_RATIO,
        update_label,
        TRUE,
        "label_qrp_fill_ratio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_CONFLICT_RATIO,
        update_label,
        TRUE,
        "label_qrp_conflict_ratio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_HASHED_KEYWORDS,
        update_label,
        TRUE,
        "label_qrp_hashed_keywords",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_PATCH_RAW_LENGTH,
        update_label,
        TRUE,
        "label_qrp_patch_raw_length",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_PATCH_LENGTH,
        update_label,
        TRUE,
        "label_qrp_patch_length",
        FREQ_UPDATES, 0
	),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_QRP_PATCH_COMP_RATIO,
        update_label,
        TRUE,
        "label_qrp_patch_comp_ratio",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_G2_BROWSE_COUNT,
        update_label,
        TRUE,
        "label_g2_browse_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HTML_BROWSE_COUNT,
        update_label,
        TRUE,
        "label_html_browse_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_QHITS_BROWSE_COUNT,
        update_label,
        TRUE,
        "label_qhits_browse_count",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_G2_BROWSE_SERVED,
        update_label,
        TRUE,
        "label_g2_browse_served",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_HTML_BROWSE_SERVED,
        update_label,
        TRUE,
        "label_html_browse_served",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_QHITS_BROWSE_SERVED,
        update_label,
        TRUE,
        "label_qhits_browse_served",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_OVERLOADED_CPU,
        overloaded_cpu_changed,
        TRUE,
        "eventbox_image_chip",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_NET_BUFFER_SHORTAGE,
        net_buffer_shortage_changed,
        TRUE,
        "eventbox_net_buffer_shortage",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_TCP_NO_LISTENING,
        tcp_no_listening_changed,
        TRUE,
        "eventbox_tcp_no_listening",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UPLOADS_STALLING,
        uploads_stalling_changed,
        TRUE,
        "eventbox_image_warning",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UPLOADS_BW_IGNORE_STOLEN,
        uploads_early_stalling_changed,
        TRUE,
        "eventbox_early_stall_1",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UPLOADS_BW_NO_STEALING,
        uploads_early_stalling_changed,
        TRUE,
        "eventbox_early_stall_2",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_UPLOADS_BW_UNIFORM,
        uploads_early_stalling_changed,
        TRUE,
        "eventbox_early_stall_3",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PORT_MAPPING_POSSIBLE,
        port_mapping_update,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_PORT_MAPPING_SUCCESSFUL,
        port_mapping_update,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_FILE_DESCRIPTOR_SHORTAGE,
        file_descriptor_warn_changed,
        TRUE,
        "eventbox_image_fd_shortage",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_FILE_DESCRIPTOR_RUNOUT,
        file_descriptor_warn_changed,
        TRUE,
        "eventbox_image_fd_runout",
        /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROCESS_OOB_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_process_oob_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEND_OOB_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_send_oob_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_PROXY_OOB_QUERIES,
        update_togglebutton,
        TRUE,
        "checkbutton_proxy_oob_queries",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_G2,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_g2",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_GUESS,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_guess",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_GUESS_CLIENT,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_guess_client",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_NATPMP,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_natpmp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_UPNP,
        update_togglebutton,
        TRUE,
        "checkbutton_enable_upnp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_UPNP_MAPPING_LEASE_TIME,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upnp_mapping_lease_time",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_UDP,
        enable_udp_changed,
        TRUE,
        "checkbutton_enable_udp",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_ENABLE_DHT,
        enable_dht_changed,
        TRUE,
        "checkbutton_enable_dht",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONVERT_SPACES,
        update_togglebutton,
        TRUE,
        "checkbutton_config_convert_spaces",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONVERT_EVIL_CHARS,
        update_togglebutton,
        TRUE,
        "checkbutton_config_convert_evil_chars",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_CONVERT_OLD_FILENAMES,
        update_togglebutton,
        TRUE,
        "checkbutton_config_convert_old_filenames",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BEAUTIFY_FILENAMES,
        update_togglebutton,
        TRUE,
        "checkbutton_config_beautify_filenames",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_SORT_CASESENSE,
        update_togglebutton,
        TRUE,
        "checkbutton_search_sort_casesense",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_DISPLAY_GUESS_STATS,
        search_display_guess_stats_changed,
        TRUE,
        "checkbutton_search_display_guess_stats",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_GUESS_STATS_SHOW_TOTAL,
        search_display_guess_stats_changed,
        TRUE,
        "checkbutton_guess_stats_show_total",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_DISCARD_SPAM,
        update_togglebutton,
        TRUE,
        "checkbutton_search_discard_spam",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_DISCARD_HASHLESS,
        update_togglebutton,
        TRUE,
        "checkbutton_search_discard_hashless",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_DISCARD_ALIEN_IP,
        update_togglebutton,
        TRUE,
        "checkbutton_search_discard_alien_ip",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_SEARCH_DISCARD_BANNED_GUID,
        update_togglebutton,
        TRUE,
        "checkbutton_search_discard_banned_guid",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_SEARCH_JUMP_TO_CREATED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_jump_to_created",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BIND_TO_FORCED_LOCAL_IP,
        update_togglebutton,
        TRUE,
        "checkbutton_config_bind_ipv4",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BIND_TO_FORCED_LOCAL_IP6,
        update_togglebutton,
        TRUE,
        "checkbutton_config_bind_ipv6",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_USE_IPV6_TRT,
        update_togglebutton,
        TRUE,
        "checkbutton_config_ipv6_trt_enable",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_IPV6_TRT_PREFIX,
        update_entry,
        TRUE,
        "entry_config_ipv6_trt_prefix",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_DHT_LOOKUP_IN,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_input_dht_lookup_bw",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_DHT_LOOKUP_OUT,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_output_dht_lookup_bw",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_BW_GUESS_OUT,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_bw_guess_out",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_GUESS_MAXIMIZE_BW,
        update_togglebutton,
        TRUE,
        "checkbutton_guess_maximize_bw",
        FREQ_UPDATES, 0
    ),
    PROP_ENTRY(
        gui_main_window,
        PROP_DOWNLOAD_QUEUE_FROZEN,
        update_queue_frozen,
        TRUE,
       	NULL,
        FREQ_UPDATES, 0
    ),
#ifdef USE_GTK2
    PROP_ENTRY(
        gui_dlg_prefs,
        PROP_STATUS_ICON_ENABLED,
        update_togglebutton,
        TRUE,
        "checkbutton_status_icon_enabled",
        FREQ_UPDATES, 0
    ),
#endif	/* USE_GTK2 */
};

/* Not needed any longer */
#undef PROP_ENTRY

/**
 * Fetches a pointer to the map entry which handles the given
 * property. This can be use only when settings_gui_init_prop_map
 * has successfully been called before.
 */
static prop_map_t *
settings_gui_get_map_entry(property_t prop)
{
    gint entry = NOT_IN_MAP;

    if (
        (prop >= gui_prop_set_stub->offset) &&
        (prop < gui_prop_set_stub->offset+gui_prop_set_stub->size)
    ) {
        entry = gui_init_list[prop-GUI_PROPERTY_MIN];
    } else
    if (
        (prop >= gnet_prop_set_stub->offset) &&
        (prop < gnet_prop_set_stub->offset+gnet_prop_set_stub->size)
    ) {
        entry = gnet_init_list[prop-GNET_PROPERTY_MIN];
    } else
        g_error("%s: property does not belong to known set: %u",
			G_STRFUNC, prop);

    g_assert(entry != NOT_IN_MAP);

    return &property_map[entry];
}


/**
 * Use information from property_map to connect callbacks to signals
 * from the backend.
 *
 * You can't connect more then one callback to a single property change.
 * You can however IGNORE a property change to suppress a warning in
 * debugging mode. This is done by settings the cb field (callback) in
 * property_map to IGNORE_CB.
 *
 * The tooltips for the widgets are set from to the description from the
 * property definition.
 */
static void
settings_gui_init_prop_map(void)
{
    guint n;

    if (GUI_PROPERTY(gui_debug) >= 2) {
        g_debug("%s(): property_map size: %u",
            G_STRFUNC, (guint) N_ITEMS(property_map));
    }

    /*
     * Fill in automatic fields in property_map.
     */
    for (n = 0; n < N_ITEMS(property_map); n++) {
        property_t prop = property_map[n].prop;
        prop_def_t *def;

        /*
         * Fill in prop_set_stub
         */
        if (
            (prop >= gui_prop_set_stub->offset) &&
            (prop < gui_prop_set_stub->offset+gui_prop_set_stub->size)
        ) {
            property_map[n].stub = gui_prop_set_stub;
            property_map[n].init_list = gui_init_list;
        } else if (
            (prop >= gnet_prop_set_stub->offset) &&
            (prop < gnet_prop_set_stub->offset+gnet_prop_set_stub->size)
        ) {
            property_map[n].stub = gnet_prop_set_stub;
            property_map[n].init_list = gnet_init_list;
        } else
            g_error("%s: property does not belong to known set: %u",
				G_STRFUNC, prop);

        /*
         * Fill in type
         */
        def = property_map[n].stub->get_def(prop);

        property_map[n].type = def->type;

        prop_free_def(def);
    }

    /*
     * Now the map is complete and can be processed.
     */
    for (n = 0; n < N_ITEMS(property_map); n ++) {
        property_t  prop      = property_map[n].prop;
        prop_def_t *def       = property_map[n].stub->get_def(prop);
        guint32     idx       = prop - property_map[n].stub->offset;
        gint       *init_list = property_map[n].init_list;

        if (init_list[idx] == NOT_IN_MAP) {
            init_list[idx] = n;
        } else {
            g_error("%s: property %s already mapped to %d",
                G_STRFUNC, def->name, init_list[idx]);
        }

        if (property_map[n].cb != IGNORE_CB) {
            settings_gui_config_widget(&property_map[n], def);

            /*
             * Add listener
             */
            if (GUI_PROPERTY(gui_debug) >= 10) {
                g_debug("%s(): adding changes listener [%s]",
				   G_STRFUNC, def->name);
			}
            property_map[n].stub->prop_changed_listener.add_full(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init,
                property_map[n].f_type,
                property_map[n].f_interval);
            if (GUI_PROPERTY(gui_debug) >= 10) {
                g_debug("%s(): adding changes listener [%s][done]",
					G_STRFUNC, def->name);
			}
        } else if (GUI_PROPERTY(gui_debug) >= 10) {
            g_debug("%s(): property ignored: %s", G_STRFUNC, def->name);
        }
        prop_free_def(def);
    }

    if (GUI_PROPERTY(gui_debug) >= 1) {
        for (n = 0; n < GUI_PROPERTY_NUM; n++) {
            if (gui_init_list[n] == NOT_IN_MAP) {
                g_info("%s(): [GUI] unmapped property: %s",
					G_STRFUNC, gui_prop_name(n+GUI_PROPERTY_MIN));
            }
        }
    }

    if (GUI_PROPERTY(gui_debug) >= 1) {
        for (n = 0; n < GNET_PROPERTY_NUM; n++) {
            if (gnet_init_list[n] == NOT_IN_MAP) {
                g_info("%s(): [GNET] unmapped property: %s",
					G_STRFUNC, gnet_prop_name(n+GNET_PROPERTY_MIN));
            }
        }
    }
}

static void
settings_gui_save_panes(void)
{
	guint i;

	for (i = 0; i < N_ITEMS(panes); i++) {
		GtkPaned *paned;

		paned = GTK_PANED(gui_main_window_lookup(panes[i].name));
		if (GTK_WIDGET_VISIBLE(gtk_paned_get_child1(paned)))
			paned_save_position(paned, panes[i].prop);
	}
}

void
settings_gui_restore_panes(void)
{
	guint i;

	for (i = 0; i < N_ITEMS(panes); i++) {
		GtkPaned *paned;

		paned = GTK_PANED(gui_main_window_lookup(panes[i].name));
		if (GTK_WIDGET_VISIBLE(gtk_paned_get_child1(paned)))
			paned_restore_position(paned, panes[i].prop);
		else
			gtk_paned_set_position(paned, 0);
	}
}

void G_COLD
settings_gui_early_init(void)
{
    gui_prop_set_stub = gui_prop_get_stub();
    gnet_prop_set_stub = gnet_prop_get_stub();

    properties = gui_prop_init();
}

void G_COLD
settings_gui_init(void)
{
    gint n;

	g_assert_log(properties != NULL,
		"%s(): settings_gui_early_init() not called yet!", G_STRFUNC);

    tooltips = gtk_tooltips_new();
	sensitive_changes = hikset_create(
		offsetof(struct widget_change, name), HASH_KEY_STRING, 0);

   	prop_load_from_file(properties, settings_gui_config_dir(), property_file);

    for (n = 0; n < GUI_PROPERTY_NUM; n ++) {
        gui_init_list[n] = NOT_IN_MAP;
    }

    for (n = 0; n < GNET_PROPERTY_NUM; n ++) {
        gnet_init_list[n] = NOT_IN_MAP;
    }

    settings_gui_init_prop_map();

	/*
	 * If they don't have requested compilation of the "remote shell", disable
	 * the checkbutton controlling it but leave it in the GUI so that they
	 * know they miss something...
	 *		--RAM, 27/12/2003
	 */
#ifndef USE_REMOTE_CTRL
	gtk_widget_set_sensitive(
		gui_dlg_prefs_lookup("checkbutton_enable_remote_shell"), FALSE);
#endif /* USE_REMOTE_CTRL */
}

static void G_COLD
sensitive_free_value(void *value, void *unused_data)
{
	struct widget_change *wc = value;

	(void) unused_data;

	cq_cancel(&wc->ev);
	WFREE(wc);
}

void G_COLD
settings_gui_shutdown(void)
{
    guint n;

    /*
     * Remove the listeners
     */

    for (n = 0; n < N_ITEMS(property_map); n ++) {
        if (property_map[n].cb != IGNORE_CB) {
            property_map[n].stub->prop_changed_listener.remove(
                property_map[n].prop,
                property_map[n].cb);
        }
    }

	hikset_foreach(sensitive_changes, sensitive_free_value, NULL);
	hikset_free_null(&sensitive_changes);

    /*
     * There are no Gtk signals to listen to, so we must set those
     * values on exit.
     */

	settings_gui_save_panes();

    /*
     * Save properties to file
     */

    prop_save_to_file(properties, settings_gui_config_dir(), property_file);

    /*
     * Free allocated memory.
     */

    gui_prop_shutdown();

    G_FREE_NULL(home_dir);
}

GtkTooltips *
settings_gui_tooltips(void)
{
	return tooltips;
}

/* vi: set ts=4 sw=4 cindent: */
