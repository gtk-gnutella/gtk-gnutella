/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI stuff used by share.c
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
#include "settings_cb.h"
#include "gnet.h"
#include "settings_gui.h"
#include "gtk-missing.h"

/* 
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)                                            \
    gboolean on_##a##_focus_out_event                                   \
        (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)   \
    {                                                                   \
        on_##a##_activate(GTK_EDITABLE(widget), NULL);                  \
        return TRUE;                                                    \
    }

#define togglebutton_changed(pref,p, tb) do {                           \
        gboolean val = gtk_toggle_button_get_active                     \
            (GTK_TOGGLE_BUTTON(tb));                                    \
        pref##_prop_set_boolean(p, &val, 0, 1);                         \
    } while (0)

#define checkmenu_changed(pref,p, cb) do {                              \
        gboolean val = GTK_CHECK_MENU_ITEM(cb)->active;                 \
        pref##_prop_set_boolean(p, &val, 0, 1);                         \
    } while (0)

void on_spinbutton_search_reissue_timeout_changed
    (GtkEditable *editable, gpointer user_data)
{
    extern search_t *current_search; 
    // FIXME: current_search should be in the gui and call should use
    // search handle of current search instead of pointer!

    search_update_reissue_timeout(current_search,
        gtk_spin_button_get_value(GTK_SPIN_BUTTON(editable)));
}

void on_spinbutton_minimum_speed_changed
    (GtkEditable *editable, gpointer user_data)
{
    extern search_t *current_search; 
    // FIXME: current_search should be in the gui and call should use
    // search handle of current search instead of pointer!

    if (current_search != NULL)
        current_search->speed = gtk_spin_button_get_value
            (GTK_SPIN_BUTTON(editable));
    
}

void on_entry_config_proxy_ip_activate
    (GtkEditable *editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));
    guint32 ip = host_to_ip(e);

    gnet_prop_set_guint32(PROP_PROXY_IP, &ip, 0, 1);

	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_proxy_ip)

void on_entry_config_socks_username_activate
    (GtkEditable *editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));

    gnet_prop_set_string(PROP_SOCKS_USER, e);
	
    g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_username)

void on_entry_config_socks_password_activate
    (GtkEditable * editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));

    gnet_prop_set_string(PROP_SOCKS_PASS, e);
	
    g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_password)

void on_checkbutton_config_bw_ul_usage_enabled_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gnet, PROP_BW_UL_USAGE_ENABLED, tb);
}

void on_checkbutton_search_pick_all_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gui, PROP_SEARCH_PICK_ALL, tb);
}

void on_checkbutton_queue_regex_case_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gui, PROP_QUEUE_REGEX_CASE, tb);
}

void on_checkbutton_monitor_enable_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gui, PROP_MONITOR_ENABLED, tb);
}


void on_checkbutton_config_proxy_connections_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gnet, PROP_PROXY_CONNECTIONS, tb);
}

void on_checkbutton_config_proxy_auth_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gnet, PROP_PROXY_AUTH, tb);
}

void on_checkbutton_search_autoselect_ident_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gui, PROP_SEARCH_AUTOSELECT_IDENT, tb);
}

void on_checkbutton_search_remove_downloaded_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gnet, PROP_SEARCH_REMOVE_DOWNLOADED, tb);
}

void on_checkbutton_search_jump_to_downloads_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    togglebutton_changed(gui, PROP_JUMP_TO_DOWNLOADS, tb);
}

void on_checkbutton_downloads_never_push_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    gboolean b = !gtk_toggle_button_get_active(tb);

    gnet_prop_set_boolean(PROP_SEND_PUSHES, &b, 0, 1);
}


void on_checkbutton_config_bws_in_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    gboolean b = gtk_toggle_button_get_active(tb);
    GtkWidget *w = lookup_widget
        (main_window, "spinbutton_config_bws_in");

    gnet_prop_set_boolean(PROP_BW_HTTP_IN_ENABLED, &b, 0, 1);

    gtk_widget_set_sensitive(w, b);
}

void on_checkbutton_config_bws_out_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    gboolean b = gtk_toggle_button_get_active(tb);
    gboolean val;
    GtkWidget *w = lookup_widget
        (main_window, "spinbutton_config_bws_out");
    GtkWidget *c = lookup_widget
        (main_window, "checkbutton_config_bw_ul_usage_enabled");
    GtkWidget *s = lookup_widget
        (main_window, "spinbutton_config_ul_usage_min_percentage");

    gnet_prop_get_boolean(PROP_BW_UL_USAGE_ENABLED, &val, 0, 1);
    gnet_prop_set_boolean(PROP_BW_HTTP_OUT_ENABLED, &b, 0, 1);

    gtk_widget_set_sensitive(w, b);
    gtk_widget_set_sensitive(c, b);
    gtk_widget_set_sensitive(s, b && val);
}

void on_checkbutton_config_bws_gin_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    gboolean b = gtk_toggle_button_get_active(tb);
    GtkWidget *w = lookup_widget
        (main_window, "spinbutton_config_bws_gin");

    gnet_prop_set_boolean(PROP_BW_GNET_IN_ENABLED, &b, 0, 1);

    gtk_widget_set_sensitive(w, b);
}

void on_checkbutton_config_bws_gout_toggled
    (GtkToggleButton *tb, gpointer user_data)
{
    gboolean b = gtk_toggle_button_get_active(tb);
    GtkWidget *w = lookup_widget
        (main_window, "spinbutton_config_bws_gout");

    gnet_prop_set_boolean(PROP_BW_GNET_OUT_ENABLED, &b, 0, 1);

    gtk_widget_set_sensitive(w, b);
}

void on_menu_toolbar_visible_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
	checkmenu_changed(gui, PROP_TOOLBAR_VISIBLE, menuitem);
}

void on_menu_statusbar_visible_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
	checkmenu_changed(gui, PROP_STATUSBAR_VISIBLE, menuitem);
}

void on_menu_downloads_visible_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_DOWNLOADS_VISIBLE, menuitem);
}

void on_menu_uploads_visible_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_UPLOADS_VISIBLE, menuitem);
}

void on_menu_connections_visible_activate(GtkMenuItem * menuitem,
									   gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_CONNECTIONS_VISIBLE, menuitem);
}

void on_menu_bws_in_visible_activate(GtkMenuItem * menuitem,
								     gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_IN_VISIBLE, menuitem);
}

void on_menu_bws_out_visible_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_OUT_VISIBLE, menuitem);
}

void on_menu_bws_gin_visible_activate(GtkMenuItem * menuitem,
						 		      gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GIN_VISIBLE, menuitem);
}

void on_menu_bws_gout_visible_activate(GtkMenuItem * menuitem,
								       gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GOUT_VISIBLE, menuitem);
}

void on_popup_search_toggle_tabs_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    gboolean val;

    gui_prop_get_boolean(PROP_SEARCH_RESULTS_SHOW_TABS, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_SEARCH_RESULTS_SHOW_TABS, &val, 0, 1);
}
