/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
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

#include "main_gui.h"
#include "nodes_gui.h"

#include "settings_gui.h"
#include "search_gui.h"
#include "monitor_gui.h"

#include "filter_cb.h"

#include "filter.h"

#include "oldconfig.h"

#include <pwd.h>


/***
 *** Private function
 ***/

/*
 * load_legacy_settings:
 *
 * If no configuration files are found for frontend and core, it tries
 * to read in the old config file.
 * FIXME: This should be removed as soon as possible, probably for 1.0.
 */
void load_legacy_settings(void)
{
    struct passwd *pwd = getpwuid(getuid());
    gchar *config_dir;
    gchar *home_dir;
    gchar tmp[2000] = "";
    gchar core_config_file[2000] = "";
    gchar gui_config_file[2000] = "";

    config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
    if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

    if (!home_dir)
		g_warning("can't find your home directory!");
 
    if (!config_dir) {
		if (home_dir) {
			g_snprintf(tmp, sizeof(tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(tmp);
		} else
			g_warning("no home directory: can't check legacy configuration!");
	}

    g_snprintf(core_config_file, sizeof(core_config_file), 
        "%s/%s", config_dir, "config_gnet");
    g_snprintf(gui_config_file, sizeof(gui_config_file), 
        "%s/%s", config_dir, "config_gui");

    if (!file_exists(core_config_file) && !file_exists(gui_config_file)) {
        g_warning("No configuration found, trying legacy config file");
        config_init();
    }

    g_free(config_dir);
    g_free(home_dir);
}



/***
 *** Public functions
 ***/

void main_gui_init(void)
{
    gtk_clist_column_titles_passive
        (GTK_CLIST(lookup_widget(main_window, "clist_nodes")));
	gtk_clist_column_titles_passive
        (GTK_CLIST(lookup_widget(main_window, "clist_uploads")));
	gtk_clist_column_titles_passive
        (GTK_CLIST(lookup_widget(main_window, "clist_downloads")));

    {
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_downloads_queue"));

        gtk_clist_column_titles_passive(clist);
        gtk_clist_set_reorderable(clist, TRUE);
        gtk_clist_set_use_drag_icons(clist, FALSE);
    }  

    // FIXME: those gtk_widget_set_sensitive should become obsolete when
    // all property-change callbacks are set up properly
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_remove_file"), FALSE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), FALSE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_nodes, "popup_nodes_remove"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort"), FALSE); 
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_named"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_host"), FALSE);
    gtk_widget_set_sensitive(
        lookup_widget(popup_downloads, "popup_downloads_push"),
    	!gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON
                (lookup_widget(main_window, 
                               "checkbutton_downloads_never_push"))));

    settings_gui_init();
    nodes_gui_init();
    /* Must come before search_init() so searches/filters can be loaded.*/
	filter_init(); 
    search_gui_init();
    filter_update_targets(); /* Make sure the default filters are ok */
    monitor_gui_init();

    load_legacy_settings();
}

void main_gui_run(void)
{
    guint32 coord[4] = { 0, 0, 0, 0 };

    gui_update_global();

    gtk_widget_show(main_window);		/* Display the main window */

    gui_prop_get_guint32(PROP_WINDOW_COORDS, coord, 0, 4);

    if ((coord[2] != 0) && (coord[3] != 0))
        gdk_window_move_resize(main_window->window, 
	    coord[0], coord[1], coord[2], coord[3]);

    gtk_main();
}

void main_gui_shutdown(void)
{
    guint32 coord[4] = { 0, 0, 0, 0};

	gdk_window_get_root_origin(main_window->window, &coord[0], &coord[1]);
	gdk_window_get_size(main_window->window, &coord[2], &coord[3]);
    gui_prop_set_guint32(PROP_WINDOW_COORDS, coord, 0, 4);

    /*
     * Discard all changes and close the dialog.
     */
    filter_close_dialog(FALSE);

    filter_cb_close();
    monitor_gui_shutdown();
    search_gui_shutdown(); /* must be done before filter_shutdown! */
	filter_shutdown();
    nodes_gui_shutdown();
    settings_gui_shutdown();
}

void main_gui_timer()
{
    gui_update_global();
    gui_update_traffic_stats();
    filter_timer(); /* Update the filter stats */
}
