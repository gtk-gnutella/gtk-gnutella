/*
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include <signal.h>
#include <locale.h>
#include <sys/utsname.h>		/* For uname() */

#include "interface.h"
#include "gui.h"
#include "support.h"
#include "search.h"
#include "share.h"
#include "sockets.h"
#include "routing.h"
#include "downloads.h"
#include "hosts.h"
#include "dialog-filters.h"
#include "filter.h"
#include "misc.h"
#include "autodownload.h"
#include "gmsg.h"
#include "bsched.h"
#include "search_stats.h"
#include "upload_stats.h"

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */
#define EXIT_GRACE				20	/* Seconds to wait before exiting */

/* */

GtkWidget *main_window;
GtkWidget *shutdown_window;

struct gnutella_socket *s_listen = NULL;
gchar *version_string = NULL;
time_t start_time;
gchar *start_rfc822_date = NULL;		/* RFC822 format of start_time */

static guint main_slow_update = 0;
static gboolean exiting = FALSE;
static time_t exit_time = 0;

/* */

/*
 * gtk_gnutella_exit
 *
 * Exit program, return status `n' to parent process.
 *
 * Shutdown systems, so we can track memory leaks, and wait for EXIT_GRACE
 * seconds so that BYE messages can be sent to other nodes.
 */
void gtk_gnutella_exit(gint n)
{
	time_t now = time((time_t *) NULL);
    time_t tick;
    gchar tmp[256];

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

    exit_time = now;

	node_bye_all();
	upload_close();		/* Done before config_close() for stats update */
	download_close();

    /*
     * Make sure the gui writes config variabes it owns but that can't 
     * be updated via callbacks.
     *      --BLUE, 16/05/2002
     */
    gui_shutdown();

	if (hosts_idle_func)
		gtk_idle_remove(hosts_idle_func);
	config_shutdown();

	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown();
	filters_shutdown();

	/* 
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 */

    gtk_widget_hide(main_window);
    gtk_widget_show(shutdown_window);

	while (node_bye_pending() && 
           (tick = time((time_t *) NULL)) - now < EXIT_GRACE) {
         g_snprintf(tmp, sizeof(tmp), "%d seconds", 
            (gint)difftime(now,exit_time));
        gtk_label_set(GTK_LABEL(label_shutdown_count),tmp);
		gtk_main_iteration_do(FALSE);
		usleep(50000);					/* 50 ms */
	}

   	bsched_shutdown();
	share_close();
	node_close();
	host_close();
	routing_close();
	bsched_close();
	gui_close();
	config_close();
	g_free(version_string);
	g_free(start_rfc822_date);

    printf("gtk-gnutella shut down cleanly.\n\n");

	gtk_exit(n);
}

static void sig_terminate(int n)
{
	gtk_gnutella_exit(1);
}

static void init_constants(void)
{
	gchar buf[128];
	struct utsname un;

	(void) uname(&un);

	g_snprintf(buf, sizeof(buf), "gtk-gnutella/%u.%u%s (%s; %s; %s %s %s)",
		GTA_VERSION, GTA_SUBVERSION, GTA_REVCHAR, GTA_RELEASE,
		GTA_INTERFACE, un.sysname, un.release, un.machine);

	version_string = g_strdup(buf);

        start_time = time((time_t *) NULL);
	start_rfc822_date = g_strdup(date_to_rfc822_gchar(start_time));
}

static void slow_main_timer(time_t now)
{
	ul_flush_stats_if_dirty();
}

static gboolean main_timer(gpointer p)
{
	time_t now = time((time_t *) NULL);

    /*
    static gboolean shutdown = FALSE;

    if (exiting) {
        gchar tmp[256];

        if (!shutdown) {
            shutdown = TRUE;
            gtk_widget_hide(main_window);
            gtk_widget_show(shutdown_window);
        }
        g_snprintf(tmp, sizeof(tmp), "%d seconds", 
            (gint)difftime(now,exit_time));
        gtk_label_set(GTK_LABEL(label_shutdown_count),tmp);
    }
    */

    bsched_timer();				    /* Scheduling update */
	host_timer();					/* Host connection */
	node_timer(now);				/* Node timeouts */
    if (!exiting) {
        download_timer(now);  	    /* Download timeouts */
        upload_timer(now);			/* Upload timeouts */
    }
	socket_monitor_incoming();		/* Expire connecting sockets */
	pcache_possibly_expired(now);	/* Expire pong cache */

	/*
	 * GUI update
	 */

    if (!exiting) {
        gui_statusbar_clear_timeouts(now);
        gui_update_global();

        /* Update for things that change slowly */
        if (main_slow_update++ > SLOW_UPDATE_PERIOD) {
            main_slow_update = 0;
            slow_main_timer(now);
        }
    }

	return TRUE;
}

gint main(gint argc, gchar ** argv)
{
	gint i;

	const gchar *menus[] = {
		"gnutellaNet",
		"Uploads",
		"Stats",
		"Downloads",
		"Search",
		"Monitor",
		"Stats",
		"Config",
		NULL
	};

    const gint menutabs[] = { 0, 1, 2, 3, 4, 5, 6, 7, -1 };

	gchar mtmp[1024];

	gint optimal_width;
    GtkCTreeNode * parent_node = NULL;    
    GtkCTreeNode * last_node = NULL;


	g_assert(sizeof(menus) / sizeof(menus[0]) - 2 == NOTEBOOK_MAIN_IDX_MAX);

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

	setlocale(LC_TIME, "C");	/* strftime() must emit standard dates */

	/* Glade inits */

	gtk_set_locale();

	gtk_init(&argc, &argv);

	add_pixmap_directory(PACKAGE_DATA_DIR "/pixmaps");
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");

	main_window = create_main_window();
    shutdown_window = create_shutdown_window();

	/* Our inits */

	gui_init();
	init_constants();
	config_init();
	host_init();
	gmsg_init();
    bsched_init();
	network_init();
	routing_init();
	filters_init();			/* Must come before search_init() for retrieval */
	search_init();
	share_init();
	download_init();
	autodownload_init();

   	gui_update_all();

	/* Some signal handlers */

	signal(SIGTERM, sig_terminate);
	signal(SIGINT, sig_terminate);
	signal(SIGPIPE, SIG_IGN);

#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	/* Create the main listening socket */

	if (listen_port)
		s_listen = socket_listen(0, listen_port, GTA_TYPE_CONTROL);

	/* Final interface setup */

	optimal_width =
		gtk_clist_optimal_column_width(GTK_CLIST(ctree_menu), 0);

    // gnutellaNet
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &menus[0],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[0]);

    // Uploads
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &menus[1],
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, (gpointer) &menutabs[1]);

    // Uploads -> Stats
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, (gchar **) &menus[2],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[2]);

    // Downloads
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &menus[3],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[3]);

    // Search
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &menus[4],
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, (gpointer) &menutabs[4]);

    // Search -> Monitor
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, (gchar **) & menus[5],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[5]);

    // Search -> Monitor
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, (gchar **) & menus[6],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[6]);

    // Config
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) & menus[7],
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, (gpointer) &menutabs[7]); 

	gtk_clist_select_row(GTK_CLIST(ctree_menu), 0, 0);

	gtk_widget_set_usize(sw_menu, optimal_width,
						 (ctree_menu->style->font->ascent +
						  ctree_menu->style->font->descent + 4) * 8);

	gui_update_c_gnutellanet();
	gui_update_c_uploads();
	gui_update_c_downloads(0, 0);

	gui_update_global();

#ifdef GTA_REVISION
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u %s", GTA_VERSION,
			   GTA_SUBVERSION, GTA_REVISION);
#else
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u", GTA_VERSION,
			   GTA_SUBVERSION);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), mtmp);
	gtk_widget_show(main_window);		/* Display the main window */

	/* Setup the main timer */

	gtk_timeout_add(1000, (GtkFunction) main_timer, NULL);

	/* Okay, here we go */

	if (search_stats_enabled)
		enable_search_stats();

	bsched_enable_all();
	gtk_main();

	return 0;
}

/* vi: set ts=4: */
