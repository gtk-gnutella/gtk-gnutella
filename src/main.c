
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

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */

/* */

GtkWidget *main_window;

struct gnutella_socket *s_listen = NULL;
gchar *version_string = NULL;
time_t start_time;
gchar *start_rfc822_date = NULL;		/* RFC822 format of start_time */

static guint main_slow_update = 0;

/* */

void gtk_gnutella_exit(gint n)
{
	if (hosts_idle_func)
		gtk_idle_remove(hosts_idle_func);
	config_save();

	/* Shutdown systems, so we can track memory leaks */
	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown();
	filters_shutdown();
	share_close();
	node_close();
	host_close();
	routing_close();
	download_close();
	upload_close();
	bsched_close();
	gui_close();
	config_close();
	g_free(version_string);
	g_free(start_rfc822_date);

	gtk_exit(n);
}

static void SIG_Handler(int n)
{
	gtk_gnutella_exit(1);
}

static void SIG_Ignore(int n)
{
	signal(SIGPIPE, SIG_Ignore);		/* SIG_IGN -- running under debugger */
	return;
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

gboolean main_timer(gpointer p)
{
	time_t now = time((time_t *) NULL);

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
	node_timer(now);				/* Node timeouts */
	download_timer(now);			/* Download timeouts */
	upload_timer(now);				/* Upload timeouts */
	socket_monitor_incoming();		/* Expire connecting sockets */
	pcache_possibly_expired(now);	/* Expire pong cache */

	/*
	 * GUI update
	 */

	gui_update_global();
	gui_update_stats();

	/* Update for things that change slowly */
	if (main_slow_update++ > SLOW_UPDATE_PERIOD) {
		main_slow_update = 0;
		gui_update_config_port();		/* Show current IP:port if dynamic IP */
	}

	return TRUE;
}

gint main(gint argc, gchar ** argv)
{
	gint i;
	const gchar *menus[] = {
		"gnutellaNet",
		"Uploads",
		"Downloads",
		"Search",
		"  Monitor",
		"Config",
		NULL
	};
	gchar *titles[5];
	gchar mtmp[1024];
	gint optimal_width;

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

	setlocale(LC_TIME, "C");	/* strftime() must emit standard dates */

	/* Glade inits */

	gtk_set_locale();

	gtk_init(&argc, &argv);

	add_pixmap_directory(PACKAGE_DATA_DIR "/pixmaps");
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");

	main_window = create_main_window();

	create_popup_nodes();
	create_popup_hosts();
	create_popup_search();
	create_popup_monitor();
	create_popup_uploads();
	create_popup_dl_active();
	create_popup_dl_queued();

	gui_set_status(NULL);

	/* Our inits */

	init_constants();
	config_init();
	host_init();
	gmsg_init();
	bsched_init();
	network_init();
	routing_init();
	search_init();
	share_init();
	filters_init();
	download_init();
	autodownload_init();

	/* Some signal handlers */

	signal(SIGTERM, SIG_Handler);
	signal(SIGINT, SIG_Handler);
	signal(SIGPIPE, SIG_Ignore);		/* SIG_IGN -- running under debugger */

	/* Create the main listening socket */

	if (listen_port)
		s_listen = socket_listen(0, listen_port, GTA_TYPE_CONTROL);

	/* Final interface setup */

	optimal_width =
		gtk_clist_optimal_column_width(GTK_CLIST(clist_stats), 0);

	for (i = 0; i < 6; i++)
		gtk_clist_insert(GTK_CLIST(clist_menu), i, (gchar **) & menus[i]);
	gtk_clist_select_row(GTK_CLIST(clist_menu), 0, 0);

	gtk_widget_set_usize(sw_menu, optimal_width,
						 (clist_menu->style->font->ascent +
						  clist_menu->style->font->descent + 4) * 6);

	gtk_clist_column_titles_passive(GTK_CLIST(clist_nodes));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_uploads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_download_queue));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_monitor));

	gtk_clist_set_reorderable(GTK_CLIST(clist_download_queue), TRUE);

	titles[0] = NULL;

	for (i = 0; i < 3; i++)
		gtk_clist_append(GTK_CLIST(clist_connections), titles);
	for (i = 0; i < 4; i++)
		gtk_clist_append(GTK_CLIST(clist_stats), titles);

	gtk_widget_set_usize(sw_connections, optimal_width,
						 (clist_connections->style->font->ascent +
						  clist_connections->style->font->descent +
						  4) * 3);
	gtk_widget_set_usize(sw_stats, optimal_width,
						 (clist_stats->style->font->ascent +
						  clist_stats->style->font->descent + 4) * 4);

	gui_update_stats();

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

	gtk_widget_set_sensitive(popup_hosts_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_active_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_queued_title, FALSE);
	gtk_widget_set_sensitive(popup_monitor_title, FALSE);
	gtk_widget_set_sensitive(popup_nodes_title, FALSE);
	gtk_widget_set_sensitive(popup_uploads_title, FALSE);
	gtk_widget_set_sensitive(popup_search_title, FALSE);

	gtk_widget_show(main_window);		/* Display the main window */

	/* Setup the main timer */

	gtk_timeout_add(1000, (GtkFunction) main_timer, NULL);

	/* Okay, here we go */

	bsched_enable_all();
	gtk_main();

	return 0;
}

/* vi: set ts=4: */
