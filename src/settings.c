/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * gtk-gnutella configuration.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "settings.h"
#include "search.h"
#include "hosts.h"
#include "upload_stats.h"
#include "sockets.h"
#include "inet.h"

#define debug dbg

static gchar *config_file = "config_gnet";
static gchar *host_file = "hosts";
static gchar *ul_stats_file = "upload_stats";

static gchar *home_dir = NULL;
gchar *config_dir = NULL;

static prop_set_t *properties = NULL;

/* 
 * For backward compatibility these values are still read, but 
 * no longer written to the config file:
 *
 * Variable                    Changed at       New name
 * ----------------            ---------------- -------------
 * socksv5_user                0.90u 12/05/2002 socks_user
 * socksv5_pass                0.90u 12/05/2002 socks_pass
 * progressbar_bps_in_visible  0.90u 15/05/2002 progressbar_bws_in_visible
 * progressbar_bps_out_visible 0.90u 15/05/2002 progressbar_bws_out_visible
 * progressbar_bps_in_avg      0.90u 15/05/2002 progressbar_bws_in_avg
 * progressbar_bps_out_avg     0.90u 15/05/2002 progressbar_bws_out_avg
 */

static gchar cfg_tmp[4096];
static gchar *pidfile = "gtk-gnutella.pid";

static void settings_callbacks_init(void);
static void settings_callbacks_shutdown(void);


/* ----------------------------------------- */

/*
 * ensure_unicity
 *
 * Look for any existing PID file. If found, look at the pid recorded
 * there and make sure it has died. Abort operations if it hasn't...
 */
static void ensure_unicity(gchar *file)
{
	FILE *fd;
	pid_t pid = (pid_t) 0;
	gchar buf[16];

	fd = fopen(file, "r");
	if (fd == NULL)
		return;				/* Assume it's missing if can't be opened */

	buf[0] = '\0';
	fgets(buf, sizeof(buf) - 1, fd);
	sscanf(buf, "%d", &pid);
	fclose(fd);

	if (pid == 0)
		return;				/* Can't read it back correctly */

	/*
	 * Existence check relies on the existence of signal 0. The kernel
	 * won't actually send anything, but will perform all the existence
	 * checks inherent to the kill() syscall for us...
	 */

	if (-1 == kill(pid, 0)) {
		if (errno != ESRCH)
			g_warning("kill() return unexpected error: %s", g_strerror(errno));
		return;
	}

	fprintf(stderr,
		"You seem to have left another gtk-gnutella running (pid = %d)\n",
		pid);
	exit(1);
}

/*
 * save_pid
 *
 * Write our pid to the pidfile.
 */
static void save_pid(gchar *file)
{
	FILE *fd;

	fd = fopen(file, "w");

	if (fd == NULL) {
		g_warning("unable to create pidfile \"%s\": %s",
			file, g_strerror(errno));
		return;
	}

	fprintf(fd, "%d\n", (gint) getpid());

	if (0 != fclose(fd))
		g_warning("could not flush pidfile \"%s\": %s",
			file, g_strerror(errno));
}

/* ----------------------------------------- */

void settings_init(void)
{
    struct passwd *pwd = NULL;

    properties = gnet_prop_init();

	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	memset(guid, 0, sizeof(guid));

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		g_warning("can't find your home directory!");

	if (!config_dir) {
		if (home_dir) {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(cfg_tmp);
		} else
			g_warning("no home directory: prefs will not be saved!");
	}

	if (config_dir && !is_directory(config_dir)) {
		g_warning("creating configuration directory '%s'\n", config_dir);

		if (mkdir(config_dir, 0755) == -1) {
			g_warning("mkdir(%s) failed: %s\n\n",
				config_dir, g_strerror(errno));
			g_free(config_dir);
			config_dir = NULL;
		}
	}

	if (config_dir) {
		/* Ensure we're the only instance running */

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, pidfile);
		ensure_unicity(cfg_tmp);
		save_pid(cfg_tmp);

		/* Parse the configuration */
        prop_load_from_file(properties, config_dir, config_file);
    
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, host_file);
		hosts_read_from_file(cfg_tmp, TRUE);	/* Loads the catched hosts */

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s",
			config_dir, ul_stats_file);
		ul_stats_load_history(cfg_tmp);		/* Loads the upload statistics */
	}

	/* watch for filter_file defaults */

	if (hard_ttl_limit < max_ttl) {
		hard_ttl_limit = max_ttl;
		g_warning("hard_ttl_limit was too small, adjusted to %u",
			hard_ttl_limit);
	}

	/* Flow control depends on this being not too small */
	if (node_sendqueue_size < 1.5 * settings_max_msg_size()) {
		node_sendqueue_size = (guint32) (1.5 * settings_max_msg_size());
		g_warning("node_sendqueue_size was too small, adjusted to %u",
			node_sendqueue_size);
	}

    settings_callbacks_init();
}

guint32 *settings_parse_array(gchar * str, guint32 n)
{
	/* Parse comma delimited settings */

	static guint32 array[10];
	gchar **h = g_strsplit(str, ",", n + 1);
	guint32 *r = array;
	gint i;

	for (i = 0; i < n; i++) {
		if (!h[i]) {
			r = NULL;
			break;
		}
		array[i] = atol(h[i]);
	}

	g_strfreev(h);
	return r;
}

void settings_hostcache_save(void)
{
	/* Save the catched hosts & upload history */

	if (hosts_idle_func) {
		g_warning("exit() while still reading the hosts file, "
			"catched hosts not saved !\n");
	} else {
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, host_file);
		hosts_write_to_file(cfg_tmp);
	}
}

/*
 * settings_upload_stats_save:
 *
 * Save upload statistics.
 */
static void settings_upload_stats_save(void)
{
	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, ul_stats_file);
	ul_stats_dump_history(cfg_tmp, TRUE);
}

/*
 * settings_remove_pidfile:
 *
 * Remove pidfile.
 */
static void settings_remove_pidfile(void)
{
	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, pidfile);

	if (-1 == unlink(cfg_tmp))
		g_warning("could not remove pidfile \"%s\": %s",
			cfg_tmp, g_strerror(errno));
}

/*
 * settings_ip_changed:
 *
 * This routine is called when we determined that our IP was no longer the
 * one we computed.  We base this on some headers sent back when we handshake
 * with other nodes, and as a result, cannot trust the information.
 *
 * What we do henceforth is trust 3 successive indication that our IP changed,
 * provided we get the same information each time.
 *
 *		--RAM, 13/01/2002
 */
void settings_ip_changed(guint32 new_ip)
{
	static guint32 last_ip_seen = 0;
	static gint same_ip_count = 0;

	g_assert(!force_local_ip);		/* Must be called when IP isn't forced */

	if (new_ip != last_ip_seen) {
		last_ip_seen = new_ip;
		same_ip_count = 1;
		return;
	}

	if (++same_ip_count < 3)
		return;

	last_ip_seen = 0;
	same_ip_count = 0;

	if (new_ip == local_ip)
		return;

    gnet_prop_set_guint32(PROP_LOCAL_IP, &new_ip, 0, 1);
}

/*
 * settings_max_msg_size:
 *
 * Maximum message payload size we are configured to handle.
 */
guint32 settings_max_msg_size(void)
{
	/*
	 * Today, they are fixed at config time, but they will be set via
	 * GUI tomorrow, so the max size is not fixed in time.
	 *				--RAM, 15/09/2001
	 */

	guint32 maxsize;

	maxsize = MAX(search_queries_kick_size, search_answers_kick_size);
	maxsize = MAX(maxsize, other_messages_kick_size);

	return maxsize;
}

void settings_shutdown(void)
{
    settings_callbacks_shutdown();

    prop_save_to_file(properties, config_dir, config_file);

	settings_hostcache_save();
	settings_upload_stats_save();
	settings_remove_pidfile();
}

/*
 * settings_close:
 *
 * Finally free all memory allocated. Call after settings_shutdown.
 */
void settings_close(void)
{
    gnet_prop_shutdown();

	if (home_dir)
		g_free(home_dir);
	if (config_dir)
		g_free(config_dir);
}

void gnet_get_bw_stats(gnet_bw_stats_t *s)
{
    g_assert(s != NULL);

    s->gnet_in_enabled  = bws_gin_enabled;
    s->gnet_in          = bsched_bps(bws.gin);
    s->gnet_in_avg      = bsched_avg_bps(bws.gin);
    s->gnet_in_limit    = bws.gin->bw_per_second;

    s->gnet_out_enabled = bws_gout_enabled;
    s->gnet_out         = bsched_bps(bws.gout);
    s->gnet_out_avg     = bsched_avg_bps(bws.gout);
    s->gnet_out_limit   = bws.gout->bw_per_second;

    s->http_in_enabled  = bws_in_enabled;
    s->http_in          = bsched_bps(bws.in);
    s->http_in_avg      = bsched_avg_bps(bws.in);
    s->http_in_limit    = bws.in->bw_per_second;

    s->http_out_enabled = bws_out_enabled;
    s->http_out         = bsched_bps(bws.out);
    s->http_out_avg     = bsched_avg_bps(bws.out);
    s->http_out_limit   = bws.out->bw_per_second;
}

/***
 *** Callbacks
 ***/
static gboolean up_connections_changed(property_t prop)
{
    guint32 up_connections;
    guint32 max_connections;
    
    gnet_prop_get_guint32(PROP_UP_CONNECTIONS, &up_connections, 0, 1);
    gnet_prop_get_guint32(PROP_MAX_CONNECTIONS, &max_connections, 0, 1);

    if (up_connections > max_connections)
        gnet_prop_set_guint32(PROP_MAX_CONNECTIONS, &up_connections, 0, 1);

    return FALSE;
}

static gboolean max_connections_changed(property_t prop)
{
    guint32 up_connections;
    guint32 max_connections;
    
    gnet_prop_get_guint32(PROP_UP_CONNECTIONS, &up_connections, 0, 1);
    gnet_prop_get_guint32(PROP_MAX_CONNECTIONS, &max_connections, 0, 1);

    if (up_connections > max_connections)
        gnet_prop_set_guint32(PROP_UP_CONNECTIONS, &max_connections, 0, 1);

    return FALSE;
}

static gboolean max_hosts_cached_changed(property_t prop)
{
    guint32 max_hosts_cached;
    guint32 hosts_in_catcher;

    gnet_prop_get_guint32(PROP_MAX_HOSTS_CACHED, &max_hosts_cached, 0, 1);
    gnet_prop_get_guint32(PROP_HOSTS_IN_CATCHER, &hosts_in_catcher, 0, 1);

    if (max_hosts_cached < hosts_in_catcher)
        host_prune_cache();

    return FALSE;
}

static gboolean listen_port_changed(property_t prop)
{
	static guint32 old_listen_port = 0;
    guint32 listen_port;

    gnet_prop_get_guint32(prop, &listen_port, 0, 1);

	/*
	 * If port did not change values, do nothing.
	 */

	if (listen_port == old_listen_port)
		return FALSE;

	old_listen_port = listen_port;
	inet_firewalled();			/* Assume we're firewalled on port change */

    /*
     * Close old port.
     */
    if (s_listen)
        socket_destroy(s_listen);

    /*
     * If the new port != 0, open the new port
     */
	if (listen_port != 0)
		s_listen = socket_listen(0, listen_port, SOCK_TYPE_CONTROL);
    else
		s_listen = NULL;

    /*
     * If socket allocation failed, reset the property
     */
    if ((s_listen == NULL) && (listen_port != 0)) {
        old_listen_port = listen_port = 0;
        gnet_prop_set_guint32(prop, &listen_port, 0, 1);
        return TRUE;
    }

    return FALSE;
}

static gboolean bw_http_in_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    if (val)
        bsched_enable(bws.in);
    else
        bsched_disable(bws.in);

    return FALSE;
}

static gboolean bw_http_out_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    if (val)
        bsched_enable(bws.out);
    else
        bsched_disable(bws.out);

    return FALSE;
}

static gboolean bw_gnet_in_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    if (val)
        bsched_enable(bws.gin);
    else
        bsched_disable(bws.gin);

    return FALSE;
}

static gboolean bw_gnet_out_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    if (val)
        bsched_enable(bws.gout);
    else
        bsched_disable(bws.gout);

    return FALSE;
}

static gboolean node_sendqueue_size_changed(property_t prop)
{
    guint32 val;
    guint32 min = 1.5 * settings_max_msg_size();

    gnet_prop_get_guint32(PROP_NODE_SENDQUEUE_SIZE, &val, 0, 1);

    if (val < min) {
        gnet_prop_set_guint32(PROP_NODE_SENDQUEUE_SIZE, &min, 0, 1);
        return TRUE;
    }
    
    return FALSE;
}

static gboolean scan_extensions_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    parse_extensions(s);

    g_free(s);

    return FALSE;
}

static gboolean save_file_path_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    if (!is_directory(s)) {
        prop_def_t *def = gnet_prop_get_def(prop);
        gchar* path = (home_dir) ? (home_dir) : *def->data.string.def;
    
        g_warning(
            "save_file_path: directory %s is not available, "
            "using %s instead", s, path); 

        gnet_prop_set_string(prop, path);

        prop_free_def(def);

        return TRUE;
    }

    if (s)
        g_free(s);

    return FALSE;
}

static gboolean move_file_path_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    if (!is_directory(s)) {
        gchar *path = gnet_prop_get_string(PROP_SAVE_FILE_PATH, NULL, 0);

        g_warning(
            "move_file_path: directory %s is not available, "
            "using %s instead", s, path); 

        gnet_prop_set_string(prop, path);

        g_free(path);

        return TRUE;
    }
    
    if (s)
        g_free(s);

    return FALSE;
}

static gboolean shared_dirs_paths_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    // FIXME: should give notification or reset prop if parsing fails
    shared_dirs_parse(s);

    g_free(s);

    return FALSE;
}

static gboolean local_netmasks_string_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    parse_netmasks(s);

    g_free(s);

    return FALSE;
}

static gboolean hard_ttl_limit_changed(property_t prop)
{
    guint32 hard_ttl_limit;
    guint32 max_ttl;

    gnet_prop_get_guint32(PROP_HARD_TTL_LIMIT, &hard_ttl_limit, 0, 1);
    gnet_prop_get_guint32(PROP_MAX_TTL, &max_ttl, 0, 1);

    if (hard_ttl_limit < max_ttl)
        gnet_prop_set_guint32(PROP_MAX_TTL, &hard_ttl_limit, 0, 1);

    return FALSE;
}

static gboolean max_ttl_changed(property_t prop)
{
    guint32 hard_ttl_limit;
    guint32 max_ttl;

    gnet_prop_get_guint32(PROP_HARD_TTL_LIMIT, &hard_ttl_limit, 0, 1);
    gnet_prop_get_guint32(PROP_MAX_TTL, &max_ttl, 0, 1);

    if (hard_ttl_limit < max_ttl)
        gnet_prop_set_guint32(PROP_HARD_TTL_LIMIT, &max_ttl, 0, 1);

    return FALSE;
}

static gboolean bw_http_in_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32(prop, &val, 0, 1);
    bsched_set_bandwidth(bws.in, val);
    
    return FALSE;
}

static gboolean bw_http_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32(prop, &val, 0, 1);
    bsched_set_bandwidth(bws.out, val);
    
    return FALSE;
}

static gboolean bw_gnet_in_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32(prop, &val, 0, 1);
    bsched_set_bandwidth(bws.gin, val);
    
    return FALSE;
}

static gboolean bw_gnet_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32(prop, &val, 0, 1);
    bsched_set_bandwidth(bws.gout, val);
    
    return FALSE;
}

/***
 *** Property-to-callback map
 ***/

typedef struct prop_map {
    property_t prop;            /* property handle */
    prop_changed_listener_t cb; /* callback function */
    gboolean init;              /* init widget with current value */
} prop_map_t;

#define IGNORE NULL

static prop_map_t property_map[] = {
    {
        PROP_NODE_SENDQUEUE_SIZE,
        node_sendqueue_size_changed,
        TRUE
    },
    {
        PROP_SEARCH_QUERIES_KICK_SIZE,
        node_sendqueue_size_changed,
        TRUE
    },
    {
        PROP_SEARCH_ANSWERS_KICK_SIZE,
        node_sendqueue_size_changed,
        TRUE
    },
    { 
        PROP_UP_CONNECTIONS, 
        up_connections_changed, 
        TRUE 
    },
    {
        PROP_MAX_CONNECTIONS, 
        max_connections_changed, 
        TRUE 
    },
    {
        PROP_MAX_HOSTS_CACHED, 
        max_hosts_cached_changed, 
        TRUE 
    },
    {
        PROP_LISTEN_PORT, 
        listen_port_changed, 
        TRUE
    },
    {
        PROP_BW_HTTP_IN_ENABLED, 
        bw_http_in_enabled_changed, 
        FALSE
    },
    {
        PROP_BW_HTTP_OUT_ENABLED, 
        bw_http_out_enabled_changed, 
        FALSE
    },
    {
        PROP_BW_GNET_IN_ENABLED, 
        bw_gnet_in_enabled_changed, 
        FALSE
    },
    {
        PROP_BW_GNET_OUT_ENABLED, 
        bw_gnet_out_enabled_changed, 
        FALSE
    },
    {
        PROP_SCAN_EXTENSIONS,
        scan_extensions_changed,
        TRUE
    },
    {
        PROP_SAVE_FILE_PATH,
        save_file_path_changed,
        TRUE
    },
    {
        PROP_MOVE_FILE_PATH,
        move_file_path_changed,
        TRUE
    },
    {
        PROP_SHARED_DIRS_PATHS,
        shared_dirs_paths_changed,
        TRUE
    },
    {
        PROP_LOCAL_NETMASKS_STRING,
        local_netmasks_string_changed,
        TRUE
    },
    {
        PROP_HARD_TTL_LIMIT,
        hard_ttl_limit_changed,
        TRUE
    },
    {
        PROP_MAX_TTL,
        max_ttl_changed,
        TRUE
    },
    {
        PROP_BW_HTTP_IN,
        bw_http_in_changed,
        FALSE
    },
    {
        PROP_BW_HTTP_OUT,
        bw_http_out_changed,
        FALSE
    },
    {
        PROP_BW_GNET_IN,
        bw_gnet_in_changed,
        FALSE
    },
    {
        PROP_BW_GNET_OUT,
        bw_gnet_out_changed,
        FALSE
    }
};

/***
 *** Control functions
 ***/

#define PROPERTY_MAP_SIZE (sizeof(property_map) / sizeof(property_map[0]))

static gboolean init_list[GNET_PROPERTY_NUM];

static void settings_callbacks_init(void)
{
    gint n;

    for (n = 0; n < GNET_PROPERTY_NUM; n ++)
        init_list[n] = FALSE;

    if (debug >= 2) {
        printf("settings_callbacks_init: property_map size: %u\n", 
            PROPERTY_MAP_SIZE);
    }

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        property_t prop = property_map[n].prop;
        guint32 idx   = prop-GNET_PROPERTY_MIN;

        if (!init_list[idx])
           init_list[idx] = TRUE;
        else
            g_warning("settings_callbacks_init:" 
                " property %d already mapped", n);

        if (property_map[n].cb != IGNORE) {
            gnet_prop_add_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init);
        } else if (debug >= 10) {
            prop_def_t *def = gnet_prop_get_def(prop);
            printf("settings_callbacks_init: "
                "property ignored: %s\n", def->name);
            prop_free_def(def);
        }
    }

    if (debug >= 1) {
        for (n = 0; n < GNET_PROPERTY_NUM; n++) {
            if (!init_list[n]) {
                prop_def_t *def = gnet_prop_get_def(n+GNET_PROPERTY_MIN);
                printf("settings_callbacks_init: "
                    "unmapped property: %s\n", def->name); 
                prop_free_def(def);
            }
        }
    }
}

static void settings_callbacks_shutdown(void)
{
    gint n;

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        if (property_map[n].cb != IGNORE) {
            gnet_prop_remove_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb);
        }
    }
}

 

/* vi: set ts=4: */
