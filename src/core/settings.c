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
 * @ingroup core
 * @file
 *
 * Gtk-Gnutella configuration.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "common.h"

#ifdef I_NETDB
#include <netdb.h>
#endif

#include "lib/eval.h"

#include "settings.h"
#include "search.h"
#include "hosts.h"
#include "upload_stats.h"
#include "sockets.h"
#include "inet.h"
#include "hcache.h"
#include "downloads.h"
#include "share.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/core/main.h"		/* For debugging() */
#include "if/core/net_stats.h"

#include "if/bridge/c2ui.h"

#include "lib/bit_array.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$");

#define debug dbg

static const gchar config_file[] = "config_gnet";
static const gchar ul_stats_file[] = "upload_stats";

#define PID_FILE_MODE	(S_IRUSR | S_IWUSR) /* 0600 */
#define CONFIG_DIR_MODE /* 0750 */ \
    (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP)

static gchar *home_dir = NULL;
static gchar *config_dir = NULL;

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

static const gchar pidfile[] = "gtk-gnutella.pid";

static void settings_callbacks_init(void);
static void settings_callbacks_shutdown(void);
static void update_uptimes(void);

/* ----------------------------------------- */

/**
 * @return the currently used local listening address.
 */
host_addr_t
listen_addr(void)
{
	return force_local_ip ? forced_local_ip : local_ip;
}

/**
 * @return the currently used local listening address.
 */
host_addr_t
listen_addr6(void)
{
	return force_local_ip6 ? forced_local_ip6 : local_ip6;
}

gboolean
is_my_address(const host_addr_t addr, guint16 port)
{
	return port == listen_port && (
		host_addr_equal(addr, listen_addr()) ||
		host_addr_equal(addr, listen_addr6())
	);
}


/**
 * Look for any existing PID file. If found, look at the pid recorded
 * there and make sure it has died. Abort operations if it hasn't...
 *
 * @returns -1 on failure, the file descriptor of the pidfile otherwise.
 */
static gint
ensure_unicity(const gchar *file)
{
	gint fd, e;
	gboolean locking_failed;

	g_assert(file);

	fd = file_create(file, O_RDWR, PID_FILE_MODE);
	if (-1 == fd) {
		e = errno;
		g_warning("could not access \"%s\": %s", file, g_strerror(e));
		return -1;
	}

/* FIXME: These might be enums, a compile-time check would be better */
#if defined(F_SETLK) && defined(F_WRLCK)
	{
		static const struct flock zero_flock;
		struct flock fl;

		fl = zero_flock;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		/* l_start and l_len are zero, which means the whole is locked */

		locking_failed = -1 == fcntl(fd, F_SETLK, &fl);
		if (locking_failed) {
			e = errno;

			locking_failed = TRUE;
			g_warning("fcntl(%d, F_SETLK, ...) failed for \"%s\": %s",
				fd, file, g_strerror(e));

			/*
			 * Use F_GETLK to determing the PID of the process, the
			 * reinitialization of "fl" might be unnecessary but who
			 * knows.
			 */
			fl = zero_flock;
			fl.l_type = F_WRLCK;
			fl.l_whence = SEEK_SET;

			if (-1 != fcntl(fd, F_GETLK, &fl)) {
				g_warning("another gtk-gnutella process seems to "
					"be still running (pid=%lu)", (gulong) fl.l_pid);
			}
		}
	}
#else
	locking_failed = TRUE;
	errno = 0;
#endif /* F_SETLK && F_WRLCK */

	if (!locking_failed)
		goto done;

	if (is_temporary_error(e) || EACCES == e)
		goto failed;		/* The file appears to be locked */

	/* Maybe F_SETLK is not supported by the OS or filesystem,
	 * fall back to weaker PID locking */
	{
		ssize_t r;
		gchar buf[33];

		r = read(fd, buf, sizeof buf - 1);
		e = errno;

		if ((ssize_t) -1 == r) {
			/* This would be odd */
			g_warning("could not read pidfile \"%s\": %s", file, g_strerror(e));
			goto failed;
		}

		/* Check the PID in the file */
		{
			guint64 u;
			gint error;

			g_assert(r >= 0 && (size_t) r < sizeof buf);
			buf[r] = '\0';

			u = parse_uint64(buf, NULL, 10, &error);

			/* If the pidfile seems to be corrupt, ignore it */
			if (!error && u > 1) {
				pid_t pid = u;

				if (0 == kill(pid, 0)) {
					g_warning("another gtk-gnutella process seems to "
						"be still running (pid=%lu)", (gulong) pid);
					goto failed;
				}
			}
		}
	}

done:
	/* Keep the fd open, otherwise the lock is lost */
	return fd;

failed:
	close(fd);
	return -1;
}

/**
 * Write our pid to the pidfile.
 */
static void
save_pid(gint fd)
{
	size_t len;
	gchar buf[32];

	g_assert(-1 != fd);

	gm_snprintf(buf, sizeof buf, "%lu\n", (gulong) getpid());
	len = strlen(buf);

	if (-1 == ftruncate(fd, 0))	{
		g_warning("ftruncate() failed for pidfile: %s", g_strerror(errno));
		return;
	}

	if (0 != lseek(fd, 0, SEEK_SET))	{
		g_warning("lseek() failed for pidfile: %s", g_strerror(errno));
		return;
	}

	if (len != (size_t) write(fd, buf, len))
		g_warning("could not flush pidfile: %s", g_strerror(errno));
}

/* ----------------------------------------- */

/**
 * @return the amount of physical RAM in KB, or zero in case of failure
 */
static guint64
settings_getphysmemsize(void)
#if defined (_SC_PHYS_PAGES)
{
	size_t pagesize = compat_pagesize();
	glong pages;

	errno = 0;
	pages = sysconf(_SC_PHYS_PAGES);
	if ((glong) -1 == pages && 0 != errno) {
		g_warning("sysconf(_SC_PHYS_PAGES) failed: %s", g_strerror(errno));
		return 0;
	}
	return (pagesize >> 10) * (gulong) pages;
}
#elif defined (HAS_SYSCTL) && defined (CTL_HW) && defined (HW_USERMEM64)
{
/* There's also HW_PHYSMEM but HW_USERMEM is better for our needs. */
	int mib[2] = { CTL_HW, HW_USERMEM64 };
	guint64 amount = 0;
	size_t len = sizeof amount;

	if (-1 == sysctl(mib, 2, &amount, &len, NULL, 0)) {
		g_warning(
			"settings_getphysmemsize: sysctl() for HW_USERMEM64 failed: %s",
			g_strerror(errno));
		return 0;
	}

	return amount / 1024;
}
#elif defined (HAS_SYSCTL) && defined (CTL_HW) && defined (HW_USERMEM)
{
/* There's also HW_PHYSMEM but HW_USERMEM is better for our needs. */
	int mib[2] = { CTL_HW, HW_USERMEM };
	guint32 amount = 0;
	size_t len = sizeof amount;

	if (-1 == sysctl(mib, 2, &amount, &len, NULL, 0)) {
		g_warning(
			"settings_getphysmemsize: sysctl() for HW_USERMEM failed: %s",
			g_strerror(errno));
		return 0;
	}

	return amount / 1024;
}
#elif defined (HAS_GETINVENT)
{
	inventory_t *inv;
	long physmem = 0;

	if (-1 == setinvent()) {
		g_warning("settings_getphysmemsize: setinvent() failed: %s",
			g_strerror(errno));
		return 0;
	}

	errno = 0;
	while ((inv = getinvent()) != NULL) {
		if (inv->inv_class == INV_MEMORY && inv->inv_type == INV_MAIN_MB) {
			physmem = inv->inv_state;
			break;
		}
	}
	endinvent();

	if (-1L == physmem && 0 != errno) {
		g_warning("settings_getphysmemsize: "
			"getinvent() for INV_MEMORY faild: %s", g_strerror(errno));
		return 0;
	}

	return physmem * 1024;
}
#else /* ! _SC_PHYS_PAGES && ! HAS_SYSCTL && ! HAS_GETINVENT */
{
	g_warning("Unable to determine amount of physical RAM");
	return 0;
}
#endif /* _SC_PHYS_PAGES */

void
settings_init(void)
{
	guint64 memory = settings_getphysmemsize();
	guint64 amount = memory; 
	char *path = NULL;
	guint max_fd;

#ifdef RLIMIT_DATA 
	{
		struct rlimit lim;
	
		if (-1 != getrlimit(RLIMIT_DATA, &lim)) {
			guint32 maxdata = lim.rlim_cur >> 10;
			amount = MIN(amount, maxdata);		/* For our purposes */
		}
	}
#endif /* RLIMIT_DATA */

    properties = gnet_prop_init();
	max_fd = compat_max_fd();
	
	gnet_prop_set_guint32_val(PROP_SYS_NOFILE, max_fd);
	gnet_prop_set_guint64_val(PROP_SYS_PHYSMEM, amount);

	memset(deconstify_gchar(servent_guid), 0, sizeof servent_guid);
	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	home_dir = g_strdup(eval_subst("~"));
	if (!home_dir)
		g_warning(_("Can't find your home directory!"));

	if (!config_dir && home_dir)
		config_dir = make_pathname(home_dir, ".gtk-gnutella");

	if (NULL == config_dir || '\0' == config_dir[0])
		goto no_config_dir;

	if (!is_directory(config_dir)) {
		g_warning(_("creating configuration directory \"%s\""), config_dir);
		if (-1 == compat_mkdir(config_dir, CONFIG_DIR_MODE)) {
			g_warning("mkdir(\"%s\") failed: \"%s\"",
				config_dir, g_strerror(errno));
			goto no_config_dir;
		}
	}

	g_assert(NULL != config_dir);
	/* Ensure we're the only instance running */

	path = make_pathname(config_dir, pidfile);
	{
		gint fd;

		if (-1 == (fd = ensure_unicity(path))) {
			g_warning(
				_("You seem to have left another gtk-gnutella running\n"));
			exit(EXIT_FAILURE);
		}
		save_pid(fd);
		/* The file descriptor must be kept open */
	}
	G_FREE_NULL(path);

		/* Parse the configuration */
	prop_load_from_file(properties, config_dir, config_file);

	if (debugging(0)) {
		g_message("detected amount of physical RAM: %s",
			short_kb_size(memory, display_metric_units));
		g_message("process can use at maximum: %s",
			short_kb_size(amount, display_metric_units));
		g_message("process can use %u file descriptors", max_fd);
		g_message("max I/O vector size is %d items", MAX_IOV_COUNT);
	}

	path = make_pathname(config_dir, ul_stats_file);
	upload_stats_load_history(path);	/* Loads the upload statistics */
	G_FREE_NULL(path);


	/* watch for filter_file defaults */

	if (hard_ttl_limit < max_ttl) {
		*(guint32 *) &hard_ttl_limit = max_ttl;
		g_warning("hard_ttl_limit was too small, adjusted to %u",
			hard_ttl_limit);
	}

	/* Flow control depends on this being not too small */
	if (node_sendqueue_size < 1.5 * settings_max_msg_size()) {
		*(guint32 *) &node_sendqueue_size =
			(guint32) (1.5 * settings_max_msg_size());
		g_warning("node_sendqueue_size was too small, adjusted to %u",
			node_sendqueue_size);
	}

    settings_callbacks_init();
	return;

no_config_dir:
	g_warning(_("Cannot proceed without valid configuration directory"));
	exit(EXIT_FAILURE); /* g_error() would dump core, that's ugly. */
}

/**
 * Get the config directory
 */
const gchar *
settings_config_dir(void)
{
	g_assert(NULL != config_dir);
	return (const gchar *) config_dir;
}

/**
 * Gets the home dir.
 */
const gchar *
settings_home_dir(void)
{
	g_assert(NULL != home_dir);
	return (const gchar *) home_dir;
}

/**
 * @return The "net" parameter to use for name_to_host_addr() according
 *         to the current configuration.
 */
enum net_type
settings_dns_net(void)
{
	switch (network_protocol) {
	case NET_USE_BOTH: return NET_TYPE_NONE;
	case NET_USE_IPV4: return NET_TYPE_IPV4;
	case NET_USE_IPV6:
#ifdef USE_IPV6
	return NET_TYPE_IPV6;
#else
	return NET_TYPE_NONE;
#endif /* USE_IPV6 */
	}
	g_assert_not_reached();
	return NET_TYPE_NONE;
}

/**
 * Remove pidfile.
 */
static void
settings_remove_pidfile(void)
{
	gchar *path;

	path = make_pathname(config_dir, pidfile);
	g_return_if_fail(NULL != path);
	if (-1 == unlink(path))
		g_warning("could not remove pidfile \"%s\": %s",
			path, g_strerror(errno));
	G_FREE_NULL(path);
}

static void
addr_ipv4_changed(const host_addr_t new_addr, const host_addr_t peer)
{
	static guint same_addr_count = 0;
	static host_addr_t peers[3], last_addr_seen;
	guint i;

	g_return_if_fail(!force_local_ip); /* Must be called when IP isn't forced */
	g_return_if_fail(NET_TYPE_IPV4 == host_addr_net(new_addr));
	g_return_if_fail(NET_TYPE_IPV4 == host_addr_net(peer));

	/*
	 * Accept updates for private addresses only from peer in the same /16
	 * network; addresses are in host byte order.
	 */
	if (
		is_private_addr(new_addr) &&
		is_private_addr(peer) &&
		!host_addr_matches(peer, new_addr, 16) /* CIDR /16 */
	) {
		return;
	}

	for (i = 0; i < G_N_ELEMENTS(peers); i++) {
		if (host_addr_matches(peer, new_addr, 16)) /* CIDR /16 */
			return;
	}

	if (!host_addr_equal(new_addr, last_addr_seen)) {
		last_addr_seen = new_addr;
		same_addr_count = 1;
		peers[0] = peer;
		return;
	}

	g_assert(same_addr_count > 0 && same_addr_count < G_N_ELEMENTS(peers));
	peers[same_addr_count] = peer;

	if (++same_addr_count < G_N_ELEMENTS(peers))
		return;

	last_addr_seen = zero_host_addr;
	same_addr_count = 0;
	for (i = 0; i < G_N_ELEMENTS(peers); i++) {
		peers[i] = zero_host_addr;
	}

	if (host_addr_equal(new_addr, local_ip))
		return;

    gnet_prop_set_ip_val(PROP_LOCAL_IP, new_addr);
}

static void
addr_ipv6_changed(const host_addr_t new_addr, const host_addr_t peer)
{
	static guint same_addr_count = 0;
	static host_addr_t peers[3], last_addr_seen;
	guint i;

	g_return_if_fail(!force_local_ip6); /* Must not be called if IP is forced */
	g_return_if_fail(NET_TYPE_IPV6 == host_addr_net(new_addr));
	g_return_if_fail(NET_TYPE_IPV6 == host_addr_net(peer));

	/*
	 * Accept updates for private addresses only from peer in the same /64
	 * network; addresses are in host byte order.
	 */
	if (
		is_private_addr(new_addr) &&
		is_private_addr(peer) &&
		!host_addr_matches(peer, new_addr, 64) /* CIDR /64 */
	) {
		return;
	}

	for (i = 0; i < G_N_ELEMENTS(peers); i++) {
		if (host_addr_matches(peer, new_addr, 64)) /* CIDR /64 */
			return;
	}

	if (!host_addr_equal(new_addr, last_addr_seen)) {
		last_addr_seen = new_addr;
		same_addr_count = 1;
		peers[0] = peer;
		return;
	}

	g_assert(same_addr_count > 0 && same_addr_count < G_N_ELEMENTS(peers));
	peers[same_addr_count] = peer;

	if (++same_addr_count < G_N_ELEMENTS(peers))
		return;

	last_addr_seen = zero_host_addr;
	same_addr_count = 0;
	for (i = 0; i < G_N_ELEMENTS(peers); i++) {
		peers[i] = zero_host_addr;
	}

	if (host_addr_equal(new_addr, local_ip6))
		return;

    gnet_prop_set_ip_val(PROP_LOCAL_IP6, new_addr);
}


/**
 * This routine is called when we determined that our IP was no longer the
 * one we computed.
 *
 * We base this on some headers sent back when we handshake with other nodes,
 * and as a result, cannot trust the information.
 *
 * What we do henceforth is trust 3 successive indication that our IP changed,
 * provided we get the same information each time.
 *
 *		--RAM, 13/01/2002
 *
 * @param `new_addr' the newly suggested address.
 * @param `peer' the IP address of peer which reported the new IP address.
 *
 * There must be 3 peers from 3 different /16 networks before a change is
 * accepted. Otherwise, it would be very easy to confuse GTKG by connecting
 * 3 times in a row and submitting a *wrong* IP address.
 *
 *		--cbiere, 2004-08-01
 */
void
settings_addr_changed(const host_addr_t new_addr, const host_addr_t peer)
{
	g_assert(is_host_addr(new_addr)); /* The new IP must be valid */
	g_assert(is_host_addr(peer)); /* The peer's IP must be valid */

	if (!host_addr_is_routable(new_addr) || !host_addr_is_routable(peer))
		return;

	/*
	 * Don't accept updates for private addresses from non-private addresses
	 * and vice-versa.
	 */
	if (is_private_addr(new_addr) ^ is_private_addr(peer))
		return;

	if (host_addr_net(new_addr) != host_addr_net(peer))
		return;

	switch (host_addr_net(new_addr)) {
	case NET_TYPE_IPV4:
		addr_ipv4_changed(new_addr, peer);
		break;
	case NET_TYPE_IPV6:
		addr_ipv6_changed(new_addr, peer);
		break;
	case NET_TYPE_NONE:
		break;
	}
}

/**
 * Maximum message payload size we are configured to handle.
 */
guint32
settings_max_msg_size(void)
{
	/*
	 * Today, they are fixed at config time, but they will be set via
	 * GUI tomorrow, so the max size is not fixed in time.
	 *				--RAM, 15/09/2001
	 *
	 * They can be changed via the GUI as of today...
	 *				-- RAM, 24/12/2003
	 */

	guint32 maxsize;

	maxsize = MAX(search_queries_kick_size, search_answers_kick_size);
	maxsize = MAX(maxsize, other_messages_kick_size);

	return maxsize;
}

/**
 * Ask them to set a property to be able to run.
 */
void
settings_ask_for_property(const gchar *name, const gchar *value)
{
	fprintf(stderr, "\n*** ANCIENT VERSION DETECTED! ***\n\n");
	fprintf(stderr,
		"Sorry, this program is too ancient to run without\n"
		"an explicit user action: If it's not possible to upgrade\n"
		"you may edit the file\n\n"
		"\t%s%s%s\n\n"
		"and set the variable \"%s\" to\n\"%s\".\n\n"
		"You will then be able to run this version forever, but\n"
		"please consider upgrading, as Gnutella is an evolving\n"
		"network in which ancient software is less useful or even\n"
		"harmful!\n\n",
		config_dir, G_DIR_SEPARATOR_S, config_file, name, value);
	fprintf(stderr, "*** EXITING ***\n\n");
	exit(EXIT_FAILURE);
}

/**
 * Called at exit time to flush the property files.
 */
void
settings_shutdown(void)
{
	update_uptimes();
    settings_callbacks_shutdown();

    prop_save_to_file(properties, config_dir, config_file);
}

/**
 * Save settings if dirty.
 */
void
settings_save_if_dirty(void)
{
    prop_save_to_file_if_dirty(properties, config_dir, config_file);
}

/**
 * Finally free all memory allocated. Call after settings_shutdown.
 */
void
settings_close(void)
{
	settings_remove_pidfile();
    gnet_prop_shutdown();

	G_FREE_NULL(home_dir);
	G_FREE_NULL(config_dir);
}

void
gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *s)
{
    g_assert(s != NULL);

    switch (type) {
    case BW_GNET_IN:
        s->enabled  = bws_gin_enabled;
        s->current  = bsched_bps(bws.gin);
        s->average  = bsched_avg_bps(bws.gin);
        s->limit    = bws.gin->bw_per_second;
        break;
    case BW_GNET_OUT:
        s->enabled  = bws_gout_enabled;
        s->current  = bsched_bps(bws.gout);
        s->average  = bsched_avg_bps(bws.gout);
        s->limit    = bws.gout->bw_per_second;
        break;
    case BW_GNET_UDP_IN:
        s->enabled  = bws_gin_enabled;
        s->current  = bsched_bps(bws.gin_udp);
        s->average  = bsched_avg_bps(bws.gin_udp);
        s->limit    = bws.gin_udp->bw_per_second;
        break;
    case BW_GNET_UDP_OUT:
        s->enabled  = bws_gout_enabled;
        s->current  = bsched_bps(bws.gout_udp);
        s->average  = bsched_avg_bps(bws.gout_udp);
        s->limit    = bws.gout_udp->bw_per_second;
        break;
    case BW_HTTP_IN:
        s->enabled  = bws_in_enabled;
        s->current  = bsched_bps(bws.in);
        s->average  = bsched_avg_bps(bws.in);
        s->limit    = bws.in->bw_per_second;
        break;
    case BW_HTTP_OUT:
        s->enabled  = bws_out_enabled;
        s->current  = bsched_bps(bws.out);
        s->average  = bsched_avg_bps(bws.out);
        s->limit    = bws.out->bw_per_second;
        break;
    case BW_LEAF_IN:
        s->enabled  = bws_glin_enabled;
        s->current  = bsched_bps(bws.glin);
        s->average  = bsched_avg_bps(bws.glin);
        s->limit    = bws.glin->bw_per_second;
        break;
    case BW_LEAF_OUT:
        s->enabled  = bws_glout_enabled;
        s->current  = bsched_bps(bws.glout);
        s->average  = bsched_avg_bps(bws.glout);
        s->limit    = bws.glout->bw_per_second;
        break;
    }
}

/***
 *** Internal helpers.
 ***/

/**
 * Compute the EMA of the IP address lifetime up to now, but do not
 * update the property.
 */
guint32
get_average_ip_lifetime(time_t now, enum net_type net)
{
	time_t current_ip_stamp;
	guint32 average_ip_uptime;
	glong lifetime;

	switch (net) {
	case NET_TYPE_IPV4: 
		gnet_prop_get_timestamp_val(PROP_CURRENT_IP_STAMP, &current_ip_stamp);
		gnet_prop_get_guint32_val(PROP_AVERAGE_IP_UPTIME, &average_ip_uptime);
		break;
	case NET_TYPE_IPV6: 
		gnet_prop_get_timestamp_val(PROP_CURRENT_IP6_STAMP, &current_ip_stamp);
		gnet_prop_get_guint32_val(PROP_AVERAGE_IP6_UPTIME, &average_ip_uptime);
		break;
	default:
		return 0;
	}

	if (current_ip_stamp) {
		lifetime = delta_time(now, current_ip_stamp);
		lifetime = MAX(0, lifetime);
	} else
		lifetime = 0;

	/*
	 * The average lifetime is computed as an EMA on 3 terms.
	 * The smoothing factor sm=2/(3+1) is therefore 0.5.
	 */

	average_ip_uptime += (lifetime >> 1) - (average_ip_uptime >> 1);

	return average_ip_uptime;
}

/**
 * Called whenever the IP address we advertise changed.
 * Update the average uptime for a given IP address.
 */
static void
update_address_lifetime(void)
{
	static host_addr_t old_addr, old_addr_v6;
	time_t current_ip_stamp;
	host_addr_t addr;

	addr = listen_addr();
	if (!is_host_addr(old_addr)) {				/* First time */
		old_addr = addr;
		gnet_prop_get_timestamp_val(PROP_CURRENT_IP_STAMP, &current_ip_stamp);
		if (0 == current_ip_stamp)
			gnet_prop_set_timestamp_val(PROP_CURRENT_IP_STAMP, tm_time());
	}

	if (!host_addr_equal(old_addr, addr)) {
		time_t now;

		/*
		 * IP address changed, update lifetime information.
		 */

		now = tm_time();
		old_addr = addr;

		gnet_prop_get_timestamp_val(PROP_CURRENT_IP_STAMP, &current_ip_stamp);

		if (current_ip_stamp)
			gnet_prop_set_guint32_val(PROP_AVERAGE_IP_UPTIME,
					get_average_ip_lifetime(now, host_addr_net(addr)));

		gnet_prop_set_timestamp_val(PROP_CURRENT_IP_STAMP, now);
	}

	addr = listen_addr6();
	if (!is_host_addr(old_addr_v6)) {				/* First time */
		old_addr_v6 = addr;
		gnet_prop_get_timestamp_val(PROP_CURRENT_IP6_STAMP, &current_ip_stamp);
		if (0 == current_ip_stamp)
			gnet_prop_set_timestamp_val(PROP_CURRENT_IP6_STAMP, tm_time());
	}

	if (!host_addr_equal(old_addr_v6, addr)) {
		time_t now;

		/*
		 * IP address changed, update lifetime information.
		 */

		now = tm_time();
		old_addr_v6 = addr;

		gnet_prop_get_timestamp_val(PROP_CURRENT_IP6_STAMP, &current_ip_stamp);
		if (current_ip_stamp)
			gnet_prop_set_guint32_val(PROP_AVERAGE_IP6_UPTIME,
					get_average_ip_lifetime(now, host_addr_net(addr)));

		gnet_prop_set_timestamp_val(PROP_CURRENT_IP6_STAMP, now);
	}
}

/**
 * Compute the EMA of the averate servent uptime, up to now, but do not
 * update the property.
 */
guint32
get_average_servent_uptime(time_t now)
{
	guint32 avg_servent_uptime;
	time_t start;
	glong uptime;

	gnet_prop_get_guint32_val(PROP_AVERAGE_SERVENT_UPTIME, &avg_servent_uptime);
	gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);

	uptime = delta_time(now, start);
	uptime = MAX(0, uptime);

	/*
	 * The average uptime is computed as an EMA on 7 terms.
	 * The smoothing factor sm=2/(7+1) is therefore 0.25.
	 */

	avg_servent_uptime += (uptime >> 2) - (avg_servent_uptime >> 2);

	return avg_servent_uptime;
}

/**
 * Called at shutdown time to update the average_uptime property before
 * saving the properties to disk.
 */
static void
update_uptimes(void)
{
	time_t now = tm_time();

	gnet_prop_set_guint32_val(PROP_AVERAGE_SERVENT_UPTIME,
		get_average_servent_uptime(now));

	gnet_prop_set_guint32_val(PROP_AVERAGE_IP_UPTIME,
		get_average_ip_lifetime(now, NET_TYPE_IPV4));
	gnet_prop_set_guint32_val(PROP_AVERAGE_IP6_UPTIME,
		get_average_ip_lifetime(now, NET_TYPE_IPV6));
}

/***
 *** Callbacks
 ***/
static gboolean
up_connections_changed(property_t prop)
{
    guint32 up_connections;
    guint32 max_connections;

	g_assert(PROP_UP_CONNECTIONS == prop);
    gnet_prop_get_guint32_val(prop, &up_connections);
    gnet_prop_get_guint32_val(PROP_MAX_CONNECTIONS, &max_connections);

    if (up_connections > max_connections)
        gnet_prop_set_guint32_val(PROP_MAX_CONNECTIONS, up_connections);

    return FALSE;
}

static gboolean
max_connections_changed(property_t prop)
{
    guint32 up_connections;
    guint32 max_connections;

	g_assert(PROP_MAX_CONNECTIONS == prop);
    gnet_prop_get_guint32_val(prop, &max_connections);
    gnet_prop_get_guint32_val(PROP_UP_CONNECTIONS, &up_connections);

    if (up_connections > max_connections)
        gnet_prop_set_guint32_val(PROP_UP_CONNECTIONS, max_connections);

    return FALSE;
}

static gboolean
max_hosts_cached_changed(property_t prop)
{
	g_assert(PROP_MAX_HOSTS_CACHED == prop);
    hcache_prune(HCACHE_FRESH_ANY);

    return FALSE;
}

static gboolean
max_ultra_hosts_cached_changed(property_t prop)
{
	g_assert(PROP_MAX_ULTRA_HOSTS_CACHED == prop);
    hcache_prune(HCACHE_FRESH_ULTRA);

    return FALSE;
}

static gboolean
max_bad_hosts_cached_changed(property_t prop)
{
	g_assert(PROP_MAX_BAD_HOSTS_CACHED == prop);
    hcache_prune(HCACHE_BUSY);
    hcache_prune(HCACHE_TIMEOUT);
    hcache_prune(HCACHE_UNSTABLE);

    return FALSE;
}

static host_addr_t
get_bind_addr(enum net_type net)
{
	host_addr_t addr = zero_host_addr;
	
	switch (net) {
	case NET_TYPE_IPV4:
		addr = listen_addr();
		if (
			!force_local_ip ||
			!bind_to_forced_local_ip ||
			!host_addr_initialized(addr)
		) {
			addr = ipv4_unspecified;
		}
		break;
	case NET_TYPE_IPV6:
		addr = listen_addr6();
		if (
			!force_local_ip6 ||
			!bind_to_forced_local_ip6 ||
			!host_addr_initialized(addr)
		) {
			addr = ipv6_unspecified;
		}
		break;
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}
	return addr;
}

static gboolean
enable_udp_changed(property_t prop)
{
	gboolean enabled;
	
    gnet_prop_get_boolean_val(prop, &enabled);
	if (enabled) {
		if (s_tcp_listen) {
			s_udp_listen = socket_udp_listen(get_bind_addr(NET_TYPE_IPV4),
								listen_port);
			if (!s_udp_listen) {
				gcu_statusbar_warning(_("Failed to create IPv4 UDP socket"));
			}
		}
		if (s_tcp_listen6) {
			s_udp_listen6 = socket_udp_listen(get_bind_addr(NET_TYPE_IPV6),
								listen_port);
			if (!s_udp_listen) {
				gcu_statusbar_warning(_("Failed to create IPv6 UDP socket"));
			}
		}
	} else {
		socket_free_null(&s_udp_listen);
		socket_free_null(&s_udp_listen6);
	}
	node_update_udp_socket();

	return FALSE;
}

static void
request_new_sockets(guint16 port, gboolean check_firewalled)
{
	host_addr_t bind_addr = zero_host_addr;
	host_addr_t bind_addr6 = zero_host_addr;

	/*
	 * Close old ports.
	 */

	socket_free_null(&s_tcp_listen);
	socket_free_null(&s_tcp_listen6);
	socket_free_null(&s_udp_listen);
	socket_free_null(&s_udp_listen6);

	/*
	 * If the new port != 0, open the new port
	 */

	if (0 == port)
		return;

	if (NET_USE_BOTH == network_protocol || NET_USE_IPV4 == network_protocol) {
		s_tcp_listen = socket_tcp_listen(bind_addr, port, SOCK_TYPE_CONTROL);
		if (enable_udp) {
			s_udp_listen = socket_udp_listen(get_bind_addr(NET_TYPE_IPV4),
							port);
			if (!s_udp_listen) {
				socket_free_null(&s_tcp_listen);
			}
		}
	}
	if (NET_USE_BOTH == network_protocol || NET_USE_IPV6 == network_protocol) {
		s_tcp_listen6 = socket_tcp_listen(bind_addr6, port, SOCK_TYPE_CONTROL);
		if (enable_udp) {
			s_udp_listen6 = socket_udp_listen(get_bind_addr(NET_TYPE_IPV6),
								port);
			if (!s_udp_listen6) {
				socket_free_null(&s_tcp_listen6);
			}
		}
	}
	
	/*
	 * If UDP is enabled, also listen on the same UDP port.
	 */

	if (enable_udp) {
		node_update_udp_socket();
	}

	if (check_firewalled) {
		inet_firewalled();
		inet_udp_firewalled();
	}
}

static gboolean
listen_port_changed(property_t prop)
{
	static guint32 old_port = (guint32) -1;

	/*
	 * If port did not change values, do nothing.
	 */

	if (listen_port == old_port && listen_port != 0)
		return FALSE;
	old_port = listen_port;

	/*
	 * 1 is a magic port number for us, which means "pick a random port"
	 * whereas 0 means "don't listen on any port".
	 */

	if (1 != listen_port) {
		request_new_sockets(listen_port, FALSE);
	} else {
		bit_array_t tried[BIT_ARRAY_SIZE(65536)];
		guint num_tried = 0;
    	guint32 port = listen_port;

		/* Mark ports below 1024 as already tried, these ports can
		 * be configured manually but we don't want to pick one of
		 * these when not explicitely told so as it may grab the
		 * port of an important service (which is currently down).
		 */

		bit_array_set_range(tried, 0, 1023);
		bit_array_clear_range(tried, 1024, 65535);

		do {
			guint32 i;

			i = random_value(65535 - 1024) + 1024;
			port = i;

			/* Check whether this port was tried before */
			do {
				if (!bit_array_get(tried, i)) {
					port = i;
					break;
				}
				i = (i + 101) & 0xffff;
			} while (i != port);

			g_assert(port > 1023);
			request_new_sockets(port, FALSE);

			if (s_tcp_listen || s_tcp_listen6)
				break;

		} while (++num_tried < 65535 - 1024);

		old_port = port;
		gnet_prop_set_guint32_val(prop, port);
	}

	inet_firewalled();
	inet_udp_firewalled();

	/*
     * If socket allocation failed, reset the property
     */

    if (s_tcp_listen == NULL && listen_port != 0) {
		gcu_statusbar_warning(_("Failed to create listening sockets"));
		old_port = (guint32) -1;
        return TRUE;
    } else {
		old_port = listen_port;
	}

    return FALSE;
}

static gboolean
network_protocol_changed(property_t prop)
{

	(void) prop;
	request_new_sockets(listen_port, TRUE);
	return FALSE;
}


static gboolean
bw_http_in_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.in);
    else
        bsched_disable(bws.in);

    return FALSE;
}

static gboolean
bw_http_out_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.out);
    else
        bsched_disable(bws.out);

    return FALSE;
}

static gboolean
bw_gnet_in_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.gin);
    else
        bsched_disable(bws.gin);

    return FALSE;
}

static gboolean
bw_gnet_out_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.gout);
    else
        bsched_disable(bws.gout);

    return FALSE;
}

static gboolean
bw_gnet_lin_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.glin);
    else
        bsched_disable(bws.glin);

    return FALSE;
}

static gboolean
bw_gnet_lout_enabled_changed(property_t prop)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bws.glout);
    else
        bsched_disable(bws.glout);

    return FALSE;
}

static gboolean
node_sendqueue_size_changed(property_t unused_prop)
{
    guint32 val;
    guint32 min = 1.5 * settings_max_msg_size();

	(void) unused_prop;
    gnet_prop_get_guint32_val(PROP_NODE_SENDQUEUE_SIZE, &val);
    if (val < min) {
        gnet_prop_set_guint32_val(PROP_NODE_SENDQUEUE_SIZE, min);
        return TRUE;
    }

    return FALSE;
}

static gboolean
scan_extensions_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    parse_extensions(s);
    G_FREE_NULL(s);

    return FALSE;
}

static gboolean
file_path_changed(property_t prop)
{
    gchar *s;

	s = gnet_prop_get_string(prop, NULL, 0);
	g_assert(s != NULL);

	if (!is_directory(s)) {
		g_message("Attempt to create directory \"%s\"", s);

		if (0 != create_directory(s))
			g_message("Attempt failed: \"%s\"", g_strerror(errno));
	}

    G_FREE_NULL(s);
    return FALSE;
}

static gboolean
shared_dirs_paths_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);
	gboolean ok;

	ok = shared_dirs_parse(s);
	G_FREE_NULL(s);

	if (!ok) {
		shared_dirs_update_prop();
		return TRUE;
	}

	return FALSE;
}

static gboolean
local_netmasks_string_changed(property_t prop)
{
    gchar *s = gnet_prop_get_string(prop, NULL, 0);

    parse_netmasks(s);
    G_FREE_NULL(s);

    return FALSE;
}

static gboolean
hard_ttl_limit_changed(property_t prop)
{
    guint32 hard_ttl_limit;
    guint32 max_ttl;

	g_assert(PROP_HARD_TTL_LIMIT == prop);
    gnet_prop_get_guint32_val(prop, &hard_ttl_limit);
    gnet_prop_get_guint32_val(PROP_MAX_TTL, &max_ttl);

    if (hard_ttl_limit < max_ttl)
        gnet_prop_set_guint32_val(PROP_MAX_TTL, hard_ttl_limit);

    return FALSE;
}

static gboolean
max_ttl_changed(property_t prop)
{
    guint32 hard_ttl_limit;
    guint32 max_ttl;

	g_assert(PROP_MAX_TTL == prop);
    gnet_prop_get_guint32_val(prop, &max_ttl);
    gnet_prop_get_guint32_val(PROP_HARD_TTL_LIMIT, &hard_ttl_limit);

    if (hard_ttl_limit < max_ttl)
        gnet_prop_set_guint32_val(PROP_HARD_TTL_LIMIT, max_ttl);

    return FALSE;
}

static gboolean
bw_http_in_changed(property_t prop)
{
    guint32 val;

	g_assert(PROP_BW_HTTP_IN == prop);
    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.in, val);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_http_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.out, val);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_gnet_in_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.gin, val / 2);
    bsched_set_bandwidth(bws.gin_udp, val / 2);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_gnet_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.gout, val / 2);
    bsched_set_bandwidth(bws.gout_udp, val / 2);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_gnet_lin_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.glin, val);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_gnet_lout_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(bws.glout, val);

	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &val);
	bsched_set_peermode(val);

    return FALSE;
}

static gboolean
bw_allow_stealing_changed(property_t prop)
{
	gboolean val;

	gnet_prop_get_boolean_val(prop, &val);

	if (val)
		bsched_config_steal_http_gnet();
	else
		bsched_config_steal_gnet();

	return FALSE;
}

static gboolean
node_online_mode_changed(property_t prop)
{
	gboolean val;

	gnet_prop_get_boolean_val(prop, &val);
	node_set_online_mode(val);

    return FALSE;
}

static gboolean
lib_debug_changed(property_t unused_prop)
{
	(void) unused_prop;
/* XXX -- common_dbg is no longer a property! --RAM */
#if 0
	gnet_prop_get_guint32_val(prop, &common_dbg);
#endif
    return FALSE;
}

static gboolean
force_local_addr_changed(property_t prop)
{
	(void) prop;

	if (
		NET_TYPE_NONE != host_addr_net(local_ip) &&
		NET_TYPE_IPV4 != host_addr_net(local_ip)
	) {
		gnet_prop_set_ip_val(PROP_LOCAL_IP, zero_host_addr);
	}
	if (
		NET_TYPE_NONE != host_addr_net(local_ip6) &&
		NET_TYPE_IPV6 != host_addr_net(local_ip6)
	) {
		gnet_prop_set_ip_val(PROP_LOCAL_IP6, zero_host_addr);
	}
	update_address_lifetime();
	request_new_sockets(listen_port, TRUE);
    return FALSE;
}

static gboolean
forced_local_ip_changed(property_t prop)
{
	(void) prop;
	if (force_local_ip || force_local_ip6) {
		request_new_sockets(listen_port, TRUE);
	}
    return FALSE;
}

static gboolean
local_addr_changed(property_t prop)
{
	enum net_type net;
	host_addr_t addr;

	switch (prop) {
	case PROP_LOCAL_IP:
		net = NET_TYPE_IPV4;
		break;
	case PROP_LOCAL_IP6:
		net = NET_TYPE_IPV6;
		break;
	default:
		net = NET_TYPE_NONE;
		g_assert_not_reached();
	}

	gnet_prop_get_ip_val(prop, &addr);

	/* If the address is invalid or does not match the network type;
	 * reset it and try to guess the correct one by looking at all
	 * network interfaces.
	 */	
	if (
		!is_host_addr(addr) ||
		net != host_addr_net(addr) ||
		host_addr_is_ipv4_mapped(addr)
	) {
		GSList *sl_addrs, *sl;

		addr = zero_host_addr;
		sl_addrs = host_addr_get_interface_addrs();
		for (sl = sl_addrs; NULL != sl; sl = g_slist_next(sl)) {
			host_addr_t *addr_ptr;

			addr_ptr = sl->data;
			if (
				net == host_addr_net(*addr_ptr) &&
				host_addr_is_routable(*addr_ptr)
			) {
				addr = *addr_ptr;
				break;
			}
		}
		host_addr_free_interface_addrs(&sl_addrs);
		gnet_prop_set_ip_val(prop, addr);
	}

	update_address_lifetime();
    return FALSE;
}

static gboolean
configured_peermode_changed(property_t prop)
{
    guint32 val;
	gboolean forced = FALSE;

    gnet_prop_get_guint32_val(prop, &val);

	/* XXX: The following is disabled because it is too restrictive and
	 *		annoying in LAN. If a user doesn't use the default "auto"
	 *		mode, it can be assumed that he knows what he's doing. Also,
	 *		while it's sub-optimal it's not absolutely required for an
	 *		ultrapeer to accept incoming connections (from external hosts).
	 * 
	 *		--cbiere, 2005-05-14
	 */
#if 0
	/*
	 * We don't allow them to be anything but a leaf node if they are
	 * firewalled.  We even restrict the "normal" mode, which is to be
	 * avoided anyway, and will be removed in a future release.
	 *		--RAM, 2004-09-19
	 */

	switch (val) {
	case NODE_P_NORMAL:
	case NODE_P_ULTRA:
		if (is_firewalled) {
			val = NODE_P_AUTO;
			forced = TRUE;
			g_warning("must run as a leaf when TCP-firewalled");
			gcu_statusbar_warning(
				_("Can only run as a leaf when TCP-firewalled"));
		}
		break;
	default:
		break;
	}
#endif

	if (val == NODE_P_AUTO) {
		if (connected_nodes() > 0)		/* Already connected */
			return forced;				/* Keep our current operating mode */
		val = NODE_P_LEAF;				/* Force leaf mode */
		/* FALL THROUGH */
	}

	gnet_prop_set_guint32_val(PROP_CURRENT_PEERMODE, val);

    return forced;
}

static gboolean
current_peermode_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	node_current_peermode_changed((node_peer_t) val);

    return FALSE;
}

static gboolean
download_rx_size_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	download_set_socket_rx_size(val * 1024);

	return FALSE;
}

static gboolean
node_rx_size_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	node_set_socket_rx_size(val * 1024);

	return FALSE;
}

/*
 * Automatically reset properties have a callout queue entry associated
 * with them.  When the entry fires, the property is cleared.  Each time
 * the property is set, the callout entry is reactivated some time in the
 * future.
 */

static gpointer ev_file_descriptor_shortage = NULL;
static gpointer ev_file_descriptor_runout = NULL;

#define RESET_PROP_TM	(10*60*1000)	/**< 10 minutes in ms */

/**
 * callout queue callback
 *
 * Reset the property.
 */
static void
reset_property_cb(cqueue_t *unused_cq, gpointer obj)
{
	property_t prop = (property_t) GPOINTER_TO_UINT(obj);

	(void) unused_cq;
	switch (prop) {
	case PROP_FILE_DESCRIPTOR_SHORTAGE:
		ev_file_descriptor_shortage = NULL;
		break;
	case PROP_FILE_DESCRIPTOR_RUNOUT:
		ev_file_descriptor_runout = NULL;
		break;
	default:
		g_error("unhandled property #%d", prop);
		break;
	}

	gnet_prop_set_boolean_val(prop, FALSE);
}

static gboolean
file_descriptor_x_changed(property_t prop)
{
	gboolean state;
	gpointer *ev = NULL;

	gnet_prop_get_boolean_val(prop, &state);
	if (!state)
		return FALSE;

	/*
	 * Property is set to TRUE: arm callback to reset it in 10 minutes.
	 */

	switch (prop) {
	case PROP_FILE_DESCRIPTOR_SHORTAGE:
		ev = &ev_file_descriptor_shortage;
		break;
	case PROP_FILE_DESCRIPTOR_RUNOUT:
		ev = &ev_file_descriptor_runout;
		break;
	default:
		g_error("unhandled property #%d", prop);
		break;
	}

	g_assert(ev != NULL);

	if (*ev == NULL)
		*ev = cq_insert(callout_queue, RESET_PROP_TM, reset_property_cb,
			GUINT_TO_POINTER(prop));
	else
		cq_resched(callout_queue, *ev, RESET_PROP_TM);

    return FALSE;
}

/***
 *** Property-to-callback map
 ***/

typedef struct prop_map {
    property_t prop;            /**< property handle */
    prop_changed_listener_t cb; /**< callback function */
    gboolean init;              /**< init widget with current value */
} prop_map_t;

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
        PROP_MAX_ULTRA_HOSTS_CACHED,
        max_ultra_hosts_cached_changed,
        TRUE
	},
    {
        PROP_MAX_BAD_HOSTS_CACHED,
        max_bad_hosts_cached_changed,
        TRUE
	},
    {
        PROP_LISTEN_PORT,
        listen_port_changed,
        TRUE
    },
    {
        PROP_NETWORK_PROTOCOL,
        network_protocol_changed,
        FALSE
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
        PROP_BW_GNET_LEAF_IN_ENABLED,
        bw_gnet_lin_enabled_changed,
        FALSE
    },
    {
        PROP_BW_GNET_LEAF_OUT_ENABLED,
        bw_gnet_lout_enabled_changed,
        FALSE
    },
    {
        PROP_SCAN_EXTENSIONS,
        scan_extensions_changed,
        TRUE
    },
    {
        PROP_SAVE_FILE_PATH,
        file_path_changed,
        TRUE
    },
    {
        PROP_MOVE_FILE_PATH,
        file_path_changed,
        TRUE
    },
    {
        PROP_BAD_FILE_PATH,
        file_path_changed,
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
    },
    {
        PROP_BW_GNET_LIN,
        bw_gnet_lin_changed,
        FALSE
    },
    {
        PROP_BW_GNET_LOUT,
        bw_gnet_lout_changed,
        FALSE
    },
    {
        PROP_BW_ALLOW_STEALING,
        bw_allow_stealing_changed,
        FALSE
    },
	{
		PROP_ONLINE_MODE,
		node_online_mode_changed,
		TRUE						/* Need to call callback at init time */
	},
    {
        PROP_LIB_DEBUG,
        lib_debug_changed,
        TRUE
    },
	{
		PROP_FORCE_LOCAL_IP,
		force_local_addr_changed,
		TRUE,
	},
	{
		PROP_FORCE_LOCAL_IP6,
		force_local_addr_changed,
		TRUE,
	},
	{
		PROP_FORCED_LOCAL_IP,
		forced_local_ip_changed,
		TRUE,
	},
	{
		PROP_FORCED_LOCAL_IP6,
		forced_local_ip_changed,
		TRUE,
	},
	{
		PROP_LOCAL_IP,
		local_addr_changed,
		TRUE,
	},
	{
		PROP_LOCAL_IP6,
		local_addr_changed,
		TRUE,
	},
	{
		PROP_CONFIGURED_PEERMODE,
		configured_peermode_changed,
		TRUE,
	},
	{
		PROP_CURRENT_PEERMODE,
		current_peermode_changed,
		TRUE,
	},
	{
		PROP_DOWNLOAD_RX_SIZE,
		download_rx_size_changed,
		TRUE,
	},
	{
		PROP_NODE_RX_SIZE,
		node_rx_size_changed,
		TRUE,
	},
	{
		PROP_FILE_DESCRIPTOR_SHORTAGE,
		file_descriptor_x_changed,
		FALSE,
	},
	{
		PROP_FILE_DESCRIPTOR_RUNOUT,
		file_descriptor_x_changed,
		FALSE,
	},
	{
		PROP_ENABLE_UDP,
		enable_udp_changed,
		FALSE,				/* UDP socket inited via listen_port_changed() */
	},
};

/***
 *** Control functions
 ***/

#define PROPERTY_MAP_SIZE G_N_ELEMENTS(property_map)

static gboolean init_list[GNET_PROPERTY_NUM];

static void
settings_callbacks_init(void)
{
    guint n;

    for (n = 0; n < GNET_PROPERTY_NUM; n ++)
        init_list[n] = FALSE;

    if (debug >= 2) {
        printf("settings_callbacks_init: property_map size: %u\n",
            (guint) PROPERTY_MAP_SIZE);
    }

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        property_t prop = property_map[n].prop;
        guint32 idx = prop - GNET_PROPERTY_MIN;

        if (!init_list[idx])
           init_list[idx] = TRUE;
        else
            g_warning("settings_callbacks_init:"
                " property %d already mapped", n);

        if (property_map[n].cb) {
            gnet_prop_add_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init);
        } else if (debug >= 10) {
            printf("settings_callbacks_init: property ignored: %s\n",
				gnet_prop_name(prop));
        }
    }

    if (debug >= 1) {
        for (n = 0; n < GNET_PROPERTY_NUM; n++) {
            if (!init_list[n])
                printf("settings_callbacks_init: unmapped property: %s\n",
					gnet_prop_name(n+GNET_PROPERTY_MIN));
        }
    }
}

static void
settings_callbacks_shutdown(void)
{
    guint n;

	if (ev_file_descriptor_shortage != NULL) {
		cq_cancel(callout_queue, ev_file_descriptor_shortage);
		ev_file_descriptor_shortage = NULL;
	}
	if (ev_file_descriptor_runout != NULL) {
		cq_cancel(callout_queue, ev_file_descriptor_runout);
		ev_file_descriptor_runout = NULL;
	}

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        if (property_map[n].cb) {
            gnet_prop_remove_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb);
        }
    }
}

/* vi: set ts=4 sw=4 cindent: */
