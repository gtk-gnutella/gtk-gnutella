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
 * gtk-gnutella configuration.
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

#include "bsched.h"
#include "downloads.h"
#include "hcache.h"
#include "hosts.h"
#include "inet.h"
#include "search.h"
#include "settings.h"
#include "share.h"
#include "sockets.h"
#include "upload_stats.h"
#include "routing.h"			/* For gnet_reset_guid() */
#include "ipp_cache.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/core/main.h"		/* For debugging() */
#include "if/core/net_stats.h"
#include "if/dht/dht.h"

#include "if/bridge/c2ui.h"

#include "lib/bit_array.h"
#include "lib/cq.h"
#include "lib/debug.h"
#include "lib/file.h"
#include "lib/getphysmemsize.h"
#include "lib/glib-missing.h"
#include "lib/palloc.h"
#include "lib/sha1.h"
#include "lib/tm.h"
#include "lib/zalloc.h"

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

static const char config_file[] = "config_gnet";
static const char ul_stats_file[] = "upload_stats";

static const mode_t IPC_DIR_MODE = S_IRUSR | S_IWUSR | S_IXUSR; /* 0700 */
static const mode_t PID_FILE_MODE = S_IRUSR | S_IWUSR; /* 0600 */
static const mode_t CONFIG_DIR_MODE =
	S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP; /* 0750 */

static char *home_dir = NULL;
static char *config_dir = NULL;

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

static const char pidfile[] = "gtk-gnutella.pid";
static const char dirlockfile[] = ".gtk-gnutella.lock";

static gboolean settings_init_running;

static void settings_callbacks_init(void);
static void settings_callbacks_shutdown(void);
static void update_uptimes(void);

/* ----------------------------------------- */

/**
 * Insert local IP:port in the local address cache if combination is valid.
 */
static void
remember_local_addr_port(void)
{
	host_addr_t addr;
	guint16 port;

	addr = listen_addr();
	port = GNET_PROPERTY(listen_port);

	if (host_is_valid(addr, port))
		local_addr_cache_insert(addr, port);

	addr = listen_addr6();

	if (host_is_valid(addr, port))
		local_addr_cache_insert(addr, port);
}

/**
 * @return the currently used local listening address.
 */
host_addr_t
listen_addr(void)
{
	if (s_tcp_listen) {
		return GNET_PROPERTY(force_local_ip)
				? GNET_PROPERTY(forced_local_ip)
				: GNET_PROPERTY(local_ip);
	} else {
		return zero_host_addr;
	}
}

/**
 * @return the currently used local listening address.
 */
host_addr_t
listen_addr6(void)
{
	if (s_tcp_listen6) {
		return GNET_PROPERTY(force_local_ip6)
				? GNET_PROPERTY(forced_local_ip6)
				: GNET_PROPERTY(local_ip6);
	} else {
		return zero_host_addr;
	}
}

host_addr_t
listen_addr_by_net(enum net_type net)
{
	switch (net) {
	case NET_TYPE_IPV4: return listen_addr();
	case NET_TYPE_IPV6: return listen_addr6();
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	return zero_host_addr;
}
	
gboolean
is_my_address(const host_addr_t addr)
{
	return host_addr_equal(addr, listen_addr_by_net(host_addr_net(addr)));
}

gboolean
is_my_address_and_port(const host_addr_t addr, guint16 port)
{
	return port == GNET_PROPERTY(listen_port) && is_my_address(addr);
}


/**
 * Look for any existing PID file. If found, look at the pid recorded
 * there and make sure it has died. Abort operations if it hasn't...
 *
 * @returns Returns zero on success and -1 on failure.
 *          If fd_ptr is NULL the lock is only tested but not created.
 *			On failure errno is set to EEXIST, if the PID file was already
 *			locked. Other errno values imply that the PID file could not
 *			be created.
 */
static int
ensure_unicity(const char *file, int *fd_ptr)
{
	gboolean locked = FALSE;
	int fd;

	g_assert(file);

	fd = file_create(file, O_RDWR, PID_FILE_MODE);
	if (fd < 0) {
		int saved_errno = errno;

		if (fd_ptr || GNET_PROPERTY(lockfile_debug)) {
			g_warning("could not create \"%s\": %s", file, g_strerror(errno));
		}

		errno = saved_errno;
		return -1;
	}

	if (GNET_PROPERTY(lockfile_debug)) {
		g_message("file \"%s\" opened", file);
	}
/* FIXME: These might be enums, a compile-time check would be better */
#if defined(F_SETLK) && defined(F_WRLCK)
	{
		static const struct flock zero_flock;
		struct flock fl;
		gboolean locking_failed;

		fl = zero_flock;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		/* l_start and l_len are zero, which means the whole file is locked */

		locking_failed = -1 == fcntl(fd, F_SETLK, &fl);

		if (GNET_PROPERTY(lockfile_debug)) {
			g_message("file \"%s\" fcntl-locking %s", file,
				locking_failed ? "failed" : "succeeded");
		}

		if (locking_failed) {
			int saved_errno = errno;

			if (fd_ptr || GNET_PROPERTY(lockfile_debug)) {
				g_warning("fcntl(%d, F_SETLK, ...) failed for \"%s\": %s",
					fd, file, g_strerror(saved_errno));
				/*
				 * Use F_GETLK to determine the PID of the process, the
				 * reinitialization of "fl" might be unnecessary but who
				 * knows.
				 */
				fl = zero_flock;
				fl.l_type = F_WRLCK;
				fl.l_whence = SEEK_SET;

				if (-1 != fcntl(fd, F_GETLK, &fl)) {
					g_warning("another gtk-gnutella process seems to "
							"be using \"%s\" (pid=%lu)",
							file, (gulong) fl.l_pid);
				} else {
					g_warning("fcntl(%d, F_GETLK, ...) failed for \"%s\": %s",
						fd, file, g_strerror(errno));
				}
			}

			if (is_temporary_error(saved_errno) || EACCES == saved_errno) {
				goto failed;	/* The file seems to be locked */
			}
		} else {
			locked = TRUE;
		}
	}
#endif /* F_SETLK && F_WRLCK */

	/*
	 * Maybe F_SETLK is not supported by the OS or filesystem?
	 * Fall back to weaker PID locking
	 */

	if (!locked) {
		ssize_t r;
		char buf[33];

		if (GNET_PROPERTY(lockfile_debug)) {
			g_message("file \"%s\" being read for PID", file);
		}
		r = read(fd, buf, sizeof buf - 1);
		if ((ssize_t) -1 == r) {
			/* This would be odd */
			if (fd_ptr || GNET_PROPERTY(lockfile_debug)) {
				g_warning("could not read file \"%s\": %s",
					file, g_strerror(errno));
			}
			goto failed;
		}

		/* Check the PID in the file */
		{
			guint64 u;
			int error;

			g_assert(r >= 0 && (size_t) r < sizeof buf);
			buf[r] = '\0';

			u = parse_uint64(buf, NULL, 10, &error);

			/* If the pidfile seems to be corrupt, ignore it */
			if (!error && u > 1) {
				pid_t pid = u;

				if (GNET_PROPERTY(lockfile_debug)) {
					g_message("file \"%s\" trying to send SIGZERO to PID %lu",
						file, (unsigned long) pid);
				}

				if (0 == kill(pid, 0)) {
					if (fd_ptr) {
						g_warning("another gtk-gnutella process seems to "
							"be using \"%s\" (pid=%lu)", file, (gulong) pid);
					}
					goto failed;
				}
			}
		}
	}

	if (GNET_PROPERTY(lockfile_debug)) {
		g_message("file \"%s\" LOCKED (mode %s)",
			file, fd_ptr ? "check" : "permanent");
	}

	if (NULL == fd_ptr) {
		/*
		 * We keep the empty PID file around. Otherwise,
		 * there's a race-condition without fcntl() locking.
		 */
		close(fd);
	} else {
		/* Keep the fd open, otherwise the lock is lost */
		*fd_ptr = fd;
	}

	return 0;

failed:

	if (GNET_PROPERTY(lockfile_debug)) {
		g_message("file \"%s\" NOT LOCKED", file);
	}
	close(fd);
	errno = EEXIST;
	if (fd_ptr) {
		*fd_ptr = -1;
	}
	return -1;
}

/**
 * Write our pid to the lockfile, opened as "fd".
 */
static void
save_pid(int fd, const char *path)
{
	size_t len;
	char buf[32];

	g_assert(fd >= 0);

	len = gm_snprintf(buf, sizeof buf, "%lu\n", (gulong) getpid());

	if (GNET_PROPERTY(lockfile_debug)) {
		g_message("file \"%s\" about to be written with PID %lu on fd #%d",
			path, (gulong) getpid(), fd);
	}
	if (-1 == ftruncate(fd, 0))	{
		g_warning("ftruncate() failed for \"%s\": %s",
			path, g_strerror(errno));
		return;
	}
	if (0 != lseek(fd, 0, SEEK_SET))	{
		g_warning("lseek() failed for \"%s\": %s", path, g_strerror(errno));
		return;
	}
	if (len != (size_t) write(fd, buf, len)) {
		g_warning("could not flush \"%s\": %s", path, g_strerror(errno));
	}
}

/* ----------------------------------------- */

/**
 * Initializes "config_dir" and "home_dir".
 */
void
settings_early_init(void)
{
	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	home_dir = g_strdup(eval_subst("~"));
	if (home_dir) {
		if (!is_absolute_path(home_dir)) {
			g_error("$HOME must point to an absolute path!");
		}
	} else {
		g_error(_("Can't find your home directory!"));
	}
	if (config_dir) {
		if (!is_absolute_path(config_dir)) {
			g_error("$GTK_GNUTELLA_DIR must point to an absolute path!");
		}
	} else { 
		config_dir = make_pathname(home_dir, ".gtk-gnutella");
	}
}

/**
 * Make sure there is only one process leaving file "path/lockfile" around.
 *
 * @param path			the path where the lockfile is to be held
 * @param lockfile		the basename of the locking file
 * @param fd_ptr		if non-NULL, return the opened file descriptor here
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
settings_unique_usage(const char *path, const char *lockfile, int *fd_ptr)
{
	char *file;
	int saved_errno, ret;

	g_assert(path != NULL);
	g_assert(lockfile != NULL);

	file = make_pathname(path, lockfile);
	ret = ensure_unicity(file, fd_ptr);
	saved_errno = errno;

	if (0 == ret && fd_ptr) {
		save_pid(*fd_ptr, file);
	}
	G_FREE_NULL(file);

	errno = saved_errno;
	/* The file descriptor must be kept open */
	return ret;
}

/**
 * Tries to ensure that the current process is the only running instance
 * gtk-gnutella for the current value of GTK_GNUTELLA_DIR.
 *
 * @returns On success zero is returned, otherwise -1 is returned
 *			and errno is set.
 */
static int
settings_ensure_unicity(void)
{
	int fd;

	g_assert(config_dir);

	return settings_unique_usage(config_dir, pidfile, &fd);
}

int
settings_is_unique_instance(void)
{
	g_assert(config_dir);

	return settings_unique_usage(config_dir, pidfile, NULL) && EEXIST == errno;
}

/**
 * Tries to ensure that the current process is the only writer in
 * the directory where files are saved.
 *
 * @return 0 on success, -1 otherwise with errno set.
 */
static int
settings_ensure_unique_save_file_path(void)
{
	static int save_file_path_lock = -1;
	int fd;
	int ret;

	ret = settings_unique_usage(GNET_PROPERTY(save_file_path),
				dirlockfile, &fd);

	if (0 == ret) {
		if (save_file_path_lock >= 0) {
			close(save_file_path_lock);
		}
		save_file_path_lock = fd;
	}

	return ret;
}

static void
settings_init_session_id(void)
{
	SHA1Context ctx;
	struct sha1 digest;
	guint32 noise[64];
	size_t size;

	random_bytes(noise, sizeof noise);
	SHA1Reset(&ctx);
	SHA1Input(&ctx, &noise, sizeof noise);
	SHA1Result(&ctx, &digest);

	size = MIN(GUID_RAW_SIZE, sizeof digest.data);
	gnet_prop_set_storage(PROP_SESSION_ID, digest.data, size);
}

void
settings_init(void)
{
	guint64 memory = getphysmemsize();
	guint64 amount = memory / 1024;
	guint max_fd;

	settings_init_running = TRUE;

#ifdef RLIMIT_DATA 
	{
		struct rlimit lim;
	
		if (-1 != getrlimit(RLIMIT_DATA, &lim)) {
			guint32 maxdata = lim.rlim_cur / 1024;
			amount = MIN(amount, maxdata);		/* For our purposes */
		}
	}
#endif /* RLIMIT_DATA */

    properties = gnet_prop_init();
	max_fd = compat_max_fd();
	
	gnet_prop_set_guint32_val(PROP_SYS_NOFILE, max_fd);
	gnet_prop_set_guint64_val(PROP_SYS_PHYSMEM, amount);

	settings_init_session_id();
	memset(deconstify_gpointer(GNET_PROPERTY(servent_guid)), 0, GUID_RAW_SIZE);

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

	/*
	 * Parse the configuration.
	 *
	 * Reset the KUID and the GUID if the file was copied from another
	 * instance to prevent duplicate IDs on the network which are harmful
	 * for everyone.
	 */

	if (!prop_load_from_file(properties, config_dir, config_file)) {
		if (debugging(0))
			g_warning("config file \"%s\" was copied over", config_file);
		dht_reset_kuid();
		gnet_reset_guid();
	}

	/*
	 * Ensure this is the only instance running.
	 *
	 * This is done after loading the configuration file to benefit from
	 * the "lockfile_debug" property.
	 */

	if (0 != settings_ensure_unicity()) {
		g_warning(_("You seem to have left another gtk-gnutella running"));
		exit(EXIT_FAILURE);
	}

	if (debugging(0)) {
		g_message("detected amount of physical RAM: %s",
			short_size(memory, GNET_PROPERTY(display_metric_units)));
		g_message("process can use at maximum: %s",
			short_kb_size(amount, GNET_PROPERTY(display_metric_units)));
		g_message("process can use %u file descriptors", max_fd);
		g_message("max I/O vector size is %d items", MAX_IOV_COUNT);
		g_message("virtual memory page size is %lu bytes",
			(gulong) compat_pagesize());
	}

	{
		char *path;

		path = make_pathname(config_dir, ul_stats_file);
		upload_stats_load_history(path);	/* Loads the upload statistics */
		G_FREE_NULL(path);
	}


	/* watch for filter_file defaults */

	if (GNET_PROPERTY(hard_ttl_limit) < GNET_PROPERTY(max_ttl)) {
		*(guint32 *) &GNET_PROPERTY(hard_ttl_limit) = GNET_PROPERTY(max_ttl);
		g_warning("hard_ttl_limit was too small, adjusted to %u",
			GNET_PROPERTY(hard_ttl_limit));
	}

	/* Flow control depends on this being not too small */
	if (GNET_PROPERTY(node_sendqueue_size) < 1.5 * settings_max_msg_size()) {
		*(guint32 *) &GNET_PROPERTY(node_sendqueue_size) =
			(guint32) (1.5 * settings_max_msg_size());
		g_warning("node_sendqueue_size was too small, adjusted to %u",
			GNET_PROPERTY(node_sendqueue_size));
	}

    settings_callbacks_init();
	settings_init_running = FALSE;
	return;

no_config_dir:
	g_warning(_("Cannot proceed without valid configuration directory"));
	exit(EXIT_FAILURE); /* g_error() would dump core, that's ugly. */
}

/**
 * Get the config directory
 */
const char *
settings_config_dir(void)
{
	g_assert(NULL != config_dir);
	return (const char *) config_dir;
}

/**
 * Gets the home dir.
 */
const char *
settings_home_dir(void)
{
	g_assert(NULL != home_dir);
	return (const char *) home_dir;
}

/**
 * Gets the IPC directory.
 */
static const char *
settings_ipc_dir(void)
{
	static const char *path;

	if (!path) {
		path = make_pathname(settings_config_dir(), "ipc");
	}
	return NOT_LEAKING(path);

}
/**
 * Gets the path of the local socket.
 */
const char *
settings_local_socket_path(void)
{
	static const char *path;

	if (!path) {
		path = make_pathname(settings_ipc_dir(), "socket");
	}
	return NOT_LEAKING(path);
}

/**
 * @return The "net" parameter to use for name_to_host_addr() according
 *         to the current configuration.
 */
enum net_type
settings_dns_net(void)
{
	switch (GNET_PROPERTY(network_protocol)) {
	case NET_USE_BOTH: return NET_TYPE_NONE;
	case NET_USE_IPV4: return NET_TYPE_IPV4;
	case NET_USE_IPV6:
#ifdef HAS_IPV6
	return NET_TYPE_IPV6;
#else
	return NET_TYPE_NONE;
#endif /* HAS_IPV6 */
	}
	g_assert_not_reached();
	return NET_TYPE_NONE;
}

/**
 * Remove "path/lockfile".
 */
static void
settings_remove_lockfile(const char *path, const char *lockfile)
{
	char *file;

	g_return_if_fail(!is_null_or_empty(path));
	g_return_if_fail(lockfile);

	file = make_pathname(path, lockfile);
	if (-1 == unlink(file)) {
		g_warning("could not remove lockfile \"%s\": %s",
			file, g_strerror(errno));
	}
	G_FREE_NULL(file);
}

static void
addr_ipv4_changed(const host_addr_t new_addr, const host_addr_t peer)
{
	static guint same_addr_count = 0;
	static host_addr_t peers[3], last_addr_seen;
	guint i;

	g_return_if_fail(NET_TYPE_IPV4 == host_addr_net(new_addr));
	g_return_if_fail(NET_TYPE_IPV4 == host_addr_net(peer));

	if (GNET_PROPERTY(force_local_ip))
		return;

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

	if (host_addr_equal(new_addr, GNET_PROPERTY(local_ip)))
		return;

    gnet_prop_set_ip_val(PROP_LOCAL_IP, new_addr);
}

static void
addr_ipv6_changed(const host_addr_t new_addr, const host_addr_t peer)
{
	static guint same_addr_count = 0;
	static host_addr_t peers[3], last_addr_seen;
	guint i;

	g_return_if_fail(NET_TYPE_IPV6 == host_addr_net(new_addr));
	g_return_if_fail(NET_TYPE_IPV6 == host_addr_net(peer));

	if (GNET_PROPERTY(force_local_ip6))
		return;

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

	if (host_addr_equal(new_addr, GNET_PROPERTY(local_ip6)))
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
	g_assert(host_addr_initialized(new_addr));
	g_assert(host_addr_initialized(peer));

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
	case NET_TYPE_LOCAL:
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

	maxsize = GNET_PROPERTY(search_queries_kick_size);
	maxsize = MAX(maxsize, GNET_PROPERTY(search_answers_kick_size));
	maxsize = MAX(maxsize, GNET_PROPERTY(other_messages_kick_size));

	return maxsize;
}

/**
 * Called at exit time to flush the property files.
 */
void
settings_shutdown(void)
{
	update_uptimes();
	remember_local_addr_port();
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
	settings_remove_lockfile(config_dir, pidfile);
	settings_remove_lockfile(GNET_PROPERTY(save_file_path), dirlockfile);
    gnet_prop_shutdown();

	G_FREE_NULL(home_dir);
	G_FREE_NULL(config_dir);
}

static void
bw_stats(gnet_bw_stats_t *s, gboolean enabled, bsched_bws_t bws)
{
	s->enabled = enabled;
	s->current = bsched_bps(bws);
	s->average = bsched_avg_bps(bws);
	s->limit = bsched_bw_per_second(bws);
}

void
gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *s)
{
    g_assert(s != NULL);

    switch (type) {
    case BW_GNET_IN:
		bw_stats(s, GNET_PROPERTY(bws_gin_enabled), BSCHED_BWS_GIN);
		return;
    case BW_GNET_OUT:
		bw_stats(s, GNET_PROPERTY(bws_gout_enabled), BSCHED_BWS_GOUT);
		return;
    case BW_GNET_UDP_IN:
		bw_stats(s, GNET_PROPERTY(bws_gin_enabled), BSCHED_BWS_GIN_UDP);
		return;
    case BW_GNET_UDP_OUT:
		bw_stats(s, GNET_PROPERTY(bws_gout_enabled), BSCHED_BWS_GOUT_UDP);
		return;
    case BW_HTTP_IN:
		bw_stats(s, GNET_PROPERTY(bws_in_enabled), BSCHED_BWS_IN);
		return;
    case BW_HTTP_OUT:
		bw_stats(s, GNET_PROPERTY(bws_out_enabled), BSCHED_BWS_OUT);
		return;
    case BW_LEAF_IN:
		bw_stats(s, GNET_PROPERTY(bws_glin_enabled), BSCHED_BWS_GLIN);
		return;
    case BW_LEAF_OUT:
		bw_stats(s, GNET_PROPERTY(bws_glout_enabled), BSCHED_BWS_GLOUT);
		return;
    }
	g_assert_not_reached();
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
	guint32 lifetime, average;
	time_t stamp;

	switch (net) {
	case NET_TYPE_IPV4: 
		stamp = GNET_PROPERTY(current_ip_stamp);
		average = GNET_PROPERTY(average_ip_uptime);
		break;
	case NET_TYPE_IPV6: 
		stamp = GNET_PROPERTY(current_ip6_stamp);
		average = GNET_PROPERTY(average_ip6_uptime);
		break;
	default:
		return 0;
	}

	if (stamp) {
		time_delta_t d = delta_time(now, stamp);
		lifetime = MAX(0, d);
	} else
		lifetime = 0;

	/*
	 * The average lifetime is computed as an EMA on 3 terms.
	 * The smoothing factor sm=2/(3+1) is therefore 0.5.
	 */

	average += (lifetime >> 1) - (average >> 1);

	return average;
}

/**
 * Called whenever the IP address we advertise changed.
 * Update the average uptime for a given IP address and remember the new
 * address in the "local_addr" cache.
 */
static void
update_address_lifetime(void)
{
	static host_addr_t old_addr, old_addr_v6;
	time_t now;
	host_addr_t addr;

	now = tm_time();
	addr = listen_addr();
	if (!is_host_addr(old_addr)) {				/* First time */
		old_addr = addr;
		if (0 == GNET_PROPERTY(current_ip_stamp)) {
			gnet_prop_set_timestamp_val(PROP_CURRENT_IP_STAMP, now);
		}
	}

	if (!host_addr_equal(old_addr, addr)) {
		/*
		 * IPv4 address changed, update lifetime information.
		 */

		old_addr = addr;
		if (GNET_PROPERTY(current_ip_stamp)) {
			gnet_prop_set_guint32_val(PROP_AVERAGE_IP_UPTIME,
				get_average_ip_lifetime(now, host_addr_net(addr)));
		}
		gnet_prop_set_timestamp_val(PROP_CURRENT_IP_STAMP, now);
	}

	addr = listen_addr6();
	if (!is_host_addr(old_addr_v6)) {				/* First time */
		old_addr_v6 = addr;
		if (0 == GNET_PROPERTY(current_ip6_stamp)) {
			gnet_prop_set_timestamp_val(PROP_CURRENT_IP6_STAMP, now);
		}
	}

	if (!host_addr_equal(old_addr_v6, addr)) {
		/*
		 * IPv6 address changed, update lifetime information.
		 */

		old_addr_v6 = addr;
		if (GNET_PROPERTY(current_ip6_stamp)) {
			gnet_prop_set_guint32_val(PROP_AVERAGE_IP6_UPTIME,
				get_average_ip_lifetime(now, host_addr_net(addr)));
		}
		gnet_prop_set_timestamp_val(PROP_CURRENT_IP6_STAMP, now);
	}

	/*
	 * We remember every local IP:port combination we had for some time in
	 * order to later spot alternate locations that point back to one of
	 * our recent IP:port.
	 */

	remember_local_addr_port();
}

/**
 * Compute the EMA of the averate servent uptime, up to now, but do not
 * update the property.
 */
guint32
get_average_servent_uptime(time_t now)
{
	guint32 avg;
	time_delta_t d;
	glong uptime;

	d = delta_time(now, GNET_PROPERTY(start_stamp));
	uptime = MAX(0, d);

	/*
	 * The average uptime is computed as an EMA on 7 terms.
	 * The smoothing factor sm=2/(7+1) is therefore 0.25.
	 */

	avg = GNET_PROPERTY(average_servent_uptime);
	avg += (uptime >> 2) - (avg >> 2);

	return avg;
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
	g_assert(PROP_UP_CONNECTIONS == prop);

    if (GNET_PROPERTY(up_connections) > GNET_PROPERTY(max_connections)) {
        gnet_prop_set_guint32_val(PROP_MAX_CONNECTIONS,
			GNET_PROPERTY(up_connections));
	}
    return FALSE;
}

static gboolean
max_connections_changed(property_t prop)
{
	g_assert(PROP_MAX_CONNECTIONS == prop);

    if (GNET_PROPERTY(up_connections) > GNET_PROPERTY(max_connections)) {
        gnet_prop_set_guint32_val(PROP_UP_CONNECTIONS,
			GNET_PROPERTY(max_connections));
	}
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
		addr = GNET_PROPERTY(force_local_ip)
				? GNET_PROPERTY(forced_local_ip)
				: GNET_PROPERTY(local_ip);

		if (
			!GNET_PROPERTY(force_local_ip) ||
			!GNET_PROPERTY(bind_to_forced_local_ip) ||
			!host_addr_initialized(addr)
		) {
			addr = ipv4_unspecified;
		}
		break;
	case NET_TYPE_IPV6:
		addr = GNET_PROPERTY(force_local_ip6)
				? GNET_PROPERTY(forced_local_ip6)
				: GNET_PROPERTY(local_ip6);
		if (
			!GNET_PROPERTY(force_local_ip6) ||
			!GNET_PROPERTY(bind_to_forced_local_ip6) ||
			!host_addr_initialized(addr)
		) {
			addr = ipv6_unspecified;
		}
		break;
	case NET_TYPE_LOCAL:
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
			g_assert(!s_udp_listen);
			s_udp_listen = socket_udp_listen(get_bind_addr(NET_TYPE_IPV4),
								GNET_PROPERTY(listen_port));
			if (!s_udp_listen) {
				gcu_statusbar_warning(_("Failed to create IPv4 UDP socket"));
			}
		}
		if (s_tcp_listen6) {
			g_assert(!s_udp_listen6);
			s_udp_listen6 = socket_udp_listen(get_bind_addr(NET_TYPE_IPV6),
								GNET_PROPERTY(listen_port));
			if (!s_udp_listen6) {
				gcu_statusbar_warning(_("Failed to create IPv6 UDP socket"));
			}
		}
	} else {
		/* Also takes care of freeing s_udp_listen and s_udp_listen6 */
		node_udp_disable();

		/* We have to free them anyway during startup*/
		socket_free_null(&s_udp_listen);
		socket_free_null(&s_udp_listen6);
	}
	node_update_udp_socket();

	return FALSE;
}

static gboolean
enable_dht_changed(property_t prop)
{
	gboolean enabled;
	
    gnet_prop_get_boolean_val(prop, &enabled);
	if (enabled) {
		dht_initialize(TRUE);
	} else {
		dht_close();
	}

	return FALSE;
}

static gboolean
enable_local_socket_changed(property_t prop)
{
	gboolean enabled;
	
    gnet_prop_get_boolean_val(prop, &enabled);
	if (enabled) {
		if (!s_local_listen) {
			const char *ipc_dir;

			ipc_dir = settings_ipc_dir();
			if (0 == compat_mkdir(ipc_dir, IPC_DIR_MODE) || EEXIST == errno) {
				const char *socket_path;

				socket_path = settings_local_socket_path();
				s_local_listen = socket_local_listen(socket_path);
			} else {
				g_warning("mkdir() failed: %s", g_strerror(errno));
			}

			if (!s_local_listen) {
				gcu_statusbar_warning(_("Failed to create local socket"));
			}
		}
	} else {
		socket_free_null(&s_local_listen);
	}

	return FALSE;
}

static void
request_new_sockets(guint16 port, gboolean check_firewalled)
{
	/* Also takes care of freeing s_udp_listen and s_udp_listen6 */
	node_udp_disable();

	/* We have to free them anyway during startup*/
	socket_free_null(&s_udp_listen);
	socket_free_null(&s_udp_listen6);

	/*
	 * Close sockets at the old port.
	 */

	socket_free_null(&s_tcp_listen);
	socket_free_null(&s_tcp_listen6);

	/*
	 * If the new port != 0, open the new port
	 */

	if (0 == port)
		return;

	if (
		NET_USE_BOTH == GNET_PROPERTY(network_protocol) ||
		NET_USE_IPV4 == GNET_PROPERTY(network_protocol)
	) {
		host_addr_t bind_addr = get_bind_addr(NET_TYPE_IPV4);

		s_tcp_listen = socket_tcp_listen(bind_addr, port);
		if (GNET_PROPERTY(enable_udp)) {
			g_assert(!s_udp_listen);
			s_udp_listen = socket_udp_listen(bind_addr, port);
			if (!s_udp_listen) {
				socket_free_null(&s_tcp_listen);
			}
		}
	}
	if (
		NET_USE_BOTH == GNET_PROPERTY(network_protocol) ||
		NET_USE_IPV6 == GNET_PROPERTY(network_protocol)
	) {
		host_addr_t bind_addr = get_bind_addr(NET_TYPE_IPV6);

		s_tcp_listen6 = socket_tcp_listen(bind_addr, port);
		if (GNET_PROPERTY(enable_udp)) {
			g_assert(!s_udp_listen6);
			s_udp_listen6 = socket_udp_listen(bind_addr, port);
			if (!s_udp_listen6) {
				socket_free_null(&s_tcp_listen6);
			}
		}
	}
	
	/*
	 * If UDP is enabled, also listen on the same UDP port.
	 */

	if (GNET_PROPERTY(enable_udp)) {
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

	if (
		GNET_PROPERTY(listen_port) == old_port &&
		GNET_PROPERTY(listen_port) != 0
	)
		return FALSE;
	old_port = GNET_PROPERTY(listen_port);

	/*
	 * 1 is a magic port number for us, which means "pick a random port"
	 * whereas 0 means "don't listen on any port".
	 */

	if (1 != GNET_PROPERTY(listen_port)) {
		request_new_sockets(GNET_PROPERTY(listen_port), FALSE);
	} else {
		bit_array_t tried[BIT_ARRAY_SIZE(65536)];
		guint num_tried = 0;
    	guint32 port = GNET_PROPERTY(listen_port);

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

	if (!settings_init_running) {
		inet_firewalled();
		inet_udp_firewalled();
		inet_udp_check_unsolicited();
	}

	/*
     * If socket allocation failed, reset the property
     */

    if (s_tcp_listen == NULL && GNET_PROPERTY(listen_port) != 0) {
		gcu_statusbar_warning(_("Failed to create listening sockets"));
		old_port = (guint32) -1;
        return TRUE;
    } else {
		old_port = GNET_PROPERTY(listen_port);
		remember_local_addr_port();
	}

    return FALSE;
}

static gboolean
network_protocol_changed(property_t prop)
{

	(void) prop;
	request_new_sockets(GNET_PROPERTY(listen_port), !settings_init_running);
	return FALSE;
}


static gboolean
bw_switch(property_t prop, bsched_bws_t bs)
{
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    if (val)
        bsched_enable(bs);
    else
        bsched_disable(bs);
	return FALSE;
}

static gboolean
bw_http_in_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_IN);
}

static gboolean
bw_http_out_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_OUT);
}

static gboolean
bw_gnet_in_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_GIN);
}

static gboolean
bw_gnet_out_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_GOUT);
}

static gboolean
bw_gnet_lin_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_GLIN);
}

static gboolean
bw_gnet_lout_enabled_changed(property_t prop)
{
	return bw_switch(prop, BSCHED_BWS_GLOUT);
}

static gboolean
node_sendqueue_size_changed(property_t unused_prop)
{
    guint32 min = 1.5 * settings_max_msg_size();

	(void) unused_prop;
    if (GNET_PROPERTY(node_sendqueue_size) < min) {
        gnet_prop_set_guint32_val(PROP_NODE_SENDQUEUE_SIZE, min);
        return TRUE;
    }

    return FALSE;
}

static gboolean
scan_extensions_changed(property_t prop)
{
    char *s = gnet_prop_get_string(prop, NULL, 0);

    parse_extensions(s);
    G_FREE_NULL(s);

    return FALSE;
}

static int
request_directory(const char *pathname)
{
	if (!is_absolute_path(pathname)) {
		errno = EINVAL;
		return -1;
	}

	if (is_directory(pathname))
		return 0;

	g_message("Attempt to create directory \"%s\"", pathname);

	if (0 == create_directory(pathname, DEFAULT_DIRECTORY_MODE))
		return 0;

	g_message("Attempt failed: \"%s\"", g_strerror(errno));
	return -1;
}

static gboolean
file_path_changed(property_t prop)
{
    char *pathname;

	pathname = gnet_prop_get_string(prop, NULL, 0);
	request_directory(pathname);
    G_FREE_NULL(pathname);
    return FALSE;
}

static gboolean
save_file_path_changed(property_t prop)
{
	static char *old_path;
	char *path;

	path = gnet_prop_get_string(prop, NULL, 0);

	if (GNET_PROPERTY(lockfile_debug)) {
		g_message("save_file_path_change(): path=\"%s\"\n\told_path=\"%s\"",
			NULL_STRING(path), NULL_STRING(old_path));
	}

	if (
		!is_null_or_empty(path) &&
		(NULL == old_path || 0 != strcmp(path, old_path))
	) {
		gboolean failure = FALSE;

		if (request_directory(path)) {
			failure = TRUE;
		} else if (settings_ensure_unique_save_file_path()) {
			failure = TRUE;
			gcu_statusbar_warning(
				"Save path already used by another gtk-gnutella!");
		}
		if (failure) {
			g_warning(
				"not changing save file path to \"%s\", keeping old \"%s\"",
					path, NULL_STRING(old_path));
			gnet_prop_set_string(prop, old_path);
			G_FREE_NULL(path);
			return TRUE; /* Force changed value */
		}
	}
	
	G_FREE_NULL(old_path);
	old_path = path;
	return FALSE;
}

static gboolean
shared_dirs_paths_changed(property_t prop)
{
    char *s = gnet_prop_get_string(prop, NULL, 0);
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
    char *s = gnet_prop_get_string(prop, NULL, 0);

    parse_netmasks(s);
    G_FREE_NULL(s);

    return FALSE;
}

static gboolean
hard_ttl_limit_changed(property_t prop)
{
	g_assert(PROP_HARD_TTL_LIMIT == prop);

    if (GNET_PROPERTY(hard_ttl_limit) < GNET_PROPERTY(max_ttl)) {
        gnet_prop_set_guint32_val(PROP_MAX_TTL, GNET_PROPERTY(hard_ttl_limit));
	}
    return FALSE;
}

static gboolean
max_ttl_changed(property_t prop)
{
	g_assert(PROP_MAX_TTL == prop);

    if (GNET_PROPERTY(hard_ttl_limit) < GNET_PROPERTY(max_ttl)) {
        gnet_prop_set_guint32_val(PROP_HARD_TTL_LIMIT, GNET_PROPERTY(max_ttl));
	}
    return FALSE;
}

static gboolean
bw_http_in_changed(property_t prop)
{
    guint32 val;

	g_assert(PROP_BW_HTTP_IN == prop);
    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_IN, val);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

    return FALSE;
}

static gboolean
bw_http_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_OUT, val);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

    return FALSE;
}

static gboolean
bw_gnet_in_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_GIN, val / 2);
    bsched_set_bandwidth(BSCHED_BWS_GIN_UDP, val / 2);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

    return FALSE;
}

static gboolean
bw_gnet_out_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_GOUT, val / 2);
    bsched_set_bandwidth(BSCHED_BWS_GOUT_UDP, val / 2);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

    return FALSE;
}

static gboolean
bw_gnet_lin_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_GLIN, val);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

    return FALSE;
}

static gboolean
bw_gnet_lout_changed(property_t prop)
{
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    bsched_set_bandwidth(BSCHED_BWS_GLOUT, val);
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

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
zalloc_always_gc_changed(property_t prop)
{
	gboolean val;

	gnet_prop_get_boolean_val(prop, &val);
	set_zalloc_always_gc(val);

    return FALSE;
}

static gboolean
zalloc_debug_changed(property_t prop)
{
	guint32 val;

	gnet_prop_get_guint32_val(prop, &val);
	set_zalloc_debug(val);

    return FALSE;
}

static gboolean
palloc_debug_changed(property_t prop)
{
	guint32 val;

	gnet_prop_get_guint32_val(prop, &val);
	set_palloc_debug(val);

    return FALSE;
}

static gboolean
lib_debug_changed(property_t prop)
{
	guint32 val;

	gnet_prop_get_guint32_val(prop, &val);
	set_library_debug(val);

    return FALSE;
}

static gboolean
lib_stats_changed(property_t prop)
{
	guint32 val;

	gnet_prop_get_guint32_val(prop, &val);
	set_library_stats(val);

    return FALSE;
}

static gboolean
forced_local_ip_changed(property_t prop)
{
	(void) prop;
	if (GNET_PROPERTY(force_local_ip) || GNET_PROPERTY(force_local_ip6)) {
		update_address_lifetime();
		request_new_sockets(GNET_PROPERTY(listen_port), !settings_init_running);
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
		host_addr_is_ipv4_mapped(addr) ||
		NET_TYPE_IPV6 == net
	) {
		GSList *sl_addrs, *sl;
		host_addr_t old_addr = addr;

		addr = zero_host_addr;
		sl_addrs = host_addr_get_interface_addrs(net);
		for (sl = sl_addrs; NULL != sl; sl = g_slist_next(sl)) {
			host_addr_t *addr_ptr;

			addr_ptr = sl->data;
			if (host_addr_is_routable(*addr_ptr)) {
				addr = *addr_ptr;
				break;
			}
		}
		host_addr_free_interface_addrs(&sl_addrs);
		if (!host_addr_equal(old_addr, addr)) {
			gnet_prop_set_ip_val(prop, addr);
		}
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
		if (GNET_PROPERTY(is_firewalled)) {
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
	(void) prop;

	node_current_peermode_changed(GNET_PROPERTY(current_peermode));
	bsched_set_peermode(GNET_PROPERTY(current_peermode));

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

static cevent_t *ev_file_descriptor_shortage;
static cevent_t *ev_file_descriptor_runout;

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
	cevent_t **ev = NULL;

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
        save_file_path_changed,
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
        PROP_ZALLOC_DEBUG,
        zalloc_debug_changed,
        TRUE
    },
    {
        PROP_PALLOC_DEBUG,
        palloc_debug_changed,
        TRUE
    },
    {
        PROP_LIB_DEBUG,
        lib_debug_changed,
        TRUE
    },
    {
        PROP_LIB_STATS,
        lib_stats_changed,
        TRUE
    },
    {
        PROP_ZALLOC_ALWAYS_GC,
        zalloc_always_gc_changed,
        TRUE
    },
	{
		PROP_FORCE_LOCAL_IP,
		forced_local_ip_changed,
		TRUE,
	},
	{
		PROP_FORCE_LOCAL_IP6,
		forced_local_ip_changed,
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
		PROP_BIND_TO_FORCED_LOCAL_IP,
		forced_local_ip_changed,
		TRUE,
	},
	{
		PROP_BIND_TO_FORCED_LOCAL_IP6,
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
	{
		PROP_ENABLE_DHT,
		enable_dht_changed,
		FALSE,
	},
	{
		PROP_ENABLE_LOCAL_SOCKET,
		enable_local_socket_changed,
		TRUE,
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
    unsigned n;

    for (n = 0; n < GNET_PROPERTY_NUM; n ++)
        init_list[n] = FALSE;

    if (GNET_PROPERTY(dbg) >= 2) {
        printf("settings_callbacks_init: property_map size: %u\n",
            (guint) PROPERTY_MAP_SIZE);
    }

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        property_t prop = property_map[n].prop;
        guint32 idx = prop - GNET_PROPERTY_MIN;

        if (init_list[idx]) {
            g_error("settings_callbacks_init: property %u already mapped", n);
		}

		init_list[idx] = TRUE;
        if (property_map[n].cb) {
            gnet_prop_add_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init);
        } else if (GNET_PROPERTY(dbg) >= 10) {
            printf("settings_callbacks_init: property ignored: %s\n",
				gnet_prop_name(prop));
        }
    }

    if (GNET_PROPERTY(dbg) >= 1) {
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

	cq_cancel(callout_queue, &ev_file_descriptor_shortage);
	cq_cancel(callout_queue, &ev_file_descriptor_runout);

    for (n = 0; n < PROPERTY_MAP_SIZE; n ++) {
        if (property_map[n].cb) {
            gnet_prop_remove_prop_changed_listener(
                property_map[n].prop,
                property_map[n].cb);
        }
    }
}

/* vi: set ts=4 sw=4 cindent: */
