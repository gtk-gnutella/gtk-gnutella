/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * UDP Host Cache.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "gnutella.h"
#include "guid.h"
#include "hcache.h"
#include "hosts.h"
#include "nodes.h"
#include "pcache.h"
#include "sockets.h"
#include "udp.h"
#include "uhc.h"

#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"
#include "if/core/settings.h"

#include "lib/override.h"		/* Must be the last header included */

#define UHC_MAX_ATTEMPTS 3		/**< Maximum connection / resolution attempts */
#define UHC_TIMEOUT		 20000	/**< Host cache timeout, milliseconds */
#define UHC_RETRY_AFTER	 3600	/**< Frequency of contacts for an UHC (secs) */

/**
 * Request context, used when we decide to get hosts via the UDP host caches.
 *
 * It keeps track of the amount of messages we sent, and which GUID we used
 * in the pings.
 */
static struct uhc_context {
	const gchar *host;			/**< Last selected host (string atom) */
	cevent_t *timeout_ev;		/**< Ping timeout */
	gint attempts;				/**< Connection / resolution attempts */
	host_addr_t addr;			/**< Resolved IP address for host */
	guint16 port;				/**< Port of selected host cache */
	gchar muid[GUID_RAW_SIZE];	/**< MUID of the ping */
} uhc_ctx;

static GList *uhc_avail;	/**< List of UHCs as string */
static GList *uhc_used;		/**< List of used UHCs as ``struct used_uhc'' */

struct used_uhc {
	const gchar	*host;	/**< An UHC host as "<host>:<port>" (string atom) */
	time_t		stamp;	/**< Timestamp of the last request */
};

/**
 * The following hosts are there for bootstrapping purposes only.
 */
static const struct {
	const gchar *uhc;
} boot_hosts[] = {
	{ "g6.6dns.org:1337" },
	{ "guruz.udp-host-cache.com:6666" },
	{ "secondary.udp-host-cache.com:9999" },
	{ "uhc.udp-host-cache.com:9999" },
	{ "uhc2.limewire.com:20181" },
	{ "void.ghostwhitecrab.de:443" },
	{ "yang.cloud.bishopston.net:33558" },
	{ "yin.cloud.bishopston.net:33558" },
};

static gboolean uhc_connecting = FALSE;

static void uhc_host_resolved(const host_addr_t *addr, size_t n,
				gpointer uu_udata);

/**
 * Parse hostname:port and return the hostname and port parts.
 *
 * @param hp	host:port string
 * @param host	where the pointer to the hostname is returned (static data)
 * @param port	where the port is written to
 *
 * @return TRUE if we successfully parsed the string.
 */
static gboolean
uhc_get_host_port(const gchar *hp, const gchar **host, guint16 *port)
{
	static gchar hostname[MAX_HOSTLEN + 1];
	const gchar *ep;
	guint32 u;
	gint error;
	size_t len;


	g_assert(hp);
	g_assert(host);
	g_assert(port);

	*host = NULL;
	*port = 0;

	if (!string_to_host_or_addr(hp, &ep, NULL) || ':' != *ep)
		return FALSE;

	len = ep - hp;
	if (len >= sizeof hostname)
		return FALSE;
	memcpy(hostname, hp, len);
	hostname[len] = '\0';

	g_assert(':' == *ep);
	ep++;

	u = parse_uint32(ep, NULL, 10, &error);
	if (error || u < 1 || u > 0xffff)
		return FALSE;

	*host = hostname;			/* Static data! */
	*port = u;

	return TRUE;
}

static void
add_available_uhc(const gchar *hc)
{
	const gchar *host;

	g_assert(hc);

	host = atom_str_get(hc);
	uhc_avail = random_value(100) < 50
		? g_list_append(uhc_avail, deconstify_gchar(host))
		: g_list_prepend(uhc_avail, deconstify_gchar(host));
}

static struct used_uhc *
used_uhc_new(const gchar *host)
{
	struct used_uhc *uu;

	g_assert(host);
	uu = g_malloc(sizeof *uu);
	uu->host = atom_str_get(host);
	uu->stamp = tm_time();
	return uu;
}

static void
used_uhc_free(struct used_uhc **ptr)
{
	if (*ptr) {	
		struct used_uhc *uu = *ptr;
		atom_str_free_null(&uu->host);
		G_FREE_NULL(uu);
		*ptr = NULL;
	}
}

/**
 * Pick host at random among the host array.
 *
 * @return TRUE if OK.
 */
static gboolean
uhc_pick(void)
{
	gchar *hc;
	size_t len;
	guint idx;
	time_t now = tm_time();

	/* First check whether used UHCs can added back */
	while (uhc_used) {
		struct used_uhc *uu;

		uu = uhc_used->data;
		g_assert(uu);

		/*
		 * Wait UHC_RETRY_AFTER secs before contacting the UHC again.
		 * Can't be too long because the UDP reply may get lost if the
		 * requesting host already has a saturated b/w.
		 * If we come here, it's because we're lacking hosts for establishing
		 * a Gnutella connection, after we exhausted our caches.
		 */

		if (delta_time(now, uu->stamp) < UHC_RETRY_AFTER)
			break;

		add_available_uhc(uu->host);
		uhc_used = g_list_remove(uhc_used, uu);
		used_uhc_free(&uu);
	}

	len = g_list_length(uhc_avail);
	if (len < 1) {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("BOOT ran out of UHCs");
		return FALSE;
	}

	idx = random_value(len - 1);
	hc = g_list_nth_data(uhc_avail, idx);
	g_assert(hc);

	uhc_avail = g_list_remove(uhc_avail, hc);
	uhc_used = g_list_append(uhc_used, used_uhc_new(hc));

	if (!uhc_get_host_port(hc, &uhc_ctx.host, &uhc_ctx.port)) {
		g_warning("cannot parse UDP host cache \"%s\"", hc);
		return FALSE;
	}

	/*
	 * Give GUI feedback.
	 */
	{
		gchar msg[256];

		gm_snprintf(msg, sizeof msg, _("Looking for UDP host cache %s"), hc);
		gcu_statusbar_message(msg);
	}

	return TRUE;
}

/**
 * Try a random host cache.
 */
static void
uhc_try_random(void)
{
	g_assert(uhc_connecting);
	g_assert(uhc_ctx.timeout_ev == NULL);

	if (uhc_ctx.attempts >= UHC_MAX_ATTEMPTS || !uhc_pick()) {
		uhc_connecting = FALSE;
		return;
	}
	uhc_ctx.attempts++;

	/*
	 * The following may recurse if resolution is synchronous, but
	 * we're protected by the `attempts' counter.
	 */

	(void) adns_resolve(uhc_ctx.host, settings_dns_net(),
				uhc_host_resolved, NULL);
}

/**
 * Callout queue callback, invoked when the ping was sent and we did not
 * get a reply within the specified timeout.
 */
static void
uhc_ping_timeout(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (GNET_PROPERTY(bootstrap_debug))
		g_warning("no reply from UDP host cache %s:%u",
			uhc_ctx.host, uhc_ctx.port);

	uhc_ctx.timeout_ev = NULL;
	uhc_try_random();
}

/**
 * Send an UDP ping to the host cache.
 */
static void
uhc_send_ping(void)
{
	g_assert(uhc_connecting);

	guid_random_muid(uhc_ctx.muid);	

	if (udp_send_ping(uhc_ctx.muid, uhc_ctx.addr, uhc_ctx.port, TRUE)) {

		if (GNET_PROPERTY(bootstrap_debug))
			g_message("BOOT sent UDP SCP ping %s to %s:%u",
				guid_hex_str(uhc_ctx.muid), uhc_ctx.host, uhc_ctx.port);
		/*
		 * Give GUI feedback.
		 */
		{
			gchar msg[256];

			gm_snprintf(msg, sizeof msg,
				_("Sent ping to UDP host cache %s:%u"),
				uhc_ctx.host, uhc_ctx.port);
			gcu_statusbar_message(msg);
		}

		/*
		 * Arm a timer to see whether we should not try to ping another
		 * host cache if we don't get a timely reply.
		 */

		g_assert(uhc_ctx.timeout_ev == NULL);

		uhc_ctx.timeout_ev = cq_insert(callout_queue,
				UHC_TIMEOUT, uhc_ping_timeout, NULL);
	} else {
		g_message("BOOT failed to send UDP SCP to %s",
			host_addr_port_to_string(uhc_ctx.addr, uhc_ctx.port));
	}
}

/**
 * Callback for adns_resolve(), invoked when the resolution is complete.
 */
static void
uhc_host_resolved(const host_addr_t *addrs, size_t n, gpointer uu_udata)
{
	(void) uu_udata;
	g_assert(addrs);

	/*
	 * If resolution failed, try again if possible.
	 */

	if (0 == n) {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("could not resolve UDP host cache \"%s\"",
				uhc_ctx.host);

		uhc_try_random();
		return;
	}

	uhc_ctx.addr = addrs[random_raw() % n];
	
	if (GNET_PROPERTY(bootstrap_debug))
		g_message("BOOT UDP host cache \"%s\" resolved to %s",
			uhc_ctx.host, host_addr_to_string(uhc_ctx.addr));


	/*
	 * Now send the ping.
	 */

	uhc_send_ping();
}

/**
 * Check whether we're waiting for some UDP host cache pongs.
 */
gboolean
uhc_is_waiting(void)
{
	return uhc_connecting;
}

/**
 * Get more hosts to connect to from UDP host caches, asynchronously.
 */
void
uhc_get_hosts(void)
{
	/*
	 * Make sure we don't probe host caches more than once at a time.
	 * Ancient versions are denied the right to contact host caches and
	 * must find out hosts another way.
	 */

	if (uhc_connecting || GNET_PROPERTY(ancient_version))
		return;

	if (!udp_active())
		return;

	/*
	 * Reset context.
	 */

	uhc_connecting = TRUE;
	uhc_ctx.attempts = 0;

	g_assert(uhc_ctx.timeout_ev == NULL);

	/*
	 * Pick a random host.
	 */

	uhc_try_random();
}

/**
 * Called when a pong with an "IPP" extension was received.
 */
void
uhc_ipp_extract(gnutella_node_t *n, const gchar *payload, gint paylen)
{
	gint i, cnt;

	g_assert(0 == paylen % 6);

	cnt = paylen / 6;

	if (GNET_PROPERTY(bootstrap_debug))
		g_message("extracting %d host%s in UDP IPP pong %s from %s (%s)",
			cnt, cnt == 1 ? "" : "s",
			guid_hex_str(gnutella_header_get_muid(&n->header)), node_addr(n),
			uhc_connecting ? "expected" : "unsollicited");

	for (i = 0; i < cnt; i++) {
		host_addr_t ha;
		guint16 port;

		ha = host_addr_peek_ipv4(&payload[i * 6]);
		port = peek_le16(&payload[i * 6 + 4]);

		hcache_add_caught(HOST_ULTRA, ha, port, "UDP-HC");

		if (GNET_PROPERTY(bootstrap_debug) > 1)
			g_message("BOOT collected %s from UDP IPP pong from %s",
				host_addr_to_string(ha), node_addr(n));
	}

	if (!uhc_connecting)
		return;

	/*
	 * Check whether this was a reply from our request.
	 *
	 * The reply could come well after we decided it timed out and picked
	 * another UDP host cache, which ended-up replying, so we must really
	 * check whether we're still in a probing cycle.
	 */

	if (!guid_eq(uhc_ctx.muid, gnutella_header_get_muid(&n->header)))
		return;

	if (GNET_PROPERTY(bootstrap_debug)) {
		g_message("BOOT UDP cache \"%s\" replied: got %d host%s from %s",
			uhc_ctx.host, cnt, cnt == 1 ? "" : "s", node_addr(n));
	}

	/*
	 * Terminate the probing cycle if we got hosts.
	 */

	if (cnt > 0) {
		gchar msg[256];

		cq_cancel(callout_queue, &uhc_ctx.timeout_ev);
		uhc_connecting = FALSE;

		gm_snprintf(msg, sizeof(msg),
			NG_("Got %d host from UDP host cache %s",
				"Got %d hosts from UDP host cache %s",
				cnt),
			cnt, uhc_ctx.host);

		gcu_statusbar_message(msg);
	} else {
		uhc_try_random();
	}
}

/**
 * Initializations.
 */
void
uhc_init(void)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS(boot_hosts); i++) {
		const gchar *host, *ep, *uhc;
		guint16 port;

		uhc = boot_hosts[i].uhc;

		/* Some consistency checks */
		uhc_get_host_port(uhc, &host, &port);
		g_assert(NULL != host);
		g_assert(0 != port);

		ep = is_strprefix(uhc, host);
		g_assert(NULL != ep);
		g_assert(':' == ep[0]);

		add_available_uhc(uhc);
	}
}

/**
 * Cleanup during process termination.
 */
void
uhc_close(void)
{
	cq_cancel(callout_queue, &uhc_ctx.timeout_ev);
	uhc_connecting = FALSE;
	while (uhc_avail) {
		const gchar *host = uhc_avail->data;
		uhc_avail = g_list_remove(uhc_avail, uhc_avail->data);
		atom_str_free_null(&host);
	}
	while (uhc_used) {
		struct used_uhc *uu = uhc_used->data;
		uhc_used = g_list_remove(uhc_used, uu);
		used_uhc_free(&uu);
	}
}

/* vi: set ts=4 sw=4 cindent: */
