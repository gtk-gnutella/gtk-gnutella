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
 * @file
 *
 * UDP Host Cache.
 */

#include "common.h"

RCSID("$Id$");

#include "gnutella.h"
#include "uhc.h"
#include "udp.h"
#include "nodes.h"
#include "pcache.h"
#include "hcache.h"
#include "hosts.h"

#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/hashlist.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

#define UHC_MAX_ATTEMPTS	3	/* Maximum connection / resolution attempts */
#define UHC_TIMEOUT			20	/* Host cache timeout, in seconds */

/*
 * Request context, used when we decide to get hosts via the UDP host caches.
 *
 * It keeps track of the amount of messages we sent, and which GUID we used
 * in the pings.
 */
static struct uhc_context {
	GHashTable *guids;			/* GUIDs we sent */
	gint attempts;				/* Connection / resolution attempts */
	const gchar *host;			/* Last selected host */
	guint32 ip;					/* Resolved IP address for host */
	guint16 port;				/* Port of selected host cache */
	gpointer timeout_ev;		/* Ping timeout */
} uhc_ctx;

/*
 * The following hosts are there for bootstrapping purposes only.
 */

static const gchar * const boot_hosts[] = {
	"galvatron.dyndns.org:59009",
	"kisama.ath.cx:8080",
	"krill.shacknet.nu:20095",
	"starscream.dynalias.com:80",
};

static gboolean uhc_connecting = FALSE;

static void uhc_host_resolved(guint32 ip, gpointer uu_udata);

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
	gchar *q = hostname;
	gchar *end = hostname + sizeof(hostname);
	gchar *p;
	gchar c;
	gint iport;
	
	p = (gchar *) hp;
	while ((c = *p++) && q < end) {
		if (c == ':') {
			*q++ = '\0';
			break;
		}
		*q++ = c;
	}
	hostname[MAX_HOSTLEN] = '\0';

	if (c != ':')
		return FALSE;			/* No port! */

	if (1 != sscanf(p, "%u", &iport))
		return FALSE;

	*host = hostname;			/* Static data! */
	*port = iport;

	return TRUE;
}

/**
 * Pick host at random among the host array.
 *
 * @return TRUE if OK.
 */
static gboolean
uhc_pick(void)
{
	gint idx;
	const gchar *hc;
	gchar msg[256];

	idx = random_value(G_N_ELEMENTS(boot_hosts) - 1);
	hc = boot_hosts[idx];

	if (!uhc_get_host_port(hc, &uhc_ctx.host, &uhc_ctx.port)) {
		g_warning("cannot parse UDP host cache \"%s\"", hc);
		return FALSE;
	}

	/*
	 * Give GUI feedback.
	 */

	gm_snprintf(msg, sizeof(msg), _("Looking for UDP host cache %s"), hc);
	gcu_statusbar_message(msg);

	return TRUE;
}

/**
 * Free GUID atoms held in hash table.	-- foreach() callback
 */
static gboolean
uhc_guid_free(gpointer key, gpointer uu_data, gpointer uu_user)
{
	(void) uu_user;
	(void) uu_data;

	atom_guid_free(key);
	return TRUE;
}

/**
 * Reset the list of ping GUIDs.
 */
static void
uhc_guid_reset(void)
{
	g_hash_table_foreach_remove(uhc_ctx.guids, uhc_guid_free, NULL);
}

/**
 * Try a random host cache.
 */
static void
uhc_try_random()
{
	g_assert(uhc_connecting);
	g_assert(uhc_ctx.timeout_ev == NULL);

	if (uhc_ctx.attempts++ >= UHC_MAX_ATTEMPTS || !uhc_pick()) {
		uhc_connecting = FALSE;
		return;
	}

	/*
	 * The following may recurse if resolution is synchronous, but
	 * we're protected by the `attempts' counter.
	 */

	(void) adns_resolve(uhc_ctx.host, uhc_host_resolved, NULL);
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

	if (gwc_debug)
		g_warning("no reply from UDP host cache %s:%u",
			uhc_ctx.host, uhc_ctx.port);

	uhc_ctx.timeout_ev = NULL;
	uhc_try_random();
}

/**
 * Send an UDP ping to the host cache.
 */
static void
uhc_send_ping(guint32 ip, guint16 port)
{
	struct gnutella_msg_init *m;
	struct gnutella_node *n = node_udp_get_ip_port(ip, port);
	guint32 size;
	gchar *muid;
	gchar msg[256];

	g_assert(uhc_connecting);

	m = build_ping_msg(NULL, 1, TRUE, &size);
	muid = atom_guid_get(m->header.muid);
	udp_send_msg(n, m, size);

	/*
	 * Save the GUID of the ping we sent, to be able to determine when
	 * we get a reply from our queries.
	 */

	if (g_hash_table_lookup(uhc_ctx.guids, muid))
		g_warning("GUID random number generator is weak");
	else
		g_hash_table_insert(uhc_ctx.guids, muid, GUINT_TO_POINTER(1));

	if (gwc_debug)
		g_message("sent UDP SCP ping %s to %s",
			guid_hex_str(muid), ip_port_to_gchar(ip, port));

	/*
	 * Give GUI feedback.
	 */

	gm_snprintf(msg, sizeof(msg), _("Sent ping to UDP host cache %s:%u"),
		uhc_ctx.host, uhc_ctx.port);
	gcu_statusbar_message(msg);

	/*
	 * Arm a timer to see whether we should not try to ping another
	 * host cache if we don't get a timely reply.
	 */

	g_assert(uhc_ctx.timeout_ev == NULL);

	uhc_ctx.timeout_ev = cq_insert(callout_queue,
		UHC_TIMEOUT * 1000, uhc_ping_timeout, NULL);
}

/**
 * Callback for adns_resolve(), invoked when the resolution is complete.
 */
static void
uhc_host_resolved(guint32 ip, gpointer uu_udata)
{
	(void) uu_udata;

	/*
	 * If resolution failed, try again if possible.
	 */

	if (ip == 0 || !host_is_valid(ip, uhc_ctx.port)) {
		if (gwc_debug)
			g_warning("could not resolve UDP host cache \"%s\"",
				uhc_ctx.host);

		uhc_try_random();
		return;
	}

	if (gwc_debug)
		g_message("UDP host cache \"%s\" resolved to %s",
			uhc_ctx.host, ip_to_gchar(ip));

	uhc_ctx.ip = ip;

	/*
	 * Now send the ping.
	 */

	uhc_send_ping(uhc_ctx.ip, uhc_ctx.port);
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

	if (uhc_connecting || ancient_version)
		return;

	if (!enable_udp)
		return;

	/*
	 * Reset context.
	 */

	uhc_connecting = TRUE;
	uhc_ctx.attempts = 0;
	uhc_guid_reset();

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
	const gchar *p;
	gint i;
	gint cnt;
	gboolean replied = FALSE;

	g_assert(0 == paylen % 6);

	cnt = paylen / 6;

	if (gwc_debug)
		g_message("extracting %d host%s in UDP IPP pong %s from %s (%s)",
			cnt, cnt == 1 ? "" : "s", 
			guid_hex_str(n->header.muid), node_ip(n),
			uhc_connecting ? "expected" : "unsollicited");

	for (i = 0, p = payload; i < cnt; i++) {
		guint32 ip;
		guint16 port;

		READ_GUINT32_BE(p, ip);
		p += 4;
		READ_GUINT16_LE(p, port);
		p += 2;

		hcache_add_caught(HOST_ULTRA, ip, port, "UDP-HC");
	}

	/*
	 * Check whether this was a reply from our request.
	 *
	 * The reply could come well after we decided it timed out and picked
	 * another UDP host cache, which ended-up replying, so we must really
	 * check whether we're still in a probing cycle.
	 */

	if (uhc_connecting && g_hash_table_lookup(uhc_ctx.guids, n->header.muid)) {
		g_assert(uhc_ctx.timeout_ev != NULL);

		if (gwc_debug)
			g_message("UDP cache \"%s\" (%s) replied: got %d host%s from %s",
				uhc_ctx.host, ip_port_to_gchar(uhc_ctx.ip, uhc_ctx.port),
				cnt, cnt == 1 ? "" : "s", node_ip(n));

		/*
		 * Terminate the probing cycle if we got hosts.
		 */

		if (cnt) {
			replied = TRUE;
			cq_cancel(callout_queue, uhc_ctx.timeout_ev);
			uhc_ctx.timeout_ev = NULL;
			uhc_connecting = FALSE;
		} else
			uhc_try_random();
	}

	/*
	 * Display GUI feedback, if we got a sollicited reply.
	 */

	if (replied) {
		gchar msg[256];

		if (cnt == 1)
			gm_snprintf(msg, sizeof(msg),
				_("Got %d host from UDP host cache %s:%u"),
				cnt, uhc_ctx.host, uhc_ctx.port);
		else
			gm_snprintf(msg, sizeof(msg),
				_("Got %d hosts from UDP host cache %s:%u"),
				cnt, uhc_ctx.host, uhc_ctx.port);

		gcu_statusbar_message(msg);
	}
}

/**
 * Initializations.
 */
void
uhc_init(void)
{
	uhc_ctx.guids = g_hash_table_new(guid_hash, guid_eq);
}

/**
 * Cleanup during process termination.
 */
void
uhc_close(void)
{
	uhc_guid_reset();
	g_hash_table_destroy(uhc_ctx.guids);

	if (uhc_ctx.timeout_ev)
		cq_cancel(callout_queue, uhc_ctx.timeout_ev);

	uhc_connecting = FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
