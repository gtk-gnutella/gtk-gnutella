/*
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

#include "gnutella.h"
#include "guid.h"
#include "hcache.h"
#include "hosts.h"
#include "nodes.h"
#include "pcache.h"
#include "sockets.h"
#include "udp.h"
#include "uhc.h"
#include "ghc.h"

#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/mempcpy.h"
#include "lib/parse.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

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
	const char *host;			/**< Last selected host (static buffer) */
	cevent_t *timeout_ev;		/**< Ping timeout */
	int attempts;				/**< Connection / resolution attempts */
	host_addr_t addr;			/**< Resolved IP address for host */
	uint16 port;				/**< Port of selected host cache */
	struct guid muid;			/**< MUID of the ping */
} uhc_ctx;

static hash_list_t *uhc_list;	/**< List of ``struct uhc'' */

struct uhc {
	const char	*host;	/**< An UHC host as "<host>:<port>" (string atom) */
	time_t		stamp;	/**< Timestamp of the last request */
	uint		used;	/**< How often have we tried to contact it */
};

/**
 * The following hosts are there for bootstrapping purposes only.
 */
static const struct {
	const char *uhc;
} boot_hosts[] = {
#if defined(USE_LOCAL_UHC)
	{ "localhost:6346" },
#else	/* !USE_LOCAL_UHC */
	{ "1.uhc.gtk-gnutella.nl:19104" },
	{ "uhc.gtk-gnutella.nl:15749" },
	{ "useast.gnutella.dyslexicfish.net:3558" },
	{ "uswest.gnutella.dyslexicfish.net:3558" },
	{ "uk.gnutella.dyslexicfish.net:3558" },
#endif	/* USE_LOCAL_UHC */
};

static bool uhc_connecting = FALSE;

static void uhc_host_resolved(const host_addr_t *addr, size_t n, void *udata);
static void uhc_send_ping(void);

/**
 * Parse hostname:port and return the hostname and port parts.
 *
 * @param hp	host:port string
 * @param host	where the pointer to the hostname is returned (static data)
 * @param port	where the port is written to
 *
 * @return TRUE if we successfully parsed the string.
 */
static bool
uhc_get_host_port(const char *hp, const char **host, uint16 *port)
{
	static char hostname[MAX_HOSTLEN + 1];
	const char *ep;
	uint32 u;
	int error;
	size_t len;
	char *p;

	g_assert(hp);
	g_assert(host);
	g_assert(port);

	*host = NULL;
	*port = 0;
	hostname[0] = '\0';

	if (!string_to_host_or_addr(hp, &ep, NULL) || ':' != *ep)
		return FALSE;

	len = ep - hp;
	if (len >= sizeof hostname)
		return FALSE;
	p = mempcpy(hostname, hp, len);
	*p = '\0';

	g_assert(':' == *ep);
	ep++;

	u = parse_uint32(ep, NULL, 10, &error);
	if (error || u < 1 || u > 0xffff)
		return FALSE;

	*host = hostname;			/* Static data! */
	*port = u;

	return TRUE;
}

static struct uhc *
uhc_new(const char *host)
{
	struct uhc *uhc;

	g_assert(host != NULL);

	WALLOC0(uhc);
	uhc->host = atom_str_get(host);
	return uhc;
}

static void
uhc_free(struct uhc **ptr)
{
	if (*ptr) {	
		struct uhc *uu = *ptr;
		atom_str_free_null(&uu->host);
		WFREE(uu);
		*ptr = NULL;
	}
}

static uint
uhc_hash(const void *key)
{
	const struct uhc *uhc = key;

	return string_mix_hash(uhc->host);
}

static int
uhc_equal(const void *p, const void *q)
{
	const struct uhc *a = p, *b = q;

	return 0 == strcmp(a->host, b->host);
}


static void
uhc_list_add(const char *host)
{
	struct uhc *uhc;

	g_return_if_fail(host);

	uhc = uhc_new(host);
	if (hash_list_contains(uhc_list, uhc)) {
		g_warning("duplicate bootstrap UHC: \"%s\"", uhc->host);
		uhc_free(&uhc);
		return;
	}

	if (GNET_PROPERTY(bootstrap_debug) > 1)
		g_debug("adding UHC %s", host);
			
	if (random_value(100) < 50) {
		hash_list_append(uhc_list, uhc);
	} else {
		hash_list_prepend(uhc_list, uhc);
	}
}

/**
 * @return NULL on error, a newly allocated string via halloc() otherwise.
 */
static char *
uhc_get_next(void)
{
	struct uhc *uhc;
	char *host;
	time_t now;

	g_return_val_if_fail(uhc_list, NULL);
	
	now = tm_time();
	uhc = hash_list_head(uhc_list);
	if (NULL == uhc)
		return NULL;

	/*
	 * Wait UHC_RETRY_AFTER secs before contacting the UHC again.
	 * Can't be too long because the UDP reply may get lost if the
	 * requesting host already has a saturated b/w.
	 * If we come here, it's because we're lacking hosts for establishing
	 * a Gnutella connection, after we exhausted our caches.
	 */
	if (uhc->stamp && delta_time(now, uhc->stamp) < UHC_RETRY_AFTER)
		return NULL;

	uhc->stamp = now;
	host = h_strdup(uhc->host);

	if (uhc->used < UHC_MAX_ATTEMPTS) {
		uhc->used++;
		hash_list_moveto_tail(uhc_list, uhc);
	} else {
		hash_list_remove(uhc_list, uhc);
		uhc_free(&uhc);
	}

	return host;
}

/**
 * Pick host at random among the host array.
 *
 * @return TRUE if OK.
 */
static bool
uhc_pick(void)
{
	bool success = FALSE;
	char *uhc;

	uhc = uhc_get_next();
	if (NULL == uhc) {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("BOOT ran out of UHCs, switching to GHCs");
		ghc_get_hosts();
		goto finish;
	}

	if (!uhc_get_host_port(uhc, &uhc_ctx.host, &uhc_ctx.port)) {
		g_warning("cannot parse UDP host cache \"%s\"", uhc);
		goto finish;
	}

	/*
	 * Give GUI feedback.
	 */
	{
		char msg[256];

		str_bprintf(msg, sizeof msg, _("Looking for UDP host cache %s"), uhc);
		gcu_statusbar_message(msg);
	}
	success = TRUE;

finish:
	HFREE_NULL(uhc);
	return success;
}

/**
 * Try a random host cache.
 */
static void
uhc_try_random(void)
{
	host_addr_t addr;

	g_assert(uhc_connecting);
	g_assert(uhc_ctx.timeout_ev == NULL);

	if (!uhc_pick()) {
		uhc_connecting = FALSE;
		return;
	}

	/*
	 * The following may recurse if resolution is synchronous, but
	 * we're protected by the `attempts' counter.
	 */

	if (string_to_host_addr(uhc_ctx.host, NULL, &addr)) {
		uhc_ctx.addr = addr;
		
		if (GNET_PROPERTY(bootstrap_debug))
			g_debug("BOOT UDP host cache \"%s\"", uhc_ctx.host);

		uhc_send_ping();
	} else {
		(void) adns_resolve(uhc_ctx.host, settings_dns_net(),
					uhc_host_resolved, NULL);
	}
}

/**
 * Callout queue callback, invoked when the ping was sent and we did not
 * get a reply within the specified timeout.
 */
static void
uhc_ping_timeout(cqueue_t *cq, void *unused_obj)
{
	(void) unused_obj;

	if (GNET_PROPERTY(bootstrap_debug))
		g_warning("no reply from UDP host cache %s:%u",
			uhc_ctx.host, uhc_ctx.port);

	cq_zero(cq, &uhc_ctx.timeout_ev);
	uhc_try_random();
}

/**
 * Send an UDP ping to the host cache.
 */
static void
uhc_send_ping(void)
{
	g_assert(uhc_connecting);

	guid_random_muid(&uhc_ctx.muid);	

	if (udp_send_ping(&uhc_ctx.muid, uhc_ctx.addr, uhc_ctx.port, TRUE)) {

		if (GNET_PROPERTY(bootstrap_debug) || GNET_PROPERTY(log_uhc_pings_tx)) {
			g_debug("BOOT sent UDP SCP ping #%s to %s:%u",
				guid_hex_str(&uhc_ctx.muid), uhc_ctx.host, uhc_ctx.port);
		}

		/*
		 * Give GUI feedback.
		 */
		{
			char msg[256];

			str_bprintf(msg, sizeof msg,
				_("Sent ping to UDP host cache %s:%u"),
				uhc_ctx.host, uhc_ctx.port);
			gcu_statusbar_message(msg);
		}

		/*
		 * Arm a timer to see whether we should not try to ping another
		 * host cache if we don't get a timely reply.
		 */

		g_assert(uhc_ctx.timeout_ev == NULL);

		uhc_ctx.timeout_ev = cq_main_insert(UHC_TIMEOUT,
			uhc_ping_timeout, NULL);
	} else {
		g_warning("BOOT failed to send UDP SCP to %s",
			host_addr_port_to_string(uhc_ctx.addr, uhc_ctx.port));
	}
}

/**
 * Callback for adns_resolve(), invoked when the resolution is complete.
 */
static void
uhc_host_resolved(const host_addr_t *addrs, size_t n, void *uu_udata)
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

	if (n > 1)
	{
		size_t i;
		/* Current uhc was moved to tail by uhc_get_next */
		struct uhc *uhc = hash_list_tail(uhc_list);
		
		/*
		 * UHC resolved to multiple endpoints. Could be roundrobbin or
		 * IPv4 and IPv6 address. Adding them as seperate entries if the IPv6 is
		 * unreachable we might be retrying the IPv6 over and over again, there
		 * is no garantee that the random_u32() above will eventually pick
		 * the IPv4 address.
		 * 	-- JA 24/7/2011
		 */
		for(i = 0; i < n; i++) {	
			const char *host = host_addr_port_to_string(addrs[i], uhc_ctx.port);
			g_debug("BOOT UDP host cache \"%s\" resolved to %s",
				uhc_ctx.host, host);
			
			uhc_list_add(host);
		}
		
		hash_list_remove(uhc_list, uhc);
		uhc_try_random();
		
		return;
	}
	
	uhc_ctx.addr = addrs[0];

	
	if (GNET_PROPERTY(bootstrap_debug))
		g_debug("BOOT UDP host cache \"%s\" resolved to %s",
			uhc_ctx.host, host_addr_to_string(uhc_ctx.addr));


	/*
	 * Now send the ping.
	 */

	uhc_send_ping();
}

/**
 * Check whether we're waiting for some UDP host cache pongs.
 */
bool
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

	if (!udp_active()) {
		g_message("BOOT cannot contact UHCs (UDP inactive), using GHCs");
		ghc_get_hosts();
		return;
	}

	g_message("BOOT will be contacting an UHC");

	/*
	 * Reset context.
	 */

	uhc_connecting = TRUE;

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
uhc_ipp_extract(gnutella_node_t *n, const char *payload, int paylen,
	enum net_type type)
{
	int i, cnt;
	int len = NET_TYPE_IPV6 == type ? 18 : 6;
	const void *p;

	g_assert(0 == paylen % len);

	cnt = paylen / len;

	if (GNET_PROPERTY(bootstrap_debug))
		g_debug("extracting %d host%s in UDP IPP pong #%s from %s",
			cnt, plural(cnt),
			guid_hex_str(gnutella_header_get_muid(&n->header)), node_addr(n));

	for (i = 0, p = payload; i < cnt; i++, p = const_ptr_add_offset(p, len)) {
		host_addr_t ha;
		uint16 port;

		host_ip_port_peek(p, type, &ha, &port);
		hcache_add_caught(HOST_ULTRA, ha, port, "UDP-HC");

		if (GNET_PROPERTY(bootstrap_debug) > 2)
			g_debug("BOOT collected %s from UDP IPP pong from %s",
				host_addr_port_to_string(ha, port), node_addr(n));
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

	if (!guid_eq(&uhc_ctx.muid, gnutella_header_get_muid(&n->header)))
		return;

	if (GNET_PROPERTY(bootstrap_debug)) {
		g_debug("BOOT UDP cache \"%s\" replied: got %d host%s from %s",
			uhc_ctx.host, cnt, plural(cnt), node_addr(n));
	}

	/*
	 * Terminate the probing cycle if we got hosts.
	 */

	if (cnt > 0) {
		char msg[256];

		cq_cancel(&uhc_ctx.timeout_ev);
		uhc_connecting = FALSE;

		str_bprintf(msg, sizeof(msg),
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
G_GNUC_COLD void
uhc_init(void)
{
	uint i;

	g_return_if_fail(NULL == uhc_list);
	uhc_list = hash_list_new(uhc_hash, uhc_equal);

	for (i = 0; i < G_N_ELEMENTS(boot_hosts); i++) {
		const char *host, *ep, *uhc;
		uint16 port;

		uhc = boot_hosts[i].uhc;

		/* Some consistency checks */
		uhc_get_host_port(uhc, &host, &port);
		g_assert(NULL != host);
		g_assert(0 != port);

		ep = is_strprefix(uhc, host);
		g_assert(NULL != ep);
		g_assert(':' == ep[0]);

		uhc_list_add(uhc);
	}
}

/**
 * Cleanup during process termination.
 */
G_GNUC_COLD void
uhc_close(void)
{
	cq_cancel(&uhc_ctx.timeout_ev);
	uhc_connecting = FALSE;

	if (uhc_list) {
		struct uhc *uhc;

		while (NULL != (uhc = hash_list_shift(uhc_list))) {
			uhc_free(&uhc);
		}
		hash_list_free(&uhc_list);
	}
}

/* vi: set ts=4 sw=4 cindent: */
