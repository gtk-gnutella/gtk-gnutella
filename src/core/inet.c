/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Internet status.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$");

#include "inet.h"
#include "nodes.h"				/* For node_become_firewalled() */
#include "sockets.h"
#include "settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/cq.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/***
 *** Firewall status management structures.
 ***/

/*
 * For firewalled (FW) servents, we normally don't send pongs for ourselves.
 * Except during startup time, and periodically every hour.  The idea is that
 * by sending pongs, we can perhaps get an incoming Gnet connection that will
 * prove us we're not firewalled.
 */

#define FW_STARTUP_GRACE		300		/**< Startup period: we send pongs */
#define FW_GRACE_INTERVAL		3600	/**< Every hour, new grace period */
#define FW_PERIODIC_GRACE		120		/**< We send pongs for 2 minutes */
#define FW_INCOMING_WINDOW		3600	/**< Incoming monitoring window */
#define FW_SOLICITED_WINDOW		3600	/**< Solicited UDP monitoring window */

static time_t fw_time = 0;				/**< When we last became firewalled */

/*
 * To detect switching from firewalled -> non-firewalled, we use incoming
 * connections (checking done in socket_accept()).
 *
 * To detect switching from non-firewalled -> firewalled, we arm a timer
 * each time we get an incoming connection.  If we don't get another
 * connection before the timer expires, we might have switched to firewalled
 * mode.
 */

static gpointer incoming_ev = NULL;			/**< Callout queue timer */
static gpointer incoming_udp_ev = NULL;		/**< Idem */
static gpointer solicited_udp_ev = NULL;	/**< Idem */

/*
 * Unfortunately, to accurately detect true unsolicited UDP traffic, we have
 * to keep a table listing all the IP addresses to whom we've recently
 * sent traffic, in the last FW_UDP_WINDOW seconds.  We don't consider ports,
 * only IPs.
 */

#define FW_UDP_WINDOW			120		/**< 2 minutes, in most firewalls */

static GHashTable *outgoing_udp = NULL;		/**< Maps "IP" => "ip_record" */

struct ip_record {
	host_addr_t addr;			/**< The IP address to which we sent data */
	gpointer timeout_ev;		/**< The expiration time for the fw breach */
};

/***
 *** External connection status management structures.
 ***/

/*
 * In order to determine whether we're successfully connected to the Internet,
 * we look whether we make at least one connection to the Internet within a
 * monitoring window.  If we can't get a connection, then we're probably no
 * longer connected.
 */

#define OUTGOING_WINDOW		150			/**< Outgoing monitoring window */

static guint32 activity_seen = 0;		/**< Activity recorded in period */
static gpointer outgoing_ev = NULL;		/**< Callout queue timer */

static void inet_set_is_connected(gboolean val);

/**
 * Create a new ip_record structure.
 */
static struct ip_record *
ip_record_make(const host_addr_t addr)
{
	struct ip_record *ipr;

	ipr = walloc(sizeof *ipr);

	ipr->addr = addr;
	ipr->timeout_ev = NULL;

	return ipr;
}

/**
 * Free ip_record structure.
 */
static void
ip_record_free(struct ip_record *ipr)
{
	if (ipr->timeout_ev)
		cq_cancel(callout_queue, ipr->timeout_ev);
	wfree(ipr, sizeof *ipr);
}

/**
 * Free ip_record structure and remove it from the `outgoing_udp' table.
 */
static void
ip_record_free_remove(struct ip_record *ipr)
{
	g_hash_table_remove(outgoing_udp, &ipr->addr);
	ip_record_free(ipr);
}

/**
 * Touch ip_record when we send a new datagram to that IP.
 */
static void
ip_record_touch(struct ip_record *ipr)
{
	g_assert(ipr->timeout_ev != NULL);

	cq_resched(callout_queue, ipr->timeout_ev, FW_UDP_WINDOW * 1000);
}

/**
 * Callout queue callback, invoked when it's time to destroy the record.
 */
static void
ip_record_destroy(cqueue_t *unused_cq, gpointer obj)
{
	struct ip_record *ipr = obj;

	(void) unused_cq;
	ipr->timeout_ev = NULL;			/* The event that fired */
	ip_record_free_remove(ipr);
}

/**
 * @returns whether ip is that of the local machine of in the same local
 * network area.
 */
static gboolean
is_local_addr(const host_addr_t addr)
{
	static host_addr_t our_addr, our_addr_v6;

	if (NET_USE_IPV4 == network_protocol || NET_USE_BOTH == network_protocol) {
		
		if (!is_host_addr(our_addr)) {
			/* This should not change */
			our_addr = name_to_single_host_addr(local_hostname(),
						NET_TYPE_IPV4);
		}
		if (!is_host_addr(our_addr))
			our_addr = listen_addr();
		if (!is_host_addr(our_addr))
			our_addr = name_to_single_host_addr("localhost", NET_TYPE_IPV4);
		if (host_addr_equal(addr, listen_addr()))	/* Ourselves */
			return TRUE;
	}
	
	if (NET_USE_IPV6 == network_protocol || NET_USE_BOTH == network_protocol) {
		if (!is_host_addr(our_addr_v6)) {
			/* This should not change */
			our_addr_v6 = name_to_single_host_addr(local_hostname(),
							NET_TYPE_IPV6);
		}
		if (!is_host_addr(our_addr_v6))
			our_addr = listen_addr6();
		if (!is_host_addr(our_addr_v6))
			our_addr = name_to_single_host_addr("localhost", NET_TYPE_IPV6);

		if (host_addr_equal(addr, listen_addr6()))	/* Ourselves */
			return TRUE;
	}

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		{
			static host_addr_t loopback;

			if (!is_host_addr(loopback))
				string_to_host_addr("127.0.0.0", NULL, &loopback);

			return	host_addr_matches(addr, loopback, 8) ||
					host_addr_matches(addr, our_addr, 24); /* Same LAN/24 */
		}
	case NET_TYPE_IPV6:
		return	host_addr_matches(addr, ipv6_link_local, 64) ||
				host_addr_matches(addr, ipv6_site_local, 64);
	case NET_TYPE_NONE:
		return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

/***
 *** Firewall status management routines.
 ***/

/**
 * Called when we enter the firewalled status (TCP).
 */
void
inet_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_FIREWALLED, TRUE);
	fw_time = tm_time();

	if (incoming_ev) {
		cq_cancel(callout_queue, incoming_ev);
		incoming_ev = NULL;
	}

	node_became_firewalled();
}

/**
 * Called when we enter the firewalled status (UDP).
 */
void
inet_udp_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_UDP_FIREWALLED, TRUE);

	if (incoming_udp_ev) {
		cq_cancel(callout_queue, incoming_udp_ev);
		incoming_udp_ev = NULL;
	}

	node_became_udp_firewalled();
}

/**
 * This is a callback invoked when no solicited UDP has been received
 * for some amount of time.  We conclude we're no longer able to get
 * solicited UDP traffic.
 */
static void
got_no_udp_solicited(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (dbg)
		printf("FW: got no solicited UDP traffic for %d secs\n",
			FW_SOLICITED_WINDOW);

	solicited_udp_ev = NULL;
	gnet_prop_set_boolean_val(PROP_RECV_SOLICITED_UDP, FALSE);
}

/**
 * Called whenever we receive solicited UDP traffic.
 */
static void
inet_udp_got_solicited(void)
{
	gnet_prop_set_boolean_val(PROP_RECV_SOLICITED_UDP, TRUE);

	if (solicited_udp_ev == NULL) {
		activity_seen++;
		cq_insert(callout_queue,
			FW_SOLICITED_WINDOW * 1000, got_no_udp_solicited, NULL);
		if (dbg)
			printf("FW: got solicited UDP traffic\n");
	} else
		cq_resched(callout_queue,
			solicited_udp_ev, FW_SOLICITED_WINDOW * 1000);
}

/**
 * This is a callback invoked when no incoming connection has been received
 * for some amount of time.  We conclude we became firewalled.
 */
static void
got_no_connection(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (dbg)
		g_message("FW: got no connection to port %u for %d secs",
			socket_listen_port(), FW_INCOMING_WINDOW);

	incoming_ev = NULL;
	inet_firewalled();
}

/**
 * This is a callback invoked when no unsolicited UDP datagrams have been
 * received for some amount of time.  We conclude we became firewalled.
 */
static void
got_no_udp_unsolicited(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (dbg)
		g_message("FW: got no unsolicited UDP datagram to port %u for %d secs",
			socket_listen_port(), FW_INCOMING_WINDOW);

	incoming_udp_ev = NULL;
	inet_udp_firewalled();
}


/**
 * Called when we have determined we are definitely not TCP-firewalled.
 */
static void
inet_not_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_FIREWALLED, FALSE);
	node_proxy_cancel_all();

	if (dbg)
		g_message("FW: we're not TCP-firewalled for port %u",
			socket_listen_port());
}

/**
 * Called when we have determined we are definitely not UDP-firewalled.
 */
static void
inet_udp_not_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_UDP_FIREWALLED, FALSE);

	if (dbg)
		g_message("FW: we're not UDP-firewalled for port %u",
			socket_listen_port());
}

/**
 * Called when we got an incoming connection from another computer at `ip'.
 */
void
inet_got_incoming(const host_addr_t addr)
{
	gboolean is_local = is_local_addr(addr);

	/*
	 * If we get an incoming connection from the outside, we're surely
	 * connected to the Internet.
	 */

	if (!is_local)
		activity_seen++;				/* In case we have a timer set */

	if (!is_inet_connected && !is_local)
		inet_set_is_connected(TRUE);

	/*
	 * If we already know we're not firewalled, we have already scheduled
	 * a callback in the future.  We need to reschedule it, since we just
	 * got an incoming connection.
	 */

	if (!is_firewalled) {
		g_assert(incoming_ev);
		cq_resched(callout_queue, incoming_ev, FW_INCOMING_WINDOW * 1000);
		return;
	}

	/*
	 * Make sure we're not connecting locally.
	 * If we're not, then we're not firewalled.
	 */

	if (!is_local)
		inet_not_firewalled();

	incoming_ev = cq_insert(
		callout_queue, FW_INCOMING_WINDOW * 1000,
		got_no_connection, NULL);
}

/**
 * Called when we got an incoming unsolicited datagram from another
 * computer at `ip'.
 *
 * i.e. the datagram was sent directly to our listening socket port,
 * and not to a masqueraded port on the firewall opened because we
 * previously sent out an UDP datagram to a host and got its reply.
 */
static void
inet_udp_got_unsolicited_incoming(void)
{
	/*
	 * If we already know we're not firewalled, we have already scheduled
	 * a callback in the future.  We need to reschedule it, since we just
	 * got an incoming connection.
	 */

	if (!is_udp_firewalled) {
		g_assert(incoming_udp_ev);
		cq_resched(callout_queue, incoming_udp_ev, FW_INCOMING_WINDOW * 1000);
		return;
	}

	inet_udp_not_firewalled();

	g_assert(incoming_udp_ev == NULL);

	incoming_udp_ev = cq_insert(
		callout_queue, FW_INCOMING_WINDOW * 1000,
		got_no_udp_unsolicited, NULL);
}

/**
 * Called when we got an incoming datagram from another computer at `ip'.
 */
void
inet_udp_got_incoming(const host_addr_t addr)
{
	gboolean is_local = is_local_addr(addr);

	if (!is_local)
		activity_seen++;				/* In case we have a timer set */

	if (!is_inet_connected && !is_local)
		inet_set_is_connected(TRUE);

	/*
	 * Make sure we're not connecting locally.
	 * If we're not, then we're not firewalled, unless we recently sent
	 * some data to that IP address.
	 */

	if (!is_local_addr(addr)) {
		gpointer ipr;

		ipr = g_hash_table_lookup(outgoing_udp, &addr);
		inet_udp_got_solicited();
		if (NULL == ipr)
			inet_udp_got_unsolicited_incoming();
	}
}

/**
 * Record that we sent an UDP datagram to some host, thereby opening a
 * breach on the firewall for the UDP reply.
 */
void
inet_udp_record_sent(const host_addr_t addr)
{
	struct ip_record *ipr;

	ipr = g_hash_table_lookup(outgoing_udp, &addr);
	if (ipr != NULL)
		ip_record_touch(ipr);
	else {
		ipr = ip_record_make(addr);
		g_hash_table_insert(outgoing_udp, &ipr->addr, ipr);
		ipr->timeout_ev = cq_insert(callout_queue, FW_UDP_WINDOW * 1000,
			ip_record_destroy, ipr);
	}
}

/**
 * Check whether we can answer a ping with a pong.
 *
 * Normally, when we're firewalled, we don't answer. However, if we have
 * a non-private IP and are within a "grace period", act as if we were not:
 * we can only know we're not firewalled when we get an incoming connection.
 */
gboolean
inet_can_answer_ping(void)
{
	gint elapsed;

	if (!is_firewalled)
		return current_peermode != NODE_P_LEAF;	/* Leaves don't send pongs */

	if (!is_host_addr(listen_addr()) && !is_host_addr(listen_addr6()))
		return FALSE;		/* We don't know our local IP, we can't reply */

	if (is_private_addr(listen_addr()) && is_private_addr(listen_addr6()))
		return FALSE;

	elapsed = delta_time(tm_time(), fw_time);	/* Since last status change */

	/*
	 * If we're close to a status change, send pongs.
	 */

	if (elapsed < FW_STARTUP_GRACE)
		return TRUE;

	/*
	 * Every FW_GRACE_INTERVAL, we also send pongs during FW_PERIODIC_GRACE.
	 */

	g_assert(FW_PERIODIC_GRACE < FW_GRACE_INTERVAL);

	if (elapsed % FW_GRACE_INTERVAL < FW_PERIODIC_GRACE)
		return TRUE;

	return FALSE;
}

/***
 *** External connection status management routines.
 ***/

/**
 * Sets our internet connection status.
 */
static void
inet_set_is_connected(gboolean val)
{
	gnet_prop_set_boolean_val(PROP_IS_INET_CONNECTED, val);

	if (dbg)
		printf("FW: we're %sconnected to the Internet\n",
			val ? "" : "no longer ");
}

/**
 * This callback is periodically called when there has been outgoing
 * connections attempted.
 */
static void
check_outgoing_connection(cqueue_t *unused_cq, gpointer unused_obj)
{
	outgoing_ev = NULL;

	(void) unused_cq;
	(void) unused_obj;

	if (activity_seen == 0)				/* Nothing over the period */
		inet_set_is_connected(FALSE);

	activity_seen = 0;
}

/**
 * Called each time we attempt a connection.
 */
void
inet_connection_attempted(const host_addr_t addr)
{
	/*
	 * Count the attempt if it's not a local connection.
	 */

	if (is_local_addr(addr))
		return;

	/*
	 * Start timer if not already done.
	 */

	if (!outgoing_ev) {
		activity_seen = 0;
		outgoing_ev = cq_insert(
			callout_queue, OUTGOING_WINDOW * 1000,
			check_outgoing_connection, NULL);
	}
}

/**
 * Called each time a connection attempt succeeds.
 */
void
inet_connection_succeeded(const host_addr_t addr)
{
	/*
	 * Count the attempt if it's not a local connection.
	 */

	if (is_local_addr(addr))
		return;

	activity_seen++;

	if (!is_inet_connected)
		inet_set_is_connected(TRUE);
}

/**
 * Called when reading activity occurred during a b/w scheduling period.
 */
void
inet_read_activity(void)
{
	activity_seen++;

	/*
	 * We're not sure activity was not with a local node, so don't
	 * call inet_set_is_connected(TRUE) at this point!
	 */
}

/**
 * Initialization code.
 */
void
inet_init(void)
{
	/*
	 * If we persisted "is_firewalled" to FALSE, arm the no-connection timer.
	 */

	if (!is_firewalled)
		incoming_ev = cq_insert(
			callout_queue, FW_INCOMING_WINDOW * 1000,
			got_no_connection, NULL);

	/*
	 * If we persisted "is_udp_firewalled" to FALSE, idem.
	 */

	if (!is_udp_firewalled)
		incoming_udp_ev = cq_insert(
			callout_queue, FW_INCOMING_WINDOW * 1000,
			got_no_udp_unsolicited, NULL);

	/*
	 * If we persisted "recv_solicited_udp" to TRUE, idem.
	 */

	if (recv_solicited_udp)
		solicited_udp_ev = cq_insert(
			callout_queue, FW_SOLICITED_WINDOW * 1000,
			got_no_udp_solicited, NULL);

	/*
	 * Initialize the table used to record outgoing UDP traffic.
	 */

	outgoing_udp = g_hash_table_new(host_addr_hash_func, host_addr_eq_func);
}

/**
 * Hash table iteration callback to free the "ip_record" structure.
 */
static void
free_ip_record(gpointer key, gpointer value, gpointer unused_udata)
{
	struct ip_record *ipr = value;

	(void) unused_udata;
	g_assert(&ipr->addr == key);
	ip_record_free(ipr);
}

/**
 * Shutdown cleanup.
 */
void
inet_close(void)
{
	g_hash_table_foreach(outgoing_udp, free_ip_record, NULL);
	g_hash_table_destroy(outgoing_udp);

	if (incoming_ev)
		cq_cancel(callout_queue, incoming_ev);
	if (incoming_udp_ev)
		cq_cancel(callout_queue, incoming_udp_ev);
	if (solicited_udp_ev)
		cq_cancel(callout_queue, solicited_udp_ev);
}

/* vi: set ts=4 sw=4 cindent: */
