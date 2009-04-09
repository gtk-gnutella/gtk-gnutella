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

RCSID("$Id$")

#include "inet.h"
#include "nodes.h"				/* For node_become_firewalled() */
#include "sockets.h"
#include "settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/aging.h"
#include "lib/cq.h"
#include "lib/tm.h"
#include "lib/wd.h"
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
 * To detect switching from non-firewalled -> firewalled, we arm a watchdog
 * each time we get an incoming connection.  If we don't get another
 * connection before the timer expires, we might have switched to firewalled
 * mode.
 */

static watchdog_t *incoming_wd;
static watchdog_t *incoming_udp_wd;
static watchdog_t *solicited_udp_wd;

/*
 * Unfortunately, to accurately detect true unsolicited UDP traffic, we have
 * to keep a table listing all the IP addresses to whom we've recently
 * sent traffic, in the last FW_UDP_WINDOW seconds.  We don't consider ports,
 * only IPs.
 */

#define FW_UDP_WINDOW			120		/**< 2 minutes, in most firewalls */

static aging_table_t *outgoing_udp;		/**< IP addresses to whom we send */

struct ip_record {
	host_addr_t addr;			/**< The IP address to which we sent data */
	cevent_t *timeout_ev;		/**< The expiration time for the fw breach */
};

/**
 * States of our small automaton to try to detect reception of unsolicited
 * messages if we do not get them naturally: there are only a few such messages
 * that can only be viewed as unsolicited.
 *
 * SO if we don't get these, we enter the mode UNSOLICITED_PREPARE in which
 * we just record the addresses of whom we send things to.  We ignore any
 * unsolicited checks for non-matching addresses at this point.  After
 * FW_UDP_WINDOW seconds have elapsed, we enter UNSOLICITED_CHECK and the
 * first time we get an unsolicited packet, we know...  At which point we
 * move back to UNSOLICTED_OFF to turn off these checks.
 */

enum solicited_states {
	UNSOLICITED_OFF = 0,
	UNSOLICITED_PREPARE,
	UNSOLICITED_CHECK
};

static enum solicited_states outgoing_udp_state = UNSOLICITED_OFF;
static cevent_t *unsolicited_udp_ev;

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

static watchdog_t *outgoing_wd;			/**< Watchdog for outgoing activity */

static void inet_set_is_connected(gboolean val);

/**
 * Checks whether a host address is considered being "local".
 *
 * @param addr The host address to check.
 * @returns TRUE if the IP address is that of the local machine or
 *			a private address. Otherwise FALSE is returned.
 */
static gboolean
is_local_addr(const host_addr_t addr)
{
	static host_addr_t our_addr, our_addr_v6;

	/* Note: DNS resolution of the hostname(s) is only attempted once per
	 *  	 session. While /etc/hosts can be corrected on the fly. It's
	 *		 unlikely that will actually happen and the resolution can
	 *		 cause blocking of several seconds which is not acceptable
	 *		 except during the startup phase.
	 */
	if (
		NET_USE_IPV4 == GNET_PROPERTY(network_protocol) ||
		NET_USE_BOTH == GNET_PROPERTY(network_protocol)
	) {
		if (!is_host_addr(our_addr)) {
			static gboolean tried;

			if (!tried) {
				tried = TRUE;
				/* This should not change */
				our_addr = name_to_single_host_addr(local_hostname(),
						NET_TYPE_IPV4);
			}
		}
		if (!is_host_addr(our_addr))
			our_addr = listen_addr();
		if (!is_host_addr(our_addr)) {
			static gboolean tried;

			if (!tried) {
				tried = TRUE;
				our_addr = name_to_single_host_addr("localhost", NET_TYPE_IPV4);
				if (!is_host_addr(our_addr)) {
					g_warning("No \"127.0.0.1 localhost\" in /etc/hosts!?!");
					our_addr = ipv4_loopback;
				}
			}
		}
	}
	
	if (
		NET_USE_IPV6 == GNET_PROPERTY(network_protocol) ||
		NET_USE_BOTH == GNET_PROPERTY(network_protocol)
	) {
		if (!is_host_addr(our_addr_v6)) {
			static gboolean tried;

			if (!tried) {
				/* This should not change */
				tried = TRUE;
				our_addr_v6 = name_to_single_host_addr(local_hostname(),
								NET_TYPE_IPV6);
			}
		}
		if (!is_host_addr(our_addr_v6))
			our_addr = listen_addr6();
		if (!is_host_addr(our_addr_v6)) {
			static gboolean tried;

			if (!tried) {
				tried = TRUE;
				our_addr = name_to_single_host_addr("localhost", NET_TYPE_IPV6);
				if (!is_host_addr(our_addr)) {
					g_warning("No \"::1 localhost\" in /etc/hosts!?!");
					our_addr = ipv6_loopback;
				}
			}
		}
	}

	if (is_my_address(addr))
		return TRUE;

	if (host_addr_equal(addr, ipv4_loopback))
		return TRUE;
	if (host_addr_equal(addr, ipv6_loopback))
		return TRUE;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
	case NET_TYPE_IPV6:
		return is_private_addr(addr);
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		return TRUE;
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
	wd_sleep(incoming_wd);
	node_became_firewalled();
}

/**
 * Called when we enter the firewalled status (UDP).
 */
void
inet_udp_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_UDP_FIREWALLED, TRUE);
	node_became_udp_firewalled();
}

/**
 * Callout queue callback.
 * Enter the UNSOLICITED_CHECK state.
 */
static void
move_to_unsolicited_check(cqueue_t *unused_cq, gpointer unused_data)
{
	(void) unused_cq;
	(void) unused_data;

	unsolicited_udp_ev = NULL;		/* Event fired */

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: will be now monitoring UDP for unsolicited messages");

	outgoing_udp_state = UNSOLICITED_CHECK;
}

/**
 * Enter the UNSOLICITED_PREPARE state.
 */
static void
move_to_unsolicited_prepare(void)
{
	if (GNET_PROPERTY(fw_debug))
		g_message("FW: set for unsolicited traffic detection in %d secs",
			FW_UDP_WINDOW);

	unsolicited_udp_ev = cq_insert(callout_queue, FW_UDP_WINDOW * 1000,
		move_to_unsolicited_check, NULL);
	outgoing_udp_state = UNSOLICITED_PREPARE;
}

/**
 * Enter the UNSOLICITED_OFF state.
 */
static void
move_to_unsolicited_off(void)
{
	if (GNET_PROPERTY(fw_debug))
		g_message("FW: turning off unsolicited traffic detection");

	outgoing_udp_state = UNSOLICITED_OFF;
	cq_cancel(callout_queue, &unsolicited_udp_ev);	/* Paranoid */
}

/**
 * This is a callback invoked when no solicited UDP has been received
 * for some amount of time.  We conclude we're no longer able to get
 * solicited UDP traffic.
 */
static gboolean
got_no_udp_solicited(watchdog_t *unused_wd, gpointer unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: got no solicited UDP traffic for %d secs",
			FW_SOLICITED_WINDOW);

	gnet_prop_set_boolean_val(PROP_RECV_SOLICITED_UDP, FALSE);
	return FALSE;			/* Disarm watchdog */
}

/**
 * Called whenever we receive solicited UDP traffic.
 */
static void
inet_udp_got_solicited(void)
{
	gnet_prop_set_boolean_val(PROP_RECV_SOLICITED_UDP, TRUE);

	if (wd_wakeup(solicited_udp_wd) && GNET_PROPERTY(fw_debug))
		g_message("FW: got solicited UDP traffic");

	wd_kick(solicited_udp_wd);
}

/**
 * This is a callback invoked when no incoming connection has been received
 * for some amount of time.  We conclude we became firewalled.
 */
static gboolean
got_no_connection(watchdog_t *unused_wd, gpointer unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: got no connection to port %u for %d secs",
			socket_listen_port(), FW_INCOMING_WINDOW);

	inet_firewalled();
	return FALSE;			/* Disarm watchdog */
}

/**
 * This is a callback invoked when no unsolicited UDP datagrams have been
 * received for some amount of time.  We conclude we became firewalled.
 */
static gboolean
got_no_udp_unsolicited(watchdog_t *unused_wd, gpointer unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: got no unsolicited UDP datagram to port %u for %d secs",
			socket_listen_port(), FW_INCOMING_WINDOW);

	/*
	 * If we are in the UNSOLICITED_OFF state, move to UNSOLICITED_PREPARE
	 * for FW_UDP_WINDOW seconds.
	 *
	 * Otherwise, move to UNSOLICITED_OFF and state we are firewalled.
	 */

	STATIC_ASSERT(FW_UDP_WINDOW < FW_SOLICITED_WINDOW);

	if (UNSOLICITED_OFF == outgoing_udp_state) {
		move_to_unsolicited_prepare();
		return TRUE;		/* Let watchdog fire again at next period */
	} else {
		if (GNET_PROPERTY(fw_debug)) {
			g_message("FW: no unsolicited UDP again for %d secs on port %u "
				"=> firewalled", FW_SOLICITED_WINDOW, socket_listen_port());
		}
		move_to_unsolicited_off();
		inet_udp_firewalled();
		return TRUE;		/* Try again to detect unsolicited at next period */
	}
}

/**
 * Called when we have determined we are definitely not TCP-firewalled.
 */
static void
inet_not_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_FIREWALLED, FALSE);
	node_proxy_cancel_all();

	if (GNET_PROPERTY(fw_debug))
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

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: we're not UDP-firewalled for port %u",
			socket_listen_port());
}

/**
 * Called when we got an incoming connection from another computer at `ip'.
 */
void
inet_got_incoming(const host_addr_t addr)
{
	if (is_local_addr(addr)) {
		if (GNET_PROPERTY(fw_debug))
			g_message("FW: not counting local connection from %s",
				host_addr_to_string(addr));
		return;
	}

	if (GNET_PROPERTY(fw_debug) > 19)
		g_message("FW: got TCP connection from %s", host_addr_to_string(addr));

	/*
	 * If we get an incoming connection from the outside, we're surely
	 * connected to the Internet.
	 */

	if (
		wd_sleep(outgoing_wd) &&
		!GNET_PROPERTY(is_inet_connected) &&
		GNET_PROPERTY(fw_debug)
	) {
		g_message("FW: got incoming connection => connected");
	}

	if (!GNET_PROPERTY(is_inet_connected))
		inet_set_is_connected(TRUE);

	/*
	 * We're not firewalled.
	 */

	if (GNET_PROPERTY(is_firewalled)) {
		wd_wakeup(incoming_wd);
		inet_not_firewalled();
	}

	wd_kick(incoming_wd);
}

/**
 * Called when we got an incoming unsolicited datagram from another computer.
 *
 * i.e. the datagram was sent directly to our listening socket port,
 * and not to a masqueraded port on the firewall opened because we
 * previously sent out an UDP datagram to a host and got its reply.
 *
 * There are some messages that we know cannot be received from UDP as
 * a reply of some sort (i.e. sent back to us through a masquerated port).
 * When we do get these messages, then this routine can be called explicitly.
 */
void 
inet_udp_got_unsolicited_incoming(void)
{
	if (outgoing_udp_state != UNSOLICITED_OFF) {
		if (GNET_PROPERTY(fw_debug))
			g_message("FW: got unsolicited UDP message => not firewalled");
		move_to_unsolicited_off();
	}

	if (GNET_PROPERTY(is_udp_firewalled))
		inet_udp_not_firewalled();

	wd_kick(incoming_udp_wd);
}

/**
 * Called when we got an incoming datagram from another computer at `ip'.
 */
void
inet_udp_got_incoming(const host_addr_t addr)
{
	if (is_local_addr(addr))
		return;

	if (
		wd_sleep(outgoing_wd) &&
		!GNET_PROPERTY(is_inet_connected) &&
		GNET_PROPERTY(fw_debug)
	) {
		g_message("FW: got incoming UDP traffic => connected");
	}

	if (!GNET_PROPERTY(is_inet_connected))
		inet_set_is_connected(TRUE);

	inet_udp_got_solicited();

	/*
	 * If checking for unsolicited traffic, then we have a match if we
	 * get a message from an IP to whom we haven't sent anything recently.
	 */

	if (
		UNSOLICITED_CHECK == outgoing_udp_state &&
		NULL == aging_lookup(outgoing_udp, &addr)
	) {
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
	if (UNSOLICITED_OFF == outgoing_udp_state)
		return;		/* Not currently monitoring for unsolicited UDP */

	if (!aging_lookup_revitalise(outgoing_udp, &addr)) {
		aging_insert(outgoing_udp,
			wcopy(&addr, sizeof addr), uint_to_pointer(1));
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
	int elapsed;

	/* Leaves don't send pongs */
	if (!GNET_PROPERTY(is_firewalled))
		return GNET_PROPERTY(current_peermode) != NODE_P_LEAF;

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

	if (GNET_PROPERTY(fw_debug))
		g_message("FW: we're %sconnected to the Internet",
			val ? "" : "no longer ");
}

/**
 * This callback fires when there was no outgoing activity for the period
 * after the watchdog was started.
 */
static gboolean
no_outgoing_connection(watchdog_t *unused_wd, gpointer unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	inet_set_is_connected(FALSE);		/* Nothing over the period */
	return FALSE;						/* Put watchdog back to sleep */
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

	wd_wakeup(outgoing_wd);
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

	if (
		wd_sleep(outgoing_wd) &&
		!GNET_PROPERTY(is_inet_connected) &&
		GNET_PROPERTY(fw_debug)
	) {
		g_message("FW: outgoing TCP connection succeeded => connected");
	}

	if (!GNET_PROPERTY(is_inet_connected))
		inet_set_is_connected(TRUE);
}

/**
 * Called when reading activity occurred during a b/w scheduling period.
 */
void
inet_read_activity(void)
{
	/*
	 * We're not sure activity was not with a local node, so don't
	 * call inet_set_is_connected(TRUE) at this point!
	 */

	wd_kick(outgoing_wd);
}

/**
 * Initialization code.
 */
void
inet_init(void)
{
	/*
	 * Monitoring watchdogs for incoming connections.
	 */

	incoming_wd = wd_make("incoming TCP connections",
		FW_INCOMING_WINDOW, got_no_connection, NULL, FALSE);

	incoming_udp_wd = wd_make("unsolicited UDP message",
		FW_INCOMING_WINDOW, got_no_udp_unsolicited, NULL, TRUE);

	solicited_udp_wd = wd_make("solicited UDP reply",
		FW_SOLICITED_WINDOW, got_no_udp_solicited, NULL, FALSE);

	/*
	 * Start the required watchdog depending on the persisted property values.
	 */

	if (!GNET_PROPERTY(is_firewalled))
		wd_wakeup(incoming_wd);

	if (GNET_PROPERTY(recv_solicited_udp))
		wd_wakeup(solicited_udp_wd);

	/*
	 * Monitoring watchdog for outgoing connections.
	 */

	outgoing_wd = wd_make("outgoing TCP connections",
		OUTGOING_WINDOW, no_outgoing_connection, NULL, FALSE);

	/*
	 * Initialize the table used to record outgoing UDP traffic.
	 */

	outgoing_udp = aging_make(FW_UDP_WINDOW,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	outgoing_udp_state = UNSOLICITED_OFF;
}

/**
 * Shutdown cleanup.
 */
void
inet_close(void)
{
	aging_destroy(&outgoing_udp);
	cq_cancel(callout_queue, &unsolicited_udp_ev);
	wd_free_null(&outgoing_wd);
	wd_free_null(&incoming_wd);
	wd_free_null(&incoming_udp_wd);
	wd_free_null(&solicited_udp_wd);
}

/* vi: set ts=4 sw=4 cindent: */
