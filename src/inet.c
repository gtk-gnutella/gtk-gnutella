/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Internet status.
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

#include <stdio.h>

#include "inet.h"
#include "nodes.h"		/* For node_beaome_firewalled() */
#include "settings.h"
#include "bsched.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

extern cqueue_t *callout_queue;

/***
 *** Firewall status management structures.
 ***/

/*
 * For firewalled (FW) servents, we normally don't send pongs for ourselves.
 * Except during startup time, and periodically every hour.  The idea is that
 * by sending pongs, we can perhaps get an incoming Gnet connection that will
 * prove us we're not firewalled.
 */

#define FW_STARTUP_GRACE		300		/* Startup period where we send pongs */
#define FW_GRACE_INTERVAL		3600	/* Every hour, new grace period */
#define FW_PERIODIC_GRACE		120		/* We send pongs for 2 minutes */
#define FW_INCOMING_WINDOW		3600	/* Incoming monitoring window */

static time_t fw_time = 0;				/* When we last became firewalled */

/*
 * To detect switching from firewalled -> non-firewalled, we use incoming
 * connections (checking done in socket_accept()).
 *
 * To detect switching from non-firewalled -> firewalled, we arm a timer
 * each time we get an incoming connection.  If we don't get another
 * connection before the timer expires, we might have switched to firewalled
 * mode.
 */

static gpointer incoming_ev = NULL;		/* Callout queue timer */

/***
 *** External connection status management structures.
 ***/

/*
 * In order to determine whether we're successfully connected to the Internet,
 * we look whether we make at least one connection to the Internet within a
 * monitoring window.  If we can't get a connection, then we're probably no
 * longer connected.
 */

#define OUTGOING_WINDOW		150			/* Outgoing monitoring window */

static guint32 outgoing_connected = 0;	/* Successful connections in period */
static gpointer outgoing_ev = NULL;		/* Callout queue timer */

static void inet_set_is_connected(gboolean val);

/*
 * is_local_ip
 *
 * Returns whether ip is that of the local machine of in the same local
 * network area.
 */
static gboolean is_local_ip(guint32 ip)
{
	static guint32 our_ip = 0;

	if (our_ip == 0)
		our_ip = host_to_ip(host_name());		/* This should not change */
	if (our_ip == 0)
		our_ip = listen_ip();
	if (our_ip == 0)
		our_ip = 0x7f000001;

	return
		ip == listen_ip()	||							/* Ourselves */
		(ip & 0xffffff00) == (our_ip & 0xffffff00)	||	/* Same LAN/24 */
		(ip & 0xff000000) == 0x7f000000; 				/* Loopback 127.xxx */
}

/***
 *** Firewall status management routines.
 ***/

/*
 * inet_firewalled
 *
 * Called when we enter the firewalled status.
 */
void inet_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_FIREWALLED, TRUE);
	fw_time = time(NULL);

	if (incoming_ev) {
		cq_cancel(callout_queue, incoming_ev);
		incoming_ev = NULL;
	}

	node_became_firewalled();
}

/*
 * got_no_connection
 *
 * This is a callback invoked when no incoming connection has been received
 * for some amount of time.  We conclude we became firewalled.
 */
static void got_no_connection(cqueue_t *cq, gpointer obj)
{
	if (dbg)
		printf("FW: got no connection to port %u for %d secs\n",
			listen_port, FW_INCOMING_WINDOW);

	incoming_ev = NULL;
	inet_firewalled();
}

/*
 * inet_not_firewalled
 *
 * Called when we have determined we are definitely not firewalled.
 */
static void inet_not_firewalled(void)
{
	gnet_prop_set_boolean_val(PROP_IS_FIREWALLED, FALSE);

	if (dbg)
		printf("FW: we're not firewalled for port %u\n", listen_port);
}

/*
 * inet_got_incoming
 *
 * Called when we got an incoming connection from another computer at `ip'.
 */
void inet_got_incoming(guint32 ip)
{
	gboolean is_local = is_local_ip(ip);

	/*
	 * If we get an incoming connection from the outside, we're surely
	 * connected to the Internet.
	 */

	if (!is_inet_connected && !is_local) {
		outgoing_connected++;				/* In case we have a timer set */
		inet_set_is_connected(TRUE);
	}

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

	if (!is_local_ip(ip))
		inet_not_firewalled();

	incoming_ev = cq_insert(
		callout_queue, FW_INCOMING_WINDOW * 1000,
		got_no_connection, NULL);
}

/*
 * inet_can_answer_ping
 *
 * Check whether we can answer a ping with a pong.
 *
 * Normally, when we're firewalled, we don't answer. However, if we have
 * a non-private IP and are within a "grace period", act as if we were not:
 * we can only know we're not firewalled when we get an incoming connection.
 */
gboolean inet_can_answer_ping(void)
{
	guint32 ip;
	time_t elapsed;

	if (!is_firewalled)
		return current_peermode != NODE_P_LEAF;	/* Leaves don't send pongs */

	ip = listen_ip();

	if (!ip)
		return FALSE;		/* We don't know our local IP, we can't reply */

	if (is_private_ip(ip))
		return FALSE;

	elapsed = time(NULL) - fw_time;		/* Since last status change */

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

static void inet_set_is_connected(gboolean val)
{
	gnet_prop_set_boolean_val(PROP_IS_INET_CONNECTED, val);

	if (dbg)
		printf("FW: we're %sconnected to the Internet\n",
			val ? "" : "no longer ");
}

/*
 * check_outgoing_connection
 *
 * This callback is periodically called when there has been outgoing
 * connections attempted.
 */
static void check_outgoing_connection(cqueue_t *cq, gpointer obj)
{
	guint32 last_received;

	outgoing_ev = NULL;

	/*
	 * If we received data during last second, then we're not really
	 * disconnected.
	 */

	last_received = 0;

	if (bws.in)  last_received += bsched_bps(bws.in);
	if (bws.gin) last_received += bsched_bps(bws.gin);


	if (
		outgoing_connected == 0	&&		/* No success over the period */
		last_received == 0				/* And no data received last second */
	)
		inet_set_is_connected(FALSE);

	outgoing_connected = 0;
}

/*
 * inet_connection_attempted
 *
 * Called each time we attempt a connection.
 */
void inet_connection_attempted(guint32 ip)
{
	/*
	 * Count the attempt if it's not a local connection.
	 */

	if (is_local_ip(ip))
		return;

	/* 
	 * Start timer if not already done.
	 */

	if (!outgoing_ev) {
		outgoing_connected = 0;
		outgoing_ev = cq_insert(
			callout_queue, OUTGOING_WINDOW * 1000,
			check_outgoing_connection, NULL);
	}
}

/*
 * inet_connection_succeeded
 *
 * Called each time a connection attempt succeeds.
 */
void inet_connection_succeeded(guint32 ip)
{
	/*
	 * Count the attempt if it's not a local connection.
	 */

	if (is_local_ip(ip))
		return;

	outgoing_connected++;

	if (!is_inet_connected)
		inet_set_is_connected(TRUE);
}

/*
 * inet_init
 *
 * Initialization code.
 */
void inet_init(void)
{
	/*
	 * If we persisted "is_firewalled" to FALSE, arm the no-connection timer.
	 */

	if (!is_firewalled)
		incoming_ev = cq_insert(
			callout_queue, FW_INCOMING_WINDOW * 1000,
			got_no_connection, NULL);
}

/* vi: set ts=4: */

