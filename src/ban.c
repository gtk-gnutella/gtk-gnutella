/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Banning control.
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

#include <stdio.h>			/* For debug printf() only */
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "ban.h"
#include "cq.h"
#include "sockets.h"
#include "misc.h"			/* For debug printf() only */

/*
 * We keep a hash table, indexed by IP address, which records all the
 * requests we have from the various IPs.  When hammering is detected,
 * the IP address is banned for some time.
 *
 * We use linear decay to gradually decrease the amount of requests made
 * over time.
 */

#define BAN_DELAY		300		/* Initial ban delay: 5 minutes */
#define MAX_REQUEST		10		/* Maximum of 10 requests... */
#define MAX_PERIOD		60		/* ...per minute */
#define MAX_BAN			86400	/* One day */

static GHashTable *info;		/* Info by IP address */
static gfloat decay_coeff;		/* Decay coefficient, per second */

extern cqueue_t *callout_queue;
extern gint dbg;

/*
 * Information kept in the info table, per IP address.
 */
struct ip_info {
	gfloat counter;				/* Counts connection, decayed linearily */
	guint32 ip;					/* IP address */
	time_t ctime;				/* When did last connection occur? */
	gpointer cq_ev;				/* Scheduled callout event */
	gint ban_delay;				/* Banning delay, in seconds */
	gboolean banned;			/* Is this IP currently banned? */
};

static void ipf_destroy(cqueue_t *cq, gpointer obj);

/*
 * ipf_make
 *
 * Create new ip_info structure for said IP.
 */
static struct ip_info *ipf_make(guint32 ip, time_t now)
{
	struct ip_info *ipf;

	ipf = g_malloc(sizeof(*ipf));

	ipf->counter = 1.0;
	ipf->ip = ip;
	ipf->ctime = now;
	ipf->ban_delay = 0;
	ipf->banned = FALSE;

	/*
	 * Schedule collecting of record.
	 *
	 * Our counter is 1, and the liner decay per second is decay_coeff,
	 * so it will reach 0 in 1/decay_coeff seconds.  The callout queue takes
	 * time in milli-seconds.
	 */

	ipf->cq_ev = cq_insert(callout_queue,
		(gint) (1000.0 / decay_coeff), ipf_destroy, ipf);

	return ipf;
}

/*
 * ipf_free
 *
 * Free ip_info structure.
 */
static void ipf_free(struct ip_info *ipf)
{
	g_assert(ipf);

	if (ipf->cq_ev)
		cq_cancel(callout_queue, ipf->cq_ev);

	g_free(ipf);
}

/*
 * ipf_destroy
 *
 * Called from callout queue when it's time to destroy the record.
 */
static void ipf_destroy(cqueue_t *cq, gpointer obj)
{
	struct ip_info *ipf = (struct ip_info *) obj;

	g_assert(ipf);
	g_assert(!ipf->banned);
	g_assert((gpointer) ipf == g_hash_table_lookup(info, (gpointer) ipf->ip));

	if (dbg > 8)
		printf("disposing of BAN %s\n", ip_to_gchar(ipf->ip));

	g_hash_table_remove(info, (gpointer) ipf->ip);
	ipf->cq_ev = NULL;
	ipf_free(ipf);
}

/*
 * ipf_unban
 *
 * Called from callout queue when it's time to unban the IP.
 */
static void ipf_unban(cqueue_t *cq, gpointer obj)
{
	struct ip_info *ipf = (struct ip_info *) obj;
	time_t now = time((time_t *) NULL);

	g_assert(ipf);
	g_assert(ipf->banned);
	g_assert((gpointer) ipf == g_hash_table_lookup(info, (gpointer) ipf->ip));

	/*
	 * Decay counter by measuring the amount of seconds since last connection
	 * and applying the linear decay coefficient.
	 */

	ipf->counter -= (now - ipf->ctime) * decay_coeff;
	ipf->ctime = now;

	if (dbg > 4)
		printf("removing BAN for %s, counter = %.3f\n",
			ip_to_gchar(ipf->ip), ipf->counter);


	/*
	 * If counter is negative or null, we can remove the entry.
	 */

	if (ipf->counter <= 0.0) {
		if (dbg > 8)
			printf("disposing of BAN %s\n", ip_to_gchar(ipf->ip));

		g_hash_table_remove(info, (gpointer) ipf->ip);
		ipf->cq_ev = NULL;
		ipf_free(ipf);
		return;
	}

	ipf->banned = FALSE;
	ipf->cq_ev = cq_insert(callout_queue,
		(gint) (1000.0 * ipf->counter / decay_coeff), ipf_destroy, ipf);
}

/*
 * ban_allow
 *
 * Check whether we can allow connection from `ip' to proceed.
 *
 * Returns:
 *
 *   BAN_OK     ok, can proceed with connection.
 *   BAN_FIRST  will ban, but send back message, then close connection.
 *   BAN_FORCE	don't send back anything, and call ban_force().
 */
gint ban_allow(guint32 ip)
{
	struct ip_info *ipf;
	time_t now = time((time_t *) NULL);

	ipf = (struct ip_info *) g_hash_table_lookup(info, (gpointer) ip);

	/*
	 * First time we see this IP?  It's OK then.
	 */

	if (ipf == NULL) {
		ipf = ipf_make(ip, now);
		g_hash_table_insert(info, (gpointer) ip, ipf);
		return BAN_OK;
	}

	/*
	 * Decay counter by measuring the amount of seconds since last connection
	 * and applying the linear decay coefficient.
	 */

	ipf->counter -= (now - ipf->ctime) * decay_coeff;

	if (ipf->counter < 0.0)
		ipf->counter = 0.0;

	/*
	 * Account for the new connection.
	 *
	 * Note that connections made during the ban time are also accounted for,
	 * which will possibly penalize the remote IP when it is unbanned!
	 */

	ipf->counter += 1.0;
	ipf->ctime = now;

	if (dbg > 4)
		printf("BAN %s, counter = %.3f (%s)\n",
			ip_to_gchar(ipf->ip), ipf->counter,
			ipf->banned ? "already banned" :
			ipf->counter > (gfloat) MAX_REQUEST ? "banning" : "OK");

	g_assert(ipf->cq_ev);

	/*
	 * If the IP is already banned, it already has an "unban" callback.
	 */

	if (ipf->banned)
		return BAN_FORCE;

	/*
	 * Ban the IP if it crossed the request limit.
	 */

	if (ipf->counter > (gfloat) MAX_REQUEST) {
		cq_cancel(callout_queue, ipf->cq_ev);	/* Cancel ipf_destroy */

		ipf->banned = TRUE;

		if (ipf->ban_delay)
			ipf->ban_delay *= 2;
		else
			ipf->ban_delay = BAN_DELAY;

		if (ipf->ban_delay > MAX_BAN)
			ipf->ban_delay = MAX_BAN;

		ipf->cq_ev =
			cq_insert(callout_queue, 1000 * ipf->ban_delay, ipf_unban, ipf);

		return BAN_FIRST;
	}

	/*
	 * OK, we accept this connection.  Reschedule cleanup.
	 */

	cq_resched(callout_queue, ipf->cq_ev,
		(gint) (1000.0 * ipf->counter / decay_coeff));

	return BAN_OK;
}

/*
 * Banning structures.
 *
 * We maintain a FIFO of all the file descriptors we've banned.  When we
 * have MAX_BANNED_FD entries in the FIFO, start closing the oldest one.
 */

#define MAX_BANNED_FD	100
#define SOCK_BUFFER		512				/* Reduced socket buffer */

static GList *banned_head = NULL;
static GList *banned_tail = NULL;
static gint banned_count = 0;

/*
 * ban_force
 *
 * Force banning of the connection.
 *
 * We're putting it in a list and forgetting about it.
 */
void ban_force(struct gnutella_socket *s)
{
	gint fd = s->file_desc;

	if (banned_count >= MAX_BANNED_FD) {
		GList *prev = g_list_previous(banned_tail);

		g_assert(banned_tail);
		g_assert(prev);

		(void) close((gint) banned_tail->data);		/* Reclaim fd */

		if (dbg > 9)
			printf("closed BAN fd #%d\n", (gint) banned_tail->data);

		banned_head = g_list_remove_link(banned_head, banned_tail);
		g_list_free_1(banned_tail);
		banned_tail = prev;
	} else
		banned_count++;

	/*
	 * Shrink socket buffers, and dispose of the socket structure.
	 */

	sock_send_buf(s, SOCK_BUFFER, TRUE);
	sock_recv_buf(s, SOCK_BUFFER, TRUE);

	s->file_desc = -1;				/* Prevent fd close by socket_free() */

	/*
	 * Insert banned fd in the list.
	 */

	banned_head = g_list_prepend(banned_head, (gpointer) fd);
	if (banned_tail == NULL)
		banned_tail = banned_head;
}

/*
 * ban_delay
 *
 * Return banning delay for banned IP.
 */
gint ban_delay(guint32 ip)
{
	struct ip_info *ipf;

	ipf = (struct ip_info *) g_hash_table_lookup(info, (gpointer) ip);
	g_assert(ipf);

	return ipf->ban_delay;
}

/*
 * ban_init
 *
 * Initialize the banning system.
 */
void ban_init(void)
{
	info = g_hash_table_new(g_direct_hash, 0);
	decay_coeff = (gfloat) MAX_REQUEST / MAX_PERIOD;
}

static void free_info(gpointer key, gpointer value, gpointer udata)
{
	ipf_free((struct ip_info *) value);
}

/*
 * ban_close
 *
 * Called at shutdown time to reclaim all memory.
 */
void ban_close(void)
{
	GList *l;

	g_hash_table_foreach(info, free_info, NULL);
	g_hash_table_destroy(info);

	for (l = banned_head; l; l = l->next)
		(void) close((gint) l->data);		/* Reclaim fd */

	g_list_free(banned_head);
}

