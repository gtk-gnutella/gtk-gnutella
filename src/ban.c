/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

#include "gnutella.h"

#include <stdio.h>			/* For debug printf() only */
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "ban.h"
#include "sockets.h"
#include "version.h" /* for version_is_too_old() */
#include "token.h"
#include "atoms.h"

#include "gnet_property.h"
#include "gnet_property_priv.h"

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * We keep a hash table, indexed by IP address, which records all the
 * requests we have from the various IPs.  When hammering is detected,
 * the IP address is banned for some time.
 *
 * We use linear decay to gradually decrease the amount of requests made
 * over time.
 */

#define BAN_DELAY		300		/* Initial ban delay: 5 minutes */
#define MAX_REQUEST		5		/* Maximum of 5 requests... */
#define MAX_PERIOD		60		/* ...per minute */
#define MAX_BAN			10800	/* 3 hours */

static GHashTable *info;		/* Info by IP address */
static gfloat decay_coeff;		/* Decay coefficient, per second */
static zone_t *ipf_zone;		/* Zone for ip_info allocation */

extern cqueue_t *callout_queue;

/***
 *** Hammering-specific banning.
 ***/

/*
 * Information kept in the info table, per IP address.
 */
struct ip_info {
	gfloat counter;				/* Counts connection, decayed linearily */
	guint32 ip;					/* IP address */
	time_t ctime;				/* When did last connection occur? */
	gpointer cq_ev;				/* Scheduled callout event */
	gint ban_delay;				/* Banning delay, in seconds */
	gchar *ban_msg;				/* Banning message (atom) */
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

	ipf = zalloc(ipf_zone);

	ipf->counter = 1.0;
	ipf->ip = ip;
	ipf->ctime = now;
	ipf->ban_delay = 0;
	ipf->ban_msg = NULL;
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

	if (ipf->ban_msg)
		atom_str_free(ipf->ban_msg);

	zfree(ipf_zone, ipf);
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
	g_assert(
		(gpointer) ipf == g_hash_table_lookup(info, GUINT_TO_POINTER(ipf->ip)));

	if (dbg > 8)
		printf("disposing of BAN %s\n", ip_to_gchar(ipf->ip));

	g_hash_table_remove(info, GUINT_TO_POINTER(ipf->ip));
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
	gint delay;

	g_assert(ipf);
	g_assert(ipf->banned);
	g_assert(
		(gpointer) ipf == g_hash_table_lookup(info, GUINT_TO_POINTER(ipf->ip)));

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
	 * Compute new scheduling delay.
	 */

	delay = (gint) (1000.0 * ipf->counter / decay_coeff);

	/*
	 * If counter is negative or null, we can remove the entry.
	 * Since we round to an integer, we must consider `delay' and
	 * not the original counter.
	 */

	if (delay <= 0) {
		if (dbg > 8)
			printf("disposing of BAN %s\n", ip_to_gchar(ipf->ip));

		g_hash_table_remove(info, GUINT_TO_POINTER(ipf->ip));
		ipf->cq_ev = NULL;
		ipf_free(ipf);
		return;
	}

	ipf->banned = FALSE;
	ipf->cq_ev = cq_insert(callout_queue, delay, ipf_destroy, ipf);
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
 *   BAN_MSG	will ban with explicit message and tailored error code.
 */
ban_type_t ban_allow(guint32 ip)
{
	struct ip_info *ipf;
	time_t now = time((time_t *) NULL);

	ipf = (struct ip_info *) g_hash_table_lookup(info, GUINT_TO_POINTER(ip));

	/*
	 * First time we see this IP?  It's OK then.
	 */

	if (ipf == NULL) {
		ipf = ipf_make(ip, now);
		g_hash_table_insert(info, GUINT_TO_POINTER(ip), ipf);
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
	 *
	 * When there is a message recorded, return BAN_MSG to signal that
	 * we need special processing: dedicated error code, and message to
	 * extract.
	 */

	if (ipf->banned)
		return (ipf->ban_msg == NULL) ? BAN_FORCE : BAN_MSG;

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
 * ban_record
 *
 * Record banning with specific message for a given IP, for MAX_BAN seconds.
 */
void ban_record(guint32 ip, const gchar *msg)
{
	struct ip_info *ipf;

	/*
	 * If is possible that we already have an ip_info for that host.
	 */

	ipf = (struct ip_info *) g_hash_table_lookup(info, GUINT_TO_POINTER(ip));

	if (ipf == NULL) {
		ipf = ipf_make(ip, time(NULL));
		g_hash_table_insert(info, GUINT_TO_POINTER(ip), ipf);
	}

	if (ipf->ban_msg != NULL)
		atom_str_free(ipf->ban_msg);

	ipf->ban_msg = atom_str_get(msg);
	ipf->ban_delay = MAX_BAN;

	if (ipf->banned)
		cq_resched(callout_queue, ipf->cq_ev, MAX_BAN * 1000);
	else {
		cq_cancel(callout_queue, ipf->cq_ev);	/* Cancel ipf_destroy */
		ipf->banned = TRUE;
		ipf->cq_ev =
			cq_insert(callout_queue, MAX_BAN * 1000, ipf_unban, ipf);
	}
}

/*
 * Banning structures.
 *
 * We maintain a FIFO of all the file descriptors we've banned.  When we
 * have `max_banned_fd' entries in the FIFO, start closing the oldest one.
 */

#define SOCK_BUFFER		512				/* Reduced socket buffer */

static GList *banned_head = NULL;
static GList *banned_tail = NULL;

/*
 * reclaim_fd
 *
 * Internal version of ban_reclaim_fd().
 *
 * Reclaim a file descriptor used for banning.
 * Returns TRUE if we did reclaim something, FALSE if there was nothing.
 */
static gboolean reclaim_fd(void)
{
	GList *prev;

	if (banned_tail == NULL) {
		g_assert(banned_head == NULL);
		g_assert(banned_count == 0);
		return FALSE;					/* Empty list */
	}

	g_assert(banned_head != NULL);
	g_assert(banned_count > 0);

	(void) close(GPOINTER_TO_INT(banned_tail->data));	/* Reclaim fd */

	if (dbg > 9)
		printf("closed BAN fd #%d\n", GPOINTER_TO_INT(banned_tail->data));

	prev = g_list_previous(banned_tail);
	banned_head = g_list_remove_link(banned_head, banned_tail);
	g_list_free_1(banned_tail);
	banned_tail = prev;

	gnet_prop_set_guint32_val(PROP_BANNED_COUNT, banned_count - 1);

	return TRUE;
}

/*
 * ban_reclaim_fd
 *
 * Reclaim a file descriptor used for banning.
 *
 * This routine is called when there is a shortage of file descriptors, so
 * we activate the "file_descriptor_shortage" property.  However, if we have
 * nothing to reclaim, we activate the "file_descriptor_runout" property
 * instead, which signifies that processing will be degraded.
 *
 * Returns TRUE if we did reclaim something, FALSE if there was nothing.
 */
gboolean ban_reclaim_fd(void)
{
	gboolean reclaimed;

	reclaimed = reclaim_fd();

	/*
	 * Those properties will be cleared if more than 10 minutes elapse
	 * after their last setting to TRUE.
	 */

	if (reclaimed)
		gnet_prop_set_boolean_val(PROP_FILE_DESCRIPTOR_SHORTAGE, TRUE);
	else
		gnet_prop_set_boolean_val(PROP_FILE_DESCRIPTOR_RUNOUT, TRUE);

	return reclaimed;
}

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

	if (banned_count >= max_banned_fd) {
		g_assert(banned_tail);
		g_assert(max_banned_fd <= 1 || (banned_tail != banned_head));

		reclaim_fd();
	}

	/*
	 * Shrink socket buffers.
	 */

	sock_send_buf(s, SOCK_BUFFER, TRUE);
	sock_recv_buf(s, SOCK_BUFFER, TRUE);

	s->file_desc = -1;				/* Prevent fd close by socket_free() */

	/*
	 * Insert banned fd in the list.
	 */

	banned_head = g_list_prepend(banned_head, GINT_TO_POINTER(fd));
	if (banned_tail == NULL)
		banned_tail = banned_head;

	gnet_prop_set_guint32_val(PROP_BANNED_COUNT, banned_count + 1);
}

/*
 * ban_is_banned
 *
 * Check whether IP is already recorded as being banned.
 */
gboolean ban_is_banned(guint32 ip)
{
	struct ip_info *ipf;

	ipf = (struct ip_info *) g_hash_table_lookup(info, GUINT_TO_POINTER(ip));

	return ipf != NULL && ipf->banned;
}

/*
 * ban_delay
 *
 * Return banning delay for banned IP.
 */
gint ban_delay(guint32 ip)
{
	struct ip_info *ipf;

	ipf = (struct ip_info *) g_hash_table_lookup(info, GUINT_TO_POINTER(ip));
	g_assert(ipf);

	return ipf->ban_delay;
}

/*
 * ban_message
 *
 * Return banning message for banned IP.
 */
gchar *ban_message(guint32 ip)
{
	struct ip_info *ipf;

	ipf = (struct ip_info *) g_hash_table_lookup(info, GUINT_TO_POINTER(ip));
	g_assert(ipf);

	return ipf->ban_msg;
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
	ipf_zone = zget(sizeof(struct ip_info), 0);

	ban_max_recompute();
}

/*
 * ban_max_recompute
 *
 * Recompute the maximum amount of file descriptors we dedicate to banning.
 */
void ban_max_recompute(void)
{
	guint32 max;

	max = MIN(ban_max_fds, sys_nofile * ban_ratio_fds / 100);
	max = MAX(1, max);

	if (dbg)
		printf("will use at most %d file descriptor%s for banning\n",
			max, max == 1 ? "" : "s");

	gnet_prop_set_guint32_val(PROP_MAX_BANNED_FD, max);
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
		(void) close(GPOINTER_TO_INT(l->data));		/* Reclaim fd */

	g_list_free(banned_head);
	zdestroy(ipf_zone);
}

/***
 *** Vendor-specific banning.
 ***/

static const gchar *harmful = "Harmful version banned, upgrade required";
static const gchar *refused = "Connection refused";
static const gchar *too_old = "Outdated version, please upgrade";

/*
 * ban_vendor
 *
 * Check whether servent identified by its vendor string should be banned.
 * When we ban, we ban for both gnet and download connections.  Such banning
 * is exceptional, usually restricted to some versions and the servent's author
 * is informed about the banning.
 *
 * Returns NULL if we shall not ban, a banning reason string otherwise.
 */
const gchar *ban_vendor(const gchar *vendor)
{
	gboolean is_gtkg = FALSE;

#define GTKG_NAME	"gtk-gnutella/"
#define GTKG_LEN	(sizeof(GTKG_NAME) - 1)

	/*
	 * If vendor starts with "!gtk-gnutella", skip the leading '!' for
	 * our tests here.
	 */

	if (
		vendor[0] == '!' &&
		0 == strncmp(vendor + 1, GTKG_NAME, GTKG_LEN)
	) {
		vendor++;
		is_gtkg = TRUE;
	}

	/*
	 * Ban gtk-gnutella/0.90 from the network.  This servent had
	 * bugs that could corrupt the traffic.  Also ban 0.91u.
	 *
	 * Versions of GKTG deemed too old are also banned: the Gnutella
	 * network is far from being mature, and we need to ensure newer
	 * features are deployed reasonably quickly.
	 *		--RAM, 03/01/2002.
	 */

	if (
		vendor[0] == 'g' &&
		(is_gtkg || 0 == strncmp(vendor, GTKG_NAME, GTKG_LEN))
	) {
		if (
			0 == strncmp(vendor + GTKG_LEN, "0.90", 4) ||
			0 == strncmp(vendor + GTKG_LEN, "0.91u", 5) ||
			0 == strncmp(vendor + GTKG_LEN, "0.92b ", 6)
		)
			return harmful;

		if (version_is_too_old(vendor))
			return too_old;

		return NULL;
	}

#undef GTKG_NAME
#undef GTKG_LEN

#define GTKG_NAME	"Gtk-Gnutella "
#define GTKG_LEN	(sizeof(GTKG_NAME) - 1)

#define GNUC_NAME	"Gnucleus "
#define GNUC_LEN	(sizeof(GNUC_NAME) - 1)

	if (vendor[0] == 'G') {
		if (0 == strncmp(vendor, GNUC_NAME, GNUC_LEN)) {
			if (0 == strncmp(vendor + GNUC_LEN, "1.6.0.0", 7))
				return harmful;
		} else if (0 == strncmp(vendor, GTKG_NAME, GTKG_LEN))
			return refused;

		return NULL;
	}

#undef GNUC_NAME
#undef GNUC_LEN

#undef GTKG_NAME
#undef GTKG_LEN

	return NULL;
}

