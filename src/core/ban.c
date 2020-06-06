/*
 * Copyright (c) 2002-2003, 2012 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Banning logic.
 *
 * Each time an event occurs for a given IP address (connection attempt,
 * lack of OOB hit claiming), we record the event in the proper banning
 * object.  Once a threshold is reached, the IP address is "banned" for
 * some time.
 *
 * The application code entry point is ban_allow(). It returns a code telling
 * we can proceeed further with the event or if we had too many events of
 * the same kind already for the address.
 *
 * For connection attempts that are deemed hammering, it is possible to force
 * the file descriptor (the connected socket) to be kept opened for some time
 * in an attempt to slow down the request rate on the other end.
 *
 * Such banned file descriptors are kept in a FIFO queue and will be closed
 * when we need to ban a new file descriptor and we reached the maximum amount
 * of banned fds, or when we start lacking file descriptors for establishing
 * socket connections.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2012
 */

#include "common.h"

#include "ban.h"

#include "gnet_stats.h"
#include "sockets.h"		/* For socket_register_fd_reclaimer() */
#include "token.h"
#include "whitelist.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fd.h"
#include "lib/fifo.h"
#include "lib/file.h"		/* For file_register_fd_reclaimer() */
#include "lib/hevset.h"
#include "lib/misc.h"
#include "lib/parse.h"
#include "lib/spinlock.h"
#include "lib/stringify.h"	/* For plural() */
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * We keep a hash set, indexed by IP address, which records all the
 * requests we have from the various IPs.  When hammering is detected,
 * the IP address is banned for some time.
 *
 * We use linear decay to gradually decrease the amount of requests made
 * over time.
 */

#define BAN_DELAY		300		/**< Initial ban delay: 5 minutes */
#define BAN_CALLOUT		1000	/**< Every 1 second */

#define MAX_GNET_REQUEST	2		/**< Maximum of 2 requests... */
#define MAX_GNET_PERIOD		60		/**< ...per minute */
#define MAX_GNET_BAN		3600	/**< 1 hour */
#define BAN_GNET_REMIND		5		/**< Every so many attempts, remind them */

#define MAX_HTTP_REQUEST	5		/**< Maximum of 5 requests... */
#define MAX_HTTP_PERIOD		60		/**< ...per minute */
#define MAX_HTTP_BAN		10800	/**< 3 hours */
#define BAN_HTTP_REMIND		5		/**< Every so many attempts, remind them */

#define MAX_OOB_REQUEST		25		/**< Maximum of 25 unanswered claims... */
#define MAX_OOB_PERIOD		60		/**< ...per minute */
#define MAX_OOB_BAN			600		/**< 10 minutes */

#define ban_reason(p)	((p)->ban_msg ? (p)->ban_msg : "N/A")

#define FORCE_ASSIGN(t,s,f,v) G_STMT_START {	\
	*(t *) &(s)->f = v;							\
} G_STMT_END

enum ban_magic { BAN_MAGIC = 0x01d2f60d };

/**
 * A banning object.
 */
struct ban {
	enum ban_magic magic;		/**< Magic number */
	const ban_category_t cat;	/**< Category of banning object */
	unsigned delay;				/**< Initial ban delay, in seconds */
	unsigned requests;			/**< Maximum amount of requests before ban */
	unsigned period;			/**< Period (seconds) for request threshold */
	unsigned bantime;			/**< Banning time, in seconds */
	unsigned remind;			/**< Reminding period, every so many attempts */
	const float decay_coeff;	/**< Decay coefficient, per second */
	hevset_t *info;				/**< Info by IP address */
};

static inline void
ban_check(const struct ban * const b)
{
	g_assert(b != NULL);
	g_assert(BAN_MAGIC == b->magic);
}

/**
 * Known ban objects, indexed by categories.
 * These are created at ban_init() time.
 */
static struct ban *ban_object[BAN_CAT_COUNT];

static cqueue_t *ban_cq;		/**< Private callout queue */

enum addr_info_magic { ADDR_INFO_MAGIC = 0x2546b3bb };

/**
 * Information kept in the info table, per IP address.
 */
struct addr_info {
	enum addr_info_magic magic;	/**< Magic number */
	host_addr_t addr;			/**< IP address -- the embedded key */
	const char *ban_msg;		/**< Banning message (atom) */
	cevent_t *cq_ev;			/**< Scheduled callout event */
	const struct ban *owner;	/**< Owning ban object */
	time_t created;				/**< When did last connection occur? */
	unsigned ban_delay;			/**< Banning delay, in seconds */
	int ban_count;				/**< Amount of time we banned this source */
	float counter;				/**< Counts connection, decayed linearily */
	unsigned banned:1;			/**< Is this IP currently banned? */
};

static inline void
addr_info_check(const struct addr_info * const ipf)
{
	g_assert(ipf != NULL);
	g_assert(ADDR_INFO_MAGIC == ipf->magic);
}

static void ipf_destroy(cqueue_t *cq, void *obj);

const char *
ban_category_string(const ban_category_t cat)
{
	switch (cat) {
	case BAN_CAT_GNUTELLA:		return "Gnutella";
	case BAN_CAT_HTTP:			return "HTTP";
	case BAN_CAT_OOB_CLAIM:		return "OOB claim";
	case BAN_CAT_COUNT:
		break;
	}

	g_assert_not_reached();
	return NULL;
}

/**
 * Create a new ban object.
 *
 * @param cat				Category of banning events we handle
 * @param delay				Initial ban delay, in seconds
 * @param requests			Maximum amount of requests before ban
 * @param period;			Period (seconds) for request threshold
 * @param bantime			Banning time, in seconds
 * @param remind			Reminding period, every so many attempts
 *
 * @return new ban object.
 */
static struct ban *
ban_make(const ban_category_t cat,
	unsigned delay, unsigned requests, unsigned period,
	unsigned bantime, unsigned remind)
{
	struct ban *b;

	g_assert(period != 0);

	WALLOC0(b);

	b->magic = BAN_MAGIC;
	b->delay = delay;
	b->requests = requests;
	b->period = period;
	b->bantime = bantime;
	b->remind = remind;
	b->info = hevset_create_any(offsetof(struct addr_info, addr),
		host_addr_hash_func, host_addr_hash_func2, host_addr_eq_func);

	/*
	 * Assignments to read-only fields at creation time.
	 */

	FORCE_ASSIGN(ban_category_t, b, cat, cat);
	FORCE_ASSIGN(float, b, decay_coeff, (float) requests / period);

	return b;
}

/**
 * Create new addr_info structure for said IP.
 */
static struct addr_info *
ipf_make(const host_addr_t addr, time_t now, const struct ban *owner)
{
	struct addr_info *ipf;

	ban_check(owner);

	WALLOC0(ipf);

	ipf->magic = ADDR_INFO_MAGIC;
	ipf->counter = 1.0;
	ipf->addr = addr;
	ipf->created = now;
	ipf->ban_delay = 0;
	ipf->ban_count = 0;
	ipf->ban_msg = NULL;
	ipf->owner = owner;
	ipf->banned = FALSE;

	/*
	 * Schedule collecting of record.
	 *
	 * Our counter is 1, and the liner decay per second is decay_coeff,
	 * so it will reach 0 in 1/decay_coeff seconds.  The callout queue takes
	 * time in milli-seconds.
	 */
	{
		int delay;
		const float decay_coeff = owner->decay_coeff;

		delay = 1000.0 / decay_coeff;
		delay = MAX(delay, 1);
		ipf->cq_ev = cq_insert(ban_cq, delay, ipf_destroy, ipf);
	}

	return ipf;
}

/**
 * Free addr_info structure.
 */
static void
ipf_free(struct addr_info *ipf)
{
	addr_info_check(ipf);

	cq_cancel(&ipf->cq_ev);
	atom_str_free_null(&ipf->ban_msg);
	ipf->magic = 0;
	WFREE(ipf);
}

static void
free_info(void *value, void *unused_udata)
{
	(void) unused_udata;
	ipf_free(value);
}

/**
 * Destroy a ban object.
 */
static void
ban_free(struct ban *b)
{
	ban_check(b);

	hevset_foreach(b->info, free_info, NULL);
	hevset_free_null(&b->info);
	b->magic = 0;
	WFREE(b);
}

/**
 * Called from callout queue when it's time to destroy the record.
 */
static void
ipf_destroy(cqueue_t *cq, void *obj)
{
	struct addr_info *ipf = obj;

	addr_info_check(ipf);
	g_assert(!ipf->banned);

	if (GNET_PROPERTY(ban_debug) > 8)
		g_debug("disposing of %s BAN %s: %s",
			ban_category_string(ipf->owner->cat),
			host_addr_to_string(ipf->addr), ban_reason(ipf));

	hevset_remove(ipf->owner->info, &ipf->addr);
	cq_zero(cq, &ipf->cq_ev);
	ipf_free(ipf);
}

/**
 * Lift ban for given entry.
 *
 * @return TRUE if we freed the entry.
 */
static bool
ipf_lift_ban(struct addr_info *ipf)
{
	time_t now = tm_time();
	int delay;
	float decay_coeff;

	addr_info_check(ipf);
	g_assert(ipf->banned);
	ban_check(ipf->owner);

	decay_coeff = ipf->owner->decay_coeff;

	/*
	 * Decay counter by measuring the amount of seconds since last connection
	 * and applying the linear decay coefficient.
	 */

	ipf->counter -= delta_time(now, ipf->created) * decay_coeff;
	ipf->created = now;

	if (GNET_PROPERTY(ban_debug) > 2) {
		g_debug("lifting BAN for %s (%s), counter = %.3f",
			host_addr_to_string(ipf->addr), ban_reason(ipf), ipf->counter);
	}

	/**
	 * Compute new scheduling delay.
	 */

	delay = 1000.0 * ipf->counter / decay_coeff;

	/**
	 * If counter is negative or null, we can remove the entry.
	 * Since we round to an integer, we must consider `delay' and
	 * not the original counter.
	 */

	if (delay <= 0) {
		if (GNET_PROPERTY(ban_debug) > 8)
			g_debug("disposing of %s BAN %s: %s",
				ban_category_string(ipf->owner->cat),
				host_addr_to_string(ipf->addr), ban_reason(ipf));

		hevset_remove(ipf->owner->info, &ipf->addr);
		ipf_free(ipf);
		return TRUE;
	}

	ipf->banned = FALSE;
	atom_str_free_null(&ipf->ban_msg);
	ipf->cq_ev = cq_insert(ban_cq, delay, ipf_destroy, ipf);

	return FALSE;
}

/**
 * Called from callout queue when it's time to unban the IP.
 */
static void
ipf_unban(cqueue_t *cq, void *obj)
{
	struct addr_info *ipf = obj;

	addr_info_check(ipf);
	g_assert(ipf->banned);

	cq_zero(cq, &ipf->cq_ev);
	ipf_lift_ban(ipf);
}

/**
 * A legitimate connection was made (for instance we granted an upload
 * slot), hence we do not want to count the connection attempt as hammering.
 *
 * This routine is invoked to decrease the ccnnection counter, so that the
 * remote host does not incur a penalty and does not become prematurely banned.
 */
void
ban_legit(const ban_category_t cat, const host_addr_t addr)
{
	struct addr_info *ipf;
	struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
	case NET_TYPE_IPV6:
		break;
	default:
		return;
	}

	ipf = hevset_lookup(b->info, &addr);
	if (NULL == ipf)
		return;

	ipf->counter -= 1.0;

	if (ipf->banned && ipf->counter <= (float) b->requests) {
		cq_cancel(&ipf->cq_ev);
		ipf_lift_ban(ipf);
	}
}

/**
 * Check whether we can allow connection / event from `ip' to proceed.
 *
 * Returns:
 *
 *   BAN_OK     ok, can proceed with connection / event.
 *   BAN_FIRST  will ban, but send back message, then close connection.
 *   BAN_FORCE	don't send back anything, and call ban_force().
 *   BAN_MSG	will ban with explicit message and tailored error code.
 */
ban_type_t
ban_allow(const ban_category_t cat, const host_addr_t addr)
{
	struct addr_info *ipf;
	time_t now = tm_time();
	struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
	case NET_TYPE_IPV6:
		break;
	default:
		return BAN_OK;
	}

	if (whitelist_check(addr))
		return BAN_OK;

	ipf = hevset_lookup(b->info, &addr);

	/*
	 * First time we see this IP?  It's OK then.
	 */

	if (NULL == ipf) {
		ipf = ipf_make(addr, now, b);
		hevset_insert(b->info, ipf);
		return BAN_OK;
	}

	addr_info_check(ipf);

	/*
	 * Decay counter by measuring the amount of seconds since last connection
	 * and applying the linear decay coefficient.
	 */

	ipf->counter -= delta_time(now, ipf->created) * b->decay_coeff;

	if (ipf->counter < 0.0)
		ipf->counter = 0.0;

	/*
	 * Account for the new connection.
	 *
	 * Note that connections made during the ban time are also accounted for,
	 * which will possibly penalize the remote IP when it is unbanned!
	 */

	ipf->counter += 1.0;
	ipf->created = now;

	if (GNET_PROPERTY(ban_debug) > 4) {
		g_debug("BAN %s %s, counter = %.3f (%s)",
			ban_category_string(b->cat),
			host_addr_to_string(ipf->addr), ipf->counter,
			ipf->banned ? "already banned" :
			ipf->counter > (float) b->requests ? "banning" : "OK");
	}

	g_assert(ipf->cq_ev);

	/*
	 * If the IP is already banned, it already has an "unban" callback.
	 *
	 * When there is a message recorded, return BAN_MSG to signal that
	 * we need special processing: dedicated error code, and message to
	 * extract.
	 */

	if (ipf->banned) {
		/*
		 * Every ``remind'' attempts, return BAN_FIRST / BAN_MSG to let them
		 * know that they have been banned, in case they "missed" our previous
		 * indications or did not get the Retry-After right.
		 *		--RAM, 2004-06-21
		 */

		if (0 != b->remind && 0 == ++(ipf->ban_count) % b->remind)
			return (ipf->ban_msg != NULL) ? BAN_MSG : BAN_FIRST;

		return BAN_FORCE;
	}

	/*
	 * Ban the IP if it crossed the request limit.
	 */

	if (ipf->counter > (float) b->requests) {
		cq_cancel(&ipf->cq_ev);		/* Cancel ipf_destroy */

		ipf->banned = TRUE;
		atom_str_change(&ipf->ban_msg, "Too frequent connections");

		if (ipf->ban_delay)
			ipf->ban_delay *= 2;
		else
			ipf->ban_delay = BAN_DELAY;

		if (ipf->ban_delay > b->bantime)
			ipf->ban_delay = b->bantime;

		ipf->cq_ev = cq_insert(ban_cq, 1000 * ipf->ban_delay, ipf_unban, ipf);

		return BAN_FIRST;
	}

	/*
	 * OK, we accept this connection.  Reschedule cleanup.
	 */
	{
		int delay;

		delay = 1000.0 * ipf->counter / b->decay_coeff;
		delay = MAX(delay, 1);
		cq_resched(ipf->cq_ev, delay);
	}

	return BAN_OK;
}

/**
 * Record banning with specific message for a given IP, for MAX_BAN seconds.
 */
void
ban_record(ban_category_t cat, const host_addr_t addr, const char *msg)
{
	struct addr_info *ipf;
	struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	/*
	 * If is possible that we already have an addr_info for that host.
	 */

	ipf = hevset_lookup(b->info, &addr);

	if (NULL == ipf) {
		ipf = ipf_make(addr, tm_time(), b);
		hevset_insert(b->info, ipf);
	}

	addr_info_check(ipf);

	atom_str_change(&ipf->ban_msg, msg);
	ipf->ban_delay = b->bantime;

	if (GNET_PROPERTY(ban_debug)) {
		g_debug("BAN %s %s record %s: %s",
			ban_category_string(b->cat),
			ipf->banned ? "updating" : "new",
			host_addr_to_string(ipf->addr), ban_reason(ipf));
	}

	if (ipf->banned)
		cq_resched(ipf->cq_ev, b->bantime * 1000);
	else {
		cq_cancel(&ipf->cq_ev);		/* Cancel ipf_destroy */
		ipf->banned = TRUE;
		ipf->cq_ev = cq_insert(ban_cq, b->bantime * 1000, ipf_unban, ipf);
	}
}

/*
 * Banning structures.
 *
 * We maintain a FIFO of all the file descriptors we've banned.  When we
 * have `max_banned_fd' entries in the FIFO, start closing the oldest one.
 */

#define SOCK_BUFFER		512				/**< Reduced socket buffer */

static fifo_t *banned_fds;
static spinlock_t banned_fds_slk = SPINLOCK_INIT;

#define BANNED_FDS_LOCK			spinlock(&banned_fds_slk)
#define BANNED_FDS_UNLOCK		spinunlock(&banned_fds_slk)
#define BANNED_FDS_IS_LOCKED	spinlock_is_held(&banned_fds_slk)

static void
ban_close_fd(void **data_ptr)
{
	void *data = *data_ptr;
	int fd = pointer_to_int(data);

	g_assert(is_valid_fd(fd));
	g_assert(fd > STDERR_FILENO);	/* fd 0-2 are not used for sockets */

	if (GNET_PROPERTY(ban_debug) > 9) {
		g_debug("closing BAN fd #%d", fd);
	}
	fd_close(&fd);	/* Reclaim fd */
	*data_ptr = int_to_pointer(-1);
}

/**
 * Internal version of ban_reclaim_fd().
 *
 * Reclaim a file descriptor used for banning.
 *
 * @returns TRUE if we did reclaim something, FALSE if there was nothing.
 */
static bool
reclaim_fd(void)
{
	void *fd;

	g_assert(BANNED_FDS_IS_LOCKED);

	fd = fifo_remove(banned_fds);

	if (NULL == fd) {
		g_assert(GNET_PROPERTY(banned_count) == 0);
		return FALSE;					/* Empty list */
	}

	g_assert(GNET_PROPERTY(banned_count) > 0);

	ban_close_fd(&fd);
	gnet_prop_decr_guint32(PROP_BANNED_COUNT);

	/*
	 * Don't assert that:
	 *
	 * 	fifo_count(banned_fds) == GNET_PROPERTY(banned_count)
	 *
	 * at this stage because the compiler does not know that the call to
	 * gnet_prop_decr_guint32(PROP_BANNED_COUNT) will actually modify the
	 * value of GNET_PROPERTY(banned_count) and it can generate bad code.
	 *
	 * To make it work, we need to fetch the property value through
	 * the gnet_prop_get_guint32_val() interface.
	 *		--RAM, 2013-12-29
	 */

	{
		uint32 banned_count;

		gnet_prop_get_guint32_val(PROP_BANNED_COUNT, &banned_count);

		g_assert_log(fifo_count(banned_fds) == banned_count,
			"fifo_count=%u, banned_count=%u",
			fifo_count(banned_fds), banned_count);
	}

	return TRUE;
}

/**
 * Reclaim a file descriptor used for banning
 *
 * Invoked from the outside as a callback to reclaim file descriptors.
 *
 * This routine is called when there is a shortage of file descriptors, so
 * we activate the "file_descriptor_shortage" property.  However, if we have
 * nothing to reclaim, we activate the "file_descriptor_runout" property
 * instead, which signifies that processing will be degraded.
 *
 * @returns TRUE if we did reclaim something, FALSE if there was nothing.
 */
static bool
ban_reclaim_fd(void)
{
	bool reclaimed;

	BANNED_FDS_LOCK;

	reclaimed = reclaim_fd();

	/*
	 * Those properties will be cleared if more than 10 minutes elapse
	 * after their last setting to TRUE.
	 */

	if (reclaimed)
		gnet_prop_set_boolean_val(PROP_FILE_DESCRIPTOR_SHORTAGE, TRUE);
	else
		gnet_prop_set_boolean_val(PROP_FILE_DESCRIPTOR_RUNOUT, TRUE);

	BANNED_FDS_UNLOCK;

	return reclaimed;
}

/**
 * Force banning of the connection.
 *
 * We're putting it in a list and forgetting about it.
 */
void
ban_force(struct gnutella_socket *s)
{
	int fd;

	socket_check(s);
	fd = s->file_desc;
	g_return_if_fail(is_valid_fd(fd));
	g_return_if_fail(fd > STDERR_FILENO); /* fd 0-2 are not used for sockets */

	/* Ensure we're not listening to I/O events anymore. */
	socket_evt_clear(s);

	/*
	 * Shrink socket buffers.
	 */

	socket_send_buf(s, SOCK_BUFFER, TRUE);
	socket_recv_buf(s, SOCK_BUFFER, TRUE);

	/*
	 * Let the kernel discard incoming data; SHUT_WR or SHUT_RDWR
	 * would cause to sent a FIN which we want to prevent.
	 */
	shutdown(s->file_desc, SHUT_RD);

	s->file_desc = -1;				/* Prevent fd close by socket_free() */

	/*
	 * Insert banned fd in the list.
	 */

	BANNED_FDS_LOCK;

	g_assert_log(fifo_count(banned_fds) == GNET_PROPERTY(banned_count),
		"fifo_count=%u, banned_count=%u",
		fifo_count(banned_fds), GNET_PROPERTY(banned_count));

	while (fifo_count(banned_fds) >= GNET_PROPERTY(max_banned_fd)) {
		if (!reclaim_fd())
			break;
	}

	fifo_put(banned_fds, int_to_pointer(fd));

	gnet_prop_incr_guint32(PROP_BANNED_COUNT);
	gnet_stats_inc_general(GNR_BANNED_FDS_TOTAL);

	/*
	 * Don't assert that:
	 *
	 * 	fifo_count(banned_fds) == GNET_PROPERTY(banned_count)
	 *
	 * at this stage because the compiler does not know that the call to
	 * gnet_prop_incr_guint32(PROP_BANNED_COUNT) will actually modify the
	 * value of GNET_PROPERTY(banned_count) and it generates bad code.
	 *
	 * To make it work, we need to fetch the property value through
	 * the gnet_prop_get_guint32_val() interface.
	 *		--RAM, 2013-12-29
	 */

	{
		uint32 banned_count;

		gnet_prop_get_guint32_val(PROP_BANNED_COUNT, &banned_count);

		g_assert_log(fifo_count(banned_fds) == banned_count,
			"fifo_count=%u, banned_count=%u",
			fifo_count(banned_fds), banned_count);
	}

	BANNED_FDS_UNLOCK;
}

/**
 * Check whether IP is already recorded as being banned for this category.
 */
bool
ban_is_banned(const ban_category_t cat, const host_addr_t addr)
{
	struct addr_info *ipf;
	struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	ipf = hevset_lookup(b->info, &addr);
	g_assert(NULL == ipf || ADDR_INFO_MAGIC == ipf->magic);

	return ipf != NULL && ipf->banned;
}

/**
 * @return banning delay for banned IP in the given category.
 */
int
ban_delay(const ban_category_t cat, const host_addr_t addr)
{
	const struct addr_info *ipf;
	const struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	ipf = hevset_lookup(b->info, &addr);
	addr_info_check(ipf);

	return ipf->ban_delay;
}

/**
 * Get banning message for banned IP.
 *
 * This only applies to connection-type of bans since there needs to be
 * a configured reminder period whereby we explicitly tell them that they
 * are banned, so we need a communication channel for that.
 *
 * @return banning message for banned IP.
 */
const char *
ban_message(ban_category_t cat, const host_addr_t addr)
{
	const struct addr_info *ipf;
	const struct ban *b;

	g_assert(uint_is_non_negative(cat) && cat < BAN_CAT_COUNT);

	b = ban_object[cat];
	ban_check(b);

	ipf = hevset_lookup(b->info, &addr);
	addr_info_check(ipf);

	return ipf->ban_msg;
}

/**
 * Initialize the banning system.
 */
void G_COLD
ban_init(void)
{
	ban_cq = cq_main_submake("ban", BAN_CALLOUT);

	ban_object[BAN_CAT_GNUTELLA] = ban_make(BAN_CAT_GNUTELLA, BAN_DELAY,
		MAX_GNET_REQUEST, MAX_GNET_PERIOD, MAX_GNET_BAN, BAN_GNET_REMIND);

	ban_object[BAN_CAT_HTTP] = ban_make(BAN_CAT_HTTP, BAN_DELAY,
		MAX_HTTP_REQUEST, MAX_HTTP_PERIOD, MAX_HTTP_BAN, BAN_HTTP_REMIND);

	ban_object[BAN_CAT_OOB_CLAIM] = ban_make(BAN_CAT_OOB_CLAIM, BAN_DELAY,
		MAX_OOB_REQUEST, MAX_OOB_PERIOD, MAX_OOB_BAN, 0);

	banned_fds = fifo_make();
	ban_max_recompute();
	file_register_fd_reclaimer(ban_reclaim_fd);
	socket_register_fd_reclaimer(ban_reclaim_fd);
}

/**
 * Recompute the maximum amount of file descriptors we dedicate to banning.
 */
void
ban_max_recompute(void)
{
	uint32 max;

	max = (GNET_PROPERTY(sys_nofile) * GNET_PROPERTY(ban_ratio_fds)) / 100;
	max = MIN(GNET_PROPERTY(ban_max_fds), max);
	max = MAX(1, max);

	if (GNET_PROPERTY(ban_debug))
		g_info("will use at most %d file descriptor%s for banning",
			max, plural(max));

	gnet_prop_set_guint32_val(PROP_MAX_BANNED_FD, max);

	/*
	 * Close file descriptors kept opened if we now have more banned slots
	 * than the new maximum allowed.
	 */

	BANNED_FDS_LOCK;

	while (GNET_PROPERTY(banned_count) > max) {
		if (!reclaim_fd())
			break;
	}

	BANNED_FDS_UNLOCK;
}

static void
ban_fifo_fd_free(void *data, void *unused)
{
	int fd = pointer_to_int(data);

	(void) unused;

	fd_close(&fd);
}

/**
 * Called at shutdown time to reclaim all memory.
 */
void G_COLD
ban_close(void)
{
	int n;

	for (n = 0; n < BAN_CAT_COUNT; n++) {
		ban_free(ban_object[n]);
	}

	fifo_free_all_null(&banned_fds, ban_fifo_fd_free, NULL);
	cq_free_null(&ban_cq);
}

/***
 *** Vendor-specific banning.
 ***/

/*
 * These messages are sent to the remote site. Don't localize them.
 */
static const char harmful[]   = N_("Harmful version banned, upgrade required");
static const char refused[]   = N_("Connection refused");
static const char alien_net[] = N_("Use an open Gnutella or G2 servent");

/**
 * Check whether servent identified by its vendor string should be banned.
 * When we ban, we ban for both gnet and download connections.  Such banning
 * is exceptional, usually restricted to some versions and the servent's author
 * is informed about the banning.
 *
 * @returns NULL if we shall not ban, a banning reason string otherwise.
 */
const char *
ban_vendor(const char *vendor)
{
	const char *gtkg_version;

	/*
	 * If vendor starts with "!gtk-gnutella", skip the leading '!' for
	 * our tests here.
	 */

	if (vendor[0] == '!') {
		if (NULL != (gtkg_version = is_strprefix(&vendor[1], "gtk-gnutella/")))
			vendor++;
	} else {
		gtkg_version = is_strprefix(vendor, "gtk-gnutella/");
	}

	/*
	 * Ban gtk-gnutella/0.90 from the network.  This servent had
	 * bugs that could corrupt the traffic.  Also ban 0.91u.
	 *
	 * Versions of GKTG deemed too old are also banned: the Gnutella
	 * network is far from being mature, and we need to ensure newer
	 * features are deployed reasonably quickly.
	 *		--RAM, 03/01/2002.
	 *
	 * As of 2014-06-16, any version older than 0.98 is deemed harmful to
	 * the network, since they are too ancient.
	 *
	 * As of 2020-06-05, any version older than 1.1 is deemed too old.
	 */

	if (gtkg_version) {
		uint major, minor;

		if (0 != parse_major_minor(gtkg_version, NULL, &major, &minor))
			return refused;			/* Cannot parse */

		if (0 == major || (1 == major && 0 == minor))
			return harmful;			/* Too old */

		return NULL;
	}

	if ('F' == vendor[0]) {
		if (is_strprefix(vendor, "Foxy "))
			return alien_net;
	}

	if ('G' == vendor[0]) {
		const char *ver;

		if (NULL != (ver = is_strprefix(vendor, "Gnucleus "))) {
			if (is_strprefix(ver, "1.6.0.0"))
				return harmful;
		} else if (is_strprefix(vendor, "Gtk-Gnutella "))
			return refused;

		return NULL;
	}

	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
