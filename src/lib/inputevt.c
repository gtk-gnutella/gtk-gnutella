/*
 * $Id$
 *
 * Copyright (c) 2002, ko (ko-@wanadoo.fr)
 * Copyright (c) 2005, Christian Biere
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
 * @ingroup lib
 * @file
 *
 * Input I/O notification.
 *
 * Basically this is a duplicate of the GDK input facilities,
 * without the features gtkg does not use.
 *
 * The intent here is to break the GDK dependency but retain
 * the same behavior, to avoid disturbing too much of the existing code.
 *
 * @author ko (ko-@wanadoo.fr)
 * @date 2002
 * @author Christian Biere
 * @date 2005
 */

#include "common.h"

RCSID("$Id$")

#ifdef HAS_KQUEUE
#include <sys/event.h>
/*
 * Some kqueue() implementations have a "struct kevent" with "udata"
 * being of type (void *) while others have "udata" of type "intptr_t".
 * To prevent incorrect casts and compiler warnings the two macros below
 * should be used to access this struct member.
 */
#if defined(HAS_KEVENT_INT_UDATA)
#define KEVENT_UDATA_TO_PTR(x) ulong_to_pointer(x)
#define PTR_TO_KEVENT_UDATA(x) pointer_to_ulong(x)
#else
#define KEVENT_UDATA_TO_PTR(x) (x)
#define PTR_TO_KEVENT_UDATA(x) (x)
#endif /* HAVE_KEVENT_INT_UDATA */

/* In case any system has both, kqueue() is preferred */
#undef HAS_EPOLL
#undef HAS_DEV_POLL

struct inputevt_array {
	struct kevent *ev;
};

#endif /* HAS_KQUEUE */

#ifdef HAS_EPOLL
#include <sys/epoll.h>

struct inputevt_array {
	struct epoll_event *ev;
};
#undef HAS_DEV_POLL

#endif /* HAS_EPOLL */

#ifdef HAS_DEV_POLL
#include <stropts.h>	/* ioctl() */
#include <sys/devpoll.h>

struct inputevt_array {
	struct pollfd *ev;
};
#endif /* HAS_DEV_POLL */

#if !(defined(HAS_DEV_POLL) || defined(HAS_EPOLL) || defined(HAS_KQUEUE))
#define USE_POLL 1
#endif	/* */

#include "inputevt.h"
#include "misc.h"
#include "walloc.h"
#include "tm.h"
#include "bit_array.h"
#include "override.h"		/* Must be the last header included */

/*
 * The following defines map the GDK-compatible input condition flags
 * to those used by GLIB.
 *
 * Interesting remark found in gdkevents.c :
 * What do we do with G_IO_NVAL ?
 */
#define READ_CONDITION		(G_IO_IN | G_IO_PRI)
#define WRITE_CONDITION		(G_IO_OUT)
#define EXCEPTION_CONDITION	(G_IO_ERR | G_IO_HUP | G_IO_NVAL)

const gchar *
inputevt_cond_to_string(inputevt_cond_t cond)
{
	switch (cond) {
#define CASE(x) case x: return #x
	CASE(INPUT_EVENT_EXCEPTION);
	CASE(INPUT_EVENT_R);
	CASE(INPUT_EVENT_W);
	CASE(INPUT_EVENT_RX);
	CASE(INPUT_EVENT_WX);
	CASE(INPUT_EVENT_RW);
	CASE(INPUT_EVENT_RWX);
#undef CASE
	}
	return "?";
}

/**
 * The relay structure is used as a bridge to provide GDK-compatible
 * input condition flags.
 */
typedef struct {
	inputevt_handler_t handler;
	gpointer data;
	inputevt_cond_t condition;
	gint fd;
} inputevt_relay_t;

typedef struct relay_list {
	GSList *sl;
	size_t readers;
	size_t writers;
} relay_list_t;

static const inputevt_handler_t zero_handler;

#if !defined(USE_POLL)
struct poll_ctx {
	struct inputevt_array ev_arr;
	inputevt_relay_t **relay;	/**< The relay contexts */
	bit_array_t *used;			/**< A bit array, which ID slots are used */
	GSList *removed;			/**< List of removed IDs */
	GHashTable *ht;				/**< Records file descriptors */
	guint num_ev;				/**< Length of the "ev" and "relay" arrays */
	guint num_ready;			/**< Used for /dev/poll only */
	gint fd;					/**< The ``master'' fd for epoll or kqueue */
	gboolean initialized;		/**< TRUE if the context has been initialized */
	gboolean dispatching;		/**< TRUE if dispatching events */
};

static inline struct poll_ctx *
get_global_poll_ctx(void)
{
	static struct poll_ctx poll_ctx;
	return &poll_ctx;
}

#endif /* !USE_POLL */

#ifndef HAS_KQUEUE
size_t
inputevt_data_available(void)
{
	return 0;
}
#endif	/* !HAS_KQUEUE */


#if defined(HAS_KQUEUE)

static guint data_available;	/** Used by inputevt_data_available(). */

static inline gint
get_poll_event_fd(gpointer p)
{
	struct kevent *ev = p;
	return pointer_to_uint(KEVENT_UDATA_TO_PTR(ev->udata));
}

static inline inputevt_cond_t 
get_poll_event_cond(gpointer p)
{
	struct kevent *ev = p;
	inputevt_cond_t cond;
	
	cond = EV_ERROR & ev->flags ? INPUT_EVENT_EXCEPTION : 0;
	switch (ev->filter) {
	case EVFILT_READ:
		cond |= INPUT_EVENT_R;
		break;
	case EVFILT_WRITE:
		cond |= INPUT_EVENT_W;
		break;
	default:
		g_assert_not_reached();
	}
	return cond;
}

/**
 * @return A positive value indicates how much data is available for reading.
 *		   If zero is returned the amount of available data is unknown.
 */
size_t
inputevt_data_available(void)
{
	return data_available;
}

static inline void
poll_event_set_data_avail(gpointer p)
{
	struct kevent *ev = p;

	data_available = EVFILT_READ == ev->filter ? MIN(INT_MAX, ev->data) : 0;
}

static int
create_poll_fd(void)
{
	return kqueue();
}

static gint
update_poll_event(struct poll_ctx *poll_ctx, gint fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct timespec zero_ts;
	struct kevent kev[2];
	size_t i;
	gpointer udata;
	gint ret;

	if ((INPUT_EVENT_RW & old) == (INPUT_EVENT_RW & cur))
		return 0;

	i = 0;
	udata = GINT_TO_POINTER(fd);

	if ((INPUT_EVENT_R & old) != (INPUT_EVENT_R & cur)) {
		EV_SET(&kev[i], fd, EVFILT_READ,
			(INPUT_EVENT_R & cur) ? EV_ADD : (EV_DELETE | EV_DISABLE),
			0, 0, PTR_TO_KEVENT_UDATA(udata));
		i++;
	}

	if ((INPUT_EVENT_W & old) != (INPUT_EVENT_W & cur)) {
		EV_SET(&kev[i], fd, EVFILT_WRITE,
			(INPUT_EVENT_W & cur) ? EV_ADD : (EV_DELETE | EV_DISABLE),
			0, 0, PTR_TO_KEVENT_UDATA(udata));
		i++;
	}

	if (-1 == (ret = kevent(poll_ctx->fd, kev, i, NULL, 0, &zero_ts)))
		g_error("kevent() failed: %s", g_strerror(errno));

	return ret;
}

static int
check_poll_events(struct poll_ctx *poll_ctx)
{
	static const struct timespec zero_ts;
	
	g_assert(poll_ctx);
	g_assert(poll_ctx->fd >= 0);

	return kevent(poll_ctx->fd, NULL, 0,
			poll_ctx->ev_arr.ev, poll_ctx->num_ev, &zero_ts);
}

#endif /* HAS_KQUEUE */

#if defined(HAS_EPOLL)

static inline gint
get_poll_event_fd(gpointer p)
{
	struct epoll_event *ev = p;
	return GPOINTER_TO_INT(ev->data.ptr);
}

static inline inputevt_cond_t 
get_poll_event_cond(gpointer p)
{
	struct epoll_event *ev = p;
	return ((EPOLLIN | EPOLLPRI | EPOLLHUP) & ev->events ? INPUT_EVENT_R : 0)
		| (EPOLLOUT & ev->events ? INPUT_EVENT_W : 0)
		| (EPOLLERR & ev->events ? INPUT_EVENT_EXCEPTION : 0);
}

static inline void
poll_event_set_data_avail(gpointer p)
{
	(void) p;
}

static int
create_poll_fd(void)
{
	return epoll_create(1024 /* Just an arbitrary value as hint */);
}

static gint
update_poll_event(struct poll_ctx *poll_ctx, gint fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct epoll_event zero_ev;
	struct epoll_event ev;
	gint op;

	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;
	if (cur == old)
		return 0;

	ev = zero_ev;
	ev.data.ptr = GINT_TO_POINTER(fd);

	if (INPUT_EVENT_R & cur)
		ev.events |= EPOLLIN | EPOLLPRI;
	if (INPUT_EVENT_W & cur)
		ev.events |= EPOLLOUT;

	if (0 == old)
		op = EPOLL_CTL_ADD;
	else if (0 == cur)
		op = EPOLL_CTL_DEL;
	else
		op = EPOLL_CTL_MOD;

	return epoll_ctl(poll_ctx->fd, op, fd, &ev);
}

static int
check_poll_events(struct poll_ctx *poll_ctx)
{
	g_assert(poll_ctx);
	g_assert(poll_ctx->fd >= 0);
	
	return epoll_wait(poll_ctx->fd, poll_ctx->ev_arr.ev, poll_ctx->num_ev, 0);
}

#endif	/* HAS_EPOLL */

#if defined(HAS_DEV_POLL)
static int
create_poll_fd(void)
{
	return get_non_stdio_fd(open("/dev/poll", O_RDWR));
}

static gint
update_poll_event(struct poll_ctx *poll_ctx, gint fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;
	if (cur != old) {
		static const struct pollfd zero_pfd;
		struct pollfd pfd[2];
		gint i = 0;

		if (0 != old) {
			pfd[i] = zero_pfd;
			pfd[i].fd = fd;
			pfd[i].events = POLLREMOVE;
			i++;
		}
		if (0 != cur) {
			pfd[i] = zero_pfd;
			pfd[i].fd = fd;
			pfd[i].events = 0
				| (INPUT_EVENT_R & cur ? (POLLIN | POLLPRI) : 0)
				| (INPUT_EVENT_W & cur ? POLLOUT : 0);
			i++;
		}

		{
			ssize_t ret;
			size_t size;
			size = i * sizeof pfd[0];
			ret = write(poll_ctx->fd, &pfd, size);
			if ((ssize_t) -1 == ret) {
				g_error("update_poll_event(): write() failed: %s",
						g_strerror(errno));
			}
			g_assert((size_t) ret == size);
		}
	}
	return 0;
}

static int
check_poll_events(struct poll_ctx *poll_ctx)
{
	int ret;

	ret = poll_ctx->num_ready;
	poll_ctx->num_ready = 0;
	return ret;
}

static inline inputevt_cond_t 
get_poll_event_cond(gpointer p)
{
	struct pollfd *ev = p;
	return ((POLLIN | POLLHUP) & ev->revents ? INPUT_EVENT_R : 0)
		| (POLLOUT & ev->revents ? INPUT_EVENT_W : 0)
		| ((POLLERR | POLLNVAL) & ev->revents ? INPUT_EVENT_EXCEPTION : 0);
}

static inline gint
get_poll_event_fd(gpointer p)
{
	const struct pollfd *pfd = p;
	return pfd->fd;
}

static inline void
poll_event_set_data_avail(gpointer p)
{
	(void) p;
}

static inline short
poll_events_from_gio_cond(gushort events)
{
	return 0
		| ((G_IO_IN   & events) ? POLLIN   : 0)
		| ((G_IO_OUT  & events) ? POLLOUT  : 0)
		| ((G_IO_PRI  & events) ? POLLPRI  : 0)
		| ((G_IO_HUP  & events) ? POLLHUP  : 0)
		| ((G_IO_ERR  & events) ? POLLERR  : 0)
		| ((G_IO_NVAL & events) ? POLLNVAL : 0);
}

static inline gushort
poll_events_to_gio_cond(short events)
{
	return 0
		| ((POLLIN   & events) ? G_IO_IN   : 0)
		| ((POLLOUT  & events) ? G_IO_OUT  : 0)
		| ((POLLPRI  & events) ? G_IO_PRI  : 0)
		| ((POLLHUP  & events) ? G_IO_HUP  : 0)
		| ((POLLERR  & events) ? G_IO_ERR  : 0)
		| ((POLLNVAL & events) ? G_IO_NVAL : 0);
}

static void
check_dev_poll(struct poll_ctx *poll_ctx, gint *timeout_ms_ptr)
{
	struct dvpoll dvp; 
	tm_t before, after, elapsed;
	time_delta_t d;
	gint ret, timeout_ms;

	g_assert(poll_ctx);
	g_assert(timeout_ms_ptr);
#if 0
	g_assert(0 == poll_ctx->num_ready);
#endif

	if (poll_ctx->num_ev <= 0) {
		poll_ctx->num_ready = 0;
		return;
	}

	timeout_ms = *timeout_ms_ptr;
	timeout_ms = MAX(0, timeout_ms);

	dvp.dp_timeout = timeout_ms;
	dvp.dp_nfds = poll_ctx->num_ev;
	dvp.dp_fds = poll_ctx->ev_arr.ev;

	tm_now_exact(&before);
	ret = ioctl(poll_ctx->fd, DP_POLL, &dvp);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("check_dev_poll(): ioctl() failed: %s", g_strerror(errno));
	}
	tm_now_exact(&after);
	tm_elapsed(&elapsed, &after, &before);
	d = tm2ms(&elapsed);
	if (d >= timeout_ms || ret > 0) {
		timeout_ms = 0;
	} else {
		timeout_ms -= d;
	}
	poll_ctx->num_ready = MAX(0, ret);

	/* If the original timeout was negative (=INFINITE) and no event
	 * has occured, the timeout isn't touched.
	 */
	if (*timeout_ms_ptr >= 0 || ret > 0) {
		*timeout_ms_ptr = timeout_ms;
	} 
}

/**
 * This code is only used for /dev/poll. This is necessary because the
 * device does not support polling...
 */
static gint
poll_func(GPollFD *gfds, guint n, gint timeout_ms)
{
	struct poll_ctx *poll_ctx;
	struct pollfd local_pfds[16], *pfds;
	size_t w_size = 0;
	gpointer w_buf = NULL;
	gboolean do_check = FALSE;
	gint ret;

	poll_ctx = get_global_poll_ctx();
	g_assert(poll_ctx);
	g_assert(poll_ctx->initialized);
	g_assert(poll_ctx->fd >= 0);

	if (n > 0) {
		guint i;

		if (n > G_N_ELEMENTS(local_pfds)) {
			w_size = n * sizeof *pfds;
			w_buf = walloc(w_size);
			pfds = w_buf;
		} else {
			pfds = local_pfds;
		}

		for (i = 0; i < n; i++) {
			pfds[i].fd = gfds[i].fd;
			if (gfds[i].fd != poll_ctx->fd) {
				pfds[i].events = poll_events_from_gio_cond(
									gfds[i].events & ~(G_IO_ERR | G_IO_NVAL));
			} else {
				pfds[i].events = 0;
				do_check = TRUE;
			}
			pfds[i].revents = 0;
			gfds[i].revents = 0;
		}
	} else {
		pfds = NULL;
	}

	if (do_check) {
		check_dev_poll(poll_ctx, &timeout_ms);
	}

	ret = poll(pfds, n, timeout_ms);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("poll() failed: %s", g_strerror(errno));
	}
	if (do_check || ret > 0) {
		guint i;

		g_assert(ret < 0 || (guint) ret <= n);

		for (i = 0; i < n; i++) {
			g_assert(gfds[i].fd == pfds[i].fd);
			if (gfds[i].fd != poll_ctx->fd) {
				if (ret > 0) {
					gfds[i].revents = poll_events_to_gio_cond(pfds[i].revents);
				}
			} else if (poll_ctx->num_ready > 0) {
				gfds[i].revents = G_IO_IN;
			}
		}
	}

	if (do_check && poll_ctx->num_ready > 0) {
		ret = 1 + MAX(0, ret);
	}

	WFREE_NULL(w_buf, w_size);
	return ret;
}
#endif	/* HAS_DEV_POLL */

/**
 * Frees the relay structure when its time comes.
 */
static void
inputevt_relay_destroy(gpointer data)
{
	inputevt_relay_t *relay = data;
	wfree(relay, sizeof *relay);
}

/**
 * Relays the event to the registered handler function.
 * The input condition flags are properly mapped before being passed on.
 */
static gboolean
inputevt_dispatch(GIOChannel *source, GIOCondition condition, gpointer data)
{
	inputevt_cond_t cond = 0;
	inputevt_relay_t *relay = data;

	g_assert(source);

	if (condition & READ_CONDITION)
		cond |= INPUT_EVENT_R;
	if (condition & WRITE_CONDITION)
		cond |= INPUT_EVENT_W;
	if (condition & EXCEPTION_CONDITION)
		cond |= INPUT_EVENT_EXCEPTION;

	if (relay->condition & cond)
		relay->handler(relay->data, relay->fd, cond);

	return TRUE;
}

static guint
inputevt_add_source_with_glib(inputevt_relay_t *relay)
{
	GIOChannel *ch;
	guint id;
	
	ch = g_io_channel_unix_new(relay->fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
	g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */
	
	id = g_io_add_watch_full(ch, G_PRIORITY_DEFAULT,
		(INPUT_EVENT_R & relay->condition ? READ_CONDITION : 0) |
		(INPUT_EVENT_W & relay->condition ? WRITE_CONDITION : 0) |
		(INPUT_EVENT_EXCEPTION & relay->condition ? EXCEPTION_CONDITION : 0),
		inputevt_dispatch, relay, inputevt_relay_destroy);
	g_io_channel_unref(ch);

	g_assert(0 != id);	
	return id;
}

#if !defined(USE_POLL)

static void
inputevt_timer(struct poll_ctx *poll_ctx)
{
	gint n, i;

	g_assert(poll_ctx);
	g_assert(poll_ctx->initialized);
	g_assert(poll_ctx->fd >= 0);
	g_assert(poll_ctx->ht);

	/* Maybe this must safely fail for general use, thus no assertion */
	g_return_if_fail(!poll_ctx->dispatching);

	n = check_poll_events(poll_ctx);
	if (-1 == n && !is_temporary_error(errno)) {
		g_warning("check_poll_events(%d) failed: %s",
			poll_ctx->fd, g_strerror(errno));
	}

	if (n < 1) {
		/* Nothing to dispatch */
		return;
	}
	g_assert(n > 0);
	g_assert((guint) n <= poll_ctx->num_ev);
	
	poll_ctx->dispatching = TRUE;

	for (i = 0; i < n; i++) {
		inputevt_cond_t cond;
		relay_list_t *rl;
		GSList *sl;
		gint fd;

		cond = get_poll_event_cond(&poll_ctx->ev_arr.ev[i]);
		fd = get_poll_event_fd(&poll_ctx->ev_arr.ev[i]);
		g_assert(fd >= 0);
		
		rl = g_hash_table_lookup(poll_ctx->ht, GINT_TO_POINTER(fd));
		g_assert(NULL != rl);
		g_assert((0 == rl->readers && 0 == rl->writers) || NULL != rl->sl);

		for (sl = rl->sl; NULL != sl; /* NOTHING */) {
			inputevt_relay_t *relay;
			guint id;

			id = GPOINTER_TO_UINT(sl->data);
			sl = g_slist_next(sl);

			g_assert(id > 0);
			g_assert(id < poll_ctx->num_ev);

			relay = poll_ctx->relay[id];
			g_assert(relay);
			g_assert(relay->fd == fd);

			if (zero_handler == relay->handler)
				continue;

			if (relay->condition & cond) {
				poll_event_set_data_avail(&poll_ctx->ev_arr.ev[i]);
				relay->handler(relay->data, fd, cond);
			}
		}
	}
	
	if (poll_ctx->removed) {
		GSList *sl;

		for (sl = poll_ctx->removed; NULL != sl; sl = g_slist_next(sl)) {
			inputevt_relay_t *relay;
			relay_list_t *rl;
			guint id;
			gint fd;

			id = GPOINTER_TO_UINT(sl->data);
			g_assert(id > 0);
			g_assert(id < poll_ctx->num_ev);

			g_assert(0 != bit_array_get(poll_ctx->used, id));
			bit_array_clear(poll_ctx->used, id);

			relay = poll_ctx->relay[id];
			g_assert(relay);
			g_assert(zero_handler == relay->handler);

			fd = relay->fd;
			g_assert(fd >= 0);
			wfree(relay, sizeof *relay);
			poll_ctx->relay[id] = NULL;
			
			rl = g_hash_table_lookup(poll_ctx->ht, GINT_TO_POINTER(fd));
			g_assert(NULL != rl);
			g_assert(NULL != rl->sl);
		
			rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
			if (NULL == rl->sl) {
				g_assert(0 == rl->readers && 0 == rl->writers);
				wfree(rl, sizeof *rl);
				g_hash_table_remove(poll_ctx->ht, GINT_TO_POINTER(fd));
			}
		}

		g_slist_free(poll_ctx->removed);
		poll_ctx->removed = NULL;
	}
	
	poll_ctx->dispatching = FALSE;
}

static gboolean
dispatch_poll(GIOChannel *unused_source,
	GIOCondition unused_cond, gpointer udata)
{
	(void) unused_cond;
	(void) unused_source;

	inputevt_timer(udata);

	return TRUE;
}

/**
 * @todo TODO:
 *
 * epoll/kqueue automagically unregister events on close(). Therefore, we
 * should indicate when we are going to close() a file descriptor. This
 * way, we don't need to call kevent() resp. epoll_ctl(..., EPOLL_CTL_DEL, ...)
 * to unregister the event. We only need to remove the handler for it, just
 * in case that are still non-dispatched events before the descriptor is
 * finally close()d.
 *
 * For kqueue it might be possible to queue up kevent changes until the
 * next kevent() polling call but use the above mentioned hinting to
 * flush the kevent calls. This useful because unlike epoll, kqueue allows to
 * add/modify/delete multiple events per syscall. The knowledge about closed
 * descriptors is necessary as kevent() fails with EBADF otherwise and it
 * must be kept in mind, that file descriptor numbers are recycled.
 */
void
inputevt_remove(guint id)
{
	struct poll_ctx *poll_ctx;

	poll_ctx = get_global_poll_ctx();
	g_assert(poll_ctx->initialized);
	g_assert(0 != id);

	if (poll_ctx->fd < 0) {
		g_source_remove(id);
	} else {
		inputevt_relay_t *relay;
		relay_list_t *rl;
		inputevt_cond_t old, cur;
		gint fd;

		g_assert(poll_ctx->ht);
		g_assert(id < poll_ctx->num_ev);
		g_assert(0 != bit_array_get(poll_ctx->used, id));

		relay = poll_ctx->relay[id];
		g_assert(NULL != relay);
		g_assert(zero_handler != relay->handler);
		g_assert(relay->fd >= 0);

		fd = relay->fd;
		rl = g_hash_table_lookup(poll_ctx->ht, GINT_TO_POINTER(fd));
		g_assert(NULL != rl);
		g_assert(NULL != rl->sl);

		g_assert(rl->readers > 0 || rl->writers > 0);
		old = (rl->readers ? INPUT_EVENT_R : 0) |
			(rl->writers ? INPUT_EVENT_W : 0);

		if (INPUT_EVENT_R & relay->condition) {
			g_assert(rl->readers > 0);
			--rl->readers;
		}
		if (INPUT_EVENT_W & relay->condition) {
			g_assert(rl->writers > 0);
			--rl->writers;
		}

		cur = (rl->readers ? INPUT_EVENT_R : 0) |
			(rl->writers ? INPUT_EVENT_W : 0);
	
		if (-1 == update_poll_event(poll_ctx, fd, old, cur)) {
			g_warning("update_poll_event(%d, %d) failed: %s",
				poll_ctx->fd, fd, g_strerror(errno));
		}
	
		/* Mark as removed */
		relay->handler = zero_handler;
		
		if (poll_ctx->dispatching) {
			/*
			 * Don't clear the "used" bit yet because this slot must
			 * not be recycled whilst dispatching events.
			 */
			poll_ctx->removed = g_slist_prepend(poll_ctx->removed,
									GUINT_TO_POINTER(id));
		} else {
			wfree(relay, sizeof *relay);
			
			rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
			if (NULL == rl->sl) {
				g_assert(0 == rl->readers && 0 == rl->writers);
				wfree(rl, sizeof *rl);
				g_hash_table_remove(poll_ctx->ht, GINT_TO_POINTER(fd));
			}

			bit_array_clear(poll_ctx->used, id);
		}
	}
}

static inline guint
inputevt_get_free_id(const struct poll_ctx *poll_ctx)
{
	if (0 == poll_ctx->num_ev)
		return (guint) -1;
	
	return bit_array_first_clear(poll_ctx->used, 0, poll_ctx->num_ev - 1);
}

static guint 
inputevt_add_source(inputevt_relay_t *relay)
{
	struct poll_ctx *poll_ctx;
	guint id;

	poll_ctx = get_global_poll_ctx();
	g_assert(poll_ctx->initialized);
	g_assert(relay->fd >= 0);
	
	if (poll_ctx->fd < 0) {
		/*
		 * Linux systems with 2.4 kernels usually have all epoll stuff
		 * in their headers but the system calls just return ENOSYS.
		 */
		id = inputevt_add_source_with_glib(relay);
	} else {
		inputevt_cond_t old;
		guint f;

		g_assert(poll_ctx->ht);

		f = inputevt_get_free_id(poll_ctx);
		g_assert((guint) -1 == f || f < poll_ctx->num_ev);

		if ((guint) -1 != f) {
			id = f;
		} else {
			guint i, n = poll_ctx->num_ev;
			size_t size;

			/*
			 * If there was no free ID, the arrays are resized to the
			 * double size.
			 */

			poll_ctx->num_ev = 0 != n ? n << 1 : 32;

			size = poll_ctx->num_ev * sizeof poll_ctx->ev_arr.ev[0];
			poll_ctx->ev_arr.ev = g_realloc(poll_ctx->ev_arr.ev, size);
			
			poll_ctx->used = bit_array_realloc(poll_ctx->used,
								poll_ctx->num_ev);
			bit_array_clear_range(poll_ctx->used, n, poll_ctx->num_ev - 1);

			if (0 == n) {
				/* ID 0 is reserved for compatibility with GLib's IDs */
				bit_array_set(poll_ctx->used, 0);
				id = 1;
			} else {
				id = n;
			}

			size = poll_ctx->num_ev * sizeof poll_ctx->relay[0];
			poll_ctx->relay = g_realloc(poll_ctx->relay, size);
			for (i = n; i < poll_ctx->num_ev; i++)
				poll_ctx->relay[i] = NULL;
		}

		g_assert(id < poll_ctx->num_ev);
		bit_array_set(poll_ctx->used, id);
		g_assert(0 != bit_array_get(poll_ctx->used, id));

		poll_ctx->relay[id] = relay;

		{
			gpointer key = GINT_TO_POINTER(relay->fd);
			relay_list_t *rl;

			rl = g_hash_table_lookup(poll_ctx->ht, key);
			if (rl) {
				if (rl->writers || rl->readers)	{
					inputevt_relay_t *r;
					guint x;
		
			 		g_assert(NULL != rl->sl);
				
					x = GPOINTER_TO_UINT(rl->sl->data);
					g_assert(x != id);
					g_assert(x > 0);
					g_assert(x < poll_ctx->num_ev);

					r = poll_ctx->relay[x];
					g_assert(r);
					g_assert(r->fd == relay->fd);
				}
				old = (rl->readers ? INPUT_EVENT_R : 0) |
					(rl->writers ? INPUT_EVENT_W : 0);
			} else {
				rl = walloc(sizeof *rl);
				rl->readers = 0;
				rl->writers = 0;
				rl->sl = NULL;
				old = 0;
			}

			if (INPUT_EVENT_R & relay->condition)
				rl->readers++;
			if (INPUT_EVENT_W & relay->condition)
				rl->writers++;

			rl->sl = g_slist_prepend(rl->sl, GUINT_TO_POINTER(id));
			g_hash_table_insert(poll_ctx->ht, key, rl);
		}

		if (
			-1 == update_poll_event(poll_ctx, relay->fd,
					old, (old | relay->condition))
		) {
			g_error("update_poll_event(%d, %d, ...) failed: %s",
				poll_ctx->fd, relay->fd, g_strerror(errno));
		}
	}

	g_assert(0 != id);	
	return id;
}

/**
 * Performs module initialization.
 */
void
inputevt_init(void)
{
	struct poll_ctx *poll_ctx;
	
	poll_ctx = get_global_poll_ctx();
	g_assert(!poll_ctx->initialized);
	
	poll_ctx->initialized = TRUE;

	poll_ctx->fd = create_poll_fd();
	if (poll_ctx->fd < 0) {
		g_warning("create_poll_fd() failed: %s", g_strerror(errno));
		/* This is no hard error, we fall back to the GLib source watcher */
	} else {
		GIOChannel *ch;

#ifdef HAS_DEV_POLL
		g_main_set_poll_func(poll_func);
#endif	/* HAS_DEV_POLL */

		poll_ctx->ht = g_hash_table_new(NULL, NULL);
		ch = g_io_channel_unix_new(poll_ctx->fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
		g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */

		(void) g_io_add_watch(ch, READ_CONDITION, dispatch_poll, poll_ctx);
	}
}

#endif /* !USE_POLL */

#ifdef USE_POLL
static guint 
inputevt_add_source(inputevt_relay_t *relay)
{
	return inputevt_add_source_with_glib(relay);
}

void
inputevt_remove(guint id)
{
	g_source_remove(id);
}

void
inputevt_init(void)
{
	/* Nothing to do */
}
#endif /* USE_POLL */

/**
 * Adds an event source to the main GLIB monitor queue.
 *
 * A replacement for gdk_input_add().
 * Behaves exactly the same, except destroy notification has
 * been removed (since gtkg does not use it).
 */
guint
inputevt_add(gint fd, inputevt_cond_t cond,
	inputevt_handler_t handler, gpointer data)
{
	inputevt_relay_t *relay = walloc(sizeof *relay);
	gboolean ok = FALSE;

	g_assert(fd >= 0);
	g_assert(zero_handler != handler);

	switch (cond) {
	case INPUT_EVENT_RX:
	case INPUT_EVENT_R:
	case INPUT_EVENT_WX:
	case INPUT_EVENT_W:
	case INPUT_EVENT_RWX:
	case INPUT_EVENT_RW:
		ok = TRUE;
		break;
	case INPUT_EVENT_EXCEPTION:
		g_error("must not specify INPUT_EVENT_EXCEPTION only!");
	}
	g_assert(ok);

	relay->condition = cond;
	relay->handler = handler;
	relay->data = data;
	relay->fd = fd;

	return inputevt_add_source(relay);
}

/**
 * Performs module cleanup.
 */
void
inputevt_close(void)
{
	/* no cleanup required */
}

/* vi: set ts=4 sw=4 cindent: */
