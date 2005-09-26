/*
 * $Id$
 *
 * Copyright (c) 2002, ko (ko-@wanadoo.fr)
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
 */

#include "common.h"

RCSID("$Id$");

#ifdef HAS_EPOLL
#include <sys/epoll.h>
#endif /* HAS_EPOLL */

#ifdef HAS_KQUEUE
#include <sys/event.h>
#endif /* HAS_KQUEUE */

#include "inputevt.h"
#include "walloc.h"
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

/**
 * The relay structure is used as a bridge to provide GDK-compatible
 * input condition flags.
 */
typedef struct {
	inputevt_cond_t condition;
	inputevt_handler_t handler;
	gpointer data;
	gint fd;
} inputevt_relay_t;


#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)

static inline gpointer
get_poll_event_udata(gpointer p)
#ifdef HAS_KQUEUE 
{
	struct kevent *ev = p;
	return (gpointer) (gulong) ev->udata;
}
#else /* !HAS_KQUEUE */
{
	struct epoll_event *ev = p;
	return ev->data.ptr;
}
#endif /* HAS_KQUEUE */

static inline inputevt_cond_t 
get_poll_event_cond(gpointer p)
#ifdef HAS_KQUEUE 
{
	struct kevent *ev = p;
	GIOCondition cond;
	
	cond = EV_ERROR & ev->flags ? INPUT_EVENT_EXCEPTION : 0;
	switch (ev->filter) {
	case EVFILT_READ:
		cond |= INPUT_EVENT_R;
		break;
	case EVFILT_WRITE:
		cond |= INPUT_EVENT_W;
		break;
	}
	return cond;
}
#else /* !HAS_KQUEUE */
{
	struct epoll_event *ev = p;
	return ((EPOLLIN | EPOLLPRI | EPOLLHUP) & ev->events ? INPUT_EVENT_R : 0)
		| (EPOLLOUT & ev->events ? INPUT_EVENT_W : 0)
		| (EPOLLERR & ev->events ? INPUT_EVENT_EXCEPTION : 0);
}
#endif /* HAS_KQUEUE */


static gint
add_poll_event(gint pfd, gint fd, GIOCondition cond, gpointer udata)
#ifdef HAS_KQUEUE
{
	static const struct timespec zero_ts;
	struct kevent kev[2];
	size_t i = 0;

	if (READ_CONDITION & cond) {
		g_message("add_poll_event(%d, %d, EVFILT_READ, ...)", pfd, fd);
		EV_SET(&kev[i], fd, EVFILT_READ, EV_ADD,
			0, 0, (gulong) (gpointer) udata);
		i++;
	}
	if (WRITE_CONDITION & cond) {
		g_message("add_poll_event(%d, %d, EVFILT_WRITE, ...)", pfd, fd);
		EV_SET(&kev[i], fd, EVFILT_WRITE, EV_ADD,
			0, 0, (gulong) (gpointer) udata);
		i++;
	}

	/* @todo TODO:
	 * Instead of adding each single event, we could probably accumulate them
	 * and then add all of them in check_poll_events(). However, events may be
	 * removed before ever polled etc., so it may be more complex as it sounds.
	 * It would save many syscalls though.
	 */
	return kevent(pfd, kev, i, NULL, 0, &zero_ts);
}
#else /* !HAS_KQUEUE */
{
	static const struct epoll_event zero_ev;
	struct epoll_event ev;

	ev = zero_ev;
	ev.data.ptr = udata;
	ev.events = (cond & EXCEPTION_CONDITION ? EPOLLERR : 0) |
				(cond & READ_CONDITION ? EPOLLIN : 0) |
				(cond & WRITE_CONDITION ? EPOLLOUT : 0);

	return epoll_ctl(pfd, EPOLL_CTL_ADD, fd, &ev);
}
#endif /* HAS_KQUEUE */

static gint
remove_poll_event(gint pfd, gint fd)
#ifdef HAS_KQUEUE
{
	static const struct timespec zero_ts;
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE | EV_DISABLE, 0, 0, 0);
	if (-1 == kevent(pfd, &kev, 1, NULL, 0, &zero_ts) && ENOENT != errno) {
		g_warning("kevent() failed (fd=%d, EVFIL_READ): %s",
			fd, g_strerror(errno));
		raise(SIGTRAP);
	}
	EV_SET(&kev, fd, EVFILT_WRITE, EV_DELETE | EV_DISABLE, 0, 0, 0);
	if (-1 == kevent(pfd, &kev, 1, NULL, 0, &zero_ts) && ENOENT != errno) {
		g_warning("kevent() failed (fd=%d, EVFIL_WRITE): %s",
			fd, g_strerror(errno));
		raise(SIGTRAP);
	}
	return 0;
}
#else /* !HAS_KQUEUE */
{
	return epoll_ctl(pfd, EPOLL_CTL_DEL, fd, NULL);
}
#endif /* HAS_KQUEUE */

static int
create_poll_fd(void)
#ifdef HAS_KQUEUE 
{
	return kqueue();
}
#else /* !HAS_KQUEUE */
{
	return epoll_create(1024 /* Just an arbitrary value as hint */);
}
#endif /* HAS_KQUEUE */

static int
check_poll_events(int fd, gpointer events, int n)
#ifdef HAS_KQUEUE 
{
	static const struct timespec zero_ts;
	
	g_assert(fd >= 0);
	g_assert(n >= 0);
	g_assert(0 == n || NULL != events);
	
	g_message("%s(%d, %p, %d)", __func__, fd, events, n);
	return kevent(fd, NULL, 0, events, n, &zero_ts);
}
#else /* !HAS_KQUEUE */
{
	g_assert(fd >= 0);
	g_assert(n >= 0);
	g_assert(0 == n || NULL != events);
	
	return epoll_wait(fd, events, n, 0);
}
#endif /* HAS_KQUEUE */

#endif /* HAS_EPOLL || HAS_KQUEUE */

/*
 * Functions for handling arrays of bits. On BSD systems, the * macros from
 * <bitstring.h> could be used for better efficiency. So far, the following
 * implementation does not eliminate loop overhead by handling all bits
 * of a "gulong" at once where possible.
 */

/* @todo TODO: Move these functions to bit_array.h */

static inline gulong *
bit_array_realloc(gulong *base, size_t n)
{
	size_t size;
	
	size = n / (8 * sizeof base[0]);
	size += n % (8 * sizeof base[0]) ? 1 : 0;
	size *= sizeof base[0];
	return g_realloc(base, size);
}

#define BIT_ARRAY_BYTE(base, i) base[i / (8 * sizeof base[0])]
#define BIT_ARRAY_BIT(base, i) (1UL << (i % (8 * sizeof base[0]))) 

static inline void
bit_array_set(gulong *base, size_t i)
{
	BIT_ARRAY_BYTE(base, i) |= BIT_ARRAY_BIT(base, i);
}

static inline void 
bit_array_clear(gulong *base, size_t i)
{
	BIT_ARRAY_BYTE(base, i) &= ~BIT_ARRAY_BIT(base, i);
}

static inline void 
bit_array_flip(gulong *base, size_t i)
{
	BIT_ARRAY_BYTE(base, i) ^= BIT_ARRAY_BIT(base, i);
}

static inline gboolean
bit_array_get(const gulong *base, size_t i)
{
	return 0 != (BIT_ARRAY_BYTE(base, i) & BIT_ARRAY_BIT(base, i));
}

static inline void 
bit_array_clear_range(gulong *base, size_t from, size_t to)
{
	g_assert(from <= to);

	if (from <= to) {
		size_t i = from;
	
		do
			bit_array_clear(base, i);
		while (i++ != to);
	}
}

static inline size_t
bit_array_first_clear(gulong *base, size_t from, size_t to)
{
	g_assert(from <= to);

	if (from <= to) {
		size_t i = from;
	
		do
			if (0 == bit_array_get(base, i))
				return i;
		while (i++ != to);
	}

	return (size_t) -1;
}

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
inputevt_add_source_with_glib(gint fd,
	GIOCondition cond, inputevt_relay_t *relay)
{
	GIOChannel *ch;
	guint id;
	
	ch = g_io_channel_unix_new(fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
	g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */
	
	id = g_io_add_watch_full(ch, G_PRIORITY_DEFAULT, cond,
				 inputevt_dispatch, relay, inputevt_relay_destroy);
	g_io_channel_unref(ch);

	g_assert(0 != id);	
	return id;
}

#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)

static struct {
#ifdef HAS_KQUEUE
	struct kevent *ev; 			/**< Used by kevent() */
#else /* HAS_KQUEUE */
	struct epoll_event *ev; 	/**< Used by epoll_wait() */
#endif /* !HAS_KQUEUE */

	inputevt_relay_t **relay;	/**< The relay contexts */
	gulong *used;				/**< A bit array, which ID slots are used */
	guint num_ev;				/**< Length of the "ev" and "relay" arrays */
	gint fd;					/**< The ``master'' fd for epoll or kqueue */
	gboolean initialized;		/**< TRUE if the context has been initialized */
	guint dispatch_id;			/**< ID of the currently dispatched event */
} poll_ctx;

void
inputevt_timer(void)
{
	gint n, i;

	g_assert(poll_ctx.initialized);
	g_assert(-1 != poll_ctx.fd);

	/* Maybe this must safely fail for general use, thus no assertion */
	g_return_if_fail(0 == poll_ctx.dispatch_id);

	n = check_poll_events(poll_ctx.fd, poll_ctx.ev, poll_ctx.num_ev);
	if (-1 == n) {
		g_warning("check_poll_events(%d) failed: %s",
			poll_ctx.fd, g_strerror(errno));
	}

	for (i = 0; i < n; i++) {
		inputevt_relay_t *relay;
		GIOCondition cond;

		/* A relay handler might remove any of the other registered events */
		if (0 == bit_array_get(poll_ctx.used, i))
			continue;

		poll_ctx.dispatch_id = i;
		cond = get_poll_event_cond(&poll_ctx.ev[i]);
		relay = get_poll_event_udata(&poll_ctx.ev[i]);
		g_assert(relay);
		g_assert(relay->fd >= 0);

#if 0
		g_message("relay: fd=%d, cond=%s, handler=%p",
			relay->fd, inputevt_cond_to_string(cond), relay->handler);
#endif
		
		if (relay->condition & cond)
			relay->handler(relay->data, relay->fd, cond);
#if 0
		else
			g_message("IGNORED!!!");
#endif
	}
	poll_ctx.dispatch_id = 0;
}

static gboolean
dispatch_poll(GIOChannel *unused_source,
	GIOCondition unused_cond, gpointer unused_data)
{
	(void) unused_cond;
	(void) unused_data;
	(void) unused_source;

	inputevt_timer();

	return TRUE;
}

void
inputevt_remove(guint id)
{
	g_assert(poll_ctx.initialized);
	g_assert(0 != id);

	if (-1 == poll_ctx.fd) {
		g_source_remove(id);
	} else {
		inputevt_relay_t *relay;
		
		g_assert(id < poll_ctx.num_ev);
		g_assert(0 != bit_array_get(poll_ctx.used, id));

		relay = poll_ctx.relay[id];
		g_assert(NULL != relay);

		
		if (-1 == remove_poll_event(poll_ctx.fd, relay->fd)) {
			g_warning("remove_poll_event(%d, %d) failed: %s",
				poll_ctx.fd, relay->fd, g_strerror(errno));
		}

		poll_ctx.relay[id] = NULL;
		wfree(relay, sizeof *relay);
		bit_array_clear(poll_ctx.used, id);
	}
}
#endif /* HAS_EPOLL || HAS_KQUEUE*/

static guint 
inputevt_add_source(gint fd, GIOCondition cond, inputevt_relay_t *relay)
#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)
{
	guint id;

	g_assert(poll_ctx.initialized);
	g_assert(fd >= 0);
	g_assert(relay);
	
	if (-1 == poll_ctx.fd) {
		/*
		 * Linux systems with 2.4 kernels usually have all epoll stuff
		 * in their headers but the system calls just return ENOSYS.
		 */
		id = inputevt_add_source_with_glib(fd, cond, relay);
	} else {
		size_t f, h;

		if (-1 == add_poll_event(poll_ctx.fd, fd, cond, relay)) {
			g_error("epoll_ctl(%d, EPOLL_CTL_ADD, %d, ...) failed: %s",
				poll_ctx.fd, fd, g_strerror(errno));
			return -1;
		}

		if (poll_ctx.num_ev > 0) {
			/*
			 * A relay handler can remove and register any event whilst we
			 * iterate in inputevt_timer(). Therefore, not yet dispatched
			 * events must not be recycled because this could cause emission
			 * of a bogus event for the wrong file descriptor.
			 */
			if (0 != poll_ctx.dispatch_id)
				h = poll_ctx.dispatch_id - 1;
			else 
				h = poll_ctx.num_ev - 1;

			/* Find a free ID */
			f = bit_array_first_clear(poll_ctx.used, 0, h);
		} else {
			f = (size_t) -1;
		}
		g_assert((size_t) -1 == f || f < poll_ctx.num_ev);

		/*
		 * If there was no free ID, the arrays are resized to the
		 * double size.
		 */
		if ((size_t) -1 != f) {
			id = f;
		} else {
			guint i, n = poll_ctx.num_ev;
			size_t size;

			poll_ctx.num_ev = 0 != n ? n << 1 : 32;

			size = poll_ctx.num_ev * sizeof poll_ctx.ev[0];
			poll_ctx.ev = g_realloc(poll_ctx.ev, size);

			poll_ctx.used = bit_array_realloc(poll_ctx.used, poll_ctx.num_ev);
			bit_array_clear_range(poll_ctx.used, n, poll_ctx.num_ev - 1);

			if (0 == n) {
				/* ID 0 is reserved for compatibility with GLib's IDs */
				bit_array_set(poll_ctx.used, 0);
				id = 1;
			} else {
				id = n;
			}

			size = poll_ctx.num_ev * sizeof poll_ctx.relay[0];
			poll_ctx.relay = g_realloc(poll_ctx.relay, size);
			for (i = n; i < poll_ctx.num_ev; i++)
				poll_ctx.relay[i] = NULL;
		}

		g_assert(id < poll_ctx.num_ev);
		bit_array_set(poll_ctx.used, id);
		g_assert(0 != bit_array_get(poll_ctx.used, id));
		poll_ctx.relay[id] = relay;
	}

	g_assert(0 != id);	
	return id;
}
#else /* !(HAS_EPOLL || HAS_KQUEUE) */
{
	return inputevt_add_source_with_glib(fd, cond, relay);
}
#endif /* HAS_EPOLL || HAS_KQUEUE */

/**
 * Adds an event source to the main GLIB monitor queue.
 *
 * A replacement for gdk_input_add().
 * Behaves exactly the same, except destroy notification has
 * been removed (since gtkg does not use it).
 */
guint
inputevt_add(gint fd, inputevt_cond_t condition,
	inputevt_handler_t handler, gpointer data)
{
	inputevt_relay_t *relay = walloc(sizeof *relay);
	GIOCondition cond = 0;

	relay->condition = condition;
	relay->handler = handler;
	relay->data = data;
	relay->fd = fd;

	switch (condition) {
	case INPUT_EVENT_RX:
		cond |= EXCEPTION_CONDITION;
	case INPUT_EVENT_R:
		cond |= READ_CONDITION;
		break;

	case INPUT_EVENT_WX:
		cond |= EXCEPTION_CONDITION;
	case INPUT_EVENT_W:
		cond |= WRITE_CONDITION;
		break;

	case INPUT_EVENT_RWX:
		cond |= EXCEPTION_CONDITION;
	case INPUT_EVENT_RW:
		cond |= (READ_CONDITION | WRITE_CONDITION);
		break;

	case INPUT_EVENT_EXCEPTION:
		g_error("must not specify INPUT_EVENT_EXCEPTION only!");
	}
	g_assert(0 != cond);

	return inputevt_add_source(fd, cond, relay);
}

const gchar *
inputevt_cond_to_string(inputevt_cond_t cond)
{
	switch (cond) {
#define CASE(x) case x: return STRINGIFY(x)
	CASE(INPUT_EVENT_EXCEPTION);
	CASE(INPUT_EVENT_R);
	CASE(INPUT_EVENT_W);
	CASE(INPUT_EVENT_RW);
	CASE(INPUT_EVENT_RX);
	CASE(INPUT_EVENT_WX);
	CASE(INPUT_EVENT_RWX);
#undef CASE
	}
	return "?";
}

/**
 * Performs module initialization.
 */
void
inputevt_init(void)
{
#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)
	g_assert(!poll_ctx.initialized);
	
	poll_ctx.initialized = TRUE;

	if (-1 == (poll_ctx.fd = create_poll_fd())) {
		g_warning("create_poll_fd() failed: %s", g_strerror(errno));
		/* This is no hard error, we fall back to the GLib source watcher */
	} else {
		GIOChannel *ch;
			
		ch = g_io_channel_unix_new(poll_ctx.fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
		g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */

		(void) g_io_add_watch(ch, READ_CONDITION, dispatch_poll, NULL);
	}
#endif /* HAS_EPOLL || HAS_KQUEUE */
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
