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

#ifdef HAS_KQUEUE
#include <sys/event.h>

/* In case any system has both, kqueue() is preferred */
#ifdef HAS_EPOLL
#undef HAS_EPOLL
#endif /* HAS_EPOLL */

#endif /* HAS_KQUEUE */

#ifdef HAS_EPOLL
#include <sys/epoll.h>
#endif /* HAS_EPOLL */

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

#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)

static const inputevt_handler_t zero_handler;

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
	inputevt_cond_t cond;
	
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
update_poll_event(gint pfd, gint fd, inputevt_cond_t old, inputevt_cond_t cur)
#ifdef HAS_KQUEUE
{
	static const struct timespec zero_ts;
	struct kevent kev[2];
	size_t i = 0;
	gulong udata = (gulong) GINT_TO_POINTER(fd);

	/* @todo TODO:
	 * Instead of updating each single event, we could probably accumulate them
	 * and then add all of them in check_poll_events(). However, events may be
	 * removed before ever polled etc., so it may be more complex as it sounds.
	 * It would save many syscalls though.
	 */
	
	if ((INPUT_EVENT_R & old) != (INPUT_EVENT_R & cur)) {
		EV_SET(&kev[i], fd, EVFILT_READ,
			(INPUT_EVENT_R & cur) ? EV_ADD : (EV_DELETE | EV_DISABLE),
			0, 0, udata);
		i++;
	}
	if ((INPUT_EVENT_W & old) != (INPUT_EVENT_W & cur)) {
		EV_SET(&kev[i], fd, EVFILT_WRITE,
			(INPUT_EVENT_W & cur) ? EV_ADD : (EV_DELETE | EV_DISABLE),
			0, 0, udata);
		i++;
	}
	return kevent(pfd, kev, i, NULL, 0, &zero_ts);
}
#else /* !HAS_KQUEUE */
{
	static const struct epoll_event zero_ev;
	struct epoll_event ev;

	ev = zero_ev;
	ev.data.ptr = GINT_TO_POINTER(fd);

	if ((INPUT_EVENT_R & old) != (INPUT_EVENT_R & cur)) {
		if (INPUT_EVENT_R & cur)
			ev.events |= EPOLLIN | EPOLLPRI;
	}
	if ((INPUT_EVENT_W & old) != (INPUT_EVENT_W & cur)) {
		if (INPUT_EVENT_W & cur)
			ev.events |= EPOLLOUT;
	}

	return epoll_ctl(pfd,
			ev.events ? (old ? EPOLL_CTL_MOD : EPOLL_CTL_ADD) : EPOLL_CTL_DEL,
			fd, &ev);
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
	
	size = (n / 8) + (n % (8 * sizeof base[0]) ? sizeof base[0] : 0);
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
	inputevt_cond_t cond, inputevt_relay_t *relay)
{
	GIOChannel *ch;
	guint id;
	
	ch = g_io_channel_unix_new(fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
	g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */
	
	id = g_io_add_watch_full(ch, G_PRIORITY_DEFAULT,
			(INPUT_EVENT_R & cond ? READ_CONDITION : 0) |
			(INPUT_EVENT_W & cond ? WRITE_CONDITION : 0) |
			(INPUT_EVENT_EXCEPTION & cond ? EXCEPTION_CONDITION : 0),
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
	GSList *removed;			/**< List of removed IDs */
	GHashTable *ht;				/**< Records file descriptors */
	guint num_ev;				/**< Length of the "ev" and "relay" arrays */
	gint fd;					/**< The ``master'' fd for epoll or kqueue */
	gboolean initialized;		/**< TRUE if the context has been initialized */
	gboolean dispatching;		/**< TRUE if dispatching events */
} poll_ctx;

void
inputevt_timer(void)
{
	gint n, i;

	g_assert(poll_ctx.initialized);
	g_assert(-1 != poll_ctx.fd);

	/* Maybe this must safely fail for general use, thus no assertion */
	g_return_if_fail(!poll_ctx.dispatching);

	n = check_poll_events(poll_ctx.fd, poll_ctx.ev, poll_ctx.num_ev);
	if (-1 == n) {
		g_warning("check_poll_events(%d) failed: %s",
			poll_ctx.fd, g_strerror(errno));
	}

	if (n < 1) {
		/* Nothing to dispatch */
		return;
	}
	g_assert(n > 0);
	g_assert((guint) n <= poll_ctx.num_ev);
	
	poll_ctx.dispatching = TRUE;

	for (i = 0; i < n; i++) {
		inputevt_cond_t cond;
		relay_list_t *rl;
		GSList *sl;
		gint fd;

		cond = get_poll_event_cond(&poll_ctx.ev[i]);
		fd = GPOINTER_TO_INT(get_poll_event_udata(&poll_ctx.ev[i]));
		g_assert(fd >= 0);
		
		rl = g_hash_table_lookup(poll_ctx.ht, GINT_TO_POINTER(fd));
		g_assert(NULL != rl);
		g_assert((0 == rl->readers && 0 == rl->writers) || NULL != rl->sl);

		for (sl = rl->sl; NULL != sl; /* NOTHING */) {
			inputevt_relay_t *relay;
			guint id;

			id = GPOINTER_TO_UINT(sl->data);
			sl = g_slist_next(sl);

			g_assert(id > 0);
			g_assert(id < poll_ctx.num_ev);

			relay = poll_ctx.relay[id];
			g_assert(relay);
			g_assert(relay->fd == fd);

			if (zero_handler == relay->handler)
				continue;

			if (relay->condition & cond)
				relay->handler(relay->data, fd, cond);
		}
	}
	
	if (poll_ctx.removed) {
		GSList *sl;

		for (sl = poll_ctx.removed; NULL != sl; sl = g_slist_next(sl)) {
			inputevt_relay_t *relay;
			relay_list_t *rl;
			guint id;
			gint fd;

			id = GPOINTER_TO_UINT(sl->data);
			g_assert(id > 0);
			g_assert(id < poll_ctx.num_ev);

			g_assert(0 != bit_array_get(poll_ctx.used, id));
			bit_array_clear(poll_ctx.used, id);

			relay = poll_ctx.relay[id];
			g_assert(relay);
			g_assert(zero_handler == relay->handler);

			fd = relay->fd;
			g_assert(fd >= 0);
			wfree(relay, sizeof *relay);
			poll_ctx.relay[id] = NULL;
			
			rl = g_hash_table_lookup(poll_ctx.ht, GINT_TO_POINTER(fd));
			g_assert(NULL != rl);
			g_assert(NULL != rl->sl);
		
			rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
			if (NULL == rl->sl) {
				g_assert(0 == rl->readers && 0 == rl->writers);
				wfree(rl, sizeof *rl);
				g_hash_table_remove(poll_ctx.ht, GINT_TO_POINTER(fd));
			}
		}

		g_slist_free(poll_ctx.removed);
		poll_ctx.removed = NULL;
	}
	
	poll_ctx.dispatching = FALSE;
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
		relay_list_t *rl;
		inputevt_cond_t old, cur;
		gint fd;

		g_assert(id < poll_ctx.num_ev);
		g_assert(0 != bit_array_get(poll_ctx.used, id));

		relay = poll_ctx.relay[id];
		g_assert(NULL != relay);
		g_assert(zero_handler != relay->handler);
		g_assert(relay->fd >= 0);

		fd = relay->fd;
		rl = g_hash_table_lookup(poll_ctx.ht, GINT_TO_POINTER(fd));
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
	
		if (-1 == update_poll_event(poll_ctx.fd, fd, old, cur)) {
			g_warning("update_poll_event(%d, %d) failed: %s",
				poll_ctx.fd, fd, g_strerror(errno));
		}
	
		/* Mark as removed */
		relay->handler = zero_handler;
		
		if (poll_ctx.dispatching) {
			/*
			 * Don't clear the "used" bit yet because this slot must
			 * not be recycled whilst dispatching events.
			 */
			poll_ctx.removed = g_slist_prepend(poll_ctx.removed,
									GUINT_TO_POINTER(id));
		} else {
			wfree(relay, sizeof *relay);
			
			rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
			if (NULL == rl->sl) {
				g_assert(0 == rl->readers && 0 == rl->writers);
				wfree(rl, sizeof *rl);
				g_hash_table_remove(poll_ctx.ht, GINT_TO_POINTER(fd));
				g_message("Removing fd %d", fd);
			}

			bit_array_clear(poll_ctx.used, id);
		}
	}
}

static inline guint
inputevt_get_free_id(void)
{
	if (0 == poll_ctx.num_ev)
		return (guint) -1;
	
	return bit_array_first_clear(poll_ctx.used, 0, poll_ctx.num_ev - 1);
}
#endif /* HAS_EPOLL || HAS_KQUEUE*/

static guint 
inputevt_add_source(gint fd, inputevt_cond_t cond, inputevt_relay_t *relay)
#if defined(HAS_EPOLL) || defined(HAS_KQUEUE)
{
	guint id;

	g_assert(poll_ctx.initialized);
	g_assert(fd >= 0);
	g_assert(relay);
	g_assert(relay->fd == fd);
	
	if (-1 == poll_ctx.fd) {
		/*
		 * Linux systems with 2.4 kernels usually have all epoll stuff
		 * in their headers but the system calls just return ENOSYS.
		 */
		id = inputevt_add_source_with_glib(fd, cond, relay);
	} else {
		inputevt_cond_t old;
		guint f;

		f = inputevt_get_free_id();
		g_assert((guint) -1 == f || f < poll_ctx.num_ev);

		if ((guint) -1 != f) {
			id = f;
		} else {
			guint i, n = poll_ctx.num_ev;
			size_t size;

			/*
			 * If there was no free ID, the arrays are resized to the
			 * double size.
			 */

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

		{
			gpointer key = GINT_TO_POINTER(fd);
			relay_list_t *rl;

			rl = g_hash_table_lookup(poll_ctx.ht, key);
			if (rl) {
				if (rl->writers || rl->readers)	{
					inputevt_relay_t *r;
					guint x;
		
			 		g_assert(NULL != rl->sl);
				
					x = GPOINTER_TO_UINT(rl->sl->data);
					g_assert(x != id);
					g_assert(x > 0);
					g_assert(x < poll_ctx.num_ev);

					r = poll_ctx.relay[x];
					g_assert(r);
					g_assert(r->fd == fd);
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

			if (INPUT_EVENT_R & cond)
				rl->readers++;
			if (INPUT_EVENT_W & cond)
				rl->writers++;

			rl->sl = g_slist_prepend(rl->sl, GUINT_TO_POINTER(id));
			g_hash_table_insert(poll_ctx.ht, key, rl);
		}

		cond |= old;
		if (
			cond != old &&
			-1 == update_poll_event(poll_ctx.fd, fd, old, cond)
		) {
			g_error("update_poll_event(%d, %d, ...) failed: %s",
				poll_ctx.fd, fd, g_strerror(errno));
		}
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
inputevt_add(gint fd, inputevt_cond_t cond,
	inputevt_handler_t handler, gpointer data)
{
	inputevt_relay_t *relay = walloc(sizeof *relay);
	gboolean ok;

	g_assert(fd >= 0);
	g_assert(zero_handler != handler);

	switch (cond) {
	case INPUT_EVENT_RX:
	case INPUT_EVENT_R:
	case INPUT_EVENT_WX:
	case INPUT_EVENT_W:
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
	CASE(INPUT_EVENT_RX);
	CASE(INPUT_EVENT_WX);
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

		poll_ctx.ht = g_hash_table_new(NULL, NULL);
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
