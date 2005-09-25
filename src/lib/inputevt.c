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

#ifndef FAKE_EPOLL
#include <sys/epoll.h>
#endif /* FAKE_EPOLL */

#if FAKE_EPOLL 
/* This is just for faking the existence of epoll() to check whether
 * things compile.
 */
typedef union epoll_data {
	void *ptr;
	int fd;
	guint32 u32;
	guint64 u64;
} epoll_data_t;

enum {
	EPOLLIN		= (1 << 0),
	EPOLLOUT	= (1 << 1),
	EPOLLERR	= (1 << 2),
	EPOLLHUP	= (1 << 3),
	EPOLLPRI	= (1 << 4),
	EPOLLET		= (1 << 5),
};

enum {
	EPOLL_CTL_ADD,
	EPOLL_CTL_MOD,
	EPOLL_CTL_DEL,
};

struct epoll_event {
	guint32 events;      /* Epoll events */
	epoll_data_t data;      /* User data variable */
};

int epoll_create(int n)
{
	(void) n;
	errno = ENOSYS;
	return -1;
}

int epoll_wait(int fd, struct epoll_event *events, int maxevents, int timeout)
{
	(void) fd;
	(void) events;
	(void) maxevents;
	(void) timeout;
	errno = ENOSYS;
	return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	(void) epfd;
	(void) op;
	(void) fd;
	(void) event;
	errno = ENOSYS;
	return -1;
}
#endif /* 0 */

#endif /* HAS_EPOLL */

#include "inputevt.h"
#include "walloc.h"
#include "override.h"		/* Must be the last header included */

/*
 * Macros for setting and getting bits of bit arrays. Parameters may be
 * evaluated multiple times, thus pass only constants or variables. No
 * bounds checks are performed. "base" must point to an array of an
 * integer type (like guint8, guint16, guint32 etc.).
 */

static inline void
bit_array_set(gulong *base, size_t i)
{
	base[i / sizeof base[0]] |= 1UL << (i % (8 * sizeof base[0]));
}

static inline void 
bit_array_clear(gulong *base, size_t i)
{
	base[i / sizeof base[0]] &= ~(1UL << (i % (8 * sizeof base[0])));
}

static inline void 
bit_array_clear_range(gulong *base, size_t from, size_t to)
{
	g_assert(from <= to);

	if (from <= to) {
		size_t i = from;
	
		do
			bit_array_clear(base, i);
		while (i++ != from);
	}
}

static inline void 
bit_array_flip(gulong *base, size_t i)
{
	base[i / sizeof (base[0])] ^= 1UL << (i % (8 * sizeof base[0]));
}

static inline gboolean
bit_array_get(const gulong *base, size_t i)
{
	return 0 != (base[i / sizeof base[0]] &
					(1UL << (i % (8 * sizeof base[0]))));
}

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
	
	return id;
}

#ifdef HAS_EPOLL

static struct {
	struct epoll_event *ev; 	/**< Used by epoll_wait() */
	inputevt_relay_t **relay;	/**< The relay contexts */
	gulong *used;				/**< A bit array, which ID slots are used */
	guint num_ev;				/**< Length of the "ev" and "relay" arrays */
	gint fd;					/**< The ``master'' fd for epoll() */
	gboolean initialized;		/**< TRUE if the context has been initialized */
} epoll_ctx;

static gboolean
dispatch_epoll(GIOChannel *source,
	GIOCondition unused_cond, gpointer unused_data)
{
	gint n, i;

	(void) unused_cond;
	(void) unused_data;
	g_assert(source);

	g_assert(epoll_ctx.initialized);
	g_assert(-1 != epoll_ctx.fd);

	n = epoll_wait(epoll_ctx.fd, epoll_ctx.ev, epoll_ctx.num_ev, 0);
	if (-1 == n) {
		g_warning("epoll_wait(%d) failed: %s",
			epoll_ctx.fd, g_strerror(errno));
	}

	for (i = 0; i < n; i++) {
		const struct epoll_event *ev;
		inputevt_relay_t *relay;
		GIOCondition cond;

		ev = &epoll_ctx.ev[i];
		relay = ev->data.ptr;
		cond =
			((EPOLLIN | EPOLLPRI | EPOLLHUP) & ev->events ? READ_CONDITION : 0)
			| (EPOLLOUT & ev->events ? WRITE_CONDITION : 0)
			| (EPOLLERR & ev->events ? EXCEPTION_CONDITION : 0);
			
		if (relay->condition & cond)
			relay->handler(relay->data, relay->fd, cond);
	}
		
	return TRUE;
}

void
inputevt_remove(guint id)
{
	g_assert(epoll_ctx.initialized);

	if (-1 == epoll_ctx.fd) {
		g_source_remove(id);
	} else {
		inputevt_relay_t *relay;
		
		g_assert(id < epoll_ctx.num_ev);
		g_assert(0 != bit_array_get(epoll_ctx.used, id));

		relay = epoll_ctx.relay[id];
		g_assert(NULL != relay);

		if (-1 == epoll_ctl(epoll_ctx.fd, EPOLL_CTL_DEL, relay->fd, NULL)) {
			g_warning("epoll_ctl(%d, EPOLL_CTL_DEL, %d, ...) failed: %s",
				epoll_ctx.fd, relay->fd, g_strerror(errno));
		}

		epoll_ctx.relay[id] = NULL;
		wfree(relay, sizeof *relay);
		bit_array_clear(epoll_ctx.used, id);
	}
}
#endif /* !HAS_EPOLL*/

static guint 
inputevt_add_source(gint fd, GIOCondition cond, inputevt_relay_t *relay)
#ifdef HAS_EPOLL
{
	guint id;

	g_assert(-1 != fd);
	g_assert(relay);
	
	if (!epoll_ctx.initialized) {
		epoll_ctx.initialized = TRUE;

		if (-1 == (epoll_ctx.fd = epoll_create(1024))) {
			g_warning("epoll_create() failed: %s", g_strerror(errno));
		} else {
			GIOChannel *ch;
			
			ch = g_io_channel_unix_new(fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
			g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */

			(void) g_io_add_watch(ch, READ_CONDITION,
					dispatch_epoll, GINT_TO_POINTER(epoll_ctx.fd));
		}
	}

	if (-1 == epoll_ctx.fd) {
		/*
		 * Linux systems with 2.4 kernels usually have all epoll stuff
		 * in their headers but the system calls just return ENOSYS.
		 */
		id = inputevt_add_source_with_glib(fd, cond, relay);
	} else {
		static const struct epoll_event zero_ev;
		struct epoll_event ev;

		ev = zero_ev;
		ev.data.ptr = relay;
		ev.events = (cond & EXCEPTION_CONDITION ? EPOLLERR : 0) |
					(cond & READ_CONDITION ? EPOLLIN : 0) |
					(cond & WRITE_CONDITION ? EPOLLOUT : 0);

		if (-1 == epoll_ctl(epoll_ctx.fd, EPOLL_CTL_ADD, fd, &ev)) {
			g_error("epoll_ctl(%d, EPOLL_CTL_ADD, %d, ...) failed: %s",
				epoll_ctx.fd, fd, g_strerror(errno));
			return -1;
		}

		/* Find a free ID */
		for (id = 0; id < epoll_ctx.num_ev; id++) {
			if (!bit_array_get(epoll_ctx.used, id))
				break;
		}

		/*
		 * If there was no free ID, the arrays are resized to the
		 * double size.
		 */
		if (epoll_ctx.num_ev == id) {
			size_t size;
			guint i, n = epoll_ctx.num_ev;

			if (0 != epoll_ctx.num_ev)			
				epoll_ctx.num_ev <<= 1;
			else
				epoll_ctx.num_ev = 32;

			size = epoll_ctx.num_ev * sizeof epoll_ctx.ev[0];
			epoll_ctx.ev = g_realloc(epoll_ctx.ev, size);

			size = (epoll_ctx.num_ev * sizeof epoll_ctx.used[0]) / 8 + 1;
			epoll_ctx.used = g_realloc(epoll_ctx.used, size);
			bit_array_clear_range(epoll_ctx.used, n, epoll_ctx.num_ev - 1);

			size = epoll_ctx.num_ev * sizeof epoll_ctx.relay[0];
			epoll_ctx.relay = g_realloc(epoll_ctx.relay, size);
			for (i = n; i < epoll_ctx.num_ev; i++)
				epoll_ctx.relay[i] = NULL;
		}

		g_assert(id < epoll_ctx.num_ev);
		bit_array_set(epoll_ctx.used, id);
		epoll_ctx.relay[id] = relay;
	}

	return id;
}
#else /* !HAS_EPOLL */
{
	return inputevt_add_source_with_glib(fd, cond, relay);
}
#endif /* HAS_EPOLL */

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

/**
 * Performs module initialization.
 */
void
inputevt_init(void)
{
	/* no initialization required */
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
