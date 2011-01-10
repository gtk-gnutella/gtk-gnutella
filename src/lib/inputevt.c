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

/**
 * Select the optimum I/O event handling scheme
 */
#if defined(HAS_KQUEUE)
#define USE_KQUEUE
#elif defined(HAS_EPOLL)
#define USE_EPOLL
#elif defined(HAS_DEV_POLL)
#define USE_DEV_POLL
#elif defined(HAS_SELECT) && defined(MINGW32)
#define USE_POLL		/* Use if WSAPoll() if possible */
#define USE_WIN_SELECT	/* Fallback without WSAPoll() */
#elif defined(HAS_POLL) || defined(HAS_SELECT)
#define USE_POLL
#else
#define USE_GLIB_IO_CHANNELS	/* Use GLib IO Channels with default function */
#endif

/**
 * Debugging options.
 */
#if 0
#define INPUTEVT_SAFETY_ASSERT	/* Enable safety_assert() */
#endif
#if 1
#define INPUTEVT_DEBUGGING		/* Additional debugging traces */
#endif

#ifdef INPUTEVT_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

/* Enable and tweak, for testing only */
#if 0 /* XXX */
#undef USE_POLL
#undef USE_EPOLL
#undef USE_KQUEUE
#undef USE_DEV_POLL
#undef USE_GLIB_IO_CHANNELS
#undef USE_WIN_SELECT

/* Override by manual #define below */
#define USE_WIN_SELECT
#define USE_POLL

/* The following lines are for test-compiling without MINGW */
#if 0 && !defined(MINGW32)
#define mingw_has_wsapoll() 0
typedef struct {
	unsigned short fd_count;
	unsigned fd_array[FD_SETSIZE];
} FAKE_fd_set;
#define fd_set FAKE_fd_set
#define MINGW32 1
#endif	/* !MINGW32 */

#endif /* XXX */

#ifdef USE_KQUEUE
#include <sys/event.h>
/*
 * Some kqueue() implementations have a "struct kevent" with "udata"
 * being of type (void *) while others have "udata" of type "intptr_t".
 * To prevent incorrect casts and compiler warnings the two macros below
 * should be used to access this struct member.
 */
#ifdef HAS_KEVENT_INT_UDATA
#define KEVENT_UDATA_TO_PTR(x) ulong_to_pointer(x)
#define PTR_TO_KEVENT_UDATA(x) pointer_to_ulong(x)
#else
#define KEVENT_UDATA_TO_PTR(x) (x)
#define PTR_TO_KEVENT_UDATA(x) (x)
#endif /* HAVE_KEVENT_INT_UDATA */

struct inputevt_array {
	struct kevent *ev;
};

#endif /* USE_KQUEUE */

#ifdef USE_EPOLL
#include <sys/epoll.h>

struct inputevt_array {
	struct epoll_event *ev;
};

#endif /* USE_EPOLL */

#ifdef USE_DEV_POLL
#include <stropts.h>	/* ioctl() */
#include <sys/devpoll.h>

struct inputevt_array {
	struct pollfd *ev;
};
#endif /* USE_DEV_POLL */

#if defined(USE_POLL) || defined(USE_WIN_SELECT)
struct inputevt_array {
	struct pollfd *ev;
};
#endif	/* USE_POLL */


/**
 * The following functions must be implemented by any I/O event handler:
 *
 * 	gboolean create_poll_fd(int *fd_ptr);
 * 	int check_poll_events(struct poll_ctx *poll_ctx);
 * 	inline inputevt_cond_t get_poll_event_cond(unsigned idx);
 * 	int get_poll_event_fd(unsigned idx);
 * 	void poll_event_set_data_avail(gpointer p);
 * 	int update_poll_event(struct poll_ctx *poll_ctx, int fd,
 * 		inputevt_cond_t old, inputevt_cond_t cur);
 *
 * When INPUTEVT_DEBUGGING is set, one also needs:
 *
 *  const char *polling_method(void);
 */

#include "bit_array.h"
#include "compat_poll.h"
#include "fd.h"
#include "inputevt.h"
#include "glib-missing.h"
#include "misc.h"
#include "tm.h"
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

const char *
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
	int fd;
} inputevt_relay_t;

typedef struct relay_list {
	GSList *sl;
	size_t readers;
	size_t writers;
	unsigned poll_idx;
} relay_list_t;

static const inputevt_handler_t zero_handler;

#if !defined(USE_GLIB_IO_CHANNELS)
struct poll_ctx {
	inputevt_relay_t **relay;	/**< The relay contexts */
	bit_array_t *used_event_id;	/**< A bit array, which ID slots are used */
	bit_array_t *used_poll_idx;	/**< -"-, which Poll IDX slots are used */
	GSList *removed;			/**< List of removed IDs */
	GHashTable *ht;				/**< Records file descriptors */
	guint num_ev;				/**< Length of the "ev" and "relay" arrays */
	guint num_poll_idx;			/**< Length of used_poll_idx array */
	guint num_ready;			/**< Used for /dev/poll only */
	int fd;						/**< The ``master'' fd for epoll or kqueue */
	unsigned initialized:1;		/**< TRUE if the context has been initialized */
	unsigned use_glib_io:1;		/**< TRUE if falling back GLib IO Channels */
	unsigned dispatching:1;		/**< TRUE if dispatching events */
	struct inputevt_array ev_arr;
#ifdef USE_WIN_SELECT
	fd_set rfds, orfds;
	fd_set wfds, owfds;
	fd_set xfds, oxfds;
	int	fd_array[FD_SETSIZE];
#endif	/* USE_WIN_SELECT */
};

static inline struct poll_ctx *
get_global_poll_ctx(void)
{
	static struct poll_ctx poll_ctx;
	return &poll_ctx;
}

#ifdef USE_WIN_SELECT
static inline void
fd_set_register(fd_set *fds, unsigned idx)
{
	g_assert(fds);
	g_assert(idx < FD_SETSIZE);
#ifdef MINGW32
	g_assert(fds->fd_count <= FD_SETSIZE);
	g_assert(-1 == cast_to_fd(fds->fd_array[idx]));

	if (fds->fd_count <= idx) {
		fds->fd_count = idx + 1;
	}
#endif	/* MINGW32 */
}

static inline void
fd_set_clear(fd_set *fds, unsigned idx, int fd)
#ifdef MINGW32
{
	(void) fd;
	g_assert(idx < FD_SETSIZE);
	g_assert(fds->fd_count <= FD_SETSIZE);

	fds->fd_array[idx] = -1;
	if (fds->fd_count == idx)
		fds->fd_count--;
}
#else
{
	g_assert(idx < FD_SETSIZE);
	FD_CLR(fd, fds);
}
#endif	/* MINGW32 */

static inline void
fd_set_zero(fd_set *fds)
#ifdef MINGW32
{
	unsigned i;

	fds->fd_count = 0;
	for (i = 0; i < G_N_ELEMENTS(fds->fd_array); i++) {
		fds->fd_array[i] = -1;
	}
}
#else
{
	FD_ZERO(fds);
}
#endif	/* MINGW32 */

static inline void
fd_set_modify(fd_set *fds, unsigned idx, int fd, int value)
#ifdef MINGW32
{
	(void) fd;
	fds->fd_array[idx] = value;
}
#else
{
	(void) idx;
	if (value < 0)
		FD_CLR(fd, fds);
	else
		FD_SET(fd, fds);
}
#endif	/* MINGW32 */

#endif	/* USE_WIN_SELECT */

static inline unsigned
inputevt_poll_idx_new(struct poll_ctx *ctx, int fd)
{
	unsigned idx;

	g_assert(is_valid_fd(fd));

	if (ctx->num_poll_idx > 0)
		idx = bit_array_first_clear(ctx->used_poll_idx, 0,
			ctx->num_poll_idx - 1);
	else
		idx = (unsigned) -1;

	if ((unsigned) -1 == idx) {
		unsigned n = ctx->num_poll_idx;

		ctx->num_poll_idx = 0 != n ? n << 1 : 32;
		bit_array_resize(&ctx->used_poll_idx, n, ctx->num_poll_idx);
		idx = n;
	}
	g_assert((unsigned) -1 != idx);
	g_assert(idx < ctx->num_poll_idx);
	bit_array_set(ctx->used_poll_idx, idx);

	g_assert(idx < ctx->num_ev);

#if defined(USE_POLL)
	{
		struct pollfd *pfd = &ctx->ev_arr.ev[idx];

		g_assert(-1 == cast_to_fd(pfd->fd));
		pfd->fd = fd;
		pfd->revents = 0;
		pfd->events = 0;
	}
#endif	/* USE_POLL */

#if defined(USE_WIN_SELECT)
	{
		g_assert(-1 == ctx->fd_array[idx]);
		ctx->fd_array[idx] = fd;

		fd_set_register(&ctx->rfds, idx);
		fd_set_register(&ctx->wfds, idx);
		fd_set_register(&ctx->xfds, idx);
	}
#endif	/* USE_WIN_SELECT */

	return idx;
}

static inline void
inputevt_poll_idx_free(struct poll_ctx *ctx, unsigned idx)
{
	g_assert((unsigned) -1 != idx);
	g_assert(idx < ctx->num_poll_idx);
	g_assert(0 != bit_array_get(ctx->used_poll_idx, idx));
	bit_array_clear(ctx->used_poll_idx, idx);

	g_assert(idx < ctx->num_ev);

#ifdef USE_POLL
	{
		struct pollfd *pfd = &ctx->ev_arr.ev[idx];

		g_assert(is_valid_fd(pfd->fd));
		pfd->fd = -1;
		pfd->revents = 0;
		pfd->events = 0;
	}
#endif	/* USE_POLL */

#ifdef USE_WIN_SELECT
	{
		int fd;

		g_assert(idx < G_N_ELEMENTS(ctx->fd_array));
		fd = ctx->fd_array[idx];

		g_assert(is_valid_fd(fd));
		ctx->fd_array[idx] = -1;

		fd_set_clear(&ctx->rfds, idx, fd);
		fd_set_clear(&ctx->wfds, idx, fd);
		fd_set_clear(&ctx->xfds, idx, fd);
	}
#endif	/* USE_WIN_SELECT */
}

#endif /* !USE_GLIB_IO_CHANNELS */

#ifndef USE_KQUEUE
size_t
inputevt_data_available(void)
{
	return 0;
}
#endif	/* !USE_KQUEUE */


#ifdef USE_KQUEUE

static guint data_available;	/** Used by inputevt_data_available(). */

static inline int
get_poll_event_fd(const struct poll_ctx *ctx, unsigned idx)
{
	const struct kevent *ev = &ctx->ev_arr.ev[idx];
	return pointer_to_uint(KEVENT_UDATA_TO_PTR(ev->udata));
}

static inline inputevt_cond_t 
get_poll_event_cond(const struct poll_ctx *ctx, unsigned idx)
{
	const struct kevent *ev = &ctx->ev_arr.ev[idx];
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
poll_event_set_data_avail(const struct poll_ctx *ctx, unsigned idx)
{
	const struct kevent *ev = &ctx->ev_arr.ev[idx];
	data_available = EVFILT_READ == ev->filter ? MIN(INT_MAX, ev->data) : 0;
}

static gboolean
create_poll_fd(int *fd_ptr)
{
	int fd = kqueue();
	*fd_ptr = fd;
	return is_valid_fd(fd);
}

static inline const char *
polling_method(void)
{
	return "kqueue()";
}

static int
update_poll_event(struct poll_ctx *poll_ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct timespec zero_ts;
	struct kevent kev[2];
	size_t i;
	gpointer udata;
	int ret;

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
	g_assert(poll_ctx->initialized);

	return kevent(poll_ctx->fd, NULL, 0,
			poll_ctx->ev_arr.ev, poll_ctx->num_ev, &zero_ts);
}

#endif /* USE_KQUEUE */

#ifdef USE_EPOLL

static inline int
get_poll_event_fd(const struct poll_ctx *ctx, unsigned idx)
{
	const struct epoll_event *ev = &ctx->ev_arr.ev[idx];
	return GPOINTER_TO_INT(ev->data.ptr);
}

static inline inputevt_cond_t 
get_poll_event_cond(const struct poll_ctx *ctx, unsigned idx)
{
	const struct epoll_event *ev = &ctx->ev_arr.ev[idx];
	return ((EPOLLIN | EPOLLPRI | EPOLLHUP) & ev->events ? INPUT_EVENT_R : 0)
		| (EPOLLOUT & ev->events ? INPUT_EVENT_W : 0)
		| (EPOLLERR & ev->events ? INPUT_EVENT_EXCEPTION : 0);
}

static gboolean
create_poll_fd(int *fd_ptr)
{
	int fd = epoll_create(1024 /* Just an arbitrary value as hint */);
	*fd_ptr = fd;
	return is_valid_fd(fd);
}

static inline const char *
polling_method(void)
{
	return "epoll()";
}

static int
update_poll_event(struct poll_ctx *poll_ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct epoll_event zero_ev;
	struct epoll_event ev;
	int op;

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
	g_assert(poll_ctx->initialized);
	
	return epoll_wait(poll_ctx->fd, poll_ctx->ev_arr.ev, poll_ctx->num_ev, 0);
}

#endif	/* USE_EPOLL */

#ifdef USE_DEV_POLL
static gboolean
create_poll_fd(int *fd_ptr)
{
	int fd = get_non_stdio_fd(open("/dev/poll", O_RDWR));
	*fd_ptr = fd;
	return is_valid_fd(fd);
}

static inline const char *
polling_method(void)
{
	return "/dev/poll";
}

static int
update_poll_event(struct poll_ctx *poll_ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;
	if (cur != old) {
		static const struct pollfd zero_pfd;
		struct pollfd pfd[2];
		size_t i = 0;

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
			g_assert((size_t) ret == size || (ssize_t)-1 == ret);
		}
	}
	return 0;
}

static int
collect_events(struct poll_ctx *poll_ctx, int timeout_ms)
{
	struct dvpoll dvp; 
	int ret;

	dvp.dp_timeout = timeout_ms;
	dvp.dp_nfds = poll_ctx->num_ev;
	dvp.dp_fds = poll_ctx->ev_arr.ev;

	ret = ioctl(poll_ctx->fd, DP_POLL, &dvp);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("check_dev_poll(): ioctl() failed: %s", g_strerror(errno));
	}
	return ret;
}
#endif	/* USE_DEV_POLL */

#if defined(USE_POLL) || defined(USE_WIN_SELECT)
static gboolean
create_poll_fd(int *fd_ptr)
{
	*fd_ptr = -1;	/* There is no special file descriptor */
	return TRUE;	
}
#endif	/* USE_POLL || USE_WIN_SELECT */


#ifndef USE_KQUEUE
static inline void
poll_event_set_data_avail(const struct poll_ctx *unused_ctx,
	unsigned unused_idx)
{
	/* Not directly supported and probably not worth a ioctl() */
	(void) unused_ctx;
	(void) unused_idx;
}
#endif	/* !USE_KQUEUE */

#ifdef USE_WIN_SELECT
static int
update_poll_event_with_select(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	relay_list_t *rl;

	g_assert(is_valid_fd(fd));

	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;

	rl = g_hash_table_lookup(ctx->ht, GINT_TO_POINTER(fd));
	g_assert(NULL != rl);
	g_assert(NULL != rl->sl);

	g_assert(rl->poll_idx < ctx->num_poll_idx);

	if (old != cur) {
		fd_set_modify(&ctx->rfds, rl->poll_idx, fd, (INPUT_EVENT_R & cur) ? fd : -1);
		fd_set_modify(&ctx->wfds, rl->poll_idx, fd, (INPUT_EVENT_W & cur) ? fd : -1);
		fd_set_modify(&ctx->xfds, rl->poll_idx, fd, fd);
	}
	return 0;
}
#endif /* USE_WIN_SELECT */

#if defined(USE_POLL) || defined(USE_WIN_SELECT)

static inline const char *
polling_method(void)
{
#ifdef USE_WIN_SELECT
	if (!mingw_has_wsapoll())
		return "select()";
#endif	/* USE_WIN_SELECT */

	return "poll()";
}

static int
update_poll_event(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	struct pollfd *pfd;
	relay_list_t *rl;

#ifdef USE_WIN_SELECT
	if (!mingw_has_wsapoll())
		return update_poll_event_with_select(ctx, fd, old, cur);
#endif	/* USE_WIN_SELECT */

	g_assert(is_valid_fd(fd));

	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;

	rl = g_hash_table_lookup(ctx->ht, GINT_TO_POINTER(fd));
	g_assert(NULL != rl);
	g_assert(NULL != rl->sl);

	g_assert(rl->poll_idx < ctx->num_poll_idx);
	pfd = &ctx->ev_arr.ev[rl->poll_idx];
	g_assert(cast_to_fd(pfd->fd) == fd);

	if (old != cur) {
		pfd->revents = 0;
		if (cur) {
			pfd->events = 0
				| (INPUT_EVENT_R & cur ? (POLLIN | POLLPRI) : 0)
				| (INPUT_EVENT_W & cur ? POLLOUT : 0);
		} else {
			pfd->events = 0;
		}
	}
	return 0;
}

#ifdef USE_WIN_SELECT
static int
collect_events_with_select(struct poll_ctx *ctx, int timeout_ms)
{
	struct timeval tv;
	int ret;
	fd_set rfds, wfds, xfds;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000UL;

	memcpy(&rfds, &ctx->rfds, sizeof rfds);
	memcpy(&wfds, &ctx->wfds, sizeof wfds);
	memcpy(&xfds, &ctx->xfds, sizeof xfds);

	ret = select(INT_MAX, /* FIXME: INT_MAX is just a hack */
			(void *) &rfds,
			(void *) &wfds,
			(void *) &xfds,
			timeout_ms < 0 ? NULL : &tv);
	if (ret > 0) {
		memcpy(&ctx->orfds, &rfds, sizeof rfds);
		memcpy(&ctx->owfds, &wfds, sizeof wfds);
		memcpy(&ctx->oxfds, &xfds, sizeof xfds);
	}
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("collect_events(): select() failed: %s", g_strerror(errno));
	}
	return ret;
}
#endif	/* USE_WIN_SELECT */

static int
collect_events(struct poll_ctx *ctx, int timeout_ms)
{
	int ret;

#ifdef USE_WIN_SELECT
	if (!mingw_has_wsapoll())
		return collect_events_with_select(ctx, timeout_ms);
#endif	/* USE_WIN_SELECT */

	ret = compat_poll(ctx->ev_arr.ev, ctx->num_ev, timeout_ms);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("collect_events(): poll() failed: %s", g_strerror(errno));
	}
	return ret;
}
#endif	/* USE_POLL */

#if defined(USE_POLL) || defined(USE_DEV_POLL) || defined(USE_WIN_SELECT)
static int
check_poll_events(struct poll_ctx *poll_ctx)
{
	int ret;

	ret = poll_ctx->num_ready;
	poll_ctx->num_ready = 0;
	return ret;
}
#endif	/* USE_POLL || USE_DEV_POLL || USE_WIN_SELECT */

#ifdef USE_WIN_SELECT
static inline int
get_poll_event_fd_with_select(const struct poll_ctx *ctx, unsigned idx)
{
	int fd;

	g_assert(idx < G_N_ELEMENTS(ctx->fd_array));
	fd = ctx->fd_array[idx];

	return fd;
}

static inline inputevt_cond_t 
get_poll_event_cond_with_select(const struct poll_ctx *ctx, unsigned idx)
#ifdef MINGW32
{
	int r, w, x;

	r = ctx->orfds.fd_array[idx];
	w = ctx->owfds.fd_array[idx];
	x = ctx->oxfds.fd_array[idx];

	return (is_valid_fd(r) ? INPUT_EVENT_R : 0)
		| (is_valid_fd(w) ? INPUT_EVENT_W : 0)
		| (is_valid_fd(x) ? INPUT_EVENT_EXCEPTION : 0);
}
#else
{
	int fd;

	g_assert(idx < G_N_ELEMENTS(ctx->fd_array));
	fd = ctx->fd_array[idx];
	g_assert(is_valid_fd(fd));

	return (FD_ISSET(fd, &ctx->orfds) ? INPUT_EVENT_R : 0)
		| (FD_ISSET(fd, &ctx->owfds) ? INPUT_EVENT_W : 0)
		| (FD_ISSET(fd, &ctx->oxfds) ? INPUT_EVENT_EXCEPTION : 0);
}
#endif	/* MINGW32*/

#endif	/* USE_WIN_SELECT */

#if defined(USE_POLL) || defined(USE_DEV_POLL)
static inline int
get_poll_event_fd(const struct poll_ctx *ctx, unsigned idx)
{
	const struct pollfd *pfd;

#ifdef USE_WIN_SELECT
	if (!mingw_has_wsapoll())
		return get_poll_event_fd_with_select(ctx, idx);
#endif	/* USE_WIN_SELECT */

	pfd = &ctx->ev_arr.ev[idx];
	return pfd->fd;
}

static inline inputevt_cond_t 
get_poll_event_cond(const struct poll_ctx *ctx, unsigned idx)
{
	const struct pollfd *pfd;

#ifdef USE_WIN_SELECT
	if (!mingw_has_wsapoll())
		return get_poll_event_cond_with_select(ctx, idx);
#endif	/* USE_WIN_SELECT */

	pfd = &ctx->ev_arr.ev[idx];
	return ((POLLIN | POLLHUP) & pfd->revents ? INPUT_EVENT_R : 0)
		| (POLLOUT & pfd->revents ? INPUT_EVENT_W : 0)
		| ((POLLERR | POLLNVAL) & pfd->revents ? INPUT_EVENT_EXCEPTION : 0);
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
#endif	/* USE_POLL || USE_DEV_POLL */

#if defined(USE_POLL) || defined(USE_DEV_POLL) || defined(USE_WIN_SELECT)
static gint (*default_poll_func)(GPollFD *, guint, gint);

static gboolean
dispatch_poll(GIOChannel *unused_source,
	GIOCondition unused_cond, gpointer udata);

static void
check_for_events(struct poll_ctx *poll_ctx, int *timeout_ms_ptr)
{
	tm_t before, after;
	time_delta_t d;
	int ret, timeout_ms;

	g_assert(poll_ctx);
	g_assert(timeout_ms_ptr);
	g_assert(0 == poll_ctx->num_ready);

	if (poll_ctx->num_ev <= 0) {
		poll_ctx->num_ready = 0;
		return;
	}

	timeout_ms = *timeout_ms_ptr;
	timeout_ms = MAX(0, timeout_ms);

	tm_now_exact(&before);
	ret = collect_events(poll_ctx, timeout_ms);
	tm_now_exact(&after);
	d = tm_elapsed_ms(&after, &before);
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

static int
poll_func(GPollFD *gfds, guint n, int timeout_ms)
{
	struct poll_ctx *poll_ctx;
	int r;

	poll_ctx = get_global_poll_ctx();
	g_assert(poll_ctx);
	g_assert(poll_ctx->initialized);

	if (0 == poll_ctx->num_ready) {
		check_for_events(poll_ctx, &timeout_ms);
	}

	if (poll_ctx->num_ready > 0) {
		dispatch_poll(NULL, 0, poll_ctx);
	}

	r = default_poll_func(gfds, n, timeout_ms);

#ifdef INPUTEVT_DEBUGGING
	if (-1 == r) {
		g_warning("INPUTEVT default poll function failed: %s",
			g_strerror(errno));
	}
#endif

	return r;
}
#endif	/* USE_DEV_POLL || USE_POLL || USE_WIN_SELECT */

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

#if !defined(USE_GLIB_IO_CHANNELS)

/**
 * Purge removed sources.
 */
static void
inputevt_purge_removed(struct poll_ctx *poll_ctx)
{
	GSList *sl;

	for (sl = poll_ctx->removed; NULL != sl; sl = g_slist_next(sl)) {
		inputevt_relay_t *relay;
		relay_list_t *rl;
		guint id;
		int fd;

		id = GPOINTER_TO_UINT(sl->data);
		g_assert(id > 0);
		g_assert(id < poll_ctx->num_ev);

		g_assert(0 != bit_array_get(poll_ctx->used_event_id, id));
		bit_array_clear(poll_ctx->used_event_id, id);

		relay = poll_ctx->relay[id];
		g_assert(relay);
		g_assert(zero_handler == relay->handler);

		fd = relay->fd;
		g_assert(is_valid_fd(fd));
		wfree(relay, sizeof *relay);
		poll_ctx->relay[id] = NULL;
		
		rl = g_hash_table_lookup(poll_ctx->ht, GINT_TO_POINTER(fd));
		g_assert(NULL != rl);
		g_assert(NULL != rl->sl);
	
		rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
		if (NULL == rl->sl) {
			g_assert(0 == rl->readers && 0 == rl->writers);
			inputevt_poll_idx_free(poll_ctx, rl->poll_idx);
			rl->poll_idx = -1;
			wfree(rl, sizeof *rl);
			g_hash_table_remove(poll_ctx->ht, GINT_TO_POINTER(fd));
		}
	}

	gm_slist_free_null(&poll_ctx->removed);
}

static void
inputevt_timer(struct poll_ctx *poll_ctx)
{
	int n, i;

	g_assert(poll_ctx);
	g_assert(poll_ctx->initialized);
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
	g_assert(UNSIGNED(n) <= poll_ctx->num_ev);
	
	poll_ctx->dispatching = TRUE;

	/**
	 * FIXME:	select() returns the total number of events
	 *			which could be 3 * ctx->num_ev.
	 */
	for (i = 0; n > 0 && UNSIGNED(i) < poll_ctx->num_ev; i++) {
		inputevt_cond_t cond;
		relay_list_t *rl;
		GSList *sl;
		int fd;

		fd = get_poll_event_fd(poll_ctx, i);
		g_assert(fd >= -1);
		if (!is_valid_fd(fd))
			continue;

		cond = get_poll_event_cond(poll_ctx, i);
		if (0 == cond)
			continue;

		n--;
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
				poll_event_set_data_avail(poll_ctx, i);
				relay->handler(relay->data, fd, cond);
			}
		}
	}
	
	if (poll_ctx->removed) {
		inputevt_purge_removed(poll_ctx);
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

	if (poll_ctx->use_glib_io) {
		g_source_remove(id);
	} else {
		inputevt_relay_t *relay;
		relay_list_t *rl;
		inputevt_cond_t old, cur;
		int fd;

		g_assert(poll_ctx->ht);
		g_assert(id < poll_ctx->num_ev);
		g_assert(0 != bit_array_get(poll_ctx->used_event_id, id));

		relay = poll_ctx->relay[id];
		g_assert(NULL != relay);
		g_assert(zero_handler != relay->handler);
		g_assert(is_valid_fd(relay->fd));

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
			 * Don't clear the "used_event_id" bit yet because this slot must
			 * not be recycled whilst dispatching events.
			 */
			poll_ctx->removed = g_slist_prepend(poll_ctx->removed,
									GUINT_TO_POINTER(id));
		} else {
			wfree(relay, sizeof *relay);
			
			rl->sl = g_slist_remove(rl->sl, GUINT_TO_POINTER(id));
			if (NULL == rl->sl) {
				g_assert(0 == rl->readers && 0 == rl->writers);
				inputevt_poll_idx_free(poll_ctx, rl->poll_idx);
				rl->poll_idx = -1;
				wfree(rl, sizeof *rl);
				g_hash_table_remove(poll_ctx->ht, GINT_TO_POINTER(fd));
			}

			bit_array_clear(poll_ctx->used_event_id, id);
		}
	}
}

static inline guint
inputevt_get_free_id(const struct poll_ctx *poll_ctx)
{
	if (0 == poll_ctx->num_ev)
		return (guint) -1;
	
	return bit_array_first_clear(poll_ctx->used_event_id,
				0, poll_ctx->num_ev - 1);
}

static guint 
inputevt_add_source(inputevt_relay_t *relay)
{
	struct poll_ctx *poll_ctx;
	inputevt_cond_t old;
	guint f, id;

	poll_ctx = get_global_poll_ctx();
	g_assert(poll_ctx->initialized);
	g_assert(is_valid_fd(relay->fd));
	
	/*
	 * Linux systems with 2.4 kernels usually have all epoll stuff
	 * in their headers but the system calls just return ENOSYS.
	 */
	if (poll_ctx->use_glib_io)
		return inputevt_add_source_with_glib(relay);

	g_assert(poll_ctx->ht);

	f = inputevt_get_free_id(poll_ctx);
	g_assert((guint) -1 == f || f < poll_ctx->num_ev);

	if ((guint) -1 != f) {
		id = f;
	} else {
		guint i, n = poll_ctx->num_ev;

		/*
		 * If there was no free ID, the arrays are resized to the
		 * double size.
		 */

		poll_ctx->num_ev = 0 != n ? n << 1 : 32;

		{
			size_t size = poll_ctx->num_ev * sizeof poll_ctx->ev_arr.ev[0];
			poll_ctx->ev_arr.ev = g_realloc(poll_ctx->ev_arr.ev, size);
		}

#ifdef USE_POLL
		for (i = n; i < poll_ctx->num_ev; i++) {
			struct pollfd *pfd = &poll_ctx->ev_arr.ev[i];
			pfd->fd = -1;
			pfd->events = 0;
			pfd->revents = 0;
		}
#endif /* USE_POLL */

		bit_array_resize(&poll_ctx->used_event_id, n, poll_ctx->num_ev);

		if (0 == n) {
			/* ID 0 is reserved for compatibility with GLib's IDs */
			bit_array_set(poll_ctx->used_event_id, 0);
			id = 1;
		} else {
			id = n;
		}

		{
			size_t size = poll_ctx->num_ev * sizeof poll_ctx->relay[0];
			poll_ctx->relay = g_realloc(poll_ctx->relay, size);
			for (i = n; i < poll_ctx->num_ev; i++)
				poll_ctx->relay[i] = NULL;
		}
	}

	g_assert(id < poll_ctx->num_ev);
	bit_array_set(poll_ctx->used_event_id, id);
	g_assert(0 != bit_array_get(poll_ctx->used_event_id, id));

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
			rl->poll_idx = inputevt_poll_idx_new(poll_ctx, relay->fd);
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

	g_assert(0 != id);	
	return id;
}

/**
 * Performs module initialization.
 */
void
inputevt_init(void)
{
	struct poll_ctx *ctx;

#ifdef INPUTEVT_DEBUGGING
	g_info("INPUTEVT using customized I/O dispatching with %s",
		polling_method());
#endif

	ctx = get_global_poll_ctx();
	g_assert(!ctx->initialized);
	
	ctx->initialized = TRUE;

	if (create_poll_fd(&ctx->fd)) {
		set_close_on_exec(ctx->fd);	/* Just in case */

		ctx->ht = g_hash_table_new(NULL, NULL);

#if defined(USE_WIN_SELECT)
		{
			size_t i;

			for (i = 0; i < G_N_ELEMENTS(ctx->fd_array); i++)
				ctx->fd_array[i] = -1;
		}
		fd_set_zero(&ctx->rfds);
		fd_set_zero(&ctx->wfds);
		fd_set_zero(&ctx->xfds);
#endif	/* USE_WIN_SELECT */

#if defined(USE_DEV_POLL) || defined(USE_POLL) || defined(USE_WIN_SELECT)
		default_poll_func = g_main_context_get_poll_func(NULL);
		g_main_context_set_poll_func(NULL, poll_func);
#else
		{
			GIOChannel *ch;

			ch = g_io_channel_unix_new(ctx->fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
			g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */

			(void) g_io_add_watch(ch, READ_CONDITION, dispatch_poll, ctx);
		}
#endif	/* USE_DEV_POLL */
	} else {
		ctx->use_glib_io = TRUE;
		g_warning("create_poll_fd() failed: %s", g_strerror(errno));
		/* This is no hard error, we fall back to the GLib source watcher */
	}
}
#endif /* !USE_GLIB_IO_CHANNELS */

#ifdef USE_GLIB_IO_CHANNELS
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
#ifdef USE_POLL
	g_main_context_set_poll_func(NULL, compat_poll);
#endif	/* USE_POLL */

#ifdef INPUTEVT_DEBUGGING
	{
		const char *method;
#ifdef USE_POLL
		method = polling_method();
#else
		method = "glib's polling";
#endif	/* USE_POLL */
		g_info("INPUTEVT using glib's I/O channels with %s", method);
	}
#endif	/* INPUTEVT_DEBUGGING */
}
#endif /* USE_GLIB_IO_CHANNELS */

/**
 * Adds an event source to the main GLIB monitor queue.
 *
 * A replacement for gdk_input_add().
 * Behaves exactly the same, except destroy notification has
 * been removed (since gtkg does not use it).
 */
guint
inputevt_add(int fd, inputevt_cond_t cond,
	inputevt_handler_t handler, gpointer data)
{
	inputevt_relay_t *relay = walloc(sizeof *relay);
	gboolean ok = FALSE;

	g_assert(is_valid_fd(fd));
	g_assert(zero_handler != handler);

	safety_assert(is_a_socket(fd) || is_a_fifo(fd));

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
#if !defined(USE_GLIB_IO_CHANNELS)
	struct poll_ctx *poll_ctx;
	
	poll_ctx = get_global_poll_ctx();
	inputevt_purge_removed(poll_ctx);
	gm_hash_table_destroy_null(&poll_ctx->ht);
	G_FREE_NULL(poll_ctx->used_poll_idx);
	G_FREE_NULL(poll_ctx->used_event_id);
	G_FREE_NULL(poll_ctx->relay);
	G_FREE_NULL(poll_ctx->ev_arr.ev);
	close(poll_ctx->fd);
	poll_ctx->initialized = FALSE;
#endif
}

/* vi: set ts=4 sw=4 cindent: */
