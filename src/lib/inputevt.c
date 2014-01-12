/*
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

/**
 * Debugging options.
 */
#if 0
#define INPUTEVT_SAFETY_ASSERT	/* Enable safety_assert() */
#endif
#if 1
#define INPUTEVT_DEBUGGING		/* Additional debugging traces */
#include "str.h"
#endif

#ifdef INPUTEVT_SAFETY_ASSERT
#define safety_assert(x)	g_assert(x)
#else
#define safety_assert(x)
#endif

/* Enable and tweak, for testing only */
#if 0 /* XXX */
#undef HAS_POLL
#undef HAS_SELECT
#undef HAS_EPOLL
#undef HAS_KQUEUE
#undef HAS_DEV_POLL

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

#ifdef HAS_KQUEUE
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
#endif /* HAS_KQUEUE */

#ifdef HAS_EPOLL
#include <sys/epoll.h>
#endif /* HAS_EPOLL */

#ifdef HAS_DEV_POLL
#include <stropts.h>	/* ioctl() */
#include <sys/devpoll.h>
#endif /* HAS_DEV_POLL */

#include "bit_array.h"
#include "compat_poll.h"
#include "fd.h"
#include "glib-missing.h"	/* For g_main_context_get_poll_func() with GTK1 */
#include "hashlist.h"
#include "htable.h"
#include "inputevt.h"
#include "log.h"			/* For s_error() */
#include "misc.h"
#include "mutex.h"
#include "plist.h"
#include "pslist.h"
#include "stringify.h"
#include "tm.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

static unsigned inputevt_debug;
static unsigned inputevt_stid = THREAD_INVALID_ID;

/**
 * Set debugging level.
 */
void 
inputevt_set_debug(unsigned level)
{
	inputevt_debug = level;
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

const char *
inputevt_cond_to_string(inputevt_cond_t cond)
{
	switch (cond) {
#define CASE(x) case x: return #x
	CASE(INPUT_EVENT_NONE);
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
	void *data;
	inputevt_cond_t condition;
	int fd;
} inputevt_relay_t;

typedef struct relay_list {
	pslist_t *sl;
	size_t readers;
	size_t writers;
	unsigned poll_idx;
} relay_list_t;

struct event {
	int fd;
	inputevt_cond_t condition;
	unsigned data_available;
};

static const inputevt_handler_t zero_handler;
static int (*default_poll_func)(GPollFD *, unsigned, int);

struct poll_ctx {
	mutex_t lock;				/**< Thread-safe lock */
	inputevt_relay_t **relay;	/**< The relay contexts */
	bit_array_t *used_event_id;	/**< A bit array, which ID slots are used */
	bit_array_t *used_poll_idx;	/**< -"-, which Poll IDX slots are used */
	pslist_t *removed;			/**< List of removed IDs */
	htable_t *ht;				/**< Records file descriptors */
	hash_list_t *readable;		/**< Records readable file descriptors */
	int master_fd;				/**< The ``master'' fd for epoll or kqueue */
	unsigned num_ev;			/**< Length of the "ev" and "relay" arrays */
	unsigned num_poll_idx;		/**< Length of used_poll_idx array */
	unsigned max_poll_idx;
	unsigned num_ready;			/**< Used for /dev/poll only */
	unsigned initialized:1;		/**< TRUE if the context has been initialized */
	unsigned dispatching:1;		/**< TRUE if dispatching events */

#ifdef HAS_KQUEUE
	struct kevent *kev_arr;
#endif	/* HAS_KQUEUE*/

#ifdef HAS_EPOLL
	struct epoll_event *ep_arr;
#endif	/* HAS_EPOLL */

	struct pollfd *pfd_arr;

	/**
	 * The following members must be provided by the I/O event handler
	 * and constitute the common interface.
	 */
	const char *polling_method;
	int (*collect_events)(struct poll_ctx *, int); /* non-pollable master fd */
	int (*event_check_all)(struct poll_ctx *);
	struct event (*event_get)(const struct poll_ctx *, unsigned);
	int (*event_set_mask)(struct poll_ctx *, int,
			inputevt_cond_t, inputevt_cond_t);
};

/*
 * The lock used by the context must be recursive since inputevt_remove()
 * can be called in the middle of inputevt_timer().
 */

#define CTX_LOCK(c)			mutex_lock(&c->lock)
#define CTX_UNLOCK(c)		mutex_unlock(&c->lock)
#define CTX_IS_LOCKED(c)	mutex_is_owned(&c->lock)

static unsigned data_available;
/**
 * @return A positive value indicates how much data is available for reading.
 *		   If zero is returned the amount of available data is unknown.
 */
size_t
inputevt_data_available(void)
{
	return data_available;
}

static inline struct poll_ctx *
get_global_poll_ctx(void)
{
	static struct poll_ctx ctx;
	return &ctx;
}

static inline unsigned
inputevt_poll_idx_new(struct poll_ctx *ctx, int fd)
{
	unsigned idx;

	g_assert(CTX_IS_LOCKED(ctx));
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
	if (idx == ctx->max_poll_idx)
		ctx->max_poll_idx = idx + 1;

	{
		struct pollfd *pfd = &ctx->pfd_arr[idx];

		g_assert(-1 == cast_to_fd(pfd->fd));
		pfd->fd = fd;
		pfd->revents = 0;
		pfd->events = 0;
	}

	g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
	return idx;
}

static inline void
inputevt_poll_idx_free(struct poll_ctx *ctx, unsigned *idx_ptr)
{
	const unsigned idx = *idx_ptr;

	g_assert(CTX_IS_LOCKED(ctx));
	g_assert(!ctx->dispatching);
	g_assert((unsigned) -1 != idx);
	g_assert(idx < ctx->num_poll_idx);
	g_assert(0 != bit_array_get(ctx->used_poll_idx, idx));

	g_assert(idx < ctx->num_ev);

	{
		struct pollfd *pfd = &ctx->pfd_arr[idx];
		const unsigned last_idx = ctx->max_poll_idx - 1;

		g_assert(idx < ctx->max_poll_idx);
		g_assert(last_idx < ctx->max_poll_idx);

		if (idx == last_idx) {
			pfd = &ctx->pfd_arr[idx];
		} else {
			relay_list_t *rl;

			pfd = &ctx->pfd_arr[last_idx];
			safety_assert(is_valid_fd(pfd->fd));

			rl = htable_lookup(ctx->ht, int_to_pointer(pfd->fd));
			safety_assert(NULL != rl);
			safety_assert(last_idx == rl->poll_idx);

			rl->poll_idx = idx;
			ctx->pfd_arr[idx] = *pfd;
		}
		bit_array_clear(ctx->used_poll_idx, last_idx);
		ctx->max_poll_idx--;

		g_assert(is_valid_fd(pfd->fd));
		pfd->fd = -1;
		pfd->revents = 0;
		pfd->events = 0;
	}

	g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
	*idx_ptr = -1;
}

#ifdef HAS_KQUEUE
static struct event
event_get_with_kqueue(const struct poll_ctx *ctx, unsigned idx)
{
	const struct kevent *ev = &ctx->kev_arr[idx];
	struct event event;

	g_assert(CTX_IS_LOCKED(ctx));

	event.fd = pointer_to_uint(KEVENT_UDATA_TO_PTR(ev->udata));
	event.condition = EV_ERROR & ev->flags ? INPUT_EVENT_EXCEPTION : 0;
	switch (ev->filter) {
	case EVFILT_READ:
		event.condition |= INPUT_EVENT_R;
		event.data_available = MIN(INT_MAX, ev->data);
		break;
	case EVFILT_WRITE:
		event.condition |= INPUT_EVENT_W;
		event.data_available = 0;
		break;
	default:
		g_assert_not_reached();
	}
	return event;
}

static int
event_set_mask_with_kqueue(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct timespec zero_ts;
	struct kevent kev[2];
	size_t i;
	void *udata;
	int ret;

	g_assert(CTX_IS_LOCKED(ctx));

	if ((INPUT_EVENT_RW & old) == (INPUT_EVENT_RW & cur))
		return 0;

	i = 0;
	udata = int_to_pointer(fd);

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

	if (-1 == (ret = kevent(ctx->master_fd, kev, i, NULL, 0, &zero_ts)))
		s_error("kevent() failed: %m");

	return ret;
}

static int
event_check_all_with_kqueue(struct poll_ctx *ctx)
{
	static const struct timespec zero_ts;
	
	g_assert(ctx);
	g_assert(ctx->initialized);
	g_assert(CTX_IS_LOCKED(ctx));

	return kevent(ctx->master_fd, NULL, 0, ctx->kev_arr, ctx->num_ev, &zero_ts);
}

#endif /* HAS_KQUEUE */

#ifdef HAS_EPOLL
static struct event
event_get_with_epoll(const struct poll_ctx *ctx, unsigned idx)
{
	const struct epoll_event *ev = &ctx->ep_arr[idx];
	struct event event;

	g_assert(CTX_IS_LOCKED(ctx));

	event.fd = pointer_to_int(ev->data.ptr);
	event.condition =
		((EPOLLIN | EPOLLPRI | EPOLLHUP) & ev->events ? INPUT_EVENT_R : 0)
		| (EPOLLOUT & ev->events ? INPUT_EVENT_W : 0)
		| (EPOLLERR & ev->events ? INPUT_EVENT_EXCEPTION : 0);
	event.data_available = 0;
	return event;
}

static int
event_set_mask_with_epoll(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	static const struct epoll_event zero_ev;
	struct epoll_event ev;
	int op;

	g_assert(CTX_IS_LOCKED(ctx));

	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;
	if (cur == old)
		return 0;

	ev = zero_ev;
	ev.data.ptr = int_to_pointer(fd);

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

	return epoll_ctl(ctx->master_fd, op, fd, &ev);
}

static int
event_check_all_with_epoll(struct poll_ctx *ctx)
{
	g_assert(ctx);
	g_assert(ctx->initialized);
	g_assert(CTX_IS_LOCKED(ctx));
	
	return epoll_wait(ctx->master_fd, ctx->ep_arr, ctx->num_ev, 0);
}
#endif	/* HAS_EPOLL */

#ifdef HAS_DEV_POLL
static int
event_set_mask_with_dev_poll(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	g_assert(CTX_IS_LOCKED(ctx));

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
			ret = write(ctx->master_fd, &pfd, size);
			g_assert((size_t) ret == size || (ssize_t)-1 == ret);
		}
	}
	return 0;
}

static int
collect_events_with_devpoll(struct poll_ctx *ctx, int timeout_ms)
{
	struct dvpoll dvp; 
	int ret;

	g_assert(timeout_ms >= 0);		/* Never infinite (blocking) */
	g_assert(CTX_IS_LOCKED(ctx));

	dvp.dp_timeout = timeout_ms;
	dvp.dp_nfds = ctx->num_ev;
	dvp.dp_fds = ctx->pfd_arr;

	ret = ioctl(ctx->master_fd, DP_POLL, &dvp);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("%s(): ioctl(%d, DP_POLL) failed: %m",
			G_STRFUNC, ctx->master_fd);
	}
	return ret;
}
#endif	/* HAS_DEV_POLL */

static int
event_set_mask_with_poll(struct poll_ctx *ctx, int fd,
	inputevt_cond_t old, inputevt_cond_t cur)
{
	struct pollfd *pfd;
	relay_list_t *rl;

	g_assert(CTX_IS_LOCKED(ctx));
	g_assert(is_valid_fd(fd));

	old &= INPUT_EVENT_RW;
	cur &= INPUT_EVENT_RW;

	rl = htable_lookup(ctx->ht, int_to_pointer(fd));
	g_assert(NULL != rl);
	g_assert(NULL != rl->sl);

	g_assert(rl->poll_idx < ctx->num_poll_idx);
	pfd = &ctx->pfd_arr[rl->poll_idx];
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

#ifdef MINGW32
static unsigned
get_poll_idx(const struct poll_ctx *ctx, int fd)
{
	relay_list_t *rl;

	safety_assert(is_valid_fd(fd));
	safety_assert(is_open_fd(fd));
	g_assert(CTX_IS_LOCKED(ctx));

	rl = htable_lookup(ctx->ht, int_to_pointer(fd));
	g_assert(NULL != rl);
	return rl->poll_idx;
}

static int
collect_events_with_select(struct poll_ctx *ctx, int timeout_ms)
{
	struct timeval tv;
	fd_set r, w, x;
	unsigned i, num_fd = 0;
	int ret;

	g_assert(timeout_ms >= 0);		/* Never infinite (blocking) */
	g_assert(CTX_IS_LOCKED(ctx));

	/* FD_ZERO() */
	r.fd_count = 0;
	w.fd_count = 0;
	x.fd_count = 0;

	g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
	g_assert(ctx->max_poll_idx <= FD_SETSIZE);

	for (i = 0; i < ctx->max_poll_idx; i++) {
		struct pollfd *pfd = &ctx->pfd_arr[i];

		pfd->revents = 0;
		if (!is_valid_fd(pfd->fd))
			continue;

		safety_assert(is_open_fd(pfd->fd));
		num_fd++;

		/* FD_SET() */
		if (POLLIN & pfd->events) {
			safety_assert(r.fd_count < FD_SETSIZE);
			r.fd_array[r.fd_count++] = pfd->fd;
		}
		if (POLLOUT & pfd->events) {
			safety_assert(w.fd_count < FD_SETSIZE);
			w.fd_array[w.fd_count++] = pfd->fd;
		}
		safety_assert(x.fd_count < FD_SETSIZE);
		x.fd_array[x.fd_count++] = pfd->fd;
	}

	/* On Windows select() requires at least one valid fd */
	if (0 == num_fd)
		return 0;

	if (timeout_ms < 0) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000UL;
	}

	ret = select(FD_SETSIZE, (void *) &r, (void *) &w, (void *) &x,
			timeout_ms < 0 ? NULL : &tv);

	if (ret < 0) {
		if (!is_temporary_error(errno)) {
			g_warning("%s(): select() failed: %m", G_STRFUNC);
		}
		return -1;
	}

	if (ret > 0) {
		/* FD_ISSET() */
		for (i = UNSIGNED(r.fd_count); i-- > 0; /* NOTHING */) {
			int fd = cast_to_fd(r.fd_array[i]);
			ctx->pfd_arr[get_poll_idx(ctx, fd)].revents |= POLLIN; 
		}
		for (i = UNSIGNED(w.fd_count); i-- > 0; /* NOTHING */) {
			int fd = cast_to_fd(w.fd_array[i]);
			ctx->pfd_arr[get_poll_idx(ctx, fd)].revents |= POLLOUT;
		}
		for (i = UNSIGNED(x.fd_count); i-- > 0; /* NOTHING */) {
			int fd = cast_to_fd(x.fd_array[i]);
			ctx->pfd_arr[get_poll_idx(ctx, fd)].revents |= POLLERR;
		}
	}
	return ret;
}
#endif /* MINGW32 */

static int
collect_events_with_poll(struct poll_ctx *ctx, int timeout_ms)
{
	int ret;

	g_assert(timeout_ms >= 0);		/* Never infinite (blocking) */
	g_assert(CTX_IS_LOCKED(ctx));

	ret = compat_poll(ctx->pfd_arr, ctx->max_poll_idx, timeout_ms);
	if (-1 == ret && !is_temporary_error(errno)) {
		g_warning("%s(): poll() failed: %m", G_STRFUNC);
	}
	return ret;
}

static int
event_check_all_with_poll(struct poll_ctx *ctx)
{
	int ret;

	g_assert(CTX_IS_LOCKED(ctx));

	ret = ctx->num_ready;
	ctx->num_ready = 0;
	return ret;
}

static struct event
event_get_with_poll(const struct poll_ctx *ctx, unsigned idx)
{
	const struct pollfd *pfd = &ctx->pfd_arr[idx];
	struct event event;

	g_assert(CTX_IS_LOCKED(ctx));

	event.fd = pfd->fd;
	event.data_available = 0;
	event.condition = ((POLLIN | POLLHUP) & pfd->revents ? INPUT_EVENT_R : 0)
		| (POLLOUT & pfd->revents ? INPUT_EVENT_W : 0)
		| ((POLLERR | POLLNVAL) & pfd->revents ? INPUT_EVENT_EXCEPTION : 0);
	return event;
}

static void
check_for_events(struct poll_ctx *ctx, int *timeout_ms_ptr)
{
	tm_t before, after;
	time_delta_t d;
	int ret, timeout_ms;

	g_assert(ctx);
	g_assert(CTX_IS_LOCKED(ctx));
	g_assert(timeout_ms_ptr);
	g_assert(0 == ctx->num_ready);

	g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
	if (ctx->max_poll_idx <= 0) {
		ctx->num_ready = 0;
		return;
	}

	/*
	 * Make sure event checking is non-blocking: if the timeout is negative,
	 * then force 0 to ensure the application will not block if the kernel
	 * has no pending events to report.
	 */

	timeout_ms = *timeout_ms_ptr;
	timeout_ms = MAX(0, timeout_ms);

	tm_now_exact(&before);
	ret = (*ctx->collect_events)(ctx, timeout_ms);
	tm_now_exact(&after);
	d = tm_elapsed_ms(&after, &before);
	if (d >= timeout_ms || ret > 0) {
		timeout_ms = 0;
	} else {
		timeout_ms -= d;
	}
	ctx->num_ready = MAX(0, ret);

	/* If the original timeout was negative (=INFINITE) and no event
	 * has occured, the timeout isn't touched.
	 */
	if (*timeout_ms_ptr >= 0 || ret > 0) {
		*timeout_ms_ptr = timeout_ms;
	} 
}

void
inputevt_poll_idx_compact(struct poll_ctx *ctx)
{
	CTX_LOCK(ctx);

	if (inputevt_debug > 9) {
		str_t *str = str_new_from("pollfd[] = {");
		unsigned num_unused = 0;
		unsigned i;

		g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
		for (i = ctx->max_poll_idx; i-- > 0; /* NOTHING */) {
			num_unused += !bit_array_get(ctx->used_poll_idx, i);
		}
		g_assert(num_unused <= ctx->max_poll_idx);

		g_assert(ctx->max_poll_idx <= ctx->num_poll_idx);
		for (i = 0; i < ctx->max_poll_idx; i++) {
			int fd = cast_to_fd(ctx->pfd_arr[i].fd);

			g_assert(is_valid_fd(fd) == bit_array_get(ctx->used_poll_idx, i));
			str_catf(str, "%s%d", i > 0 ? "," : "", fd);
		}
		g_assert(num_unused <= ctx->max_poll_idx);

		str_putc(str, '}');
		s_debug("%s (used=%u, unused=%u)",
			str_2c(str), ctx->max_poll_idx - num_unused, num_unused);
		str_destroy_null(&str);

		/* Indices [max_poll_idx...num_poll_idx[ must not be used! */
		for (i = ctx->max_poll_idx; i < ctx->num_poll_idx; i++) {
			int fd = cast_to_fd(ctx->pfd_arr[i].fd);
			g_assert(!is_valid_fd(fd));
			g_assert(!bit_array_get(ctx->used_poll_idx, i));
		}
	}

	CTX_UNLOCK(ctx);
}

static void
relay_list_remove(struct poll_ctx *ctx, unsigned id)
{
	relay_list_t *rl;
	inputevt_relay_t *relay;

	g_assert(id > 0);
	g_assert(id < ctx->num_ev);
	g_assert(CTX_IS_LOCKED(ctx));

	relay = ctx->relay[id];
	g_assert(relay);
	g_assert(zero_handler == relay->handler);
	g_assert(is_valid_fd(relay->fd));

	rl = htable_lookup(ctx->ht, int_to_pointer(relay->fd));
	g_assert(NULL != rl);
	g_assert(NULL != rl->sl);
	
	rl->sl = pslist_remove(rl->sl, uint_to_pointer(id));
	if (NULL == rl->sl) {
		g_assert(0 == rl->readers && 0 == rl->writers);
		inputevt_poll_idx_free(ctx, &rl->poll_idx);
		hash_list_remove(ctx->readable, int_to_pointer(relay->fd));
		htable_remove(ctx->ht, int_to_pointer(relay->fd));
		WFREE(rl);
	}
}

/**
 * Purge removed sources.
 */
static void
inputevt_purge_removed(struct poll_ctx *ctx)
{
	pslist_t *sl;

	g_assert(CTX_IS_LOCKED(ctx));

	PSLIST_FOREACH(ctx->removed, sl) {
		inputevt_relay_t *relay;
		unsigned id;

		id = pointer_to_uint(sl->data);
		g_assert(id > 0);
		g_assert(id < ctx->num_ev);

		g_assert(0 != bit_array_get(ctx->used_event_id, id));
		bit_array_clear(ctx->used_event_id, id);

		relay = ctx->relay[id];
		relay_list_remove(ctx, id);		
		WFREE(relay);
		ctx->relay[id] = NULL;
	}

	pslist_free_null(&ctx->removed);
}

/**
 * Our main I/O event dispatching loop.
 */
static G_GNUC_HOT void
inputevt_timer(struct poll_ctx *ctx)
{
	int num_events;

	g_assert(ctx != NULL);

	CTX_LOCK(ctx);

	g_assert(ctx->initialized);
	g_assert(ctx->ht != NULL);

	/* Maybe this must safely fail for general use, thus no assertion */
	if (ctx->dispatching) {
		CTX_UNLOCK(ctx);
		s_critical("%s(): called recursively / concurrently", G_STRFUNC);
		return;
	}

	num_events = (*ctx->event_check_all)(ctx);
	if (-1 == num_events && !is_temporary_error(errno)) {
		g_warning("event_check_all(%d) failed: %m", ctx->master_fd);
	}

	ctx->dispatching = TRUE;

	if (num_events > 0) {
		unsigned idx;
		pslist_t *evlist = NULL, *es;

		g_assert(UNSIGNED(num_events) <= ctx->num_ev);
	
		for (idx = 0; num_events > 0 && idx < ctx->num_ev; idx++) {
			struct event event;

			event = (*ctx->event_get)(ctx, idx);
			g_assert(event.fd >= -1);

			if (!is_valid_fd(event.fd) || 0 == event.condition)
				continue;

			num_events--;
			evlist = pslist_prepend(evlist, WCOPY(&event));
		}

		/*
		 * Invoke I/O callbacks without any locks.
		 *
		 * Becauuse ctx->dispatching is TRUE, no changes to the relay list
		 * can happen concurrently (hopefully -- RAM).
		 */

		CTX_UNLOCK(ctx);

		PSLIST_FOREACH(evlist, es) {
			relay_list_t *rl;
			pslist_t *sl;
			struct event *event = es->data;

			rl = htable_lookup(ctx->ht, int_to_pointer(event->fd));
			g_assert(NULL != rl);
			g_assert((0 == rl->readers && 0 == rl->writers) || NULL != rl->sl);

			for (sl = rl->sl; NULL != sl; /* NOTHING */) {
				inputevt_relay_t *relay;
				unsigned id;

				id = pointer_to_uint(sl->data);
				g_assert(id > 0);
				g_assert(id < ctx->num_ev);

				sl = pslist_next(sl);

				relay = ctx->relay[id];
				g_assert(relay);
				g_assert(relay->fd == event->fd);

				if G_UNLIKELY(zero_handler == relay->handler)
					continue;

				if (relay->condition & event->condition) {
					data_available = event->data_available;
					relay->handler(relay->data, relay->fd, event->condition);
				}
			}

			WFREE(event);
		}

		pslist_free_null(&evlist);
		CTX_LOCK(ctx);
	}

	if (hash_list_length(ctx->readable) > 0) {
		plist_t *iter, *list = hash_list_list(ctx->readable);

		hash_list_clear(ctx->readable);

		/*
		 * Now that we snapshot the list of readable file descriptors, we
		 * can release the context lock to make sure callbacks are invoked
		 * with not locks held.
		 *
		 * Same as above for regular fd events, we hope that the relay list
		 * will not be concurrently updated in a way that would corrupt our
		 * processing whilst we no longer hold the lock.	--RAM
		 */

		CTX_UNLOCK(ctx);

		if (inputevt_debug > 2) {
			unsigned long count = plist_length(list);
			s_debug("%s(): %lu fake event%s", G_STRFUNC, count, plural(count));
		}

		PLIST_FOREACH(list, iter) {
			int fd = pointer_to_int(iter->data);
			relay_list_t *rl;
			pslist_t *sl;

			g_assert(is_valid_fd(fd));

			rl = htable_lookup(ctx->ht, int_to_pointer(fd));
			g_assert(NULL != rl);
			g_assert((0 == rl->readers && 0 == rl->writers) || NULL != rl->sl);

			for (sl = rl->sl; NULL != sl; /* NOTHING */) {
				inputevt_relay_t *relay;
				unsigned id;

				id = pointer_to_uint(sl->data);
				sl = pslist_next(sl);

				g_assert(id > 0);
				g_assert(id < ctx->num_ev);

				relay = ctx->relay[id];
				g_assert(relay);
				g_assert(relay->fd == fd);

				if G_UNLIKELY(zero_handler == relay->handler)
					continue;

				if (INPUT_EVENT_R & relay->condition) {
					data_available = 0;
					relay->handler(relay->data, relay->fd, INPUT_EVENT_R);
				}
			}
		}
		plist_free_null(&list);
		CTX_LOCK(ctx);
	}
	
	ctx->dispatching = FALSE;

	if (ctx->removed) {
		inputevt_purge_removed(ctx);
	}

	CTX_UNLOCK(ctx);
}

/**
 * Trampoline function bridging glib's event loop with ours.
 */
static bool
dispatch_poll(GIOChannel *unused_source,
	GIOCondition unused_cond, void *udata)
{
	struct poll_ctx *ctx = udata;

	(void) unused_cond;
	(void) unused_source;

	inputevt_timer(ctx);
	return TRUE;
}

static int
poll_func(GPollFD *gfds, unsigned n, int timeout_ms)
{
	struct poll_ctx *ctx;
	int r;
	bool dispatching;

	ctx = get_global_poll_ctx();
	g_assert(ctx);
	g_assert(ctx->initialized);

	CTX_LOCK(ctx);

	if (0 == ctx->num_ready) {
		check_for_events(ctx, &timeout_ms);
	}

	dispatching = ctx->num_ready > 0;

	CTX_UNLOCK(ctx);

	if (dispatching) {
		dispatch_poll(NULL, 0, ctx);
	}

	r = default_poll_func(gfds, n, timeout_ms);

#ifdef INPUTEVT_DEBUGGING
	if (-1 == r) {
		g_warning("INPUTEVT default poll function failed: %m");
	}
#endif

	return r;
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
inputevt_remove(unsigned *id_ptr)
{
	struct poll_ctx *ctx;
	inputevt_relay_t *relay;
	relay_list_t *rl;
	inputevt_cond_t old, cur;
	unsigned id;
	int fd;

	id = *id_ptr;
	if (0 == id)
		return;

	ctx = get_global_poll_ctx();
	g_assert(ctx->initialized);
	g_assert(ctx->ht);
	g_assert(0 != id);
	g_assert(id < ctx->num_ev);
	g_assert(0 != bit_array_get(ctx->used_event_id, id));

	CTX_LOCK(ctx);

	relay = ctx->relay[id];
	g_assert(NULL != relay);
	g_assert(zero_handler != relay->handler);
	g_assert(is_valid_fd(relay->fd));

	fd = relay->fd;
	rl = htable_lookup(ctx->ht, int_to_pointer(fd));
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

	if (-1 == (*ctx->event_set_mask)(ctx, fd, old, cur)) {
		g_warning("event_set_mask(%d, %d) failed: %m", ctx->master_fd, fd);
	}

	/* Mark as removed */
	relay->handler = zero_handler;

	if (ctx->dispatching) {
		/*
		 * Don't clear the "used_event_id" bit yet because this slot must
		 * not be recycled whilst dispatching events.
		 */
		ctx->removed = pslist_prepend(ctx->removed, uint_to_pointer(id));
	} else {
		relay_list_remove(ctx, id);		
		WFREE(relay);
		ctx->relay[id] = NULL;
		bit_array_clear(ctx->used_event_id, id);
	}
	*id_ptr = 0;

	CTX_UNLOCK(ctx);
}

static inline unsigned
inputevt_get_free_id(const struct poll_ctx *ctx)
{
	g_assert(CTX_IS_LOCKED(ctx));

	if (0 == ctx->num_ev)
		return (unsigned) -1;
	
	return bit_array_first_clear(ctx->used_event_id, 0, ctx->num_ev - 1);
}

static unsigned
inputevt_add_source(inputevt_relay_t *relay)
{
	struct poll_ctx *ctx;
	inputevt_cond_t old;
	unsigned f, id;

	g_assert(is_valid_fd(relay->fd));

	ctx = get_global_poll_ctx();

	CTX_LOCK(ctx);

	g_assert(ctx->initialized);
	g_assert(ctx->ht);

	f = inputevt_get_free_id(ctx);
	g_assert((unsigned) -1 == f || f < ctx->num_ev);

	if ((unsigned) -1 != f) {
		id = f;
	} else {
		unsigned i, n = ctx->num_ev;

		/*
		 * If there was no free ID, the arrays are resized to the
		 * double size.
		 */

		ctx->num_ev = 0 != n ? n << 1 : 32;

#ifdef HAS_KQUEUE
		XREALLOC_ARRAY(ctx->kev_arr, ctx->num_ev);
#endif

#ifdef HAS_EPOLL
		XREALLOC_ARRAY(ctx->ep_arr, ctx->num_ev);
#endif

		XREALLOC_ARRAY(ctx->pfd_arr, ctx->num_ev);

		for (i = n; i < ctx->num_ev; i++) {
			struct pollfd *pfd = &ctx->pfd_arr[i];
			pfd->fd = -1;
			pfd->events = 0;
			pfd->revents = 0;
		}

		bit_array_resize(&ctx->used_event_id, n, ctx->num_ev);

		if (0 == n) {
			/* ID 0 is reserved for compatibility with GLib's IDs */
			bit_array_set(ctx->used_event_id, 0);
			id = 1;
		} else {
			id = n;
		}

		XREALLOC_ARRAY(ctx->relay, ctx->num_ev);
		for (i = n; i < ctx->num_ev; i++)
			ctx->relay[i] = NULL;
	}

	g_assert(id < ctx->num_ev);
	bit_array_set(ctx->used_event_id, id);
	g_assert(0 != bit_array_get(ctx->used_event_id, id));

	ctx->relay[id] = relay;

	{
		void *key = int_to_pointer(relay->fd);
		relay_list_t *rl;

		rl = htable_lookup(ctx->ht, key);
		if (rl) {

			if (rl->writers || rl->readers)	{
				inputevt_relay_t *r;
				unsigned x;

				g_assert(NULL != rl->sl);

				x = pointer_to_uint(rl->sl->data);
				g_assert(x != id);
				g_assert(x > 0);
				g_assert(x < ctx->num_ev);

				r = ctx->relay[x];
				g_assert(r);
				g_assert(r->fd == relay->fd);
			}
			old = (rl->readers ? INPUT_EVENT_R : 0) |
				(rl->writers ? INPUT_EVENT_W : 0);
		} else {
			WALLOC(rl);
			rl->readers = 0;
			rl->writers = 0;
			rl->sl = NULL;
			rl->poll_idx = inputevt_poll_idx_new(ctx, relay->fd);
			old = 0;
			htable_insert(ctx->ht, key, rl);
		}

		if (INPUT_EVENT_R & relay->condition)
			rl->readers++;
		if (INPUT_EVENT_W & relay->condition)
			rl->writers++;

		rl->sl = pslist_prepend(rl->sl, uint_to_pointer(id));
	}

	if 
		(-1 == (*ctx->event_set_mask)(ctx, relay->fd,
									 old, (old | relay->condition))
	) {
		g_error("event_set_mask(%d, %d, ...) failed: %m",
			ctx->master_fd, relay->fd);
	}

	CTX_UNLOCK(ctx);

	g_assert(0 != id);	
	return id;
}

void
inputevt_set_readable(int fd)
{
	struct poll_ctx *ctx = get_global_poll_ctx();
	void *key = int_to_pointer(fd);

	if (inputevt_debug > 3) {
		s_debug("%s: fd=%d", G_STRFUNC, fd);
	}
	g_assert(is_valid_fd(fd));

	CTX_LOCK(ctx);

	if (
		htable_contains(ctx->ht, key) &&
		!hash_list_contains(ctx->readable, key)
	) {
		hash_list_append(ctx->readable, key);
	}

	CTX_UNLOCK(ctx);
}

static int
init_with_kqueue(struct poll_ctx *ctx)
#ifdef HAS_KQUEUE
{
	const int fd = kqueue();

	if (!is_valid_fd(fd)) {
		g_warning("kqueue() failed: %m");
		return -1;
	}

	g_assert(CTX_IS_LOCKED(ctx));

	g_main_context_set_poll_func(NULL, default_poll_func);
	ctx->master_fd = fd;
	ctx->polling_method = "kqueue()";
	ctx->collect_events = NULL; /* master fd can be polled */
	ctx->event_check_all = event_check_all_with_kqueue;
	ctx->event_get = event_get_with_kqueue;
	ctx->event_set_mask = event_set_mask_with_kqueue;
	return 0;
}
#else
{
	(void) ctx;
	errno = ENOTSUP;
	return -1;
}
#endif

static int
init_with_devpoll(struct poll_ctx *ctx)
#ifdef HAS_DEV_POLL
{
	const int fd = get_non_stdio_fd(open("/dev/poll", O_RDWR));

	if (!is_valid_fd(fd)) {
		g_warning("%s(): open(\"/dev/poll\", O_RDWR) failed: %m", G_STRFUNC);
		return -1;
	}

	g_assert(CTX_IS_LOCKED(ctx));

	g_main_context_set_poll_func(NULL, default_poll_func);
	ctx->master_fd = fd;
	ctx->polling_method = "/dev/poll";
	ctx->collect_events = collect_events_with_devpoll;
	ctx->event_check_all = event_check_all_with_poll; /* Identical to poll() */
	ctx->event_get = event_get_with_poll;	/* Identical to poll() */
	ctx->event_set_mask = event_set_mask_with_poll; /* Identical to poll() */
	return 0;
}
#else
{
	(void) ctx;
	errno = ENOTSUP;
	return -1;
}
#endif	/* HAS_DEV_POLL */

static int
init_with_epoll(struct poll_ctx *ctx)
#ifdef HAS_EPOLL
{
	const int fd = epoll_create(1024 /* Just an arbitrary value as hint */);

	if (!is_valid_fd(fd)) {
		g_warning("epoll_create() failed: %m");
		return -1;
	}

	g_assert(CTX_IS_LOCKED(ctx));

	g_main_context_set_poll_func(NULL, default_poll_func);
	ctx->master_fd = fd;
	ctx->polling_method = "epoll()";
	ctx->collect_events = NULL; /* master fd can be polled */
	ctx->event_check_all = event_check_all_with_epoll;
	ctx->event_get = event_get_with_epoll;
	ctx->event_set_mask = event_set_mask_with_epoll;
	return 0;
}
#else
{
	(void) ctx;
	errno = ENOTSUP;
	return -1;
}
#endif	/* HAS_EPOLL */

static int
init_with_poll(struct poll_ctx *ctx)
{
	default_poll_func = g_main_context_get_poll_func(NULL);

	g_assert(CTX_IS_LOCKED(ctx));

	g_main_context_set_poll_func(NULL, poll_func);
	ctx->master_fd = -1;
	ctx->polling_method = "poll()";
	ctx->collect_events = collect_events_with_poll;
	ctx->event_check_all = event_check_all_with_poll;
	ctx->event_get = event_get_with_poll;
	ctx->event_set_mask = event_set_mask_with_poll;

#ifdef MINGW32
	if (!mingw_has_wsapoll()) {
		ctx->polling_method = "Windows select()";
		ctx->collect_events = collect_events_with_select;
	}
#endif	/* MINGW32 */

	return 0;
}

/**
 * @return the thread ID where the I/O event loop runs from.
 */
unsigned
inputevt_thread_id(void)
{
	return inputevt_stid;
}

/**
 * Performs module initialization.
 * @param use_poll If TRUE, kqueue(), epoll(), /dev/poll etc. won't be used.
 */
void
inputevt_init(int use_poll)
{
	struct poll_ctx *ctx;

	ctx = get_global_poll_ctx();
	inputevt_stid = thread_small_id();

	g_assert(!ctx->initialized);
	ctx->initialized = TRUE;
	ctx->ht = htable_create(HASH_KEY_SELF, 0);
	ctx->readable = hash_list_new(NULL, NULL);
	mutex_init(&ctx->lock);

	/*
	 * This hash table can be accessed from inputevt_timer() without the
	 * context lock, hence it needs to be marked thread-safe.
	 */

	htable_thread_safe(ctx->ht);

	CTX_LOCK(ctx);

	init_with_poll(ctx); /* Must be called first and provides the default */

	if (!use_poll) {
		if (init_with_kqueue(ctx)) {
			if (init_with_epoll(ctx)) {
				init_with_devpoll(ctx);
			}
		}
	}

	CTX_UNLOCK(ctx);

	if (is_valid_fd(ctx->master_fd)) {
		GIOChannel *ch;

		set_close_on_exec(ctx->master_fd);	/* Just in case */

		ch = g_io_channel_unix_new(ctx->master_fd);

#if GLIB_CHECK_VERSION(2, 0, 0)
		g_io_channel_set_encoding(ch, NULL, NULL); /* binary data */
#endif /* GLib >= 2.0 */

		(void) g_io_add_watch(ch, READ_CONDITION, dispatch_poll, ctx);
	}

#ifdef INPUTEVT_DEBUGGING
	s_info("INPUTEVT using customized I/O dispatching with %s",
		ctx->polling_method);
#endif
}

/**
 * Adds an event source to the main GLIB monitor queue.
 *
 * A replacement for gdk_input_add().
 * Behaves exactly the same, except destroy notification has
 * been removed (since gtkg does not use it).
 */
unsigned
inputevt_add(int fd, inputevt_cond_t cond,
	inputevt_handler_t handler, void *data)
{
	inputevt_relay_t *relay;

	g_assert(is_valid_fd(fd));
	g_assert(zero_handler != handler);

	safety_assert(is_open_fd(fd));
	safety_assert(is_a_socket(fd) || is_a_fifo(fd));

	switch (cond) {
	case INPUT_EVENT_RX:
	case INPUT_EVENT_R:
	case INPUT_EVENT_WX:
	case INPUT_EVENT_W:
	case INPUT_EVENT_RWX:
	case INPUT_EVENT_RW:
		goto cond_is_okay;
	case INPUT_EVENT_EXCEPTION:
		g_error("must not specify INPUT_EVENT_EXCEPTION only!");
	case INPUT_EVENT_NONE:
		g_error("cannot specify INPUT_EVENT_NONE only!");
	}
	g_assert_not_reached();

cond_is_okay:
	WALLOC(relay);
	relay->condition = cond;
	relay->handler = handler;
	relay->data = data;
	relay->fd = fd;

	return inputevt_add_source(relay);
}

/**
 * Force I/O processing for all the ready sources.
 *
 * This is meant to be used when the main GLib event loop is not given
 * a chance to execute but we still want to process pending I/O events.
 */
void
inputevt_dispatch(void)
{
	struct poll_ctx *ctx = get_global_poll_ctx();

	inputevt_timer(ctx);
}

/**
 * Performs module cleanup.
 */
void
inputevt_close(void)
{
	struct poll_ctx *ctx;
	
	ctx = get_global_poll_ctx();
	inputevt_stid = THREAD_INVALID_ID;

	CTX_LOCK(ctx);

	inputevt_purge_removed(ctx);
	htable_free_null(&ctx->ht);
	hash_list_free(&ctx->readable);
	G_FREE_NULL(ctx->used_poll_idx);
	G_FREE_NULL(ctx->used_event_id);
	XFREE_NULL(ctx->relay);
	XFREE_NULL(ctx->pfd_arr);
	fd_close(&ctx->master_fd);
	ctx->initialized = FALSE;

	CTX_UNLOCK(ctx);
	mutex_destroy(&ctx->lock);
}

/* vi: set ts=4 sw=4 cindent: */
