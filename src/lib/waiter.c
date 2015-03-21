/*
 * Copyright (c) 2013, Raphael Manfredi
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
 * Asynchronous waiter.
 *
 * This is used to receive (asynchronous) events from another thread whilst
 * waiting in a I/O loop: the waiter is select()able via a dedicated file
 * descriptor and can therefore trigger a processing callback.
 *
 * A waiter can be added to any condition variable to be informed when the
 * predicate protected by the condition variable may have changed.  This is
 * not the same as waiting directly on the condition variable because that is
 * a blocking operation, whereas the notification happens asynchronously.
 *
 * A waiter can be used to block a thread until a proper notification occurs.
 * If the waiter has been inserted into several condition variables, this
 * allows the thread to wait for multiple events, although it will have to
 * determine for itself which one occurred since there is no data sent to
 * indicate the source of the event.
 *
 * A waiter can spawn children objects which will share the same waiting
 * I/O handle.  When different children waiter objects are inserted into
 * different condition variables, then the waiter can determine precisely
 * which conditions have triggered by inspecting each child in turn.
 *
 * The waiter can also be used as an inter-thread event signalling mechanism
 * if its address is known by another thread, to pop out the waiting thread
 * out of its select() and process the event as it would process any other
 * pending I/O condition.
 *
 * One proper usage of a waiter is for the I/O-driven thread to create it,
 * insert the waiter's file descriptor into its set of monitored files and
 * install the appropriate callback to its main waiting loop.
 *
 * When an event is received, it must be acknowledged with waiter_ack() or
 * the waiter will keep its I/O readiness status.
 *
 * Each waiter is reference-counted and will be disposed of when its last
 * reference is gone.  At that point, its file descriptor is closed and must
 * no longer be used as it could be re-assigned for some other purpose.
 * This means the waiter object must be removed from the I/O event loop before
 * it gets destroyed.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "waiter.h"
#include "elist.h"
#include "fd.h"
#include "spinlock.h"
#include "thread.h"				/* For thread_assert_no_locks() */
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

enum waiter_magic {
	WAITER_MAGIC = 0x61b5de89,
	WAITER_MASTER_MAGIC = 0x6337f7f1
};

struct mwaiter;

/**
 * An asynchronous waiter (child).
 */
struct waiter {
	enum waiter_magic magic;	/* Magic number */
	int refcnt;					/* Reference count */
	bool notified;				/* Whether we received a notification */
	struct mwaiter *parent;		/* Parent master waiter */
	void *data;					/* Opaque data attached to waiter */
	link_t lk;					/* List of siblings */
};

/**
 * A master waiter.
 */
struct mwaiter {
	struct waiter waiter;
	/* Extra fields for the master */
	socket_fd_t wfd[2];			/* Socket-pair used for waiting / signalling */
	uint m_notified:1;			/* Notification sent on the pipe */
	uint m_blocking:1;			/* One thread is blocked reading the pipe */
	size_t children;			/* Amount of children, for assertions */
	elist_t idle;				/* List of idle children */
	elist_t active;				/* List of active children */
	spinlock_t lock;			/* Thread-safe lock */
};

static inline void
waiter_check(const struct waiter * const w)
{
	g_assert(w != NULL);
	g_assert(WAITER_MAGIC == w->magic || WAITER_MASTER_MAGIC == w->magic);
}

static inline void
waiter_master_check(const struct mwaiter * const mw)
{
	g_assert(mw != NULL);
	g_assert(WAITER_MASTER_MAGIC == mw->waiter.magic);
}

static inline bool
waiter_is_child(const struct waiter * const w)
{
	return WAITER_MAGIC == w->magic;
}

static struct mwaiter *
cast_to_mwaiter(const struct waiter *w)
{
	g_assert(WAITER_MASTER_MAGIC == w->magic);

	return (struct mwaiter *) w;
}

#define MWAITER_LOCK(m)			spinlock(&(m)->lock)
#define MWAITER_UNLOCK(m)		spinunlock(&(m)->lock)

#define MWAITER_LOCK_QUICK(m)	spinlock_hidden(&(m)->lock)
#define MWAITER_UNLOCK_QUICK(m)	spinunlock_hidden(&(m)->lock)

#define MWAITER_LOCK_IS_HELD(m)	spinlock_is_held(&(m)->lock)

#ifdef HAS_SOCKETPAIR
#define INVALID_FD		INVALID_SOCKET
#else
#define INVALID_FD		-1
#endif

/**
 * Create a new asynchronous master waiter.
 *
 * @param data		opaque data attached to waiter
 *
 * @return new master waiter object.
 */
waiter_t *
waiter_make(void *data)
{
	struct mwaiter *mw;
	waiter_t *w;

	WALLOC0(mw);
	w = &mw->waiter;
	w->magic = WAITER_MASTER_MAGIC;
	w->refcnt = 1;
	elist_init(&mw->idle, offsetof(struct waiter, lk));
	elist_init(&mw->active, offsetof(struct waiter, lk));
	spinlock_init(&mw->lock);
	w->parent = mw;
	w->data = data;

	elist_append(&mw->idle, w);		/* Inserts itself in the idle list */
	mw->children = 1;				/* And count itself as its child */
	mw->wfd[0] = INVALID_FD;
	mw->wfd[1] = INVALID_FD;

	return w;
}

/**
 * Spawn a new child, associated with supplied opaque data.
 *
 * If the given parent is a child waiter, then we spawn a sibling instead.
 *
 * @param wp	the parent waiter out of which we need to spawn a new child
 * @param data	the data to associate to the new waiter object
 */
waiter_t *
waiter_spawn(const waiter_t *wp, void *data)
{
	waiter_t *w;
	struct mwaiter *mw;

	waiter_check(wp);

	mw = wp->parent;
	waiter_master_check(mw);

	WALLOC0(w);
	w->magic = WAITER_MAGIC;
	w->refcnt = 1;
	w->data = data;
	w->parent = mw;

	MWAITER_LOCK(mw);
	elist_append(&mw->idle, w);		/* New waiter is idle by default */
	mw->children++;					/* One new child */
	MWAITER_UNLOCK(mw);

	return w;
}

/**
 * Called to close master file descriptors.
 *
 * The master waiter must be locked upon entry.
 */
static void
waiter_close_master_fd(struct mwaiter *mw)
{
	g_assert(MWAITER_LOCK_IS_HELD(mw));

#ifdef HAS_SOCKETPAIR
	if (INVALID_SOCKET != mw->wfd[0]) {
		s_close(mw->wfd[0]);
		s_close(mw->wfd[1]);
		mw->wfd[0] = INVALID_SOCKET;
		mw->wfd[1] = INVALID_SOCKET;
	}
#else	/* !HAS_SOCKETPAIR */
	if (-1 != mw->wfd[0]) {
		fd_close(&mw->wfd[0]);
		fd_close(&mw->wfd[1]);
	}
#endif	/* HAS_SOCKETPAIR */
}

/**
 * Close the waiter's file descriptors when we no longer need I/O waiting.
 */
void
waiter_close_fd(waiter_t *w)
{
	struct mwaiter *mw;

	waiter_check(w);

	mw = w->parent;
	waiter_master_check(mw);

	MWAITER_LOCK(mw);
	waiter_close_master_fd(mw);
	MWAITER_UNLOCK(mw);
}

/**
 * Destroy a waiter.
 *
 * This routine must be called with the master waiter locked to avoid race
 * conditions with a thread waiting (to release the master) for all its children
 * to be gone by monitoring its child count.
 *
 * Upon return the master waiter is unlocked only if it was given as argument.
 */
static void
waiter_free(waiter_t *w)
{
	waiter_check(w);
	g_assert(0 == w->refcnt);

	if (WAITER_MASTER_MAGIC == w->magic) {
		struct mwaiter *mw = cast_to_mwaiter(w);

		g_assert(0 == ptr_cmp(w->parent, mw));		/* Proper master */
		g_assert(MWAITER_LOCK_IS_HELD(mw));

		/*
		 * One should not free a master with children waiters.
		 *
		 * If this becomes a problem (difficult ordered destruction)
		 * then we can always promote one of the children to the master
		 * status by re-parenting all the children but one.
		 *
		 * But until then, fatal error...
		 */

		g_assert_log(1 == mw->children,
			"%s(): attempting to free master waiter with %zu children",
			G_STRFUNC, mw->children);

	 	/* The master must be the only one left in the lists */
		g_assert(1 == elist_count(&mw->idle) + elist_count(&mw->active));

		waiter_close_master_fd(mw);
		spinlock_destroy(&mw->lock);	/* Unlocks the waiter */

		w->magic = 0;
		WFREE(mw);
	} else {
		struct mwaiter *mw = w->parent;
		elist_t *list;

		g_assert(0 != ptr_cmp(mw, w));		/* Or it would be a master! */
		g_assert(MWAITER_LOCK_IS_HELD(mw));

		/*
		 * Remove the child from the master's list.
		 * The one where it belongs to is given by its status.
		 */

		list = w->notified ? &mw->active : &mw->idle;
		elist_remove(list, w);
		mw->children--;

		g_assert(mw->children >= 1);	/* The master remains, at least */

		/* Master waiter remains locked */

		w->magic = 0;
		WFREE(w);
	}
}

/**
 * Signal the waiter held in the specified master waiter.
 *
 * @param mw		the master waiter
 * @param w			the waiter to notify (can be mw itself)
 */
static void
waiter_signal_internal(struct mwaiter *mw, waiter_t *w)
{
	g_assert(MWAITER_LOCK_IS_HELD(mw));

	if (!w->notified) {
		w->notified = TRUE;
		elist_remove(&mw->idle, w);
		elist_append(&mw->active, w);
	}
	if (!mw->m_notified) {
		char c = '\0';
		if G_UNLIKELY(INVALID_FD == mw->wfd[0]) {
			mw->m_notified = TRUE;
		} else if G_UNLIKELY(-1 == s_write(mw->wfd[1], &c, 1)) {
			s_minicarp("%s(): cannot notify about event: %m", G_STRFUNC);
		} else {
			mw->m_notified = TRUE;
		}
	}
}

/**
 * Add one reference to an asynchronous waiter.
 *
 * @return the referenced waiter.
 */
waiter_t *
waiter_refcnt_inc(waiter_t *w)
{
	waiter_check(w);

	atomic_int_inc(&w->refcnt);
	return w;
}

/**
 * Remove one reference to an asynchronous waiter.
 *
 * If the reference count drops to 0, the waiter is freed.
 *
 * @return whether the waiter is still referenced.
 */
bool
waiter_refcnt_dec(waiter_t *w)
{
	bool ref;
	struct mwaiter *mw;

	waiter_check(w);

	mw = w->parent;
	waiter_master_check(mw);

	MWAITER_LOCK(mw);

	if (1 == atomic_int_dec(&w->refcnt)) {
		bool is_master = !waiter_is_child(w);
		if (is_master && mw->m_blocking) {
			s_error("%s(): removing last reference on blocking master waiter",
				G_STRFUNC);
		}
		waiter_free(w);				/* Unlocks the master waiter if is_master */
		if (is_master)
			return FALSE;
		ref = FALSE;

		/* Master still valid and locked */

		waiter_master_check(mw);
		g_assert(MWAITER_LOCK_IS_HELD(mw));
	} else {
		ref = TRUE;
	}

	/*
	 * If the master is suspended and it has no more children and just one
	 * reference, we need to unblock it or it will stay blocked forever.
	 */

	if (mw->m_blocking && 1 == mw->children && 1 == mw->waiter.refcnt)
		waiter_signal_internal(mw, &mw->waiter);

	MWAITER_UNLOCK(mw);

	return ref;
}

/**
 * Destroy reference to waiter and nullify its pointer.
 */
void
waiter_destroy_null(waiter_t **w_ptr)
{
	waiter_t *w = *w_ptr;

	if (w != NULL) {
		waiter_refcnt_dec(w);
		*w_ptr = NULL;
	}
}

/**
 * Signal the waiter.
 */
void
waiter_signal(waiter_t *w)
{
	struct mwaiter *mw;

	waiter_check(w);

	/*
	 * It does not matter whether this is the master waiter or one of its
	 * children since the master references itself.
	 */

	mw = w->parent;
	waiter_master_check(mw);

	MWAITER_LOCK(mw);
	waiter_signal_internal(mw, w);
	MWAITER_UNLOCK(mw);
}

/**
 * Clear the notification on the master waiter.
 */
static void
waiter_master_clear(struct mwaiter *mw)
{
	g_assert(spinlock_is_held(&mw->lock));

	if (mw->m_notified) {
		char c;
		if G_UNLIKELY(-1 == s_read(mw->wfd[0], &c, 1)) {
			s_minicarp("%s(): cannot acknowledge event: %m", G_STRFUNC);
		} else {
			mw->m_notified = FALSE;
		}
	}
}

/**
 * Acknowledge reception of signal.
 */
void
waiter_ack(waiter_t *w)
{
	struct mwaiter *mw;

	waiter_check(w);
	g_assert(w->notified);

	/*
	 * It does not matter whether this is the master waiter or one of its
	 * children since the master references itself.
	 */

	mw = w->parent;
	waiter_master_check(mw);

	MWAITER_LOCK(mw);		/* Could block if a bug, let's record this */

	w->notified = FALSE;
	elist_remove(&mw->active, w);
	elist_append(&mw->idle, w);
	waiter_master_clear(mw);

	MWAITER_UNLOCK(mw);
}

/**
 * Check whether waiter has been notified.
 */
bool
waiter_notified(const waiter_t *w)
{
	waiter_check(w);

	/*
	 * The notification field is normally written with the spinlock taken
	 * on the master.  We need to issue a manual (read) barrier now to make
	 * sure we have the proper value in the CPU cache (update could have been
	 * done on another CPU).  This avoids having to take any lock.
	 */

	atomic_mb();
	return w->notified;
}

/**
 * Get the waiter's reading file descriptor, for I/O waiting.
 *
 * This always returns the master file descriptor, when called on a child
 * waiter object.
 *
 * @return the fd that can be inserted in poll() or select() to wait for events
 */
int
waiter_fd(const waiter_t *w)
{
	struct mwaiter *mw;
	socket_fd_t fd;
	bool need_event = FALSE;

	waiter_check(w);

	mw = w->parent;
	waiter_master_check(mw);

	MWAITER_LOCK(mw);

	fd = mw->wfd[0];

	if (INVALID_FD != fd)
		goto done;

	/*
	 * We don't use a pipe() because Windows can only select() on sockets.
	 * So we use a socketpair() instead and we'll emulate that on Windows.
	 * Of course, since we use sockets we need to use s_read() and s_write()
	 * as well, again for our friend Windows.
	 *
	 * FIXME:
	 * On Linux, we could use eventfd() to save one file descriptor?  Will
	 * need a new metaconfig unit.  Only the master waiter needs a file
	 * descriptor, and we won't have many, so it's not a big win.
	 */

#ifdef HAS_SOCKETPAIR
	if (-1 == socketpair(AF_LOCAL, SOCK_STREAM, 0, mw->wfd))
		s_error("%s(): socketpair() failed: %m", G_STRFUNC);
#else
	if (-1 == pipe(mw->wfd))
		s_error("%s(): pipe() failed: %m", G_STRFUNC);
#endif

	fd = mw->wfd[0];

	/*
	 * If we are already in the "notified" state, we will need to send us
	 * the event we could not receive before since we had not opened the
	 * communication channel.
	 */

	need_event = mw->m_notified;

done:
	MWAITER_UNLOCK(mw);

	/*
	 * Portability note: we use s_write() here, even though we could be using
	 * a pipe if there is no socketpair()...  However, s_write() only exists
	 * for Windows, and on UNIX s_write() is transparently remapped to write().
	 * Given that on Windows we have socketpair(), because we emulate it, it is
	 * completely safe to use s_write().
	 */

	if (need_event) {
		char c = '\0';
		if G_UNLIKELY(-1 == s_write(mw->wfd[1], &c, 1)) {
			s_minicarp("%s(): cannot notify ourselves about pending event: %m",
				G_STRFUNC);
		}
	}

	return fd;
}

/**
 * How many times is the waiter object referenced?
 *
 * @return the current reference count of the waiter.
 */
int
waiter_refcnt(const waiter_t *w)
{
	waiter_check(w);

	atomic_mb();
	return w->refcnt;
}

/**
 * How many children does the waiter have?
 *
 * @return the amount of children, 0 meaning a child waiter.
 */
int
waiter_child_count(const waiter_t *w)
{
	waiter_check(w);

	if (waiter_is_child(w))
		return 0;

	atomic_mb();
	return cast_to_mwaiter(w)->children;
}

/**
 * @return the waiter's opaque data registered at creation time.
 */
void *
waiter_data(const waiter_t *w)
{
	waiter_check(w);

	atomic_mb();
	return w->data;
}

/**
 * Set the waiter's opaque data.
 *
 * @param w		the waiter object
 * @param data	the new opaque data to set in the object
 *
 * @return the previous opaque data.
 */
void *
waiter_set_data(waiter_t *w, void *data)
{
	void *odata;

	waiter_check(w);

	/*
	 * Since we take no locks, we need the memory barriers to ensure the
	 * update is atomically seen on all CPUs.
	 */

	atomic_mb();
	odata = w->data;
	w->data = data;
	atomic_mb();

	return odata;
}

/**
 * Wait for one of our waiter to be signaled.
 *
 * This can be called on the master or on any of its children, but when the
 * call returns, the object may not appear notified (spurious wakeup),
 * especially if called on a child and another sibling gets notified.
 *
 * Only one thread is allowed to block at a time, others will not be blocked.
 *
 * The thread will be unblocked when the master waiter ends up with 1 reference
 * count and 1 child (itself).
 *
 * @return TRUE if we blocked, FALSE if we were denied blocking because
 * another thread is already waiting.
 */
bool
waiter_suspend(const waiter_t *w)
{
	struct mwaiter *mw;
	char c;
	bool allowed = TRUE;

	waiter_check(w);

	mw = w->parent;
	waiter_master_check(mw);

	/*
	 * To block we'll need to open a communication channel...
	 */

	if G_UNLIKELY(INVALID_FD == mw->wfd[0])
		(void) waiter_fd(w);

	/*
	 * Don't allow blocking if another thread is blocking on the waiter or
	 * when we just have one reference and no children: nobody will be able
	 * to signal us (a global memory reference does not count -- if a separate
	 * thread wants to signal us, it needs to reference count us).
	 *
	 * This is a safety precaution against programming errors, but it is by
	 * no means a guarantee against deadlocks or foreever blocks: we don't
	 * know we'll be signaled even if we blocked.
	 */

	MWAITER_LOCK_QUICK(mw);
	if (mw->m_blocking || (1 == mw->waiter.refcnt && 1 == mw->children))
		allowed = FALSE;
	else
		mw->m_blocking = TRUE;
	MWAITER_UNLOCK_QUICK(mw);

	if (!allowed)
		return FALSE;

	/*
	 * We're about to block, we must not hold any lock.
	 */

	thread_assert_no_locks(G_STRFUNC);

	if G_UNLIKELY(-1 == s_read(mw->wfd[0], &c, 1)) {
		s_minicarp("%s(): could not receive event: %m", G_STRFUNC);
		MWAITER_LOCK_QUICK(mw);
		mw->m_blocking = FALSE;
		MWAITER_UNLOCK_QUICK(mw);
	} else {
		MWAITER_LOCK_QUICK(mw);
		mw->m_notified = FALSE;
		mw->m_blocking = FALSE;
		MWAITER_UNLOCK_QUICK(mw);
	}

	return TRUE;
}

/**
 * Invoke callback on each notified waiter in the master waiter.
 *
 * The callback is passed each notified waiter object.  The status is
 * atomically reset to un-notified before invoking the callback, so
 * there is no need to call waiter_ack().
 *
 * @param w		a waiter (can be a child waiter)
 * @param cb	the callback to invoke on each notified waiter
 * @param data	opaque callback data to propagate
 *
 * @return the amount of notified waiters we had.
 */
size_t
waiter_foreach_notified(const waiter_t *w, data_fn_t cb, void *data)
{
	struct mwaiter *mw;
	waiter_t **notified = NULL, **p;
	size_t i, count;

	waiter_check(w);

	mw = w->parent;
	waiter_master_check(mw);

	/*
	 * Construct the list of notified waiter objects in "notified" and
	 * move all the notified objects back to the idle list after clearing
	 * their notified status.
	 */

	MWAITER_LOCK(mw);
	count = elist_count(&mw->active);
	if (count != 0) {
		link_t *lk;

		WALLOC_ARRAY(notified, count);
		p = notified;

		ELIST_FOREACH(&mw->active, lk) {
			waiter_t *wi = elist_data(&mw->active, lk);

			waiter_check(wi);
			g_assert(wi->notified);

			*p++ = wi;
		}

		for (i = 0, p = notified; i < count; i++) {
			waiter_t *wi = *p++;

			elist_remove(&mw->active, wi);
			elist_append(&mw->idle, wi);
			wi->notified = FALSE;
		}
	}
	waiter_master_clear(mw);
	MWAITER_UNLOCK(mw);

	/*
	 * Now that we no longer hold the lock on the master waiter object,
	 * invoke the callbacks.  This allows re-entrance in the code, if needed.
	 */

	for (i = 0, p = notified; i < count; i++) {
		waiter_t *wi = *p++;
		(*cb)(wi, data);
	}

	WFREE_ARRAY_NULL(notified, count);

	return count;
}

/* vi: set ts=4 sw=4 cindent: */
