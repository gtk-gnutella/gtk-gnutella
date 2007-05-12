/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * PDU Messages.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "pmsg.h"

#include "lib/zalloc.h"
#include "lib/walloc.h"
#include "lib/override.h"			/* Must be the last header included */

#define implies(a,b)	(!(a) || (b))
#define valid_ptr(a)	(((gulong) (a)) > 100L)

#define EMBEDDED_OFFSET	G_STRUCT_OFFSET(pdata_t, d_embedded)

/**
 * An extended message block.
 *
 * An extended message block can be identified by its `m_prio' field
 * having the PMSG_PF_EXT flag set.
 */
typedef struct pmsg_ext {
	struct pmsg pmsg;				/**< Must be the first member */
	/* Additional fields */
	pmsg_free_t m_free;				/**< Free routine */
	gpointer m_arg;					/**< Argument to pass to free routine */
} pmsg_ext_t;

static inline void
pmsg_ext_check_consistency(const pmsg_ext_t * const emb)
{
	g_assert(emb);
	g_assert(PMSG_EXT_MAGIC == emb->pmsg.magic);
	g_assert(PMSG_PF_EXT & emb->pmsg.m_prio);
}

static zone_t *mb_zone = NULL;

static inline ALWAYS_INLINE pmsg_ext_t *
cast_to_pmsg_ext(pmsg_t *mb)
{
	pmsg_ext_t *emb;

	emb = (pmsg_ext_t *) mb;
	pmsg_ext_check_consistency(emb);
	return emb;
}

static inline ALWAYS_INLINE pmsg_t *
cast_to_pmsg(pmsg_ext_t *emb)
{
	pmsg_ext_check_consistency(emb);
	return &emb->pmsg;
}

/**
 * Allocate internal variables.
 */
void
pmsg_init(void)
{
	mb_zone = zget(sizeof(pmsg_t), 1024);
}

/**
 * Free internal variables
 */
void
pmsg_close(void)
{
	zdestroy(mb_zone);
}

/**
 * Compute message's size.
 */
int
pmsg_size(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);

	return mb->m_wptr - mb->m_rptr;
}

/**
 * Fill newly created message block.
 *
 * @return the message block given as argument.
 */
static pmsg_t *
pmsg_fill(pmsg_t *mb, pdata_t *db, gint prio, gconstpointer buf, gint len)
{
	mb->magic = (PMSG_PF_EXT & prio) ? PMSG_EXT_MAGIC : PMSG_MAGIC;
	mb->m_data = db;
	mb->m_prio = prio;
	mb->m_check = NULL;
	db->d_refcnt++;

	if (buf) {
		mb->m_rptr = db->d_arena;
		mb->m_wptr = db->d_arena + len;
		memcpy(db->d_arena, buf, len);
	} else
		mb->m_rptr = mb->m_wptr = db->d_arena;

	g_assert(implies(buf, len == pmsg_size(mb)));

	pmsg_check_consistency(mb);
	return mb;
}

/**
 * Create new message from user provided data, which are copied into the
 * allocated data block.  If no user buffer is provided, an empty message
 * is created and the length is used to size the data block.
 *
 * @return a message made of one message block referencing one new data block.
 */
pmsg_t *
pmsg_new(gint prio, gconstpointer buf, gint len)
{
	pmsg_t *mb;
	pdata_t *db;

	g_assert(len > 0);
	g_assert(implies(buf, valid_ptr(buf)));
	g_assert(0 == (prio & ~PMSG_PRIO_MASK));

	mb = zalloc(mb_zone);
	db = pdata_new(len);

	return pmsg_fill(mb, db, prio, buf, len);
}

/**
 * Like pmsg_new() but returns an extended form with a free routine callback.
 */
pmsg_t *
pmsg_new_extend(gint prio, gconstpointer buf, gint len,
	pmsg_free_t free_cb, gpointer arg)
{
	pmsg_ext_t *emb;
	pdata_t *db;

	g_assert(len > 0);
	g_assert(implies(buf, valid_ptr(buf)));
	g_assert(0 == (prio & ~PMSG_PRIO_MASK));

	emb = walloc(sizeof(*emb));
	db = pdata_new(len);

	emb->m_free = free_cb;
	emb->m_arg = arg;

	(void) pmsg_fill(&emb->pmsg, db, prio | PMSG_PF_EXT, buf, len);

	return cast_to_pmsg(emb);
}

/**
 * Allocate new message using existing data block `db'.
 * The `roff' and `woff' are used to delimit the start and the end (first
 * unwritten byte) of the message within the data buffer.
 *
 * @return new message.
 */
pmsg_t *
pmsg_alloc(gint prio, pdata_t *db, gint roff, gint woff)
{
	pmsg_t *mb;

	g_assert(valid_ptr(db));
	g_assert(roff >= 0 && (size_t) roff <= pdata_len(db));
	g_assert(woff >= 0 && (size_t) woff <= pdata_len(db));
	g_assert(woff >= roff);
	g_assert(0 == (prio & ~PMSG_PRIO_MASK));

	mb = zalloc(mb_zone);

	pmsg_fill(mb, db, prio, NULL, 0);

	mb->m_rptr += roff;
	mb->m_wptr += woff;

	return mb;
}

/**
 * Extended cloning of message, adds a free routine callback.
 */
pmsg_t *
pmsg_clone_extend(pmsg_t *mb, pmsg_free_t free_cb, gpointer arg)
{
	pmsg_ext_t *nmb;

	pmsg_check_consistency(mb);

	nmb = walloc(sizeof(*nmb));
	nmb->pmsg.magic = PMSG_EXT_MAGIC;

	nmb->pmsg.m_rptr = mb->m_rptr;
	nmb->pmsg.m_wptr = mb->m_wptr;
	nmb->pmsg.m_data = mb->m_data;
	nmb->pmsg.m_prio = mb->m_prio;
	nmb->pmsg.m_check = mb->m_check;
	pdata_addref(nmb->pmsg.m_data);

	nmb->pmsg.m_prio |= PMSG_PF_EXT;
	nmb->m_free = free_cb;
	nmb->m_arg = arg;

	return cast_to_pmsg(nmb);
}

/**
 * Replace free routine from an extended message block.
 * The original free routine and its argument are returned.
 *
 * This is used when wrapping an existing extended message and its metadata
 * in another extension structure.
 *
 * @param mb the extended message block
 * @param nfree the new free routine (NULL to cancel)
 * @param narg the new argument to pass to the free routine
 * @param oarg where the old argument to the free routine is returned.
 * Can be NULL if no return is expected.
 *
 * @return the old free routine.
 */
pmsg_free_t
pmsg_replace_ext(pmsg_t *mb, pmsg_free_t nfree, gpointer narg, gpointer *oarg)
{
	pmsg_ext_t *nmb;
	pmsg_free_t fn;

	nmb = cast_to_pmsg_ext(mb);
	if (oarg)
		*oarg = nmb->m_arg;
	fn = nmb->m_free;

	nmb->m_free = nfree;		/* Can be NULL to cancel */
	nmb->m_arg = narg;

	return fn;
}

/**
 * Get the "meta data" from an extended message block (the argument passed
 * to the embedded free routine).
 */
gpointer
pmsg_get_metadata(pmsg_t *mb)
{
	return cast_to_pmsg_ext(mb)->m_arg;
}

/**
 * Set the pre-send checking routine for the buffer.
 *
 * This routine, if it exists (non-NULL) is called just before enqueueing
 * the message for sending.  If it returns FALSE, the message is immediately
 * dropped.
 *
 * The callback routine must not modify the message, as the buffer can
 * be shared among multiple messages, unless its refcount is 1.
 *
 * @return the previous pre-send checking routine.
 */
pmsg_check_t
pmsg_set_check(pmsg_t *mb, pmsg_check_t check)
{
	pmsg_check_t old;

	pmsg_check_consistency(mb);

	old = mb->m_check;
	mb->m_check = check;

	return old;
}

/**
 * Shallow cloning of extended message, result is referencing the same data.
 */
static pmsg_t *
pmsg_clone_ext(pmsg_ext_t *mb)
{
	pmsg_ext_t *nmb;

	pmsg_ext_check_consistency(mb);

	nmb = walloc(sizeof(*nmb));
	*nmb = *mb;					/* Struct copy */
	pdata_addref(nmb->pmsg.m_data);

	return cast_to_pmsg(nmb);
}

/**
 * Shallow cloning of message, result is referencing the same data.
 */
pmsg_t *
pmsg_clone(pmsg_t *mb)
{
	if (pmsg_is_extended(mb)) {
		return pmsg_clone_ext(cast_to_pmsg_ext(mb));
	} else {
		pmsg_t *nmb;

		pmsg_check_consistency(mb);
		nmb = zalloc(mb_zone);
		*nmb = *mb;					/* Struct copy */
		pdata_addref(nmb->m_data);

		return nmb;
	}
}

/**
 * Free all message blocks, and decrease ref count on all data buffers.
 */
void
pmsg_free(pmsg_t *mb)
{
	pdata_t *db = mb->m_data;

	pmsg_check_consistency(mb);

	/*
	 * Invoke free routine on extended message block.
	 */

	if (pmsg_is_extended(mb)) {
		pmsg_ext_t *emb = cast_to_pmsg_ext(mb);
		if (emb->m_free)
			(*emb->m_free)(mb, emb->m_arg);
		memset(emb, 0, sizeof *emb);
		wfree(emb, sizeof(*emb));
	} else {
		memset(mb, 0, sizeof *mb);
		zfree(mb_zone, mb);
	}

	/*
	 * Unref buffer data only after possible free routine was
	 * invoked, since it may cause a free, preventing access to
	 * memory from within the free routine.
	 */

	pdata_unref(db);
}

/**
 * @return amount of data that can be written at the end of the message.
 */
gint
pmsg_writable_length(const pmsg_t *mb)
{
	pdata_t *arena;
	gint available;

	pmsg_check_consistency(mb);

	/*
	 * If buffer is not writable (shared among several readers), it is
	 * forbidden to write any new data to it.
	 */

	arena = mb->m_data;
	available = arena->d_end - mb->m_wptr;
	return pmsg_is_writable(mb) ? available : 0;
}

/**
 * Write data at the end of the message.
 * The message must be the only reference to the underlying data.
 *
 * @returns amount of written data.
 */
gint
pmsg_write(pmsg_t *mb, gconstpointer data, gint len)
{
	pdata_t *arena;
	gint available, written;

	pmsg_check_consistency(mb);
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */

	arena = mb->m_data;
	available = arena->d_end - mb->m_wptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	written = len >= available ? available : len;
	if (written != 0) {
		memcpy(mb->m_wptr, data, written);
		mb->m_wptr += written;
	}
	return written;
}

/**
 * Read data from the message, returning the amount of bytes transferred.
 */
gint
pmsg_read(pmsg_t *mb, gpointer data, gint len)
{
	gint available, readable;

	pmsg_check_consistency(mb);

	available = mb->m_wptr - mb->m_rptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	readable = len >= available ? available : len;
	if (readable != 0) {
		memcpy(data, mb->m_rptr, readable);
		mb->m_rptr += readable;
	}
	return readable;
}

/**
 * Discard data from the message, returning the amount of bytes discarded.
 */
gint
pmsg_discard(pmsg_t *mb, gint len)
{
	gint available, n;

	pmsg_check_consistency(mb);

	available = mb->m_wptr - mb->m_rptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	n = len >= available ? available : len;
	mb->m_rptr += n;
	return n;
}


/**
 * Discard trailing data from the message, returning the amount of
 * bytes discarded.
 */
gint
pmsg_discard_trailing(pmsg_t *mb, gint len)
{
	gint available, n;

	pmsg_check_consistency(mb);

	available = mb->m_wptr - mb->m_rptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	n = len >= available ? available : len;
	mb->m_wptr -= n;
	return n;
}

/**
 * Allocate a new data block of given size.
 * The block header is at the start of the allocated block.
 */
pdata_t *
pdata_new(int len)
{
	pdata_t *db;
	gchar *arena;

	g_assert(len > 0);

	arena = g_malloc(len + EMBEDDED_OFFSET);

	db = pdata_allocb(arena, len + EMBEDDED_OFFSET, NULL, 0);

	g_assert((size_t) len == pdata_len(db));

	return db;
}

/**
 * Create an embedded data buffer out of existing arena.
 *
 * The optional `freecb' structure supplies the free routine callback to be
 * used to free the arena, with freearg as additional argument.
 */
pdata_t *
pdata_allocb(void *buf, gint len, pdata_free_t freecb, gpointer freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(len >= (gint) EMBEDDED_OFFSET);
	g_assert(implies(freecb, valid_ptr(freecb)));

	db = buf;

	db->d_arena = db->d_embedded;
	db->d_end = db->d_arena + (len - EMBEDDED_OFFSET);
	db->d_refcnt = 0;
	db->d_free = freecb;
	db->d_arg = freearg;

	g_assert((size_t) len - EMBEDDED_OFFSET == pdata_len(db));

	return db;
}

/**
 * Create an external (arena not embedded) data buffer out of existing arena.
 *
 * The optional `freecb' structure supplies the free routine callback to be
 * used to free the arena, with freearg as additional argument.
 */
pdata_t *
pdata_allocb_ext(void *buf, gint len, pdata_free_t freecb, gpointer freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(implies(freecb, valid_ptr(freecb)));

	db = walloc(sizeof(*db));

	db->d_arena = buf;
	db->d_end = (gchar *) buf + len;
	db->d_refcnt = 0;
	db->d_free = freecb;
	db->d_arg = freearg;

	g_assert((size_t) len == pdata_len(db));
	g_assert(db->d_arena != db->d_embedded);

	return db;
}

/**
 * This free routine can be used when there is nothing to be freed for
 * the buffer, probably because it was made out of a static buffer.
 */
void
pdata_free_nop(gpointer unused_p, gpointer unused_arg)
{
	(void) unused_p;
	(void) unused_arg;
}

/**
 * Free data block when its reference count has reached 0.
 */
static void
pdata_free(pdata_t *db)
{
	gboolean is_embedded = (db->d_arena == db->d_embedded);

	g_assert(db->d_refcnt == 0);

	/*
	 * If user supplied a free routine for the buffer, invoke it.
	 */

	if (db->d_free) {
		gpointer p = is_embedded ? (gpointer) db : (gpointer) db->d_arena;
		(*db->d_free)(p, db->d_arg);
		if (!is_embedded)
			wfree(db, sizeof(*db));
	} else {
		if (!is_embedded) {
			G_FREE_NULL(db->d_arena);
			wfree(db, sizeof(*db));
		} else {
			G_FREE_NULL(db);
		}
	}
}

/**
 * Decrease reference count on buffer, and free it when it reaches 0.
 */
void
pdata_unref(pdata_t *db)
{
	g_assert(valid_ptr(db));
	g_assert(db->d_refcnt > 0);

	if (db->d_refcnt-- == 1)
		pdata_free(db);
}

/**
 * Creates an iovec from a singly-linked list of pmsg_t buffers.
 * NOTE: The iovec will hold no more than MAX_IOV_COUNT items. That means
 *       the iovec might not cover the whole buffered data. This limited
 *		 is applied because writev() could fail with EINVAL otherwise
 *		 which would simply add more unnecessary complexity.
 */
struct iovec *
pmsg_slist_to_iovec(slist_t *slist, gint *iovcnt_ptr, size_t *size_ptr)
{
	struct iovec *iov;
	size_t held = 0;
	gint n;

	g_assert(slist);

	n = slist_length(slist);

	if (n > 0) {
		slist_iter_t *iter;
		gint i;

		n = MIN(n, MAX_IOV_COUNT);
		iov = g_malloc(n * sizeof *iov);

		iter = slist_iter_before_head(slist);
		for (i = 0; i < n; i++) {
			pmsg_t *mb;
			size_t size;

			mb = slist_iter_next(iter);
			g_assert(mb);

			size = pmsg_size(mb);
			g_assert(size > 0);
			held += size;

			iov[i].iov_base = deconstify_gpointer(pmsg_read_base(mb));
			iov[i].iov_len = size;
		}
		slist_iter_free(&iter);
	} else {
		iov = NULL;
	}
	if (iovcnt_ptr) {
		*iovcnt_ptr = MAX(0, n);
	}
	if (size_ptr) {
		*size_ptr = held;
	}
	return iov;
}

/**
 * Discard `n_bytes' from the pmsg_t buffer slist and free all completely
 * discarded buffers.
 */
void
pmsg_slist_discard(slist_t *slist, size_t n_bytes)
{
	slist_iter_t *iter;

	g_assert(slist);

	iter = slist_iter_on_head(slist);
	while (n_bytes > 0) {
		pmsg_t *mb;
		size_t size;

		g_assert(slist_iter_has_item(iter));
		mb = slist_iter_current(iter);
		g_assert(mb);

		size = pmsg_size(mb);
		if (size > n_bytes) {
			pmsg_discard(mb, n_bytes);
			break;
		} else {
			pmsg_free(mb);
			n_bytes -= size;
			slist_iter_remove(iter);
		}
	}
	slist_iter_free(&iter);
}

/**
 * Appends `n_bytes' to the pmsg_t buffer. If the last pmsg_t is writable
 * it is filled with as much data as space is still available. Otherwise
 * or if this space is not sufficient another pmsg_t is created and
 * append to the list.
 */
void
pmsg_slist_append(slist_t *slist, const void *data, size_t n_bytes)
{
	pmsg_t *mb;

	g_assert(slist);

	if (0 == n_bytes)
		return;
	g_assert(NULL != data);

	mb = slist_tail(slist);
	if (mb && pmsg_is_writable(mb)) {
		size_t n;

		n = pmsg_write(mb, data, n_bytes);
		data = (const char *) data + n;
		n_bytes -= n;
	}
	if (n_bytes > 0) {
		mb = pmsg_new(PMSG_P_DATA, NULL, n_bytes);
		pmsg_write(mb, data, n_bytes);
		slist_append(slist, mb);
	}
}

/* vi: set ts=4 sw=4 cindent: */
