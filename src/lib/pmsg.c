/*
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

#include "pmsg.h"

#include "halloc.h"
#include "log.h"				/* For s_carp_once() */
#include "mempcpy.h"
#include "stacktrace.h"
#include "stringify.h"			/* For plural() */
#include "unsigned.h"			/* For size_is_non_negative() */
#include "walloc.h"

#include "override.h"			/* Must be the last header included */

#define valid_ptr(a)	(((ulong) (a)) > 100L)

#define EMBEDDED_OFFSET	offsetof(pdata_t, d_embedded)

/**
 * An extended message block.
 *
 * An extended message block can be identified by its `m_flags' field
 * having the PMSG_PF_EXT flag set.
 */
typedef struct pmsg_ext {
	struct pmsg pmsg;				/**< Must be the first member */
	/* Additional fields */
	pmsg_free_t m_free;				/**< Free routine */
	void *m_arg;					/**< Argument to pass to free routine */
} pmsg_ext_t;

static inline void
pmsg_ext_check_consistency(const pmsg_ext_t * const emb)
{
	g_assert(emb);
	g_assert(PMSG_EXT_MAGIC == emb->pmsg.magic);
	g_assert(PMSG_PF_EXT & emb->pmsg.m_flags);
}

static inline ALWAYS_INLINE pmsg_ext_t *
cast_to_pmsg_ext(const pmsg_t *mb)
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
	/* Nothing to do */
}

/**
 * Free internal variables
 */
void
pmsg_close(void)
{
	/* Nothing to do */
}

/**
 * Reset message block, discarding all the data buffered and restoring the
 * state it had after creation.  Upon return, it can be used as if a brand
 * new message block had been created.
 */
void
pmsg_reset(pmsg_t *mb)
{
	pmsg_check(mb);

	mb->m_rptr = mb->m_wptr = mb->m_data->d_arena;	/* Empty buffer */
	mb->m_flags = PMSG_EXT_MAGIC == mb->magic ? PMSG_PF_EXT : 0;
	mb->m_u.m_check = NULL;						/* Clear "pre-send" checks */
}

/**
 * Fill newly created message block.
 *
 * @return the message block given as argument.
 */
static pmsg_t *
pmsg_fill(pmsg_t *mb, pdata_t *db, int prio, bool ext, const void *buf, int len)
{
	mb->magic = ext ? PMSG_EXT_MAGIC : PMSG_MAGIC;
	mb->m_data = db;
	mb->m_prio = prio;
	mb->m_flags = ext ? PMSG_PF_EXT : 0;
	mb->m_u.m_check = NULL;
	mb->m_refcnt = 1;
	db->d_refcnt++;

	if (buf) {
		mb->m_rptr = db->d_arena;
		mb->m_wptr = db->d_arena + len;
		memcpy(db->d_arena, buf, len);
	} else
		mb->m_rptr = mb->m_wptr = db->d_arena;

	g_assert(implies(buf, len == pmsg_size(mb)));

	pmsg_check(mb);
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
pmsg_new(int prio, const void *buf, int len)
{
	pmsg_t *mb;
	pdata_t *db;

	g_assert(len > 0);
	g_assert(implies(buf, valid_ptr(buf)));

	WALLOC(mb);
	db = pdata_new(len);

	return pmsg_fill(mb, db, prio, FALSE, buf, len);
}

/**
 * Like pmsg_new() but returns an extended form with a free routine callback.
 */
pmsg_t *
pmsg_new_extend(int prio, const void *buf, int len,
	pmsg_free_t free_cb, void *arg)
{
	pmsg_ext_t *emb;
	pdata_t *db;

	g_assert(len > 0);
	g_assert(implies(buf, valid_ptr(buf)));

	WALLOC(emb);
	db = pdata_new(len);

	emb->m_free = free_cb;
	emb->m_arg = arg;

	(void) pmsg_fill(&emb->pmsg, db, prio, TRUE, buf, len);

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
pmsg_alloc(int prio, pdata_t *db, int roff, int woff)
{
	pmsg_t *mb;

	g_assert(valid_ptr(db));
	g_assert(roff >= 0 && (size_t) roff <= pdata_len(db));
	g_assert(woff >= 0 && (size_t) woff <= pdata_len(db));
	g_assert(woff >= roff);

	WALLOC(mb);

	pmsg_fill(mb, db, prio, FALSE, NULL, 0);

	mb->m_rptr += roff;
	mb->m_wptr += woff;

	return mb;
}

/**
 * Extended cloning of message, adds a free routine callback.
 */
pmsg_t *
pmsg_clone_extend(const pmsg_t *mb, pmsg_free_t free_cb, void *arg)
{
	pmsg_ext_t *nmb;

	pmsg_check(mb);

	WALLOC(nmb);
	nmb->pmsg = *mb;		/* Struct copy */
	nmb->pmsg.magic = PMSG_EXT_MAGIC;

	pdata_addref(nmb->pmsg.m_data);

	nmb->pmsg.m_flags |= PMSG_PF_EXT;
	nmb->pmsg.m_refcnt = 1;
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
pmsg_replace_ext(pmsg_t *mb, pmsg_free_t nfree, void *narg, void **oarg)
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
void *
pmsg_get_metadata(const pmsg_t *mb)
{
	return cast_to_pmsg_ext(mb)->m_arg;
}

/*
 * Ensure we do not have a check/hook installed already, otherwise loudly
 * warn them once, as this is probably not intended!
 */
static void
pmsg_no_presend_check(const pmsg_t * const mb, const char *caller)
{
	/*
	 * Because m_check and m_hook are in the same union and have the same
	 * memory size, it is sufficient to check for one field being non-NULL.
	 */

	if G_LIKELY(NULL == mb->m_u.m_check)
		return;

	s_carp_once("%s(): mb=%p (%d byte%s, prio=%u, refcnt=%u, flags=0x%x)"
		" already has %s %s()",
		caller, mb, pmsg_size(mb), plural(pmsg_size(mb)),
		mb->m_prio, mb->m_refcnt, mb->m_flags,
		(mb->m_flags & PMSG_PF_HOOK) ? "transmit hook" : "can-send callback",
		stacktrace_function_name(mb->m_u.m_check));
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
 */
void
pmsg_set_send_callback(pmsg_t *mb, pmsg_check_t check)
{
	pmsg_check(mb);

	/*
	 * If there is already something installed (a hook or a callback),
	 * then warn them as it is probably a mistake.
	 */

	pmsg_no_presend_check(mb, G_STRFUNC);

	mb->m_u.m_check = check;
	mb->m_flags &= ~PMSG_PF_HOOK;	/* Is not a hook */
}

/**
 * Set the pre-transmit hook routine for the buffer.
 *
 * This routine, if it exists (non-NULL) is called just before sending
 * the message at the lowest level.  If it returns FALSE, the message is
 * immediately dropped.
 *
 * The callback routine must not modify the message.
 *
 * The difference with a "can-send callback" is that a hook is only invoked
 * on the standalone buffer, the layer perusing this information being
 * able to gather all its context from the message, using its protocol header
 * relevant to the layer.
 */
void
pmsg_set_transmit_hook(pmsg_t *mb, pmsg_hook_t hook)
{
	pmsg_check(mb);

	/*
	 * If there is already something installed (a hook or a callback),
	 * then warn them as it is probably a mistake.
	 */

	pmsg_no_presend_check(mb, G_STRFUNC);

	mb->m_u.m_hook = hook;
	mb->m_flags |= PMSG_PF_HOOK;	/* Is a hook */
}

/**
 * Shallow cloning of extended message, result is referencing the same data.
 */
static pmsg_t *
pmsg_clone_ext(pmsg_ext_t *mb)
{
	pmsg_ext_t *nmb;

	pmsg_ext_check_consistency(mb);

	WALLOC(nmb);
	*nmb = *mb;					/* Struct copy */
	nmb->pmsg.m_refcnt = 1;
	pdata_addref(nmb->pmsg.m_data);

	return cast_to_pmsg(nmb);
}

/**
 * Shallow cloning of message, result is referencing the same data.
 *
 * This is not the same thing as pmsg_ref() because here a new message block
 * is created (albeit the data are shared with the original message).
 */
pmsg_t *
pmsg_clone(const pmsg_t *mb)
{
	if (pmsg_is_extended(mb)) {
		return pmsg_clone_ext(cast_to_pmsg_ext(mb));
	} else {
		pmsg_t *nmb;

		pmsg_check(mb);
		WALLOC(nmb);
		*nmb = *mb;					/* Struct copy */
		nmb->m_refcnt = 1;
		pdata_addref(nmb->m_data);

		return nmb;
	}
}

/**
 * Shallow cloning of message, making sure we have a plain clone even if
 * the original was extended.
 */
pmsg_t *
pmsg_clone_plain(const pmsg_t *mb)
{
	pmsg_t *nmb;

	pmsg_check(mb);

	WALLOC(nmb);
	memcpy(nmb, mb, sizeof *nmb);
	nmb->magic = PMSG_MAGIC;		/* Force plain message */
	nmb->m_flags &= ~PMSG_PF_EXT;	/* In case original was extended */
	nmb->m_refcnt = 1;
	pdata_addref(nmb->m_data);

	return nmb;
}

/**
 * Increase the reference count on the message block.
 *
 * This must be used in TX stacks when there is a free routine installed
 * on messages and we want to keep another reference to the message, yet
 * allow upper layers to pmsg_free() the message block as if it had been
 * sent from their point of view.
 *
 * It also allows correct pmsg_was_sent() checks in free routines, whereas
 * a pmsg_clone() would create a new message.
 *
 * @return its argument, for convenience.
 */
pmsg_t *
pmsg_ref(pmsg_t *mb)
{
	pmsg_check(mb);
	g_assert(mb->m_refcnt != 0);

	mb->m_refcnt++;

	g_assert(mb->m_refcnt != 0);		/* Safeguard against overflows */

	return mb;
}

/**
 * Free all message blocks, and decrease ref count on all data buffers.
 *
 * If the message block is referenced by more than one place, simply
 * decrease its reference count.  No freeing occurs and the free routine
 * is therefore not invoked.
 */
void
pmsg_free(pmsg_t *mb)
{
	pdata_t *db = mb->m_data;

	pmsg_check(mb);
	g_assert(mb->m_refcnt != 0);

	/*
	 * Don't free anything if refcnt != 1.
	 */

	if (mb->m_refcnt > 1U) {
		mb->m_refcnt--;
		return;
	}

	/*
	 * Invoke free routine on extended message block.
	 */

	if (pmsg_is_extended(mb)) {
		pmsg_ext_t *emb = cast_to_pmsg_ext(mb);
		if (emb->m_free)
			(*emb->m_free)(mb, emb->m_arg);
		WFREE0(emb);
	} else {
		WFREE0(mb);
	}

	/*
	 * Unref buffer data only after possible free routine was
	 * invoked, since it may cause a free, preventing access to
	 * memory from within the free routine.
	 */

	pdata_unref(db);
}

/**
 * Free message block referenced in the variable and nullify it.
 */
void
pmsg_free_null(pmsg_t **mb_ptr)
{
	pmsg_t *mb = *mb_ptr;

	if (mb) {
		pmsg_free(mb);
		*mb_ptr = NULL;
	}
}

/**
 * @return amount of data that can be written at the end of the message.
 */
int
pmsg_writable_length(const pmsg_t *mb)
{
	pdata_t *arena;
	int available;

	pmsg_check(mb);

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
int
pmsg_write(pmsg_t *mb, const void *data, int len)
{
	pdata_t *arena;
	int available, written;

	pmsg_check(mb);
	g_assert_log(len >= 0, "%s(): len=%d", G_STRFUNC, len);
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */

	arena = mb->m_data;
	available = arena->d_end - mb->m_wptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	written = len >= available ? available : len;
	if (written != 0)
		mb->m_wptr = mempcpy(mb->m_wptr, data, written);

	return written;
}

/**
 * Read data from the message, returning the amount of bytes transferred.
 */
int
pmsg_read(pmsg_t *mb, void *data, int len)
{
	int available, readable;

	pmsg_check(mb);
	g_assert_log(len >= 0, "%s(): len=%d", G_STRFUNC, len);

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
int
pmsg_discard(pmsg_t *mb, int len)
{
	int available, n;

	pmsg_check(mb);
	g_assert_log(len >= 0, "%s(): len=%d", G_STRFUNC, len);

	available = mb->m_wptr - mb->m_rptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	/*
	 * The read pointer moves forward to point after the discarded bytes.
	 */

	n = len >= available ? available : len;
	mb->m_rptr += n;
	return n;
}

/**
 * Discard trailing data from the message, returning the amount of
 * bytes discarded.
 */
int
pmsg_discard_trailing(pmsg_t *mb, int len)
{
	int available, n;

	pmsg_check(mb);
	g_assert_log(len >= 0, "%s(): len=%d", G_STRFUNC, len);

	available = mb->m_wptr - mb->m_rptr;
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	/*
 	 * The write pointer moves backward to point before the discarded bytes.
	 */

	n = len >= available ? available : len;
	mb->m_wptr -= n;
	return n;
}

/**
 * Copy ``len'' bytes from the source message block to the destination by
 * reading the source bytes and writing them to the recipient.
 *
 * @returns amount of bytes written, which may be lower than the requested
 * amount if the source buffer was shorter or there is not enough room in
 * the destination.
 */
int
pmsg_copy(pmsg_t *dest, pmsg_t *src, int len)
{
	int copied, available;

	pmsg_check(dest);
	pmsg_check(src);
	g_assert_log(len >= 0, "%s(): len=%d", G_STRFUNC, len);
	g_assert(pmsg_is_writable(dest));	/* Not shared, or would corrupt data */

	copied = src->m_wptr - src->m_rptr;	/* Available data in source */
	copied = MIN(copied, len);
	available = pmsg_available(dest);	/* Room in destination buffer */
	copied = MIN(copied, available);

	if (copied > 0) {
		dest->m_wptr = mempcpy(dest->m_wptr, src->m_rptr, copied);
		src->m_rptr += copied;
	}

	return copied;
}

/**
 * Shift back unread data to the beginning of the buffer.
 */
void
pmsg_compact(pmsg_t *mb)
{
	int shifting;

	pmsg_check(mb);
	g_assert(pmsg_is_writable(mb));		/* Not shared, or would corrupt data */
	g_assert(mb->m_rptr <= mb->m_wptr);

	shifting = mb->m_rptr - mb->m_data->d_arena;
	g_assert(shifting >= 0);

	if (shifting != 0) {
		memmove(mb->m_data->d_arena, mb->m_rptr, pmsg_size(mb));
		mb->m_rptr -= shifting;
		mb->m_wptr -= shifting;
	}
}

/**
 * Shift back unread data to the beginning of the buffer if that can make
 * at least 1/nth of the total arena size available for writing.
 */
void
pmsg_fractional_compact(pmsg_t *mb, int n)
{
	int shifting;

	g_assert(n > 0);
	pmsg_check(mb);
	g_assert(pmsg_is_writable(mb));		/* Not shared, or would corrupt data */
	g_assert(mb->m_rptr <= mb->m_wptr);

	shifting = mb->m_rptr - mb->m_data->d_arena;
	g_assert(shifting >= 0);

	if (shifting != 0) {
		unsigned available = pmsg_available(mb) + shifting;
		if (available >= pmsg_phys_len(mb) / n) {
			memmove(mb->m_data->d_arena, mb->m_rptr, pmsg_size(mb));
			mb->m_rptr -= shifting;
			mb->m_wptr -= shifting;
		}
	}
}

/**
 * Split a buffer at given offset: the data before that offset are left in
 * the original buffer whilst the data starting at the offset (included)
 * are moved to a new buffer.  The original buffer no longer holds the data
 * starting at the offset.
 *
 * @return new message block containing the data starting at the offset.
 */
pmsg_t *
pmsg_split(pmsg_t *mb, int offset)
{
	int slen;			/* Split length */
	const char *start;

	g_assert(offset >= 0);
	g_assert(offset < pmsg_size(mb));
	pmsg_check(mb);

	start = mb->m_rptr + offset;
	slen = mb->m_wptr - start;

	g_assert(slen > 0);
	mb->m_wptr -= slen;							/* Logically removed */

	return pmsg_new(mb->m_prio, start, slen);	/* Copies data */
}

/**
 * Allocate a new data block of given size.
 * The block header is at the start of the allocated block.
 */
pdata_t *
pdata_new(int len)
{
	pdata_t *db;
	char *arena;

	g_assert(len > 0);

	arena = walloc(len + EMBEDDED_OFFSET);
	db = pdata_allocb(arena, len + EMBEDDED_OFFSET, NULL, 0);

	g_assert((size_t) len == pdata_len(db));
	g_assert(db->d_arena == db->d_embedded);

	return db;
}

/**
 * Create an embedded data buffer out of existing arena.
 *
 * The optional `freecb' structure supplies the free routine callback to be
 * used to free the arena, with freearg as additional argument.
 * If no free routine is specified (i.e. NULL given as `freecb'), then the
 * arena will be freed with wfree(buf, len) when the data buffer is reclaimed.
 */
pdata_t *
pdata_allocb(void *buf, int len, pdata_free_t freecb, void *freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(UNSIGNED(len) >= EMBEDDED_OFFSET);
	g_assert(implies(freecb, valid_ptr(freecb)));

	db = buf;

	db->magic = PDATA_MAGIC;
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
 * used to free the arena, with freearg as additional argument.  If the free
 * routine is NULL, then the external arena will be freed with g_free() when
 * the data buffer is reclaimed.
 */
pdata_t *
pdata_allocb_ext(void *buf, int len, pdata_free_t freecb, void *freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(implies(freecb, valid_ptr(freecb)));

	WALLOC(db);
	db->magic = PDATA_MAGIC;
	db->d_arena = buf;
	db->d_end = (char *) buf + len;
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
pdata_free_nop(void *unused_p, void *unused_arg)
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
	bool is_embedded;

	pdata_check(db);
	g_assert(0 == db->d_refcnt);

	is_embedded = (db->d_arena == db->d_embedded);

	/*
	 * If user supplied a free routine for the buffer, invoke it.
	 */

	if (db->d_free) {
		void *p = is_embedded ? (void *) db : (void *) db->d_arena;
		(*db->d_free)(p, db->d_arg);
		if (!is_embedded) {
			db->magic = 0;
			WFREE(db);
		}
	} else {
		size_t len = pdata_len(db);	/* Before resetting the magic number */
		db->magic = 0;
		if (!is_embedded) {
			wfree(db->d_arena, len);
			WFREE(db);
		} else {
			wfree(db, len + EMBEDDED_OFFSET);
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
 * It should be freed via hfree().
 *
 * NOTE: The iovec will hold no more than MAX_IOV_COUNT items. That means
 *       the iovec might not cover the whole buffered data. This limit
 *		 is applied because writev() could fail with EINVAL otherwise
 *		 which would simply add more unnecessary complexity.
 */
iovec_t *
pmsg_slist_to_iovec(slist_t *slist, int *iovcnt_ptr, size_t *size_ptr)
{
	iovec_t *iov;
	size_t held = 0;
	int n;

	g_assert(slist);

	n = slist_length(slist);

	if (n > 0) {
		slist_iter_t *iter;
		int i;

		n = MIN(n, MAX_IOV_COUNT);
		HALLOC_ARRAY(iov, n);

		iter = slist_iter_before_head(slist);
		for (i = 0; i < n; i++) {
			pmsg_t *mb;
			size_t size;

			mb = slist_iter_next(iter);
			pmsg_check(mb);

			size = pmsg_size(mb);
			g_assert(size > 0);
			held += size;

			iovec_set(&iov[i], deconstify_pointer(pmsg_start(mb)), size);
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

	iter = slist_iter_removable_on_head(slist);
	while (n_bytes > 0) {
		pmsg_t *mb;
		size_t size;

		g_assert(slist_iter_has_item(iter));
		mb = slist_iter_current(iter);
		pmsg_check(mb);

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

#define PMSG_SLIST_GROW_MIN	1024	/**< Minimum to allocate on new blocks */

/**
 * Appends `n_bytes' to the pmsg_t buffer. If the last pmsg_t is writable
 * it is filled with as much data as space is still available. Otherwise
 * or if this space is not sufficient another pmsg_t is created and
 * appendded to the list.
 */
void
pmsg_slist_append(slist_t *slist, const void *data, size_t n_bytes)
{
	pmsg_t *mb;

	g_assert(slist);
	g_assert_log(size_is_non_negative(n_bytes),
		"%s(): n_bytes=%zd", G_STRFUNC, n_bytes);

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
		mb = pmsg_new(PMSG_P_DATA, NULL, MAX(n_bytes, PMSG_SLIST_GROW_MIN));
		pmsg_write(mb, data, n_bytes);
		slist_append(slist, mb);
	}
}

/**
 * Returns the size of the data held in the buffer list.
 */
size_t
pmsg_slist_size(const slist_t *slist)
{
	slist_iter_t *iter;
	size_t size = 0;

	g_assert(slist != NULL);

	iter = slist_iter_before_head(slist);
	while (slist_iter_has_next(iter)) {
		const pmsg_t *mb;

		mb = slist_iter_next(iter);
		pmsg_check(mb);

		size += pmsg_size(mb);
	}
	slist_iter_free(&iter);

	return size;
}

/**
 * Read data from the pmsg list into supplied buffer.  Copied data is
 * removed from the list.
 *
 * @param slist		the pmsg list
 * @param buf		start of buffer where data must be copied
 * @param len		length of buffer
 *
 * @return amount of copied bytes.
 */
size_t
pmsg_slist_read(slist_t *slist, void *buf, size_t len)
{
	slist_iter_t *iter;
	size_t remain = len;
	void *p;

	g_assert(slist != NULL);
	g_assert_log(size_is_non_negative(len), "%s(): len=%zd", G_STRFUNC, len);

	iter = slist_iter_removable_on_head(slist);
	p = buf;

	while (remain != 0 && slist_iter_has_item(iter)) {
		pmsg_t *mb = slist_iter_current(iter);
		int n;

		n = pmsg_read(mb, p, remain);
		remain -= n;
		p = ptr_add_offset(p, n);
		if (0 == pmsg_size(mb)) {			/* Fully copied message */
			pmsg_free(mb);
			slist_iter_remove(iter);		/* Warning: moves to next */
		} else {
			break;		/* No need to continue on partial copy */
		}
	}
	slist_iter_free(&iter);

	return len - remain;
}

/**
 * Free all items from the pmsg list, keeping the list container.
 */
void
pmsg_slist_discard_all(slist_t *slist)
{
	pmsg_t *mb;

	while ((mb = slist_shift(slist)) != NULL) {
		pmsg_free(mb);
	}
}

/**
 * Free the pmsg list, including the list container, nullifying its pointer.
 */
void
pmsg_slist_free_all(slist_t **slist_ptr)
{
	slist_free_all(slist_ptr, cast_to_free_fn(pmsg_free));
}

/**
 * Write an IPv4 or IPv6 address.
 */
void
pmsg_write_ipv4_or_ipv6_addr(pmsg_t *mb, host_addr_t addr)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 17);

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		pmsg_write_u8(mb, 4);
		pmsg_write_be32(mb, host_addr_ipv4(addr));
		break;
	case NET_TYPE_IPV6:
		pmsg_write_u8(mb, 16);
		pmsg_write(mb, host_addr_ipv6(&addr), 16);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_error("unexpected address in pmsg_write_ipv4_or_ipv6_addr(): %s",
			host_addr_to_string(addr));
	}
}

/**
 * Write an unsigned 64-bit quantity using variable length encoding (little
 * endian). Each serialized byte contains 7 bits, the highest bit is set when
 * this is the last byte of the encoded value.
 */
void
pmsg_write_ule64(pmsg_t *mb, uint64 v)
{
	uint64 value = v;

	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 10);	/* Will need 10 bytes at most */

	do {
		uint8 byt = (uint8) (value & 0x7f);		/* Lowest 7 bits */
		value >>= 7;
		if (0 == value) {
			byt |= 0x80;						/* Last byte emitted */
		}
		pmsg_write_u8(mb, byt);
	} while (value != 0);
}

/**
 * Write NUL-terminated string, up to `n' characters or the first seen NUL
 * in the buffer, whichever comes first.
 *
 * The string is written as: <ule64(length)><bytes>, no trailing NUL.
 */
void
pmsg_write_fixed_string(pmsg_t *mb, const char *str, size_t n)
{
	size_t len;

	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(UNSIGNED(pmsg_available(mb)) >= n + 10);	/* Need ule64 length */
	g_assert_log(size_is_non_negative(n), "%s(): n=%zd", G_STRFUNC, n);

	len = strlen(str);
	len = MIN(n, len);
	pmsg_write_ule64(mb, (uint64) len);

	if (len != 0) {
		pmsg_write(mb, str, len);
	}
}

/**
 * Write NUL-terminated string.
 *
 * If (size_t) -1 is given as length, then it is computed via strlen(), in
 * which case the string buffer must be NUL-terminated.  Otherwise, the value
 * is taken to be the pre-computed string length.
 *
 * The string is written as: <ule64(length)><bytes>, no trailing NUL.
 */
void
pmsg_write_string(pmsg_t *mb, const char *str, size_t length)
{
	size_t len;

	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert_log(size_is_non_negative(length) || (size_t) -1 == length,
		"%s(): length=%zd", G_STRFUNC, length);

	len = (size_t) -1 == length ? strlen(str) : length;

	g_assert(UNSIGNED(pmsg_available(mb)) >= len + 10);	/* Need ule64 length */

	pmsg_write_ule64(mb, (uint64) len);
	if (len != 0) {
		pmsg_write(mb, str, len);
	}
}

/* vi: set ts=4 sw=4 cindent: */
