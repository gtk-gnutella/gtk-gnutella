/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * PDU Messages.
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

#include <string.h>		/* For memcpy() */

#include "pmsg.h"
#include "common.h"

#define implies(a,b)	(!(a) || (b))
#define valid_ptr(a)	(((gulong) (a)) > 100L)

#define EMBEDDED_OFFSET	G_STRUCT_OFFSET(pdata_t, d_embedded)

static zone_t *mb_zone = NULL;

/*
 * pmsg_init
 *
 * Allocate internal variables.
 */
void pmsg_init(void)
{
	mb_zone = zget(sizeof(pmsg_t), 1024);
}

/*
 * pmsg_close
 *
 * Free internal variables
 */
void pmsg_close(void)
{
	zdestroy(mb_zone);
}

/*
 * pmsg_size
 *
 * Compute message's size.
 */
int pmsg_size(pmsg_t *mb)
{
	int msize = 0;

	g_assert(mb);

	/* In prevision of message block chaining */
	do {
		msize += mb->m_wptr - mb->m_rptr;
	} while (0);

	return msize;
}

/*
 * pmsg_new
 *
 * Create new message from user provided data, which are copied into the
 * allocated data block.  If no user buffer is provided, an empty message
 * is created and the length is used to size the data block.
 *
 * Returns a message made of one message block referencing one new data block.
 */
pmsg_t *pmsg_new(gint prio, void *buf, gint len)
{
	pmsg_t *mb;
	pdata_t *db;

	g_assert(len > 0);
	g_assert(implies(buf, valid_ptr(buf)));

	mb = (pmsg_t *) zalloc(mb_zone);
	db = pdata_new(len);

	mb->m_data = db;
	mb->m_prio = prio;
	db->d_refcnt++;

	if (buf) {
		mb->m_rptr = db->d_arena;
		mb->m_wptr = db->d_arena + len;
		memcpy(db->d_arena, buf, len);
	} else
		mb->m_rptr = mb->m_wptr = db->d_arena;

	g_assert(implies(buf, len == pmsg_size(mb)));

	return mb;
}

/*
 * pmsg_alloc
 *
 * Allocate new message using existing data block `db'.
 * The `roff' and `woff' are used to delimit the start and the end (first
 * unwritten byte) of the message within the data buffer.
 *
 * Return new message.
 */
pmsg_t *pmsg_alloc(gint prio, pdata_t *db, gint roff, gint woff)
{
	pmsg_t *mb;

	g_assert(valid_ptr(db));
	g_assert(roff >= 0 && roff <= pdata_len(db));
	g_assert(woff >= 0 && woff <= pdata_len(db));
	g_assert(woff >= roff);

	mb = (pmsg_t *) zalloc(mb_zone);

	mb->m_data = db;
	mb->m_prio = prio;
	db->d_refcnt++;

	mb->m_rptr = db->d_arena + roff;
	mb->m_wptr = db->d_arena + woff;

	return mb;
}

/*
 * pmsg_clone
 *
 * Shallow cloning of message, result is referencing the same data.
 */
pmsg_t *pmsg_clone(pmsg_t *mb)
{
	pmsg_t *nmb = (pmsg_t *) zalloc(mb_zone);
	
	*nmb = *mb;			/* Struct copy */
	pdata_addref(nmb->m_data);

	return nmb;
}

/*
 * pmsg_free
 *
 * Free all message blocks, and decrease ref count on all data buffers.
 */
void pmsg_free(pmsg_t *mb)
{
	/* In provision for messsage chaining */
	do {
		g_assert(valid_ptr(mb));
		pdata_unref(mb->m_data);
		zfree(mb_zone, mb);
	} while (0);
}

/*
 * pmsg_write
 *
 * Write data at the end of the message.
 * The message must be the only reference to the underlying data.
 *
 * Returns amount of written data.
 */
gint pmsg_write(pmsg_t *mb, gpointer data, gint len)
{
	pdata_t *arena = mb->m_data;
	gint available = arena->d_end - mb->m_wptr;
	gint written = len >= available ? available : len;

	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	if (written == 0)
		return 0;

	memcpy(mb->m_wptr, data, written);
	mb->m_wptr += written;

	return written;
}

/*
 * pmsg_read
 *
 * Read data from the message, returning the amount of bytes transferred.
 */
gint pmsg_read(pmsg_t *mb, gpointer data, gint len)
{
	gint available = mb->m_wptr - mb->m_rptr;
	gint readable = len >= available ? available : len;

	g_assert(available >= 0);		/* Data cannot go beyond end of arena */

	if (readable == 0)
		return 0;

	memcpy(data, mb->m_rptr, readable);
	mb->m_rptr += readable;

	return readable;
}

/*
 * pdata_new
 *
 * Allocate a new data block of given size.
 * The block header is at the start of the allocated block.
 */
pdata_t *pdata_new(int len)
{
	pdata_t *db;
	gchar *arena;

	g_assert(len > 0);

	arena = g_malloc(len + EMBEDDED_OFFSET);

	db = pdata_allocb(arena, len + EMBEDDED_OFFSET, NULL, 0);

	g_assert(len == pdata_len(db));

	return db;
}

/*
 * pdata_allocb
 *
 * Create an embedded data buffer out of existing arena.
 *
 * The optional `freecb' structure supplies the free routine callback to be
 * used to free the arena, with freearg as additional argument.
 */
pdata_t *pdata_allocb(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(len >= EMBEDDED_OFFSET);
	g_assert(implies(freecb, valid_ptr(freecb)));

	db = (pdata_t *) buf;

	db->d_arena = db->d_embedded;
	db->d_end = db->d_arena + (len - EMBEDDED_OFFSET);
	db->d_refcnt = 0;
	db->d_free = freecb;
	db->d_arg = freearg;

	g_assert(len - EMBEDDED_OFFSET == pdata_len(db));

	return db;
}

/*
 * pdata_allocb_ext
 *
 * Create an external (arena not embedded) data buffer out of existing arena.
 *
 * The optional `freecb' structure supplies the free routine callback to be
 * used to free the arena, with freearg as additional argument.
 */
pdata_t *pdata_allocb_ext(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg)
{
	pdata_t *db;

	g_assert(valid_ptr(buf));
	g_assert(implies(freecb, valid_ptr(freecb)));

	db = g_malloc(sizeof(*db));

	db->d_arena = buf;
	db->d_end = (gchar *) buf + len;
	db->d_refcnt = 0;
	db->d_free = freecb;
	db->d_arg = freearg;

	g_assert(len == pdata_len(db));

	return db;
}

/*
 * pdata_free_nop
 *
 * This free routine can be used when there is nothing to be freed for
 * the buffer, probably because it was made out of a static buffer.
 */
void pdata_free_nop(gpointer p, gpointer arg)
{
}

/*
 * pdata_free
 *
 * Free data block when its reference count has reached 0.
 */
static void pdata_free(pdata_t *db)
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
			g_free(db);
	} else {
		if (!is_embedded)
			g_free(db->d_arena);
		g_free(db);
	}
}

/*
 * pdata_unref
 *
 * Decrease reference count on buffer, and free it when it reaches 0.
 */
void pdata_unref(pdata_t *db)
{
	g_assert(valid_ptr(db));
	g_assert(db->d_refcnt > 0);

	if (db->d_refcnt-- == 1)
		pdata_free(db);
}

/* vi: set ts=4: */
