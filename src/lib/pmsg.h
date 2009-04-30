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

#ifndef _pmsg_h_
#define _pmsg_h_

#include "common.h"

#include "endian.h"
#include "host_addr.h"
#include "slist.h"

/**
 * A data buffer, can be shared by several message blocks.
 *
 * There are two incarnations of a message data block: one where the buffer's
 * arena is contiguous to the header and starts at its end (the header
 * structure has been stolen at the head of the physical data block), and one
 * where the buffer's arena was independently allocated.
 *
 * The free routine, when present, only frees the data part of the data buffer.
 * Naturally, in its embedded form, this is the whole buffer.  The first
 * argument to the free routine is the start of the data to free, i.e. it will
 * be the pdata structure in the embedded case, or the arena base in the
 * detached form.
 *
 * The d_embedded[] field is our reliable discriminent: since it is part of
 * the structure, it is necessarily within that structure.  Therefore, when
 * d_arena points to it, we know that the data buffer is of the "embedded"
 * kind.
 */

typedef void (*pdata_free_t)(gpointer p, gpointer arg);

typedef struct pdata {
	pdata_free_t d_free;		/**< Free routine */
	gpointer d_arg;				/**< Argument to free routine */
	int d_refcnt;				/**< Reference count */
	char *d_arena;				/**< First byte in buffer */
	char *d_end;				/**< First byte after buffer */
	char d_embedded[1];			/**< Start of embedded arena */
} pdata_t;

#define pdata_start(x)		((x)->d_arena)
#define pdata_len(x)		((size_t) ((x)->d_end - (x)->d_arena))
#define pdata_addref(x)		do { (x)->d_refcnt++; } while (0)

/*
 * A message block
 */

struct mqueue;

typedef struct pmsg pmsg_t;
typedef gboolean (*pmsg_check_t)(pmsg_t *mb, const struct mqueue *q);

enum pmsg_magic {
	PMSG_MAGIC		= 0x2fa50be3U,
	PMSG_EXT_MAGIC	= 0x464cc376U
};

struct pmsg {
	enum pmsg_magic	magic;
	const char *m_rptr;			/**< First unread byte in buffer */
	char *m_wptr;				/**< First unwritten byte in buffer */
	pdata_t *m_data;			/**< Data buffer */
	guint m_prio;				/**< Message priority (0 = normal) */
	pmsg_check_t m_check;		/**< Optional check before sending */
};

typedef void (*pmsg_free_t)(pmsg_t *mb, gpointer arg);

#define PMSG_PRIO_MASK		0x00ffffff	/**< Only lower bits are relevant */

#define pmsg_start(x)		((x)->m_data->d_arena)
#define pmsg_phys_len(x)	pdata_len((x)->m_data)
#define pmsg_is_writable(x)	((x)->m_data->d_refcnt == 1)
#define pmsg_prio(x)		((x)->m_prio & PMSG_PRIO_MASK)

#define pmsg_is_unread(x)	((x)->m_rptr == (x)->m_data->d_arena)
#define pmsg_read_base(x)	((x)->m_rptr)

#define pmsg_check(x,y)		((x)->m_check ? (x)->m_check((x), (y)) : TRUE)

/* Available room for pmsg_write() calls */
#define pmsg_available(x)	((x)->m_data->d_end - (x)->m_wptr)

/*
 * Message priorities.
 */

#define PMSG_P_DATA		0			/**< Regular data, lowest priority */
#define PMSG_P_CONTROL	1			/**< Control message */
#define PMSG_P_URGENT	2			/**< Urgent message */
#define PMSG_P_HIGHEST	3			/**< Highest priority */

/*
 * Flags defined in highest bits of `m_prio'.
 */

#define PMSG_PF_EXT		0x80000000	/**< Message block uses extended form */
#define PMSG_PF_SENT	0x40000000	/**< Message was successfully sent */

#define pmsg_is_extended(mb) ((mb)->m_prio & PMSG_PF_EXT)
#define pmsg_was_sent(mb) ((mb)->m_prio & PMSG_PF_SENT)
#define pmsg_mark_sent(mb) \
G_STMT_START { \
	(mb)->m_prio |= PMSG_PF_SENT; \
} G_STMT_END

/*
 * Public interface
 */

static inline void
pmsg_check_consistency(const pmsg_t * const mb)
{
	g_assert(mb);
	g_assert((PMSG_MAGIC == mb->magic) ^ (PMSG_EXT_MAGIC == mb->magic));
	g_assert((PMSG_MAGIC == mb->magic) ^ (0 != (PMSG_PF_EXT & mb->m_prio)));
}

void pmsg_init(void);
void pmsg_close(void);

pmsg_t *pmsg_new(int prio, gconstpointer buf, int len);
pmsg_t * pmsg_new_extend(
	int prio, gconstpointer buf, int len,
	pmsg_free_t free_cb, gpointer arg);
pmsg_t *pmsg_alloc(int prio, pdata_t *db, int roff, int woff);
pmsg_t *pmsg_clone(pmsg_t *mb);
pmsg_t *pmsg_clone_extend(pmsg_t *mb, pmsg_free_t free_cb, gpointer arg);
pmsg_free_t pmsg_replace_ext(
	pmsg_t *mb, pmsg_free_t nfree, gpointer narg, gpointer *oarg);
gpointer pmsg_get_metadata(pmsg_t *mb);
pmsg_check_t pmsg_set_check(pmsg_t *mb, pmsg_check_t check);
void pmsg_free(pmsg_t *mb);
void pmsg_free_null(pmsg_t **mb_ptr);
int pmsg_write(pmsg_t *mb, gconstpointer data, int len);
int pmsg_writable_length(const pmsg_t *mb);
int pmsg_read(pmsg_t *mb, gpointer data, int len);
int pmsg_discard(pmsg_t *mb, int len);
int pmsg_discard_trailing(pmsg_t *mb, int len);
void pmsg_reset(pmsg_t *mb);

pdata_t *pdata_new(int len);
pdata_t *pdata_allocb(void *buf, int len,
	pdata_free_t freecb, gpointer freearg);
pdata_t *pdata_allocb_ext(void *buf, int len,
	pdata_free_t freecb, gpointer freearg);
void pdata_free_nop(gpointer p, gpointer arg);
void pdata_unref(pdata_t *db);

struct iovec *pmsg_slist_to_iovec(slist_t *slist,
				int *iovcnt_ptr, size_t *size_ptr);
void pmsg_slist_discard(slist_t *slist, size_t n_bytes);
void pmsg_slist_append(slist_t *slist, const void *data, size_t n_bytes);

static inline void
pmsg_slist_free(slist_t **slist_ptr)
{
	slist_free_all(slist_ptr, (slist_destroy_cb) pmsg_free);
}

/**
 * Compute message's size (what remains to be read).
 */
static inline int
pmsg_size(const pmsg_t *mb)
{
	/*
	 * Not a macro because of foreseen addition of an m_cont field to link
 	 * additional message blocks (auto-extension of messages on pmsg_write).
	 */

	return mb->m_wptr - mb->m_rptr;
}

/**
 * Compute message's written size, regardless of where the read pointer is.
 */
static inline int
pmsg_written_size(const pmsg_t *mb)
{
	/*
	 * Not a macro because of foreseen addition of an m_cont field to link
 	 * additional message blocks (auto-extension of messages on pmsg_write).
	 */

	return mb->m_wptr - mb->m_data->d_arena;
}

/***
 *** Convenience routines to contruct messages directly in the arena
 *** block to avoid extra memory copies.
 ***
 *** The only drawback currently is that the arena must be properly sized
 *** in advance as message blocks are not auto-extensible (for now).
 ***
 *** In all these routines, the message must be the only reference to the
 *** underlying data, i.e. it must still be in the process of being constructed
 *** before being passed to a queue (at which time it should no longer be
 *** referenced).
 ***/

typedef size_t pmsg_offset_t;

/**
 * Current write pointer offset.
 */
static inline pmsg_offset_t
pmsg_write_offset(pmsg_t *mb)
{
	/*
	 * Same as pmsg_written_size() but returns an pmsg_offset_t for consistency
	 * with pmsg_seek().
	 */

	return mb->m_wptr - mb->m_data->d_arena;
}

/**
 * Move the write pointer to the desired offset within the message.
 * Can be used to skip the header part of the built message.
 *
 * @attention
 * WARNING: when moving back and forth, one must remember the maximum offset
 * and seek back to it as there is no bookeeping of that information within
 * the message.  It is the current write pointer that determines the value
 * of pmsg_size()...  Use pmsg_write_offset() to know the current offset.
 *
 * When moving forward only (to skip already built parts), there is no need
 * to worry as the end of the written data will always be accurate.
 */
static inline void
pmsg_seek(pmsg_t *mb, pmsg_offset_t offset)
{
	g_assert(offset <= pmsg_phys_len(mb));
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */

	mb->m_wptr = mb->m_data->d_arena + offset;
}

/**
 * Write a single byte.
 */
static inline void
pmsg_write_u8(pmsg_t *mb, guint8 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 1);

	*(guint8 *) mb->m_wptr++ = val;
}

/**
 * Write a 16-bit value in big-endian format.
 */
static inline void
pmsg_write_be16(pmsg_t *mb, guint16 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 2);

	mb->m_wptr = poke_be16(mb->m_wptr, val);
}

/**
 * Write a 16-bit value in little-endian format.
 */
static inline void
pmsg_write_le16(pmsg_t *mb, guint16 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 2);

	mb->m_wptr = poke_le16(mb->m_wptr, val);
}

/**
 * Write a 32-bit value in big-endian format.
 */
static inline void
pmsg_write_be32(pmsg_t *mb, guint32 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_be32(mb->m_wptr, val);
}

/**
 * Write a 32-bit value in little-endian format.
 */
static inline void
pmsg_write_le32(pmsg_t *mb, guint32 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_le32(mb->m_wptr, val);
}

/**
 * Write a 64-bit value in big-endian format.
 */
static inline void
pmsg_write_be64(pmsg_t *mb, guint64 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 8);

	mb->m_wptr = poke_be64(mb->m_wptr, val);
}

/**
 * Write a 64-bit value in little-endian format.
 */
static inline void
pmsg_write_le64(pmsg_t *mb, guint64 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 8);

	mb->m_wptr = poke_le64(mb->m_wptr, val);
}

/**
 * Write time_t.
 */
static inline void
pmsg_write_time(pmsg_t *mb, time_t val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_be32(mb->m_wptr, (guint32) val);
}

/**
 * Write gboolean.
 */
static inline void
pmsg_write_boolean(pmsg_t *mb, gboolean val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 1);

	*(guint8 *) mb->m_wptr++ = val ? 1 : 0;
}

/**
 * Write float in big-endian.
 */
static inline void
pmsg_write_float_be(pmsg_t *mb, float val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_float_be32(mb->m_wptr, val);
}

void pmsg_write_ipv4_or_ipv6_addr(pmsg_t *mb, host_addr_t addr);

#endif	/* _pmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
