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

typedef void (*pdata_free_t)(void *p, void *arg);

enum pdata_magic { PDATA_MAGIC = 0x0ad505b9 };

typedef struct pdata {
	enum pdata_magic magic;
	pdata_free_t d_free;		/**< Free routine */
	void *d_arg;				/**< Argument to free routine */
	int d_refcnt;				/**< Reference count */
	char *d_arena;				/**< First byte in buffer */
	char *d_end;				/**< First byte after buffer */
	char d_embedded[1];			/**< Start of embedded arena */
} pdata_t;

static inline void
pdata_check(const pdata_t * const pd)
{
	g_assert(pd != NULL);
	g_assert(PDATA_MAGIC == pd->magic);
}

static inline char *
pdata_start(const pdata_t *pd)
{
	pdata_check(pd);
	return pd->d_arena;
}

static inline size_t
pdata_len(const pdata_t *pd)
{
	pdata_check(pd);
	return ptr_diff(pd->d_end, pd->d_arena);
}

static inline void
pdata_addref(pdata_t *pd)
{
	pdata_check(pd);
	pd->d_refcnt++;
}

/*
 * A message block
 */

typedef struct pmsg pmsg_t;

typedef bool (*pmsg_check_t)(const pmsg_t *mb, const void *arg);
typedef bool (*pmsg_hook_t)(const pmsg_t *mb);

enum pmsg_magic {
	PMSG_MAGIC		= 0x2fa50be3U,
	PMSG_EXT_MAGIC	= 0x464cc376U
};

struct pmsg {
	enum pmsg_magic	magic;
	const char *m_rptr;			/**< First unread byte in buffer */
	char *m_wptr;				/**< First unwritten byte in buffer */
	pdata_t *m_data;			/**< Data buffer */
	uint8 m_flags;				/**< Message flags */
	uint8 m_prio;				/**< Message priority (0 = normal) */
	uint16 m_refcnt;			/**< Refs to this message block */
	union {
		pmsg_check_t m_check;	/**< Optional check before sending */
		pmsg_hook_t m_hook;		/**< Optional check before transmitting */
	} m_u;
};

typedef void (*pmsg_free_t)(pmsg_t *mb, void *arg);

/*
 * Message priorities (16-bit).
 */

#define PMSG_P_DATA		0			/**< Regular data, lowest priority */
#define PMSG_P_CONTROL	1			/**< Control message */
#define PMSG_P_URGENT	2			/**< Urgent message */
#define PMSG_P_HIGHEST	3			/**< Highest priority */

#define PMSG_P_COUNT	4			/**< Amount of priorities defined */

/*
 * Message flags.
 */

#define PMSG_PF_EXT		(1U << 7)	/**< Message block uses extended form */
#define PMSG_PF_SENT	(1U << 6)	/**< Message was successfully sent */
#define PMSG_PF_ACKME	(1U << 5)	/**< Request remote acknowledgment */
#define PMSG_PF_COMP	(1U << 4)	/**< Compression already attempted / done */
#define PMSG_PF_HOOK	(1U << 3)	/**< Use ``m_check'' as standalone hook */

static inline void
pmsg_check_consistency(const pmsg_t * const mb)
{
	g_assert(mb != NULL);
	g_assert((PMSG_MAGIC == mb->magic) ^ (PMSG_EXT_MAGIC == mb->magic));
	g_assert((PMSG_MAGIC == mb->magic) ^ (0 != (PMSG_PF_EXT & mb->m_flags)));
}

static inline char *
pmsg_start(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	pdata_check(mb->m_data);

	return mb->m_data->d_arena;
}

static inline size_t
pmsg_phys_len(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return pdata_len(mb->m_data);
}

static inline bool
pmsg_is_writable(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	pdata_check(mb->m_data);
	return 1 == mb->m_data->d_refcnt;
}

static inline unsigned
pmsg_prio(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return mb->m_prio;
}

static inline unsigned
pmsg_refcnt(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return mb->m_refcnt;
}

static inline bool
pmsg_is_unread(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	pdata_check(mb->m_data);
	return mb->m_rptr == mb->m_data->d_arena;
}

static inline const char *
pmsg_read_base(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return mb->m_rptr;
}

/**
 * Pre-send checks.
 */
static inline bool
pmsg_check(const pmsg_t *mb, const void *arg)
{
	pmsg_check_consistency(mb);
	return (NULL != mb->m_u.m_check && !(mb->m_flags & PMSG_PF_HOOK)) ?
		mb->m_u.m_check(mb, arg) : TRUE;
}

/**
 * Pre-transmit hook.
 */
static inline bool
pmsg_hook_check(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return (NULL != mb->m_u.m_hook && (mb->m_flags & PMSG_PF_HOOK)) ?
		mb->m_u.m_hook(mb) : TRUE;
}

/**
 * Available room for pmsg_write() calls
 */
static inline size_t
pmsg_available(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	pdata_check(mb->m_data);
	return ptr_diff(mb->m_data->d_end, mb->m_wptr);
}

static inline bool
pmsg_is_extended(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return 0 != (mb->m_flags & PMSG_PF_EXT);
}

static inline bool
pmsg_was_sent(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return 0 != (mb->m_flags & PMSG_PF_SENT);
}


static inline bool
pmsg_is_reliable(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return 0 != (mb->m_flags & PMSG_PF_ACKME);
}

static inline bool
pmsg_is_compressed(const pmsg_t *mb)
{
	pmsg_check_consistency(mb);
	return 0 != (mb->m_flags & PMSG_PF_COMP);
}

/**
 * TX layer marks message as being sent when it was sent over the network.
 */
static inline void
pmsg_mark_sent(pmsg_t *mb)
{
	mb->m_flags |= PMSG_PF_SENT;
}

/**
 * Clear the "sent" marker on message.
 */
static inline void
pmsg_clear_sent(pmsg_t *mb)
{
	mb->m_flags &= ~PMSG_PF_SENT;
}

/**
 * On unreliable medium (e.g. UDP), flag message as requiring a reliable
 * transmission, if possible.  The message will be marked as "sent" only
 * if it was acknowledged.
 */
static inline void
pmsg_mark_reliable(pmsg_t *mb)
{
	mb->m_flags |= PMSG_PF_ACKME;
}

/**
 * Clear the reliable marker.
 */
static inline void
pmsg_clear_reliable(pmsg_t *mb)
{
	mb->m_flags &= ~PMSG_PF_ACKME;
}

/**
 * Mark message as "compressed", whether or not it actually is.
 *
 * This signals the TX layers that the data has either already been compressed
 * or that compression was already attempted and did not yield any significant
 * gain.  Hence it would be a waste of time to attempt a compression again.
 */
static inline void
pmsg_mark_compressed(pmsg_t *mb)
{
	mb->m_flags |= PMSG_PF_COMP;
}

/*
 * Public interface
 */

void pmsg_init(void);
void pmsg_close(void);

pmsg_t *pmsg_new(int prio, const void *buf, int len);
pmsg_t * pmsg_new_extend(
	int prio, const void *buf, int len,
	pmsg_free_t free_cb, void *arg);
pmsg_t *pmsg_alloc(int prio, pdata_t *db, int roff, int woff);
pmsg_t *pmsg_ref(pmsg_t *mb);
pmsg_t *pmsg_clone(pmsg_t *mb);
pmsg_t *pmsg_clone_extend(pmsg_t *mb, pmsg_free_t free_cb, void *arg);
pmsg_free_t pmsg_replace_ext(
	pmsg_t *mb, pmsg_free_t nfree, void *narg, void **oarg);
void *pmsg_get_metadata(const pmsg_t *mb);
void pmsg_set_check(pmsg_t *mb, pmsg_check_t check);
void pmsg_set_hook(pmsg_t *mb, pmsg_hook_t hook);
void pmsg_free(pmsg_t *mb);
void pmsg_free_null(pmsg_t **mb_ptr);
int pmsg_write(pmsg_t *mb, const void *data, int len);
int pmsg_writable_length(const pmsg_t *mb);
int pmsg_read(pmsg_t *mb, void *data, int len);
int pmsg_discard(pmsg_t *mb, int len);
int pmsg_discard_trailing(pmsg_t *mb, int len);
int pmsg_copy(pmsg_t *dest, pmsg_t *src, int len);
pmsg_t *pmsg_split(pmsg_t *mb, int offset);
void pmsg_compact(pmsg_t *mb);
void pmsg_fractional_compact(pmsg_t *mb, int n);
void pmsg_reset(pmsg_t *mb);

pdata_t *pdata_new(int len);
pdata_t *pdata_allocb(void *buf, int len,
	pdata_free_t freecb, void *freearg);
pdata_t *pdata_allocb_ext(void *buf, int len,
	pdata_free_t freecb, void *freearg);
void pdata_free_nop(void *p, void *arg);
void pdata_unref(pdata_t *db);

iovec_t *pmsg_slist_to_iovec(slist_t *slist,
				int *iovcnt_ptr, size_t *size_ptr);
void pmsg_slist_discard(slist_t *slist, size_t n_bytes);
void pmsg_slist_append(slist_t *slist, const void *data, size_t n_bytes);
size_t pmsg_slist_size(const slist_t *slist);
size_t pmsg_slist_read(slist_t *slist, void *buf, size_t len);
void pmsg_slist_discard_all(slist_t *slist);
void pmsg_slist_free_all(slist_t **slist_ptr);

static inline void
pmsg_slist_free(slist_t **slist_ptr)
{
	slist_free_all(slist_ptr, (free_fn_t) pmsg_free);
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
pmsg_write_u8(pmsg_t *mb, uint8 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 1);

	*(uint8 *) mb->m_wptr++ = val;
}

/**
 * Write a 16-bit value in big-endian format.
 */
static inline void
pmsg_write_be16(pmsg_t *mb, uint16 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 2);

	mb->m_wptr = poke_be16(mb->m_wptr, val);
}

/**
 * Write a 16-bit value in little-endian format.
 */
static inline void
pmsg_write_le16(pmsg_t *mb, uint16 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 2);

	mb->m_wptr = poke_le16(mb->m_wptr, val);
}

/**
 * Write a 32-bit value in big-endian format.
 */
static inline void
pmsg_write_be32(pmsg_t *mb, uint32 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_be32(mb->m_wptr, val);
}

/**
 * Write a 32-bit value in little-endian format.
 */
static inline void
pmsg_write_le32(pmsg_t *mb, uint32 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 4);

	mb->m_wptr = poke_le32(mb->m_wptr, val);
}

/**
 * Write a 64-bit value in big-endian format.
 */
static inline void
pmsg_write_be64(pmsg_t *mb, uint64 val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 8);

	mb->m_wptr = poke_be64(mb->m_wptr, val);
}

/**
 * Write a 64-bit value in little-endian format.
 */
static inline void
pmsg_write_le64(pmsg_t *mb, uint64 val)
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

	mb->m_wptr = poke_be32(mb->m_wptr, (uint32) val);
}

/**
 * Write boolean.
 */
static inline void
pmsg_write_boolean(pmsg_t *mb, bool val)
{
	g_assert(pmsg_is_writable(mb));	/* Not shared, or would corrupt data */
	g_assert(pmsg_available(mb) >= 1);

	*(uint8 *) mb->m_wptr++ = booleanize(val);
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

void pmsg_write_ule64(pmsg_t *mb, uint64 val);
void pmsg_write_fixed_string(pmsg_t *mb, const char *str, size_t n);
void pmsg_write_ipv4_or_ipv6_addr(pmsg_t *mb, host_addr_t addr);
void pmsg_write_string(pmsg_t *mb, const char *str, size_t length);

#endif	/* _pmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
