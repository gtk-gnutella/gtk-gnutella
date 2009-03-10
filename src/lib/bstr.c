/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Binary memory stream parsing.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "bstr.h"
#include "casts.h"
#include "endian.h"
#include "glib-missing.h"
#include "host_addr.h"
#include "misc.h"
#include "walloc.h"
#include "override.h"			/* Must be the last header included */

#define BSTR_ERRLEN		160			/**< Default length for error string */

/**
 * A binary stream.
 */
struct bstr {
	const guchar *start;			/**< First byte in buffer */
	guchar *rptr;					/**< First unread byte in buffer */
	const guchar *end;				/**< First byte beyond buffer */
	guint32 flags;					/**< Configuration flags */
	gboolean ok;					/**< Whether everything is OK so far */
	GString *error;					/**< Last parsing error */
};

/*
 * Internal operating flags start at bit 16.
 */

#define BSTR_F_PRIVATE	0xffff0000	/**< Mask for private flags */
#define BSTR_F_EOS		(1 << 16)	/**< End of stream reached */
#define BSTR_F_PENDING	(1 << 17)	/**< Pending reset, stream invalid */

static gboolean error_eos(bstr_t *bs, ssize_t expected, const char *where);

/**
 * Reset the stream.
 */
static void
reset_stream(bstr_t *bs, gconstpointer arena, size_t len, guint32 flags)
{
	bs->ok = TRUE;
	bs->flags = flags;
	bs->rptr = deconstify_gpointer(arena);
	bs->start = bs->rptr;
	bs->end = bs->start + len;
	bs->error = NULL;
}

/**
 * Mark stream unusable.
 */
static void
mark_unusable(bstr_t *bs)
{
	bs->ok = FALSE;
	bs->flags |= BSTR_F_PENDING;
}

/**
 * Create a new memory stream to parse given arena
 *
 * @param arena		the base of the memory arena
 * @param len		total length of the arena to parse
 * @param flags		configuration flags
 *
 * @return a stream descriptor that must be freed with bstr_destroy(), or
 * which can be reused through bstr_close() and bstr_reset() at will.
 */
bstr_t *
bstr_open(gconstpointer arena, size_t len, guint32 flags)
{
	bstr_t *bs;

	g_assert(arena);
	g_assert(0 == (flags & BSTR_F_PRIVATE));

	bs = walloc(sizeof *bs);
	reset_stream(bs, arena, len, flags);

	if (len == 0)
		error_eos(bs, 0, "bstr_open");

	return bs;
}

/**
 * Reset an already used stream or something created through bstr_create()
 * to use it on another arena, with possibly different operating flags.
 *
 * @param arena		the base of the memory arena
 * @param len		total length of the arena to parse
 * @param flags		configuration flags
 */
void
bstr_reset(bstr_t *bs, gconstpointer arena, size_t len, guint32 flags)
{
	g_assert(arena);
	g_assert(0 == (flags & BSTR_F_PRIVATE));

	reset_stream(bs, arena, len, flags);

	if (len == 0)
		error_eos(bs, 0, "bstr_reset");
}

/**
 * Create the stream, but make it unusable until a bstr_reset() has
 * been done.
 *
 * @return a stream descriptor that must be freed with bstr_destroy(), or
 * which can be reused through bstr_close() and bstr_reset() at will.
 */
bstr_t *
bstr_create(void)
{
	bstr_t *bs;

	bs = walloc0(sizeof *bs);
	mark_unusable(bs);

	return bs;
}

/**
 * Close memory stream.
 * Stream can then be freed by bstr_destroy() or reused via bstr_reset().
 */
void
bstr_close(bstr_t *bs)
{
	if (bs->error) {
		g_string_free(bs->error, TRUE);
		bs->error = NULL;
	}

	mark_unusable(bs);
}

/**
 * Destroy memory stream.
 */
void
bstr_destroy(bstr_t *bs)
{
	if (bs->error)
		g_string_free(bs->error, TRUE);

	wfree(bs, sizeof *bs);
}

/**
 * Clear last error.
 */
void
bstr_clear_error(bstr_t *bs)
{
	if (bs->ok)
		return;

	/*
	 * Do not clear errors on a stream that is pending resetting.
	 */

	if (bs->flags & BSTR_F_PENDING)
		return;

	bs->ok = TRUE;

	if (bs->error)
		g_string_truncate(bs->error, 0);
}

/**
 * Check whether there was an error.
 */
gboolean
bstr_has_error(const bstr_t *bs)
{
	return !bs->ok;
}

/**
 * Report error string.
 */
const char *
bstr_error(const bstr_t *bs)
{
	if (bs->ok)
		return "OK";
	else if (bs->flags & BSTR_F_PENDING)
		return "stream waiting for a reset";
	else if (bs->flags & BSTR_F_ERROR)
		return bs->error->str;
	else if (bs->flags & BSTR_F_EOS)
		return "end of stream reached";
	else
		return "parsing error";
}

/**
 * Allocate error string if not already done.
 */
static void
alloc_error(bstr_t *bs)
{
	if (!bs->error)
		bs->error = g_string_sized_new(BSTR_ERRLEN);
}

/**
 * Record End of Stream condition.
 * @return FALSE
 */
static gboolean
error_eos(bstr_t *bs, ssize_t expected, const char *where)
{
	bs->flags |= BSTR_F_EOS;

	if (bs->flags & BSTR_F_ERROR) {
		alloc_error(bs);
		g_string_printf(bs->error,
			"%s: end of stream reached at offset %lu; expected %s more byte%s",
			where, (unsigned long) (bs->end - bs->start),
			expected ? off_t_to_string((off_t) expected) : "some",
			expected == 1 ? "" : "s");
	}

	return bs->ok = FALSE;
}

/**
 * Report invalid length condition.
 * @return FALSE
 */
static gboolean
invalid_len(bstr_t *bs, size_t len, const char *what, const char *where)
{
	if (bs->flags & BSTR_F_ERROR) {
		alloc_error(bs);
		g_string_printf(bs->error,
			"%s: invalid %s length %lu at offset %lu",
			where, what, (unsigned long ) len,
			(unsigned long) (bs->rptr - bs->start));
	}

	return bs->ok = FALSE;
}

/**
 * Report invalid length condition, bounded by a maximum value.
 * @return FALSE
 */
static gboolean
invalid_len_max(
	bstr_t *bs, size_t len, size_t max, const char *what, const char *where)
{
	if (bs->flags & BSTR_F_ERROR) {
		alloc_error(bs);
		g_string_printf(bs->error,
			"%s: invalid %s length %lu (max is %lu) at offset %lu",
			where, what, (unsigned long) len, (unsigned long) max,
			(unsigned long) (bs->rptr - bs->start));
	}

	return bs->ok = FALSE;
}

/**
 * Check that stream contains at least the expected amount of bytes.
 * Raise the "End Of Stream" error.
 */
static gboolean
expect(bstr_t *bs, ssize_t expected, const char *where)
{
	g_assert(bs);
	g_assert(expected > 0);

	if (!bs->ok)
		return FALSE;

	if (bs->end - bs->rptr >= expected)
		return TRUE;

	return error_eos(bs, expected, where);
}

/**
 * @return amount of unread data.
 */
size_t
bstr_unread_size(const bstr_t *bs)
{
	return bs->end - bs->rptr;
}

/**
 * @return current reading position.
 */
gpointer
bstr_read_base(const bstr_t *bs)
{
	return bs->rptr;
}

/**
 * Skip specified amount of bytes.
 *
 * @param bs	the binary stream
 * @param count	amount of data to skip over (can be 0 for a NOP)
 *
 * @return TRUE if OK.
 */
gboolean
bstr_skip(bstr_t *bs, size_t count)
{
	g_assert(size_is_non_negative(count));

	if (!count)
		return TRUE;

	if (!expect(bs, count, "bstr_skip"))
		return FALSE;

	bs->rptr += count;
	return TRUE;
}

/**
 * Read specified amount of bytes into buffer.
 *
 * @param bs	the binary stream
 * @param buf	where to write read data
 * @param count	amount of data to read
 * 
 * @return TRUE if OK.
 */
gboolean
bstr_read(bstr_t *bs, void *buf, size_t count)
{
	g_assert(size_is_positive(count));
	g_assert(buf);

	if (!expect(bs, count, "bstr_read"))
		return FALSE;

	memcpy(buf, bs->rptr, count);
	bs->rptr += count;
	return TRUE;
}

/**
 * Read a byte.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_u8(bstr_t *bs, guint8 *pv)
{
	g_assert(pv);

	if (!expect(bs, 1, "bstr_read_u8"))
		return FALSE;

	*pv = *(guint8 *) bs->rptr++;
	return TRUE;
}

/**
 * Read a boolean.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_boolean(bstr_t *bs, gboolean *pv)
{
	g_assert(pv);

	if (!expect(bs, 1, "bstr_read_boolean"))
		return FALSE;

	*pv = *(guint8 *) bs->rptr++ ? TRUE : FALSE;
	return TRUE;
}

/**
 * Read a little-endian 16-bit quantity.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_le16(bstr_t *bs, guint16 *pv)
{
	g_assert(pv);

	if (!expect(bs, 2, "bstr_read_le16"))
		return FALSE;

	*pv = peek_le16(bs->rptr);
	bs->rptr += 2;
	return TRUE;
}

/**
 * Read a big-endian 16-bit quantity.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_be16(bstr_t *bs, guint16 *pv)
{
	g_assert(pv);

	if (!expect(bs, 2, "bstr_read_be16"))
		return FALSE;

	*pv = peek_be16(bs->rptr);
	bs->rptr += 2;
	return TRUE;
}

/**
 * Read a little-endian 32-bit quantity.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_le32(bstr_t *bs, guint16 *pv)
{
	g_assert(pv);

	if (!expect(bs, 4, "bstr_read_le32"))
		return FALSE;

	*pv = peek_le32(bs->rptr);
	bs->rptr += 4;
	return TRUE;
}

/**
 * Read a big-endian 32-bit quantity.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_be32(bstr_t *bs, guint32 *pv)
{
	g_assert(pv);

	if (!expect(bs, 4, "bstr_read_be32"))
		return FALSE;

	*pv = peek_be32(bs->rptr);
	bs->rptr += 4;
	return TRUE;
}

/**
 * Read time.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_time(bstr_t *bs, time_t *pv)
{
	g_assert(pv);

	if (!expect(bs, 4, "bstr_read_time"))
		return FALSE;

	*pv = (time_t) peek_be32(bs->rptr);
	bs->rptr += 4;
	return TRUE;
}

/**
 * Read big-endian float.
 *
 * @param bs	the binary stream
 * @param pv	where to write the value
 *
 * @return TRUE if OK.
 */
gboolean
bstr_read_float_be(bstr_t *bs, float *pv)
{
	g_assert(pv);

	if (!expect(bs, 4, "bstr_read_float"))
		return FALSE;

	*pv = peek_float_be32(bs->rptr);
	bs->rptr += 4;

	return TRUE;
}

/**
 * Read ipv4 address.
 *
 * @param bs	the binary stream
 * @param ha	pointer to the host address structure to fill
 *
 * @return TRUE if OK
 */
gboolean
bstr_read_ipv4_addr(bstr_t *bs, host_addr_t *ha)
{
	static const char *where = "bstr_read_ipv4_addr";

	g_assert(ha);

	if (!expect(bs, 4, where))
		return FALSE;

	*ha = host_addr_peek_ipv4(bs->rptr);
	bs->rptr += 4;

	return TRUE;
}

/**
 * Read ipv6 address.
 *
 * @param bs	the binary stream
 * @param ha	pointer to the host address structure to fill
 *
 * @return TRUE if OK
 */
gboolean
bstr_read_ipv6_addr(bstr_t *bs, host_addr_t *ha)
{
	static const char *where = "bstr_read_ipv6_addr";

	g_assert(ha);

	if (!expect(bs, 16, where))
		return FALSE;

	*ha = host_addr_peek_ipv6(bs->rptr);
	bs->rptr += 16;

	return TRUE;
}

/**
 * Read a packed IP address in the following format:
 *
 * 1 byte for the address length: 4 for IPv4, 16 for IPv6
 * 4 or 16 bytes of the address (in big endian format)
 *
 * @param bs	the binary stream
 * @param ha	pointer to the host address structure to fill
 *
 * @return TRUE if OK
 */
gboolean
bstr_read_packed_ipv4_or_ipv6_addr(bstr_t *bs, host_addr_t *ha)
{
	static const char *where = "bstr_read_packed_ipv4_or_ipv6_addr";
	guint8 len;

	g_assert(ha);

	if (!expect(bs, 1, where))
		return FALSE;

	len = *(guint8 *) bs->rptr++;

	if (len != 4 && len != 16)
		return invalid_len(bs, len, "IP address", where);

	if (!expect(bs, len, where))
		return FALSE;

	switch (len) {
	case 4:  *ha = host_addr_peek_ipv4(bs->rptr); break;
	case 16: *ha = host_addr_peek_ipv6(bs->rptr); break;
	default:
		g_assert_not_reached();
	}

	bs->rptr += len;

	return TRUE;
}

/**
 * Read packed array of bytes of at most "max" bytes.
 *
 * The serialized format is:
 * 1 byte for the length of the following array (0 means empty array)
 * the bytes of the array, in increasing index order.
 *
 * @param bs	the binary stream
 * @param max	maximum number of bytes expected in the array
 * @param ptr	where to put the read bytes (must be at least "max" byte long)
 * @param pr	where to put the amount of bytes read in ptr
 */
gboolean
bstr_read_packed_array_u8(bstr_t *bs, size_t max, gpointer ptr, guint8 *pr)
{
	static const char *where = "bstr_read_packed_array_u8";
	guint8 len;

	g_assert(ptr);
	g_assert(pr);

	if (!expect(bs, 1, where))
		return FALSE;

	len = *(guint8 *) bs->rptr++;

	if (len > max)
		return invalid_len_max(bs, len, max, "array size", where);

	if (len) {
		if (!expect(bs, len, where))
			return FALSE;

		memcpy(ptr, bs->rptr, len);
		bs->rptr += len;
	}

	*pr = len;

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
