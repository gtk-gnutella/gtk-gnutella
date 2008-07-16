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

#define BSTR_F_EOS		(1 << 16)	/**< End of stream reached */

static gboolean error_eos(bstr_t *bs, ssize_t expected, const gchar *where);

/**
 * Create a new memory stream to parse given arena
 *
 * @param arena		the base of the memory arena
 * @param len		total length of the arena to parse
 * @param flags		configuration flags
 *
 * @return a stream descriptor that must be freed with bstr_close().
 */
bstr_t *
bstr_open(gconstpointer arena, size_t len, guint32 flags)
{
	bstr_t *bs;

	g_assert(arena);

	bs = walloc(sizeof *bs);
	bs->ok = TRUE;
	bs->flags = flags;
	bs->rptr = deconstify_gpointer(arena);
	bs->start = bs->rptr;
	bs->end = bs->start + len;
	bs->error = NULL;

	if (len == 0)
		error_eos(bs, 0, "bstr_open");

	return bs;
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
		return "";
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
error_eos(bstr_t *bs, ssize_t expected, const gchar *where)
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
invalid_len(bstr_t *bs, size_t len, const gchar *what, const gchar *where)
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
	bstr_t *bs, size_t len, size_t max, const gchar *what, const gchar *where)
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
	if (!bs->ok)
		return FALSE;

	if (bs->end - bs->rptr >= expected)
		return TRUE;

	g_assert(expected > 0);

	return error_eos(bs, expected, where);
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
	if (!expect(bs, 1, "bstr_read_u8"))
		return FALSE;

	*pv = *(guint8 *) bs->rptr++;
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
	guint16 v;

	if (!expect(bs, 2, "bstr_read_le16"))
		return FALSE;

	v = *(guint8 *) bs->rptr++;
	*pv = v | (guint16) (*(guint8 *) bs->rptr++) << 8;
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
	guint16 v;

	if (!expect(bs, 2, "bstr_read_be16"))
		return FALSE;

	v = (guint16) (*(guint8 *) bs->rptr++) << 8;
	*pv = v | *(guint8 *) bs->rptr++;
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
	guint32 v;

	if (!expect(bs, 4, "bstr_read_le32"))
		return FALSE;

	v = *(guint8 *) bs->rptr++;
	v |= (guint32) (*(guint8 *) bs->rptr++) << 8;
	v |= (guint32) (*(guint8 *) bs->rptr++) << 16;
	*pv = v | (guint32) (*(guint8 *) bs->rptr++) << 24;
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
	guint32 v;

	if (!expect(bs, 4, "bstr_read_be32"))
		return FALSE;

	v = (guint32) (*(guint8 *) bs->rptr++) << 24;
	v |= (guint32) (*(guint8 *) bs->rptr++) << 16;
	v |= (guint32) (*(guint8 *) bs->rptr++) << 8;
	*pv = v | *(guint8 *) bs->rptr++;
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

	if (!expect(bs, 1, where))
		return FALSE;

	len = *(guint8 *) bs->rptr++;

	if (len != 4 && len != 16)
		return invalid_len(bs, len, "IP address", where);

	if (!expect(bs, (ssize_t) len, where))
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

	if (!expect(bs, 1, where))
		return FALSE;

	len = *(guint8 *) bs->rptr++;

	if (len > max)
		return invalid_len_max(bs, len, max, "array size", where);

	if (!expect(bs, len, where))
		return FALSE;

	if (len)
		memcpy(ptr, bs->rptr, len);

	bs->rptr += len;
	*pr = len;

	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
