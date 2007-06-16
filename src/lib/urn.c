/*
 * $Id$
 *
 * Copyright (c) 2002-2004, Raphael Manfredi
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
 * URN handling of specific formats.
 *
 * @author Raphael Manfredi
 * @date 2002-2004
 */

#include "common.h"

RCSID("$Id$")

#include "base32.h"
#include "misc.h"
#include "urn.h"
#include "override.h"		/* Must be the last header included */

/**
 * Validate SHA1 starting in NUL-terminated `buf' as a proper base32 encoding
 * of a SHA1 hash, and write decoded value in `retval'.
 *
 * The SHA1 typically comes from HTTP, in a X-Gnutella-Content-URN header.
 *
 * @return TRUE if the SHA1 was valid and properly decoded, FALSE on error.
 */
gboolean
urn_get_http_sha1(const gchar *buf, struct sha1 *sha1)
{
	struct sha1 raw;
	gint i;

	if (!sha1) {
		sha1 = &raw;
	}

	/*
	 * Make sure we have at least SHA1_BASE32_SIZE characters before the
	 * end of the string.
	 */

	for (i = 0; i < SHA1_BASE32_SIZE; i++) {
		if ('\0' == buf[i])
			return FALSE;
	}

	if (SHA1_RAW_SIZE == base32_decode(sha1->data, sizeof sha1->data,
							buf, SHA1_BASE32_SIZE))
		return TRUE;

	return FALSE;
}

/**
 * Locate the start of "urn:sha1:" or "urn:bitprint:" indications and extract
 * the SHA1 out of it, placing it in the supplied `digest' buffer.
 *
 * @return whether we successfully extracted the SHA1.
 */
gboolean
urn_get_sha1(const gchar *buf, struct sha1 *sha1)
{
	const gchar *p;

	/*
	 * We handle both "urn:sha1:" and "urn:bitprint:".  In the latter case,
	 * the first 32 bytes of the bitprint is the SHA1.
	 */

	if (
		NULL == (p = is_strcaseprefix(buf, "urn:sha1:")) &&
		NULL == (p = is_strcaseprefix(buf, "urn:bitprint:"))
	)
		return FALSE;

	return urn_get_http_sha1(p, sha1);
}

gboolean
urn_get_bitprint(const gchar *buf, size_t size,
	struct sha1 *sha1, struct tth *tth)
{
	static const char prefix[] = "urn:bitprint:";
	size_t len;
	const gchar *p;

	g_assert(0 == size || NULL != buf);
	g_assert(sha1);
	g_assert(tth);

	if (size < CONST_STRLEN(prefix) + BITPRINT_BASE32_SIZE) {
		return FALSE;
	}
	p = is_strcaseprefix(buf, prefix);
	if (NULL == p) {
		return FALSE;
	}
	len = base32_decode(sha1->data, SHA1_RAW_SIZE, p, SHA1_BASE32_SIZE);
	if (len != SHA1_RAW_SIZE) {
		return FALSE;
	}
	p += SHA1_BASE32_SIZE;
	if ('.' != *p++) {
		return FALSE;
	}
	len = base32_decode(tth->data, TTH_RAW_SIZE, p, TTH_BASE32_SIZE);
	if (len != TTH_RAW_SIZE) {
		return FALSE;
	}
	return TRUE;
}

gboolean
urn_get_tth(const gchar *buf, size_t size, struct tth *tth)
{
	static const char prefix[] = "urn:tree:tiger:";
	size_t len;
	const gchar *p;

	g_assert(0 == size || NULL != buf);
	g_assert(tth);

	if (size < CONST_STRLEN(prefix) + TTH_BASE32_SIZE) {
		return FALSE;
	}
	p = is_strcaseprefix(buf, prefix);
	if (NULL == p) {
		return FALSE;
	}
	len = base32_decode(tth->data, TTH_RAW_SIZE, p, TTH_BASE32_SIZE);
	if (len != TTH_RAW_SIZE) {
		return FALSE;
	}
	return TRUE;
}

/**
 * This is the same as urn_get_sha1(), only the leading "urn:" part
 * is missing (typically a URN embedded in a GGEP "u").
 *
 * `buf' MUST start with "sha1:" or "bitprint:" indications.  Since the
 * leading "urn:" part is missing, we cannot be lenient.
 *
 * Extract the SHA1 out of it, placing it in the supplied `digest' buffer.
 *
 * @return whether we successfully extracted the SHA1.
 */
gboolean
urn_get_sha1_no_prefix(const gchar *buf, struct sha1 *sha1)
{
	const gchar *p;

	/*
	 * We handle both "sha1:" and "bitprint:".  In the latter case,
	 * the first 32 bytes of the bitprint is the SHA1.
	 */

	if (
		NULL == (p = is_strcaseprefix(buf, "sha1:")) &&
		NULL == (p = is_strcaseprefix(buf, "bitprint:"))
	)
		return FALSE;

	return urn_get_http_sha1(p, sha1);
}

/*
 * Emacs stuff:
 * Local Variables: ***
 * c-indentation-style: "bsd" ***
 * fill-column: 80 ***
 * tab-width: 4 ***
 * indent-tabs-mode: nil ***
 * End: ***
 * vi: set ts=4 sw=4 cindent:
 */
