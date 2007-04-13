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
 * Therefore, we unconditionally accept both old and new encodings.
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
			goto invalid;
	}

	if (base32_decode_into(buf, SHA1_BASE32_SIZE,
			sha1->data, sizeof sha1->data))
		return TRUE;

	/*
	 * When extracting SHA1 from HTTP headers, we want to get the proper
	 * hash value: some servents were deployed with the old base32 encoding
	 * (using the digits 8 and 9 in the alphabet instead of letters L and O
	 * in the new one).
	 *
	 * Among the 32 groups of 5 bits, equi-probable, there is a 2/32 chance
	 * of having a 8 or a 9 encoded in the old alphabet.  Therefore, the
	 * probability of not having a 8 or a 9 in the first letter is 30/32.
	 * The probability of having no 8 or 9 in the 32 letters is (30/32)^32.
	 * So the probability of having at least an 8 or a 9 is 1-(30/32)^32,
	 * which is 87.32%.
	 */

	if (base32_decode_old_into(buf, SHA1_BASE32_SIZE,
			sha1->data, sizeof sha1->data))
		return TRUE;

invalid:
	g_warning("ignoring invalid SHA1 base32 encoding: %s", buf);

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
