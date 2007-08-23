/*
 * $Id$
 *
 * Copyright (c) 2007, Raphael Manfredi
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
 * URL factory utils.
 *
 * @author Raphael Manfredi
 * @date 2007
 */

#include "common.h"

RCSID("$Id$")

#include "url_factory.h"
#include "misc.h"
#include "url.h"
#include "override.h"		/* Must be the last header included */

static gchar tmp[2048];

/**
 * Create a Bitzi lookup URL based on the SHA1.
 *
 * @return pointer to static data containing the bitzi URL
 */
const gchar *
url_for_bitzi_lookup(const struct sha1 *sha1)
{
	static const gchar base_url[] = "http://bitzi.com/lookup/";
	static gchar buf[sizeof base_url + SHA1_BASE32_SIZE];

	g_return_val_if_fail(sha1, NULL);

	concat_strings(buf, sizeof buf, base_url, sha1_base32(sha1), (void *) 0);

	return buf;
}

/**
 * Create a ShareMonkey lookup URL.
 *
 * @return pointer to static data containing the ShareMonkey URL
 */
const gchar *
url_for_sharemonkey_lookup(
	const struct sha1 *sha1, const gchar *filename, filesize_t size)
{
	static const gchar base_url[] = "http://match.sharemonkey.com/?";
	static const gchar campaign[] = "cid=25";
	const gchar *file_basename;
	gchar *escaped;

	g_return_val_if_fail(sha1, NULL);
	g_return_val_if_fail(filename, NULL);

	file_basename = filepath_basename(filename);
	escaped = url_escape(file_basename);

	concat_strings(tmp, sizeof tmp,
		base_url, campaign,
		"&n=", escaped,
		"&s=", filesize_to_string(size),
		"&sha=", sha1_base32(sha1),
		(void *) 0);

	if (escaped != file_basename)
		G_FREE_NULL(escaped);

	return tmp;
}

/* vi: set ts=4 sw=4 cindent: */
