/*
 * Copyright (c) 2004, Christian Biere
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _lib_iso3166_h_
#define _lib_iso3166_h_

#include "common.h"

#define ISO3166_INVALID ((uint16)-1)
#define ISO3166_NUM_CODES (36 * 35 + 35)

uint16 iso3166_encode_cc(const char *cc);
void iso3166_init(void);
void iso3166_close(void);
const char *iso3166_country_name(uint16 code);
const char *iso3166_country_cc(uint16 code);

static inline bool iso3166_code_is_valid(uint16 code)
{
	return ISO3166_INVALID == code || code < (unsigned) ISO3166_NUM_CODES;
}

#endif /* _lib_iso3166_h_ */

/* vi: set ts=4 sw=4 cindent: */
