/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * Timestamp functions.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#ifndef _timestamp_h_
#define _timestamp_h_

#include "misc.h"		/* For short_string_t */

/*
 * Date string conversions
 */
const char *timestamp_to_string(time_t date);
const char *timestamp_utc_to_string(time_t date);
const char *timestamp_rfc822_to_string(time_t date);
const char *timestamp_rfc822_to_string2(time_t date);
const char *timestamp_rfc1123_to_string(time_t date);

size_t timestamp_to_string_buf(time_t date, char *dst, size_t size);
size_t timestamp_utc_to_string_buf(time_t date, char *dst, size_t size);
short_string_t timestamp_get_string(time_t date);

#endif /* _timestamp_h_ */

/* vi: set ts=4 sw=4 cindent: */
