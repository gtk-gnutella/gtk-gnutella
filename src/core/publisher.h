/*
 * Copyright (c) 2009, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Shared file DHT publisher.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _core_publisher_h_
#define _core_publisher_h_

#include "lib/misc.h"		/* For sha1_t */
#include "pdht.h"			/* For pdht_info_t */

/*
 * Public interface.
 */

void publisher_init(void);
void publisher_close(void);

void publisher_add(const sha1_t *sha1);
void publisher_add_event(void *sha1);

int publisher_delay(const pdht_info_t *info, time_delta_t expiration);
bool publisher_is_acceptable(const pdht_info_t *info);

#endif	/* _core_publisher_h_ */

/* vi: set ts=4 sw=4 cindent: */
