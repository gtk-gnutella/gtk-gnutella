/*
 * Copyright (c) 2003, Jeroen Asselman
 *
 * Passive/Active Remote Queuing.
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
 
#ifndef _parq_h_
#define _parq_h_

#include "header.h"
#include "downloads.h"

/*
 * PARQ Version information
 */
 
#define PARQ_VERSION_MAJOR	1
#define	PARQ_VERSION_MINOR	0

/*
 * Public interface.
 */

void parq_download_retry_active_queued(struct download *d);
gboolean parq_download_supports_parq(header_t *header);
gboolean parq_download_parse_queue_status(struct download *d, header_t *header);
gboolean parq_download_is_active_queued(struct download *d);
void parq_download_add_header(gchar *buf, gint *rw, struct download *d);
	
#endif /* _parq_h_ */

