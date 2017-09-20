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
 * Network RX buffer allocator.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_rxbuf_h_
#define _core_rxbuf_h_

#include "common.h"
#include "lib/pmsg.h"

/*
 * Public interface
 */

pdata_t *rxbuf_new(void);
void rxbuf_free(void *p);

void rxbuf_init(void);
void rxbuf_close(void);

#endif	/* _core_rxbuf_h_ */

/* vi: set ts=4 sw=4 cindent: */
