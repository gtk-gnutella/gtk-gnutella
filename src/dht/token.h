/*
 * $Id$
 *
 * Copyright (c) 2006-2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Security tokens.
 *
 * @author Raphael Manfredi
 * @date 2006-2008
 */

#ifndef _dht_token_h_
#define _dht_token_h_

#include "common.h"
#include "lib/host_addr.h"

#define TOKEN_RAW_SIZE		4

typedef struct {
	guchar v[TOKEN_RAW_SIZE];
} token_t;

/*
 * Public interface.
 */

void token_init(void);
void token_close(void);

void token_generate(token_t *tok, host_addr_t addr, guint16 port);
gboolean token_is_valid(const token_t *tok, host_addr_t addr, guint16 port);

#endif /* _dht_token_h_ */

/* vi: set ts=4 sw=4 cindent: */
