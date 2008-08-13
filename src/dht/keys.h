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
 * @ingroup dht
 * @file
 *
 * Local key management.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _dht_keys_h_
#define _dht_keys h_

#include "kuid.h"
#include "values.h"

#define MAX_VALUES_PER_KEY	16	/**< Max amount of values allowed under key */

/*
 * Public interface.
 */

void keys_init(void);
void keys_close(void);

gboolean keys_exists(const kuid_t *key);
void keys_get_status(const kuid_t *id, gboolean *full, gboolean *loaded);
guint64 keys_has(const kuid_t *id, const kuid_t *creator_id);
void keys_add_value(const kuid_t *id, const kuid_t *creator_id, guint64 dbkey);
int keys_get(const kuid_t *id, dht_value_type_t type,
	kuid_t **secondary, int secondary_count, dht_value_t **valvec, int valcnt,
	float *loadptr);

#endif /* _dht_keys_h_ */

/* vi: set ts=4 sw=4 cindent: */
