/*
 * Copyright (c) 2002, Ch. Tronche & Raphael Manfredi
 *
 * HUGE support (Hash/URN Gnutella Extension).
 *
 * Started by Ch. Tronche (http://tronche.com/) 28/04/2002
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

#ifndef __huge_h__
#define __huge_h__

#include <sys/types.h>

#define SHA1_BASE32_SIZE 	32		/* 160 bits in base32 representation */
#define SHA1_RAW_SIZE		20		/* 160 bits in binary representation */

struct shared_file;

void huge_init(void);		/* Call this function at the beginning */
void huge_close(void);		/* Call this when servent is shutdown */

/*
 * Set the sha1_digest field in a newly created shared_file.
 * If value is found in the cache, it is used, else it is computed and
 * the computed value is saved in the cache.
 */

void request_sha1(struct shared_file *);

#endif	/* __huge_h__ */

/* 
 * Emacs stuff:
 * Local Variables: ***
 * c-indentation-style: "bsd" ***
 * fill-column: 80 ***
 * tab-width: 4 ***
 * indent-tabs-mode: nil ***
 * End: ***
 */
