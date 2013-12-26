/*
 * This file comes from RFC 3174. Inclusion in gtk-gnutella is:
 *
 *   Copyright (c) 2002-2003, Raphael Manfredi
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

#ifndef _sha1_h_
#define _sha1_h_

#include "common.h"

/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 *
 *  name          meaning
 *  uint32        unsigned 32 bit integer
 *  uint8         unsigned 8 bit integer (i.e., unsigned char)
 *  int           integer of >= 16 bits
 *
 */

#ifndef _SHA_enum_
#define _SHA_enum_
enum SHA_code
{
    SHA_SUCCESS = 0,       /**< OK */
    SHA_NULL,              /**< Null pointer parameter */
    SHA_INPUT_TOO_LONG,    /**< input data too long */
    SHA_STATE_ERROR        /**< called Input after Result */
};
#endif

struct sha1;

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1_context {
	uint32 ihash[SHA1_RAW_SIZE / 4]; /* Intermediate Message Digest  */
	uint64 length;            /* Message length in bits */
	int midx;                 /* Index into message block array */
	uint8 mblock[64];         /* 512-bit message blocks */
	bool computed;            /* Is the digest computed? */
	enum SHA_code corrupted;  /* Is the message digest corrupted? */
} SHA1_context;

/*
 *  Function Prototypes
 */

int SHA1_reset(SHA1_context *);
int SHA1_input(SHA1_context *, const void *, size_t);
int SHA1_result(SHA1_context *, struct sha1 *digest);

#endif /* _sha1_h_ */

