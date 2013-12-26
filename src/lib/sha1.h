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
enum
{
    shaSuccess = 0,
    shaNull,            /**< Null pointer parameter */
    shaInputTooLong,    /**< input data too long */
    shaStateError       /**< called Input after Result */
};
#endif

struct sha1;

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1Context {
    uint32 Intermediate_Hash[SHA1_RAW_SIZE / 4]; /* Message Digest  */
    uint64 Length;            /* Message length in bits */
    int Message_Block_Index;  /* Index into message block array */
    uint8 Message_Block[64];  /* 512-bit message blocks */
    int Computed;             /* Is the digest computed? */
    int Corrupted;            /* Is the message digest corrupted? */
} SHA1Context;

/*
 *  Function Prototypes
 */

int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const void *, size_t);
int SHA1Result(SHA1Context *, struct sha1 *digest);

#endif /* _sha1_h_ */

