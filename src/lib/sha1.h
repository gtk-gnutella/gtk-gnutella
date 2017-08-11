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

typedef struct sha1 {
	char data[SHA1_RAW_SIZE];
} sha1_t;

enum SHA1_context_magic { SHA1_CONTEXT_MAGIC = 0x73accbce };

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1_context {
	enum SHA1_context_magic magic;		/* Magic number */
	uint32 ihash[SHA1_RAW_SIZE / 4];	/* Intermediate Message Digest  */
	uint64 length;            /* Message length in bits */
	int midx;                 /* Index into message block array */
	uint8 mblock[64];         /* 512-bit message blocks */
	bool computed;            /* Is the digest computed? */
	enum SHA_code corrupted;  /* Is the message digest corrupted? */
} SHA1_context;

static inline void
SHA1_check(const SHA1_context * const ctx)
{
	g_assert(NULL == ctx || SHA1_CONTEXT_MAGIC == ctx->magic);
}

/*
 *  Function Prototypes
 */

int SHA1_reset(SHA1_context *);
int SHA1_input(SHA1_context *, const void *, size_t);
int SHA1_result(SHA1_context *, struct sha1 *digest);
int SHA1_intermediate(const SHA1_context *, struct sha1 *digest);

/**
 * Feed the SHA1 context with the content of a variable.
 */
#define SHA1_INPUT(c,v)		SHA1_input((c), &(v), sizeof(v))

/**
 * Compute the SHA1 digest of (structure) ``x'' into ``d''.
 *
 * ``x'' is the data structure, and ``sizeof(x)'' gives the size to hash.
 * ``d'' is the address of the output digest (sha1_t *).
 */
#define SHA1_COMPUTE(x,d) G_STMT_START {	\
	SHA1_context c_;						\
	SHA1_reset(&c_);						\
	SHA1_input(&c_, &(x), sizeof(x));		\
	SHA1_result(&c_, (d));					\
} G_STMT_END

#endif /* _sha1_h_ */

/* vi: set ts=4 sw=4 cindent: */
