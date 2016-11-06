/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * @file
 *
 * Portable type definitions and other conveniences.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _types_h_
#define _types_h_

/* @note This file is only for inclusion by common.h. */

/***
 *** Native types.
 ***/

#ifndef __cplusplus
/* In C++, "bool" is a builtin type, cannot redefine it */
#if 0	/* Not yet */
typedef enum bool {
	BOOL_FALSE=0,
	BOOL_TRUE = 1
} bool;
#else
typedef int bool;
#endif
#endif	/* !C++ */

#if CHARSIZE == 1
typedef signed char int8;
typedef unsigned char uint8;
#else
#error "no known 8-bit type."
#endif

#if SHORTSIZE == 2
typedef short int16;
typedef unsigned short uint16;
#else
#error "no known 16-bit type."
#endif

#if INTSIZE == 4
typedef int int32;
typedef unsigned int uint32;
#else
#error "no known 32-bit type."
#endif

#if LONGSIZE == 8
typedef long int64;
typedef unsigned long uint64;
#define INT64_CONST(x)		(x##L)
#define UINT64_CONST(x)		(x##UL)
#elif defined(CAN_HANDLE_64BITS)
typedef long long int64;
typedef unsigned long long uint64;
#define INT64_CONST(x)		(G_EXTENSION(x##LL))
#define UINT64_CONST(x)		(G_EXTENSION(x##ULL))
#else
#error "no known 64-bit type."
#endif

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

/***
 *** Generic callback types for data structures.
 ***/

/* Data comparison, with and without context: returns values  <0, 0, >0 */

typedef int (*cmp_fn_t)(const void *a, const void *b);
typedef int (*cmp_data_fn_t)(const void *a, const void *b, void *data);

/* String comparison, with and without context: returns values  <0, 0, >0 */

typedef int (*strcmp_fn_t)(const char *a, const char *b);
typedef int (*strcmp_data_fn_t)(const char *a, const char *b, void *data);

/* Data equality */

typedef bool (*eq_fn_t)(const void *a, const void *b);
typedef bool (*eq_data_fn_t)(const void *a, const void *b, void *data);

/* Hashing functions */

typedef uint (*hash_fn_t)(const void *key);
typedef uint (*hash_data_fn_t)(const void *key, void *data);

/* Iterator callbacks for data containers, optionally with constant data */

typedef void (*data_fn_t)(void *data, void *udata);
typedef void (*cdata_fn_t)(const void *data, void *udata);
typedef bool (*data_rm_fn_t)(void *data, void *udata);
typedef bool (*cdata_rm_fn_t)(const void *data, void *udata);

/* Data structure callback for selection & matching */

typedef bool (*match_fn_t)(const void *data, void *udata);

/* Iterator callbacks for associative arrays, optionally with constant key */

typedef void (*keyval_fn_t)(void *key, void *value, void *data);
typedef void (*ckeyval_fn_t)(const void *key, void *value, void *data);
typedef bool (*keyval_rm_fn_t)(void *key, void *value, void *data);
typedef bool (*ckeyval_rm_fn_t)(const void *key, void *value, void *data);

/* Allocator routine signatures, with or without allocating context */

typedef void *(*alloc_fn_t)(size_t n);
typedef void *(*alloc_data_fn_t)(void *data, size_t n);

/* Re-allocator routine signatures, with or without allocating context */

typedef void *(*realloc_fn_t)(void *p, size_t n);
typedef void *(*realloc_data_fn_t)(void *data, void *p, size_t n);

/* Data freeing callbacks signatures, with or without allocating context */

typedef void (*free_fn_t)(void *data);
typedef void (*free_keyval_fn_t)(void *key, void *value);
typedef void (*free_keyval_data_fn_t)(void *key, void *value, void *user_data);
typedef void (*free_size_fn_t)(void *data, size_t len);
typedef void (*free_data_fn_t)(void *data, void *user_data);

/* Object copying */

typedef void *(*copy_fn_t)(const void *src);
typedef void *(*copy_data_fn_t)(const void *src, void *data);

/* Generic event notification, with or without context */

typedef void (*notify_fn_t)(void *data);
typedef void (*notify_data_fn_t)(void *data, void *user_data);

/* Generic callbacks */

typedef void (*callback_fn_t)(void);
typedef int (*action_fn_t)(void);

/* Generic object field extraction routine */

typedef void *(*get_fn_t)(const void *obj);

/* Generic processing routine */

typedef void *(*process_fn_t)(void *);

/* Generic stringifiers */

typedef const char *(*stringify_fn_t)(const void *data);
typedef const char *(*stringify_len_fn_t)(const void *data, size_t len);

/* Random number generators (32-bit and 64-bit routines) */

typedef uint32 (*random_fn_t)(void);
typedef uint64 (*random64_fn_t)(void);
typedef void (*randfill_fn_t)(void *data, size_t len);

/* Generic predicate, testing a condition on some data */

typedef bool (*predicate_fn_t)(void *data);

/* Generic data feed */

typedef void (*feed_fn_t)(const void *data, size_t len);

#endif /* _types_h_ */

/* vi: set ts=4 sw=4 cindent: */
