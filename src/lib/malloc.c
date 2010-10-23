/*
 * $Id$
 *
 * Copyright (c) 2004-2010, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory.
 *
 * @author Raphael Manfredi
 * @date 2004-2010
 */

#include "common.h"		/* For RCSID */

RCSID("$Id$")

#if defined(MALLOC_STATS) && !defined(TRACK_MALLOC)
#define TRACK_MALLOC
#endif

#define MALLOC_SOURCE	/**< Avoid nasty remappings, but include signatures */

#include "atoms.h"		/* For binary_hash() */
#include "ascii.h"
#include "concat.h"		/* For concat_strings() */
#include "cq.h"
#include "endian.h"		/* For peek_*() and poke_*() */
#include "hashtable.h"
#include "parse.h"		/* For parse_pointer() */
#include "path.h"		/* For filepath_basename() */
#include "tm.h"			/* For tm_time() */
#include "stringify.h"	/* For uint64_to_string() and short_time() */
#include "unsigned.h"	/* For size_is_non_negative() */
#include "glib-missing.h"

/*
 * The following setups are more or less independent from each other.
 *
 * This comes at the price of heavy usage of conditinal compilation
 * throughout the file...
 *
 * All of these have effect even when TRACK_MALLOC is not defined.
 */

#if 0
#define MALLOC_VTABLE			/* Try to redirect glib's malloc here */
#endif
#if 0
#define MALLOC_SAFE				/* Add trailer magic to each block */
#define MALLOC_TRAILER_LEN	32	/* Additional trailer len, past end mark */
#endif
#if 0
#define MALLOC_SAFE_HEAD		/* Additional header magic before each block */
#endif
#if 0
#define MALLOC_FREE_ERASE	/* Whether freeing should erase block data */
#endif
#if 0
#define MALLOC_DUP_FREE		/* Detect duplicate frees by block tagging */
#endif
#if 0
#define MALLOC_PERIODIC		/* Periodically scan blocks for overruns */
#define MALLOC_PERIOD	5000	/* Every 5 secs */
#endif
#if 0
#define MALLOC_LEAK_ALL		/* Report all leaked "real" blocks as well */
#endif

/*
 * Enable MALLOC_VTABLE to avoid missing free() events from GTK if they
 * turn on TRACK_MALLOC.
 */

#if defined(TRACK_MALLOC) && !defined(MALLOC_VTABLE)
#define MALLOC_VTABLE		/* Will miss some free(), report false leaks */
#endif

/**
 * Most routines in this file are defined either when compiling with
 * TRACK_MALLOC or TRACK_ZALLOC.
 */

/*
 * With MALLOC_SAFE, a marker integer is put at the end of each block, and is
 * checked at free time to detect buffer overruns.  A blank safety trailer
 * can also be put to catch accidental overruns and prevent corrupting data in
 * the next block.
 */
#ifdef MALLOC_SAFE

#define MALLOC_START_MARK	0xf8b519d1U
#define MALLOC_END_MARK		0xc5c67b7aU

/*
 * Because of the extra header we put at the beginning of each blocks, it
 * is imperative to turn on MALLOC_VTABLE when MALLOC_SAFE is on so that we
 * are the ones freeing the block: the physical start of the block is not
 * the user pointer of the block!
 */

#ifndef MALLOC_VTABLE
#define MALLOC_VTABLE
#endif

/**
 * Safety trailer appended to each malloc'ed block to "absorb" overruns and
 * prevent corruption of the malloc free list (by destroying the header of
 * the next malloc'ed block).
 *
 * This is going to be additional overhead for each block, so don't set it
 * too large or there will be a huge memory penalty. 32 bytes is reasonable.
 * If set to 0, there is still the end marker protection (4 bytes).
 */
#ifndef MALLOC_TRAILER_LEN
#define MALLOC_TRAILER_LEN	0		/* No additional trailer by default */
#endif
#define MALLOC_TRAILER_MARK	'\245'	/* 0xa5 */

union mem_chunk {
  void      *next;
  guint8   u8;
  guint16  u16;
  guint32  u32;
  guint64  u64;
  float     f;
  double    d;
};

#ifdef MALLOC_SAFE_HEAD

/**
 * Header prepended to allocated blocks, when we want to check the start
 * of each block as well.  This is more dangerous because it changes the
 * start address of the blocks and it forces us to be extra careful about
 * which blocks we own (and had therefore this overhead prepended) since
 * the user does not know about that header and only passes us the start
 * of the arena.
 *
 * Also, it is required that we be the ones freeing the blocks we allocate.
 * If this is not the case and our free is not called, havoc will result.
 */
struct malloc_header {
	unsigned start;				/* Start mark (must be before arena) */
	union mem_chunk arena[1];	/* Start of user arena */
};

#define SAFE_ARENA_OFFSET	G_STRUCT_OFFSET(struct malloc_header, arena)

#endif /* MALLOC_SAFE_HEAD */

enum real_malloc_magic { REAL_MALLOC_MAGIC = 0x5fb8b88aU };

/**
 * This header is prepended to blocks allocated by real_malloc(), because
 * we know these will be freed by real_free() and these blocks are not
 * tracked.  To be able to know the size of the block to check the trailers,
 * we have to record the size within the block...
 *
 * This means that anything allocated through real_malloc() MUST be given
 * back to real_free(), because free() will not know it has to backtrack
 * to the header to free the block.
 */
struct real_malloc_header {
	enum real_malloc_magic magic;
	size_t size;				/* Size of block */
	union mem_chunk arena[1];	/* Start of user arena */
};

#define REAL_ARENA_OFFSET	G_STRUCT_OFFSET(struct real_malloc_header, arena)

#endif /* MALLOC_SAFE */

#include "misc.h"
#include "hashlist.h"
#include "glib-missing.h"
#include "override.h"

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
static hash_table_t *reals;
static hash_table_t *unknowns;
#endif

#ifdef MALLOC_VTABLE
static gboolean vtable_works;	/* Whether we can trap glib memory calls */
#endif

/**
 * Structure keeping track of allocated blocks. (visible for convenience)
 *
 * Each block is inserted into a hash table, the key being the block's user
 * address and the value being a structure keeping track of the initial
 * allocation, and possibly of all the reallocations performed.
 */
struct block {
	const char *file;
	GSList *reallocations;
	size_t size;
	int line;
	unsigned owned:1;		/**< Whether we allocated the block ourselves */
#if defined(MALLOC_SAFE) || defined(MALLOC_PERIODIC)
	unsigned corrupted:1;	/**< Whether block was marked as corrupted */
#endif
};

/**
 * Structure keeping information for blocks allocated through real_malloc().
 */
struct realblock {
#ifdef MALLOC_FRAMES
	struct frame *alloc;	/**< Allocation frame (atom) */
#endif
	size_t size;
#if defined(MALLOC_SAFE) || defined(MALLOC_PERIODIC)
	unsigned corrupted:1;	/**< Whether block was marked as corrupted */
#endif
};

#ifdef TRACK_MALLOC
static time_t init_time = 0;
static time_t reset_time = 0;

static hash_table_t *blocks = NULL;
static hash_table_t *not_leaking = NULL;

static gboolean free_record(gconstpointer o, const char *file, int line);
#endif

/*
 * When MALLOC_FRAMES is supplied, we collect allocation stack frames.
 *
 * When MALLOC_STATS is also defined, we keep track of allocation stack frames
 * for all the blocks to know how many allocation / reallocation and free
 * points there are for each allocation point (identified by file + line).
 *
 * We also keep and show the allocation stack frame using symbol names for all
 * the leaked blocks that we can identify at the end.
 */

#ifdef MALLOC_FRAMES
/*
 * getreturnaddr() and getframeaddr() are:
 *
 * Copyright (c) 2003 Maxim Sobolev <sobomax@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $X-Id: execinfo.c,v 1.3 2004/07/19 05:21:09 sobomax Exp $
 */

/*
 * The following routines rely on GCC internal macros, which are expanded at
 * compile-time (hence the parameter must be specified explicitly and
 * cannot be a variable).
 *
 * The advantage is that this is portable accross all architectures where
 * GCC is available.
 *
 * The disadvantage is that GCC is required and the stack frame maximum
 * size is constrained by the number of cases handled.
 */

#if defined(__GNUC__)
static void *
getreturnaddr(size_t level)
{
    switch (level) {
    case 0:		return __builtin_return_address(1);
    case 1:		return __builtin_return_address(2);
    case 2:		return __builtin_return_address(3);
    case 3:		return __builtin_return_address(4);
    case 4:		return __builtin_return_address(5);
    case 5:		return __builtin_return_address(6);
    case 6:		return __builtin_return_address(7);
    case 7:		return __builtin_return_address(8);
    case 8:		return __builtin_return_address(9);
    case 9:		return __builtin_return_address(10);
    case 10:	return __builtin_return_address(11);
    case 11:	return __builtin_return_address(12);
    case 12:	return __builtin_return_address(13);
    case 13:	return __builtin_return_address(14);
    case 14:	return __builtin_return_address(15);
    case 15:	return __builtin_return_address(16);
    case 16:	return __builtin_return_address(17);
    case 17:	return __builtin_return_address(18);
    case 18:	return __builtin_return_address(19);
    case 19:	return __builtin_return_address(20);
    case 20:	return __builtin_return_address(21);
    case 21:	return __builtin_return_address(22);
    case 22:	return __builtin_return_address(23);
    case 23:	return __builtin_return_address(24);
    case 24:	return __builtin_return_address(25);
    case 25:	return __builtin_return_address(26);
    case 26:	return __builtin_return_address(27);
    case 27:	return __builtin_return_address(28);
    case 28:	return __builtin_return_address(29);
    case 29:	return __builtin_return_address(30);
    case 30:	return __builtin_return_address(31);
    case 31:	return __builtin_return_address(32);
    case 32:	return __builtin_return_address(33);
    case 33:	return __builtin_return_address(34);
    case 34:	return __builtin_return_address(35);
    case 35:	return __builtin_return_address(36);
    case 36:	return __builtin_return_address(37);
    case 37:	return __builtin_return_address(38);
    case 38:	return __builtin_return_address(39);
    case 39:	return __builtin_return_address(40);
    case 40:	return __builtin_return_address(41);
    case 41:	return __builtin_return_address(42);
    case 42:	return __builtin_return_address(43);
    case 43:	return __builtin_return_address(44);
    case 44:	return __builtin_return_address(45);
    case 45:	return __builtin_return_address(46);
    case 46:	return __builtin_return_address(47);
    case 47:	return __builtin_return_address(48);
    case 48:	return __builtin_return_address(49);
    case 49:	return __builtin_return_address(50);
    case 50:	return __builtin_return_address(51);
    case 51:	return __builtin_return_address(52);
    case 52:	return __builtin_return_address(53);
    case 53:	return __builtin_return_address(54);
    case 54:	return __builtin_return_address(55);
    case 55:	return __builtin_return_address(56);
    case 56:	return __builtin_return_address(57);
    case 57:	return __builtin_return_address(58);
    case 58:	return __builtin_return_address(59);
    case 59:	return __builtin_return_address(60);
    case 60:	return __builtin_return_address(61);
    case 61:	return __builtin_return_address(62);
    case 62:	return __builtin_return_address(63);
    case 63:	return __builtin_return_address(64);
    case 64:	return __builtin_return_address(65);
    case 65:	return __builtin_return_address(66);
    case 66:	return __builtin_return_address(67);
    case 67:	return __builtin_return_address(68);
    case 68:	return __builtin_return_address(69);
    case 69:	return __builtin_return_address(70);
    case 70:	return __builtin_return_address(71);
    case 71:	return __builtin_return_address(72);
    case 72:	return __builtin_return_address(73);
    case 73:	return __builtin_return_address(74);
    case 74:	return __builtin_return_address(75);
    case 75:	return __builtin_return_address(76);
    case 76:	return __builtin_return_address(77);
    case 77:	return __builtin_return_address(78);
    case 78:	return __builtin_return_address(79);
    case 79:	return __builtin_return_address(80);
    case 80:	return __builtin_return_address(81);
    case 81:	return __builtin_return_address(82);
    case 82:	return __builtin_return_address(83);
    case 83:	return __builtin_return_address(84);
    case 84:	return __builtin_return_address(85);
    case 85:	return __builtin_return_address(86);
    case 86:	return __builtin_return_address(87);
    case 87:	return __builtin_return_address(88);
    case 88:	return __builtin_return_address(89);
    case 89:	return __builtin_return_address(90);
    case 90:	return __builtin_return_address(91);
    case 91:	return __builtin_return_address(92);
    case 92:	return __builtin_return_address(93);
    case 93:	return __builtin_return_address(94);
    case 94:	return __builtin_return_address(95);
    case 95:	return __builtin_return_address(96);
    case 96:	return __builtin_return_address(97);
    case 97:	return __builtin_return_address(98);
    case 98:	return __builtin_return_address(99);
    case 99:	return __builtin_return_address(100);
    case 100:	return __builtin_return_address(101);
    case 101:	return __builtin_return_address(102);
    case 102:	return __builtin_return_address(103);
    case 103:	return __builtin_return_address(104);
    case 104:	return __builtin_return_address(105);
    case 105:	return __builtin_return_address(106);
    case 106:	return __builtin_return_address(107);
    case 107:	return __builtin_return_address(108);
    case 108:	return __builtin_return_address(109);
    case 109:	return __builtin_return_address(110);
    case 110:	return __builtin_return_address(111);
    case 111:	return __builtin_return_address(112);
    case 112:	return __builtin_return_address(113);
    case 113:	return __builtin_return_address(114);
    case 114:	return __builtin_return_address(115);
    case 115:	return __builtin_return_address(116);
    case 116:	return __builtin_return_address(117);
    case 117:	return __builtin_return_address(118);
    case 118:	return __builtin_return_address(119);
    case 119:	return __builtin_return_address(120);
    case 120:	return __builtin_return_address(121);
    case 121:	return __builtin_return_address(122);
    case 122:	return __builtin_return_address(123);
    case 123:	return __builtin_return_address(124);
    case 124:	return __builtin_return_address(125);
    case 125:	return __builtin_return_address(126);
    case 126:	return __builtin_return_address(127);
    case 127:	return __builtin_return_address(128);
    default:	return NULL;
    }
}

static void *
getframeaddr(size_t level)
{
    switch (level) {
    case 0:		return __builtin_frame_address(1);
    case 1:		return __builtin_frame_address(2);
    case 2:		return __builtin_frame_address(3);
    case 3:		return __builtin_frame_address(4);
    case 4:		return __builtin_frame_address(5);
    case 5:		return __builtin_frame_address(6);
    case 6:		return __builtin_frame_address(7);
    case 7:		return __builtin_frame_address(8);
    case 8:		return __builtin_frame_address(9);
    case 9:		return __builtin_frame_address(10);
    case 10:	return __builtin_frame_address(11);
    case 11:	return __builtin_frame_address(12);
    case 12:	return __builtin_frame_address(13);
    case 13:	return __builtin_frame_address(14);
    case 14:	return __builtin_frame_address(15);
    case 15:	return __builtin_frame_address(16);
    case 16:	return __builtin_frame_address(17);
    case 17:	return __builtin_frame_address(18);
    case 18:	return __builtin_frame_address(19);
    case 19:	return __builtin_frame_address(20);
    case 20:	return __builtin_frame_address(21);
    case 21:	return __builtin_frame_address(22);
    case 22:	return __builtin_frame_address(23);
    case 23:	return __builtin_frame_address(24);
    case 24:	return __builtin_frame_address(25);
    case 25:	return __builtin_frame_address(26);
    case 26:	return __builtin_frame_address(27);
    case 27:	return __builtin_frame_address(28);
    case 28:	return __builtin_frame_address(29);
    case 29:	return __builtin_frame_address(30);
    case 30:	return __builtin_frame_address(31);
    case 31:	return __builtin_frame_address(32);
    case 32:	return __builtin_frame_address(33);
    case 33:	return __builtin_frame_address(34);
    case 34:	return __builtin_frame_address(35);
    case 35:	return __builtin_frame_address(36);
    case 36:	return __builtin_frame_address(37);
    case 37:	return __builtin_frame_address(38);
    case 38:	return __builtin_frame_address(39);
    case 39:	return __builtin_frame_address(40);
    case 40:	return __builtin_frame_address(41);
    case 41:	return __builtin_frame_address(42);
    case 42:	return __builtin_frame_address(43);
    case 43:	return __builtin_frame_address(44);
    case 44:	return __builtin_frame_address(45);
    case 45:	return __builtin_frame_address(46);
    case 46:	return __builtin_frame_address(47);
    case 47:	return __builtin_frame_address(48);
    case 48:	return __builtin_frame_address(49);
    case 49:	return __builtin_frame_address(50);
    case 50:	return __builtin_frame_address(51);
    case 51:	return __builtin_frame_address(52);
    case 52:	return __builtin_frame_address(53);
    case 53:	return __builtin_frame_address(54);
    case 54:	return __builtin_frame_address(55);
    case 55:	return __builtin_frame_address(56);
    case 56:	return __builtin_frame_address(57);
    case 57:	return __builtin_frame_address(58);
    case 58:	return __builtin_frame_address(59);
    case 59:	return __builtin_frame_address(60);
    case 60:	return __builtin_frame_address(61);
    case 61:	return __builtin_frame_address(62);
    case 62:	return __builtin_frame_address(63);
    case 63:	return __builtin_frame_address(64);
    case 64:	return __builtin_frame_address(65);
    case 65:	return __builtin_frame_address(66);
    case 66:	return __builtin_frame_address(67);
    case 67:	return __builtin_frame_address(68);
    case 68:	return __builtin_frame_address(69);
    case 69:	return __builtin_frame_address(70);
    case 70:	return __builtin_frame_address(71);
    case 71:	return __builtin_frame_address(72);
    case 72:	return __builtin_frame_address(73);
    case 73:	return __builtin_frame_address(74);
    case 74:	return __builtin_frame_address(75);
    case 75:	return __builtin_frame_address(76);
    case 76:	return __builtin_frame_address(77);
    case 77:	return __builtin_frame_address(78);
    case 78:	return __builtin_frame_address(79);
    case 79:	return __builtin_frame_address(80);
    case 80:	return __builtin_frame_address(81);
    case 81:	return __builtin_frame_address(82);
    case 82:	return __builtin_frame_address(83);
    case 83:	return __builtin_frame_address(84);
    case 84:	return __builtin_frame_address(85);
    case 85:	return __builtin_frame_address(86);
    case 86:	return __builtin_frame_address(87);
    case 87:	return __builtin_frame_address(88);
    case 88:	return __builtin_frame_address(89);
    case 89:	return __builtin_frame_address(90);
    case 90:	return __builtin_frame_address(91);
    case 91:	return __builtin_frame_address(92);
    case 92:	return __builtin_frame_address(93);
    case 93:	return __builtin_frame_address(94);
    case 94:	return __builtin_frame_address(95);
    case 95:	return __builtin_frame_address(96);
    case 96:	return __builtin_frame_address(97);
    case 97:	return __builtin_frame_address(98);
    case 98:	return __builtin_frame_address(99);
    case 99:	return __builtin_frame_address(100);
    case 100:	return __builtin_frame_address(101);
    case 101:	return __builtin_frame_address(102);
    case 102:	return __builtin_frame_address(103);
    case 103:	return __builtin_frame_address(104);
    case 104:	return __builtin_frame_address(105);
    case 105:	return __builtin_frame_address(106);
    case 106:	return __builtin_frame_address(107);
    case 107:	return __builtin_frame_address(108);
    case 108:	return __builtin_frame_address(109);
    case 109:	return __builtin_frame_address(110);
    case 110:	return __builtin_frame_address(111);
    case 111:	return __builtin_frame_address(112);
    case 112:	return __builtin_frame_address(113);
    case 113:	return __builtin_frame_address(114);
    case 114:	return __builtin_frame_address(115);
    case 115:	return __builtin_frame_address(116);
    case 116:	return __builtin_frame_address(117);
    case 117:	return __builtin_frame_address(118);
    case 118:	return __builtin_frame_address(119);
    case 119:	return __builtin_frame_address(120);
    case 120:	return __builtin_frame_address(121);
    case 121:	return __builtin_frame_address(122);
    case 122:	return __builtin_frame_address(123);
    case 123:	return __builtin_frame_address(124);
    case 124:	return __builtin_frame_address(125);
    case 125:	return __builtin_frame_address(126);
    case 126:	return __builtin_frame_address(127);
    case 127:	return __builtin_frame_address(128);
    default:	return NULL;
    }
}
#else	/* !__GNUC__ */
static void *
getreturnaddr(size_t level)
{
	(void) level;
	return NULL;
}

static void *
getframeaddr(size_t level)
{
	(void) level;
	return NULL;
}
#endif	/* __GNUC__ */

/**
 * A routine entry in the symbol table.
 */
struct trace {
	const void *start;			/**< Start PC address */
	char *name;					/**< Routine name */
};

/**
 * The array of trace entries.
 */
static struct {
	struct trace *base;			/**< Array base */
	size_t size;				/**< Amount of entries allocated */
	size_t count;				/**< Amount of entries held */
} trace_array;

/**
 * Hashing routine for a "struct frame".
 */
static guint
frame_hash(gconstpointer key)
{
	const struct frame *f = key;

	return binary_hash(f->stack, f->len * sizeof(void *));
}

/**
 * Comparison of two "struct frame" structures.
 */
static int
frame_eq(gconstpointer a, gconstpointer b)
{
	const struct frame *fa = a, *fb = b;

	return fa->len == fb->len &&
		0 == memcmp(fa->stack, fb->stack, fa->len * sizeof(void *));
}

/**
 * Search executable within the user's PATH.
 *
 * @return full path if found, NULL otherwise.
 */
static char *
locate_from_path(const char *argv0)
{
	char *path;
	char *tok;
	char filepath[MAX_PATH_LEN + 1];
	char *result = NULL;

	if (filepath_basename(argv0) != argv0) {
		g_warning("can't locate \"%s\" in PATH: name contains '%c' already",
			argv0, G_DIR_SEPARATOR);
		return NULL;
	}

	path = getenv("PATH");
	if (NULL == path) {
		g_warning("can't locate \"%s\" in PATH: no such environment variable",
			argv0);
		return NULL;
	}

	path = strdup(path);

	for (tok = strtok(path, ":"); tok; tok = strtok(NULL, ":")) {
		const char *dir = tok;
		struct stat buf;

		if ('\0' == *dir)
			dir = ".";
		concat_strings(filepath, sizeof filepath,
			dir, G_DIR_SEPARATOR_S, argv0, NULL);

		if (-1 != stat(filepath, &buf)) {
			if (S_ISREG(buf.st_mode) && -1 != access(filepath, X_OK)) {
				result = strdup(filepath);
				break;
			}
		}
	}

	free(path);
	return result;
}

/**
 * Compare two trace entries -- qsort() callback.
 */
static int
trace_cmp(const void *p, const void *q)
{
	struct trace const *a = p;
	struct trace const *b = q;

	return a->start == b->start ? 0 :
		pointer_to_ulong(a->start) < pointer_to_ulong(b->start) ? -1 : +1;
}

/**
 * Remove duplicate entry in trace array at the specified index.
 */
static void
trace_remove(size_t i)
{
	struct trace *t;

	g_assert(size_is_non_negative(i));
	g_assert(i < trace_array.count);

	t = &trace_array.base[i];
	free(t->name);
	if (i < trace_array.count - 1)
		memmove(t, t + 1, trace_array.count - i - 1);
	trace_array.count--;
}

/**
 * Sort trace array, remove duplicate entries.
 */
static void
trace_sort(void)
{
	size_t i = 0;
	size_t old_count = trace_array.count;
	const void *last = 0;

	qsort(trace_array.base, trace_array.count,
		sizeof trace_array.base[0], trace_cmp);

	while (i < trace_array.count) {
		struct trace *t = &trace_array.base[i];
		if (last && t->start == last) {
			trace_remove(i);
		} else {
			last = t->start;
			i++;
		}
	}

	if (old_count != trace_array.count) {
		size_t delta = old_count - trace_array.count;
		g_assert(size_is_non_negative(delta));
		g_message("stripped %u duplicate symbol%s",
			delta, 1 == delta ? "" : "s");
	}
}

/**
 * Insert new trace symbol.
 */
static void
trace_insert(const void *start, const char *name)
{
	struct trace *t;

	if (trace_array.count >= trace_array.size) {
		trace_array.size += 1024;
		if (NULL == trace_array.base)
			trace_array.base = malloc(trace_array.size * sizeof *t);
		else
			trace_array.base = realloc(trace_array.base,
				trace_array.size * sizeof *t);
		if (NULL == trace_array.base)
			g_error("out of memory");
	}

	t = &trace_array.base[trace_array.count++];
	t->start = start;
	t->name = strdup(name);
}

/**
 * Lookup trace structure encompassing given program counter.
 *
 * @return trace structure if found, NULL otherwise.
 */
static struct trace *
trace_lookup(void *pc)
{
	struct trace *low = trace_array.base,
				 *high = &trace_array.base[trace_array.count -1],
				 *mid;

	while (low <= high) {
		mid = low + (high - low) / 2;
		if (pc >= mid->start && (mid == high || pc < (mid+1)->start))
			return mid;			/* Found it! */
		else if (pc < mid->start)
			high = mid - 1;
		else
			low = mid + 1;
	}

	return NULL;				/* Not found */
}

/*
 * @eturn symbolic name for given pc offset, if found, otherwise
 * the hexadecimal value.
 */
static const char *
trace_name(void *pc)
{
	struct trace *t;
	static char buf[256];

	t = trace_lookup(pc);

	if (NULL == t) {
		gm_snprintf(buf, sizeof buf, "0x%lx", pointer_to_ulong(pc));
	} else {
		gm_snprintf(buf, sizeof buf, "%s+%u", t->name,
			(unsigned) ptr_diff(pc, t->start));
	}

	return buf;
}

/**
 * Parse the nm output line, recording symbol mapping for function entries.
 *
 * We're looking for lines like:
 *
 *	082bec77 T zget
 *	082be9d3 t zn_create
 */
static void
parse_nm(char *line)
{
	int error;
	const char *ep;
	char *p = line;
	const void *addr;

	addr = parse_pointer(p, &ep, &error);
	if (error || NULL == addr)
		return;

	p = skip_ascii_blanks(ep);

	if ('t' == ascii_tolower(*p)) {
		p = skip_ascii_blanks(&p[1]);
		str_chomp(p, 0);
		trace_insert(addr, p);
	}
}

/**
 * Load symbols from the executable we're running.
 */
static void
load_symbols(const char *argv0)
{
	struct stat buf;
	const char *file = argv0;
	char tmp[MAX_PATH_LEN + 80];
	size_t rw;
	FILE *f;

	if (-1 == stat(argv0, &buf)) {
		file = locate_from_path(argv0);
		if (NULL == file) {
			g_warning("cannot find \"%s\" in PATH, not loading symbols", argv0);
			goto done;
		}
	}

	/*
	 * Make sure there are no problematic shell meta-characters in the path.
	 */

	{
		const char meta[] = "$&`:;()<>|";
		const char *p = file;
		int c;

		while ((c = *p++)) {
			if (strchr(meta, c)) {
				g_warning("found shell meta-character '%c' in path \"%s\", "
					"not loading symbols", c, file);
				goto done;
			}
		}
	}

	rw = gm_snprintf(tmp, sizeof tmp, "nm -p %s", file);
	if (rw != strlen(file) + CONST_STRLEN("nm -p ")) {
		g_warning("full path \"%s\" too long, cannot load symbols", file);
		goto done;
	}

	f = popen(tmp, "r");

	if (NULL == f) {
		g_warning("can't run \"%s\": %s", tmp, g_strerror(errno));
		goto done;
	}

	while (fgets(tmp, sizeof tmp, f)) {
		parse_nm(tmp);
	}

	pclose(f);

done:
	g_message("loaded %u symbols from \"%s\"",
		(unsigned) trace_array.count, file);

	trace_sort();

	if (file != NULL && file != argv0)
		free(deconstify_gpointer(file));
}

/**
 * Fill supplied stackframe structure with the backtrace.
 */
void
get_stackframe(struct stackframe *fr)
{
    size_t i;

#define OFF 1	/* Remove ourselves + our caller from stack (first two items) */

    for (
		i = OFF;
		getframeaddr(i + 1) != NULL && i - OFF < G_N_ELEMENTS(fr->stack);
		i++
	) {
        if (NULL == (fr->stack[i - OFF] = getreturnaddr(i)))
			break;
    }

	fr->len = i - OFF;

#undef OFF
}

/**
 * Print stack frame to specified file, using symbolic names if possible.
 */
void
print_stack_frame(FILE *f, const struct frame *fr)
{
	size_t i;

	g_assert(fr != NULL);

	for (i = 0; i < fr->len; i++) {
		const char *where = trace_name(fr->stack[i]);
		fprintf(f, "\t%s\n", where);
		/* Stop as soon as we reach main() before backtracing into libc */
		if (is_strprefix(where, "main+"))	/* HACK ALERT */
			break;
	}
}

/**
 * Print current stack frame to specified file.
 *
 * @attention: only defined when MALLOC_FRAMES,
 * meant to be used as a last resort tool to track memory problems.
 */
void
print_where(FILE *f)
{
	struct stackframe fr;
	size_t i;

	get_stackframe(&fr);

	for (i = 0; i < fr.len; i++) {
		const char *where = trace_name(fr.stack[i]);
		fprintf(f, "\t%s\n", where);
		/* Stop as soon as we reach main() before backtracing into libc */
		if (is_strprefix(where, "main+"))	/* HACK ALERT */
			break;
	}
}

/**
 * Keep track of each distinct frames in the supplied hash table (given
 * by a pointer to the variable which holds it so that we can allocate
 * if if necessary).
 *
 * @return stack frame "atom".
 */
struct frame *
get_frame_atom(hash_table_t **hptr, const struct stackframe *f)
{
	struct frame *fr = NULL;
	hash_table_t *ht;

	ht = *hptr;
	if (NULL == ht)
		*hptr = ht = hash_table_new_full_real(frame_hash, frame_eq);
	else
		fr = hash_table_lookup(ht, f);

	if (fr == NULL) {
		fr = calloc(1, sizeof(*fr));
		memcpy(fr->stack, f->stack, f->len * sizeof f->stack[0]);
		fr->len = f->len;
		if (!hash_table_insert(ht, fr, fr)) {
			g_error("cannot record stack frame atom");
		}
	}

	return fr;
}
#else  /* !MALLOC_FRAMES */
void
print_where(FILE *f)
{
	(void) f;
	/* Empty */
}
#endif /* MALLOC_FRAMES */

/**
 * @struct stats
 *
 * When MALLOC_STATS is supplied, we keep information about the amount
 * of bytes allocated from a single point in the code, and the amount
 * of it that has been freed.
 *
 * When compiling with MALLOC_STATS, it's best to use REMAP_ZALLOC
 * as well since normally zalloc has its own block tracking features
 * that will not be accounted for in the malloc stats.
 */
#ifdef MALLOC_STATS

struct stats {
	const char *file;			/**< Place where allocation took place */
	int line;					/**< Line number */
	int blocks;					/**< Live blocks since last "reset" */
	int total_blocks;			/**< Total live blocks */
	size_t allocated;			/**< Total allocated since last "reset" */
	size_t freed;				/**< Total freed since last "reset" */
	size_t total_allocated;		/**< Total allocated overall */
	size_t total_freed;			/**< Total freed overall */
	ssize_t reallocated;		/**< Total reallocated since last "reset" */
	ssize_t total_reallocated;	/**< Total reallocated overall (algebric!) */
#ifdef MALLOC_FRAMES
	hash_table_t *alloc_frames;		/**< The frames where alloc took place */
	hash_table_t *free_frames;		/**< The frames where free took place */
	hash_table_t *realloc_frames;	/**< The frames where realloc took place */
#endif /* MALLOC_FRAMES */
};

static hash_table_t *stats = NULL; /**< maps stats(file, line) -> stats */

/**
 * Hashing routine for "struct stats".
 * Only the "file" and "line" fields are considered.
 */
static guint
stats_hash(gconstpointer key)
{
	const struct stats *s = key;

	return g_str_hash(s->file) ^ s->line;
}

/**
 * Comparison of two "struct stats" structures.
 * Only the "file" and "line" fields are considered.
 */
static int
stats_eq(gconstpointer a, gconstpointer b)
{
	const struct stats *sa = a, *sb = b;

	return  sa->line == sb->line && 0 == strcmp(sa->file, sb->file);
}
#else	/* !MALLOC_STATS */
#ifdef MALLOC_FRAMES
struct stats {
	hash_table_t *alloc_frames;		/**< The frames where alloc took place */
	hash_table_t *free_frames;		/**< The frames where free took place */
	hash_table_t *realloc_frames;	/**< The frames where realloc took place */
} gst;
#endif
#endif /* MALLOC_STATS */

/**
 * Safe malloc definitions.
 *
 * Optional: MALLOC_SAFE_HEAD to also check the beginning of the block.
 * Optional: MALLOC_TRAILER_LEN > 0 to include additional trailer to blocks.
 * Optional: MALLOC_FREE_ERASE to erase content of blocks we allocated
 * Optional: MALLOC_DUP_FREE to try to detect duplicate free via block tagging
 */
#ifdef MALLOC_SAFE

#ifdef MALLOC_SAFE_HEAD
static inline struct malloc_header *
malloc_header_from_arena(gconstpointer o)
{
	return (gpointer) ((char *) o - SAFE_ARENA_OFFSET);
}
#endif /* MALLOC_SAFE_HEAD */

static inline struct real_malloc_header *
real_malloc_header_from_arena(gconstpointer o)
{
	return (gpointer) ((char *) o - REAL_ARENA_OFFSET);
}

static inline size_t
malloc_safe_size(size_t size)
{
	return size +
#ifdef MALLOC_SAFE_HEAD
		SAFE_ARENA_OFFSET +
#endif
		sizeof(guint32) + MALLOC_TRAILER_LEN;
}

static inline size_t
real_malloc_safe_size(size_t size)
{
	return size + REAL_ARENA_OFFSET + sizeof(guint32) + MALLOC_TRAILER_LEN;
}

/**
 * Mark allocated block trailer.
 */
static void
block_write_trailer(gpointer o, size_t size)
{
	size_t trailer = MALLOC_TRAILER_LEN;
	char *p;

	p = poke_be32(ptr_add_offset(o, size), MALLOC_END_MARK);
	while (trailer--)
		*p++ = MALLOC_TRAILER_MARK;
}

/**
 * Check that block's trailer was not altered.
 *
 * @param o			the user-known pointer to the buffer
 * @param size		the user-known size of the buffer
 * @param file		file where block allocation was done
 * @param line		line number within file where allocation was done
 * @param op_file	file where free()/realloc() operation is happening
 * @param op_line	line where free()/realloc() operation is happening
 * @param showstack	whether to log the stackframe on errors
 *
 * @return whether an error was detected.
 */
static gboolean
block_check_trailer(gconstpointer o, size_t size,
	const char *file, int line, const char *op_file, int op_line,
	gboolean showstack)
{
	gboolean error = FALSE;
	size_t trailer = MALLOC_TRAILER_LEN;
	const char *p;

	if (MALLOC_END_MARK != peek_be32(const_ptr_add_offset(o, size))) {
		error = TRUE;
		g_warning(
			"MALLOC (%s:%d) block 0x%lx (%lu bytes) from %s:%d "
			"has corrupted end mark",
			op_file, op_line, (gulong) o, (unsigned long) size, file, line);
		goto done;
	}

	p = const_ptr_add_offset(o, size + sizeof(guint32));
	while (trailer--) {
		if (*p++ != MALLOC_TRAILER_MARK) {
			error = TRUE;
			g_warning(
				"MALLOC (%s:%d) block 0x%lx (%lu bytes) from %s:%d "
				"has corrupted trailer",
				op_file, op_line, (gulong) o, (unsigned long) size, file, line);
			break;
		}
	}

done:
	if (error && showstack) {
		print_where(stderr);
	}

	return error;
}

#ifdef TRACK_MALLOC
/**
 * With MALLOC_SAFE, each block we own (i.e. which we allocate ourselves)
 * is tagged at the beginning and at the end with magic numbers, to detect
 * buffer overruns.
 *
 * @param o		the user-known pointer to the buffer
 * @param size	the user-known size of the buffer
 */
static void
block_check_marks(gconstpointer o, struct block *b,
	const char *file, int line)
{
	gboolean error = FALSE;

	if (b->corrupted)
		return;			/* Already identified it was corrupted */

	if (!b->owned)
		return;			/* We only track it, we did not allocate it */

#ifdef MALLOC_SAFE_HEAD
	{
		const struct malloc_header *mh = malloc_header_from_arena(o);

		if (mh->start != MALLOC_START_MARK) {
			error = TRUE;
			b->corrupted = TRUE;
			g_warning(
				"MALLOC (%s:%d) block 0x%lx from %s:%d has corrupted start mark",
				file, line, (gulong) o, b->file, b->line);
		}
	}
#endif /* MALLOC_SAFE_HEAD */

	if (block_check_trailer(o, b->size, b->file, b->line, file, line, FALSE)) {
		b->corrupted = TRUE;
		error = TRUE;
	}

	if (error) {
		print_where(stderr);
	}
}
#endif	/* TRACK_MALLOC */

#else	/* !MALLOC_SAFE */
static inline void block_write_trailer(gpointer o, size_t size)
{
	(void) o; (void) size;
}
static inline gboolean block_check_trailer(gconstpointer o, size_t size,
	const char *file, int line, const char *op_file, int op_line,
	gboolean showstack)
{
	(void) o; (void) size; (void) file; (void) line;
	(void) op_file; (void) op_line; (void) showstack;
	return FALSE;
}
#endif	/* MALLOC_SAFE */

/**
 * When MALLOC_FREE_ERASE is set, freed blocks are overwritten to detect
 * accidental reuse of freed memory.
 */
#ifdef MALLOC_FREE_ERASE
#define MALLOC_ERASE_MARK	'Z'	/* 0x5a */

static inline void
block_erase(const void *o, size_t size)
{
	void *p = deconstify_gpointer(o);
	memset(p, MALLOC_ERASE_MARK, size);
}
#else	/* !MALLOC_FREE_ERASE */
#define block_erase(p_, s_)
#endif	/* MALLOC_FREE_ERASE */

/**
 * When MALLOC_DUP_FREE is set, the first integer of the block is marked to
 * allow free() to detect duplicates.
 */
#ifdef MALLOC_DUP_FREE
#define MALLOC_DEAD_MARK	0xdeadbeefU
#define MALLOC_DEAD_CLEAR	0x0

static inline void
block_mark_dead(const void *p, size_t size)
{
	if (size >= sizeof(guint)) {
		*(guint *) p = MALLOC_DEAD_MARK;
	}
}

static inline void
block_clear_dead(const void *p, size_t size)
{
	if (size >= sizeof(guint)) {
		*(guint *) p = MALLOC_DEAD_CLEAR;
	}
}

static inline gboolean
block_is_dead(const void *p, size_t size)
{
	if (size >= sizeof(guint)) {
		return MALLOC_DEAD_MARK == *(guint *) p;
	}

	return FALSE;
}
#endif	/* MALLOC_DUP_FREE */

#if !defined(TRACK_MALLOC) || !defined(MALLOC_DUP_FREE)
#define block_mark_dead(p_, s_)
#define block_clear_dead(p_, s_)
#define block_is_dead(p_, s_)		(FALSE)
#endif /* !TRAC_MALLOC || !MALLOC_DUP_FREE */

/**
 * With MALLOC_PERIODIC, all the allocated blocks (whether they be tracked
 * or allocated directly via real_malloc() and friends)
 */
#ifdef MALLOC_PERIODIC

static gboolean need_periodic;

struct block_check_context {
	size_t total_size;
	size_t foreign_size;
	size_t real_size;
	unsigned total_count;
	unsigned foreign_count;
	unsigned real_count;
	unsigned old_corrupted;
	unsigned new_corrupted;
};

#ifdef TRACK_MALLOC
/**
 * Iterating callback to check a tracked block.
 */
static void
block_check(const void *key, void *value, void *ctx)
{
	struct block_check_context *bc = ctx;
	struct block *b = value;
	gboolean was_corrupted;

	/*
	 * If block is marked as owned, it will be checked later when we
	 * iterate over the "real" ones.
	 */

	if (!b->owned) {
		bc->total_count++;
		bc->total_size = size_saturate_add(bc->total_size, b->size);
		bc->foreign_count++;
		bc->foreign_size = size_saturate_add(bc->foreign_size, b->size);
	}

	was_corrupted = b->corrupted;

#ifdef MALLOC_SAFE
	block_check_marks(key, b, __FILE__, __LINE__);
#else
	(void) key;
#endif

	if (was_corrupted) {
		bc->old_corrupted++;
	} else {
		if (b->corrupted) {
			bc->new_corrupted++;
		}
	}
}
#endif	/* TRACK_MALLOC */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
/**
 * Iterating callback to check a real (untracked) malloc'ed block.
 */
static void
real_check(const void *key, void *value, void *ctx)
{
	struct block_check_context *bc = ctx;
	struct realblock *rb = value;
	void *p = deconstify_gpointer(key);

	bc->total_count++;
	bc->total_size = size_saturate_add(bc->total_size, rb->size);
	bc->real_count++;
	bc->real_size = size_saturate_add(bc->real_size, rb->size);

	if (rb->corrupted) {
		bc->old_corrupted++;
	}

	if (
		!rb->corrupted &&
		block_check_trailer(p, rb->size, "FAKED", 0, _WHERE_, __LINE__, TRUE)
	) {
		bc->new_corrupted++;
		rb->corrupted = TRUE;
	}
	if (block_is_dead(p, rb->size)) {
		g_warning("MALLOC allocated block 0x%lx marked as DEAD", (gulong) p);
	}

#ifdef MALLOC_SAFE
	{
		struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
		if (REAL_MALLOC_MAGIC != rmh->magic) {
			bc->new_corrupted++;
			g_warning("MALLOC corrupted real block magic at 0x%lx (%lu byte%s)",
				(unsigned long) p,
				(unsigned long) rb->size, 1 == rb->size ? "" : "s");
		} else if (rmh->size != rb->size) {
			/* Can indicate memory corruption as well */
			bc->new_corrupted++;
			g_warning("MALLOC size mismatch for real block 0x%lx: "
				"hashtable says %lu byte%s, header says %u",
				(unsigned long) p, (unsigned long) rb->size,
				1 == rb->size ? "" : "s", rmh->size);
		}
	}
#endif	/* MALLOC_SAFE */
}

/**
 * Periodic check to make sure all the known blocks are correct.
 */
static gboolean
malloc_periodic(gpointer unused_obj)
{
	struct block_check_context ctx;
	gboolean checked = FALSE;
	tm_t start, end;
	static unsigned errors;
	char total_size[SIZE_FIELD_MAX];
	char foreign_size[SIZE_FIELD_MAX];
	char real_size[SIZE_FIELD_MAX];
	
	(void) unused_obj;

	if (0 == errors) {
		g_message("malloc periodic check starting...");
	} else {
		g_message("malloc periodic check starting... [%u error%s already]",
			errors, 1 == errors ? "" : "s");
	}

	memset(&ctx, 0, sizeof ctx);
	tm_now_exact(&start);

#ifdef TRACK_MALLOC
	checked = TRUE;
	if (blocks != NULL)
		hash_table_foreach(blocks, block_check, &ctx);
#endif
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
		checked = TRUE;
		hash_table_foreach(reals, real_check, &ctx);
#endif

	if (!checked) {
		g_message("malloc periodic: nothing to check, disabling.");
		return FALSE;
	}

	tm_now_exact(&end);

	short_size_to_string_buf(ctx.total_size, FALSE,
		total_size, sizeof total_size);
	short_size_to_string_buf(ctx.foreign_size, FALSE,
		foreign_size, sizeof foreign_size);
	short_size_to_string_buf(ctx.real_size, FALSE,
		real_size, sizeof real_size);

	if (0 == ctx.old_corrupted && 0 == ctx.new_corrupted) {
		g_message("malloc periodic check done (%u msecs): "
			"total: %u [%s], foreign: %u [%s], real: %u [%s]",
			(unsigned) tm_elapsed_ms(&end, &start),
			ctx.total_count, total_size,
			ctx.foreign_count, foreign_size,
			ctx.real_count, real_size);
	} else {
		if (ctx.new_corrupted) {
			errors++;
		}
		g_warning("malloc periodic check done (%u msecs): %s"
			"total: %u [%s], foreign: %u [%s], real: %u [%s], "
			"NEWLY CORRUPTED: %u (%u old)",
			(unsigned) tm_elapsed_ms(&end, &start),
			0 == ctx.new_corrupted ? "" : "WATCH OUT ",
			ctx.total_count, total_size,
			ctx.foreign_count, foreign_size,
			ctx.real_count, real_size,
			ctx.new_corrupted, ctx.old_corrupted);
	}

	return TRUE;
}

static void
install_malloc_periodic(void)
{
	need_periodic = FALSE;
	cq_periodic_add(callout_queue, MALLOC_PERIOD, malloc_periodic, NULL);
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */
#endif	/* MALLOC_PERIODIC */

#ifdef TRACK_MALLOC
/**
 * Ensure we keep no stale trace of any block at the specified address.
 */
static void
block_check_missed_free(const void *p, const char *file, int line)
{
	struct block *b;

	b = hash_table_lookup(blocks, p);
	if (b != NULL) {
		g_warning("MALLOC (%s:%d) reusing %sblock 0x%lx (%lu byte%s) "
			"from %s:%d, missed its freeing",
			file, line, b->owned ? "owned " : "foreign ",
			(gulong) p, (gulong) b->size, 1 == b->size ? "" : "s",
			b->file, b->line);
		print_where(stderr);

		b->owned = FALSE;					/* No need to check markers */
		free_record(p, _WHERE_, __LINE__);	/* Will remove from ``blocks'' */
	}
}
#endif	/* TRACK_MALLOC */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
/**
 * Ensure we keep no stale trace of any block at the specified address.
 */
static void
real_check_missed_free(void *p)
{
	struct realblock *rb;

	rb = hash_table_lookup(reals, p);
	if (rb != NULL) {
		if (not_leaking != NULL) {
			hash_table_remove(not_leaking, p);
		}
#ifdef TRACK_MALLOC
		if (blocks != NULL) {
			struct block *b;

			b = hash_table_lookup(blocks, p);
			if (b != NULL) {
				/*
				 * Same logic as in block_check_missed_free().
				 * Duplicated in order to avoid a second warning when we
				 * reuse the address and need to track it.
				 */

				g_warning("MALLOC reusing %s block 0x%lx (%lu byte%s) "
					"from %s:%d, missed its freeing",
					b->owned ? "owned" : "foreign",
					(gulong) p, (gulong) rb->size, 1 == rb->size ? "" : "s",
					b->file, b->line);
				b->owned = FALSE;
				free_record(p, _WHERE_, __LINE__);
			}
		}
#else	/* !TRACK_MALLOC */
		g_warning("MALLOC reusing real block 0x%lx (%lu byte%s), "
			"missed its freeing",
			(gulong) p, (gulong) rb->size, 1 == rb->size ? "" : "s");
#endif	/* TRACK_MALLOC */
		g_warning("current_frame:");
		print_where(stderr);
#ifdef MALLOC_FRAMES
		g_warning("allocation frame:");
		print_stack_frame(stderr, rb->alloc);
#endif
		hash_table_remove(reals, p);
		free(rb);
	}
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

/**
 * Calls real malloc(), no tracking.
 */
void *
real_malloc(size_t size)
{
	void *o;

#ifdef MALLOC_PERIODIC
	if (need_periodic && NULL != callout_queue)
		install_malloc_periodic();
#endif

#ifdef MALLOC_SAFE
	{
		size_t len = real_malloc_safe_size(size);
		struct real_malloc_header *rmh;

		rmh = malloc(len);

		if (rmh == NULL)
			g_error("unable to allocate %lu bytes", (gulong) size);

		rmh->magic = REAL_MALLOC_MAGIC;
		rmh->size = size;
		o = rmh->arena;
		block_write_trailer(o, size);
	}
#else  /* !MALLOC_SAFE */

	o = malloc(size);

#endif /* MALLOC_SAFE */

	if (o == NULL)
		g_error("unable to allocate %lu bytes", (gulong) size);

	block_clear_dead(o, size);

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	{
		struct realblock *rb;

		rb = calloc(1, sizeof *rb);
		rb->size = size;
		real_check_missed_free(o);
		if (!hash_table_insert(reals, o, rb)) {
			g_error("MALLOC cannot record real block 0x%lx", (gulong) o);
		}
#ifdef MALLOC_FRAMES
		{
			struct stackframe f;
			struct frame *fr;

			get_stackframe(&f);
			fr = get_frame_atom(&gst.alloc_frames, &f);
			fr->count += size;
			fr->total_count += size;
			fr->blocks++;
			rb->alloc = fr;
		}
#endif	/* MALLOC_FRAMES */
	}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

	return o;
}

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || defined(MALLOC_VTABLE)

#ifdef MALLOC_SAFE
/**
 * Free a block allocated via real_malloc() with additional header magic.
 */
static void
real_check_free(void *p)
{
	struct real_malloc_header *rmh = real_malloc_header_from_arena(p);

	if (REAL_MALLOC_MAGIC != rmh->magic)
		g_warning("MALLOC free(): corrupted real block magic at 0x%lx",
			(unsigned long) p);

	free(rmh);
}
#endif	/* MALLOC_SAFE */

/**
 * Calls real free(), no tracking.
 * Block must have been allocated via real_malloc().
 */
static void
real_free(void *p)
{
	size_t size = 0;
	gboolean owned = FALSE;
	gboolean real = FALSE;
	void *start = p;
#ifdef TRACK_MALLOC
	struct block *b = NULL;
#endif

#ifdef MALLOC_PERIODIC
	if (need_periodic && NULL != callout_queue)
		install_malloc_periodic();
#endif

	if (NULL == p)
		return;

#ifdef TRACK_MALLOC
	if (blocks) {
		b = hash_table_lookup(blocks, p);
#ifdef MALLOC_SAFE_HEAD
		/*
		 * We're given the additional malloc header to free for all the
		 * blocks we own.  This is only to handle direct real_free() calls
		 * on blocks allocated through malloc_track(): in that case, the
		 * user pointer mh->arena would be given, but we have to free
		 * the previous "mh" address instead.
		 *
		 * When coming from free_track(), we handle this already and supply
		 * the proper address to real_free().
		 */

		if (b != NULL && b->owned) {
			start = malloc_header_from_arena(p);	/* Physical start */
		}
#endif	/* MALLOC_SAFE_HEAD */
	}

	/*
	 * Because of glib's vtable setup, we may end-up here freeing something we
	 * allocated via malloc() and tracked, gave to GTK, and then GTK frees
	 * it directly via g_free(), which calls us.
	 */

	if (NULL == b) {
		if (not_leaking != NULL)
			hash_table_remove(not_leaking, p);
	} else {
		size = b->size;
		owned = b->owned;
		free_record(p, _WHERE_, __LINE__);	/* p is an "user" address */
	}
#endif
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	{
		struct realblock *rb = hash_table_lookup(reals, start);

		if (rb != NULL) {
			hash_table_remove(reals, start);
			block_check_trailer(start, rb->size,
				"FAKED", 0, _WHERE_, __LINE__, TRUE);
			block_erase(start, rb->size);
			block_mark_dead(start, rb->size);
			free(rb);
			real = TRUE;		/* Was allocated via real_malloc() */
		} else {
			if (block_is_dead(start, sizeof(guint))) {
				g_warning("MALLOC probable duplicate free of 0x%lx", (gulong) p);
				print_where(stderr);
				g_error("MALLOC invalid free()");
			} else {
				gboolean ok = FALSE;
#ifdef MALLOC_VTABLE
				/* See comment in free_track() */
				ok = hash_table_lookup(unknowns, p) != NULL;
#endif
				if (!ok) {
					g_warning("MALLOC freeing unknown block 0x%lx",
						(unsigned long) p);
					print_where(stderr);
				}
			}
		}
	}
#else
	(void) size;
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

#ifdef MALLOC_SAFE
	/*
	 * Because of glib's vtable setup, we may end-up here freeing something we
	 * allocated via malloc() and tracked.
	 *
	 * If we have a tracking block, it was allocated via real_malloc().
	 * Otherwise, it was allocated via real_malloc() with a real block header
	 * if it is marked "real".
	 */

	if (owned) {
#ifdef MALLOC_SAFE_HEAD
		struct malloc_header *mh = malloc_header_from_arena(p);
		real_check_free(mh);
#else
		real_check_free(p);
#endif	/* MALLOC_SAFE_HEAD */
	} else if (real) {
		real_check_free(p);
	} else
#endif	/* MALLOC_SAFE */
	{
		free(p);		/* NOT g_free(): would recurse if MALLOC_VTABLE */
	}
}
#endif /* TRACK_MALLOC || TRACK_ZALLOC || MALLOC_VTABLE */

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)
/**
 * Wraps strdup() call so that real_free() can be used on the result.
 */
static char *
real_strdup(const char *s)
{
	void *p;
	size_t len;

	if (s == NULL)
		return NULL;

	len = strlen(s);
	p = real_malloc(len + 1);
	memcpy(p, s, len + 1);		/* Also copy trailing NUL */

	return p;
}

/**
 * Calls real realloc(), no tracking.
 */
static void *
real_realloc(void *ptr, size_t size)
{
	void *result;
	void *p = ptr;
#ifdef TRACK_MALLOC
	struct block *b = NULL;
#endif
#ifdef MALLOC_PERIODIC
	if (need_periodic && NULL != callout_queue)
		install_malloc_periodic();
#endif

	if (p == NULL)
		return real_malloc(size);

	if (0 == size) {
		real_free(p);
		return NULL;
	} else {
		void *n;

#ifdef TRACK_MALLOC
		if (blocks) {
			b = hash_table_lookup(blocks, p);
#ifdef MALLOC_SAFE_HEAD
			/*
			 * We're given the additional malloc header to reallocate for
			 * blocks we own.
			 */
			if (NULL == b) {
				struct malloc_header *mh = p;
				b = hash_table_lookup(blocks, mh->arena);
			}
#endif	/* MALLOC_SAFE_HEAD */
		}
#endif	/* TRACK_MALLOC */

#if defined(TRACK_MALLOC) && defined(MALLOC_SAFE)
		{
			struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
			size_t len = real_malloc_safe_size(size);

			if (REAL_MALLOC_MAGIC != rmh->magic)
				g_error("MALLOC realloc(): corrupted real block magic at 0x%lx",
					(unsigned long) p);

			block_check_trailer(p, rmh->size,
				"FAKED", 0, _WHERE_, __LINE__, TRUE);

			rmh = realloc(rmh, len);
			if (rmh == NULL) {
				result = n = NULL;
			} else {
				g_assert(REAL_MALLOC_MAGIC == rmh->magic);

				rmh->size = size;
				result = n = rmh->arena;
				block_write_trailer(n, size);
#ifdef MALLOC_SAFE_HEAD
				/*
				 * Adjust variables if we were given an owned block:
				 * ``p'' is the user-start of the old block
				 * ``n'' is the user-start of the new block
				 */
				if (b != NULL && b->owned) {
					struct malloc_header *mh = n;
					n = mh->arena;
					mh = p;
					p = mh->arena;
				}
#endif	/* MALLOC_SAFE_HEAD */
			}
		}
#else	/* !(TRACK_MALLOC && MALLOC_SAFE) */
		result = n = realloc(p, size);
#endif	/* TRACK_MALLOC && MALLOC_SAFE */

		if (n == NULL)
			g_error("cannot realloc block into a %lu-byte one", (gulong) size);

#ifdef TRACK_MALLOC
		if (n != p && not_leaking != NULL) {
			if (hash_table_remove(not_leaking, p)) {
				hash_table_insert(not_leaking, n, GINT_TO_POINTER(1));
			}
		}

		if (b != NULL) {
			b->size = size;
			if (n != p && blocks != NULL) {
				hash_table_remove(blocks, p);
				block_check_missed_free(n, "FAKED", 0);
				if (!hash_table_insert(blocks, n, b)) {
					g_error("MALLOC cannot track reallocated block 0x%lx",
						(gulong) n);
				}
			}
		}
#endif	/* TRACK_MALLOC */
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
		{
			struct realblock *rb = hash_table_lookup(reals, ptr);

			if (NULL == rb) {
				g_warning("MALLOC reallocated unknown block 0x%lx",
					(unsigned long) p);
				print_where(stderr);
				g_error("MALLOC invalid realloc()");
			}

			if (result != ptr) {
				hash_table_remove(reals, ptr);
				real_check_missed_free(result);
				if (!hash_table_insert(reals, result, rb)) {
					g_error("MALLOC cannot record reallocated block 0x%lx",
						(gulong) result);
				}
			}
			rb->size = size;
		}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

		return result;
	}
}
#endif	/* TRACK_MALLOC || TRACK_ZALLOC */

#ifdef TRACK_MALLOC

#ifdef MALLOC_FRAMES
static hash_table_t *alloc_points; /**< Maps a block to its allocation frame */
#endif

/**
 * Wrapper to real malloc().
 */
static void *
real_calloc(size_t nmemb, size_t size)
{
	void *p;

	if (nmemb > 0 && size > 0 && size < ((size_t) -1) / nmemb) {
		size_t len = nmemb * size;

		p = real_malloc(len);
		memset(p, 0, len);
	} else {
		p = NULL;
	}

	return p;
}

/**
 * Called at first allocation to initialize tracking structures,.
 */
static void
track_init(void)
{
	blocks = hash_table_new_real();
	not_leaking = hash_table_new_real();

#ifdef MALLOC_STATS
	stats = hash_table_new_full_real(stats_hash, stats_eq);
#endif
#ifdef MALLOC_FRAMES
	alloc_points = hash_table_new_real();
#endif

	init_time = reset_time = tm_time_exact();
}

/**
 * malloc_log_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void
malloc_log_block(const void *k, void *v, gpointer leaksort)
{
	const struct block *b = v;

	if (hash_table_lookup(not_leaking, k))
		return;

	g_warning("leaked block 0x%lx (%lu bytes) from \"%s:%d\"",
		(gulong) k, (gulong) b->size, b->file, b->line);

	leak_add(leaksort, b->size, b->file, b->line);

	if (b->reallocations) {
		struct block *r = b->reallocations->data;
		guint cnt = g_slist_length(b->reallocations);

		g_warning("   (realloc'ed %u time%s, lastly from \"%s:%d\")",
			cnt, cnt == 1 ? "" : "s", r->file, r->line);
	}

#ifdef MALLOC_FRAMES
	{
		struct frame *fr;

		fr = hash_table_lookup(alloc_points, k);
		if (fr == NULL)
			g_warning("no allocation record for 0x%lx from %s:%d?",
				(gulong) k, b->file, b->line);
		else {

			if (trace_array.count) {
				g_message("block 0x%lx (out of %u) allocated from:",
					(gulong) k, (unsigned) fr->blocks);
				print_stack_frame(stderr, fr);
			} else {
				size_t i;
				char buf[12 * FRAME_DEPTH];
				size_t rw = 0;

				buf[0] = '\0';
				for (i = 0; i < fr->len; i++) {
					rw += gm_snprintf(&buf[rw], sizeof buf - rw,
						"0x%lx ", (gulong) fr->stack[i]);
				}
				g_message("block 0x%lx allocated from %s", (gulong) k, buf);
			}
		}
	}
#endif	/* MALLOC_FRAMES */
}

#ifdef MALLOC_LEAK_ALL
/**
 * malloc_fill_ignored		-- hash table iterator callback
 *
 * Insert all the values we see in the "ignored" table passed as argument.
 */
static void
malloc_fill_ignored(const void *u_k, void *v, gpointer ignored)
{
	hash_table_t *ign = ignored;

	(void) u_k;

	hash_table_insert(ign, v, GINT_TO_POINTER(1));
}

/**
 * Context passed to the malloc_log_real_block() iterator.
 */
struct log_real_ctx {
	hash_table_t *ignored;
	struct leak_set *ls;
};

/**
 * malloc_log_real_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void
malloc_log_real_block(const void *k, void *v, gpointer data)
{
	const struct realblock *rb = v;
	struct log_real_ctx *ctx = data;
	const void *p = k;

	if (hash_table_lookup(ctx->ignored, p))
		return;			/* Address of a an internal data structure */

#ifdef MALLOC_SAFE_HEAD
	/*
	 * Adjust the arena start if pointing to a block we own: the real block
	 * is structured like this.
	 *
	 *               user-visible pointer
	 *               v
	 *    +-----+----+-------------------+
	 *    | RMH | MH | arena (user data) |
	 *    +-----+----+-------------------+
	 *    ^     ^
	 *    phys  real
	 *
	 * We are pointing to "real" but the physical start of the block is "phys".
	 * The leading RMH header is struct real_malloc_header.
	 *
	 * However, malloc_track() will structure the arena of the physical
	 * block by craming a header (the MH header, a struct malloc_header) and
	 * returning a user-visible pointer that is after MH.
	 *
	 * If non-leaking indication was given for this block, it was with the
	 * user-visible pointer, so we need to shift the address, both for
	 * probing and for logging, provided the block is known to be owned,
	 * i.e. that it was explicitly allocated from malloc_track() initially.
	 */

	if (blocks != NULL) {
		const struct malloc_header *mh = k;
		struct block *b;

		b = hash_table_lookup(blocks, mh->arena);
		if (b != NULL && b->owned) {
			p = mh->arena;
		}
	}
#endif

	if (hash_table_lookup(not_leaking, p))
		return;

	if (hash_table_lookup(blocks, p))
		return;		/* Was already logged through malloc_log_block() */

	g_warning("leaked block 0x%lx (%lu bytes)", (gulong) p, (gulong) rb->size);

	leak_add(ctx->ls, rb->size, "FAKED", 0);

#ifdef MALLOC_FRAMES
	if (trace_array.count) {
		g_message("block 0x%lx (out of %u) allocated from:",
			(gulong) p, (unsigned) rb->alloc->blocks);
		print_stack_frame(stderr, rb->alloc);
	} else {
		size_t i;
		char buf[12 * FRAME_DEPTH];
		size_t rw = 0;
		struct frame *fr = rb->alloc;

		buf[0] = '\0';
		for (i = 0; i < fr->len; i++) {
			rw += gm_snprintf(&buf[rw], sizeof buf - rw,
				"0x%lx ", (gulong) fr->stack[i]);
		}
		g_message("block 0x%lx allocated from %s", (gulong) p, buf);
	}
#endif	/* MALLOC_FRAMES */
}
#endif	/* MALLOC_LEAK_ALL */

/**
 * Flag object ``o'' as "not leaking" if not freed at exit time.
 * @return argument ``o''.
 */
gpointer
malloc_not_leaking(gconstpointer o)
{
	/*
	 * Could be called on memory that was not allocated dynamically or which
	 * we do not know anything about. If so, just ignore silently.
	 */

	if (hash_table_lookup(reals, o)) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
	}
#ifdef MALLOC_SAFE_HEAD
	else {
		const void *p = malloc_header_from_arena(o);
		if (hash_table_lookup(reals, p)) {
			hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
		}
	}
#endif	/* MALLOC_SAFE_HEAD */
	return deconstify_gpointer(o);
}

/**
 * Record object `o' allocated at `file' and `line' of size `s'.
 * @return argument `o'.
 */
gpointer
malloc_record(gconstpointer o, size_t sz, gboolean owned,
	const char *file, int line)
{
	struct block *b;
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	if (o == NULL)			/* In case it's called externally */
		return NULL;

	if (blocks == NULL)
		track_init();

	b = real_calloc(1, sizeof(*b));
	if (b == NULL)
		g_error("unable to allocate %u bytes", (unsigned) sizeof(*b));

	b->file = short_filename(deconstify_gpointer(file));
	b->line = line;
	b->size = sz;
	b->reallocations = NULL;
	b->owned = owned;

	/**
	 * It can happen that we track the allocation of a block somewhere
	 * but the freeing happens somewhere we either we forgot to include
	 * "override.h", or happens in some library (e.g. in GTK+) where we
	 * can't record it.
	 *
	 * If we're "lucky" enough to see the address of such a block being
	 * reused again, then it has necessarily been freed, or malloc() would
	 * not reuse it again!  Fake a free from "FAKED:0".
	 */

	block_check_missed_free(o, file, line);

	if (!hash_table_insert(blocks, o, b)) {
		g_error("MALLOC cannot track block 0x%lx", (gulong) o);
	}

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL) {
			st = real_calloc(1, sizeof(*st));
			st->file = b->file;
			st->line = line;
			hash_table_insert(stats, st, st);
		}

		st->total_blocks++;
		st->blocks++;
		st->allocated += sz;
		st->total_allocated += sz;
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	{
		struct stackframe f;
		struct frame *fr;

		get_stackframe(&f);
		fr = get_frame_atom(st ? &st->alloc_frames : &gst.alloc_frames, &f);

		fr->count += sz;
		fr->total_count += sz;
		fr->blocks++;

		hash_table_insert(alloc_points, o, fr);
	}
#endif /* MALLOC_FRAMES */

	return deconstify_gpointer(o);
}

/**
 * Allocate `s' bytes.
 */
gpointer
malloc_track(size_t size, const char *file, int line)
{
	gpointer o;

#ifdef MALLOC_SAFE
	{
		size_t len = malloc_safe_size(size);
#ifdef MALLOC_SAFE_HEAD
		struct malloc_header *mh;

		mh = real_malloc(len);

		if (mh == NULL)
			g_error("unable to allocate %lu bytes", (gulong) size);

		mh->start = MALLOC_START_MARK;
		o = mh->arena;
#else  /* !MALLOC_SAFE_HEAD */
		o = real_malloc(len);
#endif /* MALLOC_SAFE_HEAD */
		block_write_trailer(o, size);
	}
#else  /* !MALLOC_SAFE */
	o = real_malloc(size);
#endif /* MALLOC_SAFE */

	if (o == NULL)
		g_error("unable to allocate %lu bytes", (gulong) size);

	block_clear_dead(o, size);

	return malloc_record(o, size, TRUE, file, line);
}

/**
 * Allocate `s' bytes, zero the allocated zone.
 */
gpointer
malloc0_track(size_t size, const char *file, int line)
{
	gpointer o;

	o = malloc_track(size, file, line);
	memset(o, 0, size);

	return o;
}

/**
 * Record freeing of allocated block.
 * @return TRUE if the block was owned
 */
static gboolean
free_record(gconstpointer o, const char *file, int line)
{
	struct block *b;
	const void *k;
	void *v;
	GSList *l;
	gboolean owned = FALSE;
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	if (NULL == o)
		return FALSE;

	if (blocks == NULL || !(hash_table_lookup_extended(blocks, o, &k, &v))) {
		if (hash_table_lookup(reals, o))
			return FALSE;

		if (block_is_dead(o, 4)) {
			g_error("MALLOC (%s:%d) duplicate free of 0x%lx",
				file, line, (gulong) o);
		}

		g_warning("MALLOC (%s:%d) attempt to free block at 0x%lx twice?",
			file, line, (gulong) o);
		print_where(stderr);
		g_error("MALLOC free() of unknown address 0x%lx", (gulong) o);
		return FALSE;
	}

	b = v;
	g_assert(o == k);

	if (b->owned) {
		owned = TRUE;

#ifdef MALLOC_SAFE
		block_check_marks(o, b, file, line);
#endif

		/*
		 * We can only erase and mark as dead blocks that we "own", i.e. for
		 * which we did not just record the address.  Indeed, blocks we do
		 * not own are not yet freed when this routine is called: for now we're
		 * just breaking the association between the address and the block
		 * information, so that no leak is reported on that block.
		 */

		block_erase(o, b->size);
		block_mark_dead(o, b->size);
	}

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL)
			g_warning(
				"MALLOC (%s:%d) no alloc record of block 0x%lx from %s:%d?",
				file, line, (gulong) o, b->file, b->line);
		else {
			/* Count present block size, after possible realloc() */
			st->freed += b->size;
			st->total_freed += b->size;
			if (st->total_blocks > 0)
				st->total_blocks--;
			else
				g_warning(
					"MALLOC (%s:%d) live # of blocks was zero at free time?",
					file, line);

			/* We could free blocks allocated before "reset", don't warn */
			if (st->blocks > 0)
				st->blocks--;
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stackframe f;
		struct frame *fr;

		get_stackframe(&f);
		fr = get_frame_atom(&st->free_frames, &f);

		fr->count += b->size;			/* Counts actual size, not original */
		fr->total_count += b->size;
	}
	hash_table_remove(alloc_points, o);
#endif /* MALLOC_FRAMES */

	hash_table_remove(blocks, o);
	hash_table_remove(not_leaking, o);

	for (l = b->reallocations; l; l = g_slist_next(l)) {
		struct block *r = l->data;
		g_assert(r->reallocations == NULL);
		real_free(r);
	}
	g_slist_free(b->reallocations);

	real_free(b);
	return owned;
}

/**
 * Free allocated block.
 */
void
free_track(gpointer o, const char *file, int line)
{
	struct block *b;

	if (blocks != NULL && (b = hash_table_lookup(blocks, o))) {
		if (free_record(o, file, line)) {
#ifdef MALLOC_SAFE_HEAD
			struct malloc_header *mh = malloc_header_from_arena(o);
			real_free(mh);
#else
			real_free(o);
#endif /* MALLOC_SAFE_HEAD */
		} else if (hash_table_lookup(reals, o)) {
			real_free(o);
		} else {
			/*
			 * Will go to real_free() if MALLOC_VTABLE and could cause a
			 * warning "freeing unknown block" because the block was not
			 * allocated by real_malloc() but is tracked nonetheless since
			 * it has been explicitly recorded.
			 *
			 * The block record has been freed already, so to avoid spurious
			 * warnings for perfectly normal situations, we enter an exception
			 * for this address so that real_free() will not complain.
			 * Obviously we can't change the signature of real_free() to add
			 * a parameter telling it it's OK to free an unknown block.
			 */
#ifdef MALLOC_VTABLE
			hash_table_insert(unknowns, o, GUINT_TO_POINTER(1));
			g_free(o);
			hash_table_remove(unknowns, o);
#else
			g_free(o);
#endif	/* MALLOC_VTABLE */
		}
	} else {
		free_record(o, file, line);
		if (hash_table_lookup(reals, o)) {
			real_free(o);
		} else {
			g_free(o);		/* Will go to real_free() if MALLOC_VTABLE */
		}
	}
}

/**
 * Free NULL-terminated vector of strings, and the vector.
 */
void
strfreev_track(char **v, const char *file, int line)
{
	char *x;
	char **iv = v;

	while ((x = *iv++))
		free_track(x, file, line);

	free_track(v, file, line);
}

/**
 * Update data structures to record that block `o' was re-alloced into
 * a block of `s' bytes at `n'.
 */
static gpointer
realloc_record(gpointer o, gpointer n, size_t size, const char *file, int line)
{
	gboolean blocks_updated = FALSE;
	struct block *b;
	struct block *r;
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	g_assert(n);

	if (blocks == NULL)
		track_init();

	if (NULL == (b = hash_table_lookup(blocks, o))) {
		/*
		 * If we went through real_realloc() via realloc_track() because we
		 * owned the block, then the old pointer was removed and the new
		 * one inserted already: check that the new pointer is in there.
		 */

		if (NULL != (b = hash_table_lookup(blocks, n))) {
			blocks_updated = TRUE;
		} else {
			g_error("MALLOC (%s:%d) attempt to realloc freed block at 0x%lx?",
				file, line, (gulong) o);
			/* In case the g_error() above is non-fatal or is a g_warning() */
			return malloc_record(n, size, FALSE, file, line);
		}
	}

	r = real_calloc(sizeof(*r), 1);
	if (r == NULL)
		g_error("unable to allocate %u bytes", (unsigned) sizeof(*r));

	r->file = short_filename(deconstify_gpointer(file));
	r->line = line;
	r->size = b->size;			/* Previous size before realloc */
	r->reallocations = NULL;

	/* Put last realloc at head */
	b->reallocations = g_slist_prepend(b->reallocations, r);
	b->size = size;

	if (n != o) {
		hash_table_remove(blocks, o);
		if (!blocks_updated) {
			block_check_missed_free(n, file, line);
			if (!hash_table_insert(blocks, n, b)) {
				g_error("MALLOC cannot track reallocated block 0x%lx",
					(gulong) n);
			}
		}
		if (not_leaking != NULL && hash_table_remove(not_leaking, o)) {
			hash_table_insert(not_leaking, n, GINT_TO_POINTER(1));
		}
	}

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL)
			g_warning(
				"MALLOC (%s:%d) no alloc record of block 0x%lx from %s:%d?",
				file, line, (gulong) o, b->file, b->line);
		else {
			/* We store variations in size, as algebric quantities */
			st->reallocated += b->size - r->size;
			st->total_reallocated += b->size - r->size;
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stackframe f;
		struct frame *fr;

		get_stackframe(&f);
		fr = get_frame_atom(&st->realloc_frames, &f);

		fr->count += b->size - r->size;
		fr->total_count += b->size - r->size;
	}
	if (n != o) {
		struct frame *fra = hash_table_lookup(alloc_points, o);
		if (fra) {
			/* Propagate the initial allocation frame through reallocs */
			hash_table_remove(alloc_points, o);
			hash_table_insert(alloc_points, n, fra);
		} else {
			g_warning(
				"MALLOC lost allocation frame for 0x%lx at %s:%d -> 0x%lx",
				(gulong) o, b->file, b->line, (gulong) n);
		}
	}
#endif /* MALLOC_FRAMES */

	return n;
}

/**
 * Realloc object `o' to `size' bytes.
 */
gpointer
realloc_track(gpointer o, size_t size, const char *file, int line)
{
	if (o == NULL)
		return malloc_track(size, file, line);

	if (0 == size) {
		free_track(o, file, line);
		return NULL;
	} else {
		gpointer n;

#ifdef MALLOC_SAFE
		struct block *b;

		if (blocks != NULL && (b = hash_table_lookup(blocks, o))) {
			if (b->owned) {
				size_t total = malloc_safe_size(size);
#ifdef MALLOC_SAFE_HEAD
				struct malloc_header *mh = malloc_header_from_arena(o);

				block_check_marks(o, b, file, line);
				mh = real_realloc(mh, total);

				if (mh == NULL) {
					g_error("cannot realloc block into a %lu-byte one",
						(gulong) size);
				}

				mh->start = MALLOC_START_MARK;
				n = mh->arena;
#else  /* !MALLOC_SAFE_HEAD */
				n = real_realloc(o, total);
#endif /* MALLOC_SAFE_HEAD */
				block_write_trailer(n, size);
				/* ``o'' was removed from ``blocks'' by real_realloc() */
			} else {
				n = realloc(o, size);
			}
		} else {
			n = real_realloc(o, size);
		}
#else  /* !MALLOC_SAFE */
		n = real_realloc(o, size);
#endif /* MALLOC_SAFE */

		if (n == NULL)
			g_error("cannot realloc block into a %lu-byte one", (gulong) size);

		return realloc_record(o, n, size, file, line);
	}
}

/**
 * Duplicate buffer `p' of length `size'.
 */
gpointer
memdup_track(gconstpointer p, size_t size, const char *file, int line)
{
	gpointer o;

	if (p == NULL)
		return NULL;

	o = malloc_track(size, file, line);
	memcpy(o, p, size);

	return o;
}

/**
 * Duplicate string `s'.
 */
char *
strdup_track(const char *s, const char *file, int line)
{
	gpointer o;
	size_t len;

	if (s == NULL)
		return NULL;

	len = strlen(s);
	o = malloc_track(len + 1, file, line);
	memcpy(o, s, len + 1);		/* Also copy trailing NUL */

	return o;
}

/**
 * Duplicate string `s', on at most `n' chars.
 */
char *
strndup_track(const char *s, size_t n, const char *file, int line)
{
	gpointer o;
	char *q;

	if (s == NULL)
		return NULL;

	o = malloc_track(n + 1, file, line);
	q = o;
	while (n-- > 0 && '\0' != (*q = *s++)) {
		q++;
	}
	*q = '\0';

	return o;
}

/**
 * Join items in `vec' with `s' in-between.
 */
char *
strjoinv_track(const char *s, char **vec, const char *file, int line)
{
	char *o;

	o = g_strjoinv(s, vec);

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
}

/**
 * The internal implementation of a vectorized g_strconcat().
 */
static char *
m_strconcatv(const char *s, va_list args)
{
	char *res;
	char *add;
	size_t size;

	size = strlen(s) + 1;
	res = real_malloc(size);
	if (NULL == res)
		g_error("out of memory");

	memcpy(res, s, size);

	while ((add = va_arg(args, char *))) {
		size_t len = strlen(add);

		if (len > 0) {
			res = real_realloc(res, size + len);
			if (NULL == res)
				g_error("out of memory");

			memcpy(&res[size - 1], add, len + 1);	/* Includes trailing NULL */
			size += len;
		}
	}

	return res;
}

/**
 * Perform string concatenation, returning newly allocated string.
 */
char *
strconcat_track(const char *file, int line, const char *s, ...)
{
	va_list args;
	char *o;

	va_start(args, s);
	o = m_strconcatv(s, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
}

/**
 * Perform printf into newly allocated string.
 */
char *
strdup_printf_track(const char *file, int line, const char *fmt, ...)
{
	va_list args;
	char *o;

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
}

/**
 * Perform a g_strplit() operation, tracking all returned strings.
 */
char **
strsplit_track(const char *s, const char *d, size_t m,
	const char *file, int line)
{
	char **v;
	char **iv;
	char *x;

	v = g_strsplit(s, d, m);
	malloc_record(v, (m + 1) * sizeof(char *), FALSE, file, line);

	iv = v;
	while ((x = *iv++))
		malloc_record(x, strlen(x) + 1, FALSE, file, line);

	return v;
}

/**
 * Record string `s' allocated at `file' and `line'.
 * @return argument `s'.
 */
char *
string_record(const char *s, const char *file, int line)
{
	if (s == NULL)
		return NULL;

	return malloc_record(s, strlen(s) + 1, FALSE, file, line);
}

/**
 * Wrapper over g_hash_table_new() to track allocation of hash tables.
 */
GHashTable *
hashtable_new_track(GHashFunc h, GCompareFunc y, const char *file, int line)
{
	const size_t size = 7 * sizeof(void *);	/* Estimated size */
	GHashTable *o;

	o = g_hash_table_new(h, y);
	return malloc_record(o, size, FALSE, file, line);
}

/**
 * Wrapper over g_hash_table_destroy() to track destruction of hash tables.
 */
void
hashtable_destroy_track(GHashTable *h, const char *file, int line)
{
	free_record(h, file, line);
	g_hash_table_destroy(h);
}

/**
 * Wrapper over hash_list_new().
 */
hash_list_t *
hash_list_new_track(
	GHashFunc hash_func, GEqualFunc eq_func, const char *file, int line)
{
	return malloc_record(
		hash_list_new(hash_func, eq_func),
		28,				/* Approx. size */
		FALSE,
		file, line);
}

/**
 * Wrapper over hash_list_free().
 */
void
hash_list_free_track(hash_list_t **hl_ptr, const char *file, int line)
{
	if (*hl_ptr) {
		free_record(*hl_ptr, file, line);
		hash_list_free(hl_ptr);
	}
}

/***
 *** List trackers, to unveil hidden linkable allocation.
 ***/

/**
 * Record GSList `list' allocated at `file' and `line'.
 * @return argument `list'.
 */
GSList *
gslist_record(const GSList * const list, const char *file, int line)
{
	const GSList *iter;

	for (iter = list; NULL != iter; iter = g_slist_next(iter)) {
		malloc_record(iter, sizeof *iter, FALSE, file, line);
	}
	return deconstify_gpointer(list);
}

GSList *
track_slist_alloc(const char *file, int line)
{
	return malloc_record(g_slist_alloc(), sizeof(GSList), FALSE, file, line);
}

GSList *
track_slist_append(GSList *l, gpointer data, const char *file, int line)
{
	GSList *new;

	new = track_slist_alloc(file, line);
	new->data = data;

	if (l) {
		GSList *last = g_slist_last(l);
		last->next = new;
		return l;
	} else
		return new;
}

GSList *
track_slist_prepend(GSList *l, gpointer data, const char *file, int line)
{
	GSList *new;

	new = track_slist_alloc(file, line);
	new->data = data;
	new->next = l;

	return new;
}

GSList *
track_slist_copy(GSList *list, const char *file, int line)
{
	return gslist_record(g_slist_copy(list), file, line);
}

void
track_slist_free(GSList *l, const char *file, int line)
{
	GSList *lk;

	for (lk = l; lk; lk = g_slist_next(lk))
		free_record(lk, file, line);

	g_slist_free(l);
}

void
track_slist_free1(GSList *l, const char *file, int line)
{
	if (l == NULL)
		return;

	free_record(l, file, line);
	g_slist_free_1(l);
}

GSList *
track_slist_remove(GSList *l, gpointer data, const char *file, int line)
{
	GSList *lk;

	lk = g_slist_find(l, data);
	if (lk == NULL)
		return l;

	return track_slist_delete_link(l, lk, file, line);
}

GSList *
track_slist_delete_link(GSList *l, GSList *lk, const char *file, int line)
{
	GSList *new;

	new = g_slist_remove_link(l, lk);
	track_slist_free1(lk, file, line);

	return new;
}

GSList *
track_slist_insert(GSList *l, gpointer data, int pos, const char *file, int line)
{
	GSList *lk;

	if (pos < 0)
		return track_slist_append(l, data, file, line);
	else if (pos == 0)
		return track_slist_prepend(l, data, file, line);

	lk = g_slist_nth(l, pos - 1);
	if (lk == NULL)
		return track_slist_append(l, data, file, line);
	else
		return track_slist_insert_after(l, lk, data, file, line);
}

GSList *
track_slist_insert_sorted(GSList *l, gpointer d, GCompareFunc c,
	const char *file, int line)
{
	int cmp;
	GSList *tmp = l;
	GSList *prev = NULL;
	GSList *new;

	if (l == NULL)
		return track_slist_prepend(l, d, file, line);

	cmp = (*c)(d, tmp->data);
	while (tmp->next != NULL && cmp > 0) {
		prev = tmp;
		tmp = tmp->next;
		cmp = (*c)(d, tmp->data);
	}

	new = track_slist_alloc(file, line);
	new->data = d;

	if (tmp->next == NULL && cmp > 0) {
		tmp->next = new;
		return l;
	}

	if (prev != NULL) {
		prev->next = new;
		new->next = tmp;
		return l;
	}

	new->next = l;
	return new;
}

GSList *
track_slist_insert_after(GSList *l, GSList *lk, gpointer data,
	const char *file, int line)
{
	GSList *new;

	if (lk == NULL)
		return track_slist_prepend(l, data, file, line);

	new = track_slist_alloc(file, line);
	new->data = data;

	new->next = lk->next;
	lk->next = new;

	return l;
}

GList *
track_list_alloc(const char *file, int line)
{
	return malloc_record(g_list_alloc(), sizeof(GList), FALSE, file, line);
}

GList *
track_list_append(GList *l, gpointer data, const char *file, int line)
{
	GList *new;

	new = track_list_alloc(file, line);
	new->data = data;

	if (l) {
		GList *last = g_list_last(l);
		last->next = new;
		new->prev = last;
		return l;
	} else
		return new;
}

GList *
track_list_prepend(GList *l, gpointer data, const char *file, int line)
{
	GList *new;

	new = track_list_alloc(file, line);
	new->data = data;

	if (l) {
		if (l->prev) {
			l->prev->next = new;
			new->prev = l->prev;
		}
		l->prev = new;
		new->next = l;
	}

	return new;
}

/**
 * Record GList `list' allocated at `file' and `line'.
 * @return argument `list'.
 */
GList *
glist_record(const GList * const list, const char *file, int line)
{
	const GList *iter;

	for (iter = list; NULL != iter; iter = g_list_next(iter)) {
		malloc_record(iter, sizeof *iter, FALSE, file, line);
	}
	return deconstify_gpointer(list);
}


GList *
track_list_copy(GList *list, const char *file, int line)
{
	return glist_record(g_list_copy(list), file, line);
}

void
track_list_free(GList *l, const char *file, int line)
{
	GList *lk;

	for (lk = l; lk; lk = g_list_next(lk))
		free_record(lk, file, line);

	g_list_free(l);
}

void
track_list_free1(GList *l, const char *file, int line)
{
	if (l == NULL)
		return;

	free_record(l, file, line);
	g_list_free_1(l);
}

GList *
track_list_remove(GList *l, gpointer data, const char *file, int line)
{
	GList *lk;

	lk = g_list_find(l, data);
	if (lk == NULL)
		return l;

	return track_list_delete_link(l, lk, file, line);
}

GList *
track_list_insert(GList *l, gpointer data, int pos, const char *file, int line)
{
	GList *lk;

	if (pos < 0)
		return track_list_append(l, data, file, line);
	else if (pos == 0)
		return track_list_prepend(l, data, file, line);

	lk = g_list_nth(l, pos - 1);
	if (lk == NULL)
		return track_list_append(l, data, file, line);
	else
		return track_list_insert_after(l, lk, data, file, line);
}

GList *
track_list_insert_sorted(GList *l, gpointer d, GCompareFunc c,
	const char *file, int line)
{
	int cmp;
	GList *tmp = l;
	GList *new;

	if (l == NULL)
		return track_list_prepend(l, d, file, line);

	cmp = (*c)(d, tmp->data);
	while (tmp->next != NULL && cmp > 0) {
		tmp = tmp->next;
		cmp = (*c)(d, tmp->data);
	}

	new = track_list_alloc(file, line);
	new->data = d;

	if (tmp->next == NULL && cmp > 0) {
		tmp->next = new;
		new->prev = tmp;
		return l;
	}

	/* Insert `new' before `tmp' */

	if (tmp->prev != NULL) {
		tmp->prev->next = new;
		new->prev = tmp->prev;
	}

	new->next = tmp;
	tmp->prev = new;

	return (tmp == l) ? new : l;
}

GList *
track_list_insert_after(GList *l, GList *lk, gpointer data,
	const char *file, int line)
{
	GList *new;

	if (lk == NULL)
		return track_list_prepend(l, data, file, line);

	new = track_list_alloc(file, line);
	new->data = data;

	new->prev = lk;
	new->next = lk->next;

	if (lk->next)
		lk->next->prev = new;

	lk->next = new;

	return l;
}

GList *
track_list_insert_before(GList *l, GList *lk, gpointer data,
	const char *file, int line)
{
	GList *new;

	if (lk == NULL)
		return track_list_append(l, data, file, line);

	new = track_list_alloc(file, line);
	new->data = data;

	new->next = lk;
	new->prev = lk->prev;

	if (lk->prev)
		lk->prev->next = new;

	lk->prev = new;

	return lk == l ? new : l;
}

GList *
track_list_delete_link(GList *l, GList *lk, const char *file, int line)
{
	GList *new;

	new = g_list_remove_link(l, lk);
	track_list_free1(lk, file, line);

	return new;
}

/***
 *** String trackers, to unveil hidden string buffer allocation.
 ***/

#define GSTRING_OBJ_SIZE	(3 * sizeof(void *))		/* Estimated size */

/**
 * Allocated length of a string object.
 */
static inline size_t
string_allocated_length(GString *s)
{
#if GLIB_CHECK_VERSION(2,0,0)
	return s->allocated_len;
#else
	struct real_gstring {
		gchar *str;
		gint len;
		gint alloc;
	} *rs = (struct real_gstring *) s;
	return rs->alloc;
#endif 
}

/**
 * string_str_track
 *
 * Track changes to the internal string object.
 * @return GString object.
 */
static GString *
string_str_track(GString *s, char *old, size_t osize,
	const char *file, int line)
{
	/*
	 * If we configured glib to trap all its g_malloc() and g_realloc()
	 * calls, it is not harmful to do additional bookkeeping here.
	 */

#ifdef MALLOC_VTABLE
	if (!vtable_works)
#endif
   	{

		size_t size = string_allocated_length(s);

		if (s->str != old) {
			free_record(old, file, line);
			malloc_record(s->str, size, FALSE, file, line);
		} else if (size != osize) {
			realloc_record(s->str, s->str, size, file, line);
		}
	}

	return s;
}

GString *
string_new_track(const char *p, const char *file, int line)
{
	GString *result = g_string_new(p);

	malloc_record(result, GSTRING_OBJ_SIZE, FALSE, file, line);
	return string_str_track(result, NULL, 0, file, line);
}

GString *
string_sized_new_track(size_t size, const char *file, int line)
{
	GString *result = g_string_sized_new(size);

	malloc_record(result, GSTRING_OBJ_SIZE, FALSE, file, line);
	return string_str_track(result, NULL, 0, file, line);
}

GString *
string_append_track(GString *s, const char *p, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_append(s, p);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_append_c_track(GString *s, char c, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_append_c(s, c);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_append_len_track(GString *s, const char *val, gssize len,
	const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_append_len(s, val, len);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_assign_track(GString *s, const char *p, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_assign(s, p);
	return string_str_track(s, old, osize, file, line);
}

void
string_free_track(GString *s, int freestr, const char *file, int line)
{
	free_record(s, file, line);

	/*
	 * If the glib vtable was setup, then the call to g_string_free() below
	 * is going to let us know about s->str being freed, so we must not
	 * call free_record() ourselves.
	 */

#ifdef MALLOC_VTABLE
	if (!vtable_works) {
#endif

	if (freestr)
		free_record(s->str, file, line);

#ifdef MALLOC_VTABLE
	}
#endif

	g_string_free(s, freestr);
}

GString *
string_prepend_track(GString *s, const char *p, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_prepend(s, p);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_prepend_c_track(GString *s, char c, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_prepend_c(s, c);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_insert_track(GString *s, int pos, const char *p,
	const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_insert(s, pos, p);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_insert_c_track(GString *s, int pos, char c, const char *file, int line)
{
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	s = g_string_insert_c(s, pos, c);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_sprintf_track(GString *s,
	const char *file, int line, const char *fmt, ...)
{
	va_list args;
	char *o;
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	g_string_assign(s, o);
	G_FREE_NULL(o);
	return string_str_track(s, old, osize, file, line);
}

GString *
string_sprintfa_track(GString *s,
	const char *file, int line, const char *fmt, ...)
{
	va_list args;
	char *o;
	char *old = s->str;
	size_t osize = string_allocated_length(s);

	va_start(args, fmt);
	o = g_strdup_vprintf(fmt, args);
	va_end(args);

	g_string_append(s, o);
	G_FREE_NULL(o);
	return string_str_track(s, old, osize, file, line);
}

#endif /* TRACK_MALLOC */

/***
 *** This section contains general-purpose leak summarizing routines that
 *** can be used by both malloc() and zalloc().
 ***/

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

struct leak_record {		/* Informations about leak at some place */
	size_t size;			/* Total size allocated there */
	size_t count;			/* Amount of allocations */
};

struct leak_set {
	GHashTable *places;		/* Maps "file:4" -> leak_record */
};

/**
 * Initialize the leak accumulator by "file:line"
 */
gpointer
leak_init(void)
{
	struct leak_set *ls;

	ls = real_malloc(sizeof *ls);
	ls->places = g_hash_table_new(g_str_hash, g_str_equal);

	return ls;
}

/**
 * Get rid of the key/value tupple in the leak table.
 */
static gboolean
leak_free_kv(gpointer key, gpointer value, gpointer unused_user)
{
	(void) unused_user;
	real_free(key);
	real_free(value);
	return TRUE;
}

/**
 * Dispose of the leaks accumulated.
 */
void
leak_close(gpointer o)
{
	struct leak_set *ls = o;

	g_hash_table_foreach_remove(ls->places, leak_free_kv, NULL);
	g_hash_table_destroy(ls->places);

	real_free(ls);
}

/**
 * Record a new leak of `size' bytes allocated at `file', line `line'.
 */
void
leak_add(gpointer o, size_t size, const char *file, int line)
{
	struct leak_set *ls = o;
	char key[1024];
	struct leak_record *lr;
	gboolean found;
	gpointer k;
	gpointer v;

	g_assert(file);
	g_assert(line >= 0);

	concat_strings(key, sizeof key,
		file, ":", uint64_to_string(line), (void *) 0);
	found = g_hash_table_lookup_extended(ls->places, key, &k, &v);

	if (found) {
		lr = v;
		lr->size += size;
		lr->count++;
	} else {
		lr = real_malloc(sizeof(*lr));
		lr->size = size;
		lr->count = 1;
		g_hash_table_insert(ls->places, real_strdup(key), lr);
	}
}

struct leak {			/* A memory leak, for sorting purposes */
	char *place;
	struct leak_record *lr;
};

/**
 * leak_size_cmp		-- qsort() callback
 *
 * Compare two pointers to "struct leak" based on their size value,
 * in reverse order.
 */
static int
leak_size_cmp(const void *p1, const void *p2)
{
	const struct leak *leak1 = p1, *leak2 = p2;

	/* Reverse order: largest first */
	return CMP(leak2->lr->size, leak1->lr->size);
}

struct filler {			/* Used by hash table iterator to fill leak array */
	struct leak *leaks;
	int count;			/* Size of `leaks' array */
	int idx;			/* Next index to be filled */
};

/**
 * fill_array			-- hash table iterator
 *
 * Append current hash table entry at the end of the "leaks" array.
 */
static void
fill_array(gpointer key, gpointer value, gpointer user)
{
	struct filler *filler = user;
	struct leak *l;
	struct leak_record *lr = value;

	g_assert(filler->idx < filler->count);

	l = &filler->leaks[filler->idx++];
	l->place = (char *) key;
	l->lr = lr;
}

/**
 * Dump the links sorted by decreasing leak size.
 */
void
leak_dump(gpointer o)
{
	struct leak_set *ls =  o;
	int count;
	struct filler filler;
	int i;

	count = g_hash_table_size(ls->places);

	if (count == 0)
		return;

	filler.leaks = real_malloc(sizeof(struct leak) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing leak size.
	 */

	g_hash_table_foreach(ls->places, fill_array, &filler);
	qsort(filler.leaks, count, sizeof(struct leak), leak_size_cmp);

	/*
	 * Dump the leaks.
	 */

	g_warning("leak summary by total decreasing size:");
	g_warning("leaks found: %d", count);

	for (i = 0; i < count; i++) {
		struct leak *l = &filler.leaks[i];
		g_warning("%lu bytes (%lu block%s) from \"%s\"",
			(gulong) l->lr->size, (gulong) l->lr->count,
			l->lr->count == 1 ? "" : "s", l->place);
	}

	real_free(filler.leaks);
}

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

/***
 *** This section contains general-purpose allocation summarizing routines that
 *** are used when MALLOC_STATS is on.
 ***
 *** This is used to spot the places where allocation takes place, sorted
 *** by decreasing allocation size.
 ***/

#ifdef MALLOC_STATS

struct afiller {		/* Used by hash table iterator to fill alloc array */
	const struct stats **stats;
	int count;			/* Size of `stats' array */
	int idx;			/* Next index to be filled */
};

/**
 * Compare two pointers to "struct stat" based on their allocation value,
 * in reverse order. -- qsort() callback
 */
static int
stats_allocated_cmp(const void *p1, const void *p2)
{
	const struct stats * const *s1 = p1, * const *s2 = p2;

	/* Reverse order: largest first */
	return CMP((*s2)->allocated, (*s1)->allocated);
}

/**
 * Compare two pointers to "struct stat" based on their total allocation value,
 * in reverse order. -- qsort() callback
 */
static int
stats_total_allocated_cmp(const void *p1, const void *p2)
{
	const struct stats * const *s1 = p1, * const *s2 = p2;

	/* Reverse order: largest first */
	return CMP((*s2)->total_allocated, (*s1)->total_allocated);
}

/**
 * Compare two pointers to "struct stat" based on their residual value,
 * in reverse order. -- qsort() callback
 */
static int
stats_residual_cmp(const void *p1, const void *p2)
{
	const struct stats * const *s1_ptr = p1, * const *s2_ptr = p2;
	const struct stats *s1 = *s1_ptr, *s2 = *s2_ptr;
	ssize_t i1 = s1->allocated + s1->reallocated - s1->freed;
	ssize_t i2 = s2->allocated + s2->reallocated - s2->freed;
	int ret;

	/* Reverse order: largest first */
	ret = CMP(i2, i1);
	return ret ? ret : stats_allocated_cmp(p1, p2);
}

/**
 * Compare two pointers to "struct stat" based on their total residual value,
 * in reverse order. -- qsort() callback
 */
static int
stats_total_residual_cmp(const void *p1, const void *p2)
{
	const struct stats * const *s1_ptr = p1, * const *s2_ptr = p2;
	const struct stats *s1 = *s1_ptr, *s2 = *s2_ptr;
	size_t i1 = s1->total_allocated + s1->total_reallocated - s1->total_freed;
	size_t i2 = s2->total_allocated + s2->total_reallocated - s2->total_freed;
	int ret;

	/* Reverse order: largest first */
	ret = CMP(i2, i1);
	return ret ? ret : stats_allocated_cmp(p1, p2);
}

/**
 * Append current hash table entry at the end of the "stats" array
 * in the supplied filler structure.  -- hash table iterator
 */
static void
stats_fill_array(const void *unused_key, void *value, void *user)
{
	struct afiller *filler = user;
	const struct stats *st = value;
	const struct stats **e;

	(void) unused_key;

	g_assert(filler->idx < filler->count);

	e = &filler->stats[filler->idx++];
	*e = st;
}

/**
 * Dump the stats held in the specified array.
 */
static void
stats_array_dump(FILE *f, struct afiller *filler)
{
	int i;

	fputs("------------- variations ------------- "
		  "[---------------- totals ----------------]  "
		  "frames\n", f);
	fprintf(f, "%7s %7s %8s %8s %4s [%7s %7s %8s %8s %6s] #a #f #r %s:\n",
		"alloc", "freed", "realloc", "remains", "live",
		"alloc", "freed", "realloc", "remains", "live", "from");

	for (i = 0; i < filler->count; i++) {
		const struct stats *st = filler->stats[i];
		int alloc_stacks;
		int free_stacks;
		int realloc_stacks;
		int remains = st->allocated + st->reallocated - st->freed;
		int total_remains =
			st->total_allocated + st->total_reallocated - st->total_freed;
		char *c_allocated = real_strdup(compact_size(st->allocated, TRUE));
		char *c_freed = real_strdup(compact_size(st->freed, TRUE));
		char *c_reallocated =
			real_strdup(compact_size(ABS(st->reallocated), TRUE));
		char *c_remains = real_strdup(compact_size(ABS(remains), TRUE));
		char *c_tallocated =
			real_strdup(compact_size(st->total_allocated, TRUE));
		char *c_tfreed = real_strdup(compact_size(st->total_freed, TRUE));
		char *c_treallocated =
			real_strdup(compact_size(ABS(st->total_reallocated), TRUE));
		char *c_tremains = real_strdup(compact_size(ABS(total_remains), TRUE));

#ifdef MALLOC_FRAMES
		alloc_stacks = st->alloc_frames == NULL ?
			0 : hash_table_size(st->alloc_frames);
		free_stacks = st->free_frames == NULL ?
			0 : hash_table_size(st->free_frames);
		realloc_stacks = st->realloc_frames == NULL ?
			0 : hash_table_size(st->realloc_frames);
#else
		alloc_stacks = free_stacks = realloc_stacks = 0;
#endif

		fprintf(f, "%7s %7s %c%7s %c%7s %4d [%7s %7s %c%7s %c%7s %6d] "
			"%2d %2d %2d \"%s:%d\"\n",
			c_allocated, c_freed,
			st->reallocated < 0 ? '-' : ' ', c_reallocated,
			remains < 0 ? '-' : ' ', c_remains,
			MIN(st->blocks, 9999),
			c_tallocated, c_tfreed,
			st->total_reallocated < 0 ? '-' : ' ', c_treallocated,
			total_remains < 0 ? '-' : ' ', c_tremains,
			MIN(st->total_blocks, 999999),
			MIN(alloc_stacks, 99),
			MIN(free_stacks, 99),
			MIN(realloc_stacks, 99),
			st->file, st->line);

		real_free(c_allocated);
		real_free(c_freed);
		real_free(c_reallocated);
		real_free(c_remains);
		real_free(c_tallocated);
		real_free(c_tfreed);
		real_free(c_treallocated);
		real_free(c_tremains);
	}

	fflush(f);
}

/**
 * Dump the allocation sorted by decreasing amount size on specified file.
 * When `total' is TRUE, sorting is made on the total stats instead of
 * the incremental ones.
 */
void
alloc_dump(FILE *f, gboolean total)
{
	int count;
	struct afiller filler;
	time_t now;

	count = hash_table_size(stats);

	if (count == 0)
		return;

	now = tm_time();
	fprintf(f, "--- distinct allocation spots found: %d at %s\n",
		count, short_time(delta_time(now, init_time)));

	filler.stats = real_malloc(sizeof(struct stats *) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing allocation size.
	 */

	hash_table_foreach(stats, stats_fill_array, &filler);
	qsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_allocated_cmp : stats_allocated_cmp);

	/*
	 * Dump the allocation based on allocation sizes.
	 */

	fprintf(f, "--- summary by decreasing %s allocation size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time(delta_time(now, total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * Now linearize hash table by decreasing residual allocation size.
	 */

	filler.idx = 0;

	hash_table_foreach(stats, stats_fill_array, &filler);
	qsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_residual_cmp : stats_residual_cmp);

	fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time(now - (total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * If we were not outputing for total memory, finish by dump sorted
	 * on total residual allocation.
	 */

	if (!total) {
		filler.idx = 0;

		hash_table_foreach(stats, stats_fill_array, &filler);
		qsort(filler.stats, count, sizeof(struct stats *),
			stats_total_residual_cmp);

		fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
			"total", "at", short_time(delta_time(now, init_time)));
		stats_array_dump(f, &filler);
	}

	fprintf(f, "--- end summary at %s\n", short_time(now - init_time));

	real_free(filler.stats);
}

/**
 * Reset incremental allocation and free counters. -- hash table iterator
 */
static void
stats_reset(const void *uu_key, void *value, gpointer uu_user)
{
	struct stats *st = value;

	(void) uu_key;
	(void) uu_user;

	st->blocks = st->allocated = st->freed = st->reallocated = 0;
}

/**
 * Atomically dump the allocation stats and reset the incremental allocation
 * statistics.
 */
void
alloc_reset(FILE *f, gboolean total)
{
	time_t now = tm_time();

	alloc_dump(f, total);
	hash_table_foreach(stats, stats_reset, NULL);

	fprintf(f, "--- incremental allocation stats reset after %s.\n",
		short_time(now - reset_time));

	reset_time = now;
}

#endif /* MALLOC_STATS */

#ifdef MALLOC_VTABLE
/**
 * In glib 1.2 there is no g_mem_set_vtable() routine.  We supply a
 * replacement that works on some platforms but not on others.
 *
 * This routine checks whether calling a simple memory allocation
 * function from glib will cause real_malloc() to be called.
 */
static void
malloc_glib12_check(void)
{
	vtable_works = TRUE;

#if !GLIB_CHECK_VERSION(2,0,0)
	{
		gpointer p;
		size_t old_size = hash_table_size(reals);

		/*
		 * Check whether the remapping is effective. This may not be
		 * the case for our GLib 1.2 hack. This is required for Darwin,
		 * for example.
		 */
		p = g_strdup("");
		if (hash_table_size(reals) == old_size) {
			static GMemVTable zero_vtable;
			fprintf(stderr, "WARNING: resetting g_mem_set_vtable\n");
			g_mem_set_vtable(&zero_vtable);
			vtable_works = FALSE;
		} else {
			G_FREE_NULL(p);
		}
	}
#endif	/* GLib < 2.0.0 */
}
#endif	/* MALLOC_VTABLE */

/**
 * Attempt to trap all raw g_malloc(), g_free(), g_realloc() calls
 * when TRACK_MALLOC and MALLOC_VTABLE are defined.
 *
 * This allows features like MALLOC_FREE_ERASE, MALLOC_SAFE, etc... to be
 * used on blocks that are allocated by glib internally or by GTK.  It also
 * enables us to see frees for blocks we track but give to GTK, and never
 * see again otherwise.
 */
void
malloc_init_vtable(void)
{
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	reals = hash_table_new_real();
	unknowns = hash_table_new_real();
#endif

#ifdef MALLOC_VTABLE
	{
		static GMemVTable vtable;

#if GLIB_CHECK_VERSION(2,0,0)
		vtable.malloc = real_malloc;
		vtable.realloc = real_realloc;
		vtable.free = real_free;
#else	/* GLib < 2.0.0 */
		vtable.gmvt_malloc = real_malloc;
		vtable.gmvt_realloc = real_realloc;
		vtable.gmvt_free = real_free;
#endif	/* GLib >= 2.0.0 */

		g_mem_set_vtable(&vtable);
		malloc_glib12_check();
	}

	/*
	 * Sanity checks of malloc settings
	 */

	{
		static const char test_string[] = "test string";
		gchar *p = g_strdup(test_string);

		if (0 != strcmp(test_string, p))
			g_error("g_strdup() is not working");
		G_FREE_NULL(p);

		p = g_malloc(CONST_STRLEN(test_string) + 20);
		memcpy(p, test_string, CONST_STRLEN(test_string) + 1);
		if (0 != strcmp(test_string, p))
			g_error("g_malloc() is not working");

		p = g_realloc(p, CONST_STRLEN(test_string) + 1);
		if (0 != strcmp(test_string, p))
			g_error("g_realloc() is not working");

		p = g_realloc(p, CONST_STRLEN(test_string) + 512);
		if (0 != strcmp(test_string, p))
			g_error("g_realloc() is not working");
		G_FREE_NULL(p);
	}
#endif	/* MALLOC_VTABLE */
}

/**
 * Called from main() to init data structures.
 */
void
malloc_init(const char *argv0)
{
	gboolean has_setting = FALSE;
	struct malloc_settings {
		guint8 use_halloc;
		guint8 track_malloc;
		guint8 track_zalloc;
		guint8 remap_zalloc;
		guint8 malloc_stats;
		guint8 malloc_frames;
		guint8 malloc_safe;
		guint8 malloc_safe_head;
		gulong malloc_trailer_len;
		guint8 malloc_free_erase;
		guint8 malloc_dup_free;
		guint8 malloc_vtable;
		guint8 malloc_periodic;
		gulong malloc_period;
		gboolean vtable_works;
	} settings;

	memset(&settings, 0, sizeof settings);

#ifdef MALLOC_FRAMES
	/*
	 * Load symbols from the executable.
	 */

	if (argv0 != NULL)
		load_symbols(argv0);
#else
	(void) argv0;
#endif

#ifdef MALLOC_PERIODIC
	/*
	 * Cannot install the periodic monitoring callback since at this stage
	 * the callout queue has not been created yet.
	 */
	need_periodic = TRUE;
#endif

	/*
	 * Log malloc configuration.
	 */

#ifdef USE_HALLOC
	settings.use_halloc = TRUE;
	has_setting = TRUE;
#endif
#ifdef TRACK_MALLOC
	settings.track_malloc = TRUE;
	has_setting = TRUE;
#endif
#ifdef TRACK_ZALLOC
	settings.track_zalloc = TRUE;
	has_setting = TRUE;
#endif
#ifdef REMAP_ZALLOC
	settings.remap_zalloc = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_STATS
	settings.malloc_stats = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_FRAMES
	settings.malloc_frames = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_SAFE
	settings.malloc_safe = TRUE;
	settings.malloc_trailer_len = MALLOC_TRAILER_LEN;
	has_setting = TRUE;
#endif
#ifdef MALLOC_SAFE_HEAD
	settings.malloc_safe_head = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_FREE_ERASE
	settings.malloc_free_erase = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_DUP_FREE
	settings.malloc_dup_free = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_VTABLE
	settings.malloc_vtable = TRUE;
	settings.vtable_works = vtable_works;
	has_setting = TRUE;
#endif
#ifdef MALLOC_PERIODIC
	settings.malloc_periodic = TRUE;
	settings.malloc_period = MALLOC_PERIOD;
	has_setting = TRUE;
#endif

	if (has_setting) {
		g_message("malloc settings: %s%s%s%s%s%s%s%s%s%s%s",
			settings.track_malloc ? "TRACK_MALLOC " : "",
			settings.track_zalloc ? "TRACK_ZALLOC " : "",
			settings.remap_zalloc ? "REMAP_ZALLOC " : "",
			settings.malloc_stats ? "MALLOC_STATS " : "",
			settings.malloc_frames ? "MALLOC_FRAMES " : "",
			settings.malloc_safe ? "MALLOC_SAFE " : "",
			settings.malloc_safe_head ? "MALLOC_SAFE_HEAD " : "",
			settings.malloc_free_erase ? "MALLOC_FREE_ERASE " : "",
			settings.malloc_dup_free ? "MALLOC_DUP_FREE " : "",
			settings.malloc_vtable ? "MALLOC_VTABLE " : "",
			settings.malloc_periodic ? "MALLOC_PERIODIC " : "");
	}

	if (settings.malloc_safe)
		g_message("malloc variable MALLOC_TRAILER_LEN = %lu",
			settings.malloc_trailer_len);

	if (settings.malloc_periodic)
		g_message("malloc variable MALLOC_PERIOD = %lu",
			settings.malloc_period);

	if (settings.malloc_vtable)
		g_message("malloc setting MALLOC_VTABLE %s",
			settings.vtable_works ? "works" : "does NOT work!");
}

/**
 * Dump all the blocks that are still used.
 */
void
malloc_close(void)
{
#ifdef TRACK_MALLOC
	gpointer leaksort;
#ifdef MALLOC_LEAK_ALL
	hash_table_t *saved_reals;
	hash_table_t *ignored;
	struct log_real_ctx log_ctx;
#endif	/* MALLOC_LEAK_ALL */

	if (blocks == NULL)
		return;

#ifdef MALLOC_STATS
	g_message("aggregated memory usage statistics:");
	alloc_dump(stderr, TRUE);
#endif

#ifdef MALLOC_LEAK_ALL
	/*
	 * We can't iterate on "reals" and fill "leaksort" without affecting
	 * the table since real_*() routines are used to allocate memory.
	 * Create a new empty one to manage the remaining allocations.
	 */

	saved_reals = reals;
	reals = hash_table_new_real();
#endif	/* MALLOC_LEAK_ALL */

	leaksort = leak_init();
	hash_table_foreach(blocks, malloc_log_block, leaksort);

#ifdef MALLOC_LEAK_ALL
	/*
	 * Before iterating on "real" blocks, we need to remove all the
	 * "struct block" and "struct realblock" addresses which are the
	 * values held within the "blocks" and "reals" tables.
	 */

	ignored = hash_table_new_real();
	hash_table_foreach(blocks, malloc_fill_ignored, ignored);
	hash_table_foreach(saved_reals, malloc_fill_ignored, ignored);

	log_ctx.ignored = ignored;
	log_ctx.ls = leaksort;

	hash_table_foreach(saved_reals, malloc_log_real_block, &log_ctx);
	hash_table_destroy_real(ignored);
#endif	/* MALLOC_LEAK_ALL */

	leak_dump(leaksort);
	leak_close(leaksort);

#ifdef MALLOC_LEAK_ALL
	/*
	 * Restore original "reals" table for the remaining free() up to the
	 * final exit point.
	 */

	hash_table_destroy_real(reals);
	reals = saved_reals;
#endif	/* MALLOC_LEAK_ALL */

#endif	/* TRACK_MALLOC */
}

/* vi: set ts=4 sw=4 cindent:  */
