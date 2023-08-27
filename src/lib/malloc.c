/*
 * Copyright (c) 2004-2010, 2020 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory.
 *
 * Code compiled with "-DTRACK_MALLOC -DREMAP_ZALLOC" will be able to
 * track most memory leaks, as well as detect (after the fact, alas) some
 * block corruptions (see MALLOC_SAFE below).
 *
 * Make sure to call malloc_close() to be able to get the final leak report.
 *
 * @author Raphael Manfredi
 * @date 2004-2010, 2020
 */

#include "common.h"		/* For RCSID */

#if defined(MALLOC_STATS) && !defined(TRACK_MALLOC)
#define TRACK_MALLOC
#endif

#define MALLOC_SOURCE	/**< Avoid nasty remapping, but include signatures */

#include "ascii.h"
#include "atomic.h"
#include "atoms.h"		/* For binary_hash() */
#include "cq.h"
#include "endian.h"		/* For peek_*() and poke_*() */
#include "hashing.h"
#include "hashtable.h"
#include "leak.h"
#include "log.h"
#include "omalloc.h"
#include "once.h"
#include "parse.h"		/* For parse_pointer() */
#include "path.h"		/* For filepath_basename() */
#include "pow2.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"			/* For tm_time() */
#include "unsigned.h"	/* For size_is_non_negative() */
#include "vsort.h"
#include "xmalloc.h"
#include "zalloc.h"		/* For zalloc_zone_info() */

/*
 * The following setups are more or less independent from each other.
 *
 * This comes at the price of heavy usage of conditional compilation
 * throughout the file...
 *
 * All of these have effect even when TRACK_MALLOC is not defined.
 */

#if 0
#define MALLOC_VTABLE		/* Try to redirect glib's malloc here */
#endif
#if 0
#define MALLOC_TIME			/* Track allocation / tracking times */
#endif
#if 0
#define MALLOC_SAFE			/* Add trailer magic to each block */
/* Additional trailer len, past end mark */
#define MALLOC_TRAILER_LEN	(2 * MEM_ALIGNBYTES)
#endif
#if 0
#define MALLOC_SAFE_HEAD	/* Additional header magic before each block */
#endif
#if 0
#define MALLOC_FREE_ERASE	/* Whether freeing should erase block data */
#endif
#if 0
#define MALLOC_DUP_FREE		/* Detect duplicate frees by block tagging */
#endif
#if 0
#define MALLOC_PERIODIC			/* Periodically scan blocks for overruns */
#define MALLOC_PERIOD	5000	/* Every 5 secs */
#endif
#if 0
#define MALLOC_LEAK_ALL		/* Report all leaked "real" blocks as well */
#endif
#if 0
#define MALLOC_CATCH_VERBOSE	/* Whether to be verbose about allocations */
#endif

/* Leave this one defined, we rely on it now -- RAM 2020-08-20 */
#define MALLOC_CATCH_MALLOC	/* Catch all malloc(), realloc() and free() calls */

/*
 * Enable MALLOC_VTABLE to avoid missing free() events from GTK if they
 * turn on TRACK_MALLOC.
 */
#if defined(TRACK_MALLOC) && !defined(MALLOC_VTABLE)
#define MALLOC_VTABLE		/* Or would miss some free(), report false leaks */
#endif

/*
 * MALLOC_CATCH_MALLOC makes sense only when TRACK_MALLOC is on.
 */
#if defined(MALLOC_CATCH_MALLOC) && !defined(TRACK_MALLOC)
#undef MALLOC_CATCH_MALLOC
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
  void   *next;
  uint8   u8;
  uint16  u16;
  uint32  u32;
  uint64  u64;
  float   f;
  double  d;
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

#define ONCE_FLAG_RUN_SAFE(f, r) G_STMT_START {		\
	if G_UNLIKELY(!ONCE_DONE((f)))					\
		once_flag_run_safe_trace(&(f),(r),# r);		\
} G_STMT_END

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
static hash_table_t *reals;
static hash_table_t *unknowns;
#endif
#ifdef MALLOC_FRAMES
static hash_table_t *alloc_points; /**< Maps a block to its allocation frame */
#endif

#ifdef MALLOC_VTABLE
static bool vtable_works;	/* Whether we can trap glib memory calls */
#endif

#ifdef malloc
#error "malloc() should not be a macro here."
#endif
#ifdef free
#error "free() should not be a macro here."
#endif
#ifdef realloc
#error "realloc() should not be a macro here."
#endif

/*
 * When not catching malloc(), we'll initialize libc_xxx routines with xxx()
 * calls.  We make sure real_malloc() calls libc_malloc() instead of malloc()
 * directly to avoid endless recursions when catching malloc(), which will
 * redirect to real_malloc()!
 */
#ifdef MALLOC_CATCH_MALLOC
#define MALLOC_INIT(x)		= call_libc_ ## x
static void malloc_trap_init(void);
static void *call_libc_malloc(size_t);
static void *call_libc_realloc(void *, size_t);
static void *call_libc_calloc(size_t, size_t);
static void call_libc_free(void *);
static bool malloc_is_boot(const void *p);
static size_t malloc_boot_size(void *p);
#else
#define MALLOC_INIT(x)		= x
#define malloc_is_boot(p)	FALSE
static inline size_t
malloc_boot_size(const void *p)
{
	(void) p;
	g_assert_not_reached();		/* Cannot be called */
}
#endif

static void          *(*libc_malloc)(size_t)          MALLOC_INIT(malloc);
static void G_UNUSED *(*libc_realloc)(void *, size_t) MALLOC_INIT(realloc);
static void G_UNUSED *(*libc_calloc)(size_t, size_t)  MALLOC_INIT(calloc);
static void G_UNUSED (*libc_free)(void *)             MALLOC_INIT(free);

/**
 * Structure keeping track of allocated blocks. (visible for convenience)
 *
 * Each block is inserted into a hash table, the key being the block's user
 * address and the value being a structure keeping track of the initial
 * allocation, and possibly of all the reallocations performed.
 */
struct block {
	const char *file;		/**< File where block tracking was initiated */
	GSList *reallocations;	/**< Reallocations that happened for block */
	size_t size;			/**< Size of tracked block */
	int line;				/**< Line number in file where block is tracked */
	int stid;				/**< ID of thread which allocated block */
#ifdef MALLOC_TIME
	time_t ttime;			/**< Tracking start time */
#endif
	unsigned owned:1;		/**< Whether we allocated the block ourselves */
#if defined(MALLOC_SAFE) || defined(MALLOC_PERIODIC)
	unsigned corrupted:1;	/**< Whether block was marked as corrupted */
#endif
};

#ifdef MALLOC_TIME
#define malloc_block_time(b)	(b)->ttime
#else
#define malloc_block_time(b)	0
#endif

/**
 * Structure keeping information for blocks allocated through real_malloc()
 * or from other allocators (in which case `is_real' will be set to FALSE).
 */
struct realblock {
#ifdef MALLOC_FRAMES
	struct frame *alloc;	/**< Allocation frame (atom) */
#endif
	size_t size;			/**< Size of allocated block */
	int stid;				/**< ID of the allocating thread */
#ifdef MALLOC_TIME
	time_t atime;			/**< Allocation time */
#endif
#if defined(MALLOC_SAFE) || defined(MALLOC_PERIODIC)
	uint corrupted:1;		/**< Whether block was marked as corrupted */
	uint header_corrupted:1;/**< Whether header corruption was reported */
#endif
	uint is_real:1;			/**< Allocated from real_malloc() directly */
	uint is_shifted:1;		/**< Allocated with real_malloc_header */
	uint is_raw:1;			/**< Has no malloc_header nor any trailer */
};

#ifdef MALLOC_TIME
#define malloc_real_time(rb)	(rb)->atime
#else
#define malloc_real_time(rb)	0
#endif

#ifdef MALLOC_FRAMES
#define malloc_real_ast(rb)	(NULL == (rb)->alloc ? NULL : (rb)->alloc->ast)
#else
#define malloc_real_ast(rb)	NULL
#endif

#ifdef TRACK_MALLOC
static time_t init_time = 0;
static time_t reset_time = 0;
#endif

#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
static hash_table_t *blocks = NULL;
static hash_table_t *not_leaking = NULL;
#endif

/**
 * Trapping points that are called once to invoke malloc_trap_init().
 *
 * These must not be invoked directly, they are rather invoked indirectly
 * through the idiom libc_malloc(s) or libc_free(p).
 */
#ifdef MALLOC_CATCH_MALLOC
static void *
call_libc_malloc(size_t s)
{
	malloc_trap_init();		/* Changes libc_malloc */
	return libc_malloc(s);
}
static void *
call_libc_realloc(void *p, size_t s)
{
	malloc_trap_init();		/* Changes libc_realloc */
	return libc_realloc(p, s);
}
static void *
call_libc_calloc(size_t nmemb, size_t size)
{
	malloc_trap_init();		/* Changes libc_calloc */
	return libc_calloc(nmemb, size);
}
static void
call_libc_free(void *p)
{
	malloc_trap_init();		/* Changes libc_free */
	libc_free(p);
}
#endif	/* MALLOC_CATCH_MALLOC */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
static once_flag_t malloc_tracking_inited;

/**
 * Setup tracking tables, once.
 */
static void G_COLD
malloc_init_tracking_once(void)
{
	reals = hash_table_new_real();
	unknowns = hash_table_new_real();

	hash_table_thread_safe(reals);
	hash_table_thread_safe(unknowns);
}

/**
 * Initialize tracking tables.
 */
void G_COLD
malloc_init_tracking(void)
{
	ONCE_FLAG_RUN(malloc_tracking_inited, malloc_init_tracking_once);
}
#endif /* TRACK MALLOC */


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
/**
 * Allocate a frame statistics atom from an atomic stacktrace.
 *
 * @param hptr		indirect hash_table_t object (allocated if missing)
 * @param st		stack trace
 *
 * @return a new frame statistics object (never freed) associated to
 * the stack trace
 */
struct frame *
get_frame_atom(hash_table_t **hptr, const struct stacktrace *st)
{
	struct frame *fr = NULL;
	hash_table_t *ht;
	const struct stackatom *ast;

	ast = stacktrace_get_atom(st);

	ht = *hptr;
	if (NULL == ht) {
		static spinlock_t frame_lck = SPINLOCK_INIT;
		spinlock(&frame_lck);
		if (NULL == (ht = *hptr)) {
			ht = hash_table_new_full_real(stack_hash, stack_eq);
			hash_table_thread_safe(ht);
			*hptr = ht;
		}
		spinunlock(&frame_lck);
	} else {
		fr = hash_table_lookup(ht, ast);
	}

	if (NULL == fr) {
		fr = omalloc0(sizeof *fr);		/* Never freed */
		fr->ast = ast;
		if (!hash_table_insert(ht, ast, fr)) {
			s_error("cannot record stack frame atom");
		}
	}

	return fr;
}
#endif	/* MALLOC_FRAMES */

/**
 * @struct malloc_stats
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

struct malloc_stats {
	const char *file;			/**< Place where allocation took place */
	int line;					/**< Line number */
	int blocks;					/**< Live blocks since last "reset" */
	int total_blocks;			/**< Total live blocks */
	AU64(allocated);			/**< Total allocated since last "reset" */
	AU64(freed);				/**< Total freed since last "reset" */
	AU64(total_allocated);		/**< Total allocated overall */
	AU64(total_freed);			/**< Total freed overall */
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
static unsigned
stats_hash(const void *key)
{
	const struct stats *s = key;
	unsigned h;

	h = string_mix_hash(s->file) ^ integer_hash_fast(s->line);

	return hashing_mix32(h);
}

/**
 * Comparison of two "struct stats" structures.
 * Only the "file" and "line" fields are considered.
 */
static int
stats_eq(const void *a, const void *b)
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
 * When MALLOC_FREE_ERASE is set, freed blocks are overwritten to detect
 * accidental reuse of freed memory.
 */
#ifdef MALLOC_FREE_ERASE
#define MALLOC_ERASE_MARK	'Z'	/* 0x5a */

static inline void
block_erase(const void *o, size_t size)
{
	void *p = deconstify_pointer(o);
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
	if (size >= sizeof(uint)) {
		*(uint *) p = MALLOC_DEAD_MARK;
	}
}

static inline void
block_clear_dead(const void *p, size_t size)
{
	if (size >= sizeof(uint)) {
		*(uint *) p = MALLOC_DEAD_CLEAR;
	}
}

static inline bool
block_is_dead(const void *p, size_t size)
{
	if (size >= sizeof(uint)) {
		return MALLOC_DEAD_MARK == *(uint *) p;
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
 * Format elapsed time if we have it, otherwise write a NUL into buffer.
 */
static inline void
malloc_alloc_elapsed(time_t alloctime, char *buf, size_t len)
{
	g_assert(size_is_positive(len));

#ifdef MALLOC_TIME
	str_bprintf(buf, len, " [%s]",
		short_time_ascii(delta_time(tm_time(), alloctime)));
#else
	(void) alloctime;
	buf[0] = '\0';
#endif	/* MALLOC_TIME */
}

#if defined(TRACK_MALLOC) && defined(MALLOC_FRAMES)
/**
 * Log informative record about the allocation point for a block (necessarily
 * tracked, since real blocks have their allocation stack embedded).
 */
static void
malloc_log_alloc_stack(const void *p, const struct block *b)
{
	struct frame *fr;

	fr = hash_table_lookup(alloc_points, p);
	if (fr == NULL)
		s_warning("no allocation record for %s%p from %s:%d?",
			b->owned ? "owned" : "tracked", p, b->file, b->line);
	else {
		s_info("block %p (out of %lu) allocated from:",
			p, (ulong) AU64_VALUE(&fr->blocks));
		stacktrace_atom_decorate(stderr, fr->ast,
			STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
	}
}

static void
malloc_log_realblock_alloc_stack(const void *p, const struct realblock *rb)
{
	char ago[32];

	malloc_alloc_elapsed(malloc_real_time(rb), ARYLEN(ago));

	if (rb->alloc != NULL) {
		s_info("block %p (out of %lu) allocated by %s%s from:",
			p, (ulong) AU64_VALUE(&rb->alloc->blocks),
			thread_id_name(rb->stid), ago);
		stacktrace_atom_decorate(stderr, rb->alloc->ast,
			STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
	} else {
		s_info("block %p allocated early (no frame) by %s%s",
			p, thread_id_name(rb->stid), ago);
	}
}
#else	/* !(TRACK_MALLOC && MALLOC_FRAMES) */
#define malloc_log_alloc_stack(p, b)
#define malloc_log_realblock_alloc_stack(p, rb)
#endif	/* TRACK_MALLOC && MALLOC_FRAMES */

/**
 * To help reduce #ifdef hell a bit.
 */
#define malloc_header_from_arena(o) o
#define malloc_owned_arena(mh) mh
#define malloc_owned_arena_setup(mh) mh

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
#undef malloc_header_from_arena
#undef malloc_owned_arena
#undef malloc_owned_arena_setup
static inline struct malloc_header *
malloc_header_from_arena(const void *o)
{
	return cast_to_pointer((char *) o - SAFE_ARENA_OFFSET);
}
static inline void *
malloc_owned_arena(struct malloc_header *mh)
{
	g_assert(MALLOC_START_MARK == mh->start);
	return mh->arena;
}
static inline void *
malloc_owned_arena_setup(struct malloc_header *mh)
{
	mh->start = MALLOC_START_MARK;
	return mh->arena;
}
#endif /* MALLOC_SAFE_HEAD */

static inline struct real_malloc_header *
real_malloc_header_from_arena(const void *o)
{
	return cast_to_pointer((char *) o - REAL_ARENA_OFFSET);
}

static inline size_t
malloc_safe_size(size_t size)
{
	return size +
#ifdef MALLOC_SAFE_HEAD
		SAFE_ARENA_OFFSET +
#endif
		sizeof(uint32) + MALLOC_TRAILER_LEN;
}

static inline size_t
real_malloc_safe_size(size_t size)
{
	return size + REAL_ARENA_OFFSET + sizeof(uint32) + MALLOC_TRAILER_LEN;
}

/**
 * Mark allocated block trailer.
 */
static void G_UNUSED
block_write_trailer(void *o, size_t size)
{
	size_t trailer = MALLOC_TRAILER_LEN;
	char *p;

	p = poke_u32(ptr_add_offset(o, size), MALLOC_END_MARK);
	while (trailer--)
		*p++ = MALLOC_TRAILER_MARK;
}

/**
 * Log allocation stack for block if known.
 */
static void
malloc_log_stack(const char *caller, const void *o, const struct stackatom *ast,
	int stid, time_t alloctime)
{
	if (ast != NULL) {
		char ago[32];

		malloc_alloc_elapsed(alloctime, ARYLEN(ago));

		s_info("%s(): block %p was allocated by %s%s from:",
			caller, o, thread_id_name(stid), ago);
		stacktrace_atom_decorate(stderr, ast,
			STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE);
	}
}

/**
 * Check that block's trailer was not altered.
 *
 * @param o			the user-known pointer to the buffer
 * @param size		the user-known size of the buffer
 * @param file		file where block allocation was done
 * @param line		line number within file where allocation was done
 * @param ast		if non-NULL, the known atomic stack frame for allocation
 * @param stid		the ID of the allocating thread
 * @param alloctime	the allocation timestamp, if known (otherwise 0)
 * @param op_file	file where free()/realloc() operation is happening
 * @param op_line	line where free()/realloc() operation is happening
 * @param showstack	whether to log the stackframe on errors
 *
 * @return whether an error was detected.
 */
static bool G_UNUSED
block_check_trailer(const void *o, size_t size,
	const char *file, int line, const struct stackatom *ast,
	int stid, time_t alloctime,
	const char *op_file, int op_line,
	bool showstack)
{
	bool error = FALSE;
	size_t trailer = MALLOC_TRAILER_LEN;
	const char *p, *trailer_start;
	const char *first_bad = NULL;

#ifdef TRACK_MALLOC
	if (0 == line && blocks != NULL) {
		const struct block *b = hash_table_lookup(blocks, o);
		if (b != NULL) {
			file = b->file;
			line = b->line;
			stid = b->stid;
		}
	}
#endif	/* TRACK_MALLOC */

	if (MALLOC_END_MARK != peek_u32(const_ptr_add_offset(o, size))) {
		s_warning(
			"%s(): MALLOC (%s:%d) %sblock %p (%zu byte%s) from %s:%d%s%s "
			"has corrupted end mark",
			G_STRFUNC, op_file, op_line,
			block_is_dead(o, size) ? "DEAD " : "", o, PLURAL(size), file, line,
			-1 == stid ? "" : " by ",
			-1 == stid ? "" : thread_id_name(stid));
		first_bad = const_ptr_add_offset(o, size);
		error = TRUE;
		goto done;
	}

	trailer_start = p = const_ptr_add_offset(o, size + sizeof(uint32));

	while (trailer--) {
		if (*p++ != MALLOC_TRAILER_MARK) {
			size_t bad = 1;
			const char *q = p;
			first_bad = p - 1;
			while (trailer--) {
				if (*q++ != MALLOC_TRAILER_MARK)
					bad++;
			}
			s_warning(
				"%s(): MALLOC (%s:%d) block %p (%zu bytes) from %s:%d "
				"has corrupted trailer (%zu byte%s starting at byte %zu of %d)",
				G_STRFUNC, op_file, op_line, o, size, file, line,
				PLURAL(bad),
				ptr_diff(p, trailer_start) - 1, MALLOC_TRAILER_LEN);
			error = TRUE;
		}
	}

done:
	if (error) {
#ifdef TRACK_MALLOC
		if (first_bad != NULL) {
			ulong addr = pointer_to_ulong(first_bad);
			const void *q;
			const void *end = const_ptr_add_offset(o,
				size + sizeof(uint32) + MALLOC_TRAILER_LEN);

			STATIC_ASSERT(IS_POWER_OF_2(MEM_ALIGNBYTES));

			/*
			 * We had corruption at the end of the block, check whether
			 * we have a known block / real allocation made in this zone
			 * that could explain the corruption.
			 */

			addr &= ~(MEM_ALIGNBYTES - 1);	/* First possible allocation */

			for (
				q = ulong_to_pointer(addr);
				ptr_cmp(q, end) < 0;
				q = const_ptr_add_offset(q, MEM_ALIGNBYTES)
			) {
				const struct block *b;
				const struct realblock *rb;
				char ago[32];

				if (blocks != NULL && (b = hash_table_lookup(blocks, q))) {
					malloc_alloc_elapsed(malloc_block_time(b), ARYLEN(ago));
					s_info("%s(): found %s block %p at offset %zu within %p, "
						"allocated from %s:%u by %s%s",
						G_STRFUNC, b->owned ? "owned" : "tracked",
						q, ptr_diff(q, o), o,
						b->file, b->line, thread_id_name(b->stid), ago);
					malloc_log_alloc_stack(q, b);
					break;
				}

				if (reals != NULL && (rb = hash_table_lookup(reals, q))) {
					malloc_alloc_elapsed(malloc_real_time(rb), ARYLEN(ago));
					s_info("%s(): found %s block %p at offset %zu within %p, "
						"allocated by %s%s",
						G_STRFUNC, rb->is_real ? "real" : "trapped",
						q, ptr_diff(q, o), o,
						thread_id_name(rb->stid), ago);
					malloc_log_realblock_alloc_stack(q, rb);
					break;
				}
			}
		}
#else	/* !TRACK_MALLOC */
		(void) first_bad;
#endif	/* TRACK_MALLOC */

#ifdef MALLOC_FRAMES
		if (NULL == ast) {
			struct frame *fr = hash_table_lookup(alloc_points, o);
			if (fr != NULL)
				ast = fr->ast;
		}
#endif	/* MALLOC_FRAMES */
		malloc_log_stack(G_STRFUNC, o, ast, stid, alloctime);
	}
	if (error && showstack) {
		stacktrace_where_print(stderr);
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
block_check_marks(const void *o, struct block *b,
	const char *file, int line)
{
	bool error = FALSE;

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
			s_warning(
				"MALLOC (%s:%d) block %p from %s:%d has corrupted start mark",
				file, line, o, b->file, b->line);
		}
	}
#endif /* MALLOC_SAFE_HEAD */

	if (
		block_check_trailer(o, b->size, b->file, b->line, NULL, b->stid,
			malloc_block_time(b), file, line, FALSE)
	) {
		b->corrupted = TRUE;
		error = TRUE;
	}

	if (error) {
		stacktrace_where_print(stderr);
	}
}
#endif	/* TRACK_MALLOC */

#else	/* !MALLOC_SAFE */
static inline void G_UNUSED
block_write_trailer(void *o, size_t size)
{
	(void) o; (void) size;
}
static inline bool G_UNUSED
block_check_trailer(const void *o, size_t size,
	const char *file, int line, const struct stackatom *ast,
	int stid, time_t alloctime,
	const char *op_file, int op_line, bool showstack)
{
	(void) o; (void) size; (void) file; (void) line;
	(void) op_file; (void) op_line; (void) showstack;
	(void) stid; (void) alloctime; (void) ast;
	return FALSE;	/* OK, no error to report */
}
#endif	/* MALLOC_SAFE */

struct block_check_context {
	size_t tracked_size;
	size_t real_size;
	unsigned tracked_count;
	unsigned real_count;
	unsigned old_corrupted;
	unsigned new_corrupted;
};

#ifdef TRACK_MALLOC
/**
 * Iterating callback to check a tracked block.
 */
static void
malloc_check_block(const void *key, void *value, void *ctx)
{
	struct block_check_context *bc = ctx;
	struct block *b = value;
	bool was_corrupted;

	bc->tracked_count++;
	bc->tracked_size = size_saturate_add(bc->tracked_size, b->size);

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
malloc_check_real(const void *key, void *value, void *ctx)
{
	struct block_check_context *bc = ctx;
	struct realblock *rb = value;
	void *p = deconstify_pointer(key);
	bool logged = FALSE;

	bc->real_count++;
	bc->real_size = size_saturate_add(bc->real_size, rb->size);

	if (rb->corrupted) {
		bc->old_corrupted++;
	}

	if (block_is_dead(p, rb->size)) {
		s_warning("%s(): MALLOC allocated real block %p (%zu byte%s) "
			"marked as DEAD",
			G_STRFUNC, p, PLURAL(rb->size));
		malloc_log_realblock_alloc_stack(p, rb);
		logged = TRUE;
	}

	if (
		!rb->corrupted && !rb->is_raw &&
		block_check_trailer(p, rb->size, "FAKED", 0, malloc_real_ast(rb),
			rb->stid, malloc_real_time(rb), _WHERE_, __LINE__, FALSE)
	) {
		bc->new_corrupted++;
		rb->corrupted = TRUE;
	}

#ifdef MALLOC_SAFE
	if (!rb->header_corrupted && rb->is_shifted) {
		struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
		bool problem = FALSE;
		if (rb->is_shifted && REAL_MALLOC_MAGIC != rmh->magic) {
			rb->header_corrupted = TRUE;
			bc->new_corrupted++;
			problem = TRUE;
			s_warning("%s(): MALLOC corrupted real block magic at %p "
				"(%zu byte%s)", G_STRFUNC, p, PLURAL(rb->size));
		}
		if (rmh->size != rb->size) {
			/* Can indicate memory corruption as well */
			bc->new_corrupted++;
			rb->header_corrupted = TRUE;
			problem = TRUE;
			s_warning("%s(): MALLOC size mismatch for real block %p: "
				"hashtable says %zu byte%s, header says %zu",
				G_STRFUNC, p, PLURAL(rb->size), rmh->size);
		}
		if (problem && !logged) {
			malloc_log_realblock_alloc_stack(p, rb);
		}
	}
#endif	/* MALLOC_SAFE */
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

/**
 * Conduct a full memory check for possible block corruption.
 *
 * @param error_count	if non-NULL, update with errors we spotted
 *
 * @return whether something was checked.
 */
static bool G_UNUSED
malloc_check_allocations(uint *error_count)
{
	struct block_check_context ctx;
	bool checked = FALSE;
	tm_t start, end;
	uint errors = 0;
	char tracked_size[SIZE_FIELD_MAX];
	char real_size[SIZE_FIELD_MAX];

	ZERO(&ctx);
	tm_now_exact(&start);

	if (error_count != NULL)
		errors = *error_count;

#ifdef TRACK_MALLOC
	checked = TRUE;
	if (blocks != NULL)
		hash_table_foreach(blocks, malloc_check_block, &ctx);
#endif
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	checked = TRUE;
	hash_table_copy_foreach(reals, malloc_check_real, &ctx);
#endif

	if (!checked)
		return FALSE;

	tm_now_exact(&end);

	short_size_to_string_buf(ctx.tracked_size, FALSE, ARYLEN(tracked_size));
	short_size_to_string_buf(ctx.real_size, FALSE, ARYLEN(real_size));

	if (0 == ctx.old_corrupted && 0 == ctx.new_corrupted) {
		s_message("%s(): check done (%u msecs): "
			"tracked: %u [%s], real: %u [%s]",
			G_STRFUNC, (unsigned) tm_elapsed_ms(&end, &start),
			ctx.tracked_count, tracked_size,
			ctx.real_count, real_size);
	} else {
		if (ctx.new_corrupted)
			errors++;
		s_warning("%s(): check done (%u msecs): %s"
			"tracked: %u [%s], real: %u [%s], "
			"NEWLY CORRUPTED: %u (%u old)",
			G_STRFUNC, (unsigned) tm_elapsed_ms(&end, &start),
			0 == ctx.new_corrupted ? "" : "WATCH OUT ",
			ctx.tracked_count, tracked_size,
			ctx.real_count, real_size,
			ctx.new_corrupted, ctx.old_corrupted);
	}

	if (error_count != NULL)
		*error_count = errors;

	return TRUE;
}

/**
 * With MALLOC_PERIODIC, all the allocated blocks (whether they be tracked
 * or allocated directly via real_malloc() and friends)
 */
#ifdef MALLOC_PERIODIC

static bool need_periodic;
static bool malloc_check_allocations(uint *error_count);

/**
 * Periodic check to make sure all the known blocks are correct.
 */
static bool
malloc_periodic(void *unused_obj)
{
	static unsigned errors;
	bool checked;

	(void) unused_obj;

	if (0 == errors) {
		s_message("%s(): check starting...", G_STRFUNC);
	} else {
		s_message("%s(): check starting... [%u error%s already]",
			G_STRFUNC, PLURAL(errors));
	}

	thread_suspend_others(TRUE);
	checked = malloc_check_allocations(&errors);
	thread_unsuspend_others();

	if (!checked)
		s_message("%s(): nothing to check, disabling.", G_STRFUNC);

	return checked;
}

static void
install_malloc_periodic(void)
{
	need_periodic = FALSE;
	cq_periodic_main_add(MALLOC_PERIOD, malloc_periodic, NULL);
}
#endif	/* MALLOC_PERIODIC */

#ifdef TRACK_MALLOC
/**
 * Ensure we keep no stale trace of any block at the specified address.
 */
static void
block_check_missed_free(const char *caller,
	const void *p, const char *file, int line)
{
	struct block *b;

	b = hash_table_lookup(blocks, p);
	if (b != NULL) {
		char ago[32];

		malloc_alloc_elapsed(malloc_block_time(b), ARYLEN(ago));

		thread_suspend_others(FALSE);	/* Try to limit nested messages */
		s_info("%s(): called from %s()", G_STRFUNC, caller);
		s_warning("%s(): MALLOC (%s:%d) reusing %sblock %p (%zu byte%s) "
			"from %s:%d by %s%s, missed its freeing",
			G_STRFUNC, file, line, b->owned ? "owned " : "foreign ",
			p, PLURAL(b->size), b->file, b->line,
			thread_id_name(b->stid), ago);
		stacktrace_where_print(stderr);

		{
			struct realblock *rb = hash_table_lookup(reals, p);
			if (rb != NULL) {
				malloc_log_realblock_alloc_stack(p, rb);
			} else {
				s_rawwarn("block %p is not tracked", p);
			}
		}

		malloc_log_alloc_stack(p, b);

		if (b->reallocations) {
			struct block *r = b->reallocations->data;
			uint cnt = g_slist_length(b->reallocations);

			s_warning("   (realloc'ed %u time%s, lastly from \"%s:%d\") by %s",
				PLURAL(cnt), r->file, r->line, thread_id_name(r->stid));
		}
		thread_unsuspend_others();

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
	bool warning = FALSE;

	rb = hash_table_lookup(reals, p);
	if (rb != NULL) {
#ifdef TRACK_MALLOC
		if (not_leaking != NULL) {
			hash_table_remove(not_leaking, p);
		}
		if (blocks != NULL) {
			struct block *b;

			b = hash_table_lookup(blocks, p);
			if (b != NULL) {
				/*
				 * Same logic as in block_check_missed_free().
				 * Duplicated in order to avoid a second warning when we
				 * reuse the address and need to track it.
				 */

				warning = TRUE;
				s_rawwarn("%s(): MALLOC reusing %s block %p (%zu byte%s) "
					"from %s:%d by %s, missed its freeing",
					G_STRFUNC, b->owned ? "owned" : "foreign",
					p, PLURAL(rb->size), b->file, b->line,
					thread_id_name(b->stid));
				b->owned = FALSE;
				free_record(p, _WHERE_, __LINE__);
			}
		}
#else	/* !TRACK_MALLOC */
		warning = TRUE;
		s_rawwarn("MALLOC reusing %s block %p (%zu byte%s), "
			"missed its freeing",
			rb->is_real ? "real" : "trapped", p, PLURAL(rb->size));
#endif	/* TRACK_MALLOC */
		if (warning) {
			s_rawwarn("current frame:");
			stacktrace_where_print(stderr);
			malloc_log_realblock_alloc_stack(p, rb);
		}
		hash_table_remove(reals, p);
		libc_free(rb);
	}
}

/**
 * Allocate and fill tracking block, used by TRACK_MALLOC.
 *
 * This is used for blocks we allocate through our trapping macros, hence we
 * have the source file and line locations where the allocation is made.
 *
 * @return allocated block, ready to be tracked in the `blocks' hash table.
 */
static inline struct block *
malloc_new_track_block(const char *file, int line, size_t size, bool owned)
{
	struct block *b = libc_calloc(1, sizeof *b);

	if (NULL == b)
		s_error("%s(): unable to allocate %zu bytes", G_STRFUNC, sizeof *b);

	b->file  = short_filename(deconstify_pointer(file));
	b->line  = line;
	b->size  = size;
	b->stid  = thread_safe_small_id();
	b->owned = owned;
#ifdef MALLOC_TIME
	b->ttime = tm_time();
#endif

	return b;
}

/**
 * Allocate and fill realblock info, used by TRACK_MALLOC.
 *
 * This is used for blocks we allocate directly at the lowest level, hence
 * we do not have the source file and line locations where the allocation
 * is actually made.
 *
 * @return allocated structure, ready to be inserted in the `reals' hash table.
 */
static struct realblock * G_UNUSED
malloc_new_track_realblock(size_t size,
	bool is_real, bool is_shifted, bool is_raw)
{
	struct realblock *rb = libc_calloc(1, sizeof *rb);

	if (NULL == rb)
		s_error("%s(): unable to allocate %zu bytes", G_STRFUNC, sizeof *rb);

	rb->size       = size;
	rb->stid       = thread_safe_small_id();
	rb->is_real    = booleanize(is_real);
	rb->is_shifted = booleanize(is_shifted);
	rb->is_raw     = booleanize(is_raw);
#ifdef MALLOC_TIME
	rb->atime   = tm_time();
#endif
#ifdef MALLOC_FRAMES
		/*
		 * Unfortunately, when called very early (before main() has
		 * started), we are not in a condition to capture frames.
		 * That would require too much early initializations, and
		 * it ends-up being recursive today due to the complex
		 * inter-mixing of layers we have built over time.  It would
		 * require a complete rethink to be able to fix that.
		 * For now, just avoid capturing the frame by setting rb->alloc
		 * to NULL if we come here too early.
		 * 		--RAM, 2020-08-18
		 */
		if (thread_main_has_started()) {
			struct stacktrace t;
			struct frame *fr;

			stacktrace_get(&t);	/* Want to see real_malloc() in stack */
			fr = get_frame_atom(&gst.alloc_frames, &t);
			AU64_ADD(&fr->count, size);
			AU64_ADD(&fr->total_count, size);
			AU64_INC(&fr->blocks);
			rb->alloc = fr;
		}
#endif	/* MALLOC_FRAMES */

	return rb;
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

/**
 * Perform bookkeeping on allocated block.
 *
 * This is used to track blocks allocated directly, for instance via
 * posix_memalign() or via real_malloc(), called through malloc().
 *
 * We call these "real" blocks because they are not tracked at the
 * source level (file / line) through a trapping allocation macro, where
 * we would go through malloc_alloc_track() or malloc_track() to allocate
 * the memory.
 *
 * The hash table records a structure associated to the user-visible pointer
 * which is going to help us manage these blocks, because they can be shaped
 * differently.  In particular:
 *
 * - `is_real' will tell us whether the block was allocated via real_malloc().
 *   This is not necessarily the case when allocation was done through
 *   malloc_alloc_track(), which can be given a specific allocation routine.
 *
 * - `is_shifted' will tell us whether a real_malloc_header structure was
 *   crammed at the very beginning of the physical block, to help us track
 *   whether the head of the block was corrupted, for instance.  It is not
 *   always TRUE, since posix_memalign(), having alignment constraints to
 *   satisfy and which the user code expects, does not allow us arbitrarily
 *   shifting the start of the block compared to the physical allocation!
 *
 * - `is_raw' indicates that there is no overhead at all surrounding the
 *   allocated block, which is the case when posix_memalign() is used.
 *   This will help the memory checker skip those blocks when trying to
 *   identify memory corruption, when compiled with MALLOC_SAFE.
 *
 * @param o				the allocated block (user-visible pointer)
 * @param size			the size of the allocated block
 * @param is_real		TRUE if comming from real_malloc()
 * @param is_shifted	TRUE if we have a real_malloc_header structure
 * @param is_raw		TRUE if not even a malloc_header structure
 *
 * @return the allocated block `o' as a convenience.
 */
static void *
malloc_bookkeeping(void *o, size_t size,
	bool is_real, bool is_shifted, bool is_raw)
{
	block_clear_dead(o, size);

	(void) size;
	(void) is_real;
	(void) is_shifted;
	(void) is_raw;

#ifdef TRACK_MALLOC
	ONCE_FLAG_RUN(malloc_tracking_inited, malloc_init_tracking_once);
#endif

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	{
		struct realblock *rb =
			malloc_new_track_realblock(size, is_real, is_shifted, is_raw);

		real_check_missed_free(o);
		if (!hash_table_insert(reals, o, rb)) {
			s_error("MALLOC cannot record real block %p", o);
		}
	}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

	return o;
}

/**
 * Calls real malloc(), no tracking.
 */
void *
real_malloc(size_t size)
{
	void *o;
	bool is_shifted = FALSE;
	bool is_raw = FALSE;

#ifdef MALLOC_CATCH_MALLOC
	ONCE_FLAG_RUN(malloc_tracking_inited, malloc_init_tracking_once);
#endif

#ifdef MALLOC_PERIODIC
	if (need_periodic)
		install_malloc_periodic();
#endif

#ifdef MALLOC_SAFE
	{
		size_t len = real_malloc_safe_size(size);
		struct real_malloc_header *rmh;

		rmh = libc_malloc(len);

		if (rmh == NULL)
			s_error("unable to allocate %zu bytes", size);

		rmh->magic = REAL_MALLOC_MAGIC;
		rmh->size = size;
		o = rmh->arena;
		block_write_trailer(o, size);
		is_shifted = TRUE;
	}
#else  /* !MALLOC_SAFE */

	o = libc_malloc(size);
	is_raw = TRUE;

#endif /* MALLOC_SAFE */

	if (o == NULL)
		s_error("unable to allocate %zu bytes", size);

	return malloc_bookkeeping(o, size, TRUE, is_shifted, is_raw);
}

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || \
	defined(TRACK_VMM) || defined(MALLOC_VTABLE)

#ifdef MALLOC_SAFE
/**
 * Free a block allocated via real_malloc() with additional header magic.
 */
static void
real_check_free(void *p)
{
	struct real_malloc_header *rmh = real_malloc_header_from_arena(p);

	if (REAL_MALLOC_MAGIC != rmh->magic)
		s_warning("MALLOC free(): corrupted real block magic at %p", p);

	libc_free(rmh);
}
#endif	/* MALLOC_SAFE */

#ifdef REMAP_ZALLOC
#define zalloc_zone_info(p,s)	FALSE
#endif

/**
 * Log information about address that we can gather by probing the various
 * layers which can allocate memory.  This could give insight about the problem.
 */
static void G_UNUSED	/* Not always used by conditional scenarios */
malloc_address_log_info(const void *p)
{
	size_t size;
	uint tid;

	s_rawinfo("MALLOC %p in %s VMM region", p, vmm_type_pointer(p));

	if (malloc_is_boot(p))
		s_rawinfo("MALLOC %p falls within boot memory region", p);

	if (vmm_page_start(p) == p)
		s_rawinfo("MALLOC %p is page-aligned", p);

	if (zalloc_zone_info(p, &size))
		s_rawinfo("MALLOC %p in %zu-byte zalloc() zone", p, size);

	if (thread_is_stack_pointer(p, p, &tid))
		s_rawinfo("MALLOC %p in stack of %s", p, thread_id_name(tid));

	if (xmalloc_block_info(p, &tid, &size)) {
		if (tid != -1U) {
			s_rawinfo("MALLOC %p is thread-private %zu-byte xmalloc() from %s",
				p, size, thread_id_name(tid));
		} else {
			s_rawinfo("MALLOC %p is a probable %zu-byte xmalloc() block", p, size);
		}
	}
}

/**
 * Calls real free(), no tracking.
 * Block must have been allocated via real_malloc().
 */
static void G_UNUSED	/* Not always used by conditional scnearios */
real_free(void *p)
{
	bool owned = FALSE;
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	void *start = p;
	const char *file = "?";
	int line = 0;
	bool is_shifted = FALSE;
#endif
#ifdef TRACK_MALLOC
	struct block *b = NULL;
#endif

#ifdef MALLOC_CATCH_MALLOC
	ONCE_FLAG_RUN(malloc_tracking_inited, malloc_init_tracking_once);
#endif

#ifdef MALLOC_PERIODIC
	if (need_periodic)
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
		owned = b->owned;
		file = b->file;
		line = b->line;
		free_record(p, _WHERE_, __LINE__);	/* p is an "user" address */
	}
#endif
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	{
		struct realblock *rb = hash_table_lookup(reals, start);

		if (rb != NULL) {
			is_shifted = rb->is_shifted;
			if (!rb->is_real) {
				s_rawwarn(
					"MALLOC freeing trapped %zu-byte block %p "
					"from %s:%d with %s()",
					rb->size, p, file, line, G_STRFUNC);
				malloc_address_log_info(p);
				stacktrace_where_print(stderr);
				s_error("%s(): attempt to free invalid pointer %p",
					G_STRFUNC, p);
			}
			if (!hash_table_remove(reals, start)) {
				s_error("%s(): cannot remove %p (start of %p)",
					G_STRFUNC, start, p);
			}
			if (!rb->is_raw) {
				block_check_trailer(start, rb->size,
					"FAKED", 0, malloc_real_ast(rb), rb->stid,
					malloc_real_time(rb),
					_WHERE_, __LINE__, TRUE);
			}
			block_erase(start, rb->size);
			block_mark_dead(start, rb->size);
			libc_free(rb);
		} else {
			if (block_is_dead(start, sizeof(uint))) {
				s_warning("MALLOC probable duplicate free of %p", p);
				stacktrace_where_print(stderr);
				s_error("MALLOC invalid free()");
			} else {
				bool ok = FALSE;
#ifdef MALLOC_VTABLE
				/* See comment in free_track() */
				ok = hash_table_lookup(unknowns, p) != NULL;
				hash_table_remove(unknowns, p);		/* We're freeing it now */
#endif
				if (!ok) {
					s_rawwarn("MALLOC freeing unknown block %p", p);
					malloc_address_log_info(p);
					stacktrace_where_print(stderr);
#ifdef MALLOC_CATCH_MALLOC
					s_error("%s(): attempt to free invalid pointer %p",
						G_STRFUNC, p);
#endif
				}
			}
		}
	}
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
		real_check_free(malloc_header_from_arena(p));
	} else if (is_shifted) {
		real_check_free(p);
	} else
#endif	/* MALLOC_SAFE */
	{
		libc_free(p);	/* NOT g_free(): would recurse if MALLOC_VTABLE */
	}
#ifndef MALLOC_SAFE
	(void) owned;		/* Avoid compiler warning */
#endif
}
#endif /* TRACK_MALLOC || TRACK_ZALLOC || TRACK_VMM || MALLOC_VTABLE */

#if defined(TRACK_MALLOC) || defined(TRACK_VMM)
/**
 * Wraps strdup() call so that real_free() can be used on the result.
 */
static inline char *
real_strdup(const char *s)
{
	void *p;
	size_t len;

	if (s == NULL)
		return NULL;

	len = vstrlen(s);
	p = real_malloc(len + 1);
	memcpy(p, s, len + 1);		/* Also copy trailing NUL */

	return p;
}
#endif	/* TRACK_MALLOC || TRACK_VMM */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
/**
 * Calls real realloc(), no tracking.
 */
static void *
real_realloc(void *p, size_t size)
{
	bool owned = FALSE;
#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
	struct block *b = NULL;
#endif

#ifdef MALLOC_CATCH_MALLOC
	ONCE_FLAG_RUN(malloc_tracking_inited, malloc_init_tracking_once);
#endif

#ifdef MALLOC_PERIODIC
	if (need_periodic)
		install_malloc_periodic();
#endif

	if (NULL == p)
		return real_malloc(size);

	if (0 == size) {
		if (malloc_is_boot(p))
			free(p);		/* Was allocated specially, our free() knows! */
		else
			real_free(p);
		return NULL;
	} else if (malloc_is_boot(p)) {
		size_t len = malloc_boot_size(p);
		void *n;

		n = real_malloc(size);
		memcpy(n, p, MIN(size, len));
		free(p);			/* Our free() knows how to deal with boot blocks */
		return n;			/* Was not tracked, still not tracked */
	} else {
		void *n;
		bool is_real = TRUE, is_shifted = FALSE, is_raw = FALSE;

#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
		if (blocks != NULL) {
			b = hash_table_lookup(blocks, p);
			owned = b != NULL && b->owned;
		}
#endif	/* TRACK_MALLOC || MALLOC_SAFE_HEAD */

#ifdef MALLOC_SAFE
		if (!owned) {
			struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
			size_t len = real_malloc_safe_size(size);
			struct realblock *rb = NULL;
			time_t alloctime;

			/* Processing a block we do not own */

#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
			{
				rb = hash_table_lookup(reals, p);
				if (NULL == rb) {
					s_error("%s(): MALLOC given unknown real block %p",
						G_STRFUNC, p);
				} else {
					is_real    = rb->is_real;
					is_shifted = rb->is_shifted;
					is_raw     = rb->is_raw;
					alloctime  = malloc_real_time(rb);
				}
			}
#else
			is_shifted = TRUE;
#endif	/* TRACK_MALLOC || MALLOC_SAFE_HEAD */

			if (!is_real) {
				s_critical("%s(): MALLOC given not-owned non-real block %p",
					G_STRFUNC, p);
				if (rb != NULL) {
					malloc_log_realblock_alloc_stack(p, rb);
				}
				s_error("%s(): cannot handle block %p", G_STRFUNC, p);
			}

			if (is_shifted) {
				if (REAL_MALLOC_MAGIC != rmh->magic)
					s_error("%s(): no real magic number for %p", G_STRFUNC, p);

				if (!is_raw) {
					block_check_trailer(p, rmh->size, "FAKED", 0, NULL,
						/* stid */ -1, alloctime,
						_WHERE_, __LINE__, TRUE);
				}

				rmh = libc_realloc(rmh, len);
				if (NULL == rmh)
					goto error;
				n = rmh->arena;
				rmh->size = size;
				g_assert(REAL_MALLOC_MAGIC == rmh->magic);
				block_write_trailer(n, size);
			} else {
				n = libc_realloc(p, size);
				if (NULL == n)
					goto error;
			}
		} else {
			struct malloc_header *mh = malloc_header_from_arena(p);
			size_t len = malloc_safe_size(size);

			/* Processing a block we own and (necessarily) track */

			mh = libc_realloc(p, len);
			if (NULL == mh)
				goto error;
			n = malloc_owned_arena(mh);
		}
#else	/* !MALLOC_SAFE */
		n = libc_realloc(p, size);
		if (n == NULL)
			goto error;
#endif	/* MALLOC_SAFE */

		/*
		 * Now that we have a (possibly new) location for the block at `n',
		 * check whether it is different from `p' to update our internal
		 * tables.
		 */

#ifdef TRACK_MALLOC
		if (n != p && not_leaking != NULL) {
			if (hash_table_remove(not_leaking, p)) {
				hash_table_insert(not_leaking, n, int_to_pointer(1));
			}
		}

		if (b != NULL) {
			b->size = size;
			if (n != p) {
				hash_table_remove(blocks, p);
				block_check_missed_free(G_STRFUNC, n, "FAKED", 0);
				if (!hash_table_insert(blocks, n, b)) {
					s_error("%s(): MALLOC cannot track reallocated block %p",
						G_STRFUNC, n);
				}
			}
		}
#endif	/* TRACK_MALLOC */

		/*
		 * Update `reals' if the address changed, and update the size
		 * of the real block to the new one after reallocation.
		 */

		{
			struct realblock *rb = hash_table_lookup(reals, p);

			if (NULL == rb) {
				s_critical("%s(): MALLOC reallocated unknown block %p",
					G_STRFUNC, p);
				s_error("%s(): MALLOC invalid realloc()", G_STRFUNC);
			}

			if (n != p) {
				hash_table_remove(reals, p);
				real_check_missed_free(n);
				if (!hash_table_insert(reals, n, rb)) {
					s_error("%s(): MALLOC cannot record reallocated block %p",
						G_STRFUNC, n);
				}
			}
			rb->size = size;
		}

		return n;
	}

error:
	s_error("%s(): cannot reallocate block %p into a %zu-byte one",
		G_STRFUNC, p, size);
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

#ifdef TRACK_MALLOC

/**
 * Called at first allocation to initialize tracking structures,.
 */
static void
track_init(void)
{
	blocks = hash_table_new_real();
	not_leaking = hash_table_new_real();

	hash_table_thread_safe(blocks);
	hash_table_thread_safe(not_leaking);

#ifdef MALLOC_STATS
	stats = hash_table_new_full_real(stats_hash, stats_eq);
	hash_table_thread_safe(stats);
#endif
#ifdef MALLOC_FRAMES
	alloc_points = hash_table_new_real();
	hash_table_thread_safe(alloc_points);
#endif

	init_time = reset_time = tm_time_exact();
}

/**
 * malloc_log_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void
malloc_log_block(const void *k, void *v, void *leaksort)
{
	const struct block *b = v;
	char ago[32];

	if (hash_table_lookup(not_leaking, k))
		return;

	malloc_alloc_elapsed(malloc_block_time(b), ARYLEN(ago));

	s_warning("leaked block %p (%zu bytes) from \"%s:%d\" by %s%s",
		k, b->size, b->file, b->line, thread_id_name(b->stid), ago);

	leak_add(leaksort, b->size, b->file, b->line);

	if (b->reallocations) {
		struct block *r = b->reallocations->data;
		uint cnt = g_slist_length(b->reallocations);

		s_warning("   (realloc'ed %u time%s, lastly from \"%s:%d\" by %s)",
			PLURAL(cnt), r->file, r->line, thread_id_name(r->stid));
	}

	malloc_log_alloc_stack(k, b);
}

#ifdef MALLOC_LEAK_ALL
/**
 * malloc_log_real_block		-- hash table iterator callback
 *
 * Log used block, and record it among the `leaksort' set for future summary.
 */
static void
malloc_log_real_block(const void *k, void *v, void *leaksort)
{
	const struct realblock *rb = v;
	const void *p = k;
	char ago[32];

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
	 * block by cramming a header (the MH header, a struct malloc_header) and
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

	malloc_alloc_elapsed(malloc_real_time(rb), ARYLEN(ago));

	s_warning("leaked block %p (%zu bytes)%s", p, rb->size, ago);
	leak_add(leaksort, rb->size, "FAKED", 0);
	malloc_log_realblock_alloc_stack(p, rb);
}
#endif	/* MALLOC_LEAK_ALL */

/**
 * Flag object ``o'' as "not leaking" if not freed at exit time.
 * @return argument ``o''.
 */
void *
malloc_not_leaking(const void *o)
{
	/*
	 * Could be called on memory that was not allocated dynamically or which
	 * we do not know anything about.
	 */

	if (hash_table_lookup(reals, malloc_header_from_arena(o))) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
		goto done;
	}

	if (blocks != NULL && hash_table_lookup(blocks, o)) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
		goto done;
	}

	/*
	 * With MALLOC_VTABLE we should track most of the allocations, it may
	 * be worth noting the usage of NOT_LEAKING() calls that are made on
	 * something we know nothing about.
	 */

	s_warning("MALLOC asked to ignore leaks on unknown address %p", o);
	stacktrace_where_print(stderr);

done:
	return deconstify_pointer(o);
}

/**
 * Trace allocation point stack frame for a tracked object.
 *
 * @param o		the user-visible pointer
 * @param b		the block information for this tracked object
 */
static inline void
malloc_frames_record(const void *o, const struct block *b)
{
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	(void) o;
	(void) b;

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL) {
			st = libc_calloc(1, sizeof(*st));
			st->file = b->file;
			st->line = b->line;
			hash_table_insert(stats, st, st);
		}

		AU64_INC(&st->total_blocks);
		AU64_INC(&st->blocks);
		AU64_ADD(&st->allocated, b->size);
		AU64_ADD(&st->total_allocated, b->size);
	}
#endif /* MALLOC_STATS */

#ifdef MALLOC_FRAMES
	{
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 2);
		fr = get_frame_atom(st ? &st->alloc_frames : &gst.alloc_frames, &t);

		AU64_ADD(&fr->count, b->size);
		AU64_ADD(&fr->total_count, b->size);
		AU64_INC(&fr->blocks);

		hash_table_insert(alloc_points, o, fr);
	}
#endif /* MALLOC_FRAMES */
}

/**
 * Update allocation point for a reallocated tracked object.
 *
 * @param o		the old user-visible pointer
 * @param n		the new user-visible pointer
 * @param b		the block information for this tracked object
 * @param r		the reallocation record
 */
static inline void
malloc_frames_update(const void *o, const void *n,
	const struct block *b, const struct block *r)
{
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	(void) o;
	(void) n;
	(void) b;
	(void) r;

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (NULL == st) {
			s_warning(
				"%s(): MALLOC no alloc record of block %p from %s:%d?",
				G_STRFUNC, o, b->file, b->line);
		} else {
			/* We store variations in size, as algebraic quantities */
			AU64_INC(&st->reallocated, b->size - r->size);
			AU64_INC(&st->total_reallocated, b->size - r->size);
		}
	}
#endif /* MALLOC_STATS */

#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 2);
		fr = get_frame_atom(&st->realloc_frames, &t);

		AU64_ADD(&fr->count, b->size - r->size);
		AU64_ADD(&fr->total_count, b->size - r->size);
	}

	if (n != o) {
		struct frame *fra = hash_table_lookup(alloc_points, o);

		if (fra != NULL) {
			/* Propagate the initial allocation frame through reallocs */
			hash_table_remove(alloc_points, o);
			if (!hash_table_insert(alloc_points, n, fra)) {
				s_warning("%s(): MALLOC cannot update allocation point for %p",
					G_STRFUNC, n);
			}
		} else {
			s_warning("%s(): MALLOC lost allocation frame for %p at %s:%d -> %p",
				G_STRFUNC, o, b->file, b->line, n);
		}
	}
#endif /* MALLOC_FRAMES */
}

/**
 * Remove allocation point for a tracked object.
 *
 * @param o		the user-visible pointer
 * @param b		the block information for this tracked object
 */
static inline void
malloc_frames_cleanup(const void *o, const struct block *b)
{
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	(void) o;
	(void) b;

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL)
			s_warning(
				"%s(): MALLOC no alloc record of block %p from %s:%d?",
				G_STRFUNC, o, b->file, b->line);
		else {
			/* Count present block size, after possible realloc() */
			AU64_ADD(&st->freed, b->size);
			AU64_ADD(&st->total_freed, b->size);
			if (st->total_blocks > 0) {
				AU64_DEC(&st->total_blocks);
			} else {
				s_warning(
					"%s(): MALLOC live # of blocks was zero at free time?",
					G_STRFUNC);
			}

			/* We could free blocks allocated before "reset", don't warn */
			if (st->blocks > 0)
				AU64_DEC(&st->blocks);
		}
	}
#endif /* MALLOC_STATS */

#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 2);
		fr = get_frame_atom(&st->free_frames, &t);

		AU64_ADD(&fr->count, b->size);	/* Counts actual size, not original */
		AU64_ADD(&fr->total_count, b->size);
	}

	hash_table_remove(alloc_points, o);
#endif /* MALLOC_FRAMES */
}

/**
 * Record object `o' allocated at `file' and `line' of size `size'.
 *
 * @param o			the allocated block (user-visible pointer)
 * @param size		the size of the allocated block
 * @param owned		whether we own the pointer (allocated by ourselves)
 * @param file		the source allocation file
 * @param line		the source allocation line
 *
 * @return argument `o'.
 */
void *
malloc_record(const void *o, size_t size, bool owned,
	const char *file, int line)
{
	struct block *b;

	if (o == NULL)			/* In case it's called externally */
		return NULL;

	if (blocks == NULL)
		track_init();

	b = malloc_new_track_block(file, line, size, owned);

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

	block_check_missed_free(G_STRFUNC, o, file, line);

	if (!hash_table_insert(blocks, o, b))
		s_error("%s(): MALLOC cannot track block %p", G_STRFUNC, o);

	malloc_frames_record(o, b);

	return deconstify_pointer(o);
}

/**
 * Allocate `s' bytes using specified allocation routine.
 *
 * @param afn		the allocation routine
 * @param size		user-size to allocate
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
void *
malloc_alloc_track(alloc_fn_t afn, size_t size, const char *file,  int line)
{
	void *o;
	bool is_raw = FALSE;

#ifdef MALLOC_SAFE
	{
		size_t len = malloc_safe_size(size);
		struct malloc_header *mh;

		mh = (*afn)(len);

		if (mh == NULL)
			s_error("unable to allocate %zu bytes", size);

		o = malloc_owned_arena_setup(mh);
		block_write_trailer(o, size);
	}
#else  /* !MALLOC_SAFE */
	o = (*afn)(size);
	is_raw = TRUE;
#endif /* MALLOC_SAFE */

	if (o == NULL)
		s_error("unable to allocate %zu bytes", size);

	/*
	 * If afn is real_malloc(), then bookkeeping was already done.
	 *
	 * Otherwise we need to do it here and flag the block as not being
	 * allocated through real_malloc(), so that any attempt to real_free()
	 * it will cause an error.
	 *
	 * Also note that there is no additional real_malloc_header here
	 * at the beginning of the block.
	 */

	if (afn != real_malloc)
		malloc_bookkeeping(o, size, FALSE, FALSE, is_raw);

	return malloc_record(o, size, TRUE, file, line);
}

/**
 * Allocate `s' bytes using specified allocation routine, zeroing allocated zone.
 *
 * @param afn		the allocation routine
 * @param size		user-size to allocate
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
void *
malloc0_alloc_track(alloc_fn_t afn, size_t size, const char *file,  int line)
{
	void *o;

	o = malloc_alloc_track(afn, size, file, line);
	memset(o, 0, size);

	return o;
}

/**
 * Allocate `s' bytes using real_malloc().
 */
void *
malloc_track(size_t size, const char *file, int line)
{
	return malloc_alloc_track(real_malloc, size, file, line);
}

/**
 * Allocate `s' bytes using real_malloc(), zero the allocated zone.
 */
void *
malloc0_track(size_t size, const char *file, int line)
{
	return malloc0_alloc_track(real_malloc, size, file, line);
}

/**
 * Record freeing of allocated block.
 * @return TRUE if the block was owned
 */
bool
free_record(const void *o, const char *file, int line)
{
	struct block *b;
	const void *k;
	void *v;
	GSList *l;
	bool owned = FALSE;

	if (NULL == o)
		return FALSE;

	if (blocks == NULL || !(hash_table_lookup_extended(blocks, o, &k, &v))) {
		if (hash_table_lookup(reals, o)) {
			s_warning("%s(): block %p is untracked but listed as real block",
				G_STRFUNC, o);
			return FALSE;
		}

		if (block_is_dead(o, 4))
			s_error("MALLOC (%s:%d) duplicate free of %p", file, line, o);

		s_warning("MALLOC (%s:%d) attempt to free block at %p twice?",
			file, line, o);

		stacktrace_where_print(stderr);
		s_error("MALLOC free() of unknown address %p", o);
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

	malloc_frames_cleanup(o, b);

	hash_table_remove(blocks, o);
	hash_table_remove(not_leaking, o);

	for (l = b->reallocations; l; l = g_slist_next(l)) {
		struct block *r = l->data;
		g_assert(r->reallocations == NULL);
		libc_free(r);
	}
	g_slist_free(b->reallocations);
	libc_free(b);

	return owned;
}

/**
 * Cleanup any entry within the `reals' table for given pointer.
 */
static void
malloc_reals_cleanup(const void *p)
{
	struct realblock *rb = hash_table_lookup(reals, p);

	if (rb != NULL) {
		hash_table_remove(reals, p);
		libc_free(rb);	/* Was allocated with calloc() */
	}
}

/**
 * Free allocated block `o'.
 *
 * @param ffn		the free routine
 * @param o			the object to free
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
void
malloc_free_track(free_fn_t ffn, void *o, const char *file,  int line)
{
	struct block *b;

	if (blocks != NULL && (b = hash_table_lookup(blocks, o))) {
		struct realblock *rb;
		void *start = malloc_header_from_arena(o);

		if (b->owned) {
			if (real_free == ffn) {
				/*
				 * real_free() handles both `block' and `reals' cleanup
				 * and expects the user-visible pointer.
				 */
				(*ffn)(o);
			} else {
				/*
				 * Allocation was made via a foreign routine, for instance
				 * e_xmalloc().  It was given an extended size, maybe, and
				 * we shifted the user-pointer forward.  Hence now we need
				 * to give the foreign free routine the actual start of the
				 * block that was allocated.
				 */
				free_record(o, file, line);
				/*
				 * We cleanup `reals' before invoking the free routine (e.g.
				 * e_free()), since that routine could very well cause
				 * further memory allocation, at the same spot.
				 */
				malloc_reals_cleanup(o);
				(*ffn)(start);
			}
		} else if ((rb = hash_table_lookup(reals, o))) {
			if (rb->is_real != (real_free == ffn)) {
				s_error("MALLOC (%s:%d) attempt to free %s %zu-byte block "
					"%p allocated from %s:%d with %s()",
					file, line, rb->is_real ? "real" : "trapped",
					rb->size, o, b->file, b->line,
					stacktrace_function_name(ffn));
			}
			if (rb->is_real)
				real_free(o);		/* Takes care of cleaning-up reals */
			else {
				if (rb->is_shifted)		/* Probably never possible */
					real_check_free(o);	/* But just in case */
				else
					(*ffn)(o);
				/* Have to cleanup reals manually here */
				malloc_reals_cleanup(o);
			}
		} else {
			if (ffn != real_free) {
				s_error("MALLOC (%s:%d) attempt to free unknown %zu-byte block "
					"%p allocated from %s:%d",
					file, line, b->size, o, b->file, b->line);
			}
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
			real_free(o);
			hash_table_remove(unknowns, o);
#else
			g_free(o);
#endif	/* MALLOC_VTABLE */
		}
	} else {
		struct realblock *rb;

		free_record(o, file, line);
		if (ffn != real_free) {
			s_error("MALLOC (%s:%d) attempt to free foreign block %p",
				file, line, o);
		}
		if ((rb = hash_table_lookup(reals, o))) {
			if (rb->is_real != (real_free == ffn)) {
				s_error("MALLOC (%s:%d) attempt to free %s %zu-byte block "
					"%p with %s()",
					file, line, rb->is_real ? "real" : "trapped",
					rb->size, o, stacktrace_function_name(ffn));
			}
			real_free(o);
		} else {
			g_free(o);		/* Will go to real_free() if MALLOC_VTABLE */
		}
	}
}

/**
 * Free allocated block.
 */
void
free_track(void *o, const char *file, int line)
{
	malloc_free_track(real_free, o, file, line);
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
 * Update data structures to record that block `o' was re-allocated into
 * a block of `s' bytes at `n'.
 */
void *
realloc_record(void *o, void *n, size_t size, const char *file, int line)
{
	bool blocks_updated = FALSE;
	struct block *b;
	struct block *r;

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
			s_error("MALLOC (%s:%d) attempt to realloc freed block at %p?",
				file, line, o);
		}
	}

	/*
	 * We pass b->size, the previous size before realloc() to
	 * track the reallocation.
	 */

	r = malloc_new_track_block(file, line, b->size, b->owned);

	/* Put last realloc at head */
	b->reallocations = g_slist_prepend(b->reallocations, r);
	b->size = size;		/* The new size */

	if (n != o) {
		hash_table_remove(blocks, o);
		if (!blocks_updated) {
			block_check_missed_free(G_STRFUNC, n, file, line);
			if (!hash_table_insert(blocks, n, b)) {
				s_error("%s(): MALLOC cannot track reallocated block %p",
					G_STRFUNC, n);
			}
		}
		if (not_leaking != NULL && hash_table_remove(not_leaking, o)) {
			hash_table_insert(not_leaking, n, int_to_pointer(1));
		}
	}

	malloc_frames_update(o, n, b, r);

	return n;
}

/**
 * Realloc object `o' to `s' bytes.
 *
 * If `o' is NULL, allocate new object.
 * If `s' is 0, free the object and return NULL.
 *
 * @param rfn		the re-allocation routine
 * @param afn		the allocation routine
 * @param ffn		the free routine
 * @param o			the object to reallocate
 * @param size		user-size to allocate
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
void *
malloc_realloc_track(realloc_fn_t rfn, alloc_fn_t afn, free_fn_t ffn,
	void *o, size_t size, const char *file,  int line)
{
	if (o == NULL)
		return malloc_alloc_track(afn, size, file, line);

	if (0 == size) {
		malloc_free_track(ffn, o, file, line);
		return NULL;
	} else {
		void *n;

#ifdef MALLOC_SAFE
		struct block *b;

		if (blocks != NULL && (b = hash_table_lookup(blocks, o))) {
			if (b->owned) {
				size_t total = malloc_safe_size(size);
				struct malloc_header *mh = malloc_header_from_arena(o);

				block_check_marks(o, b, file, line);
				mh = (*rfn)(mh, total);

				if (mh == NULL)
					goto failed;

				n = malloc_owned_arena(mh);
				block_write_trailer(n, size);
				/* ``o'' was removed from ``blocks'' by real_realloc() */
			} else {
				if (rfn != real_realloc) {
					s_error(
						"MALLOC (%s:%d) trying to realloc foreign block %p to "
						"%zu byte%s, originally %zu byte%s allocated from %s:%d",
						file, line, o, PLURAL(size), PLURAL(b->size),
						b->file, b->line);
				}
				n = real_realloc(o, size);
			}
		} else {
			n = (*rfn)(o, size);
		}
#else  /* !MALLOC_SAFE */
		n = (*rfn)(o, size);
#endif /* MALLOC_SAFE */

		if (n == NULL)
			goto failed;

		return realloc_record(o, n, size, file, line);
	}

failed:
	s_error("%s(): MALLOC (%s:%d) cannot realloc block into a %zu-byte one",
		G_STRFUNC, file, line, size);
}

/**
 * Realloc object `o' to `size' bytes.
 */
void *
realloc_track(void *o, size_t size, const char *file, int line)
{
	return
		malloc_realloc_track(
			real_realloc, real_malloc, real_free,
			o, size, file, line);
}

/**
 * Duplicate buffer `p' of `s' bytes.
 *
 * If `p' is NULL, return NULL regardless of `s'.
 *
 * @param afn		the allocation routine
 * @param p			start of buffer
 * @param s			size of buffer
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
void *
malloc_copy_track(alloc_fn_t afn,
	const void *p, size_t s, const char *file, int line)
{
	void *o;

	if (p == NULL)
		return NULL;

	o = malloc_alloc_track(afn, s, file, line);
	memcpy(o, p, s);

	return o;
}

/**
 * Duplicate buffer `p' of length `size'.
 */
void *
memdup_track(const void *p, size_t size, const char *file, int line)
{
	return malloc_copy_track(real_malloc, p, size, file, line);
}

/**
 * Duplicate string `s'.
 *
 * @param afn		the allocation routine
 * @param s			string pointer
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
char *
malloc_strdup_track(alloc_fn_t afn, const char *s, const char *file, int line)
{
	void *o;
	size_t len;

	if (s == NULL)
		return NULL;

	len = vstrlen(s);
	o = malloc_alloc_track(afn, len + 1, file, line);
	memcpy(o, s, len + 1);		/* Also copy trailing NUL */

	return o;
}

/**
 * Duplicate string `s'.
 */
char *
strdup_track(const char *s, const char *file, int line)
{
	return malloc_strdup_track(real_malloc, s, file, line);
}

/**
 * Duplicate string `s', on at most `n' chars.
 *
 * @param afn		the allocation routine
 * @param s			string pointer
 * @param n			the maximum amount of characters to duplicate
 * @param file		where allocation comes from
 * @param line		line in file where allocation comes from
 */
char *
malloc_strndup_track(alloc_fn_t afn, const char *s, size_t n,
	const char *file, int line)
{
	void *o;
	char *q;

	if (s == NULL)
		return NULL;

	o = malloc_alloc_track(afn, n + 1, file, line);
	q = o;
	while (n-- > 0 && '\0' != (*q = *s++)) {
		q++;
	}
	*q = '\0';

	return o;
}

/**
 * Duplicate string `s', on at most `n' chars.
 */
char *
strndup_track(const char *s, size_t n, const char *file, int line)
{
	return malloc_strndup_track(real_malloc, s, n, file, line);
}

/**
 * Join items in `vec' with `s' in-between.
 */
char *
strjoinv_track(const char *s, char **vec, const char *file, int line)
{
	char *o;

	o = g_strjoinv(s, vec);

	return malloc_record(o, vstrlen(o) + 1, FALSE, file, line);
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

	size = vstrlen(s) + 1;
	res = real_malloc(size);
	if (NULL == res)
		s_error("out of memory");

	memcpy(res, s, size);

	while ((add = va_arg(args, char *))) {
		size_t len = vstrlen(add);

		if (len > 0) {
			res = real_realloc(res, size + len);
			if (NULL == res)
				s_error("out of memory");

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

	/*
	 * FIXME:
	 *
	 * m_strconcatv() uses real_malloc(), but we cannot mark we own this
	 * block as there is no malloc_header structure put in case we're
	 * compiled with MALLOC_SAFE_HEAD.
	 *
	 * To be able to do that, we need to have more flags in the block
	 * and be able to pass them on to malloc_record (i.e. it must not just
	 * take TRUE/FALSE but a set of flags) so that we can tell the lower
	 * layers whether a block allocated through real_malloc() has an
	 * additional malloc_header in front of the data.
	 */

	return malloc_record(o, vstrlen(o) + 1, FALSE, file, line);
}

/**
 * Perform string concatenation, returning newly allocated string.
 */
char *
strconcat_v_track(const char *file, int line, const char *s, va_list ap)
{
	char *o;

	o = m_strconcatv(s, ap);

	/*
	 * FIXME:
	 *
	 * m_strconcatv() uses real_malloc(), but we cannot mark we own this
	 * block as there is no malloc_header structure put in case we're
	 * compiled with MALLOC_SAFE_HEAD.
	 *
	 * To be able to do that, we need to have more flags in the block
	 * and be able to pass them on to malloc_record (i.e. it must not just
	 * take TRUE/FALSE but a set of flags) so that we can tell the lower
	 * layers whether a block allocated through real_malloc() has an
	 * additional malloc_header in front of the data.
	 */

	return malloc_record(o, vstrlen(o) + 1, FALSE, file, line);
}

/**
 * Perform printf into newly allocated string.
 */
char *
strdup_vprintf_track(const char *file, int line, const char *fmt, va_list ap)
{
	char *o;

	o = g_strdup_vprintf(fmt, ap);

	return malloc_record(o, vstrlen(o) + 1, FALSE, file, line);
}

/**
 * Perform printf into newly allocated string, returning length of generated
 * string in `len'.
 */
char *
strdup_len_vprintf_track(const char *file, int line,
	const char *fmt, va_list ap, size_t *len)
{
	char *o;
	size_t l;

	o = g_strdup_vprintf(fmt, ap);
	l = vstrlen(o);

	if (len != NULL)
		*len = l;

	return malloc_record(o, l + 1, FALSE, file, line);
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

	return malloc_record(o, vstrlen(o) + 1, FALSE, file, line);
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
		malloc_record(x, vstrlen(x) + 1, FALSE, file, line);

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

	return malloc_record(s, vstrlen(s) + 1, FALSE, file, line);
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
		28,				/* Approximative size */
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
		malloc_record(PTRLEN(iter), FALSE, file, line);
	}
	return deconstify_pointer(list);
}

GSList *
track_slist_alloc(const char *file, int line)
{
	return malloc_record(g_slist_alloc(), sizeof(GSList), FALSE, file, line);
}

GSList *
track_slist_append(GSList *l, void *data, const char *file, int line)
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
track_slist_prepend(GSList *l, void *data, const char *file, int line)
{
	GSList *new;

	new = track_slist_alloc(file, line);
	new->data = data;
	new->next = l;

	return new;
}

GSList *
track_slist_prepend_const(GSList *l, const void *data,
	const char *file, int line)
{
	GSList *new;

	new = track_slist_alloc(file, line);
	new->data = deconstify_pointer(data);
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
track_slist_remove(GSList *l, void *data, const char *file, int line)
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
track_slist_insert(GSList *l, void *data, int pos, const char *file, int line)
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
track_slist_insert_sorted(GSList *l, void *d, GCompareFunc c,
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
track_slist_insert_after(GSList *l, GSList *lk, void *data,
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
track_list_append(GList *l, void *data, const char *file, int line)
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
track_list_prepend(GList *l, void *data, const char *file, int line)
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
		malloc_record(PTRLEN(iter), FALSE, file, line);
	}
	return deconstify_pointer(list);
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
track_list_remove(GList *l, void *data, const char *file, int line)
{
	GList *lk;

	lk = g_list_find(l, data);
	if (lk == NULL)
		return l;

	return track_list_delete_link(l, lk, file, line);
}

GList *
track_list_insert(GList *l, void *data, int pos, const char *file, int line)
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
track_list_insert_sorted(GList *l, void *d, GCompareFunc c,
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
track_list_insert_after(GList *l, GList *lk, void *data,
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
track_list_insert_before(GList *l, GList *lk, void *data,
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
#endif /* TRACK_MALLOC */

/***
 *** This section contains general-purpose allocation summarizing routines that
 *** are used when MALLOC_STATS is on.
 ***
 *** This is used to spot the places where allocation takes place, sorted
 *** by decreasing allocation size.
 ***/

#ifdef MALLOC_STATS

struct afiller {		/* Used by hash table iterator to fill alloc array */
	const struct malloc_stats **stats;
	int count;			/* Size of `stats' array */
	int idx;			/* Next index to be filled */
};

/**
 * Compare two pointers to "filestat_t" based on their allocation value,
 * in reverse order. -- qsort() callback
 */
static int
stats_allocated_cmp(const void *p1, const void *p2)
{
	const struct malloc_stats * const *s1 = p1, * const *s2 = p2;

	/* Reverse order: largest first */
	return CMP((*s2)->allocated, (*s1)->allocated);
}

/**
 * Compare two pointers to "filestat_t" based on their total allocation value,
 * in reverse order. -- qsort() callback
 */
static int
stats_total_allocated_cmp(const void *p1, const void *p2)
{
	const struct malloc_stats * const *s1 = p1, * const *s2 = p2;

	/* Reverse order: largest first */
	return CMP((*s2)->total_allocated, (*s1)->total_allocated);
}

/**
 * Compare two pointers to "filestat_t" based on their residual value,
 * in reverse order. -- qsort() callback
 */
static int
stats_residual_cmp(const void *p1, const void *p2)
{
	const struct malloc_stats * const *s1_ptr = p1, * const *s2_ptr = p2;
	const struct malloc_stats *s1 = *s1_ptr, *s2 = *s2_ptr;
	ssize_t i1 = s1->allocated + s1->reallocated - s1->freed;
	ssize_t i2 = s2->allocated + s2->reallocated - s2->freed;
	int ret;

	/* Reverse order: largest first */
	ret = CMP(i2, i1);
	return ret ? ret : stats_allocated_cmp(p1, p2);
}

/**
 * Compare two pointers to "filestat_t" based on their total residual value,
 * in reverse order. -- qsort() callback
 */
static int
stats_total_residual_cmp(const void *p1, const void *p2)
{
	const struct malloc_stats * const *s1_ptr = p1, * const *s2_ptr = p2;
	const struct malloc_stats *s1 = *s1_ptr, *s2 = *s2_ptr;
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
	const struct malloc_stats *st = value;
	const struct malloc_stats **e;

	(void) unused_key;

	g_assert(filler->idx < filler->count);

	e = &filler->stats[filler->idx++];
	*e = st;
}

/**
 * Dump the stats held in the specified array.
 */
static void G_COLD
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
		const struct malloc_stats *st = filler->stats[i];
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
			0 : hash_table_count(st->alloc_frames);
		free_stacks = st->free_frames == NULL ?
			0 : hash_table_count(st->free_frames);
		realloc_stacks = st->realloc_frames == NULL ?
			0 : hash_table_count(st->realloc_frames);
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
alloc_dump(FILE *f, bool total)
{
	int count;
	struct afiller filler;
	time_t now;

	count = hash_table_count(stats);

	if (count == 0)
		return;

	now = tm_time();
	fprintf(f, "--- distinct allocation spots found: %d at %s\n",
		count, short_time_ascii(delta_time(now, init_time)));

	filler.stats = real_malloc(sizeof(struct malloc_stats *) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearise hash table into an array before sorting it by
	 * decreasing allocation size.
	 */

	hash_table_foreach(stats, stats_fill_array, &filler);
	vsort(filler.stats, count, sizeof(struct malloc_stats *),
		total ? stats_total_allocated_cmp : stats_allocated_cmp);

	/*
	 * Dump the allocation based on allocation sizes.
	 */

	fprintf(f, "--- summary by decreasing %s allocation size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time_ascii(delta_time(now, total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * Now linearise hash table by decreasing residual allocation size.
	 */

	filler.idx = 0;

	hash_table_foreach(stats, stats_fill_array, &filler);
	vsort(filler.stats, count, sizeof(struct malloc_stats *),
		total ? stats_total_residual_cmp : stats_residual_cmp);

	fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time_ascii(now - (total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * If we were not outputting for total memory, finish by dump sorted
	 * on total residual allocation.
	 */

	if (!total) {
		filler.idx = 0;

		hash_table_foreach(stats, stats_fill_array, &filler);
		vsort(filler.stats, count, sizeof(struct malloc_stats *),
			stats_total_residual_cmp);

		fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
			"total", "at", short_time_ascii(delta_time(now, init_time)));
		stats_array_dump(f, &filler);
	}

	fprintf(f, "--- end summary at %s\n", short_time_ascii(now - init_time));

	real_free(filler.stats);
}

/**
 * Reset incremental allocation and free counters. -- hash table iterator
 */
static void
stats_reset(const void *uu_key, void *value, void *uu_user)
{
	struct malloc_stats *st = value;

	(void) uu_key;
	(void) uu_user;

	st->blocks = st->allocated = st->freed = st->reallocated = 0;
}

/**
 * Atomically dump the allocation stats and reset the incremental allocation
 * statistics.
 */
void
alloc_reset(FILE *f, bool total)
{
	time_t now = tm_time();

	alloc_dump(f, total);
	hash_table_foreach(stats, stats_reset, NULL);

	fprintf(f, "--- incremental allocation stats reset after %s.\n",
		short_time_ascii(now - reset_time));

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
static void G_COLD
malloc_glib12_check(void)
{
	vtable_works = TRUE;

#if !GLIB_CHECK_VERSION(2,0,0)
	{
		void *p;
		size_t old_size = hash_table_count(reals);

		/*
		 * Check whether the remapping is effective. This may not be
		 * the case for our GLib 1.2 hack. This is required for Darwin,
		 * for example.
		 */
		p = g_strdup("");
		if (hash_table_count(reals) == old_size) {
			static GMemVTable zero_vtable;
			s_warning("resetting g_mem_set_vtable()");
			g_mem_set_vtable(&zero_vtable);
			vtable_works = FALSE;
		} else {
			G_FREE_NULL(p);
		}
	}
#endif	/* GLib < 2.0.0 */
}
#endif	/* MALLOC_VTABLE */

/*
 * Sanity checks of malloc settings.
 */
static void G_COLD
malloc_sanity_checks(void)
{
	static const char test_string[] = "test string";
	gchar *p = g_strdup(test_string);

	if (0 != strcmp(test_string, p))
		s_error("g_strdup() is not working");
	G_FREE_NULL(p);

	p = g_malloc(CONST_STRLEN(test_string) + 20);
	memcpy(p, test_string, CONST_STRLEN(test_string) + 1);
	if (0 != strcmp(test_string, p))
		s_error("g_malloc() is not working");

	p = g_realloc(p, CONST_STRLEN(test_string) + 1);
	if (0 != strcmp(test_string, p))
		s_error("g_realloc() is not working");

	p = g_realloc(p, CONST_STRLEN(test_string) + 512);
	if (0 != strcmp(test_string, p))
		s_error("g_realloc() is not working");
	G_FREE_NULL(p);
}

/**
 * Attempt to trap all raw g_malloc(), g_free(), g_realloc() calls
 * when TRACK_MALLOC and MALLOC_VTABLE are defined.
 *
 * This allows features like MALLOC_FREE_ERASE, MALLOC_SAFE, etc... to be
 * used on blocks that are allocated by glib internally or by GTK.  It also
 * enables us to see frees for blocks we track but give to GTK, and never
 * see again otherwise.
 */
void G_COLD
malloc_init_vtable(void)
{
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	malloc_init_tracking();
#endif

	G_IGNORE_PUSH(-Wdeprecated-declarations);	/* For g_mem_set_vtable() */

#ifdef MALLOC_VTABLE
	{
		static GMemVTable vtable;

		vtable.malloc = real_malloc;
		vtable.realloc = real_realloc;
		vtable.free = real_free;

		g_mem_set_vtable(&vtable);
		malloc_glib12_check();
	}
#else	/* !MALLOC_VTABLE */
	/*
	 * On Windows, redirect all glib memory allocation to xmalloc() / xfree().
	 */

	if (is_running_on_mingw()) {
		static GMemVTable vtable;

#if GLIB_CHECK_VERSION(2,0,0)
		static char variable[] = "G_SLICE=always-malloc";
		putenv(variable);
#endif	/* GLib >= 2.0.0 */

		vtable.malloc = xmalloc;
		vtable.realloc = xrealloc;
		vtable.free = xfree;

		g_mem_set_vtable(&vtable);
	}
#endif	/* MALLOC_VTABLE */

	G_IGNORE_POP;			/* For g_mem_set_vtable() */

	malloc_sanity_checks();
}

/**
 * Called from main() to log settings at startup.
 */
void G_COLD
malloc_show_settings_log(logagent_t *la)
{
	bool has_setting = FALSE;
	struct malloc_settings {
		uint8 use_halloc;
		uint8 track_vmm;
		uint8 track_malloc;
		uint8 track_zalloc;
		uint8 remap_zalloc;
		uint8 malloc_stats;
		uint8 malloc_frames;
		uint8 malloc_safe;
		uint8 malloc_safe_head;
		ulong malloc_trailer_len;
		uint8 malloc_free_erase;
		uint8 malloc_dup_free;
		uint8 malloc_vtable;
		uint8 malloc_periodic;
		ulong malloc_period;
		ulong malloc_leak_all;
		ulong malloc_time;
		bool vtable_works;
	} settings;

	ZERO(&settings);

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
#ifdef TRACK_VMM
	settings.track_vmm = TRUE;
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
#ifdef MALLOC_TIME
	settings.malloc_time = TRUE;
	has_setting = TRUE;
#endif
#ifdef MALLOC_LEAK_ALL
	settings.malloc_leak_all = TRUE;
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
		log_message(la, "malloc settings: %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			settings.track_vmm ? "TRACK_VMM " : "",
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
			settings.malloc_time ? "MALLOC_TIME " : "",
			settings.malloc_leak_all ? "MALLOC_LEAK_ALL " : "",
			settings.malloc_periodic ? "MALLOC_PERIODIC " : "");
	}

	if (settings.malloc_safe)
		log_message(la, "malloc variable MALLOC_TRAILER_LEN = %lu",
			settings.malloc_trailer_len);

	if (settings.malloc_periodic)
		log_message(la, "malloc variable MALLOC_PERIOD = %lu",
			settings.malloc_period);

	if (settings.malloc_vtable)
		log_message(la, "malloc setting MALLOC_VTABLE %s",
			settings.vtable_works ? "works" : "does NOT work!");
}

/**
 * Called from main() to log settings at startup.
 */
void G_COLD
malloc_show_settings(void)
{
	malloc_show_settings_log(log_agent_stderr_get());
}

/**
 * @return amount of VMM memory used by internal tracking structures.
 */
size_t G_COLD
malloc_memory_used(void)
{
	size_t res = 0;
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)

	if (reals != NULL)
		res += hash_table_arena_memory(reals);
	if (unknowns != NULL)
		res += hash_table_arena_memory(unknowns);
#endif
#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
	if (blocks != NULL)
		res += hash_table_arena_memory(blocks);
	if (not_leaking != NULL)
		res += hash_table_arena_memory(not_leaking);
#endif

	return res;
}

/**
 * Dump all the blocks that are still used.
 */
void G_COLD
malloc_close(void)
{
#ifdef TRACK_MALLOC
	leak_set_t *leaksort;

	if (blocks == NULL)
		return;

	thread_suspend_others(TRUE);

#ifdef MALLOC_STATS
	g_message("aggregated memory usage statistics:");
	alloc_dump(stderr, TRUE);
#endif

	g_message("checking for block corruption...");
	malloc_check_allocations(NULL);

	g_message("computing leak information...");

	leaksort = leak_init();
	hash_table_copy_foreach(blocks, malloc_log_block, leaksort);

	/*
	 * We can't iterate on "reals" and fill "leaksort" without affecting
	 * the table since real_*() routines are used to allocate memory.
	 * That is why we're using hash_table_copy_foreach().
	 */

#ifdef MALLOC_LEAK_ALL
	hash_table_copy_foreach(reals, malloc_log_real_block, leaksort);
#endif	/* MALLOC_LEAK_ALL */

	leak_dump(leaksort);
	leak_close_null(&leaksort);

	thread_unsuspend_others();
#endif	/* TRACK_MALLOC */
}

/**
 * When MALLOC_CATCH_MALLOC is defined, we trap malloc() entry points and
 * friends from the C library by redefining the routines, yet we want the
 * ability to call the C library versions underneath.
 *
 * This is the job of malloc_trap_init() to capture, through the dynamic
 * linker, the next entry points in the linking chain.
 *
 * The purpose of trapping the entry points is to be able to redirect allocation
 * to real_malloc() and friends, so that we can track which block is allocated
 * and freed, when allocation is done outside of the program (i.e. in library
 * routines such as the C library itself).
 *
 * In order to allow for some bootstrapping period, we actually make sure we
 * do not redirect until the malloc_tracking_init() routine has been completed,
 * so that we are sure our tracking data structures are present.
 *
 * Also real_malloc() can allocate memory through calloc() and we need to be
 * careful to not call the calloc() routine blindly so as to avoid endless
 * recursions. That's why we make sure to invoke libc_calloc() and libc_free()
 * directly: when MALLOC_CATCH_MALLOC is not defined, these point to the real
 * calloc() and free() routines in the libc.
 */
#ifdef MALLOC_CATCH_MALLOC

#ifdef I_DLFCN
#define _GNU_SOURCE
#include <dlfcn.h>
#endif

/*
 * These are not used by this layer and therefore do not need a trapping
 * function call_libc_xxx(), nor do they need to be visible when the
 * MALLOC_CATCH_MALLOC symbol is not defined.
 */
static int (*libc_posix_memalign)(void **, size_t, size_t);
static void *(*libc_memalign)(size_t, size_t);
static int (*libc_valloc)(size_t);

static once_flag_t malloc_trap_inited;
static struct {
	void *p;				/* Allocated block */
	size_t size;			/* Length of allocated block */
} malloc_booted[20];
static uint malloc_booted_idx;
static uint malloc_booted_cnt;
static void *malloc_booted_first;
static void *malloc_booted_last;

/**
 * @return whether malloc block is a boot block.
 */
static bool
malloc_is_boot(const void *p)
{
	return ptr_cmp(p, malloc_booted_first) >= 0 &&
		ptr_cmp(p, malloc_booted_last) <= 0;
}

/**
 * Return size of boot block at `p'.
 */
static size_t
malloc_boot_size(void *p)
{
	uint i;

	for (i = 0; i < malloc_booted_idx; i++) {
		if (malloc_booted[i].p == p)
			return malloc_booted[i].size;
	}

	s_error("%s(): block %p is not a boot block (already freed?)",
		G_STRFUNC, p);
}

/**
 * Low-level allocation using sbrk().
 *
 * This is done during bootstrapping, if we do not know the libc call to
 * invoke to get the memory, yet need to allocate some memory.
 *
 * This would happen when dlsym() needs to allocate memory to perform its
 * operation.
 *
 * Blocks are tracked in a limited chunk, so that should free() be called
 * on such a block address later on, we are able to "free" it.
 */
static void *
malloc_boot_alloc(size_t size)
{
	void *p;

	if (malloc_booted_idx >= N_ITEMS(malloc_booted))
		s_error("%s(): too many bootstrapping allocations", G_STRFUNC);

#ifdef MALLOC_CATCH_VERBOSE
	fputc('#', stderr);		/* Flags bootstrapping allocation */
#endif

	malloc_booted_cnt++;
	p = malloc_booted[malloc_booted_idx].p  = sbrk(size);
	malloc_booted[malloc_booted_idx++].size = size;

	/* Record boot allocation ranges for possible realloc() or free() later */

	if G_UNLIKELY(NULL == malloc_booted_first)
		malloc_booted_first = p;
	malloc_booted_last = p;

	return p;
}

/**
 * Checks whether block address is known to be one of the bootstrapping blocks.
 *
 * If it happens to be a bootstrapping block, mark it "freed" but do not actually
 * reclaim the allocated memory.
 *
 * @return whether block address was that of a bootstrapping block.
 */
static bool
malloc_boot_free(void *p)
{
	uint i;

	for (i = 0; i < malloc_booted_idx; i++) {
		if (malloc_booted[i].p == p) {
			malloc_booted[i].p = NULL;
			malloc_booted_cnt--;
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Wrap dlsym() calls so that we can trace failure.
 */
static void *
find_symbol(const char *sym, bool mandatory)
{
	void *p = dlsym(RTLD_NEXT, sym);

	if (NULL == p && mandatory)
		s_error("%s(): cannot find %s(): %s\n", G_STRFUNC, sym, dlerror());

	return p;
}

#define FIND_SYMBOL(x)	libc_ ## x = find_symbol(# x, TRUE); atomic_mb()
#define LOOK_SYMBOL(x)	libc_ ## x = find_symbol(# x, FALSE); atomic_mb()

/**
 * Initialize trapping of malloc functions
 */
static void
malloc_trap_init(void)
{
	FIND_SYMBOL(calloc);
	FIND_SYMBOL(malloc);
	FIND_SYMBOL(realloc);
	FIND_SYMBOL(free);
	FIND_SYMBOL(posix_memalign);
	LOOK_SYMBOL(memalign);			/* Deprecated, could be missing */
	LOOK_SYMBOL(valloc);			/* Deprecated, could be missing */

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "malloc_trap_init() called\n");
#endif
}

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
  * Hook to trap malloc().
  */
void *
malloc(size_t size)
{
	void *p;

	ONCE_FLAG_RUN_SAFE(malloc_trap_inited, malloc_trap_init);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "malloc(%lu) = ", (unsigned long) size);
#endif

	if (ONCE_DONE(malloc_tracking_inited)) {
		p = real_malloc(size);
	} else if (libc_malloc == call_libc_malloc) {
		/* Allocation before we know how to find malloc() in the libc */
		p = malloc_boot_alloc(size);
	} else {
		p = libc_malloc(size);
	}

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "%p%c\n", p, ONCE_DONE(malloc_tracking_inited) ? '+' : '!');
#endif

	return p;
}

void *
realloc(void *p, size_t size)
{
	void *q;

	ONCE_FLAG_RUN_SAFE(malloc_trap_inited, malloc_trap_init);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "realloc(%p,%zu) = ", p, (unsigned long) size);
#endif

	if (ONCE_DONE(malloc_tracking_inited))
		q = real_realloc(p, size);
	else
		q = libc_realloc(p, size);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "%p%c\n", q, ONCE_DONE(malloc_tracking_inited) ? '+' : '!');
#endif

	return q;
}

void *
calloc(size_t nmemb, size_t size)
{
	void *p;

	ONCE_FLAG_RUN_SAFE(malloc_trap_inited, malloc_trap_init);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "calloc(%zu, %zu) = ", nmemb, size);
#endif

	if (ONCE_DONE(malloc_tracking_inited)) {
		p = real_calloc(nmemb, size);
	} else if (libc_calloc == call_libc_calloc) {
		size_t len = size_saturate_mult(nmemb, size);
		/* Allocation before we know how to find calloc() in the libc */
		p = malloc_boot_alloc(len);
		if (p != NULL)
			memset(p, 0, len);
	} else {
		p = libc_calloc(nmemb, size);
	}

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "%p%c\n", p, ONCE_DONE(malloc_tracking_inited) ? '+' : '!');
#endif

	return p;
}

void
free(void *p)
{
	ONCE_FLAG_RUN_SAFE(malloc_trap_inited, malloc_trap_init);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "free(%p)%c\n",
		p, ONCE_DONE(malloc_tracking_inited) ? '+' : '!');
#endif

	if (NULL == p)
		return;			/* Silently ignore */

	if (malloc_booted_cnt != 0) {
		if (malloc_boot_free(p))
			return;
	}

	if (ONCE_DONE(malloc_tracking_inited))
		real_free(p);
	else
		libc_free(p);
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int r;

	ONCE_FLAG_RUN_SAFE(malloc_trap_inited, malloc_trap_init);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "posix_memalign(%zu, %zu) = ", alignment, size);
#endif

	if (NULL == libc_posix_memalign)
		s_error("%s(): no libc counterpart!", G_STRFUNC);

	r = libc_posix_memalign(memptr, alignment, size);

#ifdef MALLOC_CATCH_VERBOSE
	fprintf(stderr, "%p (%d)\n", *memptr, r);
#endif

	/*
	 * A block allocated via posix_memalign() is always raw,
	 * regardless of MALLOC_SAFE settings.
	 */

	malloc_bookkeeping(*memptr, size, TRUE, FALSE, TRUE);

	return r;
}

#endif /* MALLOC_CATCH_MALLOC */

/* vi: set ts=4 sw=4 cindent:  */
