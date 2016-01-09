/*
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

#if defined(MALLOC_STATS) && !defined(TRACK_MALLOC)
#define TRACK_MALLOC
#endif

#define MALLOC_SOURCE	/**< Avoid nasty remappings, but include signatures */

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
#include "parse.h"		/* For parse_pointer() */
#include "path.h"		/* For filepath_basename() */
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"			/* For tm_time() */
#include "unsigned.h"	/* For size_is_non_negative() */
#include "vsort.h"
#include "xmalloc.h"

/*
 * The following setups are more or less independent from each other.
 *
 * This comes at the price of heavy usage of conditinal compilation
 * throughout the file...
 *
 * All of these have effect even when TRACK_MALLOC is not defined.
 */

#if 0
#define MALLOC_VTABLE		/* Try to redirect glib's malloc here */
#endif
#if 0
#define MALLOC_SAFE				/* Add trailer magic to each block */
#define MALLOC_TRAILER_LEN	8	/* Additional trailer len, past end mark */
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

/*
 * Enable MALLOC_VTABLE to avoid missing free() events from GTK if they
 * turn on TRACK_MALLOC.
 */

#if defined(TRACK_MALLOC) && !defined(MALLOC_VTABLE)
#define MALLOC_VTABLE		/* Or would miss some free(), report false leaks */
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

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
static hash_table_t *reals;
static hash_table_t *unknowns;
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
#ifdef MALLOC_TIME
	time_t ttime;			/**< Tracking start time */
#endif
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
	size_t size;			/**< Size of allocated block */
#ifdef MALLOC_TIME
	time_t atime;			/**< Allocation time */
#endif
#if defined(MALLOC_SAFE) || defined(MALLOC_PERIODIC)
	unsigned corrupted:1;		/**< Whether block was marked as corrupted */
	unsigned header_corrupted:1;/**< Whether header corruption was reported */
#endif
};

#ifdef TRACK_MALLOC
static time_t init_time = 0;
static time_t reset_time = 0;

static bool free_record(const void *o, const char *file, int line);
#endif

#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
static hash_table_t *blocks = NULL;
static hash_table_t *not_leaking = NULL;
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
		static spinlock_t frame_lock = SPINLOCK_INIT;
		spinlock(&frame_lock);
		if (NULL == (ht = *hptr)) {
			ht = hash_table_new_full_real(stack_hash, stack_eq);
			hash_table_thread_safe(ht);
			*hptr = ht;
		}
		spinunlock(&frame_lock);
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
malloc_header_from_arena(const void *o)
{
	return cast_to_pointer((char *) o - SAFE_ARENA_OFFSET);
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
static bool G_UNUSED
block_check_trailer(const void *o, size_t size,
	const char *file, int line, const char *op_file, int op_line,
	bool showstack)
{
	bool error = FALSE;
	size_t trailer = MALLOC_TRAILER_LEN;
	const char *p;

	if (MALLOC_END_MARK != peek_be32(const_ptr_add_offset(o, size))) {
		error = TRUE;
		s_warning(
			"MALLOC (%s:%d) block %p (%zu bytes) from %s:%d "
			"has corrupted end mark",
			op_file, op_line, o, size, file, line);
		goto done;
	}

	p = const_ptr_add_offset(o, size + sizeof(uint32));
	while (trailer--) {
		if (*p++ != MALLOC_TRAILER_MARK) {
			error = TRUE;
			s_warning(
				"MALLOC (%s:%d) block %p (%zu bytes) from %s:%d "
				"has corrupted trailer",
				op_file, op_line, o, size, file, line);
			break;
		}
	}

done:
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

	if (block_check_trailer(o, b->size, b->file, b->line, file, line, FALSE)) {
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
	const char *file, int line, const char *op_file, int op_line,
	bool showstack)
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
 * With MALLOC_PERIODIC, all the allocated blocks (whether they be tracked
 * or allocated directly via real_malloc() and friends)
 */
#ifdef MALLOC_PERIODIC

static bool need_periodic;

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
block_check(const void *key, void *value, void *ctx)
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
real_check(const void *key, void *value, void *ctx)
{
	struct block_check_context *bc = ctx;
	struct realblock *rb = value;
	void *p = deconstify_pointer(key);

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
		s_warning("MALLOC allocated block %p marked as DEAD", p);
	}

#ifdef MALLOC_SAFE
	if (!rb->header_corrupted) {
		struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
		if (REAL_MALLOC_MAGIC != rmh->magic) {
			rb->header_corrupted = TRUE;
			bc->new_corrupted++;
			s_warning("MALLOC corrupted real block magic at %p (%zu byte%s)",
				p, rb->size, plural(rb->size));
		} else if (rmh->size != rb->size) {
			/* Can indicate memory corruption as well */
			bc->new_corrupted++;
			rb->header_corrupted = TRUE;
			s_warning("MALLOC size mismatch for real block %p: "
				"hashtable says %zu byte%s, header says %zu",
				p, rb->size, plural(rb->size), rmh->size);
		}
	}
#endif	/* MALLOC_SAFE */
}

/**
 * Periodic check to make sure all the known blocks are correct.
 */
static bool
malloc_periodic(void *unused_obj)
{
	struct block_check_context ctx;
	bool checked = FALSE;
	tm_t start, end;
	static unsigned errors;
	char tracked_size[SIZE_FIELD_MAX];
	char real_size[SIZE_FIELD_MAX];
	
	(void) unused_obj;

	if (0 == errors) {
		s_message("malloc periodic check starting...");
	} else {
		s_message("malloc periodic check starting... [%u error%s already]",
			errors, plural(errors));
	}

	ZERO(&ctx);
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
		s_message("malloc periodic: nothing to check, disabling.");
		return FALSE;
	}

	tm_now_exact(&end);

	short_size_to_string_buf(ctx.tracked_size, FALSE,
		tracked_size, sizeof tracked_size);
	short_size_to_string_buf(ctx.real_size, FALSE,
		real_size, sizeof real_size);

	if (0 == ctx.old_corrupted && 0 == ctx.new_corrupted) {
		s_message("malloc periodic check done (%u msecs): "
			"tracked: %u [%s], real: %u [%s]",
			(unsigned) tm_elapsed_ms(&end, &start),
			ctx.tracked_count, tracked_size,
			ctx.real_count, real_size);
	} else {
		if (ctx.new_corrupted) {
			errors++;
		}
		s_warning("malloc periodic check done (%u msecs): %s"
			"tracked: %u [%s], real: %u [%s], "
			"NEWLY CORRUPTED: %u (%u old)",
			(unsigned) tm_elapsed_ms(&end, &start),
			0 == ctx.new_corrupted ? "" : "WATCH OUT ",
			ctx.tracked_count, tracked_size,
			ctx.real_count, real_size,
			ctx.new_corrupted, ctx.old_corrupted);
	}

	return TRUE;
}

static void
install_malloc_periodic(void)
{
	need_periodic = FALSE;
	cq_periodic_main_add(MALLOC_PERIOD, malloc_periodic, NULL);
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
		s_warning("MALLOC (%s:%d) reusing %sblock %p (%zu byte%s) "
			"from %s:%d, missed its freeing",
			file, line, b->owned ? "owned " : "foreign ",
			p, b->size, plural(b->size), b->file, b->line);
		stacktrace_where_print(stderr);

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

				s_warning("MALLOC reusing %s block %p (%zu byte%s) "
					"from %s:%d, missed its freeing",
					b->owned ? "owned" : "foreign",
					p, rb->size, plural(rb->size), b->file, b->line);
				b->owned = FALSE;
				free_record(p, _WHERE_, __LINE__);
			}
		}
#else	/* !TRACK_MALLOC */
		s_warning("MALLOC reusing real block %p (%zu byte%s), "
			"missed its freeing",
			p, rb->size, plural(rb->size));
#endif	/* TRACK_MALLOC */
		s_warning("current_frame:");
		stacktrace_where_print(stderr);
#ifdef MALLOC_FRAMES
		s_warning("allocation frame:");
		stacktrace_atom_print(stderr, rb->alloc->ast);
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
	if (need_periodic)
		install_malloc_periodic();
#endif

#ifdef MALLOC_SAFE
	{
		size_t len = real_malloc_safe_size(size);
		struct real_malloc_header *rmh;

		rmh = malloc(len);

		if (rmh == NULL)
			s_error("unable to allocate %zu bytes", size);

		rmh->magic = REAL_MALLOC_MAGIC;
		rmh->size = size;
		o = rmh->arena;
		block_write_trailer(o, size);
	}
#else  /* !MALLOC_SAFE */

	o = malloc(size);

#endif /* MALLOC_SAFE */

	if (o == NULL)
		s_error("unable to allocate %zu bytes", size);

	block_clear_dead(o, size);

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	{
		struct realblock *rb;

		rb = calloc(1, sizeof *rb);
		rb->size = size;
		real_check_missed_free(o);
		if (!hash_table_insert(reals, o, rb)) {
			s_error("MALLOC cannot record real block %p", o);
		}
#ifdef MALLOC_TIME
		rb->atime = tm_time();
#endif
#ifdef MALLOC_FRAMES
		{
			struct stacktrace t;
			struct frame *fr;

			stacktrace_get(&t);	/* Want to see real_malloc() in stack */
			fr = get_frame_atom(&gst.alloc_frames, &t);
			ATOMIC_ADD(fr->count, size);
			ATOMIC_ADD(fr->total_count, size);
			ATOMIC_INC(fr->blocks);
			rb->alloc = fr;
		}
#endif	/* MALLOC_FRAMES */
	}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

	return o;
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

	free(rmh);
}
#endif	/* MALLOC_SAFE */

#if defined(TRACK_MALLOC) || defined(TRACK_VMM)
/**
 * Calls real free(), no tracking.
 * Block must have been allocated via real_malloc().
 */
static void
real_free(void *p)
{
#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
	bool owned = FALSE;
	bool real = FALSE;
	void *start = p;
#endif
#ifdef TRACK_MALLOC
	struct block *b = NULL;
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
			if (block_is_dead(start, sizeof(uint))) {
				s_warning("MALLOC probable duplicate free of %p", p);
				stacktrace_where_print(stderr);
				s_error("MALLOC invalid free()");
			} else {
				bool ok = FALSE;
#ifdef MALLOC_VTABLE
				/* See comment in free_track() */
				ok = hash_table_lookup(unknowns, p) != NULL;
#endif
				if (!ok) {
					s_warning("MALLOC freeing unknown block %p", p);
					stacktrace_where_print(stderr);
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
#endif	/* TRACK_MALLOC || TRACK_VMM */
#endif /* TRACK_MALLOC || TRACK_ZALLOC || TRACK_VMM || MALLOC_VTABLE */

#if defined(TRACK_MALLOC) || defined(TRACK_VMM)
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
#endif	/* TRACK_MALLOC || TRACK_VMM */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
/**
 * Calls real realloc(), no tracking.
 */
static void *
real_realloc(void *ptr, size_t size)
{
	void *result;
	void *p = ptr;
#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
	struct block *b = NULL;
#endif
#ifdef MALLOC_PERIODIC
	if (need_periodic)
		install_malloc_periodic();
#endif

	if (p == NULL)
		return real_malloc(size);

	if (0 == size) {
		real_free(p);
		return NULL;
	} else {
		void *n;

#if defined(TRACK_MALLOC) || defined(MALLOC_SAFE_HEAD)
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
#endif	/* TRACK_MALLOC || MALLOC_SAFE_HEAD */

#ifdef MALLOC_SAFE
		{
			struct real_malloc_header *rmh = real_malloc_header_from_arena(p);
			size_t len = real_malloc_safe_size(size);

			if (REAL_MALLOC_MAGIC != rmh->magic) {
				s_error("MALLOC realloc(): corrupted real block magic at %p",
					p);
			}

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
#else	/* !MALLOC_SAFE */
		result = n = realloc(p, size);
#endif	/* MALLOC_SAFE */

		if (n == NULL)
			s_error("cannot realloc block into a %zu-byte one", size);

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
					s_error("MALLOC cannot track reallocated block %p", n);
				}
			}
		}
#endif	/* TRACK_MALLOC */
		{
			struct realblock *rb = hash_table_lookup(reals, ptr);

			if (NULL == rb) {
				s_warning("MALLOC reallocated unknown block %p", p);
				stacktrace_where_print(stderr);
				s_error("MALLOC invalid realloc()");
			}

			if (result != ptr) {
				hash_table_remove(reals, ptr);
				real_check_missed_free(result);
				if (!hash_table_insert(reals, result, rb)) {
					s_error("MALLOC cannot record reallocated block %p",
						result);
				}
			}
			rb->size = size;
		}

		return result;
	}
}
#endif	/* TRACK_MALLOC || MALLOC_VTABLE */

#ifdef TRACK_MALLOC

#ifdef MALLOC_FRAMES
static hash_table_t *alloc_points; /**< Maps a block to its allocation frame */
#endif

#if 0	/* UNUSED */
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
#endif	/* UNUSED */

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

#ifdef MALLOC_TIME
	str_bprintf(ago, sizeof ago, " [%s]",
		short_time_ascii(delta_time(tm_time(), b->ttime)));
#else
	ago[0] = '\0';
#endif	/* MALLOC_TIME */

	s_warning("leaked block %p (%zu bytes) from \"%s:%d\"%s",
		k, b->size, b->file, b->line, ago);

	leak_add(leaksort, b->size, b->file, b->line);

	if (b->reallocations) {
		struct block *r = b->reallocations->data;
		uint cnt = g_slist_length(b->reallocations);

		s_warning("   (realloc'ed %u time%s, lastly from \"%s:%d\")",
			cnt, plural(cnt), r->file, r->line);
	}

#ifdef MALLOC_FRAMES
	{
		struct frame *fr;

		fr = hash_table_lookup(alloc_points, k);
		if (fr == NULL)
			s_warning("no allocation record for %p from %s:%d?",
				k, b->file, b->line);
		else {
			s_message("block %p (out of %u) allocated from:",
				k, (unsigned) fr->blocks);
			stacktrace_atom_print(stderr, fr->ast);
		}
	}
#endif	/* MALLOC_FRAMES */
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

#ifdef MALLOC_TIME
	str_bprintf(ago, sizeof ago, " [%s]",
		short_time_ascii(delta_time(tm_time(), rb->atime)));
#else
	ago[0] = '\0';
#endif	/* MALLOC_TIME */

	s_warning("leaked block %p (%zu bytes)%s", p, rb->size, ago);

	leak_add(leaksort, rb->size, "FAKED", 0);

#ifdef MALLOC_FRAMES
	s_message("block %p (out of %u) allocated from:",
		p, (unsigned) rb->alloc->blocks);
	stacktrace_atom_print(stderr, rb->alloc->ast);
#endif	/* MALLOC_FRAMES */
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

	if (hash_table_lookup(reals, o)) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
		goto done;
	}

#ifdef MALLOC_SAFE_HEAD
	{
		const void *p = malloc_header_from_arena(o);
		if (hash_table_lookup(reals, p)) {
			hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
			goto done;
		}
	}
#endif	/* MALLOC_SAFE_HEAD */

	if (blocks != NULL && hash_table_lookup(blocks, o)) {
		hash_table_insert(not_leaking, o, GINT_TO_POINTER(1));
		goto done;
	}

#ifdef MALLOC_VTABLE
	/*
	 * With MALLOC_VTABLE we should track most of the allocations, it may
	 * be worth noting the usage of NOT_LEAKING() calls that are made on
	 * something we know nothing about.
	 */

	s_warning("MALLOC asked to ignore leaks on unknown address %p", o);
	stacktrace_where_print(stderr);
#endif

done:
	return deconstify_pointer(o);
}

/**
 * Record object `o' allocated at `file' and `line' of size `s'.
 * @return argument `o'.
 */
void *
malloc_record(const void *o, size_t sz, bool owned,
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

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		s_error("unable to allocate %u bytes", (unsigned) sizeof(*b));

	b->file = short_filename(deconstify_pointer(file));
	b->line = line;
	b->size = sz;
	b->reallocations = NULL;
	b->owned = owned;
#ifdef MALLOC_TIME
	b->ttime = tm_time();
#endif

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
		s_error("MALLOC cannot track block %p", o);
	}

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL) {
			st = calloc(1, sizeof(*st));
			st->file = b->file;
			st->line = line;
			hash_table_insert(stats, st, st);
		}

		ATOMIC_INC(st->total_blocks);
		ATOMIC_INC(st->blocks);
		ATOMIC_ADD(st->allocated, sz);
		ATOMIC_ADD(st->total_allocated, sz);
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	{
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 1);
		fr = get_frame_atom(st ? &st->alloc_frames : &gst.alloc_frames, &t);

		ATOMIC_ADD(fr->count, sz);
		ATOMIC_ADD(fr->total_count, sz);
		ATOMIC_INC(fr->blocks);

		hash_table_insert(alloc_points, o, fr);
	}
#endif /* MALLOC_FRAMES */

	return deconstify_pointer(o);
}

/**
 * Allocate `s' bytes.
 */
void *
malloc_track(size_t size, const char *file, int line)
{
	void *o;

#ifdef MALLOC_SAFE
	{
		size_t len = malloc_safe_size(size);
#ifdef MALLOC_SAFE_HEAD
		struct malloc_header *mh;

		mh = real_malloc(len);

		if (mh == NULL)
			s_error("unable to allocate %zu bytes", size);

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
		s_error("unable to allocate %zu bytes", size);

	block_clear_dead(o, size);

	return malloc_record(o, size, TRUE, file, line);
}

/**
 * Allocate `s' bytes, zero the allocated zone.
 */
void *
malloc0_track(size_t size, const char *file, int line)
{
	void *o;

	o = malloc_track(size, file, line);
	memset(o, 0, size);

	return o;
}

/**
 * Record freeing of allocated block.
 * @return TRUE if the block was owned
 */
static bool
free_record(const void *o, const char *file, int line)
{
	struct block *b;
	const void *k;
	void *v;
	GSList *l;
	bool owned = FALSE;
#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES)
	struct stats *st = NULL;	/* Needed in case MALLOC_FRAMES is also set */
#endif

	if (NULL == o)
		return FALSE;

	if (blocks == NULL || !(hash_table_lookup_extended(blocks, o, &k, &v))) {
		if (hash_table_lookup(reals, o))
			return FALSE;

		if (block_is_dead(o, 4)) {
			s_error("MALLOC (%s:%d) duplicate free of %p", file, line, o);
		}

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

#ifdef MALLOC_STATS
	{
		struct stats s;

		s.file = b->file;
		s.line = b->line;

		st = hash_table_lookup(stats, &s);

		if (st == NULL)
			s_warning(
				"MALLOC (%s:%d) no alloc record of block %p from %s:%d?",
				file, line, o, b->file, b->line);
		else {
			/* Count present block size, after possible realloc() */
			ATOMIC_ADD(st->freed, b->size);
			ATOMIC_ADD(st->total_freed, b->size);
			if (st->total_blocks > 0)
				ATOMIC_DEC(st->total_blocks);
			else
				s_warning(
					"MALLOC (%s:%d) live # of blocks was zero at free time?",
					file, line);

			/* We could free blocks allocated before "reset", don't warn */
			if (st->blocks > 0)
				ATOMIC_DEC(st->blocks);
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 1);
		fr = get_frame_atom(&st->free_frames, &t);

		ATOMIC_INC(fr->count, b->size);	/* Counts actual size, not original */
		ATOMIC_INC(fr->total_count, b->size);
	}
	hash_table_remove(alloc_points, o);
#endif /* MALLOC_FRAMES */

	hash_table_remove(blocks, o);
	hash_table_remove(not_leaking, o);

	for (l = b->reallocations; l; l = g_slist_next(l)) {
		struct block *r = l->data;
		g_assert(r->reallocations == NULL);
		free(r);
	}
	g_slist_free(b->reallocations);
	free(b);

	return owned;
}

/**
 * Free allocated block.
 */
void
free_track(void *o, const char *file, int line)
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
static void *
realloc_record(void *o, void *n, size_t size, const char *file, int line)
{
	bool blocks_updated = FALSE;
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
			s_error("MALLOC (%s:%d) attempt to realloc freed block at %p?",
				file, line, o);
		}
	}

	r = calloc(sizeof(*r), 1);
	if (r == NULL)
		s_error("unable to allocate %u bytes", (unsigned) sizeof(*r));

	r->file = short_filename(deconstify_pointer(file));
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
				s_error("MALLOC cannot track reallocated block %p", n);
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
			s_warning(
				"MALLOC (%s:%d) no alloc record of block %p from %s:%d?",
				file, line, o, b->file, b->line);
		else {
			/* We store variations in size, as algebric quantities */
			ATOMIC_INC(st->reallocated, b->size - r->size);
			ATOMIC_INC(st->total_reallocated, b->size - r->size);
		}
	}
#endif /* MALLOC_STATS */
#ifdef MALLOC_FRAMES
	if (st != NULL) {
		struct stacktrace t;
		struct frame *fr;

		stacktrace_get_offset(&t, 1);
		fr = get_frame_atom(&st->realloc_frames, &t);

		ATOMIC_INC(fr->count, b->size - r->size);
		ATOMIC_INC(fr->total_count, b->size - r->size);
	}
	if (n != o) {
		struct frame *fra = hash_table_lookup(alloc_points, o);
		if (fra) {
			/* Propagate the initial allocation frame through reallocs */
			hash_table_remove(alloc_points, o);
			hash_table_insert(alloc_points, n, fra);
		} else {
			s_warning("MALLOC lost allocation frame for %p at %s:%d -> %p",
				o, b->file, b->line, n);
		}
	}
#endif /* MALLOC_FRAMES */

	return n;
}

/**
 * Realloc object `o' to `size' bytes.
 */
void *
realloc_track(void *o, size_t size, const char *file, int line)
{
	if (o == NULL)
		return malloc_track(size, file, line);

	if (0 == size) {
		free_track(o, file, line);
		return NULL;
	} else {
		void *n;

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
					s_error("cannot realloc block into a %zu-byte one", size);
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
			s_error("cannot realloc block into a %zu-byte one", size);

		return realloc_record(o, n, size, file, line);
	}
}

/**
 * Duplicate buffer `p' of length `size'.
 */
void *
memdup_track(const void *p, size_t size, const char *file, int line)
{
	void *o;

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
	void *o;
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
	void *o;
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
		s_error("out of memory");

	memcpy(res, s, size);

	while ((add = va_arg(args, char *))) {
		size_t len = strlen(add);

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

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
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

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
}

/**
 * Perform printf into newly allocated string.
 */
char *
strdup_vprintf_track(const char *file, int line, const char *fmt, va_list ap)
{
	char *o;

	o = g_strdup_vprintf(fmt, ap);

	return malloc_record(o, strlen(o) + 1, FALSE, file, line);
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
	l = strlen(o);

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
		malloc_record(iter, sizeof *iter, FALSE, file, line);
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
	const struct stats **stats;
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
	const struct stats * const *s1 = p1, * const *s2 = p2;

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
	const struct stats * const *s1 = p1, * const *s2 = p2;

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
 * Compare two pointers to "filestat_t" based on their total residual value,
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
alloc_dump(FILE *f, bool total)
{
	int count;
	struct afiller filler;
	time_t now;

	count = hash_table_size(stats);

	if (count == 0)
		return;

	now = tm_time();
	fprintf(f, "--- distinct allocation spots found: %d at %s\n",
		count, short_time_ascii(delta_time(now, init_time)));

	filler.stats = real_malloc(sizeof(struct stats *) * count);
	filler.count = count;
	filler.idx = 0;

	/*
	 * Linearize hash table into an array before sorting it by
	 * decreasing allocation size.
	 */

	hash_table_foreach(stats, stats_fill_array, &filler);
	vsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_allocated_cmp : stats_allocated_cmp);

	/*
	 * Dump the allocation based on allocation sizes.
	 */

	fprintf(f, "--- summary by decreasing %s allocation size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time_ascii(delta_time(now, total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * Now linearize hash table by decreasing residual allocation size.
	 */

	filler.idx = 0;

	hash_table_foreach(stats, stats_fill_array, &filler);
	vsort(filler.stats, count, sizeof(struct stats *),
		total ? stats_total_residual_cmp : stats_residual_cmp);

	fprintf(f, "--- summary by decreasing %s residual memory size %s %s:\n",
		total ? "total" : "incremental", total ? "at" : "after",
		short_time_ascii(now - (total ? init_time : reset_time)));
	stats_array_dump(f, &filler);

	/*
	 * If we were not outputing for total memory, finish by dump sorted
	 * on total residual allocation.
	 */

	if (!total) {
		filler.idx = 0;

		hash_table_foreach(stats, stats_fill_array, &filler);
		vsort(filler.stats, count, sizeof(struct stats *),
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
		size_t old_size = hash_table_size(reals);

		/*
		 * Check whether the remapping is effective. This may not be
		 * the case for our GLib 1.2 hack. This is required for Darwin,
		 * for example.
		 */
		p = g_strdup("");
		if (hash_table_size(reals) == old_size) {
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
	reals = hash_table_new_real();
	unknowns = hash_table_new_real();

	hash_table_thread_safe(reals);
	hash_table_thread_safe(unknowns);
#endif

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
	void *leaksort;
#ifdef MALLOC_LEAK_ALL
	hash_table_t *saved_reals;
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
	hash_table_foreach(saved_reals, malloc_log_real_block, leaksort);
#endif	/* MALLOC_LEAK_ALL */

	leak_dump(leaksort);
	leak_close_null(&leaksort);

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
