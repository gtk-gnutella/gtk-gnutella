/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Atom management.
 *
 * An atom is a single piece of information that is likely to be shared
 * and which is therefore only allocated once: all other instances point
 * to the common object.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#define ATOMS_SOURCE
#include "common.h"

#include "atoms.h"
#include "buf.h"
#include "constants.h"
#include "endian.h"
#include "hashing.h"
#include "htable.h"
#include "log.h"
#include "misc.h"
#include "omalloc.h"
#include "once.h"
#include "spinlock.h"
#include "str.h"
#include "stringify.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#if 0
#define PROTECT_ATOMS
#endif

#if 0
#define ATOMS_HAVE_MAGIC
#endif

/*
 * With PROTECT_ATOMS all atoms are mapped read-only so that they cannot
 * be modified accidently. This is achieved through mprotect(). The CPU
 * overhead is significant and there is also some memory overhead but it's
 * sufficiently low for testing/debugging purposes.
 */

#ifdef ATOMS_HAVE_MAGIC
typedef enum {
	ATOM_MAGIC = 0x3eeb9a27U
} atom_prot_magic_t;

#define ATOM_MAGIC_CHECK(a) g_assert(ATOM_MAGIC == (a)->magic)
#define ATOM_SET_MAGIC(a) G_STMT_START { (a)->magic = ATOM_MAGIC; } G_STMT_END
#define ATOM_CLEAR_MAGIC(a) G_STMT_START { (a)->magic = 0; } G_STMT_END
#else
#define ATOM_MAGIC_CHECK(a)
#define ATOM_SET_MAGIC(a)
#define ATOM_CLEAR_MAGIC(a)
#endif	/* ATOMS_HAVE_MAGIC */

union mem_chunk {
  void *next;
  char align[MEM_ALIGNBYTES];
};

/**
 * Atoms are ref-counted.
 *
 * What we return to the outside is the value of atom_arena(), not a
 * pointer to the atom structure.
 *
 * The reference count is not held in the atom header but is stored in the
 * hash table tracking atoms of a given type, to limit the memory overhead,
 * and mprotect() overhead when compiling with PROTECT_ATOMS.
 */
typedef struct atom {
#ifdef ATOMS_HAVE_MAGIC
	atom_prot_magic_t magic;	/**< Magic should be at the beginning */
#endif /* ATOM_HAVE_MAGIC */
#ifdef TRACK_ATOMS
	htable_t *get;				/**< Allocation spots */
	htable_t *free;				/**< Free spots */
	spinlock_t lock;			/**< Thread-safety lock */
	size_t trackcnt;			/**< Tracking count (reference count) */
#endif	/* TRACK_ATOMS */
} atom_t;

#define ARENA_OFFSET \
	(MEM_ALIGNBYTES * ((sizeof(atom_t) / MEM_ALIGNBYTES) + \
		((sizeof(atom_t) % MEM_ALIGNBYTES) ? 1 : 0)))

/*
 * On 32-bit machines, the size and reference counts of atoms are stored as
 * values in the atom hash table.
 *
 * On 64-bit machines, the size and reference counts are encoded in the
 * pointer field.
 *
 * The atom size is therefore limited to 4 GiB, which is a reasonable upper
 * limit given that each time the atom is requested, we need to hash it.
 */

#define ATOM_SIZE_MAX	0xffffffffU

/*
 * Atom information on 32-bit machines, stored in the hash table.
 */
struct atom_info {
	size_t len;			/**< Atom length */
	int refcnt;			/**< Reference count */
};

/*
 * On 64-bit machines:
 *
 * - the size is stored in the upper 32 bits of the atom's hash table
 *   64-bit value
 * - the reference count is held in the lower 32 bits of that value.
 *
 * This allows us to simply increment or decrement the whole value to account
 * for reference changes made to the atom.
 */

#if PTRSIZE > 4
#define ATOM_LENGTH(x)	((x) >> 32)
#define ATOM_REFCNT(x)	((x) & ATOM_SIZE_MAX)
#define ATOM_INFO(l)	((l) << 32)
#else	/* PTRSIZE <= 4 */
/*
 * Make sure this unreachable code on 32-bit machines does not trigger
 * compilation warnings, and is indeed unreacheable.
 */
#define ATOM_LENGTH(x)	(s_error_expr("unused code called"), ATOM_SIZE_MAX)
#define ATOM_REFCNT(x)	(s_error_expr("unused code called"), 0)
#define ATOM_INFO(x)	(s_error_expr("unused code called"), 0)
#endif	/* PTRSIZE > 4 */

/**
 * Return the atom's length from the information stored in the hash table.
 */
static inline size_t
atom_info_length(void *p)
{
	if (4 == sizeof p) {
		/* 32-bit machine, value is a pointer to a struct atom_info */
		struct atom_info *ai = p;
		return ai->len;
	} else {
		/* 64-bit machine, value is encoded */
		return ATOM_LENGTH(pointer_to_ulong(p));
	}
}

/**
 * Return the atom's reference count from the information stored in
 * the hash table.
 */
static inline int
atom_info_refcnt(void *p)
{
	if (4 == sizeof p) {
		/* 32-bit machine, value is a pointer to a struct atom_info */
		struct atom_info *ai = p;
		return ai->refcnt;
	} else {
		/* 64-bit machine, value is encoded */
		return ATOM_REFCNT(pointer_to_ulong(p));
	}
}


static inline atom_t *
atom_from_arena(const void *key)
{
	return (atom_t *) (((char *) key) - ARENA_OFFSET);
}

static inline void *
atom_arena(const atom_t *a)
{
	return ((char *) a) + ARENA_OFFSET;
}

static inline void
atom_check(const atom_t *a)
{
	g_assert(a);
	ATOM_MAGIC_CHECK(a);
}

static once_flag_t atoms_inited;

#ifdef TRACK_ATOMS
static spinlock_t atom_track_slk = SPINLOCK_INIT;

static inline void
ATOM_TRACK_IS_LOCKED(void)
{
	g_assert(spinlock_is_held(&atom_track_slk));
}

static inline void
ATOM_ZERO(atom_t *a)
{
	a->get = a->free = NULL;
	a->trackcnt = 1;
	ZERO(&a->lock);
}

static inline void
ATOM_TRACK_REFCNT(const void *key, int delta, size_t refcnt)
{
	atom_t *a = atom_from_arena(key);

	/*
	 * The table where the atoms lies is locked, no need to use atomic ops
	 * to update the tracking count.
	 */

	a->trackcnt += delta;

	/*
	 * Ensure our tracking count is always the same as the atom's refcount.
	 */

	g_assert_log(refcnt == a->trackcnt,
		"refcnt=%zu, a->trackcnt=%zu", refcnt, a->trackcnt);
}
#else	/* !TRACK_ATOMS */
#define ATOM_TRACK_IS_LOCKED()
#define ATOM_ZERO(a)
#define ATOM_TRACK_REFCNT(k,d,r)	(void) r
#endif	/* TRACK_ATOMS */

#ifdef PROTECT_ATOMS
struct mem_pool {
	union mem_chunk chunks[1];
};

#define MEM_CACHE_LOCK(m)		spinlock(&(m)->lock)
#define MEM_CACHE_UNLOCK(m)		spinunlock(&(m)->lock)

struct mem_cache {
	spinlock_t lock;         /**< Thread safety */
	struct mem_pool **pools; /**< Dynamic array */
	union mem_chunk *avail;	 /**< First available chunk */
	size_t num_pools;		 /**< Element count of ``pools''. */
	size_t size;			 /**< Size of a single chunk */
	size_t hold;
};

static struct mem_cache *mem_cache[9];

static struct mem_pool *
mem_pool_new(size_t size, size_t hold)
{
	struct mem_pool *mp;
	size_t len;
	size_t i, step = size / sizeof mp->chunks[0];

	g_assert(size >= sizeof mp->chunks[0]);
	g_assert(0 == size % sizeof mp->chunks[0]);
	g_assert(hold > 0);

	len = hold * size;

	mp = vmm_core_alloc(len);

	for (i = 0; hold-- > 1; i += step) {
		mp->chunks[i].next = &mp->chunks[i + step];
	}

	mp->chunks[i].next = NULL;

	return mp;
}

/**
 * Allocates a mem cache that can be used to allocate memory chunks of
 * the given size. The cache works as a stack, that means the last freed
 * chunk will be used for the next allocation.
 */
static struct mem_cache *
mem_new(size_t size)
{
	struct mem_cache *mc;

	g_assert(size > 0);

	OMALLOC(mc);
	spinlock_init(&mc->lock);
	mc->size = round_size(sizeof(union mem_chunk), size);
	mc->hold = MAX(1, compat_pagesize() / mc->size);
	mc->num_pools = 0;
	mc->avail = NULL;
	mc->pools = NULL;

	return mc;
}

/**
 * Allocate a chunk.
 */
static void *
mem_alloc(struct mem_cache *mc)
{
	void *p;

	g_assert(mc);

	MEM_CACHE_LOCK(mc);

	if (NULL != (p = mc->avail)) {
		mc->avail = mc->avail->next;
	} else {
		struct mem_pool *mp;

		mp = mem_pool_new(mc->size, mc->hold);
		XREALLOC_ARRAY(mc->pools, 1 + mc->num_pools);
		mc->pools[mc->num_pools++] = mp;
		mc->avail = &mp->chunks[0];
		p = mc->avail;
		mc->avail = mc->avail->next;
	}

	MEM_CACHE_UNLOCK(mc);

	return p;
}

/**
 * This does not really "free" the chunk at ``p'' but pushes it back to
 * the mem cache and thus makes it available again for mem_alloc().
 */
static void
mem_free(struct mem_cache *mc, void *p)
{
	g_assert(mc);

	if (p) {
		union mem_chunk *c = p;

		MEM_CACHE_LOCK(mc);
		c->next = mc->avail;
		mc->avail = c;
		MEM_CACHE_UNLOCK(mc);
	}
}

/**
 * Find the appropriate mem cache for the given size.
 */
static struct mem_cache *
atom_get_mc(size_t size)
{
	uint i;

	for (i = 0; i < N_ITEMS(mem_cache); i++) {
		if (size <= mem_cache[i]->size)
			return mem_cache[i];
	}
	return NULL;
}

/**
 * Maps the memory chunk at ``ptr'' of length ``size'' read-only.
 * @note All pages partially overlapped by the chunk will be affected.
 */
static inline void
mem_protect(void *ptr, size_t size)
{
	void *p;
	size_t ps;

	ps = compat_pagesize();
	p = (char *) ptr - (uintptr_t) ptr % ps;
	size = round_size(ps, size);

	if (-1 == mprotect(p, size, PROT_READ))
		s_warning("%s(): mprotect(%p, %zu, PROT_READ) failed: %m",
			G_STRFUNC, p, size);
}

/**
 * Maps the memory chunk at ``ptr'' of length ``size'' read- and writable.
 * @note All pages partially overlapped by the chunk will be affected.
 */
static inline void
mem_unprotect(void *ptr, size_t size)
{
	void *p;
	size_t ps;

	ps = compat_pagesize();
	p = (char *) ptr - (uintptr_t) ptr % ps;
	size = round_size(ps, size);

	if (-1 == mprotect(p, size, PROT_READ | PROT_WRITE))
		s_warning("%s(): mprotect(%p, %zu, PROT_RDWR) failed: %m",
			G_STRFUNC, p, size);
}

/**
 * Maps an atom read- and writable.
 * @note All atoms that reside in the same page will be affected.
 */
static inline void
atom_unprotect(atom_t *a, size_t size)
{
	atom_check(a);
	mem_unprotect(a, size);
}

/**
 * Maps an atom read-only.
 * @note All atoms that reside in the same page will be affected.
 */
static inline void
atom_protect(atom_t *a, size_t size)
{
	atom_check(a);
	mem_protect(a, size);
}

/**
 * Allocates a new atom with the given size. The returned atom is initially
 * unprotected.
 */
static atom_t *
atom_alloc(size_t size)
{
	struct mem_cache *mc_ptr;
	atom_t *a;

	g_assert(size > 0);

	mc_ptr = atom_get_mc(size);
	if (mc_ptr) {
		a = mem_alloc(mc_ptr);
		mem_unprotect(a, size);
	} else {
		a = vmm_alloc(size);
	}
	ATOM_SET_MAGIC(a);
	ATOM_ZERO(a);

	return a;
}

/**
 * Virtually frees the given atom. If the atom used a chunk from a mem cache,
 * it is returned to this cache and further mapped read-only. Otherwise, if
 * the atom uses ordinary memory returned by malloc(), the memory is released
 * with free() and not further protected.
 */
static void
atom_dealloc(atom_t *a, size_t size)
{
	struct mem_cache *mc_ptr;

	atom_check(a);

	mc_ptr = atom_get_mc(size);
	if (mc_ptr) {
		memset(a, 0, size);
		mem_free(mc_ptr, a);
		/*
		 * It would be best to map the atom with PROT_NONE but there
		 * may be atoms in use that reside in the same page.
		 */
		mem_protect(a, size);
	} else {
		/* This may cause trouble if any library code (libc for example)
		 * relies on executable heap-memory because the page is now
		 * mapped (PROT_READ | PROT_WRITE).
		 */
		VMM_FREE_NULL(a, size);
	}
}
#else	/* !PROTECT_ATOMS */

#define atom_protect(a, size)		ATOM_MAGIC_CHECK(a)
#define atom_unprotect(a, size)		ATOM_MAGIC_CHECK(a)

static inline atom_t *
atom_alloc(size_t size)
{
	atom_t *a = walloc(size);
	ATOM_SET_MAGIC(a);
	ATOM_ZERO(a);
	return a;
}

static inline void
atom_dealloc(atom_t *a, size_t size)
{
	atom_check(a);
	ATOM_CLEAR_MAGIC(a);
	wfree(a, size);
}

#endif /* PROTECT_ATOMS */

typedef size_t (*len_func_t)(const void *v);
typedef const char *(*str_func_t)(const void *v);

/**
 * Description of atom types.
 */
typedef struct atom_desc {
	spinlock_t lock;			/**< Lock protecting the hash table */
	const char *type;			/**< Type of atoms */
	htable_t *table;			/**< Table of atoms: "atom value" -> size */
	hash_fn_t hash_func;		/**< Hashing function for atoms */
	eq_fn_t eq_func;			/**< Atom equality function */
	len_func_t len_func;		/**< Atom length function */
	str_func_t str_func;		/**< Atom to human-readable string */
} atom_desc_t;

#define ATOM_TABLE_LOCK(t)		spinlock(&(t)->lock)
#define ATOM_TABLE_UNLOCK(t)	spinunlock(&(t)->lock)

static size_t str_xlen(const void *v);
static const char *str_str(const void *v);
static size_t guid_len(const void *v);
static const char *guid_str(const void *v);
static size_t sha1_len(const void *v);
static const char *sha1_str(const void *v);
static size_t tth_len(const void *v);
static const char *tth_str(const void *v);
static size_t uint64_len(const void *v);
static const char *uint64_str(const void *v);
static size_t filesize_len(const void *v);
static const char *filesize_str(const void *v);
static size_t uint32_len(const void *v);
static const char *uint32_str(const void *v);
static const char *gnet_host_str(const void *v);
static size_t packed_host_addr_len(const void *v);
static const char *packed_host_addr_str(const void *v);

#define str_hash	string_mix_hash
#define str_eq		string_eq
#define fs_hash		filesize_hash
#define fs_eq		filesize_eq
#define fs_len		filesize_len
#define fs_str		filesize_str
#define gnh_hash	gnet_host_hash
#define gnh_eq		gnet_host_equal
#define gnh_len		gnet_host_length
#define gnh_str		gnet_host_str
#define pha_hash	packed_host_addr_hash
#define pha_eq		packed_host_addr_equal
#define pha_len		packed_host_addr_len
#define pha_str		packed_host_addr_str
#define S			SPINLOCK_INIT
#define N			NULL

/**
 * The set of all atom types we know about.
 */
static atom_desc_t atoms[] = {
	{ S, "String", N, str_hash,    str_eq,     str_xlen,   str_str  }, /* 0 */
	{ S, "GUID",   N, guid_hash,   guid_eq,    guid_len,   guid_str }, /* 1 */
	{ S, "SHA1",   N, sha1_hash,   sha1_eq,	   sha1_len,   sha1_str }, /* 2 */
	{ S, "TTH",    N, tth_hash,    tth_eq,	   tth_len,    tth_str },  /* 3 */
	{ S, "uint64", N, uint64_hash, uint64_eq,  uint64_len, uint64_str},/* 4 */
	{ S, "filesize", N, fs_hash,   fs_eq,      fs_len,     fs_str },   /* 5 */
	{ S, "uint32", N, uint32_hash, uint32_eq,  uint32_len, uint32_str},/* 6 */
	{ S, "host",   N, gnh_hash,    gnh_eq,     gnh_len,    gnh_str },  /* 7 */
	{ S, "addr",   N, pha_hash,    pha_eq,     pha_len,    pha_str },  /* 8 */
};

#undef str_hash
#undef str_eq
#undef fs_hash
#undef fs_eq
#undef fs_len
#undef fs_str
#undef gnh_hash
#undef gnh_eq
#undef gnh_len
#undef gnh_str
#undef pha_hash
#undef pha_eq
#undef pha_len
#undef pha_str
#undef S
#undef N

/**
 * @return length of string + trailing NUL.
 */
static size_t
str_xlen(const void *v)
{
	return strlen((const char *) v) + 1;
}

/**
 * @return printable form of a string, i.e. self.
 */
static const char *
str_str(const void *v)
{
	return (const char *) v;
}

/**
 * Hash a GUID (16 bytes).
 */
uint
guid_hash(const void *key)
{
	return binary_hash(key, GUID_RAW_SIZE);
}

/**
 * Test two GUIDs for equality.
 */
int
guid_eq(const void *a, const void *b)
{
	return a == b || 0 == memcmp(a, b, GUID_RAW_SIZE);
}

/**
 * @return length of GUID.
 */
static size_t
guid_len(const void *unused_guid)
{
	(void) unused_guid;
	return GUID_RAW_SIZE;
}

/**
 * @return printable form of a GUID, as pointer to static data.
 */
static const char *
guid_str(const void *v)
{
	const struct guid *guid = v;
	return guid_hex_str(guid);
}

/**
 * Hash a SHA1 (20 bytes).
 */
uint
sha1_hash(const void *key)
{
	return binary_hash(key, SHA1_RAW_SIZE);
}

/**
 * Test two SHA1s for equality.
 */
int
sha1_eq(const void *a, const void *b)
{
	return a == b || 0 == memcmp(a, b, SHA1_RAW_SIZE);
}

/**
 * @return length of SHA1.
 */
static size_t
sha1_len(const void *unused_sha1)
{
	(void) unused_sha1;
	return SHA1_RAW_SIZE;
}

/**
 * @return printable form of a SHA1, as pointer to static data.
 */
static const char *
sha1_str(const void *sha1)
{
	return sha1_base32(sha1);
}

/**
 * Hash a TTH (24 bytes).
 */
uint
tth_hash(const void *key)
{
	return binary_hash(key, TTH_RAW_SIZE);
}

/**
 * Test two TTHs for equality.
 *
 * @attention
 * NB: This routine is visible for the download mesh.
 */
int
tth_eq(const void *a, const void *b)
{
	return a == b || 0 == memcmp(a, b, TTH_RAW_SIZE);
}

/**
 * @return length of TTH.
 */
static size_t
tth_len(const void *unused_tth)
{
	(void) unused_tth;
	return TTH_RAW_SIZE;
}

/**
 * @return printable form of a TTH, as pointer to static data.
 */
static const char *
tth_str(const void *tth)
{
	return tth_base32(tth);
}

/**
 * @return length of a 64-bit integer.
 */
static size_t
uint64_len(const void *unused_v)
{
	(void) unused_v;
	return sizeof(uint64);
}

/**
 * @return length of a filesize_t.
 */
static size_t
filesize_len(const void *unused_v)
{
	(void) unused_v;
	return sizeof(filesize_t);
}

/**
 * @return length of a 32-bit integer.
 */
static size_t
uint32_len(const void *unused_v)
{
	(void) unused_v;
	return sizeof(uint32);
}

/**
 * @return length of a struct packed_host_addr.
 */
static size_t
packed_host_addr_len(const void *v)
{
	return packed_host_addr_size_ptr(v);
}

/**
 * @return printable form of a 64-bit integer, as pointer to static data.
 */
static const char *
uint64_str(const void *v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	char *p = buf_data(b);

	uint64_to_string_buf(*(const uint64 *) v, p, buf_size(b));
	return p;
}

/**
 * Test two 64-bit integers for equality.
 *
 * @return whether both referenced 64-bit integers are equal.
 */
int
uint64_eq(const void *a, const void *b)
{
	return *(const uint64 *) a == *(const uint64 *) b;
}

/**
 * Calculate the 32-bit hash of a 64-bit integer
 *
 * @return the 32-bit hash value for the referenced 64-bit integer.
 */
uint
uint64_hash(const void *p)
{
	uint64 v = *(const uint64 *) p;
#if LONGSIZE <= 4
	return integer_hash_fast(v ^ (v >> 32));
#else
	/* uint64 and ulong are identical types */
	return integer_hash_fast(v);
#endif
}

/**
 * Test two 64-bit integers for equality, with pointers not necessarily
 * aligned on 64-bit quantities.
 *
 * @return whether both referenced 64-bit integers are equal.
 */
int
uint64_mem_eq(const void *a, const void *b)
{
	return a == b || 0 == memcmp(a, b, sizeof(uint64));
}

/**
 * Calculate the 32-bit hash of a 64-bit integer whose address is not
 * necessarily aligned on 64-bit quantities.
 *
 * @return the 32-bit hash value for the referenced 64-bit integer.
 */
uint
uint64_mem_hash(const void *p)
{
	return binary_hash(p, sizeof(uint64));
}

/**
 * @return printable form of a filesize_t, as pointer to static data.
 */
static const char *
filesize_str(const void *v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT64_DEC_BUFLEN);
	char *p = buf_data(b);

	uint64_to_string_buf(*(const filesize_t *) v, p, buf_size(b));
	return p;
}

/**
 * @return printable form of a gnet_host_t *, as pointer to static data.
 */
static const char *
gnet_host_str(const void *v)
{
	buf_t *b = buf_private(G_STRFUNC, HOST_ADDR_PORT_BUFLEN);
	char *p = buf_data(b);

	gnet_host_to_string_buf(v, p, buf_size(b));
	return p;
}

/**
 * @return printable form of a struct packed_host_addr *, as pointer
 * to static data.
 */
static const char *
packed_host_addr_str(const void *v)
{
	buf_t *b = buf_private(G_STRFUNC, HOST_ADDR_PORT_BUFLEN);
	char *p = buf_data(b);
	host_addr_t addr;

	addr = packed_host_addr_unpack_ptr(v);
	host_addr_to_string_buf(addr, p, buf_size(b));

	return p;
}

/**
 * Test two filesize_t for equality.
 *
 * @return whether both referenced 64-bit integers are equal.
 */
int
filesize_eq(const void *a, const void *b)
{
	return *(const filesize_t *) a == *(const filesize_t *) b;
}

/**
 * Calculate the 32-bit hash of a filesize_t.
 *
 * @return the 32-bit hash value for the referenced 64-bit integer.
 */
uint
filesize_hash(const void *p)
{
	uint64 v = *(const filesize_t *) p;
	return v ^ (v >> 32);
}

/**
 * Test two 32-bit integers for equality.
 *
 * @return whether both referenced 32-bit integers are equal.
 */
int
uint32_eq(const void *a, const void *b)
{
	return *(const uint32 *) a == *(const uint32 *) b;
}

/**
 * Calculate the 32-bit hash of a 32-bit integer
 *
 * @return the 32-bit hash value for the referenced 32-bit integer.
 */
uint
uint32_hash(const void *p)
{
	uint32 v = *(const uint32 *) p;
	return u32_hash(v);
}

/**
 * @return printable form of a 32-bit integer, as pointer to static data.
 */
static const char *
uint32_str(const void *v)
{
	buf_t *b = buf_private(G_STRFUNC, UINT32_DEC_BUFLEN);
	char *p = buf_data(b);

	uint32_to_string_buf(*(const uint32 *) v, p, buf_size(b));
	return p;
}

/**
 * Initialize atom structures.
 */
static void G_COLD
atoms_init_once(void)
{
	bool has_setting = FALSE;
	struct atom_settings {
		uint8 track_atoms;
		uint8 protect_atoms;
		uint8 atoms_have_magic;
	} settings;
	uint i;

	ZERO(&settings);

	STATIC_ASSERT(NUM_ATOM_TYPES == N_ITEMS(atoms));
	STATIC_ASSERT(4 == sizeof(void *) || sizeof(void *) == sizeof(ulong));

#ifdef PROTECT_ATOMS
	for (i = 0; i < N_ITEMS(mem_cache); i++) {
		mem_cache[i] = mem_new((2 * sizeof (union mem_chunk)) << i);
	}
#endif /* PROTECT_ATOMS */

	for (i = 0; i < N_ITEMS(atoms); i++) {
		atom_desc_t *ad = &atoms[i];

		ad->table = htable_create_any(ad->hash_func, NULL, ad->eq_func);
	}

	/*
	 * Log atoms configuration.
	 */

#ifdef TRACK_ATOMS
	settings.track_atoms = TRUE;
	has_setting = TRUE;
#endif
#ifdef PROTECT_ATOMS
	settings.protect_atoms = TRUE;
	has_setting = TRUE;
#endif
#ifdef ATOMS_HAVE_MAGIC
	settings.atoms_have_magic = TRUE;
	has_setting = TRUE;
#endif

	if (has_setting) {
		s_message("atom settings: %s%s%s",
			settings.track_atoms ? "TRACK_ATOMS " : "",
			settings.protect_atoms ? "PROTECT_ATOMS " : "",
			settings.atoms_have_magic ? "ATOMS_HAVE_MAGIC " : "");
	}

	log_atoms_inited();		/* Atom layer is up */
}

/**
 * Initialize atom structures.
 */
void
atoms_init(void)
{
	once_flag_run(&atoms_inited, atoms_init_once);
}

/**
 * Check whether atom exists.
 *
 * @return TRUE if ``key'' is a known ``type'' atom.
 */
bool
atom_exists(enum atom_type type, const void *key)
{
	g_assert(key != NULL);

	if G_UNLIKELY(!ONCE_DONE(atoms_inited))
		return FALSE;

	return htable_contains(atoms[type].table, key);
}

/**
 * Check whether key is an atom
 *
 * @return TRUE if ``key'' points to a ``type'' atom.
 */
bool
atom_is_atom(enum atom_type type, const void *key)
{
	const void *atom;

	g_assert(key != NULL);

	if G_UNLIKELY(!ONCE_DONE(atoms_inited))
		return FALSE;

	return htable_lookup_extended(atoms[type].table, key, &atom, NULL)
		&& key == atom;
}

/**
 * Increment / decrement the atom reference count.
 *
 * Must be called with the table description locked.
 *
 * @return new reference count.
 */
static inline size_t
atom_refcnt_add(const atom_desc_t *ad, const void *key, void *value, int delta)
{
	if (4 == sizeof(void *)) {
		/* 32-bit machine, we can directly update the atom_info structure */
		struct atom_info *ai = value;
		ai->refcnt += delta;
		return ai->refcnt;
	} else {
		/* 64-bit machine, we must update the hash table value */
		ulong v = pointer_to_ulong(value);
		if (delta > 0)
			v += delta;
		else
			v -= -delta;	/* Necessary since int may be smaller than long */
		htable_insert(ad->table, key, ulong_to_pointer(v));
		return ATOM_REFCNT(v);
	}
}

/**
 * Get atom of given `type', whose value is `key'.
 * If the atom does not exist yet, `key' is cloned and makes up the new atom.
 *
 * @return the atom's value.
 */
const void *
atom_get(enum atom_type type, const void *key)
{
	atom_desc_t *ad;
	const void *orig_key;
	void *value;
	size_t size;
	atom_t *a;

	STATIC_ASSERT(0 == ARENA_OFFSET % MEM_ALIGNBYTES);
	STATIC_ASSERT(ARENA_OFFSET >= sizeof(atom_t));

    g_assert(key != NULL);
	g_assert(UNSIGNED(type) < N_ITEMS(atoms));
	ATOM_TRACK_IS_LOCKED();

	if G_UNLIKELY(!ONCE_DONE(atoms_inited))
		atoms_init();

	ad = &atoms[type];		/* Where atoms of this type are held */
	ATOM_TABLE_LOCK(ad);

	if (htable_lookup_extended(ad->table, key, &orig_key, &value)) {
		size_t refcnt;

		size = atom_info_length(value);
		/* Prevent gcc warning if ARENA_OFFSET == 0 */
		g_assert(size == ARENA_OFFSET || size > ARENA_OFFSET);

		/*
		 * Atom exists, increment ref count and return it.
		 */

		g_assert(atom_info_refcnt(value) > 0);

		refcnt = atom_refcnt_add(ad, orig_key, value, +1);
		ATOM_TRACK_REFCNT(orig_key, +1, refcnt);
		ATOM_TABLE_UNLOCK(ad);

		return orig_key;
	} else {
		size_t len;

		/*
		 * Create new atom.
		 */

		len = (*ad->len_func)(key);
		g_assert(len < ATOM_SIZE_MAX - ARENA_OFFSET);
		size = round_size_fast(MEM_ALIGNBYTES, ARENA_OFFSET + len);

		a = atom_alloc(size);
		memcpy(atom_arena(a), key, len);
		atom_protect(a, size);

		/*
		 * Insert atom in table.
		 *
		 * On 32-bit machines, we have to allocate the atom_info structure.
		 * On 64-bit machines, encode size and refcnt in a long.
		 */

		if (4 == sizeof(void *)) {
			struct atom_info *ai;

			WALLOC(ai);
			ai->len = size;
			ai->refcnt = 1;
			htable_insert(ad->table, atom_arena(a), ai);
		} else {
			ulong v = ATOM_INFO(size) + 1;	/* +1 means refcnt is 1 */
			htable_insert(ad->table, atom_arena(a), ulong_to_pointer(v));
		}

		ATOM_TABLE_UNLOCK(ad);

		return atom_arena(a);
	}
}

/**
 * Remove one reference from atom.
 * Dispose of atom if nobody references it anymore.
 */
void
atom_free(enum atom_type type, const void *key)
{
	atom_desc_t *ad;
	size_t size;
	atom_t *a;
	bool found;
	int refcnt;
	void *value;
	const void *orig_key;

    g_assert(key != NULL);
	g_assert(UNSIGNED(type) < N_ITEMS(atoms));
	ATOM_TRACK_IS_LOCKED();

	ad = &atoms[type];		/* Where atoms of this type are held */
	ATOM_TABLE_LOCK(ad);

	found = htable_lookup_extended(ad->table, key, &orig_key, &value);

	g_assert_log(found,
		"attempting to free unknown %s atom at %p", ad->type, key);
	g_assert_log(key == orig_key,
		"attempt to free %s atom copy at %p, atom was at %p",
			ad->type, key, orig_key);

	size = atom_info_length(value);

	/* Prevent gcc warning if ARENA_OFFSET == 0 */
	g_assert(size == ARENA_OFFSET || size > ARENA_OFFSET);

	a = atom_from_arena(key);
	refcnt = atom_info_refcnt(value);

	/*
	 * Dispose of atom when its reference count reaches 0.
	 */

	if (1 == refcnt) {
		htable_remove(ad->table, key);
		if (4 == sizeof(void *)) {
			/* 32-bit machine */
			struct atom_info *ai = value;
			WFREE(ai);
		}
		atom_unprotect(a, size);
		atom_dealloc(a, size);
	} else {
		size_t rcnt = atom_refcnt_add(ad, key, value, -1);
		ATOM_TRACK_REFCNT(key, -1, rcnt);
	}

	ATOM_TABLE_UNLOCK(ad);
}

#ifdef TRACK_ATOMS

/** Information about given spot. */
struct spot {
	int count;			/**< Amount of allocation/free performed at spot */
};

#define ATOM_TRACK_LOCK		spinlock_hidden(&atom_track_slk)
#define ATOM_TRACK_UNLOCK	spinunlock_hidden(&atom_track_slk)

/**
 * The tracking version of atom_get().
 *
 * @returns the atom's value.
 */
const void *
atom_get_track(enum atom_type type, const void *key, const char *file, int line)
{
	const void *atom;
	atom_t *a;
	char buf[512];
	const void *k;
	void *v;
	struct spot *sp;

	ATOM_TRACK_LOCK;

	atom = atom_get(type, key);
	a = atom_from_arena(atom);

	/*
	 * Initialize tracking tables on first allocation.
	 */

	if G_UNLIKELY(NULL == a->get) {
		/* Initialized by ATOM_ZERO() */
		g_assert_log(1 == a->trackcnt,
			"%s(): a->trackcnt=%zu", G_STRFUNC, a->trackcnt);
		spinlock_init(&a->lock);
	}

	spinlock(&a->lock);
	ATOM_TRACK_UNLOCK;

	if G_UNLIKELY(NULL == a->get) {
		a->get = htable_create(HASH_KEY_STRING, 0);
		a->free = htable_create(HASH_KEY_STRING, 0);
	}

	str_bprintf(buf, sizeof(buf), "%s:%d", short_filename(file), line);

	if (htable_lookup_extended(a->get, buf, &k, &v)) {
		sp = (struct spot *) v;
		sp->count++;
	} else {
		WALLOC(sp);
		sp->count = 1;
		htable_insert(a->get, constant_str(buf), sp);
	}

	spinunlock(&a->lock);

	return atom;
}

/**
 * Free value from the tracking table.
 */
static void
tracking_free_kv(const void *unused_key, void *value, void *unused_data)
{
	(void) unused_key;
	(void) unused_data;

	/* The key is a constant */

	wfree(value, sizeof(struct spot));
}

/**
 * Get rid of the tracking hash table and nullify its pointer.
 */
static void
destroy_tracking_table(htable_t **h_ptr)
{
	htable_t *h = *h_ptr;

	if (h != NULL) {
		htable_foreach(h, tracking_free_kv, NULL);
		htable_free_null(h_ptr);
	}
}

/**
 * The tracking version of atom_free().
 * Remove one reference from atom.
 * Dispose of atom if nobody references it anymore.
 */
void
atom_free_track(enum atom_type type, const void *key,
	const char *file, int line)
{
	atom_t *a;
	void *v;
	struct spot *sp;
	bool freed = FALSE;

	a = atom_from_arena(key);

	ATOM_TRACK_LOCK;

	/*
	 * If we're going to free the atom, dispose of the tracking tables.
	 */

	spinlock(&a->lock);

	if (1 == a->trackcnt) {
		destroy_tracking_table(&a->get);
		destroy_tracking_table(&a->free);
		spinlock_destroy(&a->lock);
		freed = TRUE;
	} else {
		spinunlock(&a->lock);
	}

	atom_free(type, key);

	if (!freed)
		spinlock(&a->lock);

	ATOM_TRACK_UNLOCK;

	if (!freed) {
		char buf[512];

		str_bprintf(buf, sizeof(buf), "%s:%d", short_filename(file), line);

		if (htable_lookup_extended(a->free, buf, NULL, &v)) {
			sp = (struct spot *) v;
			sp->count++;
		} else {
			WALLOC(sp);
			sp->count = 1;
			htable_insert(a->free, constant_str(buf), sp);
		}
		spinunlock(&a->lock);
	}
}

/**
 * Helper routine for atom_track_count.
 */
static void
atom_count_tracking_entry(const void *unused_key, void *value, void *user)
{
	struct spot *sp = value;
	size_t *count = user;

	(void) unused_key;
	*count += sp->count;
}

/**
 * Count amount of operations recorded in the tracking table.
 */
static size_t
atom_track_count(const htable_t *h)
{
	size_t count = 0;

	htable_foreach(h, atom_count_tracking_entry, &count);
	return count;
}

/**
 * Dump all the spots where some tracked operation occurred, along with the
 * amount of such operations.
 */
static void
dump_tracking_entry(const void *key, void *value, void *user)
{
	struct spot *sp = value;
	const char *what = user;

	g_warning("%10d %s at \"%s\"", sp->count, what, (char *) key);
}

/**
 * Dump the values held in the tracking table `h'.
 */
static void
dump_tracking_table(const void *atom, htable_t *h, char *what)
{
	size_t count = htable_count(h);
	size_t opcount = atom_track_count(h);

	g_warning("all %zu %s spot%s (%zu operation%s) for %p:",
		count, what, plural(count), opcount, plural(opcount), atom);

	htable_foreach(h, dump_tracking_entry, what);
}

#endif	/* TRACK_ATOMS */

/**
 * Warning about existing atom that should have been freed.
 */
static void
atom_warn_free(const void *key, void *value, void *udata)
{
	atom_t *a = atom_from_arena(key);
	atom_desc_t *ad = udata;

	g_warning("found remaining %s atom %p, refcnt=%d: \"%s\"",
		ad->type, key, atom_info_refcnt(value), (*ad->str_func)(key));

#ifdef TRACK_ATOMS
	spinlock(&a->lock);
	dump_tracking_table(key, a->get, "get");
	dump_tracking_table(key, a->free, "free");
	destroy_tracking_table(&a->get);
	destroy_tracking_table(&a->free);
	spinlock_destroy(&a->lock);
#else
	(void) a;
#endif

	/*
	 * Don't free the entry, so that we know where the leak originates from.
	 *		--RAM, 02/02/2003
	 */
}

/**
 * Shutdown atom structures, freeing all remaining atoms.
 */
void
atoms_close(void)
{
	uint i;

	for (i = 0; i < N_ITEMS(atoms); i++) {
		atom_desc_t *ad = &atoms[i];

		ATOM_TABLE_LOCK(ad);
		htable_foreach(ad->table, atom_warn_free, ad);
		htable_free_null(&ad->table);
		ATOM_TABLE_UNLOCK(ad);
	}
}

/* vi: set ts=4 sw=4 cindent: */
