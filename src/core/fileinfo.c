/*
 * Copyright (c) 2002-2003, Vidar Madsen
 * Copyright (c) 2004-2008, Christian Biere
 * Copyright (c) 2002-2012, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Structure for storing meta-information about files being
 * downloaded.
 *
 * @author Vidar Madsen
 * @date 2002-2003
 * @author Christian Biere
 * @date 2004-2008
 * @author Raphael Manfredi
 * @date 2002-2010
 */

#include "common.h"

#include <math.h>		/* For fabs() */

#include "fileinfo.h"

#include "bsched.h"
#include "dmesh.h"
#include "downloads.h"
#include "gdht.h"
#include "gmsg.h"
#include "guid.h"
#include "hosts.h"
#include "huge.h"
#include "namesize.h"
#include "nodes.h"
#include "publisher.h"
#include "routing.h"
#include "routing.h"
#include "search.h"
#include "settings.h"
#include "share.h"
#include "sockets.h"
#include "tth_cache.h"
#include "uploads.h"
#include "verify_tth.h"		/* For request_tigertree() */

#include "lib/array_util.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/concat.h"
#include "lib/crash.h"
#include "lib/eclist.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/filename.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/hikset.h"
#include "lib/htable.h"
#include "lib/http_range.h"
#include "lib/idtable.h"
#include "lib/magnet.h"
#include "lib/mempcpy.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/rbtree.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tigertree.h"
#include "lib/tm.h"
#include "lib/tokenizer.h"
#include "lib/unsigned.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"

#include "if/dht/dht.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

#define FI_MIN_CHUNK_SPLIT	512		/**< Smallest chunk we can split */
/**< Max field length we accept to save */
#define FI_MAX_FIELD_LEN	(TTH_RAW_SIZE * TTH_MAX_LEAVES)
#define FI_DHT_PERIOD		1200		/**< Requery period for DHT: 20 min */
#define FI_DHT_SOURCE_DELAY	300			/**< Penalty per known source */
#define FI_DHT_QUEUED_DELAY	150			/**< Penalty per queued source */
#define FI_DHT_RECV_DELAY	600			/**< Penalty per active source */
#define FI_DHT_RECV_THRESH	5			/**< No query if that many active */

/*
 * Aligning requested blocks is just a convenience, to make it easier later
 * to validate the file against the TTH, and also because it is likely
 * to be slightly more efficient when doing aligned disk I/Os.
 */
#define FI_OFFSET_BOUNDARY		((filesize_t) 128 * 1024)
#define FI_OFFSET_ALIGNMASK		(FI_OFFSET_BOUNDARY - 1)

enum dl_file_chunk_magic { DL_FILE_CHUNK_MAGIC = 0x563b483d };

/**
 * Download file chunks.
 *
 * These are linked to form the chunklist, the list of all the chunks defined
 * for the file and which are either completed, reserved, or empty (not yet
 * downloaded).
 */
struct dl_file_chunk {
	enum dl_file_chunk_magic magic;
	enum dl_chunk_status status;	/**< Status of range */
	filesize_t from;				/**< Range offset start (byte included) */
	filesize_t to;					/**< Range offset end (byte EXCLUDED) */
	const download_t *download;		/**< Download which "reserved" range */
	slink_t lk;						/**< Embedded one-way link */
};

static inline void
dl_file_chunk_check(const struct dl_file_chunk * const fc)
{
	g_assert(fc != NULL);
	g_assert(DL_FILE_CHUNK_MAGIC == fc->magic);
}

enum dl_avail_chunk_magic { DL_AVAIL_CHUNK_MAGIC = 0x3e69cf33 };

/**
 * Available chunks.
 *
 * For each chunk of the file, we compute the amount of sources that can
 * serve the chunk, allowing us to pick the rarest chunk when downloading.
 */
struct dl_avail_chunk {
	enum dl_avail_chunk_magic magic;
	filesize_t from;				/**< Range offset start (byte included) */
	filesize_t to;					/**< Range offset end (byte EXCLUDED) */
	size_t sources;					/**< Amount of sources offering chunk */
	slink_t lk;						/**< Embedded one-way link */
};

static inline void
dl_avail_chunk_check(const struct dl_avail_chunk * const ac)
{
	g_assert(ac != NULL);
	g_assert(DL_AVAIL_CHUNK_MAGIC == ac->magic);
}

/*
 * File information is uniquely describing an output file in the download
 * directory.  There is a many-to-one relationship between downloads and
 * file information (fileinfo or fi for short): several downloads can point
 * to the same fi, in which case they write data to the SAME file.
 *
 * Files are uniquely indexed by their SHA1 hash.  If two files bear the
 * same SHA1, then they MUST be identical, whatever their reported size.
 * We assume the largest entry is the right one.  Servers should always report
 * the full filesize in hits, but some broken servers will not, hence the
 * possible divergence in file size.
 *
 * When we don't have a SHA1 to identify a file, we use the tuple (name, size)
 * to uniquely identify a file.  The name alone is not enough, since it is
 * conceivable that two equal names could have different sizes, because
 * they are just underlying different files.
 *
 * To lookup for possible aliases, we also keep track of all our fi structs
 * by size in a table indexed solely by filesize and listing all the currently
 * recorded fi structs for that size.
 *
 * The `fi_by_sha1' hash table keeps track of the SHA1 -> fi association.
 * The `fi_by_namesize' hash table keeps track of items by (name, size).
 * The `fi_by_outname' table keeps track of the "output name" -> fi link.
 * The `fi_by_guid' hash table keeps track of the GUID -> fi association.
 */

static hikset_t *fi_by_sha1;
static htable_t *fi_by_namesize;
static hikset_t *fi_by_outname;
static hikset_t *fi_by_guid;

static const char file_info_file[] = "fileinfo";
static const char file_info_what[] = "fileinfo database";
static bool fileinfo_dirty = FALSE;
static bool can_swarm = FALSE;		/**< Set by file_info_retrieve() */
static bool can_publish_partial_sha1;

#define	FILE_INFO_MAGIC32 0xD1BB1ED0U
#define	FILE_INFO_MAGIC64 0X91E63640U

typedef uint32 fi_magic_t;

#define FILE_INFO_VERSION	6

enum dl_file_info_field {
	FILE_INFO_FIELD_NAME = 1,	/**< No longer used in 32-bit version >= 3 */
	FILE_INFO_FIELD_ALIAS,
	FILE_INFO_FIELD_SHA1,
	FILE_INFO_FIELD_CHUNK,
	FILE_INFO_FIELD_END,		/**< Marks end of field section */
	FILE_INFO_FIELD_CHA1,
	FILE_INFO_FIELD_GUID,
	FILE_INFO_FIELD_TTH,
	FILE_INFO_FIELD_TIGERTREE,
	/* Add new fields here, never change ordering for backward compatibility */

	NUM_FILE_INFO_FIELDS
};

#define FI_STORE_DELAY		60	/**< Max delay (secs) for flushing fileinfo */
#define FI_TRAILER_INT		6	/**< Amount of uint32 in the trailer */

/**
 * The swarming trailer is built within a memory buffer first, to avoid having
 * to issue mutliple write() system calls.	We can't use stdio's buffering
 * since we can sometime reuse the download's file descriptor.
 */
static struct {
	char *arena;			/**< Base arena */
	char *wptr;				/**< Write pointer */
	const char *rptr;		/**< Read pointer */
	const char *end;		/**< First byte off arena */
	size_t size;			/**< Current size of arena */
} tbuf;

#define TBUF_SIZE			512		/**< Initial trailing buffer size */
#define TBUF_GROW_BITS		9		/**< Growing chunks */

#define TBUF_GROW			((size_t) 1 << TBUF_GROW_BITS)
#define TBUF_GROW_MASK		(TBUF_GROW - 1)

static inline size_t
round_grow(size_t x)
{
	return (x + TBUF_GROW_MASK) & ~TBUF_GROW_MASK;
}

/*
 * Low level trailer buffer read/write macros.
 */

static void
tbuf_check(void)
{
	if (tbuf.arena) {
		g_assert(NULL != tbuf.end);
		g_assert(tbuf.size > 0);
		g_assert(&tbuf.arena[tbuf.size] == tbuf.end);
		if (tbuf.rptr) {
			g_assert((size_t) tbuf.rptr >= (size_t) tbuf.arena);
			g_assert((size_t) tbuf.rptr <= (size_t) tbuf.end);
		}
		if (tbuf.wptr) {
			g_assert((size_t) tbuf.wptr >= (size_t) tbuf.arena);
			g_assert((size_t) tbuf.wptr <= (size_t) tbuf.end);
		}
	} else {
		g_assert(NULL == tbuf.end);
		g_assert(NULL == tbuf.rptr);
		g_assert(NULL == tbuf.wptr);
		g_assert(0 == tbuf.size);
	}
}

/**
 * Make sure there is enough room in the buffer for `x' more bytes.
 * If `writing' is TRUE, we update the write pointer.
 */
static void
tbuf_extend(size_t x, bool writing)
{
	size_t new_size = round_grow(x + tbuf.size);
	size_t offset;

	tbuf_check();

	offset = (writing && tbuf.wptr) ? (tbuf.wptr - tbuf.arena) : 0;
	g_assert(offset <= tbuf.size);

	tbuf.arena = hrealloc(tbuf.arena, new_size);
	tbuf.end = &tbuf.arena[new_size];
	tbuf.size = new_size;
	tbuf.wptr = writing ? &tbuf.arena[offset] : NULL;
	tbuf.rptr = writing ? NULL : tbuf.arena;
}

static inline void
TBUF_INIT_READ(size_t size)
{
	tbuf_check();

	if (NULL == tbuf.arena || (size_t) (tbuf.end - tbuf.arena) < size) {
		tbuf_extend(size, FALSE);
	}
	tbuf.rptr = tbuf.arena;
	tbuf.wptr = NULL;
}

static inline void
TBUF_INIT_WRITE(void)
{
	tbuf_check();

	if (NULL == tbuf.arena) {
		tbuf_extend(TBUF_SIZE, TRUE);
	}
	tbuf.rptr = NULL;
	tbuf.wptr = tbuf.arena;
}

static inline size_t
TBUF_WRITTEN_LEN(void)
{
	tbuf_check();

	return tbuf.wptr - tbuf.arena;
}

static inline void
TBUF_CHECK(size_t size)
{
	tbuf_check();

	if (NULL == tbuf.arena || (size_t) (tbuf.end - tbuf.wptr) < size)
		tbuf_extend(size, TRUE);
}

static WARN_UNUSED_RESULT bool
TBUF_GETCHAR(uint8 *x)
{
	tbuf_check();

	if ((size_t) (tbuf.end - tbuf.rptr) >= sizeof *x) {
		*x = *tbuf.rptr;
		tbuf.rptr += sizeof *x;
		return TRUE;
	} else {
		return FALSE;
	}
}

static WARN_UNUSED_RESULT bool
TBUF_GET_UINT32(uint32 *x)
{
	tbuf_check();

	if ((size_t) (tbuf.end - tbuf.rptr) >= sizeof *x) {
		memcpy(x, tbuf.rptr, sizeof *x);
		tbuf.rptr += sizeof *x;
		return TRUE;
	} else {
		return FALSE;
	}
}

static WARN_UNUSED_RESULT bool
TBUF_READ(char *x, size_t size)
{
	tbuf_check();

	if ((size_t) (tbuf.end - tbuf.rptr) >= size) {
		memcpy(x, tbuf.rptr, size);
		tbuf.rptr += size;
		return TRUE;
	} else {
		return FALSE;
	}
}

static void
TBUF_PUT_CHAR(uint8 x)
{
	TBUF_CHECK(sizeof x);
	*tbuf.wptr = x;
	tbuf.wptr++;
}

static void
TBUF_PUT_UINT32(uint32 x)
{
	TBUF_CHECK(sizeof x);
	tbuf.wptr = mempcpy(tbuf.wptr, &x, sizeof x);
}

static void
TBUF_WRITE(const char *data, size_t size)
{
	TBUF_CHECK(size);
	tbuf.wptr = mempcpy(tbuf.wptr, data, size);
}

static inline void
file_info_checksum(uint32 *checksum, const void *data, size_t len)
{
	const uchar *p = data;
	while (len--)
		*checksum = UINT32_ROTL(*checksum, 1) ^ *p++;
}

/*
 * High-level write macros.
 */

static void
WRITE_CHAR(uint8 val, uint32 *checksum)
{
	TBUF_PUT_CHAR(val);
	file_info_checksum(checksum, &val, sizeof val);
}

static void
WRITE_UINT32(uint32 val, uint32 *checksum)
{
	val = htonl(val);
	TBUF_PUT_UINT32(val);
	file_info_checksum(checksum, &val, sizeof val);
}

static void
WRITE_STR(const char *data, size_t size, uint32 *checksum)
{
	TBUF_WRITE(data, size);
	file_info_checksum(checksum, data, size);
}

/*
 * High-level read macros.
 */

static WARN_UNUSED_RESULT bool
READ_CHAR(uint8 *val, uint32 *checksum)
{
	if (TBUF_GETCHAR(val)) {
		file_info_checksum(checksum, val, sizeof *val);
		return TRUE;
	} else {
		return FALSE;
	}
}

static WARN_UNUSED_RESULT bool
READ_UINT32(uint32 *val_ptr, uint32 *checksum)
{
	uint32 val;

	if (TBUF_GET_UINT32(&val)) {
		*val_ptr = ntohl(val);
		file_info_checksum(checksum, &val, sizeof val);
		return TRUE;
	} else {
		return FALSE;
	}
}

static WARN_UNUSED_RESULT bool
READ_STR(char *data, size_t size, uint32 *checksum)
{
	if (TBUF_READ(data, size)) {
		file_info_checksum(checksum, data, size);
		return TRUE;
	} else {
		return FALSE;
	}
}

/*
 * Addition of a variable-size trailer field.
 */

static void
FIELD_ADD(enum dl_file_info_field id, size_t n, const void *data,
	uint32 *checksum)
{
	WRITE_UINT32(id, checksum);
	WRITE_UINT32(n, checksum);
	WRITE_STR(data, n, checksum);
}

/**
 * The trailer fields of the fileinfo trailer.
 */

struct trailer {
	uint64 filesize;		/**< Real file size */
	uint32 generation;		/**< Generation number */
	uint32 length;			/**< Total trailer length */
	uint32 checksum;		/**< Trailer checksum */
	fi_magic_t magic;		/**< Magic number */
};

static fileinfo_t *file_info_retrieve_binary(const char *pathname);
static void fi_free(fileinfo_t *fi);
static void fi_update_seen_on_network(gnet_src_t srcid);
static const char *file_info_new_outname(const char *dir, const char *name);
static bool looks_like_urn(const char *filename);

static idtable_t *fi_handle_map;
static idtable_t *src_handle_map;

static event_t *fi_events[EV_FI_EVENTS];
static event_t *src_events[EV_SRC_EVENTS];

struct download *
src_get_download(gnet_src_t src_handle)
{
	return idtable_get_value(src_handle_map, src_handle);
}

static inline fileinfo_t *
file_info_find_by_handle(gnet_fi_t n)
{
	return idtable_get_value(fi_handle_map, n);
}

static inline gnet_fi_t
file_info_request_handle(fileinfo_t *fi)
{
	return idtable_new_id(fi_handle_map, fi);
}

static void
fi_event_trigger(fileinfo_t *fi, gnet_fi_ev_t id)
{
	file_info_check(fi);
	g_assert(UNSIGNED(id) < EV_FI_EVENTS);
	event_trigger(fi_events[id], T_NORMAL(fi_listener_t, (fi->fi_handle)));
}

static void
file_info_drop_handle(fileinfo_t *fi, const char *reason)
{
	file_info_check(fi);

	file_info_upload_stop(fi, reason);
	fi_event_trigger(fi, EV_FI_REMOVED);
	idtable_free_id(fi_handle_map, fi->fi_handle);
}

/**
 * Checks the kind of trailer. The trailer must be initialized.
 *
 * @return TRUE if the trailer is the 64-bit version, FALSE if it's 32-bit.
 */
static inline bool
trailer_is_64bit(const struct trailer *tb)
{
	switch (tb->magic) {
	case FILE_INFO_MAGIC32: return FALSE;
	case FILE_INFO_MAGIC64: return TRUE;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Write trailer buffer at current position on `fd', whose name is `name'.
 */
static void
tbuf_write(const file_object_t *fo, filesize_t offset)
{
	size_t size = TBUF_WRITTEN_LEN();
	ssize_t ret;

	g_assert(fo);
	g_assert(size > 0);
	g_assert(size <= tbuf.size);

	ret = file_object_pwrite(fo, tbuf.arena, size, offset);
	if ((ssize_t) -1 == ret) {
		g_warning("error while flushing trailer info for \"%s\": %m",
			file_object_pathname(fo));
	} else if ((size_t) ret != size) {
		g_warning("partial write while flushing trailer info for \"%s\"",
			file_object_pathname(fo));
	}
}

/**
 * Read trailer buffer at current position from `fd'.
 *
 * @returns -1 on error.
 */
static ssize_t
tbuf_read(int fd, size_t len)
{
	g_assert(fd >= 0);

	TBUF_INIT_READ(len);

	return read(fd, tbuf.arena, len);
}

static struct dl_file_chunk *
dl_file_chunk_alloc(void)
{
	static const struct dl_file_chunk zero_fc;
	struct dl_file_chunk *fc;

	WALLOC(fc);
	*fc = zero_fc;
	fc->magic = DL_FILE_CHUNK_MAGIC;
	return fc;
}

static void
dl_file_chunk_free(struct dl_file_chunk **fc_ptr)
{
	g_assert(fc_ptr);
	if (*fc_ptr) {
		struct dl_file_chunk *fc = *fc_ptr;

		dl_file_chunk_check(fc);
		fc->magic = 0;
		WFREE(fc);
		*fc_ptr = NULL;
	}
}

static struct dl_avail_chunk *
dl_avail_chunk_alloc(void)
{
	struct dl_avail_chunk *ac;

	WALLOC0(ac);
	ac->magic = DL_AVAIL_CHUNK_MAGIC;
	return ac;
}

static struct dl_avail_chunk *
dl_avail_chunk_new(filesize_t from, filesize_t to, size_t sources)
{
	struct dl_avail_chunk *ac;

	g_assert(from < to);
	g_assert(size_is_positive(sources));

	ac = dl_avail_chunk_alloc();
	ac->from = from;
	ac->to = to;
	ac->sources = sources;
	return ac;
}

static void
dl_avail_chunk_free(void *p)
{
	struct dl_avail_chunk *ac = p;
	dl_avail_chunk_check(ac);
	ac->magic = 0;
	WFREE(ac);
}

/**
 * Given a fileinfo GUID, return the fileinfo_t associated with it, or NULL
 * if it does not exist.
 */
fileinfo_t *
file_info_by_guid(const struct guid *guid)
{
	return hikset_lookup(fi_by_guid, guid);
}

/**
 * Checks the chunklist of fi.
 *
 * @param fi		the fileinfo struct to check.
 * @param assertion	TRUE if used in an assertion
 *
 * @return TRUE if chunklist is consistent, FALSE otherwise.
 */
static bool
file_info_check_chunklist(const fileinfo_t *fi, bool assertion)
{
	const struct dl_file_chunk *fc;
	filesize_t last = 0;

	/*
	 * This routine ends up being a CPU hog when all the asserts using it
	 * are run.  Do that only when debugging.
	 */

	if (assertion && GNET_PROPERTY(fileinfo_debug) < 10)
		return TRUE;

	file_info_check(fi);

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);
		if (last != fc->from || fc->from >= fc->to)
			return FALSE;

		last = fc->to;
		if (!fi->file_size_known || 0 == fi->size)
			continue;

		if (fc->from >= fi->size || fc->to > fi->size)
			return FALSE;
	}

	return TRUE;
}

/**
 * Store a binary record of the file metainformation at the end of the
 * supplied file descriptor, opened for writing.
 *
 * When `force' is false, we don't store unless FI_STORE_DELAY seconds
 * have elapsed since last flush to disk.
 */
static void
file_info_fd_store_binary(fileinfo_t *fi, const file_object_t *fo)
{
	const pslist_t *sl;
	const slink_t *cl;
	uint32 checksum = 0;
	uint32 length;

	g_assert(fo);
	g_return_if_fail(0 == ((FI_F_TRANSIENT | FI_F_STRIPPED) & fi->flags));

	TBUF_INIT_WRITE();
	WRITE_UINT32(FILE_INFO_VERSION, &checksum);

	/*
	 * Emit leading binary fields.
	 */

	WRITE_UINT32(fi->created, &checksum);	/* Introduced at: version 4 */
	WRITE_UINT32(fi->ntime, &checksum);			/* version 4 */
	WRITE_CHAR(fi->file_size_known, &checksum);	/* Introduced at: version 5 */

	/*
	 * Emit variable-length fields.
	 */

	FIELD_ADD(FILE_INFO_FIELD_GUID, GUID_RAW_SIZE, fi->guid, &checksum);

	if (fi->tth)
		FIELD_ADD(FILE_INFO_FIELD_TTH, TTH_RAW_SIZE, fi->tth, &checksum);

	if (fi->tigertree.leaves) {
		const void *data;
		size_t size;

		STATIC_ASSERT(TTH_RAW_SIZE == sizeof(struct tth));
		data = fi->tigertree.leaves;
		size = fi->tigertree.num_leaves * TTH_RAW_SIZE;
		FIELD_ADD(FILE_INFO_FIELD_TIGERTREE, size, data, &checksum);
	}

	if (fi->sha1)
		FIELD_ADD(FILE_INFO_FIELD_SHA1, SHA1_RAW_SIZE, fi->sha1, &checksum);

	if (fi->cha1)
		FIELD_ADD(FILE_INFO_FIELD_CHA1, SHA1_RAW_SIZE, fi->cha1, &checksum);

	PSLIST_FOREACH(fi->alias, sl) {
		size_t len = strlen(sl->data);		/* Do not store the trailing NUL */
		g_assert(len <= INT_MAX);
		if (len < FI_MAX_FIELD_LEN)
			FIELD_ADD(FILE_INFO_FIELD_ALIAS, len, sl->data, &checksum);
	}

	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH(&fi->chunklist, cl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, cl);
		uint32 from_hi, to_hi;
		uint32 chunk[5];

		dl_file_chunk_check(fc);
		from_hi = (uint64) fc->from >> 32;
		to_hi = (uint64) fc->to >> 32;

		chunk[0] = htonl(from_hi),
		chunk[1] = htonl((uint32) fc->from),
		chunk[2] = htonl(to_hi),
		chunk[3] = htonl((uint32) fc->to),
		chunk[4] = htonl(fc->status);
		FIELD_ADD(FILE_INFO_FIELD_CHUNK, sizeof chunk, chunk, &checksum);
	}

	fi->generation++;

	WRITE_UINT32(FILE_INFO_FIELD_END, &checksum);

	STATIC_ASSERT((uint64) -1 >= (filesize_t) -1);
	WRITE_UINT32((uint64) fi->size >> 32, &checksum);
	WRITE_UINT32(fi->size, &checksum);
	WRITE_UINT32(fi->generation, &checksum);

	length = TBUF_WRITTEN_LEN() + 3 * sizeof(uint32);

	WRITE_UINT32(length, &checksum);				/* Total trailer size */
	WRITE_UINT32(checksum, &checksum);
	WRITE_UINT32(FILE_INFO_MAGIC64, &checksum);

	/* Flush buffer at current position */
	tbuf_write(fo, fi->size);

	if (0 != file_object_ftruncate(fo, fi->size + length)) {
		g_warning("%s(): truncate() failed for \"%s\": %m",
			G_STRFUNC, file_info_readable_filename(fi));
	}

	fi->dirty = FALSE;
	fileinfo_dirty = TRUE;

	entropy_harvest_time();
}

/**
 * Store a binary record of the file metainformation at the end of the
 * output file, if it exists.
 */
void
file_info_store_binary(fileinfo_t *fi, bool force)
{
	file_object_t *fo;

	g_assert(!(fi->flags & (FI_F_TRANSIENT | FI_F_SEEDING)));

	/*
	 * Don't flush unless required or some delay occurred since last flush.
	 */

	fi->stamp = tm_time();
	if (!force && delta_time(fi->stamp, fi->last_flush) < FI_STORE_DELAY)
		return;

	/*
	 * When we flush the fileinfo, record the SHA1 to the DHT publisher,
	 * if known.  Indeed, the publisher can forget about a SHA1 when it
	 * believes the file is no longer shared.  But if we're flushing the
	 * trailer, then there is activity going on and maybe the file is
	 * publishable in the DHT.
	 */

	if (fi->sha1 != NULL && can_publish_partial_sha1)
		publisher_add(fi->sha1);

	fi->last_flush = fi->stamp;

	/*
	 * We don't create the file if it does not already exist.  That way,
	 * a file is only created when at least one byte of data is downloaded,
	 * since then we'll go directly to file_info_fd_store_binary().
	 */

	fo = file_object_open(fi->pathname, O_WRONLY);

	if (fo != NULL) {
		file_info_fd_store_binary(fi, fo);
		file_object_release(&fo);
	}
}

static void
file_info_got_tth_internal(fileinfo_t *fi, const struct tth *tth, bool update)
{
	file_info_check(fi);

	g_return_if_fail(tth);
	g_return_if_fail(NULL == fi->tth);
	fi->tth = atom_tth_get(tth);

	/* Update the GUI, if requested */
	if (update)
		fi_event_trigger(fi, EV_FI_INFO_CHANGED);
}

void
file_info_got_tth(fileinfo_t *fi, const struct tth *tth)
{
	file_info_got_tth_internal(fi, tth, TRUE);
}

/**
 * Invoked when a seeded file had its TTH recomputed.
 *
 * @param fi		the fileinfo
 * @param tth		the recomputed TTH value
 * @param update	whether to update the GUI
 */
static void
file_info_recomputed_tth_internal(
	fileinfo_t *fi, const struct tth *tth, bool update)
{
	size_t nleaves;

	file_info_check(fi);
	g_return_if_fail(tth != NULL);
	g_return_if_fail(fi->sha1 != NULL);
	g_return_if_fail(NULL == fi->tigertree.leaves);

	if (fi->tth != NULL && !tth_eq(fi->tth, tth)) {
		g_warning("%s(): inconsistent TTH for \"%s\": "
			"was known as %s, but got new TTH %s",
			G_STRFUNC, fi->pathname,
			bitprint_to_urn_string(fi->sha1, fi->tth), tth_base32(tth));

		atom_tth_change(&fi->tth, tth);

		/* Update the GUI */
		if (update)
			fi_event_trigger(fi, EV_FI_INFO_CHANGED);
	}

	/*
	 * Locate the TTH information by probing the TTH cache.
	 */

	nleaves = tth_cache_get_nleaves(tth);

	if G_UNLIKELY(0 == nleaves) {
		g_warning("%s(): unable to find TTH %s in cache for %s",
			G_STRFUNC, tth_base32(tth), fi->pathname);
		return;
	}

	g_assert(size_is_positive(nleaves));

	/*
	 * To indicate that the TTH was recomputed, we let the leaves
	 * pointer at NULL but we fill-in the amount of leaves and the
	 * TTH slice size.
	 */

	fi->tigertree.num_leaves = nleaves;
	fi->tigertree.slice_size = tt_slice_size(fi->size, nleaves);

	/* Update the GUI */
	if (update)
		fi_event_trigger(fi, EV_FI_INFO_CHANGED);
}

/**
 * Invoked when a seeded file had its TTH recomputed.
 */
void
file_info_recomputed_tth(fileinfo_t *fi, const struct tth *tth)
{
	file_info_recomputed_tth_internal(fi, tth, TRUE);
}

static void
fi_tigertree_free(fileinfo_t *fi)
{
	file_info_check(fi);

	if (fi->tigertree.leaves != NULL) {
		g_assert(fi->tigertree.num_leaves != 0);
		WFREE_ARRAY(fi->tigertree.leaves, fi->tigertree.num_leaves);
		ZERO(&fi->tigertree);
	}
}

void
file_info_got_tigertree(fileinfo_t *fi,
	const struct tth *leaves, size_t num_leaves, bool mark_dirty)
{
	file_info_check(fi);

	g_return_if_fail(leaves);
	g_return_if_fail(size_is_positive(num_leaves));
	g_return_if_fail(fi->tigertree.num_leaves < num_leaves);
	g_return_if_fail(fi->file_size_known);

	fi_tigertree_free(fi);
	fi->tigertree.leaves = WCOPY_ARRAY(leaves, num_leaves);
	fi->tigertree.num_leaves = num_leaves;
	fi->tigertree.slice_size = tt_slice_size(fi->size, num_leaves);

	if (mark_dirty) {
		fi->dirty = TRUE;

		/* Update the GUI */
		fi_event_trigger(fi, EV_FI_INFO_CHANGED);
	}
}

/**
 * Record that the fileinfo trailer has been stripped.
 */
void
file_info_mark_stripped(fileinfo_t *fi)
{
	file_info_check(fi);
	g_return_if_fail(!(FI_F_STRIPPED & fi->flags));

	fi->flags |= FI_F_STRIPPED;
}

static void
file_info_strip_trailer(fileinfo_t *fi, const char *pathname)
{
	file_info_check(fi);
	g_assert(!((FI_F_TRANSIENT | FI_F_SEEDING | FI_F_STRIPPED) & fi->flags));

	fi_tigertree_free(fi);

	if (-1 == truncate(pathname, fi->size)) {
		if (ENOENT == errno) {
			file_info_mark_stripped(fi);
		}
		g_warning("could not chop fileinfo trailer off \"%s\": %m", pathname);
	} else {
		file_info_mark_stripped(fi);
	}
}

/**
 * Strips the file metainfo trailer off a file.
 */
void
file_info_strip_binary(fileinfo_t *fi)
{
	file_info_strip_trailer(fi, fi->pathname);

	/* Update the GUI */
	fi_event_trigger(fi, EV_FI_INFO_CHANGED);
}

/**
 * Strips the file metainfo trailer off specified file.
 */
void
file_info_strip_binary_from_file(fileinfo_t *fi, const char *pathname)
{
	fileinfo_t *dfi;

	g_assert(is_absolute_path(pathname));
	g_assert(!(fi->flags & (FI_F_TRANSIENT | FI_F_SEEDING | FI_F_STRIPPED)));

	/*
	 * Before truncating the file, we must be really sure it is reasonnably
	 * matching the fileinfo structure we have for it: retrieve the binary
	 * trailer, and check size / completion.
	 */

	dfi = file_info_retrieve_binary(pathname);

	if (NULL == dfi) {
		g_warning("could not chop fileinfo trailer off \"%s\": file does "
			"not seem to have a valid trailer", pathname);
		return;
	}

	if (dfi->size != fi->size || dfi->done != fi->done) {
		char buf[64];

		concat_strings(buf, sizeof buf,
			filesize_to_string(dfi->done), "/",
			filesize_to_string2(dfi->size), NULL_PTR);
		g_warning("could not chop fileinfo trailer off \"%s\": file was "
			"different than expected (%s bytes done instead of %s/%s)",
			pathname, buf,
			filesize_to_string(fi->done), filesize_to_string2(fi->size));
	} else {
		file_info_strip_trailer(fi, pathname);
	}
	fi_free(dfi);
}

/**
 * Frees the chunklist and all its elements of a fileinfo struct. Note that
 * the consistency of the list isn't checked to explicitely allow freeing
 * inconsistent chunklists.
 *
 * @param fi the fileinfo struct.
 */
static void
file_info_chunklist_free(fileinfo_t *fi)
{
	file_info_check(fi);

	eslist_wfree(&fi->chunklist, sizeof(struct dl_file_chunk));
}

/**
 * Frees the chunklist and all its elements of a fileinfo struct. Note that
 * the consistency of the list isn't checked to explicitely allow freeing
 * inconsistent chunklists.
 *
 * @param fi the fileinfo struct.
 */
static void
file_info_available_free(fileinfo_t *fi)
{
	file_info_check(fi);

	eslist_wfree(&fi->available, sizeof(struct dl_avail_chunk));
}

/**
 * Cleanup the "downloading" part of the file_info structure.
 */
static void
fi_downloading_free(fileinfo_t *fi)
{
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	file_info_chunklist_free(fi);
	file_info_available_free(fi);

	http_rangeset_free_null(&fi->seen_on_network);
	fi_tigertree_free(fi);
}

/**
 * Free a `file_info' structure.
 */
static void
fi_free(fileinfo_t *fi)
{
	file_info_check(fi);
	g_assert(!fi->hashed);
	g_assert(NULL == fi->sf);

	fi_downloading_free(fi);

	file_info_upload_stop(fi, N_("File info being freed"));

	if (fi->alias != NULL) {
		pslist_t *sl;

		PSLIST_FOREACH(fi->alias, sl) {
			const char *s = sl->data;
			atom_str_free_null(&s);
		}
		pslist_free_null(&fi->alias);
	}

	atom_guid_free_null(&fi->guid);
	atom_str_free_null(&fi->pathname);
	atom_tth_free_null(&fi->tth);
	atom_sha1_free_null(&fi->sha1);
	atom_sha1_free_null(&fi->cha1);

	fi->magic = 0;
	WFREE(fi);
}

static void
file_info_hash_insert_name_size(fileinfo_t *fi)
{
	namesize_t nsk;
	pslist_t *sl, *aliases;

	file_info_check(fi);
	g_assert(fi->file_size_known);

	if (FI_F_TRANSIENT & fi->flags)
		return;

	/*
	 * Prepend the filename to the list of aliases, for the purpose of
	 * recording the entry by name+size.  This is useful when recovering
	 * downloads with no SHA1, so that we can associate their persisted
	 * magnet with the proper fileinfo.
	 *		--RAM, 2014-04-23
	 */

	aliases = fi->alias;
	aliases = pslist_prepend_const(aliases, filepath_basename(fi->pathname));

	/*
	 * The (name, size) tuples also point to a list of entries, one for
	 * each of the name aliases.  Ideally, we'd want only one, but there
	 * can be name conflicts.  This does not matter unless they disabled
	 * strict SHA1 matching...  but that is a dangerous move.
	 */

	nsk.size = fi->size;

	PSLIST_FOREACH(aliases, sl) {
		pslist_t *slist;

		nsk.name = sl->data;
		slist = htable_lookup(fi_by_namesize, &nsk);

		if (NULL != slist) {
			pslist_append(slist, fi);		/* Head not changing */
		} else {
			namesize_t *ns = namesize_make(nsk.name, nsk.size);
			slist = pslist_append(NULL, fi);
			htable_insert(fi_by_namesize, ns, slist);
		}
	}

	pslist_shift(&aliases);		/* Get rid of extra leading item */
}

static void
file_info_hash_remove_name_size(fileinfo_t *fi)
{
	namesize_t nsk;
	pslist_t *sl;

	/*
	 * Remove all the aliases from the (name, size) table.
	 */

	nsk.size = fi->size;

	PSLIST_FOREACH(fi->alias, sl) {
		namesize_t *ns;
		pslist_t *slist, *head;
		const void *key;
		void *value;
		bool found;

		nsk.name = sl->data;

		found = htable_lookup_extended(fi_by_namesize, &nsk, &key, &value);

		ns = deconstify_pointer(key);
		slist = value;
		g_assert(found);
		g_assert(NULL != slist);
		g_assert(ns->size == fi->size);

		head = slist;
		slist = pslist_remove(slist, fi);

		if (NULL == slist) {
			htable_remove(fi_by_namesize, ns);
			namesize_free(ns);
		} else if (head != slist) {
			htable_insert(fi_by_namesize, ns, slist); /* Head changed */
		}
	}
}

/**
 * Extend chunk list from `fi->size' to the new specified size.
 */
static void
fi_extend_chunklist(fileinfo_t *fi, filesize_t size)
{
	struct dl_file_chunk *fc;

	g_assert(fi->size < size);

	fc = dl_file_chunk_alloc();
	fc->from = fi->size;
	fc->to = size;
	fc->status = DL_CHUNK_EMPTY;
	eslist_append(&fi->chunklist, fc);

	/*
	 * Don't remove/re-insert `fi' from hash tables: when this routine is
	 * called, `fi' may not be "hashed".
	 */

	fi->size = size;

	g_assert(file_info_check_chunklist(fi, TRUE));
}

/**
 * Resize fileinfo to be `size' bytes, by adding empty chunk at the tail.
 */
static void
fi_resize(fileinfo_t *fi, filesize_t size)
{
	file_info_check(fi);
	g_assert(!fi->hashed);

	fi_extend_chunklist(fi, size);
}

/**
 * Resize fileinfo if size was not known already.
 */
void
file_info_resize(fileinfo_t *fi, filesize_t size)
{
	file_info_check(fi);
	g_return_unless(!fi->file_size_known);	/* Can't resize if size known */

	fi_extend_chunklist(fi, size);
	file_info_merge_adjacent(fi);

	fi_event_trigger(fi, EV_FI_INFO_CHANGED);

	if (!(fi->flags & FI_F_TRANSIENT)) {
		fi->dirty = TRUE;
		fileinfo_dirty = TRUE;
	}
}

/**
 * Add `name' as an alias for `fi' if not already known.
 * If `record' is TRUE, also record new alias entry in `fi_by_namesize'.
 */
static void
fi_alias(fileinfo_t *fi, const char *name, bool record)
{
	namesize_t *ns;
	pslist_t *list;

	file_info_check(fi);
	g_assert(!record || fi->hashed);	/* record => fi->hashed */

	/*
	 * The fastest way to know if this alias exists is to lookup the
	 * fi_by_namesize table, since all the aliases are inserted into
	 * that table.
	 */

	ns = namesize_make(name, fi->size);
	list = htable_lookup(fi_by_namesize, ns);
	if (NULL != list && NULL != pslist_find(list, fi)) {
		/* Alias already known */
	} else if (looks_like_urn(name)) {
		/* This is often caused by (URN entries in) the dmesh */
	} else {
		/*
		 * Insert new alias for `fi'.
		 */

		fi->alias = pslist_append_const(fi->alias, atom_str_get(name));

		if (record) {
			if (NULL != list) {
				pslist_append(list, fi);
			} else {
				list = pslist_append(list, fi);
				htable_insert(fi_by_namesize, ns, list);
				ns = NULL; /* Prevent freeing */
			}
		}
	}
	if (ns)
		namesize_free(ns);
}

/**
 * Extract fixed trailer at the end of the file `name', already opened as `fd'.
 * The supplied trailer buffer `tb' is filled.
 *
 * @returns TRUE if the trailer is "validated", FALSE otherwise.
 */
static bool
file_info_get_trailer(int fd, struct trailer *tb, filestat_t *sb,
	const char *name)
{
	ssize_t r;
	fi_magic_t magic;
	uint32 tr[FI_TRAILER_INT];
	filestat_t buf;
	fileoffset_t offset;
	uint64 filesize_hi;
	size_t i = 0;

	g_assert(fd >= 0);
	g_assert(tb);

	if (-1 == fstat(fd, &buf)) {
		g_warning("error fstat()ing \"%s\": %m", name);
		return FALSE;
	}

	if (sb) {
		*sb = buf;
	}

	if (!S_ISREG(buf.st_mode)) {
		g_warning("Not a regular file: \"%s\"", name);
		return FALSE;
	}

	if (buf.st_size < (fileoffset_t) sizeof tr)
		return FALSE;

	/*
	 * Don't use SEEK_END with "-sizeof(tr)" to avoid problems when
	 * fileoffset_t is defined as an 8-byte wide quantity.  Since we have
	 * the file size already, better use SEEK_SET.
	 *		--RAM, 02/02/2003 after a bug report from Christian Biere
	 */

	offset = buf.st_size - sizeof tr;		/* Start of trailer */

	/* No wrapper because this is a native fileoffset_t value. */
	if (offset != lseek(fd, offset, SEEK_SET)) {
		g_warning("%s(): error seek()ing in file \"%s\": %m", G_STRFUNC, name);
		return FALSE;
	}

	r = read(fd, tr, sizeof tr);
	if ((ssize_t) -1 == r) {
		g_warning("%s(): error reading trailer in \"%s\": %m", G_STRFUNC, name);
		return FALSE;
	}


	/*
	 * Don't continue if the number of bytes read is smaller than
	 * the minimum number of bytes needed.
	 *		-- JA 12/02/2004
	 */
	if (r < 0 || (size_t) r < sizeof tr)
		return FALSE;

	filesize_hi = 0;
	magic = ntohl(tr[5]);
	switch (magic) {
	case FILE_INFO_MAGIC64:
		filesize_hi	= ((uint64) ((uint32) ntohl(tr[0]))) << 32;
		/* FALLTHROUGH */
	case FILE_INFO_MAGIC32:
		tb->filesize = filesize_hi | ((uint32) ntohl(tr[1]));
		i = 2;
		break;
	}
	if (2 != i) {
		return FALSE;
	}

	for (/* NOTHING */; i < N_ITEMS(tr); i++) {
		uint32 v = ntohl(tr[i]);

		switch (i) {
		case 2: tb->generation	= v; break;
		case 3: tb->length		= v; break;
		case 4: tb->checksum	= v; break;
		case 5: tb->magic 		= v; break;
		default:
			g_assert_not_reached();
		}
	}

	g_assert(FILE_INFO_MAGIC32 == tb->magic || FILE_INFO_MAGIC64 == tb->magic);

	/*
	 * Now, sanity checks...  We must make sure this is a valid trailer.
	 */

	if ((uint64) buf.st_size != tb->filesize + tb->length) {
		return FALSE;
	}

	return TRUE;
}

/**
 * Check whether file has a trailer.
 *
 * @return	0 if the file has no trailer
 *			1 if the file has a trailer
 *			-1 on error.
 */
int
file_info_has_trailer(const char *path)
{
	struct trailer trailer;
	int fd;
	bool valid;

	fd = file_open_missing(path, O_RDONLY);
	if (fd < 0)
		return -1;

	valid = file_info_get_trailer(fd, &trailer, NULL, path);
	fd_forget_and_close(&fd);

	return valid ? 1 : 0;
}

fileinfo_t *
file_info_by_sha1(const struct sha1 *sha1)
{
	g_return_val_if_fail(sha1, NULL);
	g_return_val_if_fail(fi_by_sha1, NULL);
	return hikset_lookup(fi_by_sha1, sha1);
}

/**
 * Detects some loops in a one-way list.
 *
 * @return TRUE if the given slist contains a loop; FALSE otherwise.
 */
static bool
fi_alias_list_is_looping(const pslist_t *slist)
{
	const pslist_t *sl, *p;

	p = sl = slist;
	for (sl = slist; /* NOTHING */; sl = pslist_next(sl)) {
		p = pslist_next(pslist_next(p));
		if (p == sl || p == pslist_next(sl))
			break;
	}

	return NULL != p;
}

/**
 * Lookup our existing fileinfo structs to see if we can spot one
 * referencing the supplied file `name' and `size', as well as the
 * optional `sha1' hash.
 *
 * @returns the fileinfo structure if found, NULL otherwise.
 */
static fileinfo_t *
file_info_lookup(const char *name, filesize_t size, const struct sha1 *sha1)
{
	fileinfo_t *fi;
	pslist_t *list;

	/*
	 * If we have a SHA1, this is our unique key.
	 */

	if (sha1) {
		fi = hikset_lookup(fi_by_sha1, sha1);
		if (fi) {
			file_info_check(fi);
			return fi;
		}

		/*
		 * No need to continue if strict SHA1 matching is enabled.
		 * If the entry is not found in the `fi_by_sha1' table, then
		 * nothing can be found for this SHA1.
		 */

		if (GNET_PROPERTY(strict_sha1_matching))
			return NULL;
	}

	if (0 == size)
		return NULL;


	/*
	 * Look for a matching (name, size) tuple.
	 */
	{
		struct namesize nsk;

		nsk.name = deconstify_char(name);
		nsk.size = size;

		list = htable_lookup(fi_by_namesize, &nsk);
		g_assert(!fi_alias_list_is_looping(list));
		g_assert(NULL == pslist_find(list, NULL));
	}

	if (NULL != list && NULL == pslist_next(list)) {
		fi = list->data;
		file_info_check(fi);

		/* FIXME: FILE_SIZE_KNOWN: Should we provide another lookup?
		 *	-- JA 2004-07-21
		 */
		if (fi->file_size_known)
			g_assert(fi->size == size);
		return fi;
	}
	return NULL;
}

/**
 * Given a fileinfo structure, look for any other known duplicate.
 *
 * @returns the duplicate found, or NULL if no duplicate was found.
 */
static fileinfo_t *
file_info_lookup_dup(fileinfo_t *fi)
{
	fileinfo_t *dfi;

	file_info_check(fi);
	g_assert(fi->pathname);

	dfi = hikset_lookup(fi_by_outname, fi->pathname);
	if (dfi) {
		file_info_check(dfi);
		return dfi;
	}

	/*
	 * If `fi' has a SHA1, find any other entry bearing the same SHA1.
	 */

	if (fi->sha1) {
		dfi = hikset_lookup(fi_by_sha1, fi->sha1);
		if (dfi) {
			file_info_check(dfi);
			return dfi;
		}
	}

	/*
	 * The file ID must also be unique.
	 */

	g_assert(fi->guid);
	dfi = hikset_lookup(fi_by_guid, fi->guid);
	if (dfi) {
		file_info_check(dfi);
		return dfi;
	}
	return NULL;
}

/**
 * Check whether filename looks like an URN.
 */
static bool
looks_like_urn(const char *filename)
{
	const char *p, *q;
	uint i;

	/* Check for the following pattern:
	 *
	 * (urn.)?(sha1|bitprint).[a-zA-Z0-9]{SHA1_BASE32_SIZE,}
	 */

	p = is_strcaseprefix(filename, "urn");
	/* Skip a single character after the prefix */
	if (p) {
	   	if ('\0' == *p++)
			return FALSE;
	} else {
		p = filename;
	}

	q = is_strcaseprefix(p, "sha1");
	if (!q)
		q = is_strcaseprefix(p, "bitprint");

	/* Skip a single character after the prefix */
	if (!q || '\0' == *q++)
		return FALSE;

	i = 0;
	while (i < SHA1_BASE32_SIZE && is_ascii_alnum(q[i]))
		i++;

	return i < SHA1_BASE32_SIZE ? FALSE : TRUE;
}

/**
 * Determines a human-readable filename for the file, using heuristics to
 * skip what looks like an URN.
 *
 * @returns a pointer to the information in the fileinfo, but this must be
 * duplicated should it be perused later.
 */
const char *
file_info_readable_filename(const fileinfo_t *fi)
{
	const char *filename;

	file_info_check(fi);

	filename = filepath_basename(fi->pathname);
	if (looks_like_urn(filename)) {
		const pslist_t *sl;

		PSLIST_FOREACH(fi->alias, sl) {
			const char *name = sl->data;
			if (!looks_like_urn(name))
				return name;
		}
	}

	return filename;
}

/**
 * Look whether we have a partially downloaded file bearing the given SHA1.
 * If we do, return a "shared_file" structure suitable for uploading the
 * parts of the file we have (will happen only when PFSP-server is enabled).
 *
 * @return NULL if don't have any download with this SHA1, otherwise return
 * a "shared_file" structure suitable for uploading the parts of the file
 * we have (which will happen only when PFSP-server is enabled).
 */
shared_file_t *
file_info_shared_sha1(const struct sha1 *sha1)
{
	fileinfo_t *fi;

	fi = hikset_lookup(fi_by_sha1, sha1);
	if (fi != NULL) {
		file_info_check(fi);

		/*
		 * If we marked the fileinfo with FI_F_NOSHARE, we don't want to
		 * be able to share that file again.  Probably because it was a
		 * partial file that got removed from the filesystem.
		 */

		if (FI_F_NOSHARE & fi->flags)
			goto not_shared;

		/*
		 * Completed file (with SHA-1 verified) are always shared, regardless
		 * of their size.
		 *
		 * Partial files below the minimum filesize are not shared, since
		 * their SHA-1 is not yet validated and we don't partially validate
		 * chunks based on the TTH.
		 */

		if (FI_F_SEEDING & fi->flags)
			goto share;

		if (fi->done >= GNET_PROPERTY(pfsp_minimum_filesize))
			goto share;
	}

	/* FALL THROUGH */

not_shared:
	return NULL;

share:
	/*
	 * Build shared_file entry if not already present.
	 */

	g_assert(NULL != fi);
	g_assert(NULL != fi->sha1);

	if (fi->sf) {
		shared_file_check(fi->sf);
	} else {
		shared_file_from_fileinfo(fi);
		file_info_changed(fi);
	}
	return fi->sf;
}

/**
 * Allocate random GUID to use as the file ID.
 *
 * @return a GUID atom, refcount incremented already.
 */
static const guid_t *
fi_random_guid_atom(void)
{
	return guid_unique_atom(fi_by_guid, FALSE);
}

/**
 * Ensure potentially old fileinfo structure is brought up-to-date by
 * inferring or allocating missing fields.
 *
 * @return TRUE if an upgrade was necessary.
 */
static bool
fi_upgrade_older_version(fileinfo_t *fi)
{
	bool upgraded = FALSE;

	file_info_check(fi);

	/*
	 * Ensure proper timestamps for creation and update times.
	 */

	if (0 == fi->created) {
		fi->created = tm_time();
		upgraded = TRUE;
	}

	if (0 == fi->ntime) {
		fi->ntime = fi->created;
		upgraded = TRUE;
	}

	/*
	 * Enforce "size != 0 => file_size_known".
	 */

	if (fi->size && !fi->file_size_known) {
		fi->file_size_known = TRUE;
		upgraded = TRUE;
	}

	/*
	 * Versions before 2005-08-27 lacked the GUID in the fileinfo.
	 */

	if (NULL == fi->guid) {
		fi->guid = fi_random_guid_atom();
		upgraded = TRUE;
	}

	return upgraded;
}

static void
fi_tigertree_check(fileinfo_t *fi)
{
	if (fi->tigertree.leaves) {
		unsigned depth;
		struct tth root;

		if (NULL == fi->tth) {
			g_warning("trailer contains tigertree but no root hash in \"%s\"",
				fi->pathname);
			goto discard;
		}

		depth = tt_depth(fi->tigertree.num_leaves);

		if (
			fi->file_size_known &&
			fi->tigertree.num_leaves != tt_node_count_at_depth(fi->size, depth)
		) {
			g_warning("trailer contains tigertree with invalid leaf count "
				"in \"%s\": got %zu, expected %s at depth %u for %s bytes",
				fi->pathname, fi->tigertree.num_leaves,
				filesize_to_string(tt_node_count_at_depth(fi->size, depth)),
				depth, filesize_to_string2(fi->size));
			goto discard;
		}

		STATIC_ASSERT(TTH_RAW_SIZE == sizeof(struct tth));
		root = tt_root_hash(fi->tigertree.leaves, fi->tigertree.num_leaves);
		if (!tth_eq(&root, fi->tth)) {
			g_warning("trailer contains tigertree with non-matching "
				"root hash in \"%s\"",
				fi->pathname);
			goto discard;
		}
	}
	return;

discard:
	fi_tigertree_free(fi);
}

/**
 * Allocates a new fileinfo.
 */
static fileinfo_t *
file_info_allocate(void)
{
	fileinfo_t *fi;

	WALLOC0(fi);
	fi->magic = FI_MAGIC;
	eslist_init(&fi->chunklist, offsetof(struct dl_file_chunk, lk));
	eslist_init(&fi->available, offsetof(struct dl_avail_chunk, lk));

	return fi;
}

/**
 * Reads the file metainfo from the trailer of a file, if it exists.
 *
 * @returns a pointer to the info structure if found, and NULL otherwise.
 */
static fileinfo_t *
file_info_retrieve_binary(const char *pathname)
{
	uint32 tmpchunk[5];
	uint32 tmpuint;
	uint32 checksum = 0;
	fileinfo_t *fi = NULL;
	enum dl_file_info_field field;
	char tmp[FI_MAX_FIELD_LEN + 1];	/* +1 for trailing NUL on strings */
	const char *reason;
	int fd;
	uint32 version;
	struct trailer trailer;
	filestat_t sb;
	bool t64;

#define BAILOUT(x)			\
G_STMT_START {				\
	reason = (x);			\
	goto bailout;			\
	/* NOTREACHED */		\
} G_STMT_END

	g_assert(NULL != pathname);
	g_assert(is_absolute_path(pathname));

	fd = file_open_missing(pathname, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}

	if (!file_info_get_trailer(fd, &trailer, &sb, pathname)) {
		/*
		 * Silently ignore completed download files that would still lie
		 * in the directory where incomplete files are stored and which would
		 * therefore have been renamed as .OK or .BAD.
		 */

		if (download_is_completed_filename(pathname))
			goto eof;

		BAILOUT("could not find trailer");
		/* NOT REACHED */
	}
	t64 = trailer_is_64bit(&trailer);

	{
		bool ret;

		if (trailer.filesize > (filesize_t) -1) {
			errno = ERANGE;
			ret = -1;
		} else {
			ret = seek_to_filepos(fd, trailer.filesize);
		}
		if (0 != ret) {
			g_warning("seek to position %s within \"%s\" failed: %m",
				filesize_to_string(trailer.filesize), pathname);
			goto eof;
		}
	}

	/*
	 * Now read the whole trailer in memory.
	 */

	if (-1 == tbuf_read(fd, trailer.length)) {
		g_warning("%s(): "
			"unable to read whole trailer %s bytes) from \"%s\": %m",
			G_STRFUNC, filesize_to_string(trailer.filesize), pathname);
		goto eof;
	}

	/* Check version */
	if (!READ_UINT32(&version, &checksum))
		goto eof;
	if ((t64 && version > FILE_INFO_VERSION) || (!t64 && version > 5)) {
		g_warning("%s(): strange version; %u", G_STRFUNC, version);
		goto eof;
	}

	fi = file_info_allocate();
	fi->pathname = atom_str_get(pathname);
	fi->size = trailer.filesize;
	fi->generation = trailer.generation;
	fi->file_size_known = fi->use_swarming = 1;		/* Must assume swarming */
	fi->refcount = 0;
	fi->seen_on_network = NULL;
	fi->modified = sb.st_mtime;

	/*
	 * Read leading binary fields.
	 */

	if (version >= 4) {
		uint32 val;

		if (!READ_UINT32(&val, &checksum))
			goto eof;
		fi->created = val;
		if (!READ_UINT32(&val, &checksum))
			goto eof;
		fi->ntime = val;
	}

	if (version >= 5) {
		uint8 c;
		if (!READ_CHAR(&c, &checksum))
			goto eof;
		fi->file_size_known = 0 != c;
	}

	/*
	 * Read variable-length fields.
	 */

	for (;;) {
		tmpuint = FILE_INFO_FIELD_END; /* in case read() fails. */
		if (!READ_UINT32(&tmpuint, &checksum))		/* Read a field ID */
			goto eof;
		if (FILE_INFO_FIELD_END == tmpuint)
			break;
		field = tmpuint;

		if (!READ_UINT32(&tmpuint, &checksum))	/* Read field data length */
			goto eof;

		if (0 == tmpuint) {
			str_bprintf(tmp, sizeof tmp, "field #%d has zero size", field);
			BAILOUT(tmp);
			/* NOT REACHED */
		}

		if (tmpuint > FI_MAX_FIELD_LEN) {
			str_bprintf(tmp, sizeof tmp,
				"field #%d is too large (%u bytes) ", field, (uint) tmpuint);
			BAILOUT(tmp);
			/* NOT REACHED */
		}

		g_assert(tmpuint < sizeof tmp);

		if (!READ_STR(tmp, tmpuint, &checksum))
			goto eof;
		tmp[tmpuint] = '\0';				/* Did not store trailing NUL */

		switch (field) {
		case FILE_INFO_FIELD_NAME:
			/*
			 * Starting with version 3, the file name is added as an alias.
			 * We don't really need to carry the filename in the file itself!
			 */
			if (version >= 3)
				g_warning("found NAME field in fileinfo v%u for \"%s\"",
					version, pathname);
			else
				fi_alias(fi, tmp, FALSE);	/* Pre-v3 lacked NAME in ALIA */
			break;
		case FILE_INFO_FIELD_ALIAS:
			fi_alias(fi, tmp, FALSE);
			break;
		case FILE_INFO_FIELD_GUID:
			if (GUID_RAW_SIZE == tmpuint)
				fi->guid = atom_guid_get(cast_to_guid_ptr_const(tmp));
			else
				g_warning("bad length %d for GUID in fileinfo v%u for \"%s\"",
					tmpuint, version, pathname);
			break;
		case FILE_INFO_FIELD_TTH:
			if (TTH_RAW_SIZE == tmpuint) {
				struct tth tth;
				memcpy(tth.data, tmp, TTH_RAW_SIZE);
				file_info_got_tth_internal(fi, &tth, FALSE);
			} else {
				g_warning("bad length %d for TTH in fileinfo v%u for \"%s\"",
					tmpuint, version, pathname);
			}
			break;
		case FILE_INFO_FIELD_TIGERTREE:
			if (tmpuint > 0 && 0 == (tmpuint % TTH_RAW_SIZE)) {
				const struct tth *leaves;

				STATIC_ASSERT(TTH_RAW_SIZE == sizeof(struct tth));
				leaves = (const struct tth *) &tmp[0];
				file_info_got_tigertree(fi,
					leaves, tmpuint / TTH_RAW_SIZE, FALSE);
			} else {
				g_warning("bad length %d for TIGERTREE in fileinfo v%u "
					"for \"%s\"",
					tmpuint, version, pathname);
			}
			break;
		case FILE_INFO_FIELD_SHA1:
			if (SHA1_RAW_SIZE == tmpuint) {
				struct sha1 sha1;
				memcpy(sha1.data, tmp, SHA1_RAW_SIZE);
				fi->sha1 = atom_sha1_get(&sha1);
			} else
				g_warning("bad length %d for SHA1 in fileinfo v%u for \"%s\"",
					tmpuint, version, pathname);
			break;
		case FILE_INFO_FIELD_CHA1:
			if (SHA1_RAW_SIZE == tmpuint) {
				struct sha1 sha1;
				memcpy(sha1.data, tmp, SHA1_RAW_SIZE);
				fi->cha1 = atom_sha1_get(&sha1);
			} else
				g_warning("bad length %d for CHA1 in fileinfo v%u for \"%s\"",
					tmpuint, version, pathname);
			break;
		case FILE_INFO_FIELD_CHUNK:
			{
				struct dl_file_chunk *fc;

				memcpy(tmpchunk, tmp, sizeof tmpchunk);
				fc = dl_file_chunk_alloc();

				if (!t64) {
					g_assert(version < 6);

					/*
			 	 	 * In version 1, fields were written in native form.
			 	 	 * Starting with version 2, they are written in network
					 * order.
			 	 	 */

			   		if (1 == version) {
						fc->from = tmpchunk[0];
						fc->to = tmpchunk[1];
						fc->status = tmpchunk[2];
					} else {
						fc->from = ntohl(tmpchunk[0]);
						fc->to = ntohl(tmpchunk[1]);
						fc->status = ntohl(tmpchunk[2]);
					}
				} else {
					uint64 hi, lo;

					g_assert(version >= 6);
					hi = ntohl(tmpchunk[0]);
					lo = ntohl(tmpchunk[1]);
					fc->from = (hi << 32) | lo;
					hi = ntohl(tmpchunk[2]);
					lo = ntohl(tmpchunk[3]);
					fc->to = (hi << 32) | lo;
					fc->status = ntohl(tmpchunk[4]);
				}

				if (DL_CHUNK_BUSY == fc->status)
					fc->status = DL_CHUNK_EMPTY;

				eslist_append(&fi->chunklist, fc);
			}
			break;
		default:
			g_warning("%s(): unhandled field ID %u (%d bytes long)",
				G_STRFUNC, field, tmpuint);
			break;
		}
	}

	if (!file_info_check_chunklist(fi, FALSE)) {
		file_info_chunklist_free(fi);
		BAILOUT("File contains inconsistent chunk list");
		/* NOT REACHED */
	}

	/*
	 * Pre-v4 (32-bit) trailers lacked the created and ntime fields.
	 * Pre-v5 (32-bit) trailers lacked the fskn (file size known) indication.
	 */

	if (version < 4)
		fi->ntime = fi->created = tm_time();

	if (version < 5)
		fi->file_size_known = TRUE;

	fi_upgrade_older_version(fi);

	/*
	 * If the fileinfo appendix was coherent sofar, we must have reached
	 * the fixed-size trailer that we already parsed eariler.  However,
	 * in case there was an application crash (kill -9) in the middle of
	 * a write(), or a machine crash, some data can be non-consistent.
	 *
	 * Read back the trailer fileds before the checksum to get an accurate
	 * checksum recomputation, but don't assert that what we read matches
	 * the trailer we already parsed.
	 */

	/* file size */
	if (t64) {
		/* Upper 32 bits since version 6 */
		if (!READ_UINT32(&tmpuint, &checksum))
			goto eof;
	}
	if (!READ_UINT32(&tmpuint, &checksum))		/* Lower bits */
		goto eof;

	if (!READ_UINT32(&tmpuint, &checksum))		/* generation number */
		goto eof;
	if (!READ_UINT32(&tmpuint, &checksum))		/* trailer length */
		goto eof;

	if (checksum != trailer.checksum) {
		BAILOUT("checksum mismatch");
		/* NOT REACHED */
	}

	fd_forget_and_close(&fd);

	fi_tigertree_check(fi);
	file_info_merge_adjacent(fi);	/* Update fi->done */

	if (GNET_PROPERTY(fileinfo_debug) > 3)
		g_debug("FILEINFO: "
			"good trailer info (v%u, %s bytes) in \"%s\"",
			version, filesize_to_string(trailer.length), pathname);

	return fi;

bailout:

	g_warning("%s(): %s in \"%s\"", G_STRFUNC, reason, pathname);

eof:
	if (fi) {
		fi_free(fi);
		fi = NULL;
	}
	fd_forget_and_close(&fd);
	return NULL;
#undef BAILOUT
}

/**
 * Stores a file info record to the config_dir/fileinfo file, and
 * appends it to the output file in question if needed.
 */
static void
file_info_store_one(FILE *f, fileinfo_t *fi)
{
	slink_t *cl;
	pslist_t *sl;
	char *path;

	file_info_check(fi);

	/*
	 * We now persist seeded files in order to be able to resume seeding
	 * after a crash and a restart, thereby ensuring continuity of the
	 * user session.
	 * 		--RAM, 2017-10-21
	 */

	if (FI_F_SEEDING == ((FI_F_SEEDING | FI_F_NOSHARE) & fi->flags))
		goto persist;		/* Skip trailer writes, of course */

	if (fi->flags & (FI_F_TRANSIENT | FI_F_SEEDING | FI_F_STRIPPED))
		return;

	if (fi->use_swarming && fi->dirty) {
		file_info_store_binary(fi, FALSE);
	}

persist:

	/*
	 * Keep entries for incomplete or not even started downloads so that the
	 * download is started/resumed as soon as a search gains a source.
	 */

	if (0 == fi->refcount && fi->done == fi->size) {
		filestat_t st;

		if (-1 == stat(fi->pathname, &st)) {
			return; 	/* Skip: not referenced, and file no longer exists */
		}
	}

	path = filepath_directory(fi->pathname);
	fprintf(f,
		"# refcount %u\n"
		"NAME %s\n"
		"PATH %s\n"
		"GUID %s\n"
		"GENR %u\n",
		fi->refcount,
		filepath_basename(fi->pathname),
		path,
		guid_hex_str(fi->guid),
		fi->generation);
	HFREE_NULL(path);

	PSLIST_FOREACH(fi->alias, sl) {
		const char *alias = sl->data;

		g_assert(NULL != alias);
		if (looks_like_urn(alias)) {
			g_warning("skipping fileinfo alias which looks like a urn: "
				"\"%s\" (filename=\"%s\")",
				alias, filepath_basename(fi->pathname));
		} else
			fprintf(f, "ALIA %s\n", alias);
	}

	if (fi->sha1)
		fprintf(f, "SHA1 %s\n", sha1_base32(fi->sha1));
	if (fi->tth)
		fprintf(f, "TTH %s\n", tth_base32(fi->tth));
	if (fi->cha1)
		fprintf(f, "CHA1 %s\n", sha1_base32(fi->cha1));

	fprintf(f, "SIZE %s\n", filesize_to_string(fi->size));
	fprintf(f, "DONE %s\n", filesize_to_string(fi->done));
	fprintf(f, "TIME %s\n", time_t_to_string(fi->stamp));
	fprintf(f, "CTIM %s\n", time_t_to_string(fi->created));
	fprintf(f, "NTIM %s\n", time_t_to_string(fi->ntime));

	/*
	 * The following boolean tags are emitted conditionally because they
	 * have defaults: we only emit them when the value is not the default.
	 *
	 * For instance, "PAUS" is emitted only when TRUE, so when missing, the
	 * assumption will be that the file downloading was not paused, i.e. that
	 * the value of that tag was FALSE.
	 *
	 * Note that although here we only emit "PAUS 1", we can correctly process
	 * input with "PAUS 0": although we no longer emit these, we accept them.
	 *
	 * 		--RAM, 2017-10-21
	 */

	if (FI_F_PAUSED & fi->flags)
		fputs("PAUS 1\n", f);

	if (FI_F_SEEDING == ((FI_F_SEEDING | FI_F_NOSHARE) & fi->flags))
		fputs("SEED 1\n", f);

	if (!fi->file_size_known)
		fputs("FSKN 0\n", f);

	if (!fi->use_swarming)
		fputs("SWRM 0\n", f);

	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH(&fi->chunklist, cl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, cl);

		dl_file_chunk_check(fc);
		fprintf(f, "CHNK %s %s %u\n",
			filesize_to_string(fc->from), filesize_to_string2(fc->to),
			(uint) fc->status);
	}
	fprintf(f, "\n");
}

/**
 * Callback for hash table iterator. Used by file_info_store().
 */
static void
file_info_store_list(void *value, void *user_data)
{
	fileinfo_t *fi = value;

	file_info_check(fi);
	file_info_store_one(user_data, fi);
}

/**
 * Stores the list of output files and their metainfo to the
 * configdir/fileinfo database.
 */
void
file_info_store(void)
{
	FILE *f;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), file_info_file);
	f = file_config_open_write(file_info_what, &fp);

	if (!f)
		return;

	file_config_preamble(f, "Fileinfo database");

	fputs(
		"#\n"
		"# Format is:\n"
		"#	NAME <file name>\n"
		"#	PATH <path>\n"
		"#	GUID <file ID>\n"
		"#	GENR <generation number>\n"
		"#	ALIA <alias file name>\n"
		"#	SIZE <size>\n"
		"#	SHA1 <server sha1>\n"
		"#	TTH  <server tth>\n"
		"#	CHA1 <computed sha1> [when done only]\n"
		"#	DONE <bytes done>\n"
		"#	TIME <last update stamp>\n"
		"#	CTIM <entry creation time>\n"
		"#	NTIM <time when new source was seen>\n"
		"#	PAUS <boolean; paused> [when TRUE only]\n"
		"#	SEED <boolean; file seeded> [when TRUE only]\n"
		"#	FSKN <boolean; file_size_known> [when FALSE only]\n"
		"#	SWRM <boolean; use_swarming> [when FALSE only]\n"
		"#	CHNK <start> <end+1> <0=hole, 1=busy, 2=done>\n"
		"#	<blank line>\n"
		"#\n\n",
		f
	);

	hikset_foreach(fi_by_outname, file_info_store_list, f);

	file_config_close(f, &fp);
	fileinfo_dirty = FALSE;
}

/**
 * Store global file information cache if dirty.
 */
void
file_info_store_if_dirty(void)
{
	if (fileinfo_dirty)
		file_info_store();
}

/*
 * Notify interested parties that file info is being removed and free
 * its handle.  Used mainly during final cleanup.
 */
static void
fi_dispose(fileinfo_t *fi)
{
	file_info_check(fi);

	file_info_drop_handle(fi, "Shutting down");

	/*
	 * Note that normally all fileinfo structures should have been collected
	 * during the freeing of downloads, so if we come here with a non-zero
	 * refcount, something is wrong with our memory management.
	 *
	 * (refcount of zero is possible if we have a fileinfo entry but no
	 * download attached to that fileinfo)
	 */

	if (fi->refcount)
		g_warning("%s(): refcount = %u for \"%s\"",
			G_STRFUNC, fi->refcount, fi->pathname);

	fi->hashed = FALSE;
	fi_free(fi);
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_sha1_kv(void *val, void *unused_x)
{
	const fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);

	/* fi structure in value not freed, shared with other hash tables */
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_namesize_kv(const void *key, void *val, void *unused_x)
{
	namesize_t *ns = deconstify_pointer(key);
	pslist_t *list = val;

	(void) unused_x;
	namesize_free(ns);
	pslist_free(list);

	/* fi structure in value not freed, shared with other hash tables */
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_guid_kv(void *val, void *unused_x)
{
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);

	/*
	 * fi structure in value not freed, shared with other hash tables
	 * However, transient file info are only in this hash, so free them!
	 */

	if (fi->flags & FI_F_TRANSIENT)
		fi_dispose(fi);
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_outname_kv(void *val, void *unused_x)
{
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);

	/*
	 * This table is the last one to be freed, and it is also guaranteed to
	 * contain ALL fileinfo, and only ONCE, by definition.  Thus freeing
	 * happens here.
	 */

	fi_dispose(fi);
}

/**
 * Signals that some information in the fileinfo has changed, warranting
 * a display update in the GUI.
 */
void
file_info_changed(fileinfo_t *fi)
{
	file_info_check(fi);
	g_return_if_fail(fi->hashed);

	fi_event_trigger(fi, EV_FI_STATUS_CHANGED);
}

static void
src_event_trigger(struct download *d, gnet_src_ev_t id)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->src_handle_valid);

	fi = d->file_info;
	file_info_check(fi);

	g_assert(UNSIGNED(id) < EV_SRC_EVENTS);
	event_trigger(src_events[id], T_NORMAL(src_listener_t, (d->src_handle)));
}

void
fi_src_status_changed(struct download *d)
{
	src_event_trigger(d, EV_SRC_STATUS_CHANGED);
}

void
fi_src_info_changed(struct download *d)
{
	src_event_trigger(d, EV_SRC_INFO_CHANGED);
}

void
fi_src_ranges_changed(struct download *d)
{
	src_event_trigger(d, EV_SRC_RANGES_CHANGED);
}

/**
 * Pre-close some file_info information.
 * This should be separate from file_info_close so that we can avoid circular
 * dependencies with other close routines, in this case with download_close.
 */
void
file_info_close_pre(void)
{
	src_remove_listener(fi_update_seen_on_network, EV_SRC_RANGES_CHANGED);
	can_publish_partial_sha1 = FALSE;
}

/**
 * Close and free all file_info structs in the list.
 */
void G_COLD
file_info_close(void)
{
	unsigned i;

	/*
	 * Freeing callbacks expect that the freeing of the `fi_by_outname'
	 * table will free the referenced `fi' (since that table MUST contain
	 * all the known `fi' structs by definition).
	 */

	hikset_foreach(fi_by_sha1, file_info_free_sha1_kv, NULL);
	htable_foreach(fi_by_namesize, file_info_free_namesize_kv, NULL);
	hikset_foreach(fi_by_guid, file_info_free_guid_kv, NULL);
	hikset_foreach(fi_by_outname, file_info_free_outname_kv, NULL);

	g_assert(0 == idtable_count(src_handle_map));
	idtable_destroy(src_handle_map);

	for (i = 0; i < N_ITEMS(src_events); i++) {
		event_destroy(src_events[i]);
	}

	/*
	 * The hash tables may still not be completely empty, but the referenced
	 * file_info structs are all freed.
	 *      --Richard, 9/3/2003
	 */

	g_assert(0 == idtable_count(fi_handle_map));
	idtable_destroy(fi_handle_map);

	for (i = 0; i < N_ITEMS(fi_events); i++) {
		event_destroy(fi_events[i]);
	}
	hikset_free_null(&fi_by_sha1);
	htable_free_null(&fi_by_namesize);
	hikset_free_null(&fi_by_guid);
	hikset_free_null(&fi_by_outname);

	HFREE_NULL(tbuf.arena);
}

/**
 * Inserts a file_info struct into the hash tables.
 */
static void
file_info_hash_insert(fileinfo_t *fi)
{
	const fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(!fi->hashed);
	g_assert(fi->guid);
	g_assert(NULL == fi->sf);

	if (GNET_PROPERTY(fileinfo_debug) > 4)
		g_debug("FILEINFO insert 0x%p \"%s\" "
			"(%s/%s bytes done) sha1=%s",
			cast_to_constpointer(fi), fi->pathname,
			filesize_to_string(fi->done), filesize_to_string2(fi->size),
			fi->sha1 ? sha1_base32(fi->sha1) : "none");

	/*
	 * Transient fileinfo is only recorded in the GUID hash table.
	 */

	if (fi->flags & FI_F_TRANSIENT)
		goto transient;

	/*
	 * If an entry already exists in the `fi_by_outname' table, then it
	 * is for THIS fileinfo.  Otherwise, there's a structural assertion
	 * that has been broken somewhere!
	 *		--RAM, 01/09/2002
	 */

	xfi = hikset_lookup(fi_by_outname, fi->pathname);
	if (xfi) {
		file_info_check(xfi);
		g_assert(xfi == fi);
	} else {
		hikset_insert_key(fi_by_outname, &fi->pathname);
	}

	/*
	 * Likewise, there can be only ONE entry per given SHA1, but the SHA1
	 * may not be already present at this time, so the entry is optional.
	 * If it exists, it must be unique though.
	 *		--RAM, 01/09/2002
	 */

	if (fi->sha1) {
		xfi = hikset_lookup(fi_by_sha1, fi->sha1);

		if (NULL != xfi && xfi != fi)		/* See comment above */
			g_error("xfi = %p, fi = %p", (void *) xfi, (void *) fi);

		if (NULL == xfi)
			hikset_insert_key(fi_by_sha1, &fi->sha1);

		/*
		 * To be able to return hits on partial files for which we have SHA1,
		 * create a shared file entry and record it as searchable.
		 */

		shared_file_from_fileinfo(fi);
		if (fi->sf != NULL)
			share_add_partial(fi->sf);
	}

	if (fi->file_size_known) {
		file_info_hash_insert_name_size(fi);
	}

transient:
	/*
	 * Obviously, GUID entries must be unique as well.
	 */

	xfi = hikset_lookup(fi_by_guid, fi->guid);

	if (NULL != xfi && xfi != fi)		/* See comment above */
		g_error("xfi = %p, fi = %p", (void *) xfi, (void *) fi);

	if (NULL == xfi)
		hikset_insert_key(fi_by_guid, &fi->guid);

	/*
	 * Notify interested parties, update counters.
	 */

	fi->hashed = TRUE;
    fi->fi_handle = file_info_request_handle(fi);

	gnet_prop_incr_guint32(PROP_FI_ALL_COUNT);

    fi_event_trigger(fi, EV_FI_ADDED);
}

/**
 * Remove fileinfo data from all the hash tables.
 */
static void
file_info_hash_remove(fileinfo_t *fi)
{
	const fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(fi->hashed);
	g_assert(fi->guid);

	if (GNET_PROPERTY(fileinfo_debug) > 4) {
		g_debug("FILEINFO remove %p \"%s\" (%s/%s bytes done) sha1=%s",
			(void *) fi, fi->pathname,
			filesize_to_string(fi->done), filesize_to_string2(fi->size),
			fi->sha1 ? sha1_base32(fi->sha1) : "none");
	}

	file_info_drop_handle(fi, "Discarding file info");
	entropy_harvest_single(PTRLEN(fi->guid));

	g_assert(GNET_PROPERTY(fi_all_count) > 0);
	gnet_prop_decr_guint32(PROP_FI_ALL_COUNT);

	/*
	 * Transient fileinfo is only recorded in the GUID hash table.
	 */

	if (fi->flags & FI_F_TRANSIENT)
		goto transient;

	/*
	 * Remove from plain hash tables: by output name, by SHA1 and by GUID.
	 */

	xfi = hikset_lookup(fi_by_outname, fi->pathname);
	if (xfi) {
		file_info_check(xfi);
		g_assert(xfi == fi);
		hikset_remove(fi_by_outname, fi->pathname);
	}

	if (fi->sha1)
		hikset_remove(fi_by_sha1, fi->sha1);

	if (fi->file_size_known)
		file_info_hash_remove_name_size(fi);

transient:
	hikset_remove(fi_by_guid, fi->guid);

	fi->hashed = FALSE;
}

/**
 * Stop all sharing occuring for this fileinfo.
 */
void
file_info_upload_stop(fileinfo_t *fi, const char *reason)
{
	file_info_check(fi);

	if (fi->sf) {
		upload_stop_all(fi, reason);
		share_remove_partial(fi->sf);
		shared_file_fileinfo_unref(&fi->sf);

		/*
		 * If the file was beeing seeded, and we have to call this routine,
		 * it means we are no longer able to share that completed file.
		 * Probably because it was removed from the disk, or it was changed
		 * since the time it was marked completed.
		 *		--RAM, 2017-10-13
		 */

		if (FI_F_SEEDING & fi->flags) {
			fi->flags &= ~FI_F_SEEDING;
			fi->flags |= FI_F_NOSHARE;	/* Don't share this file again */
		}

		file_info_changed(fi);
		fileinfo_dirty = TRUE;
	}
}

void
file_info_resume(fileinfo_t *fi)
{
	file_info_check(fi);

	if (FI_F_PAUSED & fi->flags) {
		fi->flags &= ~FI_F_PAUSED;
		file_info_changed(fi);
	}
}

void
file_info_pause(fileinfo_t *fi)
{
	file_info_check(fi);

	if (!(FI_F_PAUSED & fi->flags)) {
		fi->flags |= FI_F_PAUSED;
		file_info_changed(fi);
		fileinfo_dirty = TRUE;
	}
}

/**
 * Unlink file from disk.
 */
void
file_info_unlink(fileinfo_t *fi)
{
	file_info_check(fi);

	/*
	 * If this fileinfo was partially shared, make sure all uploads currently
	 * requesting it are terminated.
	 */

	file_info_upload_stop(fi, N_("Partial file removed"));

	if (fi->flags & (FI_F_TRANSIENT|FI_F_SEEDING|FI_F_STRIPPED|FI_F_UNLINKED))
		return;

	/*
	 * Only try to unlink partials because completed files are
	 * already moved or renamed and this could in theory match
	 * the filename of another download started afterwards which
	 * means the wrong file would be removed.
	 */
	if (FILE_INFO_COMPLETE(fi))
		return;

	if (!file_object_unlink(fi->pathname)) {
		/*
		 * File might not exist on disk yet if nothing was downloaded.
		 */

		if (fi->done)
			g_warning("cannot unlink \"%s\": %m", fi->pathname);
	} else {
		g_warning("unlinked \"%s\" (%s/%s bytes or %u%% done, %s SHA1%s%s)",
			fi->pathname,
			filesize_to_string(fi->done), filesize_to_string2(fi->size),
			(unsigned) (fi->done * 100U / (fi->size == 0 ? 1 : fi->size)),
			fi->sha1 ? "with" : "no",
			fi->sha1 ? ": " : "",
			fi->sha1 ? sha1_base32(fi->sha1) : "");
	}
	fi->flags |= FI_F_UNLINKED;
}

/**
 * Reparent all downloads using `from' as a fileinfo, so they use `to' now.
 */
static void
file_info_reparent_all(fileinfo_t *from, fileinfo_t *to)
{
	file_info_check(from);
	file_info_check(to);
	g_assert(0 == from->done);
	g_assert(0 != strcmp(from->pathname, to->pathname));

	file_info_unlink(from);
	download_info_change_all(from, to);

	/*
	 * We can dispose of the old `from' as all downloads using it are now gone.
	 */

	g_assert(0 == from->refcount);
	g_assert(0 == from->lifecount);

	file_info_hash_remove(from);
	fi_free(from);
}

/**
 * Called when we discover the SHA1 of a running download.
 * Make sure there is no other entry already bearing that SHA1, and record
 * the information.
 *
 * @returns TRUE if OK, FALSE if a duplicate record with the same SHA1 exists.
 */
bool
file_info_got_sha1(fileinfo_t *fi, const struct sha1 *sha1)
{
	fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(sha1);
	g_assert(NULL == fi->sha1);

	xfi = hikset_lookup(fi_by_sha1, sha1);

	if (NULL == xfi) {
		fi->sha1 = atom_sha1_get(sha1);
		hikset_insert_key(fi_by_sha1, &fi->sha1);

		if (can_publish_partial_sha1)
			publisher_add(fi->sha1);

		/* Update the GUI */
		fi_event_trigger(fi, EV_FI_INFO_CHANGED);

		return TRUE;
	}

	/*
	 * Found another entry with the same SHA1.
	 *
	 * If either download has not started yet, we can keep the active one
	 * and reparent the other.  Otherwise, we have to abort the current
	 * download, which will be done when we return FALSE.
	 *
	 * XXX we could abort the download with less data downloaded already,
	 * XXX or we could reconciliate the chunks from both files, but this
	 * XXX will cost I/Os and cannot be done easily in our current
	 * XXX mono-threaded model.
	 * XXX		--RAM, 05/09/2002
	 */

	if (GNET_PROPERTY(fileinfo_debug) > 3) {
		char buf[64];

		concat_strings(buf, sizeof buf,
			filesize_to_string(xfi->done), "/",
			filesize_to_string2(xfi->size), NULL_PTR);
		g_debug("CONFLICT found same SHA1 %s in \"%s\" "
			"(%s bytes done) and \"%s\" (%s/%s bytes done)\n",
			sha1_base32(sha1), xfi->pathname, buf, fi->pathname,
			filesize_to_string(fi->done), filesize_to_string2(fi->size));
	}

	if (fi->done && xfi->done) {
		char buf[64];

		concat_strings(buf, sizeof buf,
			filesize_to_string(xfi->done), "/",
			filesize_to_string2(xfi->size), NULL_PTR);
		g_warning("found same SHA1 %s in \"%s\" (%s bytes done) and \"%s\" "
			"(%s/%s bytes done) -- aborting last one",
			sha1_base32(sha1), xfi->pathname, buf, fi->pathname,
			filesize_to_string(fi->done), filesize_to_string2(fi->size));
		return FALSE;
	}

	if (fi->done) {
		g_assert(0 == xfi->done);
		fi->sha1 = atom_sha1_get(sha1);
		file_info_reparent_all(xfi, fi);	/* All `xfi' replaced by `fi' */
		hikset_insert_key(fi_by_sha1, &fi->sha1);
	} else {
		g_assert(0 == fi->done);
		file_info_reparent_all(fi, xfi);	/* All `fi' replaced by `xfi' */
	}

	if (can_publish_partial_sha1)
		publisher_add(sha1);

	return TRUE;
}

/**
 * Extract GUID from GUID line in the ASCII "fileinfo" summary file
 * and return NULL if none or invalid, the GUID atom otherwise.
 */
static const struct guid *
extract_guid(const char *s)
{
	struct guid guid;

	if (strlen(s) < GUID_HEX_SIZE)
		return NULL;

	if (!hex_to_guid(s, &guid))
		return NULL;

	return atom_guid_get(&guid);
}

/**
 * Extract sha1 from SHA1/CHA1 line in the ASCII "fileinfo" summary file
 * and return NULL if none or invalid, the SHA1 atom otherwise.
 */
static const struct sha1 *
extract_sha1(const char *s)
{
	struct sha1 sha1;

	if (strlen(s) < SHA1_BASE32_SIZE)
		return NULL;

	if (SHA1_RAW_SIZE != base32_decode(&sha1, sizeof sha1, s, SHA1_BASE32_SIZE))
		return NULL;

	return atom_sha1_get(&sha1);
}

static const struct tth *
extract_tth(const char *s)
{
	struct tth tth;

	if (strlen(s) < TTH_BASE32_SIZE)
		return NULL;

	if (TTH_RAW_SIZE != base32_decode(&tth, sizeof tth, s, TTH_BASE32_SIZE))
		return NULL;

	return atom_tth_get(&tth);
}

enum fi_tag {
	FI_TAG_UNKNOWN = 0,
	FI_TAG_ALIA,
	FI_TAG_CHA1,
	FI_TAG_CHNK,
	FI_TAG_CTIM,
	FI_TAG_DONE,
	FI_TAG_FSKN,
	FI_TAG_GENR,
	FI_TAG_GUID,
	FI_TAG_NAME,
	FI_TAG_NTIM,
	FI_TAG_PATH,
	FI_TAG_PAUS,
	FI_TAG_SEED,
	FI_TAG_SHA1,
	FI_TAG_SIZE,
	FI_TAG_SWRM,
	FI_TAG_TIME,
	FI_TAG_TTH
};

static const tokenizer_t fi_tags[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define FI_TAG(x) { #x, CAT2(FI_TAG_,x) }

	FI_TAG(ALIA),
	FI_TAG(CHA1),
	FI_TAG(CHNK),
	FI_TAG(CTIM),
	FI_TAG(DONE),
	FI_TAG(FSKN),
	FI_TAG(GENR),
	FI_TAG(GUID),
	FI_TAG(NAME),
	FI_TAG(NTIM),
	FI_TAG(PATH),
	FI_TAG(PAUS),
	FI_TAG(SEED),
	FI_TAG(SHA1),
	FI_TAG(SIZE),
	FI_TAG(SWRM),
	FI_TAG(TIME),
	FI_TAG(TTH),

	/* Above line intentionally left blank (for "!}sort" on vi) */

#undef FI_TAG
};

static inline enum fi_tag
file_info_string_to_tag(const char *s)
{
	return TOKENIZE(s, fi_tags);
}

/**
 * Reset CHUNK info: everything will have to be downloaded again
 */
static void
fi_reset_chunks(fileinfo_t *fi)
{
	file_info_check(fi);
	if (fi->file_size_known) {
		struct dl_file_chunk *fc;

		file_info_chunklist_free(fi);
		fc = dl_file_chunk_alloc();
		fc->from = 0;
		fc->to = fi->size;
		fc->status = DL_CHUNK_EMPTY;
		eslist_append(&fi->chunklist, fc);
	}

	fi->generation = 0;		/* Restarting from scratch... */
	fi->done = 0;
	atom_sha1_free_null(&fi->cha1);
}

/**
 * Copy CHUNK info from binary trailer `trailer' into `fi'.
 */
static void
fi_copy_chunks(fileinfo_t *fi, fileinfo_t *trailer)
{
	const struct dl_file_chunk *fc;

	file_info_check(fi);
	file_info_check(trailer);
	g_assert(0 == eslist_count(&fi->chunklist));
	g_assert(file_info_check_chunklist(trailer, TRUE));

	fi->generation = trailer->generation;
	if (trailer->cha1)
		fi->cha1 = atom_sha1_get(trailer->cha1);

	ESLIST_FOREACH_DATA(&trailer->chunklist, fc) {
		dl_file_chunk_check(fc);
		g_assert(fc->from <= fc->to);

		eslist_append(&fi->chunklist, WCOPY(fc));
	}

	file_info_merge_adjacent(fi); /* Recalculates also fi->done */
}

/**
 * Loads the fileinfo database from disk, and saves a copy in fileinfo.orig.
 */
void G_COLD
file_info_retrieve(void)
{
	FILE *f;
	char line[1024];
	fileinfo_t *fi = NULL;
	bool empty = TRUE;
	bool last_was_truncated = FALSE;
	file_path_t fp;
	const char *old_filename = NULL;	/* In case we must rename the file */
	const char *path = NULL;
	const char *filename = NULL;

	/*
	 * We have a complex interaction here: each time a new entry within the
	 * download mesh is added, file_info_try_to_swarm_with() will be
	 * called.	Moreover, the download mesh is initialized before us.
	 *
	 * However, we cannot enqueue a download before the download module is
	 * initialized. And we know it is initialized now because download_init()
	 * calls us!
	 *
	 *		--RAM, 20/08/2002
	 */

	can_swarm = TRUE;			/* Allows file_info_try_to_swarm_with() */

	file_path_set(&fp, settings_config_dir(), file_info_file);
	f = file_config_open_read(file_info_what, &fp, 1);
	if (!f)
		return;

	while (fgets(line, sizeof line, f)) {
		int error;
		bool truncated = FALSE, damaged;
		const char *ep;
		char *value;
		uint64 v;

		/*
		 * The following semi-complex logic attempts to determine whether
		 * we filled the whole line buffer without reaching the end of the
		 * physical line.
		 *
		 * When truncation occurs, we skip every following "line" we'd get
		 * up to the point where we no longer need to truncate, at which time
		 * we'll be re-synchronized on the real end of the line.
		 */

		truncated = !file_line_chomp_tail(line, sizeof line, NULL);

		if (last_was_truncated) {
			last_was_truncated = truncated;
			g_warning("ignoring fileinfo line after truncation: '%s'", line);
			continue;
		} else if (truncated) {
			last_was_truncated = TRUE;
			g_warning("ignoring too long fileinfo line: '%s'", line);
			continue;
		}

		if (file_line_is_comment(line))
			continue;

		/*
		 * Reaching an empty line means the end of the fileinfo description.
		 */

		if ('\0' == *line && fi) {
			fileinfo_t *dfi;
			bool upgraded;
			bool reload_chunks = FALSE;

			if (filename && path) {
				char *pathname = make_pathname(path, filename);
				fi->pathname = atom_str_get(pathname);
				HFREE_NULL(pathname);
			} else {
				/* There's an incomplete fileinfo record */
				goto reset;
			}
			atom_str_free_null(&filename);
			atom_str_free_null(&path);

			/*
			 * There can't be duplicates!
			 */

			dfi = hikset_lookup(fi_by_outname, fi->pathname);
			if (NULL != dfi) {
				g_warning("discarding DUPLICATE fileinfo entry for \"%s\"",
					filepath_basename(fi->pathname));
				goto reset;
			}

			if (0 == fi->size) {
				fi->file_size_known = FALSE;
			}

			/*
			 * If we deserialized an older version, bring it up to date.
			 */

			upgraded = fi_upgrade_older_version(fi);

			/*
			 * If we are processing a file being seeded, skip all the
			 * CHNK, DONE and trailer consistency checks.
			 *
			 * If we are not recovering from a crash, seeded entries are
			 * discarded.
			 */

			if (FI_F_SEEDING & fi->flags) {
				if (crash_was_restarted()) {
					filestat_t sb;

					if (NULL == fi->sha1) {
						g_warning("%s(): missing SHA1 for seeded file %s",
							G_STRFUNC, fi->pathname);
						goto reset;		/* Fileinfo DB was corrupted, drop seed */
					}

					if (!file_exists(fi->pathname)) {
						g_warning("%s(): missing previously seeded file %s",
							G_STRFUNC, fi->pathname);
						goto reset;		/* User probably removed the file */
					}

					if (-1 == stat(fi->pathname, &sb)) {
						g_warning("%s(): cannot stat seeded file %s: %m",
							G_STRFUNC, fi->pathname);
						goto reset;
					}

					/*
					 * FIXME:
					 * Would need to check that the file is still accurate if
					 * the timestamp was changed since last modification.
					 * For now just warn.
					 * 		--RAM, 2017-10-23
					 */

					if (sb.st_mtime != fi->modified) {
						bool accepted = huge_cached_is_uptodate(
								fi->pathname, sb.st_size, sb.st_mtime);

						g_warning("%s(): modified seeded file %s: "
							"last modified=%lu, file mtime=%lu; %s",
							G_STRFUNC, fi->pathname,
							(ulong) fi->modified, (ulong) sb.st_mtime,
							accepted ? "resetting!" : "discarding!");

						if (!accepted)
							goto reset;

						/* This stamp is necessary to be able to upload! */
						fi->modified = sb.st_mtime;
						fi->stamp = fi->modified;	/* Persist new value */
					}

					if (fi->tth != NULL)
						file_info_recomputed_tth_internal(fi, fi->tth, FALSE);

					/* Seeding of file will be resumed */
					goto ready;
				}

				if (GNET_PROPERTY(share_debug)) {
					g_info("SHARE discarding seeded file %s", fi->pathname);
				}

				/* Drop the seeded file now */
				goto reset;
			}

			/*
			 * Allow reconstruction of missing information: if no CHNK
			 * entry was found for the file, fake one, all empty, and reset
			 * DONE and GENR to 0.
			 *
			 * If for instance the partition where temporary files are held
			 * is lost, a single "grep -v ^CHNK fileinfo > fileinfo.new"
			 * will be enough to restart without losing the collected
			 * files.
			 *
			 *		--RAM, 31/12/2003
			 */

			if (0 == eslist_count(&fi->chunklist)) {
				if (fi->file_size_known)
					g_warning("no CHNK info for \"%s\"", fi->pathname);
				fi_reset_chunks(fi);
				reload_chunks = TRUE;	/* Will try to grab from trailer */
			} else if (!file_info_check_chunklist(fi, FALSE)) {
				if (fi->file_size_known)
					g_warning("invalid set of CHNK info for \"%s\"",
						fi->pathname);
				fi_reset_chunks(fi);
				reload_chunks = TRUE;	/* Will try to grab from trailer */
			}

			g_assert(file_info_check_chunklist(fi, TRUE));

			/*
			 * If DONE does not match the actual size described by the CHNK
			 * set, them perhaps the fileinfo database was corrupted?
			 */

			{
				filesize_t done = fi->done;

				file_info_merge_adjacent(fi); /* Recalculates also fi->done */

				/*
				 * If DONE was missing, fi->done will still be 0.
				 * In that case, we don't really care since we'll have
				 * recomputed fi->done in the call above.
				 */

				if (done != 0 && fi->done != done) {
					g_warning("inconsistent DONE info for \"%s\": "
						"read %s, computed %s",
						fi->pathname, filesize_to_string(done),
						filesize_to_string2(fi->done));
					reload_chunks = TRUE;	/* Will try to grab from trailer */
				}
			}

			/*
			 * If `old_filename' is not NULL, then we need to rename
			 * the file bearing that name into the new (sanitized)
			 * name, making sure there is no filename conflict.
			 */

			if (NULL != old_filename) {
				const char *new_pathname;
				char *old_path;
				bool renamed = TRUE;

				old_path = filepath_directory(fi->pathname);
				new_pathname = file_info_new_outname(old_path,
									filepath_basename(fi->pathname));
				HFREE_NULL(old_path);
				if (NULL == new_pathname)
					goto reset;

				/*
				 * If fi->done == 0, the file might not exist on disk.
				 */

				if (-1 == rename(fi->pathname, new_pathname) && 0 != fi->done)
					renamed = FALSE;

				if (renamed) {
					g_warning("renamed \"%s\" into sanitized \"%s\"",
						fi->pathname, new_pathname);
					atom_str_change(&fi->pathname, new_pathname);
				} else {
					g_warning("cannot rename \"%s\" into \"%s\": %m",
						fi->pathname, new_pathname);
				}
				atom_str_free_null(&new_pathname);
			}

			/*
			 * Check file trailer information.	The main file is only written
			 * infrequently and the file's trailer can have more up-to-date
			 * information.
			 */

			dfi = file_info_retrieve_binary(fi->pathname);

			/*
			 * If we resetted the CHNK list above, grab those from the
			 * trailer: that cannot be worse than having to download
			 * everything again...  If there was no valid trailer, all the
			 * data are lost and the whole file will need to be grabbed again.
			 */

			if (dfi != NULL && reload_chunks) {
				fi_copy_chunks(fi, dfi);
				if (0 != eslist_count(&fi->chunklist)) {
					g_message("recovered %s downloaded bytes "
						"from trailer of \"%s\"",
						filesize_to_string(fi->done), fi->pathname);
				}
			} else if (reload_chunks)
				g_warning("lost all CHNK info for \"%s\" -- downloading again",
					fi->pathname);

			g_assert(file_info_check_chunklist(fi, TRUE));

			/*
			 * Special treatment for the GUID: if not present, it will be
			 * added during retrieval, but it will be different for the
			 * one in the fileinfo DB and the one on disk.  Set `upgraded'
			 * to signal that, so that we resync the metainfo below.
			 */

			if (dfi && dfi->guid != fi->guid)		/* They're atoms... */
				upgraded = TRUE;

			/*
			 * NOTE: The tigertree data is only stored in the trailer, not
			 * in the common "fileinfo" file. Therefore, it MUST be fetched
			 * from "dfi".
			 */

			if (dfi && dfi->tigertree.leaves && NULL == fi->tigertree.leaves) {
				file_info_got_tigertree(fi,
					dfi->tigertree.leaves, dfi->tigertree.num_leaves, FALSE);
			}

			if (dfi) {
				fi->modified = dfi->modified;
			}

			if (NULL == dfi) {
				if (is_regular(fi->pathname)) {
					g_warning("got metainfo in fileinfo cache, "
						"but none in \"%s\"", fi->pathname);
					upgraded = FALSE;			/* No need to flush twice */
					file_info_store_binary(fi, TRUE);	/* Create metainfo */
				} else {
					file_info_merge_adjacent(fi);		/* Compute fi->done */
					if (fi->done > 0) {
						g_warning("discarding cached metainfo for \"%s\": "
							"file had %s bytes downloaded "
							"but is now gone!", fi->pathname,
							filesize_to_string(fi->done));
						goto reset;
					}
				}
			} else if (dfi->generation > fi->generation) {
				g_warning("found more recent metainfo in \"%s\"", fi->pathname);
				fi_free(fi);
				fi = dfi;
			} else if (dfi->generation < fi->generation) {
				g_warning("found OUTDATED metainfo in \"%s\"", fi->pathname);
				fi_free(dfi);
				dfi = NULL;
				upgraded = FALSE;				/* No need to flush twice */
				file_info_store_binary(fi, TRUE);/* Resync metainfo */
			} else {
				g_assert(dfi->generation == fi->generation);
				fi_free(dfi);
				dfi = NULL;
			}

			/*
			 * Check whether entry is not another's duplicate.
			 */

			dfi = file_info_lookup_dup(fi);

			if (NULL != dfi) {
				g_warning("found DUPLICATE entry for \"%s\" "
					"(%s bytes) with \"%s\" (%s bytes)",
					fi->pathname, filesize_to_string(fi->size),
					dfi->pathname, filesize_to_string2(dfi->size));
				goto reset;
			}

			/*
			 * If we had to upgrade the fileinfo, make sure we resync
			 * the metadata on disk as well.
			 */

			if (upgraded) {
				g_warning("flushing upgraded metainfo in \"%s\"", fi->pathname);
				file_info_store_binary(fi, TRUE);		/* Resync metainfo */
			}

			file_info_merge_adjacent(fi);

		ready:

			file_info_hash_insert(fi);

			if (can_publish_partial_sha1 && fi->sha1 != NULL) {
				publisher_add(fi->sha1);
			}

			/*
			 * We could not add the aliases immediately because the file
			 * is formatted with ALIA coming before SIZE.  To let fi_alias()
			 * detect conflicting entries, we need to have a valid fi->size.
			 * And since the `fi' is hashed, we can detect duplicates in
			 * the `aliases' list itself as an added bonus.
			 */

			if (fi->alias) {
				pslist_t *aliases, *sl;

				/* For efficiency each alias has been prepended to
				 * the list. To preserve the order between sessions,
				 * the original list order is restored here. */
				aliases = pslist_reverse(fi->alias);
				fi->alias = NULL;
				PSLIST_FOREACH(aliases, sl) {
					const char *s = sl->data;
					fi_alias(fi, s, TRUE);
					atom_str_free_null(&s);
				}
				pslist_free_null(&aliases);
			}

			empty = FALSE;
			fi = NULL;
			continue;
		}

		if (!fi) {
			fi = file_info_allocate();
			fi->file_size_known = TRUE;		/* Unless stated otherwise below */
			fi->use_swarming = TRUE;		/* Unless stated otherwise below */
			old_filename = NULL;
		}

		value = strchr(line, ' ');
		if (!value) {
			if (*line)
				g_warning("ignoring fileinfo line: \"%s\"", line);
			continue;
		}
		*value++ = '\0'; /* Skip space and point to value */
		if ('\0' == value[0]) {
			g_warning("empty value in fileinfo line: \"%s %s\"", line, value);
			continue;
		}

		damaged = FALSE;
		switch (file_info_string_to_tag(line)) {
		case FI_TAG_NAME:
			if (GNET_PROPERTY(convert_old_filenames)) {
				char *s;
				char *b;

				b = s = filename_sanitize(value,
						GNET_PROPERTY(convert_spaces),
						GNET_PROPERTY(convert_evil_chars));

				if (GNET_PROPERTY(beautify_filenames))
					b = filename_beautify(s);

				filename = atom_str_get(b);
				if (s != value) {

					if (0 != strcmp(s, value)) {
						g_warning("fileinfo database contained an "
						"unsanitized filename: \"%s\" -> \"%s\"", value, s);

						/*
						 * Record old filename, before sanitization.
						 * We'll have to rename that file later, when we
						 * have parsed the whole fileinfo.
						 */

						old_filename = atom_str_get(value);
					}
				}

				if (b != s)		HFREE_NULL(b);
				if (value != s) HFREE_NULL(s);
			} else {
				filename = atom_str_get(value);
			}
			break;
		case FI_TAG_PATH:
			/* FIXME: Check the pathname more thoroughly */
			damaged = !is_absolute_path(value);
			path = damaged ? NULL : atom_str_get(value);
			break;
		case FI_TAG_PAUS:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v > 1;
			fi->flags |= v ? FI_F_PAUSED : 0;
			break;
		case FI_TAG_SEED:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v > 1;
			fi->flags |= v ? (FI_F_SEEDING | FI_F_STRIPPED) : 0;
			break;
		case FI_TAG_ALIA:
			if (looks_like_urn(value)) {
				g_warning("skipping alias which looks like a urn in "
					"fileinfo database: \"%s\" (pathname=\"%s\")", value,
					NULL_STRING(fi->pathname));
			} else {
				char *s;
				char *b;

				b = s = filename_sanitize(value, FALSE, FALSE);

				if (GNET_PROPERTY(beautify_filenames))
					b = filename_beautify(s);

				/* The alias is only temporarily added to fi->alias, the list
				 * of aliases has to be re-constructed with fi_alias()
			   	 * when the fileinfo record is finished. It's merely done
				 * this way to simplify discarding incomplete/invalid records
				 * utilizing fi_free().
				 * The list should be reversed once it's complete.
				 */
				fi->alias = pslist_prepend_const(fi->alias, atom_str_get(b));
				if (s != value) {
					if (strcmp(s, value)) {
						g_warning("fileinfo database contained an "
							"unsanitized alias: \"%s\" -> \"%s\"", value, s);
					}
				}
				if (b != s)		HFREE_NULL(b);
				if (s != value)	HFREE_NULL(s);
			}
			break;
		case FI_TAG_GENR:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v > (uint32) INT_MAX;
			fi->generation = v;
			break;
		case FI_TAG_SIZE:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error
				|| '\0' != *ep
				|| v >= ((uint64) 1UL << 63)
				|| (!fi->file_size_known && 0 == v);
			fi->size = v;
			break;
		case FI_TAG_FSKN:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error
				|| '\0' != *ep
				|| v > 1
				|| (0 == fi->size && 0 != v);
			fi->file_size_known = v != 0;
			break;
		case FI_TAG_TIME:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep;
			fi->stamp = v;
			fi->modified = v;		/* Until we know better */
			break;
		case FI_TAG_CTIM:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep;
			fi->created = v;
			break;
		case FI_TAG_NTIM:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep;
			fi->ntime = v;
			break;
		case FI_TAG_DONE:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v >= ((uint64) 1UL << 63);
			fi->done = v;
			break;
		case FI_TAG_SWRM:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v > 1;
			fi->use_swarming = v;
			break;
		case FI_TAG_GUID:
			fi->guid = extract_guid(value);
			damaged = NULL == fi->guid;
			break;
		case FI_TAG_TTH:
			fi->tth = extract_tth(value);
			damaged = NULL == fi->tth;
			break;
		case FI_TAG_SHA1:
			fi->sha1 = extract_sha1(value);
			damaged = NULL == fi->sha1;
			break;
		case FI_TAG_CHA1:
			fi->cha1 = extract_sha1(value);
			damaged = NULL == fi->cha1;
			break;
		case FI_TAG_CHNK:
			{
				filesize_t from, to;
				uint32 status;

				from = v = parse_uint64(value, &ep, 10, &error);
				damaged = error
					|| *ep != ' '
					|| v >= ((uint64) 1UL << 63)
					|| from > fi->size;

				if (!damaged) {
					const char *s = &ep[1];

					to = v = parse_uint64(s, &ep, 10, &error);
					damaged = error
						|| ' ' != *ep
						|| v >= ((uint64) 1UL << 63)
						|| v <= from
						|| to > fi->size;
				} else {
					to = 0;	/* For stupid compilers */
				}
				if (!damaged) {
					const char *s = &ep[1];

					status = v = parse_uint64(s, &ep, 10, &error);
					damaged = error || '\0' != *ep || v > 2U;
				} else {
					status = 0;	/* For stupid compilers */
				}
				if (!damaged) {
					struct dl_file_chunk *fc, *prev;

					fc = dl_file_chunk_alloc();
					fc->from = from;
					fc->to = to;
					if (DL_CHUNK_BUSY == status)
						status = DL_CHUNK_EMPTY;
					fc->status = status;
					prev = eslist_tail(&fi->chunklist);
					if (fc->from != (prev ? prev->to : 0)) {
						g_warning("chunklist is inconsistent (fi->size=%s)",
							filesize_to_string(fi->size));
						damaged = TRUE;
					} else {
						eslist_append(&fi->chunklist, fc);
					}
				}
			}
			break;
		case FI_TAG_UNKNOWN:
			if (*line)
				g_warning("ignoring fileinfo line: \"%s %s\"", line, value);
			break;
		}

		if (damaged)
			g_warning("damaged entry in fileinfo line: \"%s %s\"", line, value);
		continue;

	reset:
		fi_free(fi);
		fi = NULL;
		atom_str_free_null(&filename);
		atom_str_free_null(&path);
	}

	if (fi) {
		fi_free(fi);
		fi = NULL;
		if (!empty)
			g_warning("file info repository was truncated!");
	}
	atom_str_free_null(&filename);
	atom_str_free_null(&path);

	fclose(f);
}

static bool
file_info_name_is_uniq(const char *pathname)
{
	return !hikset_contains(fi_by_outname, pathname) &&
	   	path_does_not_exist(pathname);
}

/**
 * Unique filename where data will be saved.
 * String must be freed via hfree().
 */
char *
file_info_unique_filename(const char *path, const char *file,
	const char *ext)
{
	return filename_unique(path, file, ext, file_info_name_is_uniq);
}

/**
 * Allocate unique output name for file `name', stored in `dir'.
 *
 * @returns The full pathname (string atom).
 */
static const char *
file_info_new_outname(const char *dir, const char *name)
{
	char *uniq = NULL;
	const char *filename = name;
	char *b;
	char *s;

	g_return_val_if_fail(dir, NULL);
	g_return_val_if_fail(name, NULL);
	g_return_val_if_fail(is_absolute_path(dir), NULL);

	b = s = filename_sanitize(name,
			GNET_PROPERTY(convert_spaces),
			GNET_PROPERTY(convert_evil_chars));

	if (name != s)
		filename = s;

	if (GNET_PROPERTY(beautify_filenames))
		filename = b = filename_beautify(s);

	if ('\0' == filename[0]) {
		/* Don't allow empty names */
		filename = "noname";
	}

	/*
	 * If `filename' (sanitized form) is not taken yet, it will do.
	 */

	uniq = file_info_unique_filename(dir, filename, "");
	if (b != s)		HFREE_NULL(b);
	if (name != s)	HFREE_NULL(s);

	if (uniq) {
		const char *pathname;

		pathname = atom_str_get(uniq);
		HFREE_NULL(uniq);
		g_assert(!hikset_contains(fi_by_outname, pathname));
		return pathname;
	} else {
		return NULL;
	}
}

/**
 * Create a fileinfo structure from existing file with no swarming trailer.
 * The given `size' argument reflect the final size of the (complete) file.
 * The `sha1' is the known SHA1 for the file (NULL if unknown).
 */
static fileinfo_t *
file_info_create(const char *file, const char *path, filesize_t size,
	const struct sha1 *sha1, bool file_size_known)
{
	const char *pathname;
	fileinfo_t *fi;
	filestat_t st;

	pathname = file_info_new_outname(path, file);
	g_return_val_if_fail(pathname, NULL);

	fi = file_info_allocate();
	fi->pathname = pathname;				/* Get unique file name */
	fi->guid = fi_random_guid_atom();		/* Get unique ID */

	if (sha1)
		fi->sha1 = atom_sha1_get(sha1);
	fi->size = 0;	/* Will be updated by fi_resize() */
	fi->file_size_known = file_size_known;
	fi->done = 0;
	fi->use_swarming = GNET_PROPERTY(use_swarming) && file_size_known;
	fi->created = tm_time();
	fi->modified = fi->created;
	fi->seen_on_network = NULL;

	if (-1 != stat(fi->pathname, &st) && S_ISREG(st.st_mode)) {
		struct dl_file_chunk *fc;

		g_warning("%s(): assuming file \"%s\" is complete up to %s bytes",
			G_STRFUNC, fi->pathname, filesize_to_string(st.st_size));

		fc = dl_file_chunk_alloc();
		fc->from = 0;
		fi->size = fc->to = st.st_size;
		fc->status = DL_CHUNK_DONE;
		fi->modified = st.st_mtime;
		eslist_append(&fi->chunklist, fc);
		fi->dirty = TRUE;
	}

	if (size > fi->size)
		fi_resize(fi, size);

	g_assert(fi->file_size_known || !fi->use_swarming);

	return fi;
}

/**
 * Create a transient fileinfo structure.
 */
fileinfo_t *
file_info_get_transient(const char *name)
{
	fileinfo_t *fi;
	char *path;

	fi = file_info_allocate();

	path = make_pathname("/non-existent", name);
	fi->pathname = atom_str_get(path);
	HFREE_NULL(path);

	fi->guid = fi_random_guid_atom();		/* Get unique ID */

	fi->size = 0;	/* Will be updated by fi_resize() */
	fi->file_size_known = FALSE;
	fi->done = 0;
	fi->use_swarming = FALSE;
	fi->created = tm_time();
	fi->modified = fi->created;
	fi->seen_on_network = NULL;
	fi->dirty = TRUE;

	fi->flags = FI_F_TRANSIENT;		/* Not persisted to disk */

	file_info_hash_insert(fi);

	return fi;
}

/**
 * Rename dead file we cannot use, either because it bears a duplicate SHA1
 * or because its file trailer bears a duplicate file ID.
 *
 * The file is really dead, so unfortunately we have to strip its fileinfo
 * trailer so that we do not try to reparent it at a later time.
 */
static void
fi_rename_dead(fileinfo_t *fi, const char *pathname)
{
	char *path, *dead;

	file_info_check(fi);

	path = filepath_directory(pathname);
	dead = file_info_unique_filename(path,
				filepath_basename(pathname), ".DEAD");

	if (dead && 0 == rename(pathname, dead)) {
		file_info_strip_trailer(fi, dead);
	} else {
		g_warning("cannot rename \"%s\" as \"%s\": %m",
			pathname, NULL_STRING(dead));
	}
	HFREE_NULL(dead);
	HFREE_NULL(path);
}

void
file_info_mark_completed(fileinfo_t *fi)
{
	file_info_check(fi);

	if (
		fi->sha1 != NULL && GNET_PROPERTY(pfsp_server) &&
		!(FI_F_TRANSIENT & fi->flags)
		/* No size consideration here as the file is complete */
	) {
		fi->flags |= FI_F_SEEDING;

		/*
		 * Since we're going to seed that file, prepare a TTH tree for it
		 * at the right depth and cache it on disk.
		 * 		--RAM, 2017-10-17
		 */

		g_soft_assert(fi->sf != NULL);	/* file_info_hash_insert() was called */

		if (NULL == fi->sf)				/* Should never happen */
			shared_file_from_fileinfo(fi);

		/*
		 * Since shared_file_from_fileinfo() can abort when a suitable filename
		 * cannot be derived, we need to be cautious.
		 */

		if (fi->sf != NULL)
			request_tigertree(fi->sf, TRUE);
	}

	/*
	 * Now that the file is completed (and fully validated), we can get rid
	 * of the memory used in the fileinfo for the purpose of downloading,
	 * keeping only what is necessary to be able to share it.
	 * 		--RAM, 2017-10-17
	 */

	fi_downloading_free(fi);

	/*
	 * Update the GUI, now that we have cleared the range information.
	 *
	 * This should redraw the progress bar to display the file as green,
	 * without any underlying blue bar: the file is now completed, we do
	 * not care about the availability of its part on the network!
	 */

	fi_event_trigger(fi, EV_FI_RANGES_CHANGED);
	fi_event_trigger(fi, EV_FI_INFO_CHANGED);
}

/**
 * Called to update the fileinfo information with the new path and possibly
 * filename information, once the downloaded file has been moved/renamed.
 * This prepares for possible seeding of the file once it has been completed,
 * to continue "partial-file-sharing" it now that it is fully available...
 */
void
file_info_moved(fileinfo_t *fi, const char *pathname)
{
	const fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(pathname);
	g_assert(is_absolute_path(pathname));
	g_assert(!(fi->flags & FI_F_SEEDING));
	g_return_if_fail(fi->hashed);

	xfi = hikset_lookup(fi_by_outname, fi->pathname);
	if (xfi != NULL) {
		file_info_check(xfi);
		g_assert(xfi == fi);
		hikset_remove(fi_by_outname, fi->pathname);
	}

	atom_str_change(&fi->pathname, pathname);

	g_assert(NULL == hikset_lookup(fi_by_outname, fi->pathname));
	hikset_insert_key(fi_by_outname, &fi->pathname);

	if (fi->sf != NULL) {
		filestat_t sb;
		time_t mtime = 0;

		shared_file_set_path(fi->sf, fi->pathname);
		if (-1 == stat(fi->pathname, &sb)) {
			g_warning("%s(): cannot stat() shared file \"%s\": %m",
				G_STRFUNC, fi->pathname);
		} else if (fi->size + (fileoffset_t) 0 != sb.st_size + (filesize_t) 0) {
			g_warning("%s(): wrong size for shared file \"%s\": "
				"expected %s, got %s",
				G_STRFUNC, fi->pathname, filesize_to_string(fi->size),
				filesize_to_string2(sb.st_size));
		} else {
			mtime = sb.st_mtime;
		}

		/*
		 * In case they allow PFS, the completed file will be seeded and
		 * we must make sure its modification time, as returned by
		 * shared_file_modification_time(), will be accurate, now that the
		 * file has been moved to its new location and its fileinfo trailer
		 * was stripped.
		 *
		 * Among other things, this is important for upload_file_present()
		 * to detect whether the completed file was modified since it was
		 * moved, to be able to stop seeding it.
		 *
		 * We also set fi->modified because shared_file_modification_time()
		 * will transparently return that value for PFS.
		 * 		--RAM, 2017-10-11
		 */

		shared_file_set_modification_time(fi->sf, mtime);	/* Sets sf->mtime */
		fi->modified = mtime;
		fi->stamp = mtime;		/* Persisted as "TIME" in fileinfo ASCII DB */
 	}

	fi_event_trigger(fi, EV_FI_INFO_CHANGED);
	file_info_changed(fi);
	fileinfo_dirty = TRUE;
}

/**
 * @param `file' is the file name on the server.
 * @param `path' no brief description.
 * @param `size' no brief description.
 * @param `sha1' no brief description.
 * @param `file_size_known' no brief description.
 *
 * @returns a pointer to file_info struct that matches the given file
 * name, size and/or SHA1. A new struct will be allocated if necessary.
 */
fileinfo_t *
file_info_get(const char *file, const char *path, filesize_t size,
	const struct sha1 *sha1, bool file_size_known)
{
	fileinfo_t *fi;
	const char *pathname;
   	char *to_free = NULL;

	/*
	 * See if we know anything about the file already.
	 */

	fi = file_info_lookup(file, size, sha1);
	if (fi) {
		file_info_check(fi);
		if (sha1 && fi->sha1 && !sha1_eq(sha1, fi->sha1))
			fi = NULL;
	}


	if (fi) {
		/*
		 * Once we have determined the file size with certainety, we do not
		 * allow resizing.  Of course, we can't know which size is the correct
		 * one (the one we had before, or the new reported one).
		 */

		if (size != fi->size) {
			if (fi->file_size_known) {
				g_warning("file \"%s\" (SHA1 %s, %s bytes): "
					"size mismatch: %s bytes",
					fi->pathname, sha1_base32(fi->sha1),
					filesize_to_string(fi->size),
					filesize_to_string2(size));
				return NULL;
			}
		}

		/*
		 * If download size is greater, we need to resize the output file.
		 * This can only happen for a download with a SHA1, because otherwise
		 * we perform a matching on name AND size.
		 */

		if (size > fi->size) {
			g_assert(fi->sha1);
			g_assert(sha1);

			g_warning("file \"%s\" (SHA1 %s) was %s bytes, resizing to %s",
				fi->pathname, sha1_base32(fi->sha1),
				filesize_to_string(fi->size), filesize_to_string2(size));

			file_info_hash_remove(fi);
			fi_resize(fi, size);
			file_info_hash_insert(fi);
		}

		fi_alias(fi, file, TRUE);	/* Add alias if not conflicting */

		return fi;
	}


	/* First convert the filename to what the GUI used */
	{
		char *s = unknown_to_utf8_normalized(file, UNI_NORM_NETWORK, NULL);
		if (file != s) {
			file = s;
			to_free = s;
		}
	}

	/* Now convert the UTF-8 to what the filesystem wants */
	{
		char *s = utf8_to_filename(file);
		g_assert(s != file);
		G_FREE_NULL(to_free);
		to_free = s;
		file = s;
	}

	/*
	 * Compute new output name.  If the filename is not taken yet, this
	 * will be exactly `file'.  Otherwise, it will be a variant.
	 */

	pathname = file_info_new_outname(path, file);
	if (NULL == pathname)
		goto finish;

	/*
	 * Check whether the file exists and has embedded meta info.
	 * Note that we use the new `outname', not `file'.
	 */

	fi = file_info_retrieve_binary(pathname);
	if (fi) {
		/*
		 * File exists, and is NOT currently in use, otherwise `outname' would
		 * not have been selected as an output name.
		 *
		 * If filename has a SHA1, and either:
		 *
		 * 1. we don't have a SHA1 for the new download (the `sha1' parameter)
		 * 2. we have a SHA1 but it differs
		 *
		 * then the file is "dead": we cannot use it.
		 *
		 * Likewise, if the trailer bears a file ID that conflicts with
		 * one of our currently managed files, we cannot use it.
		 */

		if (NULL != fi->sha1 && (NULL == sha1 || !sha1_eq(sha1, fi->sha1))) {
			g_warning("found DEAD file \"%s\" bearing SHA1 %s",
				pathname, sha1_base32(fi->sha1));

			fi_rename_dead(fi, pathname);
			fi_free(fi);
			fi = NULL;
		} else if (hikset_contains(fi_by_guid, fi->guid)) {
			g_warning("found DEAD file \"%s\" with conflicting ID %s",
				pathname, guid_hex_str(fi->guid));

			fi_rename_dead(fi, pathname);
			fi_free(fi);
			fi = NULL;
		} else if (fi->size < size) {
			/*
			 * Existing file is smaller than the total size of this file.
			 * Trust the larger size, because it's the only sane thing to do.
			 * NB: if we have a SHA1, we know it's matching at this point.
			 */

			g_warning("found existing file \"%s\" size=%s, increasing to %s",
				pathname, filesize_to_string(fi->size),
				filesize_to_string2(size));

			fi_resize(fi, size);
		}
	}

	/*
	 * If we don't have a `fi', then it is a new file.
	 *
	 * Potential problem situations:
	 *
	 *	- File exists, but we have no file_info struct for it.
	 * => Assume the file is complete up to filesize bytes.
	 *
	 *	- File with same name as another, but with a different size.
	 * => We have no way to detect it, sorry.  All new files should have a
	 *    metainfo trailer anyway, so we'll handle it above the next time.
	 */

	if (NULL == fi) {
		fi = file_info_create(filepath_basename(pathname), path,
				size, sha1, file_size_known);

		if (NULL == fi)
			goto finish;

		fi_alias(fi, file, FALSE);
	}

	file_info_hash_insert(fi);

	/*
	 * Now that the fileinfo has been inserted in the proper hash table,
	 * we can let the DHT publisher know about it.  Partial files will not
	 * be published when PFSP is disabled, but since that can happen at
	 * runtime, it is up to the publisher to check.
	 */

	if (can_publish_partial_sha1 && fi->sha1 != NULL) {
		publisher_add(fi->sha1);
	}

finish:
	atom_str_free_null(&pathname);
	G_FREE_NULL(to_free);

	return fi;
}

/**
 * @returns a pointer to the file info struct if we have a file
 * identical to the given properties in the download queue already,
 * and NULL otherwise.
 */
fileinfo_t *
file_info_has_identical(const struct sha1 *sha1, filesize_t size)
{
	fileinfo_t *fi;

	fi = sha1 ? file_info_by_sha1(sha1) : NULL;
	if (
		fi &&
		(fi->size == size || !fi->file_size_known) &&
		!(fi->flags & (FI_F_TRANSIENT | FI_F_SEEDING | FI_F_STRIPPED))
	) {
		return fi;
	}
	return NULL;
}

/**
 * Set or clear the discard state for a fileinfo.
 */
void
file_info_set_discard(fileinfo_t *fi, bool state)
{
	file_info_check(fi);

	if (state)
		fi->flags |= FI_F_DISCARD;
	else
		fi->flags &= ~FI_F_DISCARD;
}

/**
 * Go through the chunk list and merge adjacent chunks that share the
 * same status and download. Keeps the chunk list short and tidy.
 */
void
file_info_merge_adjacent(fileinfo_t *fi)
{
	slink_t *sl, *next;
	struct dl_file_chunk *fc1, *fc2;
	filesize_t done;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	done = 0;
	fc2 = NULL;

	for (sl = eslist_first(&fi->chunklist); sl != NULL; sl = next) {
		fc1 = fc2;					/* fc1 = previous chunk in list */
		fc2 = eslist_data(&fi->chunklist, sl);	/* fc2 = current chunk */
		next = eslist_next(sl);

		if (fc2->download != NULL)
			download_check(fc2->download);

		if (DL_CHUNK_DONE == fc2->status) {
			fc2->download = NULL;			/* Done, no longer reserved */
			done += fc2->to - fc2->from;
		}

		if (NULL == fc1)
			continue;

		g_assert(fc1->to == fc2->from);

		/*
		 * Never merge adjacent busy chunks: they correspond to reserved
		 * parts of the file that will be served by different HTTP requests.
		 */

		if (fc1->status == fc2->status && DL_CHUNK_BUSY != fc2->status) {
			void *removed;

			fc1->to = fc2->to;
			removed = eslist_remove_after(&fi->chunklist, fc1);
			g_assert(removed == fc2);
			dl_file_chunk_free(&fc2);
			fc2 = fc1;					/* new current chunk */
		}
	}

	/*
	 * When file size is unknown, there may be no chunklist.
	 */

	if (0 != eslist_count(&fi->chunklist))
		fi->done = done;

	g_assert(file_info_check_chunklist(fi, TRUE));
}

/**
 * Signals that the file size became suddenly unknown.
 *
 * This happens when we are receiving data past what we thought would be
 * the end of the file.
 */
void
file_info_size_unknown(fileinfo_t *fi)
{
	file_info_check(fi);
	g_assert(fi->file_size_known);

	if (0 == (fi->flags & FI_F_TRANSIENT)) {
		file_info_hash_remove_name_size(fi);
		fi->dirty = TRUE;
		fileinfo_dirty = TRUE;
	}

	fi->file_size_known = FALSE;
	fi_event_trigger(fi, EV_FI_INFO_CHANGED);

}

/**
 * Signals that file size became known suddenly.
 *
 * The download becomes the owner of the "busy" part between what we
 * have done and the end of the file.
 */
void
file_info_size_known(struct download *d, filesize_t size)
{
	fileinfo_t *fi;

	download_check(d);

	fi = d->file_info;
	file_info_check(fi);

	g_assert(!fi->file_size_known);

	/*
	 * Mark everything we have so far as done.
	 */

	if (fi->done) {
		struct dl_file_chunk *fc = eslist_head(&fi->chunklist);

		if (NULL == fc) {
			fc = dl_file_chunk_alloc();
			fc->from = 0;
			fc->to = fi->done;			/* Byte at that offset is excluded */
			fc->status = DL_CHUNK_DONE;

			eslist_append(&fi->chunklist, fc);
		} else {
			fc->to = fi->done;

			/*
			 * Remove subsequent chunks.
			 */

			while (NULL != eslist_next(&fc->lk)) {
				struct dl_file_chunk *fcn;

				fcn = eslist_remove_after(&fi->chunklist, fc);
				dl_file_chunk_free(&fcn);
			}
		}
	}

	/*
	 * If the file size is less than the amount we think we have,
	 * then ignore it and mark the whole file as done.
	 */

	if (size > fi->done) {
		struct dl_file_chunk *fc;

		fc = dl_file_chunk_alloc();
		fc->from = fi->done;
		fc->to = size;				/* Byte at that offset is excluded */
		fc->status = DL_CHUNK_BUSY;
		fc->download = d;
		eslist_append(&fi->chunklist, fc);
	}

	fi->file_size_known = TRUE;
	fi->use_swarming = TRUE;
	fi->size = MAX(size, fi->done);
	fi->dirty = TRUE;
	fileinfo_dirty = TRUE;

	if (0 == (FI_F_TRANSIENT & fi->flags)) {
		file_info_hash_insert_name_size(fi);
	}

	g_assert(file_info_check_chunklist(fi, TRUE));

	file_info_changed(fi);
}

/**
 * Marks a chunk of the file with given status.
 * The bytes range from `from' (included) to `to' (excluded).
 *
 * When not marking the chunk as EMPTY, the range is linked to
 * the supplied download `d' so we know who "owns" it currently.
 */
void
file_info_update(const struct download *d, filesize_t from, filesize_t to,
		enum dl_chunk_status status)
{
	struct dl_file_chunk *fc, *nfc, *prevfc;
	slink_t *sl;
	fileinfo_t *fi;
	bool found = FALSE;
	int n, againcount = 0;
	bool need_merging;
	const struct download *newval;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(fi->refcount > 0);
	g_assert(from < to);

	switch (status) {
	case DL_CHUNK_DONE:
		need_merging = FALSE;
		newval = d;
		goto status_ok;
	case DL_CHUNK_BUSY:
		need_merging = TRUE;
		newval = d;
		g_assert(fi->lifecount > 0);
		goto status_ok;
	case DL_CHUNK_EMPTY:
		need_merging = TRUE;
		newval = NULL;
		goto status_ok;
	}
	g_assert_not_reached();

status_ok:

	/*
	 * If file size is not known yet, the chunk list could be empty.
	 * Simply update the downloaded amount if the chunk is marked as done.
	 */

	if (!fi->file_size_known && 0 == eslist_count(&fi->chunklist)) {
		g_assert(!fi->use_swarming);

		if (status == DL_CHUNK_DONE) {
			g_assert(from == fi->done);		/* Downloading continuously */
			fi->done += to - from;
		}

		goto done;
	}

	g_assert(file_info_check_chunklist(fi, TRUE));

	fi->stamp = tm_time();

	if (DL_CHUNK_DONE == status) {
		fi->modified = fi->stamp;
		fi->dirty = TRUE;
	}

again:

	/* I think the algorithm is safe now, but hey... */
	if (++againcount > 10) {
		g_error("%s(%s, %s, %d) is looping for \"%s\"! Man battle stations!",
			G_STRFUNC, filesize_to_string(from), filesize_to_string2(to),
			status, d->file_name);
		return;
	}

	/*
	 * Update fi->done, accurately.
	 *
	 * We don't blindly update fi->done with (to - from) when DL_CHUNK_DONE
	 * because we may be writing data to an already "done" chunk, when a
	 * previous chunk bumps into a done one.
	 *		--RAM, 04/11/2002
	 */

	for (
		n = 0, prevfc = NULL, sl = eslist_first(&fi->chunklist);
		sl != NULL;
		n++, prevfc = fc, sl = eslist_next(sl)
	) {
		fc = eslist_data(&fi->chunklist, sl);

		dl_file_chunk_check(fc);

		if (fc->to <= from) continue;
		if (fc->from >= to) break;

		if (fc->from == from && fc->to == to) {

			if (prevfc && prevfc->status == status)
				need_merging = TRUE;
			else if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;		/* Writing to completed chunk! */

			if (DL_CHUNK_DONE == status)
				fi->done += to - from;
			fc->status = status;
			fc->download = newval;
			found = TRUE;
			g_assert(file_info_check_chunklist(fi, TRUE));
			break;

		} else if (fc->from == from && fc->to < to) {

			if (prevfc && prevfc->status == status)
				need_merging = TRUE;
			else if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;		/* Writing to completed chunk! */

			if (DL_CHUNK_DONE == status)
				fi->done += fc->to - from;
			fc->status = status;
			fc->download = newval;
			from = fc->to;
			g_assert(file_info_check_chunklist(fi, TRUE));
			continue;

		} else if (fc->from == from && fc->to > to) {

			if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;		/* Writing to completed chunk! */

			if (DL_CHUNK_DONE == status)
				fi->done += to - from;

			if (
				DL_CHUNK_DONE == status &&
				NULL != prevfc &&
				prevfc->status == status
			) {
				g_assert(prevfc->to == fc->from);
				prevfc->to = to;
				fc->from = to;
				g_assert(file_info_check_chunklist(fi, TRUE));
			} else {
				nfc = dl_file_chunk_alloc();
				nfc->from = to;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;

				fc->to = to;
				fc->status = status;
				fc->download = newval;
				eslist_insert_after(&fi->chunklist, fc, nfc);
				g_assert(file_info_check_chunklist(fi, TRUE));
			}

			found = TRUE;
			break;

		} else if (fc->from < from && fc->to >= to) {

			/*
			 * New chunk [from, to] lies within ]fc->from, fc->to].
			 */

			if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;

			if (DL_CHUNK_DONE == status)
				fi->done += to - from;

			if (fc->to > to) {
				nfc = dl_file_chunk_alloc();
				nfc->from = to;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;
				eslist_insert_after(&fi->chunklist, fc, nfc);

				if (DL_CHUNK_BUSY == nfc->status) {
					/*
					 * Reserved chunk being aggressively stolen, hence its
					 * upper-part ]to, fc->to] cannot be linearily downloaded.
					 * Make it free so that the source owning the original
					 * chunk is not suddenly seen as reserving two chunks!
					 */
					nfc->status = DL_CHUNK_EMPTY;
					nfc->download = NULL;
				}
			}

			nfc = dl_file_chunk_alloc();
			nfc->from = from;
			nfc->to = to;
			nfc->status = status;
			nfc->download = newval;
			eslist_insert_after(&fi->chunklist, fc, nfc);

			fc->to = from;

			found = TRUE;
			g_assert(file_info_check_chunklist(fi, TRUE));
			break;

		} else if (fc->from < from && fc->to < to) {

			filesize_t tmp;

			if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;

			if (DL_CHUNK_DONE == status)
				fi->done += fc->to - from;

			nfc = dl_file_chunk_alloc();
			nfc->from = from;
			nfc->to = fc->to;
			nfc->status = status;
			nfc->download = newval;
			eslist_insert_after(&fi->chunklist, fc, nfc);

			tmp = fc->to;
			fc->to = from;
			from = tmp;
			g_assert(file_info_check_chunklist(fi, TRUE));
			goto again;
		}
	}

	if (!found) {
		/* Should never happen. */
		g_critical("%s(): didn't find matching chunk for <%s-%s> (%u) "
			"for \"%s\" (%s%s bytes)",
			G_STRFUNC, filesize_to_string(from), filesize_to_string2(to),
			status, fi->pathname,
			fi->file_size_known ? "" : "unknown size, currently ",
			filesize_to_string3(fi->size));

		ESLIST_FOREACH(&fi->chunklist, sl) {
			fc = eslist_data(&fi->chunklist, sl);
			g_warning("... %s %s %u", filesize_to_string(fc->from),
				filesize_to_string2(fc->to), fc->status);
		}
	}

	if (need_merging)
		file_info_merge_adjacent(fi);		/* Also updates fi->done */

	g_assert(file_info_check_chunklist(fi, TRUE));

	/*
	 * When status is DL_CHUNK_DONE, we're coming from an "active" download,
	 * i.e. we are writing to it, therefore we can reuse its file descriptor.
	 */

	if (fi->flags & FI_F_TRANSIENT)
		goto done;

	if (fi->dirty) {
		file_info_store_binary(d->file_info, FALSE);
	}

done:
	file_info_changed(fi);
}

/**
 * Go through all chunks that belong to the download,
 * and unmark them as busy.
 *
 * If `lifecount' is TRUE, the download is still counted as being "alive",
 * and this is only used for assertions.
 */
void
file_info_clear_download(struct download *d, bool lifecount)
{
	struct dl_file_chunk *fc;
	fileinfo_t *fi;
	int busy = 0;		/**< For assertions only */
	int pipelined = 0;	/**< For assertions only */

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);

		if (DL_CHUNK_BUSY == fc->status) {
			busy++;
			g_assert(fc->download != NULL);
			download_check(fc->download);
			if (download_pipelining(fc->download))
				pipelined++;
		}
		if (fc->download == d) {
		    fc->download = NULL;
		    if (DL_CHUNK_BUSY == fc->status)
				fc->status = DL_CHUNK_EMPTY;
		}
	}
	file_info_merge_adjacent(fi);

	busy -= pipelined;
	g_assert(fi->lifecount >= (lifecount ? busy : (busy - 1)));

	/*
	 * No need to flush data to disk, those are transient
	 * changes. However, we do need to trigger a status change,
	 * because other parts of gtkg, i.e. the visual progress view,
	 * needs to know about them.
	 */
    fi_event_trigger(fi, EV_FI_STATUS_CHANGED_TRANSIENT);
}

/**
 * Reset all chunks to EMPTY, clear computed SHA1 if any.
 */
void
file_info_reset(fileinfo_t *fi)
{
	struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	atom_sha1_free_null(&fi->cha1);

	/* File possibly shared */
	file_info_upload_stop(fi, N_("File info being reset"));

	fi->flags &= ~(FI_F_STRIPPED | FI_F_UNLINKED);

restart:
	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
 		struct download *d;

		dl_file_chunk_check(fc);
		d = deconstify_pointer(fc->download);
		if (d) {
			download_check(d);

			if (DOWNLOAD_IS_RUNNING(d)) {
				download_queue(d, "Requeued due to file removal");
				g_assert(NULL == fc->download);
				goto restart;	/* Because file_info_clear_download() called */
			}
		}
	}

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);
		g_assert(NULL == fc->download);
		fc->status = DL_CHUNK_EMPTY;
	}

	file_info_merge_adjacent(fi);
	fileinfo_dirty = TRUE;
}

/**
 * @returns DONE if the range requested is marked as complete,
 * or BUSY if not. Used to determine if we can do overlap
 * checking.
 */
enum dl_chunk_status
file_info_chunk_status(fileinfo_t *fi, filesize_t from, filesize_t to)
{
	const struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);

		if (from >= fc->from && to <= fc->to)
			return fc->status;
	}

	/*
	 * Ending up here will normally mean that the tested range falls over
	 * multiple chunks in the list. In that case, chances are that it's
	 * not complete, and that's our assumption...
	 */

	if (GNET_PROPERTY(fileinfo_debug)) {
		g_carp("chunk [%s, %s] not found in one piece, assuming range is BUSY",
			filesize_to_string(from), filesize_to_string2(to));
	}

	return DL_CHUNK_BUSY;
}

/**
 * Change ownership of first BUSY chunk intersecting with the specified
 * segment to the specified download, clearing all other segments bearing
 * the old owner.
 */
void
file_info_new_chunk_owner(const struct download *d,
	filesize_t from, filesize_t to)
{
	fileinfo_t *fi;
	const struct download *old = NULL;
	const slink_t *sl;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH(&fi->chunklist, sl) {
		struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);

		dl_file_chunk_check(fc);

		/*
		 * We're looking for the first busy chunk intersecting with [from, to],
		 * which happens when one of the segment bounds lies within the chunk.
		 */

		if (DL_CHUNK_BUSY != fc->status)
			continue;

		if (
			(from >= fc->from && from < fc->to) ||
			(to >= fc->from && to < fc->to)
		) {
			g_assert(fc->download != NULL);
			download_check(fc->download);
			g_assert(fc->download != d);

			old = fc->download;
			fc->download = d;
			break;
		}
	}

	if (old != NULL) {
		for (sl = eslist_next(sl); sl != NULL; sl = eslist_next(sl)) {
			struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);

			dl_file_chunk_check(fc);

			if (DL_CHUNK_BUSY == fc->status && fc->download == old) {
				fc->status = DL_CHUNK_EMPTY;
				fc->download = NULL;
			}
		}
	}
}

/**
 * @returns the status (EMPTY, BUSY or DONE) of the byte requested.
 * Used to detect if a download is crashing with another.
 */
enum dl_chunk_status
file_info_pos_status(fileinfo_t *fi, filesize_t pos)
{
	const struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);
		if (pos >= fc->from && pos < fc->to)
			return fc->status;
	}

	if (pos > fi->size) {
		g_warning("%s(): unreachable position %s in %s-byte file \"%s\"",
			G_STRFUNC, filesize_to_string(pos),
			filesize_to_string2(fi->size), fi->pathname);
	}

	return DL_CHUNK_DONE;
}

/**
 * This routine is called each time we start a new download, before
 * making the request to the remote server. If we detect that the
 * file is "gone", then it means the user manually deleted the file.
 * In that case, we need to reset all the chunks and mark the whole
 * thing as being EMPTY.
 * 		--RAM, 21/08/2002.
 */
static void
fi_check_file(fileinfo_t *fi)
{
	filestat_t buf;

	file_info_check(fi);
	g_assert(fi->done);			/* Or file will not exist */

	/*
	 * File should exist since fi->done > 0, and it was not completed.
	 *
	 * Of course, transient entries do not get a valid path so they must
	 * be excluded from this check.
	 */

	if (
		!(fi->flags & FI_F_TRANSIENT) &&
		stat(fi->pathname, &buf) && ENOENT == errno
	) {
		g_warning("file %s removed, resetting swarming", fi->pathname);
		file_info_reset(fi);
	}
}

/**
 * Count the amount of BUSY chunks attached to a given download.
 */
static int
fi_busy_count(fileinfo_t *fi, const struct download *d)
{
	const struct dl_file_chunk *fc;
	int count = 0;
	int pipelined = 0;

	download_check(d);
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);
		if (fc->download != NULL) {
			download_check(d);
			if (fc->download == d && DL_CHUNK_BUSY == fc->status) {
				count++;
				if (download_pipelining(d))
					pipelined++;
			}
		}
	}

	g_assert(fi->lifecount >= (count - pipelined));

	return count;
}

/**
 * Compares two offered ranges so that two ranges are equal when they overlap.
 */
static int
fi_chunk_overlap_cmp(const void *a, const void *b)
{
	const struct dl_file_chunk *ca = a, *cb = b;

	if (ca->to <= cb->from)			/* `to' is NOT part of the chunk range */
		return -1;

	if (cb->to <= ca->from)
		return +1;

	return 0;		/* Overlapping chunks are equal */
}

/**
 * Select a chunk randomly among the rarest chunks offered on the network.
 *
 * If no download source is provided, then we assume we can pick any missing
 * chunk. Otherwise, we make sure to select a chunk that is available from
 * that source.
 *
 * If the first chunk is not completed or not at least "pfsp_first_chunk" bytes
 * long, returns the first chunk.
 *
 * @param fi		the fileinfo where we have to pick a chunk from
 * @param d			the possibly partial download source (may be NULL)
 * @param size		the targeted chunk size
 *
 * @return the picked chunk among the fileinfo's chunklist.
 */
static const struct dl_file_chunk *
fi_pick_rarest_chunk(fileinfo_t *fi, const download_t *d, filesize_t size)
{
	rbtree_t *missing;
	http_rangeset_t *offered;
	const struct dl_file_chunk *fc;
	const struct dl_file_chunk *first, *candidate = NULL;
	uint32 rarest_count = 0;
	const struct dl_avail_chunk *rarest = NULL, *fa;

	file_info_check(fi);
	g_assert(0 != eslist_count(&fi->chunklist));

	first = eslist_head(&fi->chunklist);		/* First chunk */
	dl_file_chunk_check(first);

	if (!fi->file_size_known)
		return first;

	if (GNET_PROPERTY(pfsp_first_chunk) > 0) {
		/*
		 * See whether chunks up to ``pfsp_first_chunk'' bytes are free.
		 */

		ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
			if (fc->from >= GNET_PROPERTY(pfsp_first_chunk))
				break;

			if (DL_CHUNK_EMPTY == fc->status) {
				if (GNET_PROPERTY(download_debug)) {
					g_debug("%s(): less than %u bytes, using first chunk",
						G_STRFUNC, GNET_PROPERTY(pfsp_first_chunk));
				}

				candidate = first;
				goto done;
			}
		}
	}

	/*
	 * The `missing' red-black tree contains the file chunks that are still
	 * empty and need to be downloaded.
	 *
	 * The `offered' set contains the HTTP ranges offered by the source,
	 * if any given.  If NULL, it means the source covers the whole file.
	 */

	missing = rbtree_create(fi_chunk_overlap_cmp);
	offered = NULL == d ? NULL : d->ranges;

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);

		if (DL_CHUNK_EMPTY == fc->status) {
			rbtree_insert(missing, fc);
		}
	}

	/*
	 * Find the first missing chunk that is also offered, starting with the
	 * rarest available chunk: the fi->available list is sorted by increasing
	 * source count.
	 */

	ESLIST_FOREACH_DATA(&fi->available, fa) {
		struct dl_file_chunk *dfc;
		struct dl_file_chunk crange;

		dl_avail_chunk_check(fa);

		/*
		 * If we have already found a candidate and this chunk has more
		 * sources, we're done.
		 */

		if (rarest != NULL && fa->sources > rarest->sources)
			break;

		if (
			offered != NULL &&
			!http_rangeset_contains(offered, fa->from, fa->to - 1)
		)
			continue;		/* Range not offered */

		crange.from = fa->from;
		crange.to = fa->to;

		dfc = rbtree_lookup(missing, &crange);

		if (dfc != NULL) {
			/* Rare range overlaps with missing range */

			if (
				GNET_PROPERTY(fileinfo_debug) > 2 ||
				GNET_PROPERTY(download_debug) > 1
			) {
				g_debug("%s(): possible rarest candidate #%u for \"%s\" is "
					"[%s, %s] (%zu source%s)",
					G_STRFUNC, rarest_count + 1, fi->pathname,
					filesize_to_string(fa->from), filesize_to_string2(fa->to),
					fa->sources, plural(fa->sources));
			}

			/*
			 * If this is not the first rarest candidate we see, then randomly
			 * select it, maybe.
			 *
			 * The second rarest chunk has exactly 1/2 chance to supersede
			 * the candidate, the third has 1/3 chance, etc...  This allows
			 * us to randomly select a candidate without knowing beforehand how
			 * many we will find, whilst retaining an equal probability for
			 * all the chunks to be selected.
			 */

			g_assert(dfc->download == NULL);	/* Chunk is empty */

			if (++rarest_count > 1 && 0 != random_value(rarest_count - 1))
				continue;

			rarest = fa;
			candidate = dfc;

			/*
			 * If we're not a PFSP server, we retain the first candidate we see.
			 */

			if (!GNET_PROPERTY(pfsp_server))
				break;
		}
	}

	/*
	 * If we have a candidate, then randomly pick the starting point in the
	 * range to maximize the dispersion if we are a PFSP server and if the
	 * chunk is larger than the targeted size.
	 */

	if (rarest != NULL) {
		struct dl_file_chunk *dfc = deconstify_pointer(candidate);
		struct dl_file_chunk *nfc;
		filesize_t start, end;

		g_assert(candidate != NULL);

		/*
		 * [start, end] is the intersection of the rarest chunk we selected
		 * with the candidate chunk (missing part to be downloaded still).
		 */

		start = MAX(rarest->from, candidate->from);
		end = MIN(rarest->to, candidate->to);

		if (
			GNET_PROPERTY(fileinfo_debug) > 2 ||
			GNET_PROPERTY(download_debug) > 1
		) {
			g_debug("%s(): rarest intersection chunk for \"%s\" is "
				"[%s, %s] (%zu source%s)",
				G_STRFUNC, fi->pathname,
				filesize_to_string(start), filesize_to_string2(end),
				rarest->sources, plural(rarest->sources));
		}

		g_assert(start < end);		/* Because the two MUST overlap */

		if (end - start > size && GNET_PROPERTY(pfsp_server)) {
			filesize_t offset, length;

			length = end - start;
			length -= size;
			offset = start + get_random_file_offset(length);
			offset &= ~FI_OFFSET_ALIGNMASK;		/* Align on natural boundary */
			offset = MAX(offset, start);

			g_assert(offset >= candidate->from && offset <= candidate->to);

			start = offset;		/* Randomly selected starting point */

			if (
				GNET_PROPERTY(fileinfo_debug) > 2 ||
				GNET_PROPERTY(download_debug) > 1
			) {
				g_debug("%s(): randomly selected starting point is %s",
					G_STRFUNC, filesize_to_string(start));
			}
		}

		if (start > dfc->from && start < dfc->to) {
			/*
			 * dfc was [from, to[.  It becomes [from, start[.
			 * nfc is [start, to[ and is inserted after fc.
			 */

			nfc = dl_file_chunk_alloc();
			nfc->from = start;
			nfc->to = dfc->to;
			nfc->status = dfc->status;
			dfc->to = start;

			eslist_insert_after(&fi->chunklist, dfc, nfc);
			candidate = nfc;

			if (
				GNET_PROPERTY(fileinfo_debug) > 2 ||
				GNET_PROPERTY(download_debug) > 1
			) {
				g_debug("%s(): selected chunk is [%s, %s]",
					G_STRFUNC, filesize_to_string(nfc->from),
					filesize_to_string2(nfc->to));
			}
		}
	}

	/*
	 * If we found no candidate, use the first chunk since we have to
	 * return something that will be a valid lookup starting point.
	 */

	if (NULL == candidate)
		candidate = first;

	rbtree_free_null(&missing);

done:
	if (GNET_PROPERTY(fileinfo_debug) || GNET_PROPERTY(download_debug)) {
		g_debug("%s(): returning [%s, %s] (%u) for \"%s\"",
			G_STRFUNC, filesize_to_string(candidate->from),
			filesize_to_string2(candidate->to), candidate->status,
			fi->pathname);
	}

	return candidate;
}

/**
 * Select a chunk randomly.
 *
 * If the first chunk is not completed or not at least "pfsp_first_chunk" bytes
 * long, returns the first chunk.
 *
 * We also strive to get the latest "pfsp_last_chunk" bytes of the file as
 * well, since some file formats store important information at the tail of
 * the file as well, so we can select some of the latest chunks.
 */
static const struct dl_file_chunk *
fi_pick_chunk(fileinfo_t *fi)
{
	filesize_t offset = 0;
	slink_t *sl;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	if (GNET_PROPERTY(pfsp_first_chunk) > 0) {
		const struct dl_file_chunk *fc;

		/*
		 * Check whether first chunks cover at least "pfsp_first_chunk" bytes
		 * long.  If not, return that first chunk.
		 */

		ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
			dl_file_chunk_check(fc);

			if (fc->from >= GNET_PROPERTY(pfsp_first_chunk))
				break;		/* Already past the first "pfsp_first_chunk" bytes */

			if (DL_CHUNK_EMPTY == fc->status)
				return fc;
		}
	}

	if (GNET_PROPERTY(pfsp_last_chunk) > 0) {
		const struct dl_file_chunk *fc;
		filesize_t last_chunk_offset;

		/*
		 * Scan for the first gap within the last "pfsp_last_chunk" bytes
		 * and set "offset" to the start of it, to download the trailing chunk
		 * if available.
		 */

		last_chunk_offset = fi->size > GNET_PROPERTY(pfsp_last_chunk)
			? fi->size - GNET_PROPERTY(pfsp_last_chunk)
			: 0;

		ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
			dl_file_chunk_check(fc);

			if (DL_CHUNK_DONE == fc->status)
				continue;

			if (fc->from < last_chunk_offset && fc->to <= last_chunk_offset)
				continue;

			offset = fc->from < last_chunk_offset
				? last_chunk_offset
				: fc->from;
			break;
		}
	}

	/*
	 * Only choose a random offset if the default value of "0" was not
	 * forced to something else above.
	 */

	if (0 == offset) {
		offset = get_random_file_offset(fi->size);
		offset &= ~FI_OFFSET_ALIGNMASK;		/* Align on natural boundary */
	}

	/*
	 * Pick the first chunk whose start is after the offset.
	 */

	ESLIST_FOREACH(&fi->chunklist, sl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);

		dl_file_chunk_check(fc);

		if (fc->from >= offset)
			return fc;

		/*
		 * If offset lies within a free chunk, it will get split below.
		 * So exit without selecting anything yet.
		 */

		if (DL_CHUNK_EMPTY == fc->status && fc->to - 1 > offset)
			break;
	}

	/*
	 * If we have not picked anything, it means we have encountered a big chunk
	 * and the selected offset lies within that chunk.
	 * Be smarter and break-up any free chunk into two at the selected offset.
	 */

	ESLIST_FOREACH(&fi->chunklist, sl) {
		struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);

		dl_file_chunk_check(fc);

		if (DL_CHUNK_EMPTY == fc->status && fc->to - 1 > offset) {
			struct dl_file_chunk *nfc;

			g_assert(fc->from < offset);	/* Or we'd have cloned above */
			g_assert(fc->download == NULL);	/* Chunk is empty */

			/*
			 * fc was [from, to[.  It becomes [from, offset[.
			 * nfc is [offset, to[ and is inserted after fc.
			 */

			nfc = dl_file_chunk_alloc();
			nfc->from = offset;
			nfc->to = fc->to;
			nfc->status = DL_CHUNK_EMPTY;
			fc->to = nfc->from;

			eslist_insert_after(&fi->chunklist, fc, nfc);
			return nfc;
		}
	}

	g_assert(file_info_check_chunklist(fi, TRUE));

	/*
	 * If still no luck, never mind.  Use first chunk.
	 */

	return eslist_head(&fi->chunklist);
}

/**
 * Compute chunksize to be used for the current request.
 */
static filesize_t
fi_chunksize(fileinfo_t *fi)
{
	filesize_t chunksize;
	int src_count;
	uint32 max;

	file_info_check(fi);

	/*
	 * Chunk size is estimated based on the amount of potential concurrent
	 * downloads we can face (roughly given by the amount of queued sources
	 * plus the amount of active ones).  We also consider the amount of data
	 * that still needs to be fetched, since sources will compete for that.
	 *
	 * The aim is to reduce the chunksize as we progress, to avoid turning
	 * on aggressive swarming if possible since that forces us to close the
	 * connection to the source (and therefore lose the slot, at best, if
	 * the source is not firewalled) whenever we bump into another active
	 * chunk.
	 *		--RAM, 2005-09-27
	 */

	src_count = fi_alive_count(fi);
	src_count = MAX(1, src_count);
	chunksize = (fi->size - fi->done) / src_count;

	/*
	 * Finally trim the computed value so it falls between the boundaries
	 * they want to enforce.
	 *
	 * Note than when pipelining is allowed, we always use the pipelining
	 * maximum, even if the requested chunk will not actually be pipelined.
	 * Because latency is almost reduced to zero, it pays to have smaller
	 * pipelined chunks so that more download mesh exchanges can occur and
	 * we can learn about new sources more quickly.
	 */

	if (chunksize < GNET_PROPERTY(dl_minchunksize))
		chunksize = GNET_PROPERTY(dl_minchunksize);

	max = GNET_PROPERTY(enable_http_pipelining)
		? GNET_PROPERTY(dl_pipeline_maxchunksize)
		: GNET_PROPERTY(dl_maxchunksize);

	chunksize = MIN(chunksize, max);

	return chunksize;
}

/**
 * Compute how much the source covers the missing chunks we still have which
 * are not busy.  This is expressed as a percentage of those missing chunks.
 */
static double
fi_missing_coverage(const struct download *d)
{
	http_rangeset_t *ranges;
	fileinfo_t *fi;
	filesize_t missing_size = 0;
	filesize_t covered_size = 0;
	const struct dl_file_chunk *fc;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));
	g_assert(fi->lifecount > 0);

	/*
	 * See update_available_ranges() to understand why we can still get a
	 * non-zero download_ranges_size() despite download_ranges() returning NULL.
	 *
	 * We asssume the server has the whole file if there are no ranges and
	 * a zero ranges_size, as we have not seen any header indicating that the
	 * file would be partial.
	 */

	ranges = download_ranges(d);
	if (ranges == NULL) {
		filesize_t available = download_ranges_size(d);

		return available ? (available * 1.0) / (fi->size * 1.0) : 1.0;
	}

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		const http_range_t *r;

		if (DL_CHUNK_EMPTY != fc->status)
			continue;

		missing_size += fc->to - fc->from;

		/*
		 * Look whether this empty chunk intersects with one of the
		 * available ranges.
		 *
		 * NB: Contrary to fi chunks, the upper boundary of the range
		 * (r->end) is part of the range.
		 */

		r = http_rangeset_lookup_first(ranges, fc->from, fc->to - 1);

		while (r != NULL) {
			filesize_t start, end;

			/*
			 * Compute the intersection between range and chunk.
			 */

			start = MAX(r->start, fc->from);
			end = r->end + 1;
			end = MIN(end, fc->to);

			if (start >= end)
				break;					/* No longer intersecting */

			covered_size += end - start;
			r = http_range_next(ranges, r);
		}
	}

	g_assert(covered_size <= missing_size);

	if (missing_size == 0)			/* Weird but... */
		return 1.0;					/* they cover the whole of nothing! */

	return (covered_size * 1.0) / (missing_size * 1.0);
}

/**
 * Find the largest busy chunk not already reserved by download.
 *
 * @return largest chunk found in the fileinfo, or NULL if there are no
 * busy chunks.
 */
static const struct dl_file_chunk *
fi_find_largest(const fileinfo_t *fi, const struct download *d)
{
	const struct dl_file_chunk *fc;
	const struct dl_file_chunk *largest = NULL;

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);

		if (DL_CHUNK_BUSY != fc->status)
			continue;

		/*
		 * When doing HTTP pipelining, we need to exclude chunks owned by
		 * the download we're searching chunks for to avoid self-competing!
		 * When not doing HTTP pipeling, there's no way a chunk can be
		 * reserved by the download so the check always works anyway.
		 */

		if (fc->download == d)
			continue;				/* Don't compete with yourself */

		if (
			largest == NULL ||
			(fc->to - fc->from) > (largest->to - largest->from)
		)
			largest = fc;
	}

	return largest;
}

/**
 * Find the largest busy chunk served by the host with the smallest uploading
 * rate.
 *
 * @return chunk found in the fileinfo, or NULL if there are no busy chunks.
 */
static const struct dl_file_chunk *
fi_find_slowest(const fileinfo_t *fi, const struct download *d)
{
	const struct dl_file_chunk *fc;
	const struct dl_file_chunk *slowest = NULL;
	uint slowest_speed_avg = MAX_INT_VAL(uint);

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		uint speed_avg;

		dl_file_chunk_check(fc);

		if (DL_CHUNK_BUSY != fc->status)
			continue;

		/*
		 * Avoid self-competing with our own chunks when doing HTTP pipelining.
		 * Otherwise, there cannot be any chunk belongin to this download
		 * anyway.
		 */

		if (fc->download == d)
			continue;				/* Don't compete with yourself */

		speed_avg = download_speed_avg(fc->download);

		if (
			slowest == NULL ||
			speed_avg < slowest_speed_avg ||
			(
				speed_avg == slowest_speed_avg &&
				(fc->to - fc->from) > (slowest->to - slowest->from)
			)
		) {
			slowest = fc;
			slowest_speed_avg = speed_avg;
		}
	}

	return slowest;
}

/**
 * Find the spot we could download at the tail of an already active chunk
 * to be aggressively completing the file ASAP.
 *
 * @param d		the download source we want to consider making a request to
 * @param busy	the amount of known busy chunks in the file
 * @param from	where the start of the possible chunk request will be written
 * @param to	where the end of the possible chunk request will be written
 * @param chunk	chosen original busy chunk
 *
 * @return TRUE if we were able to find a candidate, with `from' and `to'
 * being filled with the chunk we could be requesting.
 */
static bool
fi_find_aggressive_candidate(
	const struct download *d, uint busy, filesize_t *from, filesize_t *to,
	const struct dl_file_chunk **chunk)
{
	fileinfo_t *fi = d->file_info;
	const struct dl_file_chunk *fc;
	int starving;
	filesize_t minchunk;
	bool can_be_aggressive = FALSE;
	double missing_coverage;

	/*
	 * Compute minimum chunk size for splitting.  When we're told to
	 * be aggressive and we need to be, we don't really want to honour
	 * the dl_minchunksize setting!
	 *
	 * There are fi->lifecount active downloads (queued or running) for
	 * this file, and `busy' chunks.  The difference is the amount of
	 * starving downloads...
	 */

	starving = fi->lifecount - busy;	/* Starving downloads */
	minchunk = (fi->size - fi->done) / (0 == starving ? 1 : 2 * starving);
	minchunk = MIN(minchunk, GNET_PROPERTY(dl_minchunksize));
	minchunk = MAX(minchunk, FI_MIN_CHUNK_SPLIT);

	fc = fi_find_largest(fi, d);

	if (fc != NULL && fc->to - fc->from < minchunk)
		fc = NULL;

	/*
	 * Do not let a slow uploading server interrupt a chunk served by
	 * a faster server if the time it will take to complete the chunk is
	 * larger than what the currently serving host would perform alone!
	 *
	 * However, if the slower server covers 100% of the missing chunks we
	 * need, whereas the faster server does not have 100% of them, it would
	 * be a shame to lose the connection to this slower server.  So we
	 * take into account the missing chunk coverage rate as well.
	 */

	missing_coverage = fi_missing_coverage(d);

	if (fc) {
		double longest_missing_coverage;

		download_check(fc->download);
		longest_missing_coverage = fi_missing_coverage(fc->download);

		can_be_aggressive =
			0 == download_speed_avg(fc->download)
			|| missing_coverage > longest_missing_coverage
			|| (
				fabs(longest_missing_coverage - missing_coverage) < 1e-56 &&
				download_speed_avg(d) > download_speed_avg(fc->download)
			);

		if (GNET_PROPERTY(download_debug) > 1)
			g_debug("will %s be aggressive for \"%s\" given d/l speed "
				"of %s%u B/s for largest chunk owner (%s) and %u B/s for "
				"stealer, and a coverage of missing chunks of %.2f%% and "
				"%.2f%% respectively",
				can_be_aggressive ? "really" : "not",
				fi->pathname,
				download_is_stalled(fc->download) ? "stalling " : "",
				download_speed_avg(fc->download),
				download_host_info(fc->download),
				download_speed_avg(d),
				longest_missing_coverage * 100.0, missing_coverage * 100.0);
	}

	if (!can_be_aggressive && (fc = fi_find_slowest(fi, d))) {
		double slowest_missing_coverage;

		download_check(fc->download);
		slowest_missing_coverage = fi_missing_coverage(fc->download);

		/*
		 * We couldn't be aggressive with the largest chunk.
		 * Try to see if we're faster than the slowest serving host and have
		 * a larger coverage of the missing chunks.
		 */

		can_be_aggressive =
			missing_coverage >= slowest_missing_coverage
			&& download_speed_avg(d) > download_speed_avg(fc->download);

		if (can_be_aggressive && GNET_PROPERTY(download_debug) > 1)
			g_debug("will instead be aggressive for \"%s\" given d/l speed "
				"of %s%u B/s for slowest chunk owner (%s) and %u B/s for "
				"stealer, and a coverage of missing chunks of %.2f%% and "
				"%.2f%% respectively",
				fi->pathname,
				download_is_stalled(fc->download) ? "stalling " : "",
				download_speed_avg(fc->download),
				download_host_info(fc->download),
				download_speed_avg(d),
				slowest_missing_coverage * 100.0,
				missing_coverage * 100.0);
	}

	if (!can_be_aggressive)
		return FALSE;

	g_assert(fc->download != NULL && fc->download != d);

	if (fc->to - fc->from >= 2 * FI_MIN_CHUNK_SPLIT) {
		/* Start in the middle of the selected range */
		*from = (fc->from + fc->to - 1) / 2;
		*to = fc->to;		/* 'to' is NOT in the range */
	} else {
		/* Range too small, grab everything */
		*from = fc->from;
		*to = fc->to;
	}

	*chunk = fc;

	if (GNET_PROPERTY(download_debug) > 1)
		g_debug("aggressively requesting %s@%s [%lu, %lu] "
			"for \"%s\" using %s source from %s",
			filesize_to_string(*to - *from), short_size(*from, FALSE),
			(unsigned long) *from, (unsigned long) *to - 1,
			fi->pathname,
			d->ranges != NULL ? "partial" : "complete",
			download_host_info(d));

	return TRUE;
}

/**
 * Mark [from, to] as now being a chunk reserved by given download.
 * If ``chunk'' is non-NULL, then the [from, to] belongs to that chunk
 * and the interval is being stolen by another download (during the
 * aggressive swarming phase).
 *
 * The purpose of this routine is to surround the chunk reservation
 * with assertions, some of which are costly and only run at higher
 * debugging levels.
 */
static void
file_info_reserve(const struct download *d,
	filesize_t from, filesize_t to, const struct dl_file_chunk *chunk)
{
	fileinfo_t *fi = d->file_info;
	int busy = 0, old_busy = 0;
	const struct download *old_d = NULL;

	g_assert(to >= from);
	if (chunk != NULL) {
		g_assert(from >= chunk->from);
		g_assert(to <= chunk->to);
		g_assert(chunk->download != NULL);
		g_assert(chunk->download != d);
		g_assert(DL_CHUNK_BUSY == chunk->status);
		g_assert(chunk->download->file_info == d->file_info);
	}

	if (GNET_PROPERTY(fileinfo_debug) > 2) {
		busy = fi_busy_count(fi, d);
		if (chunk != NULL) {
			old_busy = fi_busy_count(fi, chunk->download);
			old_d = chunk->download;
			g_assert(old_busy >= 1);
		}
	}

	/*
	 * Reserving means creating a DL_CHUNK_BUSY chunk owned by ``d''.
	 */

	file_info_update(d, from, to, DL_CHUNK_BUSY);

	if (GNET_PROPERTY(fileinfo_debug) > 2) {
		int new_busy = fi_busy_count(fi, d);
		g_assert(busy + 1 == new_busy);
		g_assert(new_busy <= 1 + (download_pipelining(d) ? 1 : 0));
		if (chunk != NULL) {
			int updated_busy = fi_busy_count(fi, old_d);
			g_assert(updated_busy <= old_busy);
			g_assert(updated_busy >= old_busy - 1);
		}
	}

	g_assert(file_info_check_chunklist(d->file_info, TRUE));
}

/**
 * Finds a range to download, and stores it in *from and *to.
 *
 * If "aggressive" is off, it will return only ranges that are EMPTY.
 * If on, and no EMPTY ranges are available, it will grab a chunk out of the
 * longest BUSY chunk instead, and "compete" with the download that reserved it.
 *
 * @return DL_CHUNK_EMPTY if we reserved a chunk, DL_CHUNK_BUSY if we cannot
 * grab a chunk because they are all unavailable, or DL_CHUNK_DONE if we did
 * not select a chunk but the file is complete.
 */
enum dl_chunk_status
file_info_find_hole(const struct download *d, filesize_t *from, filesize_t *to)
{
	slink_t *sl;
	fileinfo_t *fi = d->file_info;
	filesize_t chunksize;
	unsigned busy = 0;
	unsigned pipelined = 0;
	int reserved;
	eclist_t cklist;
	const struct dl_file_chunk *chunk = NULL;

	file_info_check(fi);
	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);
	g_assert(file_info_check_chunklist(fi, TRUE));

	/*
	 * No reservation for `d' yet unless we're pipelining, in which
	 * case we must have exactly 1 already (the current running request),
	 * excepted in the case of aggressive swarming where parts of our chunk
	 * could have been stolen and completed already (in which case we'll
	 * have none)..
	 */

	reserved = fi_busy_count(fi, d);
	g_assert(reserved >= 0);
	g_assert(reserved <= (download_pipelining(d) ? 1 : 0));

	/*
	 * Ensure the file has not disappeared.
	 */

	if (fi->done) {
		if (fi->done == fi->size)
			return DL_CHUNK_DONE;

		fi_check_file(fi);
	}

	if (fi->size < d->file_size) {
		g_warning("fi->size=%s < d->file_size=%s for \"%s\"",
			filesize_to_string(fi->size), filesize_to_string2(d->file_size),
			fi->pathname);
	}

	g_assert(fi->lifecount > 0);

	/*
	 * If PFSP is enabled and we know of a small amount of sources,
	 * try to request a small chunk the first time, in order to help
	 * the download mesh to propagate: we need to advertise ourselves
	 * to others, so more will come and we get more alt-loc exchanges.
	 *
	 * We do that only the first time we reconnect to a source to force
	 * a rapid exchange of alt-locs in case the amount the other source
	 * knows is more that what can fit in the reply (hoping remote will
	 * perform a random selection among its known set).
	 *
	 *		--RAM, 2005-10-27
	 */

	chunksize = fi_chunksize(fi);

	if (
		GNET_PROPERTY(pfsp_server) && d->served_reqs == 0 &&
		fi_alive_count(fi) <= FI_LOW_SRC_COUNT		/* Not enough sources */
	) {
		/*
		 * If we have enough to share the file, we can reduce the chunksize.
		 * Otherwise, try to get the amount we miss first, to be able
		 * to advertise ourselves as soon as possible.
		 */

		if (fi->done >= GNET_PROPERTY(pfsp_minimum_filesize))
			chunksize = GNET_PROPERTY(dl_minchunksize);
		else {
			filesize_t missing;

			missing = GNET_PROPERTY(pfsp_minimum_filesize) - fi->done;
			chunksize = MAX(chunksize, missing);
			chunksize = MIN(chunksize, GNET_PROPERTY(dl_maxchunksize));
		}
	}

	/*
	 * If PFSP-server is enabled, we can serve partially downloaded files.
	 * Therefore, it is interesting to request chunks in random order, to
	 * avoid everyone having the same chunks should full sources disappear.
	 *		--RAM, 11/10/2003
	 *
	 * If we have some partial sources, use a more complex chunk picking
	 * algorithm to select the rarest chunks first.
	 *		--RAM, 2012-12-01
	 */

	if (eslist_count(&fi->available) > 1) {
		chunk = fi_pick_rarest_chunk(fi, NULL, chunksize);
	} else {
		chunk = GNET_PROPERTY(pfsp_server) ?
			fi_pick_chunk(fi) : eslist_head(&fi->chunklist);
	}

	/*
	 * Iteration is done using a "circular" list illusion, to be able to
	 * nicely iterate even if we don't start from the head.
	 */

	eclist_init(&cklist, &fi->chunklist, chunk);
	chunk = NULL;		/* Will be set if we pick a chunk aggressively */

	ECLIST_FOREACH(&cklist, sl) {
		const struct dl_file_chunk *fc = eclist_data(&cklist, sl);

		dl_file_chunk_check(fc);

		if (DL_CHUNK_EMPTY != fc->status) {
			if (DL_CHUNK_BUSY == fc->status) {
				g_assert(fc->download != NULL);
				download_check(fc->download);
				if (fc->download != d && download_pipelining(fc->download))
					pipelined++;
			}
			continue;
		}

		*from = fc->from;
		*to = fc->to;
		if ((fc->to - fc->from) > chunksize)
			*to = fc->from + chunksize;
		goto selected;
	}

	busy -= pipelined;
	g_assert(fi->lifecount > (int32) busy); /* Or we'd found a chunk before */

	if (GNET_PROPERTY(use_aggressive_swarming)) {
		filesize_t start, end;

		if (fi_find_aggressive_candidate(d, busy, &start, &end, &chunk)) {
			*from = start;
			*to = end;
			goto selected;
		}
	}

	/* No holes found. */

	return (fi->done == fi->size) ? DL_CHUNK_DONE : DL_CHUNK_BUSY;

selected:	/* Selected a hole to download */

	file_info_reserve(d, *from, *to, chunk);

	return DL_CHUNK_EMPTY;
}

/**
 * Find free chunk that also fully belongs to the `ranges' list.  If found,
 * the returned chunk is marked BUSY and linked to the download `d'.
 *
 * @returns TRUE if one was found, with `from' and `to' set, FALSE otherwise.
 *
 * @attention
 * NB: In accordance with other fileinfo semantics, `to' is NOT the last byte
 * of the range but one byte AFTER the end.
 */
bool
file_info_find_available_hole(
	const struct download *d, http_rangeset_t *ranges,
	filesize_t *from, filesize_t *to)
{
	slink_t *sl;
	fileinfo_t *fi;
	filesize_t chunksize = 0;
	eclist_t cklist;
	uint busy = 0;
	uint pipelined = 0;
	const struct dl_file_chunk *chunk = NULL;

	download_check(d);
	g_assert(ranges != NULL);

	fi = d->file_info;
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	/*
	 * Ensure the file has not disappeared.
	 */

	if (fi->done) {
		if (fi->done == fi->size)
			return FALSE;;

		fi_check_file(fi);
	}

	g_assert(fi->lifecount > 0);

	/*
	 * If PFSP-server is enabled, we can serve partially downloaded files.
	 * Therefore, it is interesting to request chunks in random order, to
	 * avoid everyone having the same chunks should full sources disappear.
	 *		--RAM, 11/10/2003
	 *
	 * If we have some partial sources, use a more complex chunk picking
	 * algorithm to select the rarest chunks first.
	 *		--RAM, 2012-12-01
	 */

	if (eslist_count(&fi->available) > 1) {
		chunksize = fi_chunksize(fi);
		chunk = fi_pick_rarest_chunk(fi, d, chunksize);
	} else {
		chunk = GNET_PROPERTY(pfsp_server) ?
			fi_pick_chunk(fi) : eslist_head(&fi->chunklist);
	}

	/*
	 * Iteration is done using a "circular" list illusion, to be able to
	 * nicely iterate even if we don't start from the head.
	 */

	eclist_init(&cklist, &fi->chunklist, chunk);
	chunk = NULL;		/* Will be set if we pick a chunk aggressively */

	ECLIST_FOREACH(&cklist, sl) {
		const struct dl_file_chunk *fc = eclist_data(&cklist, sl);
		const http_range_t *r;

		if (DL_CHUNK_EMPTY != fc->status) {
			if (DL_CHUNK_BUSY == fc->status) {
				busy++;		/* Will be used by aggresive code below */
				g_assert(fc->download != NULL);
				download_check(fc->download);
				if (download_pipelining(fc->download))
					pipelined++;
			}
			continue;
		}

		/*
		 * Look whether this empty chunk intersects with one of the
		 * available ranges.
		 *
		 * NB: Contrary to fi chunks, the upper boundary of the range
		 * (r->end) is part of the range.
		 */

		r = http_rangeset_lookup(ranges, fc->from, fc->to - 1);

		if (r != NULL) {
			filesize_t start, end;

			/*
			 * Intersect range and chunk, [start, end[ is the result.
			 */

			start = MAX(r->start, fc->from);
			end = r->end + 1;
			end = MIN(end, fc->to);

			g_assert(start < end);		/* Intersection is non-empty */

			*from = start;
			*to = end;
			goto found;
		}
	}

	busy -= pipelined;

	if (GNET_PROPERTY(use_aggressive_swarming)) {
		filesize_t start, end;

		if (fi_find_aggressive_candidate(d, busy, &start, &end, &chunk)) {
			const http_range_t *r;

			/*
			 * Look whether this candidate chunk is fully held in the
			 * available remote chunks.
			 *
			 * NB: contrary to fi chunks, the upper boundary of the range
			 * (r->end) is part of the range.
			 */

			r = http_rangeset_lookup(ranges, start, end - 1);

			if (
				r != NULL &&
				r->start <= start &&
				r->end >= end - 1
			) {
				/* Selected chunk is fully contained in remote range */
				*from = start;
				*to = end;
				goto selected;
			}
		}
	}

	return FALSE;

found:
	if (0 == chunksize)
		chunksize = fi_chunksize(fi);

	if ((*to - *from) > chunksize)
		*to = *from + chunksize;

	/* FALL THROUGH */

selected:
	file_info_reserve(d, *from, *to, chunk);

	return TRUE;
}

/**
 * Called when we add something to the dmesh.
 *
 * Add the corresponding file to the download list if we're swarming
 * on it.
 *
 * @param file_name	the remote file name (as in the GET query).
 * @param idx	the remote file index (as in the GET query).
 * @param addr	the remote servent address.
 * @param port	the remote servent port.
 * @param sha1	the SHA1 of the file.
 */
void
file_info_try_to_swarm_with(
	const char *file_name, const host_addr_t addr, uint16 port,
	const struct sha1 *sha1)
{
	fileinfo_t *fi;

	if (!can_swarm)				/* Downloads not initialized yet */
		return;

	fi = file_info_by_sha1(sha1);
	if (!fi)
		return;

	file_info_check(fi);
	download_auto_new(file_name ? file_name : filepath_basename(fi->pathname),
		fi->size,
		addr,
		port,
		&blank_guid,
		NULL,	/* hostname */
		sha1,
		NULL,	/* TTH */
		tm_time(),
		fi,
		NULL,	/* proxies */
		/* FIXME: TLS? */ 0);
}

/**
 * Called when we add a firewalled source to the dmesh.
 *
 * Add the corresponding file to the download list if we're swarming
 * on it.
 *
 * @param guid		the GUID of the remote servent
 * @param proxies	list of known push-proxies (gnet_host_t)
 * @param sha1		the SHA1 of the file.
 */
void
file_info_try_to_swarm_with_firewalled(
	const guid_t *guid, hash_list_t *proxies, const struct sha1 *sha1)
{
	fileinfo_t *fi;
	gnet_host_vec_t *push_proxies = NULL;

	if (!can_swarm)				/* Downloads not initialized yet */
		return;

	fi = file_info_by_sha1(sha1);
	if (!fi)
		return;

	file_info_check(fi);

	if (proxies != NULL)
		push_proxies = gnet_host_vec_from_hash_list(proxies);

	if (GNET_PROPERTY(dmesh_debug) || GNET_PROPERTY(download_debug)) {
		g_debug("MESH supplying firewalled %s (%u push-prox%s) for %s",
			guid_hex_str(guid), proxies ? hash_list_length(proxies) : 0,
			(proxies && 1 == hash_list_length(proxies)) ? "y" : "ies",
			filepath_basename(fi->pathname));
	}

	download_auto_new(filepath_basename(fi->pathname),
		fi->size,
		ipv4_unspecified,	/* addr */
		0,					/* port */
		guid,
		NULL,				/* hostname */
		sha1,
		NULL,				/* TTH */
		tm_time(),
		fi,
		push_proxies,		/* proxies */
		/* FIXME: TLS? */ 0);

	gnet_host_vec_free(&push_proxies);
}

/**
 * Scan the given directory for files, looking at those bearing a valid
 * fileinfo trailer, yet which we know nothing about.
 */
void
file_info_scandir(const char *dir)
{
	DIR *d;
	struct dirent *dentry;
	fileinfo_t *fi;
	char *pathname = NULL;

	g_return_if_fail(dir);
	g_return_if_fail(is_absolute_path(dir));

	d = opendir(dir);
	if (NULL == d) {
		g_warning("can't open directory %s: %m", dir);
		return;
	}

	while (NULL != (dentry = readdir(d))) {
		const char *filename;

		HFREE_NULL(pathname);

		filename = dir_entry_filename(dentry);

		/**
		 * Skip ".", "..", and hidden files. We don't create any
	   	 * and we also must skip the lock file.
		 */
		if ('.' == filename[0])
			continue;

		switch (dir_entry_mode(dentry)) {
		case 0:
		case S_IFREG:
		case S_IFLNK:
			break;
		default:
			continue;
		}

		pathname = make_pathname(dir, filename);

		if (!S_ISREG(dir_entry_mode(dentry))) {
			filestat_t sb;

			if (-1 == stat(pathname, &sb)) {
				g_warning("cannot stat %s: %m", pathname);
				continue;
			}
			if (!S_ISREG(sb.st_mode))			/* Only regular files */
				continue;
		}

		fi = file_info_retrieve_binary(pathname);
		if (NULL == fi)
			continue;

		if (file_info_lookup_dup(fi)) {
			/* Already know about this */
			fi_free(fi);
			fi = NULL;
			continue;
		}

		/*
		 * We found an entry that we do not know about.
		 */

		file_info_merge_adjacent(fi);		/* Update fi->done */
		file_info_hash_insert(fi);

		g_warning("reactivated orphan entry (%.02f%% done, %s SHA1): %s",
			fi->done * 100.0 / (0 == fi->size ? 1 : fi->size),
			fi->sha1 ? "with" : "no", pathname);
	}

	HFREE_NULL(pathname);
	closedir(d);
}

/**
 * Callback for hash table iterator. Used by file_info_completed_orphans().
 */
static void
fi_spot_completed_kv(void *val, void *unused_x)
{
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);

	if (fi->refcount)
		return;				/* Attached to a download */

	if (FI_F_SEEDING && fi->flags)
		return;				/* Completed file being seeded */

	/*
	 * If the file is 100% done, fake a new download.
	 *
	 * It will be trapped by download_resume_bg_tasks() and handled
	 * as any complete download.
	 */

	if (FILE_INFO_COMPLETE(fi)) {
		download_orphan_new(filepath_basename(fi->pathname),
			fi->size, fi->sha1, fi);
	}
}

/**
 * Look through all the known fileinfo structures, looking for orphaned
 * files that are complete.
 *
 * A fake download is created for them, so that download_resume_bg_tasks()
 * can pick them up.
 */
void
file_info_spot_completed_orphans(void)
{
	hikset_foreach(fi_by_outname, fi_spot_completed_kv, NULL);
}

void
fi_add_listener(fi_listener_t cb, gnet_fi_ev_t ev,
	frequency_t t, uint32 interval)
{
    g_assert(ev < EV_FI_EVENTS);

    event_add_subscriber(fi_events[ev], (callback_fn_t) cb, t, interval);
}

void
fi_remove_listener(fi_listener_t cb, gnet_fi_ev_t ev)
{
    g_assert(ev < EV_FI_EVENTS);

    event_remove_subscriber(fi_events[ev], (callback_fn_t) cb);
}

void
src_add_listener(src_listener_t cb, gnet_src_ev_t ev,
	frequency_t t, uint32 interval)
{
    g_assert(UNSIGNED(ev) < EV_SRC_EVENTS);

    event_add_subscriber(src_events[ev], (callback_fn_t) cb, t, interval);
}

void
src_remove_listener(src_listener_t cb, gnet_src_ev_t ev)
{
    g_assert(UNSIGNED(ev) < EV_SRC_EVENTS);

    event_remove_subscriber(src_events[ev], (callback_fn_t) cb);
}

/**
 * Get an information structure summarizing the file info.
 * This is used by the GUI to avoid peeking into the file info structure
 * directly: it has its own little pre-digested information to display.
 */
gnet_fi_info_t *
fi_get_info(gnet_fi_t fih)
{
    fileinfo_t *fi;
    gnet_fi_info_t *info;
	const struct sha1 *sha1;

    fi = file_info_find_by_handle(fih);
	file_info_check(fi);

    WALLOC(info);

    info->guid = atom_guid_get(fi->guid);
    info->filename = atom_str_get(filepath_basename(fi->pathname));
	sha1 = fi->sha1 ? fi->sha1 : fi->cha1;
    info->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
    info->tth = fi->tth ? atom_tth_get(fi->tth) : NULL;
    info->fi_handle = fi->fi_handle;
	info->size = fi->size;

	info->tth_slice_size = fi->tigertree.slice_size;
	info->tth_num_leaves = fi->tigertree.num_leaves;
	info->created		 = fi->created;
	info->tth_depth      = tt_depth(fi->tigertree.num_leaves);
	info->tth_recomputed =
		NULL == fi->tigertree.leaves && fi->tigertree.num_leaves != 0;

    return info;
}

/**
 * Dispose of the info structure.
 */
void
fi_free_info(gnet_fi_info_t *info)
{
    g_assert(NULL != info);

	atom_guid_free_null(&info->guid);
	atom_str_free_null(&info->filename);
	atom_sha1_free_null(&info->sha1);
	atom_tth_free_null(&info->tth);

    WFREE(info);
}

void
fi_increase_uploaded(fileinfo_t *fi, size_t amount)
{
	file_info_check(fi);
	fi->uploaded += amount;
	file_info_changed(fi);
}

/**
 * Fill in the fileinfo status structure "s" using the fileinfo associated
 * with the fileinfo handle "fih".
 */
void
fi_get_status(gnet_fi_t fih, gnet_fi_status_t *s)
{
    fileinfo_t *fi = file_info_find_by_handle(fih);

	file_info_check(fi);
    g_assert(NULL != s);

    s->recvcount      = fi->recvcount;
    s->refcount       = fi->refcount;
    s->lifecount      = fi->lifecount;
    s->done           = fi->done;
	s->uploaded		  = fi->uploaded;
    s->recv_last_rate = fi->recv_last_rate;
    s->size           = fi->size;
    s->active_queued  = fi->active_queued;
    s->passive_queued = fi->passive_queued;
	s->modified		  =	fi->modified;
	s->dht_lookups    = fi->dht_lookups;
	s->dht_values     = fi->dht_values;

	s->paused		  = 0 != (FI_F_PAUSED & fi->flags);
	s->seeding		  = 0 != (FI_F_SEEDING & fi->flags);
	s->finished		  = 0 != FILE_INFO_FINISHED(fi);
	s->complete		  = 0 != FILE_INFO_COMPLETE(fi);
	s->verifying	  = 0 != (FI_F_VERIFYING & fi->flags);
	s->moving		  = 0 != (FI_F_MOVING & fi->flags);
	s->has_sha1 	  = NULL != fi->sha1;
	s->sha1_matched   = s->complete && s->has_sha1 && fi->sha1 == fi->cha1;
	s->sha1_failed    =
		s->complete && s->has_sha1 && fi->cha1 && fi->sha1 != fi->cha1;

	s->copied 		  = s->complete ? fi->copied : FALSE;
	s->vrfy_hashed    = s->complete ? fi->vrfy_hashed : FALSE;
	s->tth_check      = s->complete ? fi->tth_check : FALSE;

	s->dht_lookup_pending = booleanize(FI_F_DHT_LOOKUP & fi->flags);
	s->dht_lookup_running = booleanize(FI_F_DHT_LOOKING & fi->flags);
}

/**
 * Get a list with information about each chunk and status. Returns a
 * linked list of chunks with just the end byte and the status. The
 * list is fully allocated and the receiver is responsible for freeing
 * up the memory.
 */
GSList *
fi_get_chunks(gnet_fi_t fih)
{
    const fileinfo_t *fi = file_info_find_by_handle(fih);
	const struct dl_file_chunk *fc;
	GSList *chunks = NULL;

    file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		gnet_fi_chunks_t *chunk;

		WALLOC(chunk);
		chunk->from   = fc->from;
		chunk->to     = fc->to;
		chunk->status = fc->status;
		chunk->old    = TRUE;

		chunks = g_slist_prepend(chunks, chunk);
	}

	/*
	 * If the list we built is empty and the file is completed, we have
	 * already cleared the chunk list in fi_downloading_free().  To be
	 * able to let the GUI correctly display the file as complete, fake
	 * a single chunk for the whole file.
	 * 		--RAM, 2017-10-18.
	 */

	if (NULL == chunks && FILE_INFO_COMPLETE(fi)) {
		gnet_fi_chunks_t *chunk;

		WALLOC(chunk);
		chunk->from   = 0;
		chunk->to     = fi->size;
		chunk->status = DL_CHUNK_DONE;
		chunk->old    = FALSE;

		chunks = g_slist_prepend(chunks, chunk);
	}

    return g_slist_reverse(chunks);
}

/**
 * Free chunk list got by calling fi_get_chunks.
 */
void
fi_free_chunks(GSList *chunks)
{
    GSList *sl;

    for (sl = chunks; NULL != sl; sl = g_slist_next(sl)) {
    	gnet_fi_chunks_t *chunk = sl->data;
        WFREE(chunk);
    }

    g_slist_free(chunks);
}


/**
 * Get a list of available ranges for this fileinfo handle.
 * The list is fully allocated and the receiver is responsible for
 * freeing up the memory, for example using fi_free_ranges().
 */
GSList *
fi_get_ranges(gnet_fi_t fih)
{
    fileinfo_t *fi = file_info_find_by_handle(fih);
	GSList *ranges = NULL;
	const http_range_t *r;

    file_info_check(fi);

	HTTP_RANGE_FOREACH(fi->seen_on_network, r) {
		http_range_t *range;

        WALLOC(range);
        range->start = r->start;
        range->end   = r->end;

		ranges = g_slist_prepend(ranges, range);
	}

    return g_slist_reverse(ranges);
}

/**
 * Frees list of http_range_t items.
 */
void
fi_free_ranges(GSList *ranges)
{
	GSList *sl;

	for (sl = ranges; NULL != sl; sl = g_slist_next(sl)) {
        http_range_t *r = sl->data;
		WFREE(r);
	}

	g_slist_free(ranges);
}

/**
 * @return NULL terminated array of char * pointing to the aliases.
 * You can easily free the returned array with xstrfreev().
 *
 * O(2n) - n: number of aliases
 */
char **
fi_get_aliases(gnet_fi_t fih)
{
    char **a;
    uint len;
    pslist_t *sl;
    uint n;
    fileinfo_t *fi = file_info_find_by_handle(fih);

    len = pslist_length(fi->alias);

	XMALLOC_ARRAY(a, len + 1);
    a[len] = NULL; /* terminate with NULL */;

    for (sl = fi->alias, n = 0; NULL != sl; sl = pslist_next(sl), n++) {
        g_assert(n < len);
        a[n] = xstrdup(sl->data);
    }

    return a;
}

/**
 * Add new download source for the file.
 */
void
file_info_add_new_source(fileinfo_t *fi, struct download *d)
{
	fi->ntime = tm_time();
	file_info_add_source(fi, d);
}

/**
 * Add download source for the file, but preserve original "ntime".
 */
void
file_info_add_source(fileinfo_t *fi, struct download *d)
{
	file_info_check(fi);
	g_assert(NULL == d->file_info);
	g_assert(!d->src_handle_valid);

	fi->refcount++;
	fi->dirty_status = TRUE;
	d->file_info = fi;
	d->src_handle = idtable_new_id(src_handle_map, d);
	d->src_handle_valid = TRUE;
	fi->sources = pslist_prepend(fi->sources, d);

	if (download_is_alive(d)) {
		g_assert(fi->refcount > fi->lifecount);
		fi->lifecount++;
	}

	if (1 == fi->refcount) {
		g_assert(GNET_PROPERTY(fi_with_source_count)
				< GNET_PROPERTY(fi_all_count));
		gnet_prop_incr_guint32(PROP_FI_WITH_SOURCE_COUNT);
	}

	src_event_trigger(d, EV_SRC_ADDED);

	/*
	 * Source was added, but we do not need to call fi_update_seen_on_network().
	 * This will be done through a fi_src_ranges_changed() by the download
	 * code when it will learn about new ranges for the file or when the first
	 * HTTP reply will be processed after a connection is established.
	 *
	 * Until then, the source will not be taken into consideration for the
	 * computation of the seen chunk since it lacks the DL_F_REPLIED mark.
	 */
}

/**
 * Removing one source reference from the fileinfo.
 * When no sources reference the fileinfo structure, free it when
 * the fileinfo has been marked with FI_F_DISCARD.
 *
 * This replaces file_info_free()
 */
void
file_info_remove_source(fileinfo_t *fi, struct download *d)
{
	file_info_check(fi);
	g_assert(fi == d->file_info);
	g_assert(d->src_handle_valid);
	g_assert(fi->refcount > 0);
	g_assert(fi->refcount >= fi->lifecount);
	g_assert(fi->hashed);

	/*
	 * Source is removed: inform whoever is monitoring the sources via an event.
	 * Then remove the source from the fileinfo before recomputing the available
	 * chunks in the file.
	 */

	src_event_trigger(d, EV_SRC_REMOVED);
	fi->sources = pslist_remove(fi->sources, d);

	idtable_free_id(src_handle_map, d->src_handle);
	d->src_handle_valid = FALSE;

	if (download_is_alive(d))
		fi->lifecount--;

	fi->refcount--;
	fi->dirty_status = TRUE;
	d->file_info = NULL;

	/*
	 * We don't free the structure unless FI_F_DISCARD is set.
	 */

	if (0 == fi->refcount) {
		g_assert(GNET_PROPERTY(fi_with_source_count) > 0);
		gnet_prop_decr_guint32(PROP_FI_WITH_SOURCE_COUNT);

		if (fi->flags & FI_F_DISCARD) {
			file_info_hash_remove(fi);
			fi_free(fi);
		}
    }
}

/**
 * Add a cloned source.
 *
 * This is a specialized form of file_info_add_source().
 *
 * Since we're handling a cloned source, there is no need to update the
 * list of seen parts of the file on the network, because we already have
 * this information computed from the original download that has been cloned.
 *
 * @param fi	the fileinfo
 * @param d		the original download being cloned
 * @param cd	the new cloned download
 */
void
file_info_cloned_source(fileinfo_t *fi, download_t *d, download_t *cd)
{
	file_info_check(fi);
	g_assert(NULL != d->file_info);
	g_assert(cd->src_handle_valid);				/* Because it's a clone! */
	g_assert(fi->refcount > 0);
	g_assert(fi->refcount >= fi->lifecount);
	g_assert(fi->hashed);

	cd->src_handle = idtable_new_id(src_handle_map, cd);
	fi->sources = pslist_prepend(fi->sources, cd);
	src_event_trigger(cd, EV_SRC_ADDED);

	/*
	 * Do not mark fileinfo dirty, we're just increasing counters.
	 */

	fi->refcount++;
	if (download_is_alive(d)) {
		g_assert(fi->refcount > fi->lifecount);
		fi->lifecount++;
	}
}

/**
 * Is file rare on the network?
 *
 * A file is deemed rare when all the known sources are partial ones.
 */
bool
file_info_is_rare(const fileinfo_t *fi)
{
	file_info_check(fi);

	if (NULL == fi->sha1)
		return FALSE;

	return download_sha1_is_rare(fi->sha1);
}

/**
 * Can a partial file be shared?
 */
bool
file_info_partial_shareable(const fileinfo_t *fi)
{
	file_info_check(fi);

	if (0 == fi->size || !fi->file_size_known)
		return FALSE;

	if (!GNET_PROPERTY(pfsp_server)) {
		if (GNET_PROPERTY(pfsp_rare_server)) {
			if (!file_info_is_rare(fi))
				return FALSE;
		} else {
			return FALSE;
		}
	}

	return fi->done != 0;
}

/**
 * Get a copy of the sources list for a fileinfo. The items have the
 * "struct download *".
 *
 * @return A copy of the sources list.
 */
pslist_t *
file_info_get_sources(const fileinfo_t *fi)
{
	file_info_check(fi);

	return pslist_copy(fi->sources);
}

/**
 * Remove non-referenced fileinfo and reclaim its data structures.
 */
void
file_info_remove(fileinfo_t *fi)
{
	file_info_check(fi);
	g_assert(fi->refcount == 0);

	file_info_hash_remove(fi);
	fi_free(fi);
}

static void
fi_notify_helper(void *value, void *unused_udata)
{
    fileinfo_t *fi = value;

	(void) unused_udata;

	file_info_check(fi);
    if (!fi->dirty_status)
        return;

    fi->dirty_status = FALSE;
	file_info_changed(fi);
}

/**
 * Called every second by the main timer.
 */
void
file_info_timer(void)
{
	hikset_foreach(fi_by_outname, fi_notify_helper, NULL);
}

/**
 * Query the DHT for a SHA1 search if needed and appropriate.
 */
static void
fi_dht_query(fileinfo_t *fi)
{
	time_delta_t retry_period = FI_DHT_PERIOD;

	file_info_check(fi);

	if (NULL == fi->sha1 || FILE_INFO_FINISHED(fi))
		return;

	/*
	 * A paused download will not start even if we find new sources.
	 * Also there's no need to requeue a lookup if one is already pending.
	 */

	if ((FI_F_PAUSED | FI_F_DHT_LOOKUP) & fi->flags)
		return;

	/*
	 * If the file is already being actively downloaded from "enough"
	 * sources, no queries are needed, the download mesh should be correctly
	 * seeded and sufficient.
	 */

	if (fi->recvcount >= FI_DHT_RECV_THRESH)
		return;

	/*
	 * Even if the file is queued, querying the DHT could be useful.
	 * However, we don't want to requeue as often when we have sources.
	 * An actively queued source counts twice as much as a passive.
	 */

	retry_period = time_delta_add(retry_period,
		FI_DHT_SOURCE_DELAY * (fi->lifecount - fi->recvcount));
	retry_period = time_delta_add(retry_period,
		FI_DHT_QUEUED_DELAY * (2 * fi->active_queued + fi->passive_queued));
	retry_period = time_delta_add(retry_period,
		FI_DHT_RECV_DELAY * fi->recvcount);

	if (
		fi->last_dht_query &&
		delta_time(tm_time(), fi->last_dht_query) < retry_period
	)
		return;

	gdht_find_sha1(fi);
}

/**
 * Signals that a DHT query was requested (queued).
 */
void
file_info_dht_query_queued(fileinfo_t *fi)
{
	file_info_check(fi);
	g_return_if_fail(!(fi->flags & FI_F_DHT_LOOKUP));

	fi->last_dht_query = tm_time();
	fi->flags |= FI_F_DHT_LOOKUP;
	file_info_changed(fi);
}

/**
 * Signals that a DHT query is starting.
 *
 * @return TRUE if query can proceed, FALSE otherwise.
 */
bool
file_info_dht_query_starting(fileinfo_t *fi)
{
	file_info_check(fi);
	g_return_val_if_fail(fi->flags & FI_F_DHT_LOOKUP, FALSE);

	if (
		fi->flags & (
			FI_F_MOVING | FI_F_TRANSIENT | FI_F_SEEDING |
			FI_F_STRIPPED | FI_F_UNLINKED
		)
	)
		return FALSE;

	/*
	 * We already checked that at "queuing" time but since the queue can be
	 * large and things have time to change we recheck before actually
	 * issuing the query.
	 */

	if (fi->recvcount >= FI_DHT_RECV_THRESH)
		return FALSE;

	fi->flags |= FI_F_DHT_LOOKING;
	file_info_changed(fi);
	return TRUE;
}

/**
 * Signals that a DHT query was completed.
 */
void
file_info_dht_query_completed(fileinfo_t *fi, bool launched, bool found)
{
	file_info_check(fi);
	g_return_if_fail(fi->flags & FI_F_DHT_LOOKUP);

	fi->flags &= ~(FI_F_DHT_LOOKUP | FI_F_DHT_LOOKING);

	if (launched) {
		fi->dht_lookups++;
		if (found) {
			fi->dht_values++;
		}
	}
	file_info_changed(fi);
}

/**
 * Hash table iterator to launch DHT queries.
 */
static void
fi_dht_check(void *value, void *unused_udata)
{
    fileinfo_t *fi = value;

	(void) unused_udata;

	fi_dht_query(fi);
}

/**
 * Initiate a SHA1 query in the DHT immediately, without waiting for periodic
 * monitoring of sourceless fileinfos.
 */
void
file_info_dht_query(const sha1_t *sha1)
{
	fileinfo_t *fi;

	g_assert(sha1);

	if (!dht_bootstrapped())
		return;

	fi = file_info_by_sha1(sha1);
	if (fi)
		fi_dht_query(fi);
}

/**
 * Slower timer called every few minutes (about 6).
 */
void
file_info_slow_timer(void)
{
	if (!dht_bootstrapped() || GNET_PROPERTY(ancient_version))
		return;

	hikset_foreach(fi_by_outname, fi_dht_check, NULL);
}

/**
 * Hash table iterator to publish into the DHT.
 */
static void
fi_dht_publish(void *value, void *unused_udata)
{
    fileinfo_t *fi = value;

	(void) unused_udata;

	if (fi->sha1 != NULL)
		publisher_add(fi->sha1);
}

/**
 * Publish all known SHA-1 to the DHT.
 */
static void
fi_publish_all(void)
{
	hikset_foreach(fi_by_outname, fi_dht_publish, NULL);
}

/**
 * Kill all downloads associated with a fi and remove the fi itself.
 *
 * Will return FALSE if download could not be removed because it was still in
 * use, e.g. when it is being verified.
 * 		-- JA 25/10/03
 */
bool
file_info_purge(fileinfo_t *fi)
{
	pslist_t *sl, *csl;
	bool do_remove;

	file_info_check(fi);
	g_assert(fi->hashed);

	do_remove = !(fi->flags & FI_F_DISCARD) || NULL == fi->sources;
	csl = pslist_copy(fi->sources);	/* Clone list, orig can be modified */

	PSLIST_FOREACH(csl, sl) {
		struct download *d = sl->data;

		download_abort(d);
		if (!download_remove(d)) {
			pslist_free(csl);
			return FALSE;
		}
	}

	pslist_free(csl);

	if (do_remove) {
		/*
	 	* Downloads not freed at this point, this will happen when the
	 	* download_free_removed() is asynchronously called.  However, all
	 	* references to the file info has been cleared, so we can remove it.
	 	*/

		g_assert(0 == fi->refcount);

		if (fi->sha1 != NULL)
			search_dissociate_sha1(fi->sha1);

		file_info_unlink(fi);
		file_info_hash_remove(fi);
		fi_free(fi);
	}

	return TRUE;
}

bool
fi_purge(gnet_fi_t fih)
{
	return file_info_purge(file_info_find_by_handle(fih));
}

void
fi_pause(gnet_fi_t fih)
{
	file_info_pause(file_info_find_by_handle(fih));
}

void
fi_resume(gnet_fi_t fih)
{
	file_info_resume(file_info_find_by_handle(fih));
}

bool
fi_rename(gnet_fi_t fih, const char *filename)
{
	return file_info_rename(file_info_find_by_handle(fih), filename);
}

/**
 * Emit a single X-Available header, letting them know we hold a partial
 * file and how many bytes exactly, in case they want to prioritize their
 * download requests depending on file completion criteria.
 *
 * @return the size of the generated header.
 */
size_t
file_info_available(const fileinfo_t *fi, char *buf, size_t size)
{
	header_fmt_t *fmt;
	size_t len, rw;

	file_info_check(fi);
	g_assert(size_is_non_negative(size));

	fmt = header_fmt_make("X-Available", " ",
		UINT64_DEC_BUFLEN + sizeof("X-Available: bytes") + 2, size);

	header_fmt_append_value(fmt, "bytes");
	header_fmt_append_value(fmt, filesize_to_string(fi->done));
	header_fmt_end(fmt);

	len = header_fmt_length(fmt);
	g_assert(len < size);
	rw = clamp_strncpy(buf, size, header_fmt_string(fmt), len);
	header_fmt_free(&fmt);

	g_assert(rw < size);	/* No clamping occurred */

	return rw;
}

/**
 * Emit an X-Available-Ranges header listing the ranges within the file that
 * we have on disk and we can share as a PFSP-server.  The header is emitted
 * in `buf', which is `size' bytes long.
 *
 * If there is not enough room to emit all the ranges, emit a random subset
 * of the ranges but include an extra "X-Available" header to let them know
 * how many bytes we really have.
 *
 * @return the size of the generated header.
 */
size_t
file_info_available_ranges(const fileinfo_t *fi, char *buf, size_t size)
{
	const struct dl_file_chunk **fc_ary;
	header_fmt_t *fmt, *fmta = NULL;
	bool is_first = TRUE;
	char range[2 * UINT64_DEC_BUFLEN + sizeof(" bytes ")];
	slink_t *sl;
	int count;
	int nleft;
	int i;
	size_t rw;
	const char *x_available_ranges = "X-Available-Ranges";

	file_info_check(fi);
	g_assert(size_is_non_negative(size));
	g_assert(file_info_check_chunklist(fi, TRUE));

	fmt = header_fmt_make(x_available_ranges, ", ", size, size);

	ESLIST_FOREACH(&fi->chunklist, sl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);

		dl_file_chunk_check(fc);
		if (DL_CHUNK_DONE != fc->status)
			continue;

		str_bprintf(range, sizeof range, "%s%s-%s",
			is_first ? "bytes " : "",
			filesize_to_string(fc->from), filesize_to_string2(fc->to - 1));

		if (!header_fmt_append_value(fmt, range))
			break;
		is_first = FALSE;
	}

	if (NULL == sl)
		goto emit;

	/*
	 * Not everything fitted.  We have to be smarter and include only what
	 * can fit in the size we were given.
	 *
	 * However, to let them know how much file data we really hold, we're also
	 * going to include an extra "X-Available" header specifying how many
	 * bytes we have.
	 */

	header_fmt_free(&fmt);

	{
		size_t len;

		fmta = header_fmt_make("X-Available", " ",
			UINT64_DEC_BUFLEN + sizeof("X-Available: bytes") + 2, size);

		header_fmt_append_value(fmta, "bytes");
		header_fmt_append_value(fmta, filesize_to_string(fi->done));
		header_fmt_end(fmta);

		len = header_fmt_length(fmta);
		len = size > len ? size - len : 0;

		fmt = header_fmt_make(x_available_ranges, ", ", size, len);
	}

	is_first = TRUE;

	/*
	 * See how many chunks we have.
	 */

	count = 0;
	ESLIST_FOREACH(&fi->chunklist, sl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);
		dl_file_chunk_check(fc);
		if (DL_CHUNK_DONE == fc->status)
			count++;
	}

	/*
	 * Reference all the "done" chunks in `fc_ary'.
	 */

	g_assert(count > 0);		/* Or there would be nothing to emit */

	HALLOC_ARRAY(fc_ary, count);
	i = 0;

	ESLIST_FOREACH(&fi->chunklist, sl) {
		const struct dl_file_chunk *fc = eslist_data(&fi->chunklist, sl);
		dl_file_chunk_check(fc);

		if (DL_CHUNK_DONE == fc->status)
			fc_ary[i++] = fc;
	}

	g_assert(i == count);

	/*
	 * Now select chunks randomly from the set, and emit them if they fit.
	 */

	for (nleft = count; nleft > 0; nleft--) {
		const struct dl_file_chunk *fc;
		int j;

		j = random_value(nleft - 1);
		g_assert(j >= 0 && j < nleft);

		fc = fc_ary[j];
		dl_file_chunk_check(fc);
		g_assert(DL_CHUNK_DONE == fc->status);

		str_bprintf(range, sizeof range, "%s%s-%s",
			is_first ? "bytes " : "",
			filesize_to_string(fc->from), filesize_to_string2(fc->to - 1));

		if (header_fmt_append_value(fmt, range))
			is_first = FALSE;

		/*
		 * Shift upper (nleft - j - 1) items down 1 position.
		 */

		ARRAY_REMOVE(fc_ary, j, nleft);
	}

	HFREE_NULL(fc_ary);

emit:
	rw = 0;

	if (fmta) {				/* X-Available header is required */
		size_t len = header_fmt_length(fmta);
		g_assert(len + rw < size);
		rw += clamp_strncpy(&buf[rw], size - rw, header_fmt_string(fmta), len);
		header_fmt_free(&fmta);
	}

	if (!is_first) {		/* Something was recorded in X-Available-Ranges */
		size_t len;
		header_fmt_end(fmt);
		len = header_fmt_length(fmt);
		g_assert(len + rw < size);
		rw += clamp_strncpy(&buf[rw], size - rw, header_fmt_string(fmt), len);
	}

	header_fmt_free(&fmt);

	g_assert(rw < size);	/* No clamping occurred */

	return rw;
}

/**
 * Given a request range `start' (included) and `end' (included) for the
 * partially downloaded file represented by `fi', see whether we can
 * satisfy it, even partially, without touching `start' but only only by
 * possibly moving `end' down.
 *
 * @returns TRUE if the request is satisfiable, with `end' possibly adjusted,
 * FALSE is the request cannot be satisfied because `start' is not within
 * an available chunk.
 */
bool
file_info_restrict_range(fileinfo_t *fi, filesize_t start, filesize_t *end)
{
	const struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	ESLIST_FOREACH_DATA(&fi->chunklist, fc) {
		dl_file_chunk_check(fc);

		if (DL_CHUNK_DONE != fc->status)
			continue;

		if (start < fc->from || start >= fc->to)
			continue;		/* `start' is not in the range */

		/*
		 * We found an available chunk within which `start' falls.
		 * Look whether we can serve their whole request, otherwise
		 * shrink the end.
		 */

		if (*end >= fc->to)
			*end = fc->to - 1;

		return TRUE;
	}

	return FALSE;	/* Sorry, cannot satisfy this request */
}

/**
 * Creates a URL which points to a downloads (e.g. you can move this to a
 * browser and download the file there with this URL).
 *
 * @return A newly allocated string.
 */
char *
file_info_build_magnet(gnet_fi_t handle)
{
	struct magnet_resource *magnet;
	const fileinfo_t *fi;
	const pslist_t *sl;
	char *url;
	int n;

	fi = file_info_find_by_handle(handle);
	g_return_val_if_fail(fi, NULL);
	file_info_check(fi);

	magnet = magnet_resource_new();

	/* The filename used for the magnet must be UTF-8 encoded */
	magnet_set_display_name(magnet,
		lazy_filename_to_utf8_normalized(filepath_basename(fi->pathname),
			UNI_NORM_NETWORK));

	if (fi->sha1) {
		magnet_set_sha1(magnet, fi->sha1);
	}
	if (fi->tth) {
		magnet_set_tth(magnet, fi->tth);
	}
	if (fi->file_size_known && fi->size) {
		magnet_set_filesize(magnet, fi->size);
	}

	n = 0;
	for (sl = fi->sources; NULL != sl && n++ < 20; sl = pslist_next(sl)) {
		struct download *d = sl->data;
		const char *dl_url;

		download_check(d);
		dl_url = download_build_url(d);
		if (dl_url) {
			magnet_add_source_by_url(magnet, dl_url);
		}
	}

	url = magnet_to_string(magnet);
	magnet_resource_free(&magnet);
	return url;
}

/**
 * Creates a file:// URL which points to the file on the local filesystem.
 * If the file has not been created yet, NULL is returned.
 *
 * @return A newly allocated string or NULL.
 */
char *
file_info_get_file_url(gnet_fi_t handle)
{
	fileinfo_t *fi;

	fi = file_info_find_by_handle(handle);
	g_return_val_if_fail(fi, NULL);
	file_info_check(fi);

	/* Allow partials but not unstarted files */
	return fi->done > 0 ? url_from_absolute_path(fi->pathname) : NULL;
}

/**
 * Compares two available ranges.
 *
 * Our relative order is a lexicographic order on (start, length), and
 * two chunks are identical only when they start on the same position are
 * have the same length.
 */
static int
fi_avail_cmp(const void *a, const void *b)
{
	const struct dl_avail_chunk *ca = a, *cb = b;

	if (ca->from == cb->from) {
		size_t la = ca->to - ca->from;
		size_t lb = cb->to - cb->from;

		return CMP(la, lb);
	}

	return CMP(ca->from, cb->from);
}

/**
 * Compares two available ranges so that two ranges are equal when they
 * overlap.
 */
static int
fi_overlap_cmp(const void *a, const void *b)
{
	const struct dl_avail_chunk *ca = a, *cb = b;

	if (ca->to <= cb->from)
		return -1;

	if (cb->to <= ca->from)
		return +1;

	return 0;		/* Overlapping ranges are equal */
}

/**
 * Compares two available ranges on the amount of sources that provide them.
 */
static int
fi_avail_source_cmp(const void *a, const void *b)
{
	const struct dl_avail_chunk *ca = a, *cb = b;
	int c;

	c = CMP(ca->sources, cb->sources);
	return 0 == c ? CMP(ca->from, cb->from) : c;
}

/**
 * Count one more source offering chunk [from, to[.
 *
 * @param rbt		the red-black tree where we store available chunks
 * @param from		start of chunk
 * @param to		first byte beyond chunk
 */
static void
fi_count_source(rbtree_t *rbt, filesize_t from, filesize_t to)
{
	struct dl_avail_chunk *ac;
	struct dl_avail_chunk key;

	key.from = from;
	key.to = to;

	ac = rbtree_lookup(rbt, &key);
	if (NULL == ac) {
		ac = dl_avail_chunk_new(from, to, 1);
		rbtree_insert(rbt, ac);
	} else {
		ac->sources++;
	}
}

/**
 * Spread offered chunk `ac' to the list of available chunks held in the
 * red-black tree, updating the amount of sources offering each range of
 * the file.
 *
 * This is an important step in our computation of the rarest chunks offered
 * on the network.
 *
 * @param arbt		red-black tree listing available chunks with source count
 * @param ac		the offered chunk we're adding to the existing set
 */
static void
fi_update_available_forward(rbtree_t *arbt, const struct dl_avail_chunk *ac)
{
	filesize_t from;					/* Starting point of added chunk */

	dl_avail_chunk_check(ac);

	from = ac->from;

	do {
		struct dl_avail_chunk key;
		struct dl_avail_chunk *avc;		/* Available chunk */
		rbnode_t *node;					/* Tree node for faster iteration */

		key.from = from;
		key.to = ac->to;

		avc = rbtree_lookup_node(arbt, &key, &node);

		if (NULL == avc) {
			struct dl_avail_chunk *anew;

			/* Chunk overlaps with nothing -> new entry and we're done */

			anew = dl_avail_chunk_new(from, ac->to, ac->sources);
			rbtree_insert(arbt, anew);
			break;
		}

		/*
		 * Chunk `avc' overlaps with `ac'.
		 * There are six main configurations possible, with case #0 being
		 * handled flexibly (i.e. it can start / end on the same boundaries):
		 *
		 *   #0:         [=avc=]
		 *              [---ac--]
		 *
		 *   #1:           [====avc====]
		 *              [---ac--]
		 *
		 *   #2:       [====avc====]
		 *             [---ac--]
		 *
		 *   #3:     [====avc====]
		 *             [---ac--]
		 *
		 *   #4:   [====avc====]
		 *             [---ac--]
		 *
		 *   #5: [====avc====]
		 *             [---ac--]
		 *
		 * We want to find the first available chunk which overlaps with `ac'.
		 */

		 for (;;) {
			struct dl_avail_chunk *prev;
			rbnode_t *pnode = node;

			prev = rbtree_prev_node(arbt, &pnode);
			if (NULL == prev)
				break;		/* No other available chunk before `avc' */

			if (prev->to <= from)
				break;		/* No overlap with `ac' */

			avc = prev;
			node = pnode;
		}

		/*
		 * Handle cases #0 and #1 by creating a new available chunk at
		 * the beginning, then handling the overlapping part.
		 */

		if (from < avc->from) {
			struct dl_avail_chunk *anew;

			g_assert(avc->from < ac->to);	/* Overlaps with `ac' */

			anew = dl_avail_chunk_new(from, avc->from, ac->sources);
			rbtree_insert(arbt, anew);
			from = avc->from;
		}

		/*
		 * Handle cases #2, #3, #4 and #5 by splitting the existing available
		 * chunk up to the start of the offered chunk `ac', and anything
		 * following the end of `ac'.
		 */

		if (avc->from <= from) {
			struct dl_avail_chunk *anew;
			filesize_t to = MIN(avc->to, ac->to);	/* Upper intersection */
			filesize_t avc_to = avc->to;
			size_t sources = avc->sources;

			g_assert(avc->to > from);			/* Overlaps with `ac' */

			if (avc->from == from) {
				/* Case #2, or case #0 with matching start */
				avc->sources += ac->sources;	/* For the common part */

				if (avc->to > ac->to)			/* `avc' longer than `ac' */
					avc->to = ac->to;			/* Extra part added below */
			} else {
				/* Not case #2 */
				avc->to = from;					/* Truncates `avc' */

				/*
				 * Insert the common part with added source counts.
				 */

				anew = dl_avail_chunk_new(from, to, ac->sources + avc->sources);
				rbtree_insert(arbt, anew);

				avc = rbtree_next_node(arbt, &node);
				g_soft_assert(avc == anew);		/* The chunk we just inserted */
			}

			/* Handle rightmost part of cases #2 and #3 */

			if (avc_to > to) {
				anew = dl_avail_chunk_new(to, avc_to, sources);
				rbtree_insert(arbt, anew);

				avc = rbtree_next_node(arbt, &node);
				g_soft_assert(avc == anew);

				break;		/* We've consumed the whole `ac' */
			}

			from = to;
		}
	} while (from < ac->to);
}

/**
 * Recompute rarest chunk information based on all the available sources.
 */
static void
fi_update_rarest_chunks(fileinfo_t *fi)
{
	pslist_t *sl;
	rbtree_t *rbt, *arbt;
	rbtree_iter_t *iter;
	size_t sources;
	const void *item;

	if (!fi->file_size_known)
		return;

	if (GNET_PROPERTY(fileinfo_debug) > 5)
		g_debug("%s(): updating available for %s", G_STRFUNC, fi->pathname);

	/*
	 * The following comments highlight the important steps needed to compute
	 * the list of chunks available for the file with, for each chunk, the
	 * amount of source that can serve it.
	 *
	 * We have the following scenario, depicting the chunks offered:
	 *
	 * Source #1:    [-A--]   [---B--]       [--C---]
	 * Source #2:    [-----------------D-----------------] (whole file)
	 * Source #3:          [------E------]      [---F----]
	 * Source #4:    [-----------------G-----------------] (whole file)
	 *
	 * We want to build:
	 *
	 * Available:    [=a==][b][==c===][d=][e][f][=g=][=h=]
	 * # of sources:   3    3     4    3   2  3   4    3
	 *
	 * The rarest chunk is "e" (2 sources only provide that range) so this is
	 * the part of the file that needs to be downloaded first.
	 *
	 * To compute this, we loop over all the "alive" sources we know about
	 * for a file and for which we have chunk availability information.
	 *
	 * Each of the chunks (A, B, C, D, etc..) is inserted into a red-black tree
	 * whose ordering function is based on the chunk starting offset, then the
	 * length of the chunk (smallest length is smaller).
	 * When a chunk is already present, we increase its availability count:
	 * for instance, chunks D and G are identical according to our ordering
	 * function, hence when G is inserted, we simply increase the availability
	 * from 1 to 2.
	 */

	rbt = rbtree_create(fi_avail_cmp);
	sources = 0;

	PSLIST_FOREACH(fi->sources, sl) {
		const download_t *d = sl->data;

		download_check(d);
		g_assert(fi == d->file_info);

		sources++;

		if (!fi->use_swarming || !(d->flags & DL_F_PARTIAL)) {
			/* Whole range available */
			fi_count_source(rbt, 0, fi->size);
		} else if (NULL == d->ranges) {
			/* Partial file with no known ranges, ignore */
			continue;
		} else {
			const http_range_t *r;

			HTTP_RANGE_FOREACH(d->ranges, r) {
				fi_count_source(rbt, r->start, r->end + 1);
			}
		}
	}

	if (GNET_PROPERTY(fileinfo_debug) > 5) {
		g_debug("- collected %zu range%s out of %zu source%s:",
			rbtree_count(rbt), plural(rbtree_count(rbt)),
			sources, plural(sources));

		iter = rbtree_iter_new(rbt);
		while (rbtree_iter_next(iter, &item)) {
			const struct dl_avail_chunk *ac = item;		/* Chunk offered */
			g_debug("   [%s, %s] (%.2f%%) %zu source%s",
				filesize_to_string(ac->from), filesize_to_string2(ac->to),
				100.0 * (ac->to - ac->from) / (0 == fi->size ? 1 : fi->size),
				ac->sources, plural(ac->sources));
		}
		rbtree_iter_release(&iter);
	}

	/*
	 * All the unique chunks are in the red-black tree, we can iterate in order
	 * (so our visiting order will be A, D, E, B, etc..) and create the list
	 * of chunks representing the available regions and the amount of times they
	 * are offered (list of chunks a, b, c, d etc...).
	 *
	 * In our example, starting with "A" we get:
	 *
	 *     [--A-]
	 *     [====]
	 *        1
	 *
	 * because chunk "A" is present once. Then we process "D" so the list now
	 * becomes:
	 *
	 *     [----------------D------------------]
	 *     [====][=============================]
	 *        3                  2
	 *
	 * because "A" and "D" overlap so the "A" part is available twice but the
	 * count associated to "D" was 2 (chunks "D" and "G" are equal).  Then we
	 * process "E" and we further split the second chunk in our list:
	 *
	 *           [------E------]
	 *     [====][=============][==============]
	 *        3         3                2
	 *
	 * Encountering "B"
	 *
	 *              [---B--]
	 *     [====][=][======][==][==============]
	 *       3    3    4     3          2
	 *
	 * we further split the chunk, counting one more occurrence for the region
	 * covered by "B".
	 *
	 * This list is also held in a red-black tree during construction, to
	 * optimize lookups, but here we have only non-overlapping chunks
	 * so we use a different comparison function.  The red-black tree will
	 * be linearized into an embedded list at the end.
	 */

	file_info_available_free(fi);		/* Discard previous computation */

	arbt = rbtree_create(fi_overlap_cmp);
	iter = rbtree_iter_new(rbt);

	while (rbtree_iter_next(iter, &item)) {
		const struct dl_avail_chunk *ac = item;		/* Chunk offered */

		fi_update_available_forward(arbt, ac);
	}

	rbtree_iter_release(&iter);

	if (GNET_PROPERTY(fileinfo_debug) > 5) {
		filesize_t available = 0;

		iter = rbtree_iter_new(arbt);

		g_debug("- identified %zu available range%s over file:",
			rbtree_count(arbt), plural(rbtree_count(arbt)));

		while (rbtree_iter_next(iter, &item)) {
			const struct dl_avail_chunk *avc = item;

			dl_avail_chunk_check(avc);

			g_debug("   [%s, %s] %zu source%s",
				filesize_to_string(avc->from), filesize_to_string2(avc->to),
				avc->sources, plural(avc->sources));

			available += avc->to - avc->from;	/* For logging */
		}

		g_soft_assert_log(available <= fi->size,
			"available=%s, fi->size=%s",
			filesize_to_string(available), filesize_to_string2(fi->size));

		g_debug("=> %s out of %s bytes available (%.2f%%)",
			filesize_to_string(available), filesize_to_string2(fi->size),
			100.0 * available / fi->size);

		rbtree_iter_release(&iter);
	}

	/*
	 * In the end, we can dispose of the red-black trees and need only to keep
	 * the list of chunks available along with their availability count.
	 */

	rbtree_discard(rbt, dl_avail_chunk_free);
	rbtree_free_null(&rbt);

	iter = rbtree_iter_new(arbt);

	while (rbtree_iter_next(iter, &item)) {
		struct dl_avail_chunk *avc = deconstify_pointer(item);

		dl_avail_chunk_check(avc);
		eslist_append(&fi->available, avc);
	}

	rbtree_iter_release(&iter);
	rbtree_free_null(&arbt);	/* Its items are now listed in fi->available */

	/*
	 * Sort the list so that the rarest chunks come first.
	 *
	 * Note that when there are no partial sources, there is only one available
	 * chunk in the list: the chunk representing the whole file.
	 */

	eslist_sort(&fi->available, fi_avail_source_cmp);
}

/**
 * Callback for updates to ranges available on the network.
 *
 * This function gets triggered by an event when new ranges information has
 * become available for a download source.
 *
 * We collect the set of currently available ranges in fi->seen_on_network.
 * We fold in new ranges from a download source, and also remove sets of
 * ranges when a download source is no longer available.
 *
 * @param[in] srcid  The abstract id of the source that had its ranges updated.
 */
static void
fi_update_seen_on_network(gnet_src_t srcid)
{
	struct download *d;
	http_rangeset_t *hrs;
	pslist_t *sl;
	fileinfo_t *fi;

	d = src_get_download(srcid);
	download_check(d);

	fi = d->file_info;
	file_info_check(fi);

	/*
	 * We have new range information probably, so we need to recompute
	 * the rarest chunks.
	 */

	fi_update_rarest_chunks(fi);

	if (GNET_PROPERTY(fileinfo_debug) > 5)
		g_debug("%s(): updating ranges for %s", G_STRFUNC, fi->pathname);

	/*
	 * Look at all the download sources for this fileinfo and calculate the
	 * overall ranges info for this file, as determined by active sources
	 * which replied to us recently -- we not not take into account all sources.
	 */

	http_rangeset_free_null(&fi->seen_on_network);
	hrs = fi->seen_on_network = http_rangeset_create();

	PSLIST_FOREACH(fi->sources, sl) {
		struct download *src = sl->data;
		fileinfo_t *sfi;

		download_check(src);

		sfi = src->file_info;
		file_info_check(sfi);

		/*
		 * We only count the ranges of a file if it has replied to a recent
		 * request, and if the download request is not done or in an error
		 * state.
		 */

		if (
			(src->flags & DL_F_REPLIED) &&
			download_is_active(src)
		) {
			if (GNET_PROPERTY(fileinfo_debug) > 5)
				g_debug("- %s:%d replied (%s, flags=0x%x), ",
					host_addr_to_string(src->server->key->addr),
					src->server->key->port,
					download_status_to_string(src), src->flags);

			if (!sfi->use_swarming || !(src->flags & DL_F_PARTIAL)) {
				/*
				 * Indicate that the whole file is available.
				 */

				if (GNET_PROPERTY(fileinfo_debug) > 5)
					g_debug("   whole file is now available");

				http_rangeset_clear(hrs);
				http_rangeset_insert(hrs, 0, fi->size - 1);
				break;
			} else if (NULL == src->ranges) {
				/* Partial file with no known ranges, ignore */
				continue;
			} else {
				/* Merge in the new ranges */
				if (GNET_PROPERTY(fileinfo_debug) > 5) {
					g_debug("   ranges available: %s",
						http_rangeset_to_string(src->ranges));
				}

				http_rangeset_merge(hrs, src->ranges);
			}

			/*
			 * Stop looping if we have the full range covered.
			 */

			if (http_rangeset_length(hrs) == fi->size)
				break;
		}
	}

	if (GNET_PROPERTY(fileinfo_debug) > 5)
		g_debug("=> final ranges: %s", http_rangeset_to_string(hrs));

	/*
	 * Trigger a changed ranges event so that others can use the updated info.
	 */
	fi_event_trigger(d->file_info, EV_FI_RANGES_CHANGED);
}

struct file_info_foreach {
	file_info_foreach_cb callback;
	void *udata;
};

static void
file_info_foreach_helper(void *value, void *udata)
{
	struct file_info_foreach *data = udata;
    fileinfo_t *fi = value;

	file_info_check(fi);
	data->callback(fi->fi_handle, data->udata);
}

void
file_info_foreach(file_info_foreach_cb callback, void *udata)
{
	struct file_info_foreach data;

	g_return_if_fail(fi_by_guid);
	g_return_if_fail(callback);

	data.callback = callback;
	data.udata = udata;
	hikset_foreach(fi_by_guid, file_info_foreach_helper, &data);
}

const char *
file_info_status_to_string(const gnet_fi_status_t *status)
{
	static char buf[512];

	g_return_val_if_fail(status, NULL);

    if (status->recvcount) {
		uint32 secs;

		if (status->recv_last_rate) {
			secs = (status->size - status->done) / status->recv_last_rate;
		} else {
			secs = 0;
		}
        str_bprintf(buf, sizeof buf, _("Downloading (TR: %s)"),
			secs ? short_time(secs) : "-");
		goto dht_status;
    } else if (status->seeding) {
		return _("Seeding");
    } else if (status->verifying) {
		if (status->vrfy_hashed > 0) {
			str_bprintf(buf, sizeof buf,
					"%s %s (%.1f%%)",
					status->tth_check ?
						_("Computing TTH") : _("Computing SHA1"),
					short_size(status->vrfy_hashed,
						GNET_PROPERTY(display_metric_units)),
					(1.0 * status->vrfy_hashed / MAX(1, status->size)) * 100.0);
			return buf;
		} else {
			return status->tth_check ?
				_("Waiting for TTH check") : _("Waiting for SHA1 check");
		}
 	} else if (status->complete) {
		char msg_sha1[128], msg_copy[128];

		msg_sha1[0] = '\0';
		if (status->has_sha1) {
			str_bprintf(msg_sha1, sizeof msg_sha1, "%s %s",
				_("SHA1"),
				status->sha1_matched ? _("OK") :
				status->sha1_failed ? _("failed") : _("not computed yet"));
		}

		msg_copy[0] = '\0';
		if (status->moving) {
			if (0 == status->copied) {
				str_bprintf(msg_copy, sizeof msg_copy, "%s",
					_("Waiting for moving..."));
			} else if (status->copied > 0 && status->copied < status->size) {
				str_bprintf(msg_copy, sizeof msg_copy,
					"%s %s (%.1f%%)", _("Moving"),
					short_size(status->copied,
						GNET_PROPERTY(display_metric_units)),
					(1.0 * status->copied / status->size) * 100.0);
			}
		}

		concat_strings(buf, sizeof buf, _("Finished"),
			'\0' != msg_sha1[0] ? "; " : "", msg_sha1,
			'\0' != msg_copy[0] ? "; " : "", msg_copy,
			NULL_PTR);

		return buf;
    } else if (0 == status->lifecount) {
		g_strlcpy(buf, _("No sources"), sizeof buf);
		goto dht_status;
    } else if (status->active_queued || status->passive_queued) {
        str_bprintf(buf, sizeof buf,
            _("Queued (%u active, %u passive)"),
            status->active_queued, status->passive_queued);
		goto dht_status;
    } else if (status->paused) {
        return _("Paused");
    } else {
		g_strlcpy(buf, _("Waiting"), sizeof buf);
		/* FALL THROUGH */
    }

dht_status:
	{
		size_t w = strlen(buf);

		if (status->dht_lookup_running) {
			w += str_bprintf(&buf[w], sizeof buf - w, "; ");
			w += str_bprintf(&buf[w], sizeof buf - w,
				_("Querying DHT"));
		} else if (status->dht_lookup_pending) {
			w += str_bprintf(&buf[w], sizeof buf - w, "; ");
			w += str_bprintf(&buf[w], sizeof buf - w,
				_("Pending DHT query"));
		}

		if (status->dht_lookups != 0) {
			w += str_bprintf(&buf[w], sizeof buf - w, "; ");
			if (status->dht_values != 0) {
				w += str_bprintf(&buf[w], sizeof buf - w,
					NG_(
						"%u/%u successful DHT lookup",
						"%u/%u successful DHT lookups",
						status->dht_lookups),
					status->dht_values, status->dht_lookups);
			} else {
				w += str_bprintf(&buf[w], sizeof buf - w,
					NG_("%u DHT lookup", "%u DHT lookups", status->dht_lookups),
					status->dht_lookups);
			}
		}
	}

	return buf;
}

/**
 * Change the basename of a filename and rename it on-disk.
 * @return TRUE in case of success, FALSE on error.
 */
bool
file_info_rename(fileinfo_t *fi, const char *filename)
{
	bool success = FALSE;
	char *pathname;

	file_info_check(fi);
	g_return_val_if_fail(fi->hashed, FALSE);
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(filepath_basename(filename) == filename, FALSE);

	g_return_val_if_fail(!FILE_INFO_COMPLETE(fi), FALSE);
	g_return_val_if_fail(!(FI_F_TRANSIENT & fi->flags), FALSE);
	g_return_val_if_fail(!(FI_F_SEEDING & fi->flags), FALSE);
	g_return_val_if_fail(!(FI_F_STRIPPED & fi->flags), FALSE);

	{
		char *directory, *name;

		directory = filepath_directory(fi->pathname);
		name = filename_sanitize(filename, FALSE, FALSE);

		if (0 == strcmp(filepath_basename(fi->pathname), name)) {
			pathname = NULL;
			success = TRUE;
		} else {
			pathname = file_info_unique_filename(directory, name, "");
		}
		if (name != filename) {
			HFREE_NULL(name);
		}
		HFREE_NULL(directory);
	}
	if (NULL != pathname) {
		filestat_t sb;

		if (stat(fi->pathname, &sb)) {
			if (ENOENT == errno) {
				/* Assume file hasn't even been created yet */
				success = TRUE;
			}
		} else if (S_ISREG(sb.st_mode)) {
			success = file_object_rename(fi->pathname, pathname);
		}
		if (success) {
			file_info_moved(fi, pathname);
		}
		HFREE_NULL(pathname);
	}
	return success;
}

/**
 * hikset_foreach() iterator.
 *
 * Insert file info in list if it can be freed.
 */
static void
fi_test_completed(void *data, void *udata)
{
	fileinfo_t *fi = data;
	pslist_t **list = udata;

	file_info_check(fi);

	if (FILE_INFO_FINISHED(fi) && !(FI_F_SEEDING & fi->flags))
		*list = pslist_prepend(*list, fi);
}

/**
 * Clear completed entries that are not beeing seeded.
 */
void
file_info_clear_completed(void)
{
	pslist_t *to_remove = NULL, *sl;

	hikset_foreach(fi_by_guid, fi_test_completed, &to_remove);

	PSLIST_FOREACH(to_remove, sl) {
		fileinfo_t *fi = sl->data;
		file_info_purge(fi);
	}

	pslist_free(to_remove);
}

/**
 * Initialize fileinfo handling.
 */
void G_COLD
file_info_init(void)
{
	TOKENIZE_CHECK_SORTED(fi_tags);

	fi_by_sha1     = hikset_create(offsetof(fileinfo_t, sha1),
						HASH_KEY_FIXED, SHA1_RAW_SIZE);
	fi_by_namesize = htable_create_any(namesize_hash, NULL, namesize_eq);
	fi_by_guid     = hikset_create(offsetof(fileinfo_t, guid),
						HASH_KEY_FIXED, GUID_RAW_SIZE);
	fi_by_outname  = hikset_create(offsetof(fileinfo_t, pathname),
						HASH_KEY_STRING, 0);

    fi_handle_map = idtable_new(32);

    fi_events[EV_FI_ADDED]          = event_new("fi_added");
    fi_events[EV_FI_REMOVED]        = event_new("fi_removed");
    fi_events[EV_FI_INFO_CHANGED]   = event_new("fi_info_changed");
	fi_events[EV_FI_RANGES_CHANGED] = event_new("fi_ranges_changed");
    fi_events[EV_FI_STATUS_CHANGED] = event_new("fi_status_changed");
    fi_events[EV_FI_STATUS_CHANGED_TRANSIENT] =
									  event_new("fi_status_changed_transient");

	src_handle_map = idtable_new(32);

	src_events[EV_SRC_ADDED]			= event_new("src_added");
	src_events[EV_SRC_REMOVED]			= event_new("src_removed");
	src_events[EV_SRC_INFO_CHANGED]		= event_new("src_info_changed");
	src_events[EV_SRC_STATUS_CHANGED]	= event_new("src_status_changed");
	src_events[EV_SRC_RANGES_CHANGED]	= event_new("src_ranges_changed");
}

/**
 * Finish initialization of fileinfo handling. This post initialization is
 * needed to avoid circular dependencies during the init phase.
 */
void
file_info_init_post(void)
{
	/*
	 * The listener we set up here is set up in download_init(), but that must
	 * be called after file_info_init() to subscribe to src events on available
	 * range updates
	 */

	src_add_listener(fi_update_seen_on_network, EV_SRC_RANGES_CHANGED,
		FREQ_SECS, 0);

	/*
	 * Signal that so late in the initialization path, it is now possible
	 * to record new fileinfo SHA-1 for publishing (when PFSP is enabled).
	 * Then attempt publishing of already retrieved files.
	 *
	 */

	can_publish_partial_sha1 = TRUE;
	fi_publish_all();
}

/*
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4 sw=4 cindent:
 */
