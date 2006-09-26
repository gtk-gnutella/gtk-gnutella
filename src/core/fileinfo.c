/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Vidar Madsen & Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "fileinfo.h"
#include "file_object.h"
#include "sockets.h"
#include "downloads.h"
#include "uploads.h"
#include "hosts.h"
#include "routing.h"
#include "routing.h"
#include "gmsg.h"
#include "bsched.h"
#include "huge.h"
#include "dmesh.h"
#include "search.h"
#include "guid.h"
#include "share.h"
#include "settings.h"
#include "nodes.h"
#include "namesize.h"
#include "http.h"					/* For http_range_t */

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/fuzzy.h"
#include "lib/header.h"
#include "lib/idtable.h"
#include "lib/magnet.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/glib-missing.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"			/* Must be the last header included */

#define FI_MIN_CHUNK_SPLIT	512		/**< Smallest chunk we can split */
#define FI_MAX_FIELD_LEN	1024	/**< Max field length we accept to save */

struct dl_file_chunk {
	filesize_t from;				/**< Range offset start (byte included) */
	filesize_t to;					/**< Range offset end (byte EXCLUDED) */
	enum dl_chunk_status status;	/**< Status of range */
	struct download *download;		/**< Download that "reserved" the range */
};

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
 * The `fi_by_size' hash table keeps track of the fi with identical file size.
 */

static GHashTable *fi_by_sha1 = NULL;
static GHashTable *fi_by_namesize = NULL;
static GHashTable *fi_by_size = NULL;
static GHashTable *fi_by_outname = NULL;
static GHashTable *fi_by_guid = NULL;

static const gchar file_info_file[] = "fileinfo";
static const gchar file_info_what[] = "the fileinfo database";
static gboolean fileinfo_dirty = FALSE;
static gboolean can_swarm = FALSE;		/**< Set by file_info_retrieve() */

#define	FILE_INFO_MAGIC32 0xD1BB1ED0U
#define	FILE_INFO_MAGIC64 0X91E63640U

typedef guint32 fi_magic_t;

#define FILE_INFO_VERSION	6

enum dl_file_info_field {
	FILE_INFO_FIELD_NAME = 1,	/**< No longer used in 32-bit version >= 3 */
	FILE_INFO_FIELD_ALIAS,
	FILE_INFO_FIELD_SHA1,
	FILE_INFO_FIELD_CHUNK,
	FILE_INFO_FIELD_END,		/**< Marks end of field section */
	FILE_INFO_FIELD_CHA1,
	FILE_INFO_FIELD_GUID,
	/* Add new fields here, never change ordering for backward compatibility */

	NUM_FILE_INFO_FIELDS
};

#define FI_STORE_DELAY		10	/**< Max delay (secs) for flushing fileinfo */
#define FI_TRAILER_INT		6	/**< Amount of guint32 in the trailer */

/**
 * The swarming trailer is built within a memory buffer first, to avoid having
 * to issue mutliple write() system calls.	We can't use stdio's buffering
 * since we can sometime reuse the download's file descriptor.
 */
static struct {
	gchar *arena;			/**< Base arena */
	gchar *wptr;			/**< Write pointer */
	gchar *rptr;			/**< Read pointer */
	gchar *end;				/**< First byte off arena */
	guint32 size;			/**< Current size of arena */
} tbuf;

#define TBUF_SIZE			512		/**< Initial trailing buffer size */
#define TBUF_GROW_BITS		9		/**< Growing chunks */

#define TBUF_GROW			(1 << TBUF_GROW_BITS)
#define TBUF_GROW_MASK		(TBUF_GROW - 1)

#define round_grow(x)		\
	((guint32) (((guint32) (x) + TBUF_GROW_MASK) & ~TBUF_GROW_MASK))

#define trunc_int32(x)		\
	((gulong) ((gulong) (x) & ~(sizeof(guint32) - 1)))

#define int32_aligned(x)	\
	((gulong) (x) == trunc_int32(x))

/*
 * Low level trailer buffer read/write macros.
 */

#define TBUF_INIT_READ(s) do {			\
	if ((tbuf.arena + (s)) > tbuf.end)	\
		tbuf_extend(s, FALSE);			\
	tbuf.wptr = NULL;					\
	tbuf.rptr = tbuf.arena;				\
	tbuf.end = tbuf.arena + (s);		\
} while (0)

#define TBUF_INIT_WRITE() do {			\
	tbuf.rptr = NULL;					\
	tbuf.wptr = tbuf.arena;				\
	tbuf.end = tbuf.arena + tbuf.size;	\
} while (0)

#define TBUF_WRITTEN_LEN()	(tbuf.wptr - tbuf.arena)

#define TBUF_CHECK(x) do {				\
	if ((tbuf.wptr + (x)) > tbuf.end)	\
		tbuf_extend(x, TRUE);			\
} while (0)

#define TBUF_GETCHAR(x) do {			\
	if (tbuf.rptr + sizeof(guint8) <= tbuf.end) { \
		*x = *(guint8 *) tbuf.rptr;		\
		tbuf.rptr++;					\
	} else								\
		goto eof;						\
} while (0)

#define TBUF_GETINT32(x) do {			\
	if (tbuf.rptr + sizeof(gint32) <= tbuf.end) { \
		if (int32_aligned(tbuf.rptr))	\
			*x = *(gint32 *) tbuf.rptr; \
		else							\
			memcpy(x, tbuf.rptr, sizeof(gint32)); \
		tbuf.rptr += sizeof(gint32);	\
	} else								\
		goto eof;						\
} while (0)

#define TBUF_READ(x,s) do {				\
	if ((tbuf.rptr + (s)) <= tbuf.end) { \
		memcpy(x, tbuf.rptr, s);		\
		tbuf.rptr += s;					\
	} else								\
		goto eof;						\
} while (0)

#define TBUF_PUTCHAR(x) do {			\
	TBUF_CHECK(sizeof(guint8));			\
	*(guint8 *) tbuf.wptr = x;			\
	tbuf.wptr++;						\
} while (0)

#define TBUF_PUTINT32(x) do {			\
	TBUF_CHECK(sizeof(guint32));		\
	if (int32_aligned(tbuf.wptr))		\
		*(guint32 *) tbuf.wptr = x;		\
	else								\
		memcpy(tbuf.wptr, &x, sizeof(gint32));	\
	tbuf.wptr += sizeof(gint32);		\
} while (0)

#define TBUF_WRITE(x,s) do {			\
	TBUF_CHECK(s);						\
	memcpy(tbuf.wptr, x, s);			\
	tbuf.wptr += s;						\
} while (0)

/*
 * High-level write macros.
 */

#define WRITE_CHAR(a) do {			\
	guint8 val = a;					\
	TBUF_PUTCHAR(val);				\
	file_info_checksum(&checksum, (gchar *) &val, sizeof(val)); \
} while (0)

#define WRITE_INT32(a) do {			\
	gint32 val = htonl(a);			\
	TBUF_PUTINT32(val);				\
	file_info_checksum(&checksum, (gchar *) &val, sizeof(val)); \
} while(0)

#define WRITE_UINT32(a) do {			\
	guint32 val = htonl(a);			\
	TBUF_PUTINT32(val);				\
	file_info_checksum(&checksum, (gchar *) &val, sizeof(val)); \
} while(0)

#define WRITE_STR(a, b) do {		\
	TBUF_WRITE(a, b);				\
	file_info_checksum(&checksum, (gchar *) a, b); \
} while(0)

/*
 * High-level read macros.
 */

#define READ_CHAR(a) do {			\
	guint8 val;						\
	TBUF_GETCHAR(&val);				\
	file_info_checksum(&checksum, (gchar *) &val, sizeof(val)); \
} while(0)

#define READ_INT32(a) do {			\
	gint32 val;						\
	TBUF_GETINT32(&val);			\
	STATIC_ASSERT(sizeof val <= sizeof(*a)); \
	*a = ntohl(val);				\
	file_info_checksum(&checksum, (gchar *) &val, sizeof(val)); \
} while(0)

#define READ_STR(a, b) do {			\
	TBUF_READ(a, b);				\
	file_info_checksum(&checksum, (gchar *) a, b); \
} while(0)

/*
 * Addition of a variable-size trailer field.
 */

#define FIELD_ADD(a,b,c) do {		\
	guint32 l = (b);				\
	WRITE_INT32(a);					\
	WRITE_INT32(l);					\
	WRITE_STR(c, l);				\
} while(0)

/**
 * The trailer fields of the fileinfo trailer.
 */

struct trailer {
	guint64 filesize;		/**< Real file size */
	guint32 generation;		/**< Generation number */
	guint32 length;			/**< Total trailer length */
	guint32 checksum;		/**< Trailer checksum */
	fi_magic_t magic;		/**< Magic number */
};

static fileinfo_t *file_info_retrieve_binary(
	const gchar *file, const gchar *path);
static void fi_free(fileinfo_t *fi);
static void file_info_hash_remove(fileinfo_t *fi);
static void fi_update_seen_on_network(gnet_src_t srcid);
static gchar *file_info_new_outname(const gchar *name, const gchar *dir);
static gboolean looks_like_urn(const gchar *filename);

static idtable_t *fi_handle_map = NULL;

#define file_info_find_by_handle(n) \
    (fileinfo_t *) idtable_get_value(fi_handle_map, n)

#define file_info_request_handle(n) \
    idtable_new_id(fi_handle_map, n)

#define file_info_drop_handle(n) \
    idtable_free_id(fi_handle_map, n);

event_t *fi_events[EV_FI_EVENTS] = {
    NULL, NULL, NULL, NULL, NULL, NULL };

/**
 * Checks the kind of trailer. The trailer must be initialized.
 *
 * @return TRUE if the trailer is the 64-bit version, FALSE if it's 32-bit.
 */
static inline gboolean
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
 * Make sure there is enough room in the buffer for `x' more bytes.
 * If `writing' is TRUE, we update the write pointer.
 */
static void
tbuf_extend(guint32 x, gboolean writing)
{
	gint new_size = round_grow(x + tbuf.size);
	gint offset = tbuf.wptr - tbuf.arena;

	tbuf.arena = g_realloc(tbuf.arena, new_size);
	tbuf.end = tbuf.arena + new_size;
	tbuf.size = new_size;

	if (writing)
		tbuf.wptr = tbuf.arena + offset;
}

/**
 * Write trailer buffer at current position on `fd', whose name is `name'.
 */
static void
tbuf_write(const struct file_object *fo, filesize_t offset)
{
	size_t size = TBUF_WRITTEN_LEN();
	ssize_t ret;

	g_assert(fo);
	g_assert(size > 0);

	ret = file_object_pwrite(fo, tbuf.arena, size, offset);
	if ((ssize_t) -1 == ret || (size_t) ret != size) {
		const gchar *error;

		error = (ssize_t) -1 == ret ? g_strerror(errno) : "Unknown error";
		g_warning("error while flushing trailer info for \"%s\": %s",
			file_object_get_pathname(fo), error);
	}
}

/**
 * Read trailer buffer at current position from `fd'.
 *
 * @returns -1 on error.
 */
static gint
tbuf_read(gint fd, gint len)
{
	g_assert(fd >= 0);

	TBUF_INIT_READ(len);

	return read(fd, tbuf.arena, len);
}

static inline void
file_info_checksum(guint32 *checksum, gchar *d, int len)
{
	while (len--)
		*checksum = (*checksum << 1) ^ (*checksum >> 31) ^ (guchar) *d++;
}

/**
 * Checks the chunklist of fi.
 *
 * @param fi		the fileinfo struct to check.
 * @param assertion	no document
 *
 * @return TRUE if chunklist is consistent, FALSE otherwise.
 */
static gboolean
file_info_check_chunklist(fileinfo_t *fi, gboolean assertion)
{
	GSList *sl;
	filesize_t last = 0;

	/*
	 * This routine ends up being a CPU hog when all the asserts using it
	 * are run.  Do that only when debugging.
	 */

	if (assertion && !fileinfo_debug)
		return TRUE;

	file_info_check(fi);

	for (sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;

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
file_info_fd_store_binary(fileinfo_t *fi,
	const struct file_object *fo, gboolean force)
{
	GSList *fclist;
	GSList *a;
	guint32 checksum = 0;
	guint32 length;

	g_assert(fo);

	/*
	 * Don't flush unless required or some delay occurred since last flush.
	 */

	if (force || fi->stamp - fi->last_flush >= FI_STORE_DELAY)
		fi->last_flush = fi->stamp;
	else
		return;

	TBUF_INIT_WRITE();
	WRITE_INT32(FILE_INFO_VERSION);

	/*
	 * Emit leading binary fields.
	 */

	WRITE_INT32(fi->ctime);				/* Introduced at: version 4 */
	WRITE_INT32(fi->ntime);				/* version 4 */
	WRITE_CHAR(fi->file_size_known);	/* Introduced at: version 5 */

	/*
	 * Emit variable-length fields.
	 */

	FIELD_ADD(FILE_INFO_FIELD_GUID, GUID_RAW_SIZE, fi->guid);

	if (fi->sha1)
		FIELD_ADD(FILE_INFO_FIELD_SHA1, SHA1_RAW_SIZE, fi->sha1);

	if (fi->cha1)
		FIELD_ADD(FILE_INFO_FIELD_CHA1, SHA1_RAW_SIZE, fi->cha1);

	for (a = fi->alias; a; a = a->next) {
		gint len = strlen(a->data);		/* Do not store the trailing NUL */
		g_assert(len >= 0);
		if (len < FI_MAX_FIELD_LEN)
			FIELD_ADD(FILE_INFO_FIELD_ALIAS, len, a->data);
	}

	g_assert(file_info_check_chunklist(fi, TRUE));
	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		struct dl_file_chunk *fc = fclist->data;
		guint32 from_hi = (guint64) fc->from >> 32;
		guint32 to_hi = (guint64) fc->to >> 32;
		guint32 chunk[5];

		chunk[0] = htonl(from_hi),
		chunk[1] = htonl((guint32) fc->from),
		chunk[2] = htonl(to_hi),
		chunk[3] = htonl((guint32) fc->to),
		chunk[4] = htonl(fc->status);
		FIELD_ADD(FILE_INFO_FIELD_CHUNK, sizeof chunk, chunk);
	}

	fi->generation++;

	WRITE_INT32(FILE_INFO_FIELD_END);

	STATIC_ASSERT((guint64) -1 >= (filesize_t) -1);
	WRITE_INT32((guint32) ((guint64) fi->size >> 32));
	WRITE_INT32((guint32) fi->size);
	WRITE_INT32(fi->generation);

	length = TBUF_WRITTEN_LEN() + 3 * sizeof(guint32);

	WRITE_INT32(length);				/* Total trailer size */
	WRITE_INT32(checksum);
	WRITE_UINT32(FILE_INFO_MAGIC64);

	/* Flush buffer at current position */
	tbuf_write(fo, fi->size);

	if (0 != ftruncate(file_object_get_fd(fo), fi->size + length))
		g_warning("file_info_fd_store_binary(): truncate() failed: %s",
			g_strerror(errno));

	fi->dirty = FALSE;
	fileinfo_dirty = TRUE;
}

/**
 * Store a binary record of the file metainformation at the end of the
 * output file, if it exists.
 */
void
file_info_store_binary(fileinfo_t *fi)
{
	struct file_object *fo;

	g_assert(!(fi->flags & FI_F_TRANSIENT));

	/*
	 * We don't create the file if it does not already exist.  That way,
	 * a file is only created when at least one byte of data is downloaded,
	 * since then we'll go directly to file_info_fd_store_binary().
	 */

	{
		char *path = make_pathname(fi->path, fi->file_name);

		fo = file_object_open(path, O_WRONLY);
		if (!fo) {
			gint fd = file_open_missing(path, O_WRONLY);
			if (fd >= 0) {
				fo = file_object_new(fd, path, O_WRONLY);
			}
		}
		G_FREE_NULL(path);
	}
	if (fo) {
		fi->stamp = tm_time();
		file_info_fd_store_binary(fi, fo, TRUE);	/* Force flush */
		file_object_release(&fo);
	}
}

/**
 * Strips the file metainfo trailer off a file.
 */
void
file_info_strip_binary(fileinfo_t *fi)
{
	char *path;

	g_assert(!(fi->flags & FI_F_TRANSIENT));

	path = make_pathname(fi->path, fi->file_name);
	g_return_if_fail(NULL != path);

	if (-1 == truncate(path, fi->size))
		g_warning("could not chop fileinfo trailer off \"%s\": %s",
			path, g_strerror(errno));
	G_FREE_NULL(path);
}

/**
 * Strips the file metainfo trailer off specified file.
 */
void
file_info_strip_binary_from_file(fileinfo_t *fi, const gchar *file)
{
	fileinfo_t *dfi;

	g_assert(G_DIR_SEPARATOR == file[0]);	/* Absolute path given */
	g_assert(!(fi->flags & FI_F_TRANSIENT));

	/*
	 * Before truncating the file, we must be really sure it is reasonnably
	 * matching the fileinfo structure we have for it: retrieve the binary
	 * trailer, and check size / completion.
	 */

	dfi = file_info_retrieve_binary(file, "");

	if (NULL == dfi) {
		g_warning("could not chop fileinfo trailer off \"%s\": file does "
			"not seem to have a valid trailer", file);
		return;
	}

	if (dfi->size != fi->size || dfi->done != fi->done) {
		gchar buf[64];

		concat_strings(buf, sizeof buf,
			uint64_to_string(dfi->done), "/",
			uint64_to_string2(dfi->size), (void *) 0);
		g_warning("could not chop fileinfo trailer off \"%s\": file was "
			"different than expected (%s bytes done instead of %s/%s)",
			file, buf, uint64_to_string(fi->done), uint64_to_string2(fi->size));
	} else if (-1 == truncate(file, fi->size))
		g_warning("could not chop fileinfo trailer off \"%s\": %s",
			file, g_strerror(errno));

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
	GSList *sl;

	file_info_check(fi);

	for (sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl))
		wfree(sl->data, sizeof(struct dl_file_chunk));
	g_slist_free(fi->chunklist);
	fi->chunklist = NULL;
}

/**
 * Free a `file_info' structure.
 */
static void
fi_free(fileinfo_t *fi)
{
	file_info_check(fi);
	g_assert(!fi->hashed);

	/* Make sure "fi" isn't in any of the hashtables anymore. */
	{
		GSList *sl;
	
		if (fi->size_atom) {
			g_assert(fi->size == *fi->size_atom);
		}

		sl = g_hash_table_lookup(fi_by_size, &fi->size);
		g_assert(!gm_slist_is_looping(sl));
		g_assert(!g_slist_find(sl, fi));
		g_assert(!g_slist_find(sl, NULL));
	}

#if 0
	/* This does not seem to be a bug; see file_info_remove_source(). */
	if (fi->sha1) {
		g_assert(fi != g_hash_table_lookup(fi_by_sha1, fi->sha1));
	}
#endif

	/*
	 * Stop all uploads occurring for this file.
	 */

	if (NULL != fi->sf) {
		file_info_upload_stop(fi, "File info discarded");
		g_assert(NULL == fi->sf);
	}

	atom_filesize_free_null(&fi->size_atom);
	atom_guid_free_null(&fi->guid);
	atom_str_free_null(&fi->file_name);
	atom_str_free_null(&fi->path);
	atom_sha1_free_null(&fi->sha1);
	atom_sha1_free_null(&fi->cha1);

	if (fi->chunklist) {
		g_assert(file_info_check_chunklist(fi, TRUE));
		file_info_chunklist_free(fi);
	}
	if (fi->alias) {
		GSList *sl;

		for (sl = fi->alias; NULL != sl; sl = g_slist_next(sl)) {
			gchar *s = sl->data;
			atom_str_free_null(&s);
		}
		g_slist_free(fi->alias);
		fi->alias = NULL;
	}
	if (fi->seen_on_network)
		fi_free_ranges(fi->seen_on_network);

	fi->magic = 0;
	wfree(fi, sizeof *fi);
}

static void
file_info_hash_insert_name_size(fileinfo_t *fi)
{
	namesize_t nsk;
	GSList *sl;

	file_info_check(fi);
	g_assert(fi->file_size_known);
	g_assert(fi->size_atom);

	if (FI_F_TRANSIENT & fi->flags)
		return;

	/*
	 * The (name, size) tuples also point to a list of entries, one for
	 * each of the name aliases.  Ideally, we'd want only one, but there
	 * can be name conflicts.  This does not matter unless they disabled
	 * strict SHA1 matching...  but that is a dangerous move.
	 */

	nsk.size = fi->size;

	for (sl = fi->alias; NULL != sl; sl = g_slist_next(sl)) {
		GSList *slist;
		
		nsk.name = sl->data;
		slist = g_hash_table_lookup(fi_by_namesize, &nsk);

		if (NULL != slist) {
			slist = g_slist_append(slist, fi);
		} else {
			namesize_t *ns = namesize_make(nsk.name, nsk.size);
			slist = g_slist_append(slist, fi);
			g_hash_table_insert(fi_by_namesize, ns, slist);
		}
	}

	/*
	 * Finally, for a given size, maintain a list of fi's.
	 *
	 * NB: the key used here is the size_atom, as it must be shared accross
	 * all the `fi' structs with the same size!
	 */

	g_assert(*(const filesize_t *) fi->size_atom == fi->size);

	sl = g_hash_table_lookup(fi_by_size, fi->size_atom);
	g_assert(!gm_slist_is_looping(sl));
	g_assert(!g_slist_find(sl, NULL));
	g_assert(!g_slist_find(sl, fi));
	
	if (NULL != sl) {
		sl = g_slist_append(sl, fi);
	} else {
		sl = g_slist_append(sl, fi);
		g_assert(NULL != sl);
		g_hash_table_insert(fi_by_size, fi->size_atom, sl);
	}
	g_assert(!gm_slist_is_looping(sl));
	g_assert(!g_slist_find(sl, NULL));
	g_assert(g_slist_find(sl, fi));
}

/**
 * Resize fileinfo to be `size' bytes, by adding empty chunk at the tail.
 */
static void
fi_resize(fileinfo_t *fi, filesize_t size)
{
	struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(fi->size < size);
	g_assert(!fi->hashed);

	fc = walloc0(sizeof *fc);
	fc->from = fi->size;
	fc->to = size;
	fc->status = DL_CHUNK_EMPTY;
	fi->chunklist = g_slist_append(fi->chunklist, fc);

	/*
	 * Don't remove/re-insert `fi' from hash tables: when this routine is
	 * called, `fi' is no longer "hashed", or has never been "hashed".
	 */

	g_assert(fi->size_atom);

	atom_filesize_free_null(&fi->size_atom);
	fi->size = size;
	fi->size_atom = atom_filesize_get(&fi->size);

	g_assert(file_info_check_chunklist(fi, TRUE));
}

/**
 * Add `name' as an alias for `fi' if not already known.
 * If `record' is TRUE, also record new alias entry in `fi_by_namesize'.
 */
static void
fi_alias(fileinfo_t *fi, const gchar *name, gboolean record)
{
	namesize_t *ns;
	GSList *list;

	file_info_check(fi);
	g_assert(!record || fi->hashed);	/* record => fi->hashed */

	/*
	 * The fastest way to know if this alias exists is to lookup the
	 * fi_by_namesize table, since all the aliases are inserted into
	 * that table.
	 */
	
	ns = namesize_make(name, fi->size);
	list = g_hash_table_lookup(fi_by_namesize, ns);
	if (NULL != list && NULL != g_slist_find(list, fi)) {
		/* Alias already known */
	} else if (looks_like_urn(name)) {
		/* This is often caused by (URN entries in) the dmesh */
	} else {

		/*
		 * Insert new alias for `fi'.
		 */

		fi->alias = g_slist_append(fi->alias, atom_str_get(name));

		if (record) {
			if (NULL != list)
				list = g_slist_append(list, fi);
			else {
				list = g_slist_append(list, fi);
				g_hash_table_insert(fi_by_namesize, ns, list);
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
static gboolean
file_info_get_trailer(gint fd, struct trailer *tb, const gchar *name)
{
	ssize_t r;
	fi_magic_t magic;
	guint32 tr[FI_TRAILER_INT];
	struct stat buf;
	off_t offset;
	guint64 filesize_hi;
	size_t i = 0;

	g_assert(fd >= 0);
	g_assert(tb);

	if (-1 == fstat(fd, &buf)) {
		g_warning("error fstat()ing \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	if (!S_ISREG(buf.st_mode)) {
		g_warning("Not a regular file: \"%s\"", name);
		return FALSE;
	}

	if (buf.st_size < (off_t) sizeof tr)
		return FALSE;

	/*
	 * Don't use SEEK_END with "-sizeof(tr)" to avoid problems when off_t is
	 * defined as an 8-byte wide quantity.  Since we have the file size
	 * already, better use SEEK_SET.
	 *		--RAM, 02/02/2003 after a bug report from Christian Biere
	 */

	offset = buf.st_size - sizeof tr;		/* Start of trailer */

	/* No wrapper because this is a native off_t value. */
	if (offset != lseek(fd, offset, SEEK_SET)) {
		g_warning("file_info_get_trailer(): "
			"error seek()ing in file \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	r = read(fd, tr, sizeof tr);
	if ((ssize_t) -1 == r) {
		g_warning("file_info_get_trailer(): "
			"error reading trailer in  \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}


	/*
	 * Don't continue if the number of bytes read is smaller than
	 * the minimum number of bytes needed.
	 *		-- JA 12/02/2004
	 */
	if (r < (ssize_t) sizeof tr)
		return FALSE;

	filesize_hi = 0;
	magic = ntohl(tr[5]);
	switch (magic) {
	case FILE_INFO_MAGIC64:
		filesize_hi	= ((guint64) ((guint32) ntohl(tr[0]))) << 32;
		/* FALLTHROUGH */
	case FILE_INFO_MAGIC32:
		tb->filesize = filesize_hi | ((guint32) ntohl(tr[1]));
		i = 2;
		break;
	}
	if (2 != i) {
		return FALSE;
	}

	for (/* NOTHING */; i < G_N_ELEMENTS(tr); i++) {
		guint32 v = ntohl(tr[i]);

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

	if ((guint64) buf.st_size != tb->filesize + tb->length) {
		return FALSE;
	}

	return TRUE;
}

/**
 * Check whether file has a trailer.
 */
gboolean
file_info_has_trailer(const gchar *path)
{
	struct trailer trailer;
	gint fd;
	gboolean valid;

	fd = file_open_missing(path, O_RDONLY);
	if (fd < 0)
		return FALSE;

	valid = file_info_get_trailer(fd, &trailer, path);
	close(fd);

	return valid;
}

/**
 * @returns TRUE if a file_info struct has a matching file name or alias,
 * and FALSE if not.
 */
static gboolean
file_info_has_filename(fileinfo_t *fi, const gchar *file)
{
	const GSList *sl;

	for (sl = fi->alias; sl; sl = g_slist_next(sl)) {
		/* XXX: UTF-8, locale, what's the proper encoding here? */
		if (0 == ascii_strcasecmp(sl->data, file))
			return TRUE;
	}

	if (use_fuzzy_matching) {
		for (sl = fi->alias; sl; sl = g_slist_next(sl)) {
			gulong score = 100 * fuzzy_compare(sl->data, file);
			if (score >= (fuzzy_threshold << FUZZY_SHIFT)) {
				g_warning("fuzzy: \"%s\"  ==  \"%s\" (score %f)",
					cast_to_gchar_ptr(sl->data), file, score / 100.0);
				fi_alias(fi, file, TRUE);
				return TRUE;
			}
		}
	}

	return FALSE;
}

/**
 * Lookup our existing fileinfo structs to see if we can spot one
 * referencing the supplied file `name' and `size', as well as the
 * optional `sha1' hash.
 *
 * @returns the fileinfo structure if found, NULL otherwise.
 */
static fileinfo_t *
file_info_lookup(const gchar *name, filesize_t size, const gchar *sha1)
{
	fileinfo_t *fi;
	GSList *list, *sl;

	/*
	 * If we have a SHA1, this is our unique key.
	 */

	if (NULL != sha1) {
		fi = g_hash_table_lookup(fi_by_sha1, sha1);
		if (fi) {
			file_info_check(fi);
			return fi;
		}

		/*
		 * No need to continue if strict SHA1 matching is enabled.
		 * If the entry is not found in the `fi_by_sha1' table, then
		 * nothing can be found for this SHA1.
		 */

		if (strict_sha1_matching)
			return NULL;
	}

	if (0 == size) {
		return NULL;
	}

	/*
	 * Look for a matching (name, size) tuple.
	 */
	{
		struct namesize nsk;

		nsk.name = deconstify_gchar(name);
		nsk.size = size;

		list = g_hash_table_lookup(fi_by_namesize, &nsk);
		g_assert(!gm_slist_is_looping(list));
		g_assert(!g_slist_find(list, NULL));
	}

	if (NULL != list && NULL == g_slist_next(list)) {
		fi = list->data;
		file_info_check(fi);

		/* FIXME: FILE_SIZE_KNOWN: Should we provide another lookup?
		 *	-- JA 2004-07-21
		 */
		if (fi->file_size_known)
			g_assert(fi->size == size);
		return fi;
	}

	/*
	 * Look for a matching name, given the size.
	 */

	list = g_hash_table_lookup(fi_by_size, &size);
	g_assert(!gm_slist_is_looping(list));
	g_assert(!g_slist_find(list, NULL));

	for (sl = list; sl; sl = g_slist_next(sl)) {
		fi = sl->data;
		file_info_check(fi);

		/* FIXME: FILE_SIZE_KNOWN: Should we provide another lookup?
		 *	-- JA 2004-07-21
		 */
		if (fi->file_size_known)
			g_assert(fi->size == size);

		if (file_info_has_filename(fi, name))
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

	dfi = g_hash_table_lookup(fi_by_outname, fi->file_name);
	if (dfi) {
		file_info_check(dfi);
		return dfi;
	}

	/*
	 * If `fi' has a SHA1, find any other entry bearing the same SHA1.
	 */

	if (fi->sha1) {
		dfi = g_hash_table_lookup(fi_by_sha1, fi->sha1);
		if (dfi) {
			file_info_check(dfi);
			return dfi;
		}
	}

	/*
	 * The file ID must also be unique.
	 */

	dfi = g_hash_table_lookup(fi_by_guid, fi->guid);
	if (dfi) {
		file_info_check(dfi);
		return dfi;
	}
	return NULL;
}

/**
 * Check whether filename looks like an URN.
 */
static gboolean
looks_like_urn(const gchar *filename)
{
	const gchar *p, *q;
	guint i;

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
const gchar *
file_info_readable_filename(const fileinfo_t *fi)
{
	const GSList *sl;

	file_info_check(fi);

	if (looks_like_urn(fi->file_name)) {
		for (sl = fi->alias; sl; sl = g_slist_next(sl)) {
			const gchar *name = sl->data;
			if (!looks_like_urn(name))
				return name;
		}
	}

	return fi->file_name;
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
file_info_shared_sha1(const gchar *sha1)
{
	fileinfo_t *fi;

	fi = g_hash_table_lookup(fi_by_sha1, sha1);
	if (!fi)
		return NULL;

	file_info_check(fi);
	if (0 == fi->done || fi->size < pfsp_minimum_filesize)
		return NULL;

	g_assert(NULL != fi->sha1);

	/*
	 * Build shared_file entry if not already present.
	 */

	if (NULL == fi->sf) {
		static const shared_file_t zero_sf;
		shared_file_t *sf;
		const gchar *filename;
		gchar *path, *q;

		sf = walloc(sizeof *sf);
		*sf = zero_sf;

		/*
		 * Determine a proper human-readable name for the file.
		 * If it is an URN, look through the aliases.
		 */

		filename = file_info_readable_filename(fi);

		q = filename_to_utf8_normalized(filename, UNI_NORM_NETWORK);
		sf->name_nfc = atom_str_get(q);
		if (q != filename)
			G_FREE_NULL(q);

		q = UNICODE_CANONIZE(sf->name_nfc);
		sf->name_canonic = atom_str_get(q);
		if (q != sf->name_nfc)
			G_FREE_NULL(q);

		sf->name_nfc_len = strlen(sf->name_nfc);
		sf->name_canonic_len = strlen(sf->name_canonic);

		if (0 == sf->name_nfc_len || 0 == sf->name_canonic_len) {
			atom_str_free(sf->name_nfc);
			atom_str_free(sf->name_canonic);
			wfree(sf, sizeof *sf);
			return NULL;
		}

		path = make_pathname(fi->path, fi->file_name);
		g_assert(NULL != path);

		fi->sf = shared_file_ref(sf);
		sf->fi = fi;		/* Signals it's a partially downloaded file */

		/* FIXME: DOWNLOAD_SIZE:
		 * Do we need to add anything here now that fileinfos can have an
		 *  unknown length? --- Emile
		 */
		sf->file_size = fi->size;
		sf->file_index = URN_INDEX;
		sf->mtime = fi->last_flush;
		sf->flags = SHARE_F_HAS_DIGEST;
		sf->content_type = share_mime_type(SHARE_M_APPLICATION_BINARY);

		memcpy(sf->sha1_digest, fi->sha1, SHA1_RAW_SIZE);

		sf->file_path = atom_str_get(path);
		G_FREE_NULL(path);
	}

	return fi->sf;
}

/**
 * Allocate random GUID to use as the file ID.
 *
 * @return a GUID atom, refcount incremented already.
 */
static gchar *
fi_random_guid_atom(void)
{
	gchar xuid[GUID_RAW_SIZE];
	gint i;

	/*
	 * Paranoid, in case the random number generator is broken.
	 */

	for (i = 0; i < 100; i++) {
		guid_random_fill(xuid);

		if (NULL == g_hash_table_lookup(fi_by_guid, xuid))
			return atom_guid_get(xuid);
	}

	g_error("no luck with random number generator");
	return NULL;
}

/**
 * Ensure potentially old fileinfo structure is brought up-to-date by
 * inferring or allocating missing fields.
 *
 * @return TRUE if an upgrade was necessary.
 */
static gboolean
fi_upgrade_older_version(fileinfo_t *fi)
{
	gboolean upgraded = FALSE;

	file_info_check(fi);

	/*
	 * Ensure proper timestamps for creation and update times.
	 */

	if (0 == fi->ctime) {
		fi->ctime = tm_time();
		upgraded = TRUE;
	}

	if (0 == fi->ntime) {
		fi->ntime = fi->ctime;
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

/**
 * Reads the file metainfo from the trailer of a file, if it exists.
 *
 * @returns a pointer to the info structure if found, and NULL otherwise.
 */
static fileinfo_t *
file_info_retrieve_binary(const gchar *file, const gchar *path)
{
	guint32 tmpchunk[5];
	guint32 tmpguint;
	guint32 checksum = 0;
	fileinfo_t *fi = NULL;
	enum dl_file_info_field field;
	gchar tmp[FI_MAX_FIELD_LEN + 1];	/* +1 for trailing NUL on strings */
	gchar *reason;
	gchar *pathname;
	gint fd;
	guint32 version;
	struct trailer trailer;
	gboolean t64;
	GSList *chunklist = NULL;

#define BAILOUT(x)			\
G_STMT_START {				\
	reason = (x);			\
	goto bailout;			\
	/* NOTREACHED */		\
} G_STMT_END

	g_assert(NULL != file);
	g_assert(NULL != path);

	pathname = make_pathname(path, file);
	g_return_val_if_fail(NULL != pathname, NULL);

	fd = file_open_missing(pathname, O_RDONLY);
	if (fd < 0) {
		G_FREE_NULL(pathname);
		return NULL;
	}

	if (!file_info_get_trailer(fd, &trailer, pathname)) {
		BAILOUT("could not find trailer");
		/* NOT REACHED */
	}
	t64 = trailer_is_64bit(&trailer);

	{
		gboolean ret;
		
		if (trailer.filesize > (filesize_t) -1) {
			errno = ERANGE;
			ret = -1;
		} else {
			ret = seek_to_filepos(fd, trailer.filesize);
		}
		if (0 != ret) {
			g_warning("seek to position %s within \"%s\" failed: %s",
				uint64_to_string(trailer.filesize),
				pathname, g_strerror(errno));
			goto eof;
		}
	}

	/*
	 * Now read the whole trailer in memory.
	 */

	if (-1 == tbuf_read(fd, trailer.length)) {
		g_warning("file_info_retrieve_binary(): "
			"unable to read whole trailer %s bytes) from \"%s\": %s",
			uint64_to_string(trailer.filesize), pathname, g_strerror(errno));
		goto eof;
	}

	/* Check version */
	READ_INT32(&version);
	if ((t64 && version > FILE_INFO_VERSION) || (!t64 && version > 5)) {
		g_warning("file_info_retrieve_binary(): strange version; %u", version);
		goto eof;
	}

	fi = walloc0(sizeof *fi);

	fi->magic = FI_MAGIC;
	fi->file_name = atom_str_get(file);
	fi->path = atom_str_get(path);
	fi->size = trailer.filesize;
	fi->size_atom = atom_filesize_get(&fi->size);
	fi->generation = trailer.generation;
	fi->file_size_known = fi->use_swarming = 1;		/* Must assume swarming */
	fi->refcount = 0;
	fi->seen_on_network = NULL;

	/*
	 * Read leading binary fields.
	 */

	if (version >= 4) {
		READ_INT32(&fi->ctime);
		READ_INT32(&fi->ntime);
	}

	if (version >= 5)
		READ_CHAR(&fi->file_size_known);

	/*
	 * Read variable-length fields.
	 */

	for (;;) {
		tmpguint = FILE_INFO_FIELD_END; /* in case read() fails. */
		READ_INT32(&tmpguint);				/* Read a field ID */
		if (FILE_INFO_FIELD_END == tmpguint)
			break;
		field = tmpguint;

		READ_INT32(&tmpguint);				/* Read field data length */

		if (0 == tmpguint) {
			gm_snprintf(tmp, sizeof tmp, "field #%d has zero size", field);
			BAILOUT(tmp);
			/* NOT REACHED */
		}

		if (tmpguint > FI_MAX_FIELD_LEN) {
			gm_snprintf(tmp, sizeof tmp,
				"field #%d is too large (%u bytes) ", field, (guint) tmpguint);
			BAILOUT(tmp);
			/* NOT REACHED */
		}

		g_assert(tmpguint < sizeof tmp);

		READ_STR(tmp, tmpguint);
		tmp[tmpguint] = '\0';				/* Did not store trailing NUL */

		switch (field) {
		case FILE_INFO_FIELD_NAME:
			/*
			 * Starting with version 3, the file name is added as an alias.
			 * We don't really need to carry the filename in the file itself!
			 */
			if (version >= 3)
				g_warning("found NAME field in fileinfo v%u for \"%s\"",
					version, file);
			else
				fi_alias(fi, tmp, FALSE);	/* Pre-v3 lacked NAME in ALIA */
			break;
		case FILE_INFO_FIELD_ALIAS:
			fi_alias(fi, tmp, FALSE);
			break;
		case FILE_INFO_FIELD_GUID:
			if (GUID_RAW_SIZE == tmpguint)
				fi->guid = atom_guid_get(tmp);
			else
				g_warning("bad length %d for GUID in fileinfo v%u for \"%s\"",
					tmpguint, version, file);
			break;
		case FILE_INFO_FIELD_SHA1:
			if (SHA1_RAW_SIZE == tmpguint)
				fi->sha1 = atom_sha1_get(tmp);
			else
				g_warning("bad length %d for SHA1 in fileinfo v%u for \"%s\"",
					tmpguint, version, file);
			break;
		case FILE_INFO_FIELD_CHA1:
			if (SHA1_RAW_SIZE == tmpguint)
				fi->cha1 = atom_sha1_get(tmp);
			else
				g_warning("bad length %d for CHA1 in fileinfo v%u for \"%s\"",
					tmpguint, version, file);
			break;
		case FILE_INFO_FIELD_CHUNK:
			{
				struct dl_file_chunk *fc;

				memcpy(tmpchunk, tmp, sizeof tmpchunk);
				fc = walloc0(sizeof *fc);

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
					guint64 hi, lo;

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

				/* Prepend now and reverse later for better efficiency */
				chunklist = g_slist_prepend(chunklist, fc);
			}
			break;
		default:
			g_warning("file_info_retrieve_binary(): "
				"unhandled field ID %u (%d bytes long)", field, tmpguint);
			break;
		}
	}

	fi->chunklist = g_slist_reverse(chunklist);
	if (!file_info_check_chunklist(fi, FALSE)) {
		file_info_chunklist_free(fi);
		BAILOUT("File contains inconsistent chunk list");
		/* NOT REACHED */
	}

	/*
	 * Pre-v4 (32-bit) trailers lacked the ctime and ntime fields.
	 * Pre-v5 (32-bit) trailers lacked the fskn (file size known) indication.
	 */

	if (version < 4)
		fi->ntime = fi->ctime = tm_time();

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
	if (t64)
		READ_INT32(&tmpguint);	/* Upper 32 bits since version 6 */
	READ_INT32(&tmpguint);		/* Lower bits */

	READ_INT32(&tmpguint);			/* generation number */
	READ_INT32(&tmpguint);			/* trailer length */

	if (checksum != trailer.checksum) {
		BAILOUT("checksum mismatch");
		/* NOT REACHED */
	}

	close(fd);

	file_info_merge_adjacent(fi);	/* Update fi->done */

	if (fileinfo_debug > 3)
		g_message("FILEINFO: "
			"good trailer info (v%u, %s bytes) in \"%s\"",
			version, uint64_to_string(trailer.length), pathname);

	G_FREE_NULL(pathname);
	return fi;

bailout:

	g_warning("file_info_retrieve_binary(): %s in %s%s%s",
		reason, path, G_DIR_SEPARATOR == path[strlen(path) - 1]
						? "" : G_DIR_SEPARATOR_S, file);

eof:
	G_FREE_NULL(pathname);
	if (fi)
		fi_free(fi);

	close(fd);

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
	const GSList *fclist;
	const GSList *a;
	struct dl_file_chunk *fc;

	file_info_check(fi);

	if (fi->flags & FI_F_TRANSIENT)
		return;

	if (fi->use_swarming && fi->dirty)
		file_info_store_binary(fi);

	/*
	 * Keep entries for incomplete or not even started downloads so that the
	 * download is started/resumed as soon as a search gains a source.
	 */

	if (0 == fi->refcount && fi->done == fi->size) {
		gchar *path;
		struct stat st;

		path = make_pathname(fi->path, fi->file_name);
		g_return_if_fail(NULL != path);
		if (-1 == stat(path, &st)) {
			G_FREE_NULL(path);
			return; 	/* Skip: not referenced, and file no longer exists */
		}
		G_FREE_NULL(path);
	}

	fprintf(f,
		"# refcount %u\n"
		"NAME %s\n"
		"PATH %s\n"
		"GUID %s\n"
		"GENR %u\n",
		fi->refcount,
		fi->file_name,
		fi->path,
		guid_hex_str(fi->guid),
		fi->generation);

	for (a = fi->alias; a; a = g_slist_next(a)) {
		const gchar *alias = a->data;

		g_assert(NULL != alias);
		if (looks_like_urn(alias)) {
			g_warning("skipping fileinfo alias which looks like a urn: "
				"\"%s\" (file_name=\"%s\")",
				alias, fi->file_name);
		} else
			fprintf(f, "ALIA %s\n", alias);
	}

	if (fi->sha1)
		fprintf(f, "SHA1 %s\n", sha1_base32(fi->sha1));
	if (fi->cha1)
		fprintf(f, "CHA1 %s\n", sha1_base32(fi->cha1));

	fprintf(f, "SIZE %s\n", uint64_to_string(fi->size));
	fprintf(f, "FSKN %d\n", fi->file_size_known ? 1 : 0);
	fprintf(f, "DONE %s\n", uint64_to_string(fi->done));
	fprintf(f, "TIME %s\n", uint64_to_string(fi->stamp));
	fprintf(f, "CTIM %s\n", uint64_to_string(fi->ctime));
	fprintf(f, "NTIM %s\n", uint64_to_string(fi->ntime));
	fprintf(f, "SWRM %d\n", fi->use_swarming ? 1 : 0);

	g_assert(file_info_check_chunklist(fi, TRUE));
	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;
		fprintf(f, "CHNK %s %s %u\n",
			uint64_to_string(fc->from), uint64_to_string2(fc->to),
			(guint) fc->status);
	}
	fprintf(f, "\n");
}

/**
 * Callback for hash table iterator. Used by file_info_store().
 */
static void
file_info_store_list(gpointer key, gpointer val, gpointer x)
{
	const filesize_t *size_ptr;
	const GSList *sl;
	FILE *f = x;

	size_ptr = key;
	for (sl = val; sl; sl = g_slist_next(sl)) {
		fileinfo_t *fi;
		
		fi = sl->data;
		file_info_check(fi);
		g_assert(*size_ptr == fi->size);
		file_info_store_one(f, fi);
	}
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
		"#	FSKN <boolean; file_size_known>\n"
		"#	SHA1 <server sha1>\n"
		"#	CHA1 <computed sha1> [when done only]\n"
		"#	DONE <bytes done>\n"
		"#	TIME <last update stamp>\n"
		"#	CTIM <entry creation time>\n"
		"#	NTIM <time when new source was seen>\n"
		"#	SWRM <boolean; use_swarming>\n"
		"#	CHNK <start> <end+1> <0=hole, 1=busy, 2=done>\n"
		"#	<blank line>\n"
		"#\n\n",
		f
	);

	g_hash_table_foreach(fi_by_size, file_info_store_list, f);

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
	/*
	 * Note that normally all fileinfo structures should have been collected
	 * during the freeing of downloads, so if we come here with a non-zero
	 * refcount, something is wrong with our memory management.
	 *
	 * (refcount of zero is possible if we have a fileinfo entry but no
	 * download attached to that fileinfo)
	 */

	if (fi->refcount)
		g_warning("fi_dispose() refcount = %u for \"%s\"",
			fi->refcount, fi->file_name);

    event_trigger(fi_events[EV_FI_REMOVED],
        T_NORMAL(fi_listener_t, (fi->fi_handle)));
    file_info_drop_handle(fi->fi_handle);

	fi->hashed = FALSE;
	fi_free(fi);
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_sha1_kv(gpointer key, gpointer val, gpointer unused_x)
{
	const gchar *sha1 = key;
	const fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);
	g_assert(sha1 == fi->sha1);		/* SHA1 shared with fi's, don't free */

	/* fi structure in value not freed, shared with other hash tables */
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_namesize_kv(gpointer key, gpointer val, gpointer unused_x)
{
	namesize_t *ns = key;
	GSList *list = val;

	(void) unused_x;
	namesize_free(ns);
	g_slist_free(list);

	/* fi structure in value not freed, shared with other hash tables */
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static gboolean
file_info_free_size_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	GSList *slist = val, *sl;

	(void) unused_key;
	(void) unused_x;
	
	g_assert(!gm_slist_is_looping(slist));
	for (sl = slist; sl; sl = g_slist_next(sl)) {
		const fileinfo_t *fi = sl->data;
		file_info_check(fi);
		g_assert(fi->size_atom);
		g_assert(fi->size == *fi->size_atom);
		g_assert(*(const filesize_t *) unused_key == fi->size);
	}
	
	g_slist_free(slist);

	/* fi structure in value not freed, shared with other hash tables */
	return TRUE;
}

/**
 * Callback for hash table iterator. Used by file_info_close().
 */
static void
file_info_free_guid_kv(gpointer key, gpointer val, gpointer unused_x)
{
	const gchar *guid = key;
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);
	g_assert(guid == fi->guid);		/* GUID shared with fi's, don't free */

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
file_info_free_outname_kv(gpointer key, gpointer val, gpointer unused_x)
{
	const gchar *name = key;
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);
	g_assert(name == fi->file_name);	/* name shared with fi's, don't free */

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
    event_trigger(fi_events[EV_FI_STATUS_CHANGED],
        T_NORMAL(fi_listener_t, (fi->fi_handle)));
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
}

/**
 * Close and free all file_info structs in the list.
 */
void
file_info_close(void)
{
    guint n;

	/*
	 * Freeing callbacks expect that the freeing of the `fi_by_outname'
	 * table will free the referenced `fi' (since that table MUST contain
	 * all the known `fi' structs by definition).
	 */

	g_hash_table_foreach(fi_by_sha1, file_info_free_sha1_kv, NULL);
	g_hash_table_foreach(fi_by_namesize, file_info_free_namesize_kv, NULL);
	g_hash_table_foreach_remove(fi_by_size, file_info_free_size_kv, NULL);
	g_hash_table_foreach(fi_by_guid, file_info_free_guid_kv, NULL);
	g_hash_table_foreach(fi_by_outname, file_info_free_outname_kv, NULL);

    /*
     * The hash tables may still not be completely empty, but the referenced
     * file_info structs are all freed.
     *      --Richard, 9/3/2003
     */

    g_assert(0 == idtable_ids(fi_handle_map));
    idtable_destroy(fi_handle_map);

    for (n = 0; n < G_N_ELEMENTS(fi_events); n ++)
        event_destroy(fi_events[n]);

	g_hash_table_destroy(fi_by_sha1);
	g_hash_table_destroy(fi_by_namesize);
	g_hash_table_destroy(fi_by_size);
	g_hash_table_destroy(fi_by_guid);
	g_hash_table_destroy(fi_by_outname);

	G_FREE_NULL(tbuf.arena);
}

/**
 * Inserts a file_info struct into the hash tables.
 */
static void
file_info_hash_insert(fileinfo_t *fi)
{
	fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(!fi->hashed);
	g_assert((NULL != fi->size_atom) ^ (!fi->file_size_known));
	g_assert(fi->guid);

	if (fileinfo_debug > 4)
		g_message("FILEINFO insert 0x%p \"%s\" "
			"(%s/%s bytes done) sha1=%s",
			cast_to_gconstpointer(fi), fi->file_name,
			uint64_to_string(fi->done), uint64_to_string2(fi->size),
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

	xfi = g_hash_table_lookup(fi_by_outname, fi->file_name);

	if (NULL != xfi && xfi != fi)			/* See comment above */
		g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

	if (NULL == xfi)
		g_hash_table_insert(fi_by_outname, fi->file_name, fi);

	/*
	 * Likewise, there can be only ONE entry per given SHA1, but the SHA1
	 * may not be already present at this time, so the entry is optional.
	 * If it exists, it must be unique though.
	 *		--RAM, 01/09/2002
	 */

	if (fi->sha1) {
		xfi = g_hash_table_lookup(fi_by_sha1, fi->sha1);

		if (NULL != xfi && xfi != fi)		/* See comment above */
			g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

		if (NULL == xfi)
			g_hash_table_insert(fi_by_sha1, fi->sha1, fi);
	}

	if (fi->file_size_known) {
		file_info_hash_insert_name_size(fi);
	}

transient:
	/*
	 * Obviously, GUID entries must be unique as well.
	 */

	xfi = g_hash_table_lookup(fi_by_guid, fi->guid);

	if (NULL != xfi && xfi != fi)		/* See comment above */
		g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

	if (NULL == xfi)
		g_hash_table_insert(fi_by_guid, fi->guid, fi);

	/*
	 * Notify interested parties, update counters.
	 */

	fi->hashed = TRUE;
    fi->fi_handle = file_info_request_handle(fi);

	gnet_prop_set_guint32_val(PROP_FI_ALL_COUNT, fi_all_count + 1);

    event_trigger(fi_events[EV_FI_ADDED],
        T_NORMAL(fi_listener_t, (fi->fi_handle)));
}

/**
 * Remove fileinfo data from all the hash tables.
 */
static void
file_info_hash_remove(fileinfo_t *fi)
{
	namesize_t nsk;
	gboolean found;

	file_info_check(fi);
	g_assert(fi->hashed);
	g_assert((NULL != fi->size_atom) ^ (!fi->file_size_known));
	g_assert(fi->guid);

	if (fileinfo_debug > 4) {
		g_message("FILEINFO remove 0x%lx \"%s\" "
			"(%s/%s bytes done) sha1=%s\n",
			(gulong) fi, fi->file_name,
			uint64_to_string(fi->done), uint64_to_string2(fi->size),
			fi->sha1 ? sha1_base32(fi->sha1) : "none");
	}

    /*
     * Notify interested parties that file info is being removed and
	 * free its handle.
     */

    event_trigger(fi_events[EV_FI_REMOVED],
        T_NORMAL(fi_listener_t, (fi->fi_handle)));

    file_info_drop_handle(fi->fi_handle);

	gnet_prop_set_guint32_val(PROP_FI_ALL_COUNT, fi_all_count - 1);
	g_assert((gint) fi_all_count >= 0);

	/*
	 * Transient fileinfo is only recorded in the GUID hash table.
	 */

	if (fi->flags & FI_F_TRANSIENT)
		goto transient;

	/*
	 * Remove from plain hash tables: by output name, by SHA1 and by GUID.
	 */

	g_hash_table_remove(fi_by_outname, fi->file_name);

	if (fi->sha1)
		g_hash_table_remove(fi_by_sha1, fi->sha1);

	if (fi->file_size_known) {
		GSList *sl, *head;

		/*
		 * Remove all the aliases from the (name, size) table.
		 */

		nsk.size = fi->size;

		for (sl = fi->alias; NULL != sl; sl = g_slist_next(sl)) {
			namesize_t *ns;
			GSList *slist;
			gpointer key, value;

			nsk.name = sl->data;

			found = g_hash_table_lookup_extended(fi_by_namesize, &nsk,
						&key, &value);

			ns = key;
			slist = value;
			g_assert(found);
			g_assert(NULL != slist);
			g_assert(ns->size == fi->size);

			head = slist;
			slist = g_slist_remove(slist, fi);

			if (NULL == slist) {
				g_hash_table_remove(fi_by_namesize, ns);
				namesize_free(ns);
			} else if (head != slist) {
				g_hash_table_insert(fi_by_namesize, ns, slist);
				/* Head changed */
			}
		}

		/*
		 * Remove from the "by filesize" table.
		 *
		 * NB: the key used here is the size_atom, as it must be shared accross
		 * all the `fi' structs with the same size (in case we free `fi' now)!
		 */

		g_assert(*(const filesize_t *) fi->size_atom == fi->size);

		sl = g_hash_table_lookup(fi_by_size, &fi->size);
		g_assert(NULL != sl);

		g_assert(!gm_slist_is_looping(sl));
		g_assert(!g_slist_find(sl, NULL));
		g_assert(g_slist_find(sl, fi));
	
		head = g_slist_remove(sl, fi);
		if (NULL == head) {
			g_hash_table_remove(fi_by_size, fi->size_atom);
		} else if (head != sl) {
			g_hash_table_insert(fi_by_size, fi->size_atom, head);
		}
		g_assert(!gm_slist_is_looping(head));
		g_assert(!g_slist_find(head, NULL));
		g_assert(!g_slist_find(head, fi));
	}

transient:
	g_hash_table_remove(fi_by_guid, fi->guid);

	fi->hashed = FALSE;
}

/**
 * Stop all sharing occuring for this fileinfo.
 */
void
file_info_upload_stop(fileinfo_t *fi, const gchar *reason)
{
	upload_stop_all(fi, reason);
	shared_file_unref(fi->sf);
	fi->sf = NULL;
}

/**
 * Unlink file from disk.
 */
void
file_info_unlink(fileinfo_t *fi)
{
	char *path;

	file_info_check(fi);

	if (fi->flags & FI_F_TRANSIENT)
		return;

	/*
	 * Only try to unlink partials because completed files are
	 * already moved or renamed and this could in theory match
	 * the filename of another download started afterwards which 
	 * means the wrong file would be removed.
	 */
	if (fi->file_size_known && fi->size == fi->done)
		return;

	path = make_pathname(fi->path, fi->file_name);

	if (NULL == path || -1 == unlink(path)) {
		/*
		 * File might not exist on disk yet if nothing was downloaded.
		 */

		if (fi->done)
			g_warning("cannot unlink \"%s%s%s\": %s",
				fi->path, G_DIR_SEPARATOR_S, fi->file_name,
				NULL == path ?  "Out of memory" : g_strerror(errno));
	} else {
		g_warning("unlinked \"%s\" (%s/%s bytes or %d%% done, %s SHA1%s%s)",
			fi->file_name,
			uint64_to_string(fi->done), uint64_to_string2(fi->size),
			(gint) (fi->done * 100 / (fi->size == 0 ? 1 : fi->size)),
			fi->sha1 ? "with" : "no",
			fi->sha1 ? ": " : "",
			fi->sha1 ? sha1_base32(fi->sha1) : "");
	}

	/*
	 * If this fileinfo was partially shared, make sur all uploads currently
	 * requesting it are terminated.
	 */

	if (NULL != fi->sf)
		file_info_upload_stop(fi, "Partial file removed");

	G_FREE_NULL(path);
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
	g_assert(0 != strcmp(from->file_name, to->file_name));

	g_warning("about to unlink() for reparenting: \"%s\"", from->file_name);
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
gboolean
file_info_got_sha1(fileinfo_t *fi, const gchar *sha1)
{
	fileinfo_t *xfi;

	file_info_check(fi);
	g_assert(sha1);
	g_assert(NULL == fi->sha1);

	xfi = g_hash_table_lookup(fi_by_sha1, sha1);

	if (NULL == xfi) {
		fi->sha1 = atom_sha1_get(sha1);
		g_hash_table_insert(fi_by_sha1, fi->sha1, fi);
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

	if (fileinfo_debug > 3) {
		gchar buf[64];

		concat_strings(buf, sizeof buf,
			uint64_to_string(xfi->done), "/",
			uint64_to_string2(xfi->size), (void *) 0);
		g_message("CONFLICT found same SHA1 %s in \"%s\" "
			"(%s bytes done) and \"%s\" (%s/%s bytes done)\n",
			sha1_base32(sha1), xfi->file_name, buf, fi->file_name,
			uint64_to_string(fi->done), uint64_to_string2(fi->size));
	}

	if (fi->done && xfi->done) {
		gchar buf[64];

		concat_strings(buf, sizeof buf,
			uint64_to_string(xfi->done), "/",
			uint64_to_string2(xfi->size), (void *) 0);
		g_warning("found same SHA1 %s in \"%s\" (%s bytes done) and \"%s\" "
			"(%s/%s bytes done) -- aborting last one",
			sha1_base32(sha1), xfi->file_name, buf, fi->file_name,
			uint64_to_string(fi->done), uint64_to_string2(fi->size));
		return FALSE;
	}

	if (fi->done) {
		g_assert(0 == xfi->done);
		fi->sha1 = atom_sha1_get(sha1);
		file_info_reparent_all(xfi, fi);	/* All `xfi' replaced by `fi' */
		g_hash_table_insert(fi_by_sha1, fi->sha1, fi);
	} else {
		g_assert(0 == fi->done);
		file_info_reparent_all(fi, xfi);	/* All `fi' replaced by `xfi' */
	}

	return TRUE;
}

/**
 * Extract GUID from GUID line in the ASCII "fileinfo" summary file
 * and return NULL if none or invalid, the GUID atom otherwise.
 */
static gchar *
extract_guid(const gchar *s)
{
	gchar guid[GUID_RAW_SIZE];

	if (strlen(s) < GUID_HEX_SIZE)
		return NULL;

	if (!hex_to_guid(s, guid))
		return NULL;

	return atom_guid_get(guid);
}

/**
 * Extract sha1 from SHA1/CHA1 line in the ASCII "fileinfo" summary file
 * and return NULL if none or invalid, the SHA1 atom otherwise.
 */
static gchar *
extract_sha1(const gchar *s)
{
	gchar sha1[SHA1_RAW_SIZE];

	if (strlen(s) < SHA1_BASE32_SIZE)
		return NULL;

	if (!base32_decode_into(s, SHA1_BASE32_SIZE, sha1, sizeof sha1))
		return NULL;

	return atom_sha1_get(sha1);
}

typedef enum {
	FI_TAG_UNKNOWN = 0,
	FI_TAG_NAME,
	FI_TAG_PATH,
	FI_TAG_GENR,
	FI_TAG_ALIA,
	FI_TAG_SIZE,
	FI_TAG_FSKN,
	FI_TAG_SHA1,
	FI_TAG_CHA1,
	FI_TAG_DONE,
	FI_TAG_TIME,
	FI_TAG_CTIM,
	FI_TAG_NTIM,
	FI_TAG_SWRM,
	FI_TAG_CHNK,
	FI_TAG_GUID,

	NUM_FI_TAGS
} fi_tag_t;

static const struct fi_tag {
	fi_tag_t	tag;
	const gchar *str;
} fi_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

	{ FI_TAG_ALIA, "ALIA" },
	{ FI_TAG_CHA1, "CHA1" },
	{ FI_TAG_CHNK, "CHNK" },
	{ FI_TAG_CTIM, "CTIM" },
	{ FI_TAG_DONE, "DONE" },
	{ FI_TAG_FSKN, "FSKN" },
	{ FI_TAG_GENR, "GENR" },
	{ FI_TAG_GUID, "GUID" },
	{ FI_TAG_NAME, "NAME" },
	{ FI_TAG_NTIM, "NTIM" },
	{ FI_TAG_PATH, "PATH" },
	{ FI_TAG_SHA1, "SHA1" },
	{ FI_TAG_SIZE, "SIZE" },
	{ FI_TAG_SWRM, "SWRM" },
	{ FI_TAG_TIME, "TIME" },

	/* Above line intentionally left blank (for "!}sort" on vi) */
};

/**
 * Transform fileinfo tag string into tag constant.
 * For instance, "TIME" would yield FI_TAG_TIME.
 * An unknown tag yieldd FI_TAG_UNKNOWN.
 */
static fi_tag_t
file_info_string_to_tag(const gchar *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(fi_tag_map) == (NUM_FI_TAGS - 1));

#define GET_KEY(i) (fi_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return fi_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(const gchar *, s, G_N_ELEMENTS(fi_tag_map), strcmp,
		GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY
	return FI_TAG_UNKNOWN;
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

		fc = walloc0(sizeof *fc);
		fc->from = 0;
		fc->to = fi->size;
		fc->status = DL_CHUNK_EMPTY;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
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
	GSList *sl;

	file_info_check(fi);
	file_info_check(trailer);
	g_assert(NULL == fi->chunklist);
	g_assert(file_info_check_chunklist(trailer, TRUE));

	fi->generation = trailer->generation;
	if (trailer->cha1)
		fi->cha1 = atom_sha1_get(trailer->cha1);

	for (sl = trailer->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;

		g_assert(fc);
		g_assert(fc->from <= fc->to);
		g_assert(sl != trailer->chunklist || 0 == fc->from);
		/* Prepend now and reverse later for better efficiency */
		fi->chunklist = g_slist_prepend(fi->chunklist, wcopy(fc, sizeof *fc));
	}

	fi->chunklist = g_slist_reverse(fi->chunklist);

	file_info_merge_adjacent(fi); /* Recalculates also fi->done */
}

/**
 * Loads the fileinfo database from disk, and saves a copy in fileinfo.orig.
 */
void
file_info_retrieve(void)
{
	FILE *f;
	gchar line[1024];
	fileinfo_t *fi = NULL;
	gboolean empty = TRUE;
	gboolean last_was_truncated = FALSE;
	file_path_t fp;
	gchar *old_filename = NULL;		/* In case we must rename the file */

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
	f = file_config_open_read("fileinfo database", &fp, 1);
	if (!f)
		return;

	while (fgets(line, sizeof line, f)) {
		size_t len;
		gint error;
		gboolean truncated = FALSE, damaged;
		const gchar *ep;
		gchar *value;
		guint64 v;

		if ('#' == *line) continue;

		/*
		 * The following semi-complex logic attempts to determine whether
		 * we filled the whole line buffer without reaching the end of the
		 * physical line.
		 *
		 * When truncation occurs, we skip every following "line" we'd get
		 * up to the point where we no longer need to truncate, at which time
		 * we'll be re-synchronized on the real end of the line.
		 */

		len = strlen(line);
		if (sizeof line - 1 == len)
			truncated = '\n' != line[sizeof line - 2];

		if (last_was_truncated) {
			last_was_truncated = truncated;
			g_warning("ignoring fileinfo line after truncation: '%s'", line);
			continue;
		} else if (truncated) {
			last_was_truncated = TRUE;
			g_warning("ignoring too long fileinfo line: '%s'", line);
			continue;
		}

		/*
		 * Remove trailing "\n" from line, then parse it.
		 * Reaching an empty line means the end of the fileinfo description.
		 */

		str_chomp(line, len);

		if ('\0' == *line && fi) {
			fileinfo_t *dfi;
			gboolean upgraded;
			gboolean reload_chunks = FALSE;

			if (!(fi->file_name && fi->path)) {
				/* There's an incomplete fileinfo record */
				fi_free(fi);
				fi = NULL;
				continue;
			}

			/*
			 * There can't be duplicates!
			 */

			dfi = g_hash_table_lookup(fi_by_outname, fi->file_name);
			if (NULL != dfi) {
				g_warning("discarding DUPLICATE fileinfo entry for \"%s\"",
					fi->file_name);
				fi_free(fi);
				fi = NULL;
				continue;
			}

			if (0 == fi->size) {
				fi->file_size_known = FALSE;
			}

			/*
			 * If we deserialized an older version, bring it up to date.
			 */

			upgraded = fi_upgrade_older_version(fi);

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

			if (NULL == fi->chunklist) {
				if (fi->file_size_known)
					g_warning("no CHNK info for \"%s\"", fi->file_name);
				fi_reset_chunks(fi);
				reload_chunks = TRUE;	/* Will try to grab from trailer */
			} else if (!file_info_check_chunklist(fi, FALSE)) {
				if (fi->file_size_known)
					g_warning("invalid set of CHNK info for \"%s\"",
						fi->file_name);
				fi_reset_chunks(fi);
				reload_chunks = TRUE;	/* Will try to grab from trailer */
			}

			g_assert(file_info_check_chunklist(fi, TRUE));

			file_info_merge_adjacent(fi); /* Recalculates also fi->done */

			/*
			 * If `old_filename' is not NULL, then we need to rename
			 * the file bearing that name into the new (sanitized)
			 * name, making sure there is no filename conflict.
			 */

			if (NULL != old_filename) {
				gchar *new_filename;
				gchar *old_pathname;
				gchar *new_pathname;
				gboolean renamed = TRUE;

				new_filename = file_info_new_outname(fi->file_name, fi->path);
				atom_str_free_null(&fi->file_name);

				old_pathname = make_pathname(fi->path, old_filename);
				new_pathname = make_pathname(fi->path, new_filename);

				/*
				 * If fi->done == 0, the file might not exist on disk.
				 */

				if (-1 == rename(old_pathname, new_pathname) && 0 != fi->done)
					renamed = FALSE;

				if (renamed) {
					g_warning("renamed \"%s\" into sanitized \"%s\" in \"%s\"",
						old_filename, new_filename, fi->path);
					fi->file_name = new_filename;	/* Already an atom */
					atom_str_free_null(&old_filename);
				} else {
					g_warning("cannot rename \"%s\" into \"%s\" in \"%s\": %s",
						old_filename, new_filename, fi->path,
						g_strerror(errno));
					fi->file_name = old_filename;	/* Already an atom */
					atom_str_free_null(&new_filename);
				}

				G_FREE_NULL(old_pathname);
				G_FREE_NULL(new_pathname);
			}

			/*
			 * Check file trailer information.	The main file is only written
			 * infrequently and the file's trailer can have more up-to-date
			 * information.
			 */

			dfi = file_info_retrieve_binary(fi->file_name, fi->path);

			/*
			 * If we resetted the CHNK list above, grab those from the
			 * trailer: that cannot be worse than having to download
			 * everything again...  If there was no valid trailer, all the
			 * data are lost and the whole file will need to be grabbed again.
			 */

			if (dfi != NULL && reload_chunks) {
				fi_copy_chunks(fi, dfi);
				if (fi->chunklist) g_message(
					"recovered %lu downloaded bytes from trailer of \"%s\"",
						(gulong) fi->done, fi->file_name);
			} else if (reload_chunks)
				g_warning("lost all CHNK info for \"%s\" -- downloading again",
					fi->file_name);

			g_assert(file_info_check_chunklist(fi, TRUE));

			/*
			 * Special treatment for the GUID: if not present, it will be
			 * added during retrieval, but it will be different for the
			 * one in the fileinfo DB and the one on disk.  Set `upgraded'
			 * to signal that, so that we resync the metainfo below.
			 */

			if (dfi && dfi->guid != fi->guid)		/* They're atoms... */
				upgraded = TRUE;

			if (NULL == dfi) {
				gchar *pathname;

				pathname = make_pathname(fi->path, fi->file_name);
				if (is_regular(pathname)) {
					g_warning("got metainfo in fileinfo cache, "
						"but none in \"%s\"", pathname);
					upgraded = FALSE;			/* No need to flush twice */
					file_info_store_binary(fi);			/* Create metainfo */
				} else {
					file_info_merge_adjacent(fi);		/* Compute fi->done */
					if (fi->done > 0) {
						g_warning("discarding cached metainfo for \"%s\": "
							"file had %s bytes downloaded "
							"but is now gone!", pathname,
							uint64_to_string(fi->done));
						G_FREE_NULL(pathname);
						fi_free(fi);
						fi = NULL;
						continue;
					}
				}
				G_FREE_NULL(pathname);
			} else if (dfi->generation > fi->generation) {
				g_warning("found more recent metainfo in \"%s%s%s\"",
					fi->path, G_DIR_SEPARATOR_S, fi->file_name);
				fi_free(fi);
				fi = dfi;
			} else if (dfi->generation < fi->generation) {
				g_warning("found OUTDATED metainfo in \"%s%s%s\"",
					fi->path, G_DIR_SEPARATOR_S, fi->file_name);
				fi_free(dfi);
				dfi = NULL;
				upgraded = FALSE;				/* No need to flush twice */
				file_info_store_binary(fi);		/* Resync metainfo */
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
					fi->file_name, uint64_to_string(fi->size),
					dfi->file_name, uint64_to_string2(dfi->size));
				fi_free(fi);
				fi = NULL;
				continue;
			}

			/*
			 * If we had to upgrade the fileinfo, make sure we resync
			 * the metadata on disk as well.
			 */

			if (upgraded) {
				g_warning("flushing upgraded metainfo in \"%s%s%s\"",
					fi->path, G_DIR_SEPARATOR_S, fi->file_name);
				file_info_store_binary(fi);		/* Resync metainfo */
			}

			file_info_merge_adjacent(fi);
			file_info_hash_insert(fi);

			/*
			 * We could not add the aliases immediately because the file
			 * is formatted with ALIA coming before SIZE.  To let fi_alias()
			 * detect conflicting entries, we need to have a valid fi->size.
			 * And since the `fi' is hashed, we can detect duplicates in
			 * the `aliases' list itself as an added bonus.
			 */

			if (fi->alias) {
				GSList *aliases, *sl;

				/* For efficiency each alias has been prepended to
				 * the list. To preserve the order between sessions,
				 * the original list order is restored here. */
				aliases = g_slist_reverse(fi->alias);
				fi->alias = NULL;
				for (sl = aliases; NULL != sl; sl = g_slist_next(sl)) {
					gchar *s = sl->data;
					fi_alias(fi, s, TRUE);
					atom_str_free_null(&s);
				}
				g_slist_free(aliases);
				aliases = NULL;
			}

			empty = FALSE;
			fi = NULL;
			continue;
		}

		if (!fi) {
			fi = walloc0(sizeof *fi);
			fi->magic = FI_MAGIC;
			fi->refcount = 0;
			fi->seen_on_network = NULL;
			fi->file_size_known = TRUE;		/* Unless stated otherwise below */
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
			if (convert_old_filenames) {
				gchar *s;

				s = gm_sanitize_filename(value,
					convert_spaces, convert_evil_chars);
				fi->file_name = atom_str_get(s);
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

					G_FREE_NULL(s);
				}
			} else
				fi->file_name = atom_str_get(value);
			break;
		case FI_TAG_PATH:
			/* XXX: Check the pathname more thoroughly */
			damaged = !is_absolute_path(value);
			fi->path = damaged ? NULL : atom_str_get(value);
			break;
		case FI_TAG_ALIA:
			if (looks_like_urn(value)) {
				g_warning("skipping alias which looks like a urn in "
					"fileinfo database: \"%s\" (file_name=\"%s\")", value,
					NULL_STRING(fi->file_name));
			} else {
				gchar *s;

				s = gm_sanitize_filename(value, FALSE, FALSE);

				/* The alias is only temporarily added to fi->alias, the list
				 * of aliases has to be re-constructed with fi_alias()
			   	 * when the fileinfo record is finished. It's merely done
				 * this way to simplify discarding incomplete/invalid records
				 * utilizing fi_free().
				 * The list should be reversed once it's complete.
				 */
				fi->alias = g_slist_prepend(fi->alias, atom_str_get(s));
				if (s != value) {
					if (strcmp(s, value)) {
						g_warning("fileinfo database contained an "
							"unsanitized alias: \"%s\" -> \"%s\"", value, s);
					}
					G_FREE_NULL(s);
				}
			}
			break;
		case FI_TAG_GENR:
			v = parse_uint32(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v > (guint32) INT_MAX;
			fi->generation = v;
			break;
		case FI_TAG_SIZE:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error
				|| '\0' != *ep
				|| v >= ((guint64) 1UL << 63)
				|| (!fi->file_size_known && 0 == v);
			fi->size = v;
			fi->size_atom = atom_filesize_get(&fi->size);
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
			break;
		case FI_TAG_CTIM:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep;
			fi->ctime = v;
			break;
		case FI_TAG_NTIM:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep;
			fi->ntime = v;
			break;
		case FI_TAG_DONE:
			v = parse_uint64(value, &ep, 10, &error);
			damaged = error || '\0' != *ep || v >= ((guint64) 1UL << 63);
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
				guint32 status;

				from = v = parse_uint64(value, &ep, 10, &error);
				damaged = error
					|| *ep != ' '
					|| v >= ((guint64) 1UL << 63)
					|| from > fi->size;

				if (!damaged) {
					const gchar *s = &ep[1];

					to = v = parse_uint64(s, &ep, 10, &error);
					damaged = error
						|| ' ' != *ep
						|| v >= ((guint64) 1UL << 63)
						|| v <= from
						|| to > fi->size;
				} else {
					to = 0;	/* For stupid compilers */
				}
				if (!damaged) {
					const gchar *s = &ep[1];

					status = v = parse_uint64(s, &ep, 10, &error);
					damaged = error || '\0' != *ep || v > 2U;
				} else {
					status = 0;	/* For stupid compilers */
				}
				if (!damaged) {
					struct dl_file_chunk *fc, *prev;

					fc = walloc0(sizeof *fc);
					fc->from = from;
					fc->to = to;
					if (DL_CHUNK_BUSY == status)
						status = DL_CHUNK_EMPTY;
					fc->status = status;
					prev = fi->chunklist
						? g_slist_last(fi->chunklist)->data : NULL;
					if (fc->from != (prev ? prev->to : 0)) {
						g_warning("Chunklist is inconsistent (fi->size=%s)",
							uint64_to_string(fi->size));
						damaged = TRUE;
					} else {
						fi->chunklist = g_slist_append(fi->chunklist, fc);
					}
				}
			}
			break;
		case FI_TAG_UNKNOWN:
			if (*line)
				g_warning("ignoring fileinfo line: \"%s %s\"", line, value);
			break;
		case NUM_FI_TAGS:
			g_assert_not_reached();
		}

		if (damaged)
			g_warning("damaged entry in fileinfo line: \"%s %s\"", line, value);
	}

	if (fi) {
		fi_free(fi);
		if (!empty)
			g_warning("file info repository was truncated!");
	}

	fclose(f);
}

static gboolean
file_info_name_is_uniq(const gchar *pathname)
{
	const gchar *filename;
	
	g_assert(pathname);

	filename = filepath_basename(pathname);
	return !g_hash_table_lookup(fi_by_outname, filename) &&
	   	file_does_not_exist(pathname);
}

/**
 * Allocate unique output name for file `name', stored in `dir'.
 *
 * @returns filename atom.
 */
static gchar *
file_info_new_outname(const gchar *name, const gchar *dir)
{
	gchar *result, *to_free = NULL;

	{
		gchar *s;

		s = gm_sanitize_filename(name, convert_spaces, convert_evil_chars);
		if (name != s) {
			to_free = s;
			name = s;
		}
	}

	if ('\0' == name[0]) {
		/* Don't allow empty names */
		name = "noname";
	}

	/*
	 * If `name' (sanitized form) is not taken yet, it will do.
	 */

	if (
		NULL == g_hash_table_lookup(fi_by_outname, name) &&
		!filepath_exists(dir, name)
	) {
		result = atom_str_get(name);
	} else {
		gchar *ext, *name_copy;

		name_copy = g_strdup(name);
		{
			gchar *dot;

			dot = strrchr(name_copy, '.');
			if (!dot || strlen(dot) > 32) {
				/* Probably not an extension, don't preserve */
				dot = strchr(name_copy, '\0');
			}
			ext = g_strdup(dot);
			*dot = '\0';
		}

		{
			const gchar *filename;
			gchar *uniq;

			uniq = unique_filename(dir, name_copy, ext, file_info_name_is_uniq);
			if (!uniq) {
				/* Should NOT happen */
				g_error("no luck with random number generator");
			}
			/*
			 * unique_filename() returns a full pathname, thus we
			 * have to extract the basename here.
			 */
			filename = filepath_basename(uniq);
			g_assert('\0' != filename[0]);
			g_assert(!g_hash_table_lookup(fi_by_outname, filename));

			result = atom_str_get(filename);

			G_FREE_NULL(uniq);
		}
		
		G_FREE_NULL(name_copy);
		G_FREE_NULL(ext);
	}

	G_FREE_NULL(to_free);
	return result;
}

/**
 * Create a fileinfo structure from existing file with no swarming trailer.
 * The given `size' argument reflect the final size of the (complete) file.
 * The `sha1' is the known SHA1 for the file (NULL if unknown).
 */
static fileinfo_t *
file_info_create(gchar *file, const gchar *path, filesize_t size,
	const gchar *sha1, gboolean file_size_known)
{
	fileinfo_t *fi;
	struct stat st;
	char *pathname;

	fi = walloc0(sizeof *fi);
	fi->magic = FI_MAGIC;

	/* Get unique file name */
	fi->file_name = file_info_new_outname(file, path);
	fi->path = atom_str_get(path);

	/* Get unique ID */
	fi->guid = fi_random_guid_atom();

	if (sha1)
		fi->sha1 = atom_sha1_get(sha1);
	fi->size = 0;	/* Will be updated by fi_resize() */
	fi->file_size_known = file_size_known;
	fi->done = 0;
	fi->use_swarming = use_swarming && file_size_known;
	fi->ctime = tm_time();
	fi->seen_on_network = NULL;

	pathname = make_pathname(fi->path, fi->file_name);
	if (NULL != pathname && -1 != stat(pathname, &st) && S_ISREG(st.st_mode)) {
		struct dl_file_chunk *fc;

		g_warning("file_info_create(): "
			"assuming file \"%s\" is complete up to %s bytes",
			pathname, uint64_to_string(st.st_size));

		fc = walloc0(sizeof *fc);
		fc->from = 0;
		fi->size = fc->to = st.st_size;
		fc->status = DL_CHUNK_DONE;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
		fi->dirty = TRUE;
	}
	G_FREE_NULL(pathname);

	fi->size_atom = atom_filesize_get(&fi->size); /* Set now, for fi_resize() */

	if (size > fi->size)
		fi_resize(fi, size);

	g_assert(fi->file_size_known || !fi->use_swarming);

	return fi;
}

/**
 * Create a transient fileinfo structure to be perused by browse host.
 */
fileinfo_t *
file_info_get_browse(const gchar *name)
{
	fileinfo_t *fi;

	fi = walloc0(sizeof *fi);
	fi->magic = FI_MAGIC;

	fi->file_name = atom_str_get(name);
	fi->path = atom_str_get("/non-existent");

	/* Get unique ID */
	fi->guid = fi_random_guid_atom();

	fi->size = 0;	/* Will be updated by fi_resize() */
	fi->file_size_known = FALSE;
	fi->done = 0;
	fi->use_swarming = FALSE;
	fi->ctime = tm_time();
	fi->seen_on_network = NULL;
	fi->dirty = TRUE;
	fi->size_atom = atom_filesize_get(&fi->size); /* Set now, for fi_resize() */

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
fi_rename_dead(fileinfo_t *fi,
	const gchar *path, const gchar *filename)
{
	gchar *dead;
	gchar *pathname;

	file_info_check(fi);
	pathname = make_pathname(path, filename);
	dead = g_strconcat(pathname, ".DEAD", (void *) 0);

	if (
		NULL != pathname &&
		NULL != dead &&
		-1 == rename(pathname, dead)
	) {
		g_warning("cannot rename \"%s\" as \"%s\": %s",
			pathname, dead, g_strerror(errno));
		goto done;
	}

	if (-1 == truncate(dead, fi->size))
		g_warning("could not chop fileinfo trailer off \"%s\": %s",
			dead, g_strerror(errno));

done:
	G_FREE_NULL(dead);
	G_FREE_NULL(pathname);
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
file_info_get(const gchar *file, const gchar *path, filesize_t size,
	const gchar *sha1, gboolean file_size_known)
{
	fileinfo_t *fi;
	gchar *outname, *to_free = NULL;

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
		 * If download size is greater, we need to resize the output file.
		 * This can only happen for a download with a SHA1, because otherwise
		 * we perform a matching on name AND size.
		 */

		if (size > fi->size) {
			g_assert(fi->sha1);
			g_assert(sha1);

			g_warning("file \"%s\" (SHA1 %s) was %s bytes, resizing to %s",
				fi->file_name, sha1_base32(fi->sha1),
				uint64_to_string(fi->size), uint64_to_string2(size));

			file_info_hash_remove(fi);
			fi_resize(fi, size);
			file_info_hash_insert(fi);
		}

		fi_alias(fi, file, TRUE);	/* Add alias if not conflicting */

		return fi;
	}


	/* First convert the filename to what the GUI used */
	{
		gchar *s = unknown_to_utf8_normalized(file, UNI_NORM_NETWORK, NULL);
		if (file != s) {
			file = s;
			to_free = s;
		}
	}

	/* Now convert the UTF-8 to what the filesystem wants */
	{
		gchar *s = utf8_to_filename(file);
		g_assert(s != file);
		G_FREE_NULL(to_free);
		to_free = s;
		file = s;
	}

	/*
	 * Compute new output name.  If the filename is not taken yet, this
	 * will be exactly `file'.  Otherwise, it will be a variant.
	 */

	outname = file_info_new_outname(file, path);

	/*
	 * Check whether the file exists and has embedded meta info.
	 * Note that we use the new `outname', not `file'.
	 */

	if (NULL != (fi = file_info_retrieve_binary(outname, path))) {
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
			g_warning("found DEAD file \"%s\" in %s bearing SHA1 %s",
				outname, path, sha1_base32(fi->sha1));

			fi_rename_dead(fi, path, outname);
			fi_free(fi);
			fi = NULL;
		}
		else if (NULL != g_hash_table_lookup(fi_by_guid, fi->guid)) {
			g_warning("found DEAD file \"%s\" in %s with conflicting ID %s",
				outname, path, guid_hex_str(fi->guid));

			fi_rename_dead(fi, path, outname);
			fi_free(fi);
			fi = NULL;
		}
		else if (fi->size < size) {
			/*
			 * Existing file is smaller than the total size of this file.
			 * Trust the larger size, because it's the only sane thing to do.
			 * NB: if we have a SHA1, we know it's matching at this point.
			 */

			g_warning("found existing file \"%s\" size=%s, increasing to %s",
				outname, uint64_to_string(fi->size), uint64_to_string2(size));

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
		fi = file_info_create(outname, path, size, sha1, file_size_known);
		fi_alias(fi, file, FALSE);
	}

	file_info_hash_insert(fi);

	if (sha1)
		dmesh_multiple_downloads(sha1, size, fi);

	atom_str_free_null(&outname);
	G_FREE_NULL(to_free);

	return fi;
}

/**
 * @returns a pointer to the file info struct if we have a file
 * identical to the given properties in the download queue already,
 * and NULL otherwise.
 */
fileinfo_t *
file_info_has_identical(gchar *file, filesize_t size, gchar *sha1)
{
	GSList *p;
	GSList *sizelist;
	GSList *list;
	fileinfo_t *fi;
	namesize_t nsk;

	if (strict_sha1_matching) {
		if (!sha1)
			return NULL;
		return file_info_lookup(file, size, sha1);
	}

	if (sha1) {
		fi = g_hash_table_lookup(fi_by_sha1, sha1);
		if (fi)
			return fi;
	}

	if (0 == size)
		return NULL;

	/*
	 * Compute list of entries whose size matches.  If none, it is a
	 * certainty we won't have any identical entry!
	 */

	sizelist = g_hash_table_lookup(fi_by_size, &size);
	if (NULL == sizelist)
		return NULL;
	g_assert(!gm_slist_is_looping(sizelist));
	g_assert(!g_slist_find(sizelist, NULL));

	/*
	 * Only retain entry by (name, size) if it is unique.
	 * We're not going to try to disambiguate between conflicting entries!
	 */

	nsk.name = file;
	nsk.size = size;

	list = g_hash_table_lookup(fi_by_namesize, &nsk);
	fi = NULL;
	
	g_assert(!gm_slist_is_looping(list));
	g_assert(!g_slist_find(list, NULL));

	if (NULL != list && NULL == g_slist_next(list))
		fi = list->data;

	if (fi && sha1 && fi->sha1 && sha1_eq(sha1, fi->sha1))
		return fi;

	/*
	 * Look up by similar filenames.  We go through the list of all the
	 * known fileinfo entries with an identical filesize.
	 */

	for (p = sizelist; p; p = p->next) {
		fi = p->data;
		file_info_check(fi);

		/* FIXME: FILE_SIZE_KNOWN: Should we provide another lookup?
		 *	-- JA 2004-07-21
		 */
		if (fi->file_size_known)
			g_assert(fi->size == size);
		g_assert(fi->refcount >= 0);

		/*
		 * Note that we consider `fi' structures where fi->refcount == 0.
		 * Since they are around, it means they were not marked as FI_F_DISCARD
		 * and therefore those files are still of interest.
		 */

		if (sha1 && fi->sha1) {
			if (sha1_eq(sha1, fi->sha1))
				return fi;
			else
				continue;				/* SHA1 mismatch, not identical! */
		}

		if (file_info_has_filename(fi, file))
			return fi;
	}

	return NULL;
}

/**
 * Set or clear the discard state for a fileinfo.
 */
void
file_info_set_discard(fileinfo_t *fi, gboolean state)
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
	GSList *fclist;
	gboolean restart;
	filesize_t done;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	do {
		struct dl_file_chunk *fc1, *fc2;

		restart = FALSE;
		done = 0;
		fc2 = NULL;
		for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
			fc1 = fc2;
			fc2 = fclist->data;

			if (fc2->download) {
				download_check(fc2->download);
			}

			if (DL_CHUNK_DONE == fc2->status)
				done += fc2->to - fc2->from;

			if (!fc1 || !fc2)
				continue;

			g_assert(fc1->to == fc2->from);

			if (fc1->status == fc2->status && fc1->download == fc2->download) {
				fc1->to = fc2->to;
				fi->chunklist = g_slist_remove(fi->chunklist, fc2);
				wfree(fc2, sizeof *fc2);
				restart = TRUE;
				break;
			}
		}
	} while (restart);

	/*
	 * When file size is unknown, there may be no chunklist.
	 */

	if (fi->chunklist != NULL)
		fi->done = done;

	g_assert(file_info_check_chunklist(fi, TRUE));
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
	struct dl_file_chunk *fc;

	download_check(d);

	fi = d->file_info;
	file_info_check(fi);

	g_assert(!fi->file_size_known);
	g_assert(!fi->use_swarming);
	g_assert(fi->chunklist == NULL);

	/*
	 * Mark everything we have so far as done.
	 */

	if (fi->done) {
		fc = walloc(sizeof *fc);
		fc->from = 0;
		fc->to = fi->done;			/* Byte at that offset is excluded */
		fc->status = DL_CHUNK_DONE;

		fi->chunklist = g_slist_prepend(fi->chunklist, fc);
	}

	/*
	 * If the file size is less than the amount we think we have,
	 * then ignore it and mark the whole file as done.
	 */

	if (size > fi->done) {
		fc = walloc(sizeof *fc);
		fc->from = fi->done;
		fc->to = size;				/* Byte at that offset is excluded */
		fc->status = DL_CHUNK_BUSY;
		fc->download = d;

		fi->chunklist = g_slist_append(fi->chunklist, fc);
	}

	fi->file_size_known = TRUE;
	fi->use_swarming = TRUE;
	fi->size = size;
	fi->size_atom = atom_filesize_get(&fi->size);
	fi->dirty = TRUE;

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
file_info_update(struct download *d, filesize_t from, filesize_t to,
		enum dl_chunk_status status)
{
	GSList *fclist;
	int n;
	fileinfo_t *fi = d->file_info;
	struct dl_file_chunk *fc, *nfc;
	struct dl_file_chunk *prevfc;
	gboolean found = FALSE;
	int againcount = 0;
	gboolean need_merging = DL_CHUNK_DONE != status;
	struct download *newval = DL_CHUNK_EMPTY == status ? NULL : d;

	file_info_check(fi);
	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);
	g_assert(from < to);

	/*
	 * If file size is not known yet, the chunk list will be empty.
	 * Simply update the downloaded amount if the chunk is marked as done.
	 */

	if (!fi->file_size_known) {
		g_assert(fi->chunklist == NULL);
		g_assert(!fi->use_swarming);

		if (status == DL_CHUNK_DONE) {
			g_assert(from == fi->done);		/* Downloading continuously */
			fi->done += to - from;
		}

		goto done;
	}

	g_assert(file_info_check_chunklist(fi, TRUE));

	fi->stamp = tm_time();

	if (DL_CHUNK_DONE == status)
		fi->dirty = TRUE;

again:

	/* I think the algorithm is safe now, but hey... */
	if (++againcount > 10) {
		g_error("Eek! Internal error! "
			"file_info_update(%s, %s, %d) "
			"is looping for \"%s\"! Man battle stations!",
			uint64_to_string(from), uint64_to_string2(to),
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
		n = 0, prevfc = NULL, fclist = fi->chunklist;
		fclist;
		n++, prevfc = fc, fclist = g_slist_next(fclist)
	) {
		fc = fclist->data;

		if (fc->to <= from) continue;
		if (fc->from >= to) break;

		if ((fc->from == from) && (fc->to == to)) {

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

		} else if ((fc->from == from) && (fc->to < to)) {

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

		} else if ((fc->from == from) && (fc->to > to)) {

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
				nfc = walloc(sizeof *nfc);
				nfc->from = to;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;

				fc->to = to;
				fc->status = status;
				fc->download = newval;
				gm_slist_insert_after(fi->chunklist, fclist, nfc);
				g_assert(file_info_check_chunklist(fi, TRUE));
			}

			found = TRUE;
			break;

		} else if ((fc->from < from) && (fc->to >= to)) {

			/*
			 * New chunk [from, to] lies within ]fc->from, fc->to].
			 */

			if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;

			if (DL_CHUNK_DONE == status)
				fi->done += to - from;

			if (fc->to > to) {
				nfc = walloc(sizeof *nfc);
				nfc->from = to;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;
				gm_slist_insert_after(fi->chunklist, fclist, nfc);
			}

			nfc = walloc(sizeof *nfc);
			nfc->from = from;
			nfc->to = to;
			nfc->status = status;
			nfc->download = newval;
			gm_slist_insert_after(fi->chunklist, fclist, nfc);

			fc->to = from;

			found = TRUE;
			g_assert(file_info_check_chunklist(fi, TRUE));
			break;

		} else if ((fc->from < from) && (fc->to < to)) {

			filesize_t tmp;

			if (DL_CHUNK_DONE == fc->status)
				need_merging = TRUE;

			if (DL_CHUNK_DONE == status)
				fi->done += fc->to - from;

			nfc = walloc(sizeof *nfc);
			nfc->from = from;
			nfc->to = fc->to;
			nfc->status = status;
			nfc->download = newval;
			gm_slist_insert_after(fi->chunklist, fclist, nfc);

			tmp = fc->to;
			fc->to = from;
			from = tmp;
			g_assert(file_info_check_chunklist(fi, TRUE));
			goto again;
		}
	}

	if (!found) {
		/* Should never happen. */
		g_warning("file_info_update(): "
			"(%s) Didn't find matching chunk for <%s-%s> (%u)",
			fi->file_name, uint64_to_string(from),
			uint64_to_string2(to), status);

		for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
			fc = fclist->data;
			g_warning("... %s %s %u", uint64_to_string(fc->from),
				uint64_to_string2(fc->to), fc->status);
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

	if (DL_CHUNK_DONE == status)
		file_info_fd_store_binary(d->file_info, d->out_file, FALSE);
	else if (fi->dirty)
		file_info_store_binary(d->file_info);

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
file_info_clear_download(struct download *d, gboolean lifecount)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	fileinfo_t *fi = d->file_info;
	gint busy;			/**< For assertions only */

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	for (fclist = fi->chunklist, busy = 0; fclist; fclist = fclist->next) {
		fc = fclist->data;
		if (DL_CHUNK_BUSY == fc->status)
			busy++;
		if (fc->download == d) {
		    fc->download = NULL;
		    if (DL_CHUNK_BUSY == fc->status)
				fc->status = DL_CHUNK_EMPTY;
		}
	}
	file_info_merge_adjacent(d->file_info);

	g_assert(fi->lifecount >= (lifecount ? busy : (busy - 1)));

	/*
	 * No need to flush data to disk, those are transient
	 * changes. However, we do need to trigger a status change,
	 * because other parts of gtkg, i.e. the visual progress view,
	 * needs to know about them.
	 */
	event_trigger(fi_events[EV_FI_STATUS_CHANGED_TRANSIENT],
	      T_NORMAL(fi_listener_t, (fi->fi_handle)));
}

/**
 * Reset all chunks to EMPTY, clear computed SHA1 if any.
 */
void
file_info_reset(fileinfo_t *fi)
{
	struct dl_file_chunk *fc;
	GSList *list;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	atom_sha1_free_null(&fi->cha1);

	if (NULL != fi->sf)				/* File possibly shared */
		file_info_upload_stop(fi, "File info being reset");

restart:
	for (list = fi->chunklist; list; list = g_slist_next(list)) {
		struct download *d;

		fc = list->data;
		d = fc->download;
		if (d) {
			download_check(d);

			if (DOWNLOAD_IS_RUNNING(d)) {
				download_queue(d, "Requeued due to file removal");
				goto restart;	/* Because file_info_clear_download() called */
			}
		}
	}

	for (list = fi->chunklist; list; list = g_slist_next(list)) {
		fc = list->data;
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
	GSList *fclist;
	struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;
		if ((from >= fc->from) && (to <= fc->to))
			return fc->status;
	}

	/*
	 * Ending up here will normally mean that the tested range falls over
	 * multiple chunks in the list. In that case, chances are that it's
	 * not complete, and that's our assumption...
	 */

	return DL_CHUNK_BUSY;
}

/**
 * @returns the status (EMPTY, BUSY or DONE) of the byte requested.
 * Used to detect if a download is crashing with another.
 */
enum dl_chunk_status
file_info_pos_status(fileinfo_t *fi, filesize_t pos /* XXX,
	filesize_t *start, filesize_t *end */)
{
	GSList *fclist;
	struct dl_file_chunk *fc;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;
		if ((pos >= fc->from) && (pos < fc->to)) {
#if 0
			if (start)
				*start = fc->from;
			if (end)
				*end = fc->to;
#endif
			return fc->status;
		}
	}

	if (pos > fi->size)
		g_warning("file_info_pos_status(): unreachable position %s "
			"in %s-byte file \"%s\"", uint64_to_string(pos),
			uint64_to_string2(fi->size), fi->file_name);

#if 0
	if (start)
		*start = 0;
	if (end)
		*end = 0;
#endif

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
	char *path;
	struct stat buf;

	file_info_check(fi);
	g_assert(fi->done);			/* Or file will not exist */

	/*
	 * File should exist since fi->done > 0, and it was not completed.
	 */

	path = make_pathname(fi->path, fi->file_name);
	g_return_if_fail(path);

	if (-1 == do_stat(path, &buf) && ENOENT == errno) {
		g_warning("file %s removed, resetting swarming", path);
		file_info_reset(fi);
	}
	G_FREE_NULL(path);
}

/**
 * Count the amount of BUSY chunks attached to a given download.
 */
static gint
fi_busy_count(fileinfo_t *fi, struct download *d)
{
	GSList *sl;
	gint count = 0;

	download_check(d);
	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	for (sl = fi->chunklist; sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;

		if (fc->download) {
			download_check(d);
			if (fc->download == d && DL_CHUNK_BUSY == fc->status)
				count++;
		}
	}

	g_assert(fi->lifecount >= count);

	return count;
}

static filesize_t
get_random_offset(filesize_t size)
{
	filesize_t offset;

	offset = 0;
	if (size > 1) {
		guint i;
		
		for (i = 0; i < sizeof(offset); i++) {
			offset ^= (filesize_t) random_raw() << (i * CHAR_BIT);
		}
		offset %= size - 1;
	}
	return offset;
}

/**
 * Clone fileinfo's chunk list, shifting the origin of the list to a randomly
 * selected offset within the file.  If the first chunk is not completed
 * or not at least `pfsp_first_chunk' bytes long, the original list is
 * returned.
 */
static GSList *
list_clone_shift(fileinfo_t *fi)
{
	struct dl_file_chunk *fc;
	filesize_t offset;
	GSList *clone;
	GSList *sl;
	GSList *tail;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	fc = fi->chunklist->data;		/* First chunk */

	if (DL_CHUNK_DONE != fc->status || fc->to < pfsp_first_chunk)
		return fi->chunklist;

	offset = get_random_offset(fi->size);
	
	/*
	 * First pass: clone the list starting at the first chunk whose start is
	 * after the offset.
	 */

	clone = NULL;

	for (sl = fi->chunklist; sl; sl = g_slist_next(sl)) {
		fc = sl->data;
		if (fc->from >= offset) {
			clone = g_slist_copy(sl);
			break;
		}
	}

	/*
	 * If we have not cloned anything, it means we have a big chunk
	 * at the end and the selected offset lies within that chunk.
	 * Be smarter and break-up any free chunk into two at the selected offset.
	 */

	if (NULL == clone) {
		for (sl = fi->chunklist; sl; sl = g_slist_next(sl)) {
			fc = sl->data;
			if (DL_CHUNK_EMPTY == fc->status && fc->to - 1 > offset) {
				struct dl_file_chunk *nfc;

				g_assert(fc->from < offset);	/* Or we'd have cloned above */

				/*
				 * fc was [from, to[.  It becomes [from, offset[.
				 * nfc is [offset, to[ and is inserted after fc.
				 */

				nfc = walloc(sizeof *nfc);
				nfc->from = offset;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;
				fc->to = nfc->from;

				if (nfc->download) {
					download_check(nfc->download);
				}

				fi->chunklist = gm_slist_insert_after(fi->chunklist, sl, nfc);
				clone = g_slist_copy(g_slist_next(sl));
				break;
			}
		}

		g_assert(file_info_check_chunklist(fi, TRUE));
	}

	/*
	 * If still no luck, never mind.  Use original list.
	 */

	if (NULL == clone)
		return fi->chunklist;

	/*
	 * Second pass: append to the `clone' list all the chunks that end
	 * before the "from" of the first item in that list.
	 */

	fc = clone->data;
	offset = fc->from;				/* Cloning point: start of first chunk */
	tail = g_slist_last(clone);

	for (sl = fi->chunklist; sl; sl = g_slist_next(sl)) {
		fc = sl->data;
		if (fc->to > offset)		/* Not ">=" or we'd miss one chunk */
			break;					/* We've reached the cloning point */
		g_assert(fc->from < offset);
		clone = gm_slist_insert_after(clone, tail, fc);
		tail = g_slist_next(tail);
	}

	return clone;
}

/**
 * Compute chunksize to be used for the current request.
 */
static filesize_t
fi_chunksize(fileinfo_t *fi)
{
	filesize_t chunksize;
	gint src_count;

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
	 */

	if (chunksize < dl_minchunksize) chunksize = dl_minchunksize;
	if (chunksize > dl_maxchunksize) chunksize = dl_maxchunksize;

	return chunksize;
}

/**
 * Finds a range to download, and stores it in *from and *to.
 * If "aggressive" is off, it will return only ranges that are
 * EMPTY. If on, and no EMPTY ranges are available, it will
 * grab a chunk out of the longest BUSY chunk instead, and
 * "compete" with the download that reserved it.
 */
enum dl_chunk_status
file_info_find_hole(struct download *d, filesize_t *from, filesize_t *to)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	fileinfo_t *fi = d->file_info;
	filesize_t chunksize;
	guint busy = 0;
	GSList *cklist;
	gboolean cloned = FALSE;

	file_info_check(fi);
	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);
	g_assert(0 == fi_busy_count(fi, d));	/* No reservation for `d' yet */
	g_assert(file_info_check_chunklist(fi, TRUE));

	/*
	 * Ensure the file has not disappeared.
	 */

	if (fi->done) {
		if (fi->done == fi->size)
			return DL_CHUNK_DONE;

		fi_check_file(fi);
	}

	/*
	 * XXX Mirar reported that this assert sometimes fails.  Too close to
	 * XXX the release, and it's not something worth panicing.
	 * XXX This happens after "Requeued by file info change".
	 * XXX Replacing with a warning for now.
	 * XXX		--RAM, 17/10/2002
	 */

#if 0
	g_assert(fi->size >= d->file_size);
#endif /* 0 */

	if (fi->size < d->file_size) {
		g_warning("fi->size=%s < d->file_size=%s for \"%s\"",
			uint64_to_string(fi->size), uint64_to_string2(d->file_size),
			fi->file_name);
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
		pfsp_server && d->served_reqs == 0 &&
		fi_alive_count(fi) <= FI_LOW_SRC_COUNT		/* Not enough sources */
	) {
		/*
		 * If we have enough to share the file, we can reduce the chunksize.
		 * Otherwise, try to get the amount we miss first, to be able
		 * to advertise ourselves as soon as possible.
		 */

		if (fi->size >= pfsp_minimum_filesize)
			chunksize = dl_minchunksize;
		else {
			filesize_t missing = pfsp_minimum_filesize - fi->size;

			chunksize = MAX(chunksize, missing);
			chunksize = MIN(chunksize, dl_maxchunksize);
		}
	}

	/*
	 * If PFSP-server is enabled, we can serve partially downloaded files.
	 * Therefore, it is interesting to request chunks in random order, to
	 * avoid everyone having the same chunks should full sources disappear.
	 *		--RAM, 11/10/2003
	 */

	if (pfsp_server) {
		cklist = list_clone_shift(fi);
		if (cklist != fi->chunklist)
			cloned = TRUE;
	} else
		cklist = fi->chunklist;

	for (fclist = cklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;

		if (DL_CHUNK_EMPTY != fc->status) {
			if (DL_CHUNK_BUSY == fc->status)
				busy++;		/* Will be used by assert below */
			continue;
		}

		*from = fc->from;
		*to = fc->to;
		if ((fc->to - fc->from) > chunksize)
			*to = fc->from + chunksize;

		file_info_update(d, *from, *to, DL_CHUNK_BUSY);
		goto selected;
	}

	g_assert(fi->lifecount > (gint32) busy); /* Or we'd found a chunk before */

	if (use_aggressive_swarming) {
		filesize_t longest_from = 0, longest_to = 0;
		gint starving;
		filesize_t minchunk;

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
		minchunk = MIN(dl_minchunksize, fi->size - fi->done) / (2 * starving);
		if (minchunk < FI_MIN_CHUNK_SPLIT)
			minchunk = FI_MIN_CHUNK_SPLIT;

		for (fclist = cklist; fclist; fclist = g_slist_next(fclist)) {
			fc = fclist->data;

			if (DL_CHUNK_BUSY != fc->status) continue;
			if ((fc->to - fc->from) < minchunk) continue;

			if ((fc->to - fc->from) > (longest_to - longest_from)) {
				longest_from = fc->from;
				longest_to = fc->to;
			}
		}

		if (longest_to) {
			/* Start in the middle of the longest range. */
			*from = (longest_from + longest_to) / 2;
			*to = longest_to;

			file_info_update(d, *from, *to, DL_CHUNK_BUSY);
			goto selected;
		}
	}

	/* No holes found. */

	if (cloned)
		g_slist_free(cklist);

	return (fi->done == fi->size) ? DL_CHUNK_DONE : DL_CHUNK_BUSY;

selected:	/* Selected a hole to download */

	g_assert(file_info_check_chunklist(fi, TRUE));

	if (cloned)
		g_slist_free(cklist);

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
gboolean
file_info_find_available_hole(
	struct download *d, GSList *ranges, filesize_t *from, filesize_t *to)
{
	GSList *fclist;
	fileinfo_t *fi;
	filesize_t chunksize;
	GSList *cklist;
	gboolean cloned = FALSE;

	g_assert(d);
	g_assert(ranges);

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
	 */

	if (pfsp_server) {
		cklist = list_clone_shift(fi);
		if (cklist != fi->chunklist)
			cloned = TRUE;
	} else
		cklist = fi->chunklist;

	for (fclist = cklist; fclist; fclist = g_slist_next(fclist)) {
		GSList *sl;
		struct dl_file_chunk *fc = fclist->data;

		if (DL_CHUNK_EMPTY != fc->status)
			continue;

		/*
		 * Look whether this empty chunk intersects with one of the
		 * available ranges.
		 *
		 * NB: the list of ranges is sorted.  And contrary to fi chunks,
		 * the upper boundary of the range (r->end) is part of the range.
		 */

		for (sl = ranges; sl; sl = g_slist_next(sl)) {
			http_range_t *r = sl->data;

			if (r->start > fc->to)
				break;					/* No further range will intersect */

			if (r->start >= fc->from && r->start < fc->to) {
				*from = r->start;
				*to = MIN(r->end + 1, fc->to);
				goto found;
			}

			if (r->end >= fc->from && r->end < fc->to) {
				*from = MAX(r->start, fc->from);
				*to = r->end + 1;
				goto found;
			}
		}
	}

	if (cloned)
		g_slist_free(cklist);

	return FALSE;

found:
	chunksize = fi_chunksize(fi);

	if ((*to - *from) > chunksize)
		*to = *from + chunksize;

	file_info_update(d, *from, *to, DL_CHUNK_BUSY);

	if (cloned)
		g_slist_free(cklist);

	return TRUE;
}

/**
 * @return a dl_file_info if there's an active one with the same sha1.
 */
static fileinfo_t *
file_info_active(const gchar *sha1)
{
	return g_hash_table_lookup(fi_by_sha1, sha1);
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
	const gchar *file_name, guint32 idx, const host_addr_t addr, guint16 port,
	const gchar *sha1)
{
	fileinfo_t *fi;

	if (!can_swarm)				/* Downloads not initialized yet */
		return;

	fi = file_info_active(sha1);
	if (!fi)
		return;

	file_info_check(fi);
	download_auto_new(file_name ? file_name : fi->file_name,
		fi->size, idx, addr, port, blank_guid, NULL,
		sha1, tm_time(), TRUE, fi, NULL, /* XXX: TLS? */ 0);
}

/**
 * Scan the given directory for files, looking at those bearing a valid
 * fileinfo trailer, yet which we know nothing about.
 */
void
file_info_scandir(const gchar *dir)
{
	DIR *d;
	struct dirent *dentry;
	fileinfo_t *fi;
	gchar *filename = NULL;

	d = opendir(dir);
	if (NULL == d) {
		g_warning("can't open directory %s: %s", dir, g_strerror(errno));
		return;
	}

	while (NULL != (dentry = readdir(d))) {
		struct stat buf;

		if (NULL != filename)
			G_FREE_NULL(filename);

		if (
			0 == strcmp(dentry->d_name, ".") ||
			0 == strcmp(dentry->d_name, "..")
		) {
				continue;					/* Skip "." and ".." */
		}

		filename = make_pathname(dir, dentry->d_name);
		if (NULL == filename)
			continue;

		if (-1 == stat(filename, &buf)) {
			g_warning("cannot stat %s: %s", filename, g_strerror(errno));
			continue;
		}

		if (!S_ISREG(buf.st_mode))			/* Only regular files */
			continue;

		fi = file_info_retrieve_binary(dentry->d_name, dir);
		if (NULL == fi)
			continue;

		if (file_info_lookup_dup(fi)) {		/* Already know about this */
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
			fi->sha1 ? "with" : "no", filename);
	}

	G_FREE_NULL(filename);
	closedir(d);
}

/**
 * Callback for hash table iterator. Used by file_info_completed_orphans().
 */
static void
fi_spot_completed_kv(gpointer key, gpointer val, gpointer unused_x)
{
	const gchar *name = key;
	fileinfo_t *fi = val;

	(void) unused_x;
	file_info_check(fi);
	g_assert(name == fi->file_name);	/* name shared with fi's, don't free */

	if (fi->refcount)					/* Attached to a download */
		return;

	/*
	 * If the file is 100% done, fake a new download.
	 *
	 * It will be trapped by download_resume_bg_tasks() and handled
	 * as any complete download.
	 */

	if (FILE_INFO_COMPLETE(fi))
		download_orphan_new(fi->file_name, fi->size, fi->sha1, fi);
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
	g_hash_table_foreach(fi_by_outname, fi_spot_completed_kv, NULL);
}

void
fi_add_listener(fi_listener_t cb, gnet_fi_ev_t ev,
	frequency_t t, guint32 interval)
{
    g_assert(ev < EV_FI_EVENTS);

    event_add_subscriber(fi_events[ev], (GCallback) cb, t, interval);
}

void
fi_remove_listener(fi_listener_t cb, gnet_fi_ev_t ev)
{
    g_assert(ev < EV_FI_EVENTS);

    event_remove_subscriber(fi_events[ev], (GCallback) cb);
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
	const gchar *sha1;

    fi = file_info_find_by_handle(fih);
	file_info_check(fi);

    info = walloc(sizeof *info);

    info->path = fi->path ? atom_str_get(fi->path) : NULL;
    info->file_name = fi->file_name ? atom_str_get(fi->file_name) : NULL;
	sha1 = fi->sha1 ? fi->sha1 : fi->cha1;
    info->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
    info->fi_handle = fi->fi_handle;
	info->aliases   = NULL;

	if (fi->alias) {
		GSList *sl;

		for (sl = fi->alias; sl; sl = g_slist_next(sl)) {
			const gchar *alias = sl->data;
			info->aliases = g_slist_prepend(info->aliases, atom_str_get(alias));
		}
	}

    return info;
}

/**
 * Dispose of the info structure.
 */
void
fi_free_info(gnet_fi_info_t *info)
{
	GSList *sl;

    g_assert(NULL != info);

	atom_str_free_null(&info->path);
	atom_str_free_null(&info->file_name);
	atom_sha1_free_null(&info->sha1);

	for (sl = info->aliases; NULL != sl; sl = g_slist_next(sl)) {
		gchar *s = sl->data;
		atom_str_free_null(&s);
	}
	g_slist_free(info->aliases);
	info->aliases = NULL;

    wfree(info, sizeof *info);
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
    s->recv_last_rate = fi->recv_last_rate;
    s->size           = fi->size;
    s->aqueued_count  = fi->aqueued_count;
    s->pqueued_count  = fi->pqueued_count;

	if (fi->done == fi->size) {
		s->has_sha1 = fi->sha1 != NULL;
		if (fi->sha1) {
			s->sha1_hashed = fi->cha1_hashed;
			s->sha1_matched = fi->sha1 == fi->cha1;		/* Atoms... */
		}
		if (fi->copied)
			s->copied = fi->copied;
	}
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
    fileinfo_t *fi = file_info_find_by_handle(fih);
    GSList *sl, *chunks = NULL;

    file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

    for (sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
        struct dl_file_chunk *fc = sl->data;
    	gnet_fi_chunks_t *chunk;

        chunk = walloc(sizeof *chunk);
        chunk->from   = fc->from;
        chunk->to     = fc->to;
        chunk->status = fc->status;
        chunk->old    = TRUE;

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
        wfree(chunk, sizeof *chunk);
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
    http_range_t *range = NULL;
	GSList *ranges = NULL;
    const GSList *sl;

    file_info_check(fi);

    for (sl = fi->seen_on_network; NULL != sl; sl = g_slist_next(sl)) {
        const http_range_t *r = sl->data;
        range = walloc(sizeof *range);
        range->start = r->start;
        range->end   = r->end;

		ranges = g_slist_prepend(ranges, range);
	}

    return g_slist_reverse(ranges);
}

void
fi_free_ranges(GSList *ranges)
{
	GSList *sl;

	for (sl = ranges; NULL != sl; sl = g_slist_next(sl)) {
        http_range_t *r = sl->data;
		wfree(r, sizeof *r);
	}

	g_slist_free(ranges);
}



/**
 * @return NULL terminated array of gchar * pointing to the aliases.
 * You can easily free the returned array with g_strfreev().
 *
 * O(2n) - n: number of aliases
 */
gchar **
fi_get_aliases(gnet_fi_t fih)
{
    gchar **a;
    guint len;
    GSList *sl;
    guint n;
    fileinfo_t *fi = file_info_find_by_handle(fih);

    len = g_slist_length(fi->alias);

    a = g_malloc((len + 1) * sizeof a[0]);
    a[len] = NULL; /* terminate with NULL */;

    for (sl = fi->alias, n = 0; NULL != sl; sl = g_slist_next(sl), n++) {
        g_assert(n < len);
        a[n] = g_strdup(sl->data);
    }

    return a;
}

/**
 * Add new download source for the file.
 */
void
file_info_add_new_source(fileinfo_t *fi, struct download *dl)
{
	fi->ntime = tm_time();
	file_info_add_source(fi, dl);
}

/**
 * Add download source for the file, but preserve original "ntime".
 */
void
file_info_add_source(fileinfo_t *fi, struct download *dl)
{
	file_info_check(fi);
    g_assert(NULL == dl->file_info);
    g_assert(!DOWNLOAD_IS_VISIBLE(dl)); /* Must be removed from the GUI first */

    fi->refcount++;
    fi->dirty_status = TRUE;
    dl->file_info = fi;
    fi->sources = g_slist_prepend(fi->sources, dl);

	if (1 == fi->refcount) {
		gnet_prop_set_guint32_val(PROP_FI_WITH_SOURCE_COUNT,
			fi_with_source_count + 1);
		g_assert(fi_with_source_count <= fi_all_count);
	}

    event_trigger(fi_events[EV_FI_SRC_ADDED],
        T_NORMAL(fi_src_listener_t, (fi->fi_handle, dl->src_handle)));
}

/**
 * Removing one source reference from the fileinfo.
 * When no sources reference the fileinfo structure, free it if `discard'
 * is TRUE, or if the fileinfo has been marked with FI_F_DISCARD.
 * This replaces file_info_free()
 */
void
file_info_remove_source(
	fileinfo_t *fi, struct download *dl, gboolean discard)
{
	file_info_check(fi);
    g_assert(NULL != dl->file_info);
    g_assert(fi->refcount > 0);
	g_assert(fi->hashed);

    event_trigger(fi_events[EV_FI_SRC_REMOVED],
        T_NORMAL(fi_src_listener_t, (fi->fi_handle, dl->src_handle)));

    fi->refcount--;
    fi->dirty_status = TRUE;
    dl->file_info = NULL;
    fi->sources = g_slist_remove(fi->sources, dl);

	/*
	 * We don't free the structure when `discard' is FALSE: keeping the
	 * fileinfo around means it's still in the hash tables, and therefore
	 * that its SHA1, if any, is still around to help us spot duplicates.
	 *
	 * At times however, we really want to discard an unreferenced fileinfo
	 * as soon as this happens.
	 */

    if (0 == fi->refcount) {
		gnet_prop_set_guint32_val(PROP_FI_WITH_SOURCE_COUNT,
			fi_with_source_count - 1);
		g_assert((gint) fi_with_source_count >= 0);

		if (discard || (fi->flags & FI_F_DISCARD)) {
			file_info_hash_remove(fi);
			fi_free(fi);
		}
    }
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
fi_notify_helper(gpointer unused_key, gpointer value, gpointer unused_udata)
{
    fileinfo_t *fi = value;

	(void) unused_key;
	(void) unused_udata;

	file_info_check(fi);
    if (!fi->dirty_status)
        return;

    fi->dirty_status = FALSE;
	file_info_changed(fi);
}

void
file_info_timer(void)
{
	g_hash_table_foreach(fi_by_outname, fi_notify_helper, NULL);
}

/**
 * Kill all downloads associated with a fi and remove the fi itself.
 *
 * Will return FALSE if download could not be removed because it was still in
 * use, e.g. when it is being verified.
 * 		-- JA 25/10/03
 */
static gboolean
fi_purge(gnet_fi_t fih)
{
	GSList *sl;
	GSList *csl;
	fileinfo_t *fi = file_info_find_by_handle(fih);
	gboolean do_remove;

	file_info_check(fi);
	g_assert(fi->hashed);

	do_remove = !(fi->flags & FI_F_DISCARD) || NULL == fi->sources;
	csl = g_slist_copy(fi->sources);	/* Clone list, orig can be modified */

	for (sl = csl; NULL != sl; sl = g_slist_next(sl)) {
		struct download *dl = sl->data;

		download_abort(dl);
		if (!download_remove(dl)) {
			g_slist_free(csl);

			return FALSE;
		}
	}

	g_slist_free(csl);

	if (do_remove) {
		/*
	 	* Downloads not freed at this point, this will happen when the
	 	* download_free_removed() is asynchronously called.  However, all
	 	* references to the file info has been cleared, so we can remove it.
	 	*/

		g_assert(0 == fi->refcount);

		if (!FILE_INFO_COMPLETE(fi))	/* Paranoid: don't lose if complete */
			file_info_unlink(fi);
		file_info_hash_remove(fi);
		fi_free(fi);
	}

	return TRUE;
}

/**
 * Purge all handles contained in list.
 */
void
fi_purge_by_handle_list(const GSList *list)
{
    const GSList *sl;

    for (sl = list; NULL != sl; sl = g_slist_next(sl)) {
        fi_purge((gnet_fi_t) GPOINTER_TO_UINT(sl->data));
    }
}

/**
 * Emit an X-Available-Ranges header listing the ranges within the file that
 * we have on disk and we can share as a PFSP-server.  The header is emitted
 * in `buf', which is `size' bytes long.
 *
 * If there is not enough room to emit all the ranges, emit a random subset
 * of the ranges.
 *
 * @returns the size of the generated header.
 */
gint
file_info_available_ranges(fileinfo_t *fi, gchar *buf, gint size)
{
	gpointer fmt;
	gboolean is_first = TRUE;
	gchar range[80];
	GSList *sl;
	gint maxfmt = size - 3;		/* Leave room for trailing "\r\n" + NUL */
	gint count;
	gint nleft;
	gint i;
	struct dl_file_chunk **fc_ary;
	gint length;

	file_info_check(fi);
	g_assert(size >= 0);
	g_assert(file_info_check_chunklist(fi, TRUE));
	fmt = header_fmt_make("X-Available-Ranges", ", ", size);

	if (header_fmt_length(fmt) + sizeof "bytes 0-512\r\n" >= (size_t) size)
		goto emit;				/* Sorry, not enough room for anything */

	for (sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;
		gint rw;

		if (DL_CHUNK_DONE != fc->status)
			continue;

		rw = gm_snprintf(range, sizeof range, "%s%s-%s",
			is_first ? "bytes " : "",
			uint64_to_string(fc->from), uint64_to_string2(fc->to - 1));

		if (!header_fmt_value_fits(fmt, rw, maxfmt))
			break;			/* Will not fit, cannot emit all of it */

		header_fmt_append_value(fmt, range);
		is_first = FALSE;
	}

	if (NULL == sl)
		goto emit;

	/*
	 * Not everything fitted.  We have to be smarter and include only what
	 * can fit in the size we were given.
	 */

	header_fmt_free(fmt);
	fmt = header_fmt_make("X-Available-Ranges", ", ", size);
	is_first = TRUE;

	/*
	 * See how many chunks we have.
	 */

	for (count = 0, sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;
		if (DL_CHUNK_DONE == fc->status)
			count++;
	}

	/*
	 * Reference all the "done" chunks in `fc_ary'.
	 */

	g_assert(count > 0);		/* Or there would be nothing to emit */

	fc_ary = g_malloc(count * sizeof fc_ary[0]);

	for (i = 0, sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;
		if (DL_CHUNK_DONE == fc->status)
			fc_ary[i++] = fc;
	}

	g_assert(i == count);

	/*
	 * Now select chunks randomly from the set, and emit them if they fit.
	 */

	for (nleft = count; nleft > 0; nleft--) {
		gint j = random_value(nleft - 1);
		struct dl_file_chunk *fc = fc_ary[j];
		gint rw;
		gint len;

		g_assert(j >= 0 && j < nleft);
		g_assert(DL_CHUNK_DONE == fc->status);

		rw = gm_snprintf(range, sizeof range, "%s%s-%s",
			is_first ? "bytes " : "",
			uint64_to_string(fc->from), uint64_to_string2(fc->to - 1));

		len = header_fmt_length(fmt);

		if ((size_t) len + sizeof "bytes 0-512\r\n" >= (size_t) maxfmt)
			break;			/* No more room, no need to continue */

		if (header_fmt_value_fits(fmt, rw, maxfmt)) {
			header_fmt_append_value(fmt, range);
			is_first = FALSE;
		}

		/*
		 * Shift upper (nleft - j - 1) items down 1 position.
		 */

		if (nleft - 1 != j)
			memmove(&fc_ary[j], &fc_ary[j + 1],
				(nleft - j - 1) * sizeof fc_ary[0]);
	}

	G_FREE_NULL(fc_ary);

emit:
	length = 0;

	if (!is_first) {			/* Something was recorded */
		header_fmt_end(fmt);
		length = header_fmt_length(fmt);
		g_assert(length < size);
		strncpy(buf, header_fmt_string(fmt), length + 1);	/* with final NUL */
	}

	header_fmt_free(fmt);

	return length;
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
gboolean
file_info_restrict_range(fileinfo_t *fi, filesize_t start, filesize_t *end)
{
	GSList *sl;

	file_info_check(fi);
	g_assert(file_info_check_chunklist(fi, TRUE));

	for (sl = fi->chunklist; NULL != sl; sl = g_slist_next(sl)) {
		struct dl_file_chunk *fc = sl->data;

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
 */
gchar *
file_info_build_magnet(gnet_fi_t handle)
{
	struct magnet_resource *magnet;
	const fileinfo_t *fi;
	const GSList *sl;
	gchar *url;
	gint n;
   
	fi = file_info_find_by_handle(handle);
	g_return_val_if_fail(fi, NULL);
	file_info_check(fi);

	magnet = magnet_resource_new();
	if (fi->sha1) {
		magnet_set_sha1(magnet, fi->sha1);
	}
	if (fi->file_name) {
		magnet_set_display_name(magnet, fi->file_name);
	}
	if (fi->file_size_known && fi->size) {
		magnet_set_filesize(magnet, fi->size);
	}

	n = 0;
	for (sl = fi->sources; NULL != sl && n++ < 20; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		gchar *dl_url;

		g_assert(d);
		dl_url = download_build_url(d);
		if (dl_url) {
			magnet_add_source_by_url(magnet, dl_url);
		}
	}

	url = magnet_to_string(magnet);
	magnet_resource_free(magnet);
	return url;
}

/**
 * Create a ranges list with one item covering the whole file.
 * This may be better placed in http.c, but since it is only
 * used here as a utility function for fi_update_seen_on_network
 * it is now placed here.
 *
 * @param[in] size  File size to be used in range creation
 */
static GSList *
fi_range_for_complete_file(filesize_t size)
{
	http_range_t *range;

	range = walloc(sizeof *range);
	range->start = 0;
	range->end = size - 1;

    return g_slist_append(NULL, range);
}

/**
 * Callback for updates to ranges available on the network.
 *
 * This function gets triggered by an event when new ranges
 * information has become available for a download source.
 * We collect the set of currently available ranges in
 * file_info->seen_on_network. Currently we only fold in new ranges
 * from a download source, but we should also remove sets of ranges when
 * a download source is no longer available.
 *
 * @param[in] srcid  The abstract id of the source that had its ranges updated.
 *
 * @bug
 * FIXME: also remove ranges when a download source is no longer available.
 */
static void
fi_update_seen_on_network(gnet_src_t srcid)
{
	struct download *d;
	GSList *old_list;    /* The previous list of ranges, no longer needed */
	GSList *sl;           /* Temporary pointer to help remove old_list */
	GSList *r = NULL;
	GSList *new_r = NULL;

	d = src_get_download(srcid);
	g_assert(d);

	old_list = d->file_info->seen_on_network;

	/*
	 * FIXME: this code is currently only triggered by new HTTP ranges
	 * information becoming available. In addition to that we should perhaps
	 * also include add_source and delete_source. We will miss the latter in
	 * this setup especially.
	 */

	/*
	 * Look at all the download sources for this fileinfo and calculate the
	 * overall ranges info for this file.
	 */
	if (fileinfo_debug > 5)
		printf("*** Fileinfo: %s\n", d->file_info->file_name);

	for (sl = d->file_info->sources; sl; sl = g_slist_next(sl)) {
		struct download *src = sl->data;
		/*
		 * We only count the ranges of a file if it has replied to a recent
		 * request, and if the download request is not done or in an error
		 * state.
		 */
		if (
			src->flags & DL_F_REPLIED &&
			!(
				GTA_DL_COMPLETED == src->status ||
				GTA_DL_ERROR     == src->status ||
				GTA_DL_ABORTED   == src->status ||
				GTA_DL_REMOVED   == src->status ||
				GTA_DL_DONE      == src->status
			)
		) {
			if (fileinfo_debug > 5)
				printf("    %s:%d replied (%x, %x), ",
					host_addr_to_string(src->server->key->addr),
					src->server->key->port, src->flags, src->status);
			if (!src->file_info->use_swarming || NULL == src->ranges) {
				/*
				 * Indicate that the whole file is available.
				 * We could just stop here and assign the complete file range,
   				 * but I'm leaving the code as-is so that we can play with the
 				 * info more, e.g. show different colors for ranges that are
				 * available more.
				 * FIXME: it is not clear that the logic in this if()
				 * properly captures whether a whole file is available.
				 * This depends also on the HTTP error code, e.g. I
				 * believe that currently a 404 will also trigger a
				 * whole file is available event...
				*/
				if (fileinfo_debug > 5)
					printf("whole file available.\n");

				{
					GSList *full_r;

					full_r = fi_range_for_complete_file(d->file_info->size);
					new_r = http_range_merge(r, full_r);
					fi_free_ranges(full_r);
				}
			} else {
				/* Merge in the new ranges */
				if (fileinfo_debug > 5)
					printf(" ranges %s available\n",
						http_range_to_string(src->ranges));
				new_r = http_range_merge(r, src->ranges);
			}
			fi_free_ranges(r);
			r = new_r;
		}
	}
	d->file_info->seen_on_network = r;

	if (fileinfo_debug > 5)
		printf("    Final ranges: %s\n\n", http_range_to_string(r));

	/*
	 * Remove the old list and free its range elements
	 */
	fi_free_ranges(old_list);

	/*
	 * Trigger a changed ranges event so that others can use the updated info.
	 */
	event_trigger(fi_events[EV_FI_RANGES_CHANGED],
        T_NORMAL(fi_listener_t, (d->file_info->fi_handle)));
}

/**
 * Initialize fileinfo handling.
 */
void
file_info_init(void)
{
	tbuf.arena = g_malloc(TBUF_SIZE);
	tbuf.size = TBUF_SIZE;

#define bs_nop(x)	(x)

	BINARY_ARRAY_SORTED(fi_tag_map, struct fi_tag, str, strcmp, bs_nop);

#undef bs_nop

	fi_by_sha1     = g_hash_table_new(sha1_hash, sha1_eq);
	fi_by_namesize = g_hash_table_new(namesize_hash, namesize_eq);
	fi_by_size     = g_hash_table_new(filesize_hash, filesize_eq);
	fi_by_guid     = g_hash_table_new(guid_hash, guid_eq);
	fi_by_outname  = g_hash_table_new(g_str_hash, g_str_equal);

    fi_handle_map = idtable_new(32, 32);

    fi_events[EV_FI_ADDED]          = event_new("fi_added");
    fi_events[EV_FI_REMOVED]        = event_new("fi_removed");
    fi_events[EV_FI_INFO_CHANGED]   = event_new("fi_info_changed");	/* UNUSED */
    fi_events[EV_FI_STATUS_CHANGED] = event_new("fi_status_changed");
    fi_events[EV_FI_STATUS_CHANGED_TRANSIENT] =
									  event_new("fi_status_changed_transient");
    fi_events[EV_FI_SRC_ADDED]      = event_new("fi_src_added");
    fi_events[EV_FI_SRC_REMOVED]    = event_new("fi_src_removed");
	fi_events[EV_FI_RANGES_CHANGED] = event_new("fi_ranges_changed");
}

/**
 * Finish initialization of fileinfo handling. This post initialization is
 * needed to avoid circular dependencies during the init phase. The listener
 * we set up here is set up in download_init, but that must be called after
 * file_info_init.
 */
void
file_info_init_post(void)
{
	/* subscribe to src events on available range updates */
	src_add_listener(fi_update_seen_on_network, EV_SRC_RANGES_CHANGED,
		FREQ_SECS, 0);
}

/*
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4 sw=4 cindent:
 */
