/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Vidar Madsen & Raphael Manfredi
 *
 * Structure for storing meta-information about files being
 * downloaded.
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

#include "gnutella.h"

#include "fileinfo.h"
#include "downloads_gui.h"
#include "sockets.h"
#include "downloads.h"
#include "hosts.h"
#include "header.h"
#include "routing.h"
#include "routing.h"
#include "gmsg.h"
#include "bsched.h"
#include "huge.h"
#include "dmesh.h"
#include "search.h"
#include "guid.h"

#include "settings.h"
#include "nodes.h"
#include "http.h"			/* For http_range_t */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <time.h>			/* For ctime() */
#include <arpa/inet.h>		/* For ntohl() and friends... */
#include <dirent.h>
#include <ctype.h>			/* For iscntrl() */

RCSID("$Id$");

#define FI_MIN_CHUNK_SPLIT	512		/* Smallest chunk we can split */
#define FI_MAX_FIELD_LEN	1024	/* Max field length we accept to save */

/* made visible for us by atoms.c */
extern guint sha1_hash(gconstpointer key);
extern gint sha1_eq(gconstpointer a, gconstpointer b);

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
 * The `fi_by_namesize' hash table keeps track of the (name, size) -> fi one.
 * The `fi_by_outname' table keeps track of the "output name" -> fi link.
 */

static GHashTable *fi_by_sha1 = NULL;
static GHashTable *fi_by_namesize = NULL;
static GHashTable *fi_by_size = NULL;
GHashTable *fi_by_outname = NULL;

static const gchar *file_info_file = "fileinfo";
static const gchar *file_info_what = "the fileinfo database";
static gboolean fileinfo_dirty = FALSE;
static gboolean can_swarm = FALSE;		/* Set by file_info_retrieve() */

static gchar fi_tmp[4096];

#define FILE_INFO_MAGIC		0xD1BB1ED0
#define FILE_INFO_VERSION	3

enum dl_file_info_field {
	FILE_INFO_FIELD_NAME = 1,	/* No longer used in version >= 3 */
	FILE_INFO_FIELD_ALIAS,
	FILE_INFO_FIELD_SHA1,
	FILE_INFO_FIELD_CHUNK,
	FILE_INFO_FIELD_END,		/* Marks end of field section */
	FILE_INFO_FIELD_CHA1,
};

#define FI_STORE_DELAY		10	/* Max delay (secs) for flushing fileinfo */

/*
 * The swarming trailer is built within a memory buffer first, to avoid having
 * to issue mutliple write() system calls.	We can't use stdio's buffering
 * since we can sometime reuse the download's file descriptor.
 */
static struct {
	gchar *arena;			/* Base arena */
	gchar *wptr;			/* Write pointer */
	gchar *rptr;			/* Read pointer */
	gchar *end;				/* First byte off arena */
	guint32 size;			/* Current size of arena */
} tbuf;

#define TBUF_SIZE			512		/* Initial trailing buffer size */
#define TBUF_GROW_BITS		9		/* Growing chunks */

#define TBUF_GROW			(1 << TBUF_GROW_BITS)
#define TBUF_GROW_MASK		(TBUF_GROW - 1)

#define round_grow(x)		\
	((guint32) (((guint32) (x) + TBUF_GROW_MASK) & ~TBUF_GROW_MASK))

#define trunc_int32(x)		\
	((gulong) ((gulong) (x) & ~(sizeof(guint32)-1)))

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

#define READ_INT32(a) do {			\
	gint32 val;						\
	TBUF_GETINT32(&val);			\
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

/*
 * The trailer fields of the fileinfo trailer.
 */

struct trailer {
	guint32 filesize;		/* Real file size */
	guint32 generation;		/* Generation number */
	guint32 length;			/* Total trailer length */
	guint32 checksum;		/* Trailer checksum */
	guint32 magic;			/* Magic number */
};

static struct dl_file_info *file_info_retrieve_binary(
	const gchar *file, const gchar *path);
static void fi_free(struct dl_file_info *fi);
static void file_info_hash_remove(struct dl_file_info *fi);

static idtable_t *fi_handle_map = NULL;

#define file_info_find_by_handle(n) \
    (struct dl_file_info *) idtable_get_value(fi_handle_map, n)

#define file_info_request_handle(n) \
    idtable_new_id(fi_handle_map, n)

#define file_info_drop_handle(n) \
    idtable_free_id(fi_handle_map, n);

event_t *fi_events[EV_FI_EVENTS] = {
    NULL, NULL, NULL, NULL, NULL, NULL };

/*
 * tbuf_extend
 *
 * Make sure there is enough room in the buffer for `x' more bytes.
 * If `writing' is TRUE, we update the write pointer.
 */
static void tbuf_extend(guint32 x, gboolean writing)
{
	gint new_size = round_grow(x + tbuf.size);
	gint offset = tbuf.wptr - tbuf.arena;

	tbuf.arena = g_realloc(tbuf.arena, new_size);
	tbuf.end = tbuf.arena + new_size;
	tbuf.size = new_size;

	if (writing)
		tbuf.wptr = tbuf.arena + offset;
}

/*
 * tbuf_write
 *
 * Write trailer buffer at current position on `fd', whose name is `name'.
 */
static void tbuf_write(gint fd, gchar *name)
{
	g_assert(fd >= 0);
	g_assert(TBUF_WRITTEN_LEN() > 0);

	if (-1 == write(fd, tbuf.arena, TBUF_WRITTEN_LEN()))
		g_warning("error while flushing trailer info for \"%s\": %s",
			name, g_strerror(errno));
}

/*
 * tbuf_read
 *
 * Read trailer buffer at current position from `fd'.
 * Returns -1 on error.
 */
static gint tbuf_read(gint fd, gint len)
{
	g_assert(fd >= 0);

	TBUF_INIT_READ(len);

	return read(fd, tbuf.arena, len);
}

/*
 * file_info_init
 *
 * Initialize fileinfo handling.
 */
void file_info_init(void)
{
	tbuf.arena = g_malloc(TBUF_SIZE);
	tbuf.size = TBUF_SIZE;

	fi_by_sha1     = g_hash_table_new(sha1_hash, sha1_eq);
	fi_by_namesize = g_hash_table_new(namesize_hash, namesize_eq);
	fi_by_size     = g_hash_table_new(g_int_hash, g_int_equal);
	fi_by_outname  = g_hash_table_new(g_str_hash, g_str_equal);

    fi_handle_map = idtable_new(32, 32);

    fi_events[EV_FI_ADDED]          = event_new("fi_added");
    fi_events[EV_FI_REMOVED]        = event_new("fi_removed");
    fi_events[EV_FI_INFO_CHANGED]   = event_new("fi_info_changed");
    fi_events[EV_FI_STATUS_CHANGED] = event_new("fi_status_changed");
    fi_events[EV_FI_SRC_ADDED]      = event_new("fi_src_added");
    fi_events[EV_FI_SRC_REMOVED]    = event_new("fi_src_removed");
}

static inline void file_info_checksum(guint32 *checksum, gchar *d, int len)
{
	while (len--)
		*checksum = (*checksum << 1) ^ (*checksum >> 31) ^ (guchar) *d++;
}

/*
 * file_info_fd_store_binary
 *
 * Store a binary record of the file metainformation at the end of the
 * supplied file descriptor, opened for writing.
 *
 * When `force' is false, we don't store unless FI_STORE_DELAY seconds
 * have elapsed since last flush to disk.
 */
static void file_info_fd_store_binary(
	struct dl_file_info *fi, int fd, gboolean force)
{
	GSList *fclist;
	GSList *a;
	struct dl_file_chunk *fc;
	guint32 checksum = 0;
	guint32 length;

	g_assert(fd >= 0);

	/*
	 * Don't flush unless required or some delay occurred since last flush.
	 */

	if (force || fi->stamp - fi->last_flush >= FI_STORE_DELAY)
		fi->last_flush = fi->stamp;
	else
		return;

	/*
	 * Write trailer at the far end.
	 */

	if (lseek(fd, fi->size, SEEK_SET) != fi->size) {
		g_warning("file_info_store_binary(): "
			"lseek() to offset %u in \"%s\" failed: %s",
			fi->size, fi->file_name, g_strerror(errno));
		return;
	}

	TBUF_INIT_WRITE();
	WRITE_INT32(FILE_INFO_VERSION);

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

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		guint32 tmpchunk[3];
		fc = fclist->data;
		tmpchunk[0] = htonl(fc->from);
		tmpchunk[1] = htonl(fc->to);
		tmpchunk[2] = htonl(fc->status);
		FIELD_ADD(FILE_INFO_FIELD_CHUNK, sizeof(tmpchunk), tmpchunk);
	}

	fi->generation++;

	WRITE_INT32(FILE_INFO_FIELD_END);
	WRITE_INT32(fi->size);
	WRITE_INT32(fi->generation);

	length = TBUF_WRITTEN_LEN() + 3 * sizeof(guint32);

	WRITE_INT32(length);				/* Total trailer size */
	WRITE_INT32(checksum);
	WRITE_UINT32(FILE_INFO_MAGIC);

	tbuf_write(fd, fi->file_name);		/* Flush buffer at current position */

	if (ftruncate(fd, fi->size + length) != 0)
		g_warning("file_info_fd_store_binary(): truncate() failed: %s",
			g_strerror(errno));

	fi->dirty = FALSE;
	fileinfo_dirty = TRUE;
}

/*
 * file_info_store_binary
 *
 * Store a binary record of the file metainformation at the end of the
 * output file, if it exists.
 */
void file_info_store_binary(struct dl_file_info *fi)
{
	int fd;
	char *path;

	path = g_strdup_printf("%s/%s", fi->path, fi->file_name);
	g_return_if_fail(NULL != path);

	/*
	 * We don't create the file if it does not already exist.  That way,
	 * a file is only created when at least one byte of data is downloaded,
	 * since then we'll go directly to file_info_fd_store_binary().
	 */

	fd = open(path, O_WRONLY);

	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("file_info_store_binary(): "
				"can't open \"%s\" for writing: %s",
				path, g_strerror(errno));
		G_FREE_NULL(path);
		return;
	}

	G_FREE_NULL(path);
	fi->stamp = time(NULL);
	file_info_fd_store_binary(fi, fd, TRUE);	/* Force flush */
	close(fd);
}

/*
 * file_info_strip_binary
 *
 * Strips the file metainfo trailer off a file.
 */
void file_info_strip_binary(struct dl_file_info *fi)
{
	char *path;

	path = g_strdup_printf("%s/%s", fi->path, fi->file_name);
	g_return_if_fail(NULL != path);

	if (-1 == truncate(path, fi->size))
		g_warning("could not chop fileinfo trailer off \"%s\": %s",
			path, g_strerror(errno));
	G_FREE_NULL(path);
}

/*
 * file_info_strip_binary_from_file
 *
 * Strips the file metainfo trailer off specified file.
 */
void file_info_strip_binary_from_file(
	struct dl_file_info *fi, const gchar *file)
{
	struct dl_file_info *dfi;

	g_assert(file[0] == '/');		/* Absolute path given */

	/*
	 * Before truncating the file, we must be really sure it is reasonnably
	 * matching the fileinfo structure we have for it: retrieve the binary
	 * trailer, and check size / completion.
	 */

	dfi = file_info_retrieve_binary(file, "");

	if (dfi == NULL) {
		g_warning("could not chop fileinfo trailer off \"%s\": file does "
			"not seem to have a valid trailer", file);
		return;
	}

	if (dfi->size != fi->size || dfi->done != fi->done) {
		g_warning("could not chop fileinfo trailer off \"%s\": file was "
			"different than expected (%u/%u bytes done instead of %u/%u)",
			file, dfi->done, dfi->size, fi->done, fi->size);
	} else if (-1 == truncate(file, fi->size))
		g_warning("could not chop fileinfo trailer off \"%s\": %s",
			file, g_strerror(errno));

	fi_free(dfi);
}

/*
 * fi_free
 *
 * Free a `file_info' structure.
 */
static void fi_free(struct dl_file_info *fi)
{
	GSList *l;

	g_assert(fi);
	g_assert(!fi->hashed);

	if (fi->size_atom)
		atom_int_free(fi->size_atom);
	if (fi->file_name)
		atom_str_free(fi->file_name);
	if (fi->path)
		atom_str_free(fi->path);
	if (fi->sha1)
		atom_sha1_free(fi->sha1);
	if (fi->cha1)
		atom_sha1_free(fi->cha1);
	if (fi->chunklist) {
		for (l = fi->chunklist; l; l = l->next)
			wfree(l->data, sizeof(struct dl_file_chunk));
		g_slist_free(fi->chunklist);
	}
	if (fi->alias) {
		for (l = fi->alias; l; l = l->next)
			atom_str_free(l->data);
		g_slist_free(fi->alias);
	}
	wfree(fi, sizeof(*fi));
}

/*
 * fi_resize
 *
 * Resize fileinfo to be `size' bytes, by adding empty chunk at the tail.
 */
static void fi_resize(struct dl_file_info *fi, guint32 size)
{
	namesize_t nsk;
	struct dl_file_chunk *fc;
	GSList *l;
	GSList *to_remove = NULL;
	struct dl_file_info *xfi;

	g_assert(fi);
	g_assert(fi->size < size);
	g_assert(!fi->hashed);

	fc = walloc0(sizeof(*fc));
	fc->from = fi->size;
	fc->to = size;
	fc->status = DL_CHUNK_EMPTY;
	fi->chunklist = g_slist_append(fi->chunklist, fc);

	/*
	 * Don't remove/re-insert `fi' from hash tables: when this routine is
	 * called, `fi' is no longer "hashed", or has never been "hashed".
	 */

	g_assert(fi->size_atom);

	atom_int_free(fi->size_atom);
	fi->size = size;
	fi->size_atom = atom_int_get(&size);

	/*
	 * Now make sure none of the current aliases will conflict, now that we
	 * got a new size.
	 */

	nsk.size = size;

	for (l = fi->alias; l; l = l->next) {
		nsk.name = l->data;

		xfi = g_hash_table_lookup(fi_by_namesize, &nsk);

		if (xfi != NULL) {
			g_assert(xfi != fi);		/* We should not be there! */

			if (dbg) g_warning("ignoring alias \"%s\" for \"%s\" "
				"(resized to %u bytes): conflicts with \"%s\" (%u bytes)",
				nsk.name, fi->file_name, fi->size, xfi->file_name, xfi->size);

			to_remove = g_slist_prepend(to_remove, l->data);
		}
	}

	for (l = to_remove; l; l = l->next) {
		gchar *name = (gchar *) l->data;
		fi->alias = g_slist_remove(fi->alias, name);
		atom_str_free(name);
	}

	g_slist_free(to_remove);
}

/*
 * fi_alias
 *
 * Add `name' as an alias for `fi' if not already known.
 * If `record' is TRUE, also record new alias entry in `fi_by_namesize'.
 */
static void fi_alias(struct dl_file_info *fi, gchar *name, gboolean record)
{
	namesize_t nsk;
	struct dl_file_info *xfi;

	g_assert(fi);
	g_assert(!record || fi->hashed);	/* record => fi->hahsed */

	/*
	 * The fastest way to know if this alias exists is to lookup the
	 * fi_by_namesize table, since all the aliases are inserted into
	 * that table.
	 */

	nsk.name = name;
	nsk.size = fi->size;

	xfi = g_hash_table_lookup(fi_by_namesize, &nsk);

	if (xfi != NULL && xfi != fi) {
		if (dbg) g_warning("ignoring alias \"%s\" for \"%s\" (%u bytes): "
			"conflicts with \"%s\" (%u bytes)",
			name, fi->file_name, fi->size, xfi->file_name, xfi->size);
		return;
	} else if (xfi == fi)
		return;					/* Alias already known */

	/*
	 * Insert new alias for `fi'.
	 */

	fi->alias = g_slist_append(fi->alias, atom_str_get(name));

	if (record) {
		namesize_t *ns = namesize_make(nsk.name, nsk.size);
		g_hash_table_insert(fi_by_namesize, ns, fi);
	}
}

/*
 * file_info_get_trailer
 *
 * Extract fixed trailer at the end of the file `name', already opened as `fd'.
 * The supplied trailer buffer `tb' is filled.
 *
 * Returns TRUE if the trailer is "validated", FALSE otherwise.
 */
static gboolean file_info_get_trailer(
	gint fd, struct trailer *tb, const gchar *name)
{
	guint32 tr[5];
	struct stat buf;
	off_t offset;

	g_assert(fd >= 0);
	g_assert(tb);

	if (-1 == fstat(fd, &buf)) {
		g_warning("error fstat()ing \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	if (buf.st_size < sizeof(tr))
		return FALSE;

	/*
	 * Don't use SEEK_END with "-sizeof(tr)" to avoid problems when off_t is
	 * defined as an 8-byte wide quantity.  Since we have the file size
	 * already, better use SEEK_SET.
	 *		--RAM, 02/02/2003 after a bug report from Christian Biere
	 */

	offset = buf.st_size - sizeof(tr);		/* Start of trailer */

	if (offset != lseek(fd, offset, SEEK_SET)) {
		g_warning("file_info_get_trailer(): "
			"error seek()ing in file \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	if (-1 == read(fd, tr, sizeof(tr))) {
		g_warning("file_info_get_trailer(): "
			"error reading trailer in  \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	tb->filesize	= ntohl(tr[0]);
	tb->generation	= ntohl(tr[1]);
	tb->length		= ntohl(tr[2]);
	tb->checksum	= ntohl(tr[3]);
	tb->magic		= ntohl(tr[4]);

	/*
	 * Now, sanity checks...  We must make sure this is a valid trailer.
	 */

	if (tb->magic != FILE_INFO_MAGIC)
		return FALSE;

	if (buf.st_size != tb->filesize + tb->length)
		return FALSE;

	return TRUE;
}

/*
 * file_info_filesize
 *
 * Computes the real size of a file: if it has no trailer, it is its real size.
 * If it has a trailer, then fetch the filesize within.
 */
off_t file_info_filesize(const gchar *path)
{
	gint fd;
	struct stat buf;
	struct trailer trailer;
	gboolean valid;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("can't open \"%s\" for reading: %s",
				path, g_strerror(errno));
		goto plainsize;
	}

	valid = file_info_get_trailer(fd, &trailer, path);
	close(fd);

	if (valid)
		return trailer.filesize;

	/* FALL THROUGH */

plainsize:
	if (-1 == stat(path, &buf))
		return 0;

	return buf.st_size;
}

/*
 * file_info_has_filename
 *
 * Returns TRUE if a file_info struct has a matching file name or alias,
 * and FALSE if not.
 */
static gboolean file_info_has_filename(struct dl_file_info *fi, gchar *file)
{
	GSList *a;

	for (a = fi->alias; a; a = a->next) {
		if (0 == strcasecmp((gchar *)a->data, file))
			return TRUE;
	}

	if (use_fuzzy_matching) {
		for (a = fi->alias; a; a = a->next) {
			gulong score = 100 * fuzzy_compare(a->data, file);
			if (score >= (fuzzy_threshold << FUZZY_SHIFT)) {
				g_warning("fuzzy: \"%s\"  ==  \"%s\" (score %f)",
					(gchar *) a->data, file, score / 100.0);
				fi_alias(fi, file, TRUE);
				return TRUE;
			}
		}
	}
	
	return FALSE;
}

/*
 * file_info_lookup
 *
 * Lookup our existing fileinfo structs to see if we can spot one
 * referencing the supplied file `name' and `size', as well as the
 * optional `sha1' hash.
 *
 * Returns the fileinfo structure if found, NULL otherwise.
 */
static struct dl_file_info *file_info_lookup(
	gchar *name, guint32 size, const gchar *sha1)
{
	struct dl_file_info *fi;
	struct namesize nsk;
	GSList *list;
	GSList *l;

	/*
	 * If we have a SHA1, this is our unique key.
	 */

	if (sha1 != NULL) {
		fi = g_hash_table_lookup(fi_by_sha1, sha1);

		if (fi)
			return fi;

		/*
		 * No need to continue if strict SHA1 matching is enabled.
		 * If the entry is not found in the `fi_by_sha1' table, then
		 * nothing can be found for this SHA1.
		 */

		if (strict_sha1_matching)
			return NULL;
	}

	/*
	 * Look for a matching (name, size) tuple.
	 */

	nsk.name = name;
	nsk.size = size;

	fi = g_hash_table_lookup(fi_by_namesize, &nsk);

	if (fi) {
		g_assert(fi->size == size);
		return fi;
	}

	/*
	 * Look for a matching name, given the size.
	 */

	list = g_hash_table_lookup(fi_by_size, &size);

	for (l = list; l; l = l->next) {
		fi = l->data;

		g_assert(fi->size == size);

		if (file_info_has_filename(fi, name))
			return fi;
	}

	return NULL;
}

/*
 * file_info_lookup_dup
 *
 * Given a fileinfo structure, look for any other known duplicate.
 * Returns the duplicate found, or NULL if no duplicate was found.
 */
static struct dl_file_info *file_info_lookup_dup(struct dl_file_info *fi)
{
	struct dl_file_info *dfi;

	dfi = g_hash_table_lookup(fi_by_outname, fi->file_name);

	if (dfi)
		return dfi;

	/*
	 * If `fi' has a SHA1, find any other entry bearing the same SHA1.
	 */

	if (fi->sha1) {
		dfi = g_hash_table_lookup(fi_by_sha1, fi->sha1);
		if (dfi)
			return dfi;
	}

	return NULL;
}

/*
 * file_info_retrieve_binary
 *
 * Reads the file metainfo from the trailer of a file, if it exists.
 * Returns a pointer to the info structure if found, and NULL otherwise.
 */
static struct dl_file_info *file_info_retrieve_binary(
	const gchar *file, const gchar *path)
{
	guint32 tmpchunk[3];
	guint32 tmpguint;
	guint32 checksum = 0;
	struct dl_file_info *fi = NULL;
	struct dl_file_chunk *fc;
	enum dl_file_info_field field;
	gchar tmp[FI_MAX_FIELD_LEN + 1];	/* +1 for trailing NUL on strings */
	gchar *reason;
	gchar *pathname;
	gint fd;
	guint32 version;
	struct trailer trailer;

	pathname = g_strdup_printf("%s/%s", path, file);
	g_return_val_if_fail(NULL != pathname, NULL);
	
	fd = open(pathname, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("can't open \"%s\" for reading: %s",
				pathname, g_strerror(errno));
		G_FREE_NULL(pathname);
		return NULL;
	}

	if (!file_info_get_trailer(fd, &trailer, pathname)) {
		reason = "could not find trailer";
		goto bailout;
	}

	if (trailer.filesize != lseek(fd, trailer.filesize, SEEK_SET)) {
		g_warning("seek to position %u within \"%s\" failed: %s",
			trailer.filesize, pathname, g_strerror(errno));
		goto eof;
	}

	/*
	 * Now read the whole trailer in memory.
	 */

	if (-1 == tbuf_read(fd, trailer.length)) {
		g_warning("file_info_retrieve_binary(): "
			"unable to read whole trailer (%d bytes) from \"%s\": %s",
			trailer.filesize, pathname, g_strerror(errno));
		goto eof;
	}

	/* Check version */
	READ_INT32(&version);
	if (version > FILE_INFO_VERSION) {
		g_warning("file_info_retrieve_binary(): strange version; %u", version);
		goto eof;
	}

	fi = walloc0(sizeof(struct dl_file_info));
   
	fi->file_name = atom_str_get(file);
	fi->path = atom_str_get(path);
	fi->size = trailer.filesize;
	fi->size_atom = atom_int_get(&fi->size);
	fi->generation = trailer.generation;
	fi->use_swarming = 1;					/* Must assume swarming */
	fi->refcount = 0;
	
	for (;;) {
		tmpguint = FILE_INFO_FIELD_END; /* in case read() fails. */
		READ_INT32(&tmpguint);				/* Read a field ID */
		if (tmpguint == FILE_INFO_FIELD_END)
			break;
		field = tmpguint;

		READ_INT32(&tmpguint);				/* Read field data length */

		if (tmpguint == 0) {
			gm_snprintf(tmp, sizeof(tmp), "field #%d has zero size", field);
			reason = tmp;
			goto bailout;
		}
		
		if (tmpguint > FI_MAX_FIELD_LEN) {
			gm_snprintf(tmp, sizeof(tmp),
				"field #%d is too large (%u bytes) ", field, tmpguint);
			reason = tmp;
			goto bailout;
		}

		g_assert(tmpguint < sizeof(tmp));

		READ_STR(tmp, tmpguint);
		tmp[tmpguint] = '\0';				/* Did not store trailing NUL */

		switch(field) {
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
		case FILE_INFO_FIELD_SHA1:
			fi->sha1 = atom_sha1_get(tmp);
			break;
		case FILE_INFO_FIELD_CHA1:
			fi->cha1 = atom_sha1_get(tmp);
			break;
		case FILE_INFO_FIELD_CHUNK:
			memcpy(tmpchunk, tmp, sizeof(tmpchunk));
			fc = walloc0(sizeof(*fc));
			/*
			 * In version 1, fields were written in native form.
			 * Starting with version 2, they are written in network order.
			 */
			if (version == 1) {
				fc->from = tmpchunk[0];
				fc->to = tmpchunk[1];
				fc->status = tmpchunk[2];
			} else {
				fc->from = ntohl(tmpchunk[0]);
				fc->to = ntohl(tmpchunk[1]);
				fc->status = ntohl(tmpchunk[2]);
			}
			if (fc->status == DL_CHUNK_BUSY)
				fc->status = DL_CHUNK_EMPTY;
			fi->chunklist = g_slist_append(fi->chunklist, fc);
			break;
		default:
			g_warning("file_info_retrieve_binary(): "
				"unhandled field ID %u", field);
			break;
		}
	}

	/*
	 * Finally, read back the trailer fileds before the checksum
	 * to get an accurate checksum recomputation.
	 */

	READ_INT32(&tmpguint);			/* file size */
	g_assert(tmpguint == trailer.filesize);

	READ_INT32(&tmpguint);			/* generation number */
	g_assert(tmpguint == trailer.generation);

	READ_INT32(&tmpguint);			/* trailer length */
	g_assert(tmpguint == trailer.length);

	if (checksum != trailer.checksum) {
		reason = "checksum mismatch";
		goto bailout;
	}

	close(fd);

	file_info_merge_adjacent(fi);	/* Update fi->done */

	if (dbg > 3)
		printf("FILEINFO: good trailer info (v%u, %u bytes) in \"%s\"\n",
			version, trailer.length, pathname);

	G_FREE_NULL(pathname);
	return fi;

bailout:

	g_warning("file_info_retrieve_binary(): %s in %s%s%s",
		reason, path, path[strlen(path) - 1] == '/' ? "" : "/", file);

eof:
	if (NULL != pathname)
		G_FREE_NULL(pathname);
	if (fi)
		fi_free(fi);

	close(fd);

	return NULL;
}

/*
 * file_info_store_one
 *
 * Stores a file info record to the config_dir/fileinfo file, and
 * appends it to the output file in question if needed.
 */
static void file_info_store_one(FILE *f, struct dl_file_info *fi)
{
	GSList *fclist;
	GSList *a;
	struct dl_file_chunk *fc;

	if (fi->use_swarming && fi->dirty)
		file_info_store_binary(fi);

	if (fi->refcount == 0) {
		gchar *path;
		struct stat st;

		path = g_strdup_printf("%s/%s", fi->path, fi->file_name);
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
		"GENR %u\n",
		fi->refcount,
		fi->file_name,
		fi->path,
		fi->generation);

	for (a = fi->alias; a; a = a->next)
		fprintf(f, "ALIA %s\n", (gchar *)a->data);
	fprintf(f, "SHA1 %s\n", fi->sha1 ? sha1_base32(fi->sha1) : "");
	if (fi->cha1)
		fprintf(f, "CHA1 %s\n", sha1_base32(fi->cha1));
	fprintf(f,
		"SIZE %u\n"
		"DONE %u\n"
		"TIME %lu\n"
		"SWRM %u\n",
		fi->size,
		fi->done,
		(gulong) fi->stamp,
		fi->use_swarming);
  
	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;
		fprintf(f, "CHNK %u %u %u\n", fc->from, fc->to, fc->status);
	}
	fprintf(f, "\n");
}

/*
 * file_info_store_list
 *
 * Callback for hash table iterator. Used by file_info_store().
 */
static void file_info_store_list(gpointer key, gpointer val, gpointer x)
{
	GSList *l;
	struct dl_file_info *fi;
	FILE *f = (FILE *)x;

	for (l = (GSList *) val; l; l = l->next) {
		fi = (struct dl_file_info *) l->data;
		g_assert(fi->size == *(guint32 *) key);
		file_info_store_one(f, fi);
	}

}

/*
 * file_info_store
 *
 * Stores the list of output files and their metainfo to the
 * configdir/fileinfo database.
 */
void file_info_store(void)
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
		"#	GENR <generation number>\n"
		"#	ALIA <alias file name>\n"
		"#	SIZE <size>\n"
		"#	SHA1 <server sha1>\n"
		"#	CHA1 <computed sha1> [when done only]\n"
		"#	DONE <bytes done>\n"
		"#	TIME <last update stamp>\n"
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

/* 
 * file_info_store_if_dirty
 *
 * Store global file information cache if dirty.
 */
void file_info_store_if_dirty(void)
{
	if (fileinfo_dirty)
		file_info_store();
}

/*
 * file_info_free_sha1_kv
 *
 * Callback for hash table iterator. Used by file_info_close().
 */
static void file_info_free_sha1_kv(gpointer key, gpointer val, gpointer x)
{
	const gchar *sha1 = (const gchar *) key;
	const struct dl_file_info *fi = (const struct dl_file_info *) val;

	g_assert(sha1 == fi->sha1);		/* SHA1 shared with fi's, don't free */

	/* fi structure in value not freed, shared with other hash tables */
}

/*
 * file_info_free_namesize_kv
 *
 * Callback for hash table iterator. Used by file_info_close().
 */
static void file_info_free_namesize_kv(gpointer key, gpointer val, gpointer x)
{
	namesize_t *ns = (namesize_t *) key;

	namesize_free(ns);

	/* fi structure in value not freed, shared with other hash tables */
}

/*
 * file_info_free_size_kv
 *
 * Callback for hash table iterator. Used by file_info_close().
 */
static void file_info_free_size_kv(gpointer key, gpointer val, gpointer x)
{
	GSList *list = (GSList *) val;

	g_slist_free(list);

	/* fi structure in value not freed, shared with other hash tables */
}

/*
 * file_info_free_outname_kv
 *
 * Callback for hash table iterator. Used by file_info_close().
 */
static void file_info_free_outname_kv(
	gpointer key, gpointer val, gpointer x)
{
	const gchar *name = (const gchar *) key;
	struct dl_file_info *fi = (struct dl_file_info *) val;

	g_assert(name == fi->file_name);	/* name shared with fi's, don't free */

	/*
	 * This table is the last one to be freed, and it is also guaranteed to
	 * contain ALL fileinfo, and only ONCE, by definition.  Thus freeing
	 * happens here.
	 *
	 * Note that normally all fileinfo structures should have been collected
	 * during the freeing of downloads, so if we come here with a non-zero
	 * refcount, something is wrong with our memory management.
	 *
	 * (refcount of zero is possible if we have a fileinfo entry but no
	 * download attached to that fileinfo)
	 */

	if (fi->refcount)
		g_warning("file_info_free_outname_kv() refcount = %u for \"%s\"",
			fi->refcount, name);

    /*
     * Notify interested parties that file info is being removed and free
     * it's handle.
     */

    event_trigger(
        fi_events[EV_FI_REMOVED], 
        T_NORMAL(fi_listener_t, fi->fi_handle));    
    file_info_drop_handle(fi->fi_handle);

	fi->hashed = FALSE;

	fi_free(fi);
}

/*
 * file_info_close
 *
 * Close and free all file_info structs in the list.
 */
void file_info_close(void)
{
    guint n;

	/*
	 * Freeing callbacks expect that the freeing of the `fi_by_outname'
	 * table will free the referenced `fi' (since that table MUST contain
	 * all the known `fi' structs by definition).
	 */

	g_hash_table_foreach(fi_by_sha1, file_info_free_sha1_kv, NULL);
	g_hash_table_foreach(fi_by_namesize, file_info_free_namesize_kv, NULL);
	g_hash_table_foreach(fi_by_size, file_info_free_size_kv, NULL);
	g_hash_table_foreach(fi_by_outname, file_info_free_outname_kv, NULL);

    /*
     * The hash tables may still not be completely empty, but the referenced
     * file_info structs are all freed.
     *      --Richard, 9/3/2003
     */

    g_assert(idtable_ids(fi_handle_map) == 0);
    idtable_destroy(fi_handle_map);

    for (n = 0; n < G_N_ELEMENTS(fi_events); n ++)
        event_destroy(fi_events[n]);

	g_hash_table_destroy(fi_by_sha1);
	g_hash_table_destroy(fi_by_namesize);
	g_hash_table_destroy(fi_by_size);
	g_hash_table_destroy(fi_by_outname);
	
	g_free(tbuf.arena);
}

/*
 * file_info_hash_insert
 *
 * Inserts a file_info struct into the hash tables.
 */
static void file_info_hash_insert(struct dl_file_info *fi)
{
	struct dl_file_info *xfi;
	namesize_t nsk;
	GSList *l;

	g_assert(fi);
	g_assert(!fi->hashed);
	g_assert(fi->size_atom);

	if (dbg > 4) {
		printf("FILEINFO insert 0x%lx \"%s\" (%u/%u bytes done) sha1=%s\n",
			(gulong) fi, fi->file_name, fi->done, fi->size,
			fi->sha1 ? sha1_base32(fi->sha1) : "none");
		fflush(stdout);
	}

	/*
	 * If an entry already exists in the `fi_by_outname' table, then it
	 * is for THIS fileinfo.  Otherwise, there's a structural assertion
	 * that has been broken somewhere!
	 *		--RAM, 01/09/2002
	 */

	xfi = g_hash_table_lookup(fi_by_outname, fi->file_name);

	if (xfi != NULL && xfi != fi)			/* See comment above */
		g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

	if (xfi == NULL)
		g_hash_table_insert(fi_by_outname, fi->file_name, fi);

	/*
	 * Likewise, there can be only ONE entry per given SHA1, but the SHA1
	 * may not be already present at this time, so the entry is optional.
	 * If it exists, it must be unique though.
	 *		--RAM, 01/09/2002
	 */

	if (fi->sha1) {
		xfi = g_hash_table_lookup(fi_by_sha1, fi->sha1);

		if (xfi != NULL && xfi != fi)		/* See comment above */
			g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

		if (xfi == NULL)
			g_hash_table_insert(fi_by_sha1, fi->sha1, fi);
	}

	/*
	 * The (name, size) tuples must also point to ONE entry, the current
	 * one, for each of the name aliases.
	 */

	nsk.size = fi->size;

	for (l = fi->alias; l; l = l->next) {
		nsk.name = l->data;

		xfi = g_hash_table_lookup(fi_by_namesize, &nsk);

		if (xfi != NULL && xfi != fi)		/* See comment above */
			g_error("xfi = 0x%lx, fi = 0x%lx", (gulong) xfi, (gulong) fi);

		if (xfi == NULL) {
			namesize_t *ns = namesize_make(nsk.name, nsk.size);
			g_hash_table_insert(fi_by_namesize, ns, fi);
		}
	}

	/*
	 * Finally, for a given size, maintain a list of fi's.
	 *
	 * NB: the key used here is the size_atom, as it must be shared accross
	 * all the `fi' structs with the same size!
	 */

	g_assert(fi->size == *(guint32 *) fi->size_atom);

	l = g_hash_table_lookup(fi_by_size, fi->size_atom);

	if (l != NULL) {
		g_slist_append(l, fi);
	} else {
		l = g_slist_append(l, fi);
		g_assert(l != NULL);
		g_hash_table_insert(fi_by_size, fi->size_atom, l);
	}

	fi->hashed = TRUE;
    fi->fi_handle = file_info_request_handle(fi);
    event_trigger(
        fi_events[EV_FI_ADDED], 
        T_NORMAL(fi_listener_t, fi->fi_handle));    
}

/*
 * file_info_hash_remove
 *
 * Remove fileinfo data from all the hash tables.
 */
static void file_info_hash_remove(struct dl_file_info *fi)
{
	namesize_t nsk;
	gpointer x;
	gboolean found;
	GSList *l;
	GSList *newl;

	g_assert(fi);
	g_assert(fi->hashed);
	g_assert(fi->size_atom);

	if (dbg > 4) {
		printf("FILEINFO remove 0x%lx \"%s\" (%u/%u bytes done) sha1=%s\n",
			(gulong) fi, fi->file_name, fi->done, fi->size,
			fi->sha1 ? sha1_base32(fi->sha1) : "none");
		fflush(stdout);
	}

    /*
     * Notify interested parties that file info is being removed and free
     * it's handle.
     */

    event_trigger(
        fi_events[EV_FI_REMOVED], 
        T_NORMAL(fi_listener_t, fi->fi_handle));    
    file_info_drop_handle(fi->fi_handle);

	/*
	 * Remove from plain hash tables: by output name, and by SHA1.
	 */

	g_hash_table_remove(fi_by_outname, fi->file_name);

	if (fi->sha1)
		g_hash_table_remove(fi_by_sha1, fi->sha1);

	/*
	 * Remove all the aliases from the (name, size) table.
	 */

	nsk.size = fi->size;

	for (l = fi->alias; l; l = l->next) {
		union { 
			namesize_t *ns;
			gpointer ptr;
		} key;
		nsk.name = l->data;

		found = g_hash_table_lookup_extended(fi_by_namesize, &nsk,
			&key.ptr, &x);

		g_assert(found);
		g_assert(x == (gpointer) fi);
		g_assert(key.ns->size == fi->size);

		g_hash_table_remove(fi_by_namesize, key.ns);
		namesize_free(key.ns);
	}

	/*
	 * Remove from the "by filesize" table.
	 *
	 * NB: the key used here is the size_atom, as it must be shared accross
	 * all the `fi' structs with the same size (in case we free `fi' now)!
	 */

	g_assert(fi->size == *(guint32 *) fi->size_atom);

	l = g_hash_table_lookup(fi_by_size, &fi->size);

	g_assert(l != NULL);

	newl = g_slist_remove(l, fi);

	if (newl == NULL)
		g_hash_table_remove(fi_by_size, fi->size_atom);
	else if (newl != l)
		g_hash_table_insert(fi_by_size, fi->size_atom, newl);

	fi->hashed = FALSE;
}

/*
 * file_info_reparent_all
 *
 * Reparent all downloads using `from' as a fileinfo, so they use `to' now.
 */
static void file_info_reparent_all(
	struct dl_file_info *from, struct dl_file_info *to)
{
	char *path;

	g_assert(from->done == 0);
	g_assert(0 != strcmp(from->file_name, to->file_name));

	path = g_strdup_printf("%s/%s", from->path, from->file_name);
	g_return_if_fail(NULL != path);

	if (-1 == unlink(path)) {
		/*
		 * File may not exist yet if we have not started downloading anything.
		 */

		if (from->done)
			g_warning("cannot unlink \"%s\": %s", path, g_strerror(errno));
	} else
		g_warning("reparenting unlinked \"%s\" (%u/%u bytes done, %s SHA1%s%s)",
			from->file_name, from->done, from->size,
			from->sha1 ? "with" : "no",
			from->sha1 ? ": " : "",
			from->sha1 ? sha1_base32(from->sha1) : "");

	download_info_change_all(from, to);

	/*
	 * We can dispose of the old `from' as all downloads using it are now gone.
	 */

	g_assert(from->refcount == 0);
	g_assert(from->lifecount == 0);

	file_info_hash_remove(from);
	fi_free(from);
	G_FREE_NULL(path);
}

/*
 * file_info_got_sha1
 *
 * Called when we discover the SHA1 of a running download.
 * Make sure there is no other entry already bearing that SHA1, and record
 * the information.
 *
 * Returns TRUE if OK, FALSE if a duplicate record with the same SHA1 exists.
 */
gboolean file_info_got_sha1(struct dl_file_info *fi, const gchar *sha1)
{
	struct dl_file_info *xfi;

	g_assert(fi);
	g_assert(sha1);
	g_assert(fi->sha1 == NULL);

	xfi = g_hash_table_lookup(fi_by_sha1, sha1);

	if (xfi == NULL) {
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

	if (dbg > 3)
		printf("CONFLICT found same SHA1 %s in "
			"\"%s\" (%u/%u bytes done) and \"%s\" (%u/%u bytes done)\n",
			sha1_base32(sha1),
			xfi->file_name, xfi->done, xfi->size,
			fi->file_name, fi->done, fi->size);

	if (fi->done && xfi->done) {
		g_warning("found same SHA1 %s in "
			"\"%s\" (%u/%u bytes done) and \"%s\" (%u/%u bytes done) "
			"-- aborting last one",
			sha1_base32(sha1),
			xfi->file_name, xfi->done, xfi->size,
			fi->file_name, fi->done, fi->size);
		return FALSE;
	}

	if (fi->done) {
		g_assert(xfi->done == 0);
		fi->sha1 = atom_sha1_get(sha1);
		file_info_reparent_all(xfi, fi);	/* All `xfi' replaced by `fi' */
		g_hash_table_insert(fi_by_sha1, fi->sha1, fi);
	} else {
		g_assert(fi->done == 0);
		file_info_reparent_all(fi, xfi);	/* All `fi' replaced by `xfi' */
	}

	return TRUE;
}

/*
 * extract_sha1
 *
 * Extract sha1 from SHA1/CHA1 line in the ASCII "fileinfo" summary file
 * and return NULL if none or invalid, the SHA1 atom otherwise.
 */
static gchar *extract_sha1(const gchar *line)
{
	gchar sha1_digest[SHA1_RAW_SIZE];

	if (
		line[5] &&
		strlen(&line[5]) >= SHA1_BASE32_SIZE &&
		base32_decode_into(line + 5, SHA1_BASE32_SIZE,
			sha1_digest, sizeof(sha1_digest))
	)
		return atom_sha1_get(sha1_digest);

	return NULL;
}

/*
 * file_info_retrieve
 *
 * Loads the fileinfo database from disk, and saves a copy in fileinfo.orig.
 */
void file_info_retrieve(void)
{
	FILE *f;
	struct dl_file_chunk *fc = NULL;
	gchar line[1024];
	guint32 from, to, status;
	struct dl_file_info *fi = NULL;
	struct stat buf;
	gboolean empty = TRUE;
	GSList *aliases = NULL;
	gboolean last_was_truncated = FALSE;
	file_path_t fp;

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
	f = file_config_open_read("fileinfo file", &fp, 1);
	if (!f)
		return;

	line[sizeof(line)-1] = '\0';

	while (fgets(line, sizeof(line), f)) {
		gint len;
		gboolean truncated = FALSE;

		if (*line == '#') continue;

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
		if (len == sizeof(line) - 1)
			truncated = '\n' != line[sizeof(line) - 2];

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

		if ((*line == '\0') && fi && fi->file_name) {
			GSList *l;
			struct dl_file_info *dfi;

			/*
			 * There can't be duplicates!
			 */

			dfi = g_hash_table_lookup(fi_by_outname, fi->file_name);
			if (dfi != NULL) {
				g_warning("discarding DUPLICATE fileinfo entry for \"%s\"",
					fi->file_name);
				goto discard;
			}

			/* 
			 * Check file trailer information.	The main file is only written
			 * infrequently and the file's trailer can have more up-to-date
			 * information.
			 */

			dfi = file_info_retrieve_binary(fi->file_name, fi->path);

			if (dfi == NULL) {
				gm_snprintf(fi_tmp, sizeof(fi_tmp),
					"%s/%s", fi->path, fi->file_name);
				if (-1 != stat(fi_tmp, &buf)) {
					g_warning("got metainfo in fileinfo cache, "
						"but none in \"%s/%s\"", fi->path, fi->file_name);
					file_info_store_binary(fi);			/* Create metainfo */
				} else {
					file_info_merge_adjacent(fi);		/* Compute fi->done */
					if (fi->done > 0) {
						g_warning("discarding cached metainfo for \"%s/%s\": "
							"file had %d bytes downloaded but is now gone!",
							fi->path, fi->file_name, fi->done);
						goto discard;
					}
				}
			} else if (dfi->generation > fi->generation) {
				g_warning("found more recent metainfo in \"%s/%s\"",
					fi->path, fi->file_name);
				fi_free(fi);
				fi = dfi;
			} else if (dfi->generation < fi->generation) {
				g_warning("found OUTDATED metainfo in \"%s/%s\"",
					fi->path, fi->file_name);
				fi_free(dfi);
				file_info_store_binary(fi);		/* Resync metainfo */
			} else {
				g_assert(dfi->generation == fi->generation);
				fi_free(dfi);
			}

			/*
			 * Check whether entry is not another's duplicate.
			 */

			dfi = file_info_lookup_dup(fi);

			if (dfi != NULL) {
				g_warning("found DUPLICATE entry for \"%s\" (%u bytes) "
					"with \"%s\" (%u bytes)",
					fi->file_name, fi->size, dfi->file_name, dfi->size);
				goto discard;
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

			for (l = aliases; l; l = g_slist_next(l)) {
				fi_alias(fi, (gchar *) l->data, TRUE);
				atom_str_free((gchar *) l->data);
                l->data = NULL;
			}
			g_slist_free(aliases);
            aliases = NULL;

			empty = FALSE;
			fi = NULL;

			continue;

		discard:
			for (l = aliases; l; l = g_slist_next(l)) {
				atom_str_free((gchar *) l->data);
                l->data = NULL;
            }
            g_slist_free(aliases);
            aliases = NULL;
			fi_free(fi);
			fi = NULL;
			continue;
		}

		if (!fi) {
			fi = walloc0(sizeof(struct dl_file_info));
			fi->refcount = 0;
			aliases = NULL;
		}

		if (!strncmp(line, "NAME ", 5))
			fi->file_name = atom_str_get(line + 5);
		else if (!strncmp(line, "PATH ", 5))
			fi->path = atom_str_get(line + 5);
		else if (!strncmp(line, "ALIA ", 5))
			aliases = g_slist_append(aliases, atom_str_get(line + 5));
		else if (!strncmp(line, "GENR ", 5))
			fi->generation = atoi(line + 5);
		else if (!strncmp(line, "SIZE ", 5)) {
			fi->size = atoi(line + 5);
			fi->size_atom = atom_int_get(&fi->size);
		} else if (!strncmp(line, "TIME ", 5))
			fi->stamp = atoi(line + 5);
		else if (!strncmp(line, "DONE ", 5))
			fi->done = atoi(line + 5);
		else if (!strncmp(line, "SWRM ", 5))
			fi->use_swarming = atoi(line + 5);
		else if (!strncmp(line, "SHA1 ", 5))
			fi->sha1 = extract_sha1(line);
		else if (!strncmp(line, "CHA1 ", 5))
			fi->cha1 = extract_sha1(line);
		else if (!strncmp(line, "CHNK ", 5)) {
			if (sscanf(line + 5, "%u %u %u", &from, &to, &status)) {
				fc = walloc0(sizeof(struct dl_file_chunk));
				fc->from = from;
				fc->to = to;
				if (status == DL_CHUNK_BUSY) status = DL_CHUNK_EMPTY;
				fc->status = status;
				fi->chunklist = g_slist_append(fi->chunklist, fc);
			}
		} else if (*line)
			g_warning("ignoring fileinfo line: %s", line);
	}

	if (fi) {
		fi_free(fi);
		if (!empty)
			g_warning("file info repository was truncated!");
	}

	fclose(f);
}

/*
 * escape_filename
 *
 * Lazily replace all '/' if filename with '_': if a substitution needs to
 * be done, a copy of the original argument is made first.	Otherwise,
 * no change nor allocation occur.
 *
 * All the control characters are also replaced with '_'.
 *
 * Returns the pointer to the escaped filename, or the original argument if
 * no escaping needed to be performed.
 */
static gchar *escape_filename(gchar *file)
{
	gchar *escaped = NULL;
	gchar *s;
	guchar c;

	s = file;
	while ((c = *(guchar *) s)) {
		if (c == '/' || iscntrl(c)) {
			if (escaped == NULL) {
				escaped = g_strdup(file);
				s = escaped + (s - file);	/* s now refers to escaped string */
				g_assert(*(guchar *) s == c);
			}
			*s = '_';
		}
		s++;
	}

	return escaped == NULL ? file : escaped;
}

/*
 * file_info_new_outname
 *
 * Allocate unique output name for file `name'.
 * Returns filename atom.
 */
static gchar *file_info_new_outname(gchar *name)
{
	gint i;
	gchar xuid[16];
	gint flen;
	gchar *escaped = escape_filename(name);
	gchar *result;
	gchar *empty = "noname";

	if (*escaped == '\0')			/* Don't allow empty names */
		escaped = empty;

	/*
	 * If `name' (escaped form) is not taken yet, it will do.
	 */

	if (NULL == g_hash_table_lookup(fi_by_outname, escaped)) {
		result = atom_str_get(escaped);
		goto ok;
	}

	/*
	 * OK, try with .01 extension, then .02, etc...
	 */

	flen = gm_snprintf(fi_tmp, sizeof(fi_tmp), "%s", escaped);

	for (i = 1; i < 100; i++) {
		gm_snprintf(&fi_tmp[flen], sizeof(fi_tmp)-flen, ".%02d", i);
		if (NULL == g_hash_table_lookup(fi_by_outname, fi_tmp)) {
			result = atom_str_get(fi_tmp);
			goto ok;
		}
	}

	/*
	 * No luck, allocate random GUID and append it.
	 */

	guid_random_fill(xuid);

	gm_snprintf(&fi_tmp[flen], sizeof(fi_tmp)-flen, "-%s", guid_hex_str(xuid));
	if (NULL == g_hash_table_lookup(fi_by_outname, fi_tmp)) {
		result = atom_str_get(fi_tmp);
		goto ok;
	}

	g_error("no luck with random number generator");	/* Should NOT happen */
	return NULL;

ok:
	if (escaped != name && escaped != empty)
		g_free(escaped);

	return result;
}

/*
 * file_info_create
 *
 * Create a fileinfo structure from existing file with no swarming trailer.
 * The given `size' argument reflect the final size of the (complete) file.
 * The `sha1' is the known SHA1 for the file (NULL if unknown).
 */
static struct dl_file_info *file_info_create(
	gchar *file, const gchar *path, guint32 size, const gchar *sha1)
{
	struct dl_file_info *fi;
	struct stat st;
	char *pathname;

	fi = walloc0(sizeof(struct dl_file_info));
	fi->file_name = file_info_new_outname(file);	/* Get unique file name */
	fi->path = atom_str_get(path);
	if (sha1)
		fi->sha1 = atom_sha1_get(sha1);
	fi->size = 0;							/* Will be updated below */
	fi->done = 0;
	fi->use_swarming = use_swarming;

	pathname = g_strdup_printf("%s/%s", fi->path, fi->file_name);
	if (NULL != pathname && stat(pathname, &st) != -1) {
		struct dl_file_chunk *fc;

		g_warning("file_info_create(): "
			"assuming file \"%s\" is complete up to %lu bytes",
			pathname, (gulong) st.st_size);
		G_FREE_NULL(pathname);
		fc = walloc0(sizeof(struct dl_file_chunk));
		fc->from = 0;
		fi->size = fc->to = st.st_size;
		fc->status = DL_CHUNK_DONE;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
		fi->dirty = TRUE;
	} 
	if (NULL != pathname)
		G_FREE_NULL(pathname);

	fi->size_atom = atom_int_get(&fi->size);	/* Set now, for fi_resize() */

	if (size > fi->size)
		fi_resize(fi, size);

	return fi;
}

/*
 * file_info_recreate		-- UNUSED
 *
 * Existing fileinfo structure is obsolete. Recreate it from existing
 * file with no swarming info (assuming file has no free holes over its
 * completed range so far, naturally).
 */
void file_info_recreate(struct download *d)
{
	struct dl_file_info *fi = d->file_info;
	struct dl_file_info *new_fi;
	GSList *l;

	g_assert(d->status == GTA_DL_CONNECTING);

	/*
	 * Before creating new fileinfo, we must remove the old structure
	 * from the hash table.  This will also ensure that the output name is
	 * freed and available for immediate reuse.
	 */

	file_info_hash_remove(fi);
	new_fi = file_info_create(fi->file_name, fi->path, fi->size, fi->sha1);

	/*
	 * Copy old alises to new structure.
	 */

	for (l = fi->alias; l; l = g_slist_next(l)) {
		const gchar *alias = (const gchar *) l->data;
		new_fi->alias = g_slist_append(new_fi->alias, atom_str_get(alias));
	}

	file_info_hash_insert(new_fi);

	/*
	 * We change the target's file info on the fly here, because we know this
	 * download has not started yet, it's only preparing.  If we did it through
	 * the download_info_change_all() call, it would be requeued due to the
	 * fileinfo change.
	 */

	d->file_info = new_fi;			/* Don't decrement refcount on fi yet */
    file_info_add_source(new_fi, d);
	new_fi->lifecount++;

	/*
	 * All other downloads bearing the old `fi' are moved to the new one,
	 * but this will cause all running downloads to be requeued.  That's
	 * why we changed the target ourselves above.
	 */

	download_info_change_all(fi, new_fi);

	g_assert(fi->refcount == 1);	/* We did not decrement refcount on `d' */

	fi_free(fi);					/* Last reference removed */
}

/*
 * file_info_get
 *
 * Returns a pointer to file_info struct that matches the given file
 * name, size and/or SHA1. A new struct will be allocated if necessary.
 *
 * `file' is the file name on the server.
 */ 
struct dl_file_info *file_info_get(
	gchar *file, const gchar *path, guint32 size, gchar *sha1)
{
	struct dl_file_info *fi;
	gchar *outname;

	/*
	 * See if we know anything about the file already.
	 */

	fi = file_info_lookup(file, size, sha1);

	if (fi && sha1 && fi->sha1 && !sha1_eq(sha1, fi->sha1))
		fi = NULL;

	if (fi) {
		/*
		 * If download size is greater, we need to resize the output file.
		 * This can only happen for a download with a SHA1, because otherwise
		 * we perform a matching on name AND size.
		 */

		if (size > fi->size) {
			g_assert(fi->sha1);
			g_assert(sha1);

			g_warning("file \"%s\" (SHA1 %s) was %u bytes, resizing to %u",
				fi->file_name, sha1_base32(fi->sha1), fi->size, size);

			file_info_hash_remove(fi);
			fi_resize(fi, size);
			file_info_hash_insert(fi);
		}

		fi_alias(fi, file, TRUE);	/* Add alias if not conflicting */

		return fi;
	}

	/*
	 * Compute new output name.  If the filename is not taken yet, this
	 * will be exactly `file'.  Otherwise, it will be a variant.
	 */

	outname = file_info_new_outname(file);

	/*
	 * Check whether the file exists and has embedded meta info.
	 * Note that we use the new `outname', not `file'.
	 */

	if ((fi = file_info_retrieve_binary(outname, path)) != NULL) {
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
		 */

		if (fi->sha1 != NULL && (sha1 == NULL || !sha1_eq(sha1, fi->sha1))) {
			char *dead;
			char *pathname;

			g_warning("found DEAD file \"%s\" bearing SHA1 %s",
				outname, sha1_base32(fi->sha1));

			pathname = g_strdup_printf("%s/%s", path, outname);
			dead = g_strdup_printf("%s/%s.DEAD", path, outname);

			if (
				NULL != pathname &&
				NULL != dead &&
				-1 == rename(pathname, dead)
			)
				g_warning("cannot rename \"%s\" as \"%s\": %s",
					pathname, dead, g_strerror(errno));

			if (NULL != dead)
				G_FREE_NULL(dead);
			if (NULL != pathname)
				G_FREE_NULL(pathname);
			fi_free(fi);
			fi = NULL;
		}
		else if (fi->size < size) {
			/*
			 * Existing file is smaller than the total size of this file.
			 * Trust the larger size, because it's the only sane thing to do.
			 * NB: if we have a SHA1, we know it's matching at this point.
			 */

			g_warning("found existing file \"%s\" size=%u, increasing to %u",
				outname, fi->size, size);

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

	if (fi == NULL) {
		fi = file_info_create(outname, path, size, sha1);
		fi_alias(fi, file, FALSE);
	}
	
	file_info_hash_insert(fi);

	if (sha1)
		dmesh_multiple_downloads(sha1, size, fi);

	atom_str_free(outname);

	return fi;
}

/*
 * file_info_has_identical
 *
 * Returns a pointer to the file info struct if we have a file
 * identical to the given properties in the download queue already,
 * and NULL otherwise.
 */
struct dl_file_info *file_info_has_identical(
	gchar *file, guint32 size, gchar *sha1)
{
	GSList *p;
	GSList *sizelist;
	struct dl_file_info *fi;
	namesize_t nsk;

	/*
	 * Compute list of entries whose size matches.  If none, it is a
	 * certainety we won't have any identical entry!
	 */

	sizelist = g_hash_table_lookup(fi_by_size, &size);
	if (sizelist == NULL)
		return NULL;

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

	nsk.name = file;
	nsk.size = size;

	fi = g_hash_table_lookup(fi_by_namesize, &nsk);

	if (fi && sha1 && fi->sha1 && sha1_eq(sha1, fi->sha1))
		return fi;

	/*
	 * Look up by similar filenames.  We go through the list of all the
	 * known fileinfo entries with an identical filesize.
	 */

	for (p = sizelist; p; p = p->next) {
		fi = (struct dl_file_info *) p->data;

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

/*
 * file_info_set_discard
 *
 * Set or clear the discard state for a fileinfo.
 */
void file_info_set_discard(struct dl_file_info *fi, gboolean state)
{
	g_assert(fi);

	if (state)
		fi->flags |= FI_F_DISCARD;
	else
		fi->flags &= ~FI_F_DISCARD;
}

/*
 * file_info_merge_adjacent
 *
 * Go through the chunk list and merge adjacent chunks that share the
 * same status and download. Keeps the chunk list short and tidy. 
 */
void file_info_merge_adjacent(struct dl_file_info *fi)
{
	GSList *fclist;
	int n;
	struct dl_file_chunk *fc1, *fc2;
	int restart = 1;
	guint done;

	while (restart) {
		restart = 0;
		done = 0;
		fc2 = NULL;
		for (
			n = 0, fclist = fi->chunklist;
			fclist;
			n++, fclist = g_slist_next(fclist)
		) {
			fc1 = fc2;
			fc2 = fclist->data;

			if (fc2->status == DL_CHUNK_DONE)
				done += fc2->to - fc2->from;

			if (!fc1 || !fc2) continue;

			if (
				fc1->to == fc2->from &&
				fc1->status == fc2->status &&
				fc1->download == fc2->download
			) {
				fc1->to = fc2->to;
				fi->chunklist = g_slist_remove(fi->chunklist, fc2);
				wfree(fc2, sizeof(*fc2));
				restart = 1;
				break;
			}
		}
	}
	fi->done = done;
}

/*
 * file_info_update
 *
 * Marks a chunk of the file with given status.
 * The bytes range from `from' (included) to `to' (excluded).
 */
void file_info_update(
	struct download *d, guint32 from, guint32 to, enum dl_chunk_status status)
{
	GSList *fclist;
	int n;
	struct dl_file_info *fi = d->file_info;
	struct dl_file_chunk *fc, *nfc;
	gboolean found = FALSE;
	int againcount = 0;
	struct download *newval = (status == DL_CHUNK_EMPTY) ? NULL : d;

	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);

	fi->stamp = time((time_t *)NULL);

	if (status == DL_CHUNK_DONE)
		fi->dirty = TRUE;

again:

	/* I think the algorithm is safe now, but hey... */
	if (++againcount > 10) {
		g_warning("Eek! Internal error! "
			"file_info_update(%u, %u, %d) is looping for \"%s\"! "
			"Man battle stations!",
			from, to, status, d->file_name);
		return;
	}

	for (
		n = 0, fclist = fi->chunklist;
		fclist;
		n++, fclist = g_slist_next(fclist)
	) {
		fc = fclist->data;

		if (fc->to <= from) continue;
		if (fc->from >= to) break;

		if ((fc->from == from) && (fc->to == to)) {

			fc->status = status;	
			fc->download = newval;
			found = TRUE;
			break;

		} else if ((fc->from == from) && (fc->to < to)) {

			fc->status = status;
			fc->download = newval;
			from = fc->to;
			continue;

		} else if ((fc->from == from) && (fc->to > to)) {

			nfc = walloc(sizeof(struct dl_file_chunk));
			nfc->from = to;
			nfc->to = fc->to;
			nfc->status = fc->status;
			nfc->download = fc->download;

			fc->to = to;
			fc->status = status;
			fc->download = newval;
			g_slist_insert(fi->chunklist, nfc, n+1);
			found = TRUE;
			break;

		} else if ((fc->from < from) && (fc->to >= to)) {

			nfc = walloc(sizeof(struct dl_file_chunk));
			nfc->from = from;
			nfc->to = to;
			nfc->status = status;
			nfc->download = newval;
			g_slist_insert(fi->chunklist, nfc, n+1);

			if (fc->to > to) {
				nfc = walloc(sizeof(struct dl_file_chunk));
				nfc->from = to;
				nfc->to = fc->to;
				nfc->status = fc->status;
				nfc->download = fc->download;
				g_slist_insert(fi->chunklist, nfc, n+2);
			}

			fc->to = from;

			found = TRUE;
			break;

		} else if ((fc->from < from) && (fc->to < to)) {

			guint32 tmp;

			nfc = walloc(sizeof(struct dl_file_chunk));
			nfc->from = from;
			nfc->to = fc->to;
			nfc->status = status;
			nfc->download = newval;
			g_slist_insert(fi->chunklist, nfc, n+1);

			tmp = fc->to;
			fc->to = from;
			from = tmp;
			goto again;

		}
	}

	if (!found) {
		/* Should never happen. */
		g_warning("file_info_update(): "
			"(%s) Didn't find matching chunk for <%u-%u> (%u)",
			fi->file_name, from, to, status);
		for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
			fc = fclist->data;
			g_warning("... %u %u %u", fc->from, fc->to, fc->status);
		}
	}

	/*
	 * Update fi->done, accurately.
	 *
	 * We don't blindly update fi->done with (to - from) when DL_CHUNK_DONE
	 * because we may be writing data to an already "done" chunk, when a
	 * previous chunk bumps into a done one.
	 *		--RAM, 04/11/2002
	 */

	file_info_merge_adjacent(fi);		/* Also updates fi->done */

	/*
	 * When status is DL_CHUNK_DONE, we're coming from an "active" download,
	 * i.e. we are writing to it, therefore we can reuse its file descriptor.
	 */

	if (status == DL_CHUNK_DONE)
		file_info_fd_store_binary(d->file_info, d->file_desc, FALSE);
	else if (fi->dirty)
		file_info_store_binary(d->file_info);

    event_trigger(
        fi_events[EV_FI_STATUS_CHANGED], 
        T_NORMAL(fi_listener_t, fi->fi_handle));    
}

/*
 * file_info_clear_download
 *
 * Go through all chunks that belong to the download,
 * and unmark them as busy.
 *
 * If `lifecount' is TRUE, the download is still counted as being "alive",
 * and this is only used for assertions.
 */
void file_info_clear_download(struct download *d, gboolean lifecount)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	struct dl_file_info *fi = d->file_info;
	gint busy;			/* For assertions only */

	for (fclist = fi->chunklist, busy = 0; fclist; fclist = fclist->next) {
		fc = fclist->data;
		if (fc->status == DL_CHUNK_BUSY)
			busy++;
		if (fc->download == d) {
			if (fc->status == DL_CHUNK_BUSY)
				fc->status = DL_CHUNK_EMPTY;
			fc->download = NULL;
		}
	}
	file_info_merge_adjacent(d->file_info);

	g_assert(fi->lifecount >= (lifecount ? busy : (busy - 1)));

	/* No need to flush data to disk, those are transient changes */
}

/*
 * file_info_reset
 *
 * Reset all chunks to EMPTY, clear computed SHA1 if any.
 */
void file_info_reset(struct dl_file_info *fi)
{
	GSList *l;
	struct dl_file_chunk *fc;

	if (fi->cha1) {
		atom_sha1_free(fi->cha1);
		fi->cha1 = NULL;
	}

restart:
	for (l = fi->chunklist; l; l = g_slist_next(l)) {
		struct download *d;

		fc = (struct dl_file_chunk *) l->data;
		d = fc->download;

		if (d && DOWNLOAD_IS_RUNNING(d)) {
			download_queue(d, "Requeued due to file removal");
			goto restart;		/* Because file_info_clear_download() called */
		}
	}

	for (l = fi->chunklist; l; l = g_slist_next(l)) {
		fc = (struct dl_file_chunk *) l->data;
		fc->status = DL_CHUNK_EMPTY;
	}

	file_info_merge_adjacent(fi);
	fileinfo_dirty = TRUE;
}

/*
 * file_info_chunk_status
 *
 * Returns DONE if the range requested is marked as complete,
 * or BUSY if not. Used to determine if we can do overlap
 * checking.
 */
enum dl_chunk_status file_info_chunk_status(
	struct dl_file_info *fi, guint32 from, guint32 to)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	
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

/*
 * file_info_pos_status
 *
 * Returns the status (EMPTY, BUSY or DONE) of the byte requested.
 * Used to detect if a download is crashing with another.
 */
enum dl_chunk_status file_info_pos_status(struct dl_file_info *fi, guint32 pos)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	
	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;
		if ((pos >= fc->from) && (pos < fc->to))
			return fc->status;
	}

	if (pos > fi->size)
		g_warning("file_info_pos_status(): Unreachable pos??");

	return DL_CHUNK_DONE;
}

/*
 * fi_check_file
 *
 * This routine is called each time we start a new download, before
 * making the request to the remote server. If we detect that the
 * file is "gone", then it means the user manually deleted the file.
 * In that case, we need to reset all the chunks and mark the whole
 * thing as being EMPTY.
 * 		--RAM, 21/08/2002.
 */
static void fi_check_file(struct dl_file_info *fi)
{
	char *path;
	struct stat buf;

	g_assert(fi->done);			/* Or file will not exist */

	/*
	 * File should exist since fi->done > 0, and it was not completed.
	 */

	path = g_strdup_printf("%s/%s", fi->path, fi->file_name);
	g_return_if_fail(path);

	if (-1 == stat(path, &buf) && ENOENT == errno) {
		g_warning("file %s removed, resetting swarming", path);
		file_info_reset(fi);
	}
	G_FREE_NULL(path);
}

/*
 * fi_busy_count
 *
 * Count the about of BUSY chunks attached to a given download.
 */
static gint fi_busy_count(struct dl_file_info *fi, struct download *d)
{
	GSList *l;
	gint count = 0;

	for (l = fi->chunklist; l; l = g_slist_next(l)) {
		struct dl_file_chunk *fc = l->data;

		if (fc->download == d && fc->status == DL_CHUNK_BUSY)
			count++;
	}

	g_assert(fi->lifecount >= count);

	return count;
}

/*
 * file_info_find_hole
 *
 * Finds a range to download, and stores it in *from and *to.
 * If "aggressive" is off, it will return only ranges that are
 * EMPTY. If on, and no EMPTY ranges are available, it will
 * grab a chunk out of the longest BUSY chunk instead, and
 * "compete" with the download that reserved it.
 */
enum dl_chunk_status file_info_find_hole(
	struct download *d, guint32 *from, guint32 *to)
{
	GSList *fclist;
	struct dl_file_chunk *fc;
	struct dl_file_info *fi = d->file_info;
	guint32 chunksize;
	guint busy = 0;

	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);
	g_assert(0 == fi_busy_count(fi, d));	/* No reservation for `d' yet */

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
		g_warning("fi->size=%u < d->file_size=%u for \"%s\"",
			fi->size, d->file_size, fi->file_name);
	}

	g_assert(fi->lifecount > 0);

	chunksize = fi->size / fi->lifecount;

	if (chunksize < dl_minchunksize) chunksize = dl_minchunksize;
	if (chunksize > dl_maxchunksize) chunksize = dl_maxchunksize;

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;

		if (fc->status != DL_CHUNK_EMPTY) {
			if (fc->status == DL_CHUNK_BUSY)
				busy++;		/* Will be used by assert below */
			continue;
		}

		*from = fc->from;
		*to = fc->to;
#if 0
		if (*from && ((*to - *from) > (chunksize * 2)))
			*from = (*from + *to) / 2;
#endif /* 0 */
		if ((*to - *from) > chunksize)
			*to = *from + chunksize;

		file_info_update(d, *from, *to, DL_CHUNK_BUSY);
		return DL_CHUNK_EMPTY;
	}

	g_assert(fi->lifecount > busy);		/* Or we'd found a chunk before */

	if (use_aggressive_swarming) {
		guint32 longest_from = 0, longest_to = 0;
		gint starving;
		guint32 minchunk;

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

		for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
			fc = fclist->data;

			if (fc->status != DL_CHUNK_BUSY) continue;
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
			return DL_CHUNK_EMPTY;
		}
	}
	
	/* No holes found. */
	return (fi->done == fi->size) ? DL_CHUNK_DONE : DL_CHUNK_BUSY;
}

/*
 * file_info_find_available_hole
 *
 * Find free chunk that also fully belongs to the `ranges' list.
 *
 * Returns TRUE if one was found, with `from' and `to' set, FALSE otherwise.
 * NB: In accordance with other fileinfo semantics, `to' is NOT the last byte
 * of the range but one byte AFTER the end.
 */
gboolean file_info_find_available_hole(struct download *d,
	GSList *ranges, guint32 *from, guint32 *to)
{
	GSList *fclist;
	struct dl_file_info *fi;
	guint32 chunksize;

	g_assert(d);
	g_assert(ranges);

	fi = d->file_info;

	/*
	 * Ensure the file has not disappeared.
	 */

	if (fi->done) {
		if (fi->done == fi->size)
			return FALSE;;

		fi_check_file(fi);
	}

	g_assert(fi->lifecount > 0);

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		GSList *l;
		struct dl_file_chunk *fc = fclist->data;

		if (fc->status != DL_CHUNK_EMPTY)
			continue;

		/*
		 * Look whether this empty chunk intersects with one of the
		 * available ranges.
		 *
		 * NB: the list of ranges is sorted.  And contrary to fi chunks,
		 * the upper boundary of the range (r->end) is part of the range.
		 */

		for (l = ranges; l; l = g_slist_next(l)) {
			http_range_t *r = (http_range_t *) l->data;

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

	return FALSE;

found:
	chunksize = fi->size / fi->lifecount;

	if (chunksize < dl_minchunksize) chunksize = dl_minchunksize;
	if (chunksize > dl_maxchunksize) chunksize = dl_maxchunksize;

	if ((*to - *from) > chunksize)
		*to = *from + chunksize;

	file_info_update(d, *from, *to, DL_CHUNK_BUSY);

	return TRUE;
}

/*
 * file_info_active
 *
 * Return a dl_file_info if there's an active one with the same sha1.
 */
static struct dl_file_info *file_info_active(const gchar *sha1)
{
	return g_hash_table_lookup(fi_by_sha1, sha1);
}

/*
 * file_info_try_to_swarm_with
 *
 * Called when we add something to the dmesh. Add the corresponding file to the
 * download list if we're swarming on it.
 *
 * file_name: the remote file name (as in the GET query).
 * idx: the remote file index (as in the GET query)
 * ip: the remote servent ip
 * port: the remote servent port
 * sha1: the SHA1 of the file
 */
void file_info_try_to_swarm_with(
	gchar *file_name, guint32 idx, guint32 ip, guint32 port, gchar *sha1)
{
	struct dl_file_info *fi;

	if (!can_swarm)				/* Downloads not initialized yet */
		return;

	fi = file_info_active(sha1);
	if (!fi)
		return;

	download_auto_new(file_name, fi->size, idx, ip, port, blank_guid, sha1,
		time(NULL), FALSE, fi, NULL);
}

/*
 * file_info_scandir
 *
 * Scan the given directory for files, looking at those bearing a valid
 * fileinfo trailer, yet which we know nothing about.
 */
void file_info_scandir(const gchar *dir)
{
	DIR *d;
	struct dirent *dentry;
	gchar *slash = "/";
	struct dl_file_info *fi;
	gchar *filename = NULL;

	d = opendir(dir);
	if (d == NULL) {
		g_warning("can't open directory %s: %s", dir, g_strerror(errno));
		return;
	}

	if (dir[strlen(dir) - 1] == '/')
		slash = "";

	while ((dentry = readdir(d))) {
		struct stat buf;
		
		if (NULL != filename)
			G_FREE_NULL(filename);

		if (dentry->d_name[0] == '.') {
			if (
				dentry->d_name[1] == '\0' ||
				(dentry->d_name[1] == '.' && dentry->d_name[2] == '\0')
			)
				continue;					/* Skip "." and ".." */
		}

		filename = g_strdup_printf("%s%s%s", dir, slash, dentry->d_name);
		if (NULL == filename)
			continue;

		if (-1 == stat(filename, &buf)) {
			g_warning("cannot stat %s: %s", filename, g_strerror(errno));
			continue;
		}

		if (!S_ISREG(buf.st_mode))			/* Only regular files */
			continue;

		fi = file_info_retrieve_binary(dentry->d_name, dir);
		if (fi == NULL)
			continue;

		if (file_info_lookup_dup(fi)) {		/* Already know about this */
			fi_free(fi);
			continue;
		}

		/*
		 * We found an entry that we do not know about.
		 */

		file_info_merge_adjacent(fi);		/* Update fi->done */
		file_info_hash_insert(fi);

		g_warning("reactivated orphan entry (%.02f%% done, %s SHA1): %s",
			fi->done * 100.0 / (fi->size == 0 ? 1 : fi->size),
			fi->sha1 ? "with" : "no", filename);
	}

	if (NULL != filename)
		G_FREE_NULL(filename);
	closedir(d);
}

/*
 * fi_spot_completed_kv
 *
 * Callback for hash table iterator. Used by file_info_completed_orphans().
 */
static void fi_spot_completed_kv(gpointer key, gpointer val, gpointer x)
{
	const gchar *name = (const gchar *) key;
	struct dl_file_info *fi = (struct dl_file_info *) val;

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

/*
 * file_info_spot_completed_orphans
 *
 * Look through all the known fileinfo structures, looking for orphaned
 * files that are complete.
 *
 * A fake download is created for them, so that download_resume_bg_tasks()
 * can pick them up.
 */
void file_info_spot_completed_orphans(void)
{
	g_hash_table_foreach(fi_by_outname, fi_spot_completed_kv, NULL);
}

void fi_add_listener(GCallback cb, gnet_fi_ev_t ev,
    frequency_t t, guint32 interval)
{
    g_assert(ev < EV_FI_EVENTS);

    event_add_subscriber(fi_events[ev], (GCallback) cb,
        t, interval);
}

void fi_remove_listener(GCallback cb, gnet_fi_ev_t ev)
{
    g_assert(ev < EV_FI_EVENTS);

    event_remove_subscriber(fi_events[ev], cb);
}

gnet_fi_info_t *fi_get_info(gnet_fi_t fih)
{
    struct dl_file_info *fi = file_info_find_by_handle(fih); 
    gnet_fi_info_t *info;

    info = walloc(sizeof(*info));

    info->file_name = fi->file_name ? atom_str_get(fi->file_name) : NULL;
    info->fi_handle = fi->fi_handle;

    return info;

}

void fi_free_info(gnet_fi_info_t *info)
{
    g_assert(info != NULL);

	if (info->file_name)
		atom_str_free(info->file_name);

    wfree(info, sizeof(*info));
}

void fi_get_status(gnet_fi_t fih, gnet_fi_status_t *s)
{
    struct dl_file_info *fi = file_info_find_by_handle(fih); 

    g_assert(s != NULL);

    s->recvcount      = fi->recvcount;
    s->refcount       = fi->refcount;
    s->lifecount      = fi->lifecount;
    s->done           = fi->done;
    s->recv_last_rate = fi->recv_last_rate;
    s->size           = fi->size;
}


/*
 * fi_get_aliases:
 *
 * O(2n) - n: number of aliases
 *
 * Return NULL terminated array of gchar * pointing to the aliases.
 * You can easily free the returned array with g_strfreev().
 */
gchar **fi_get_aliases(gnet_fi_t fih)
{
    gchar **a;
    guint len;
    GSList *sl;
    guint n;
    struct dl_file_info *fi = file_info_find_by_handle(fih); 

    len = g_slist_length(fi->alias);

    a = g_new(gchar *, len+1);
    a[len] = NULL; /* terminate with NULL */;

    for (sl = fi->alias, n = 0; sl != NULL; sl = g_slist_next(sl), n++) {
        g_assert(n < len);
        a[n] = g_strdup((gchar *)sl->data);
    }

    return a;
}

void file_info_add_source(
    struct dl_file_info *fi, struct download *dl)
{
    g_assert(dl->file_info == NULL);

    fi->refcount++;
    fi->dirty_status = TRUE;
    dl->file_info = fi;
    fi->sources = g_slist_prepend(fi->sources, dl);

    event_trigger(
        fi_events[EV_FI_SRC_ADDED], 
        T_NORMAL(fi_src_listener_t, fi->fi_handle, dl->src_handle));    
}

/*
 * file_info_remove_source:
 *
 * Removing one source reference from the fileinfo.
 * When no sources reference the fileinfo structure, free it if `discard' 
 * is TRUE, or if the fileinfo has been marked with FI_F_DISCARD.
 * This replaces file_info_free()
 */
void file_info_remove_source(
    struct dl_file_info *fi, struct download *dl, gboolean discard)
{
    g_assert(dl->file_info != NULL);
    g_assert(fi->refcount > 0);
	g_assert(fi->hashed);
    
    event_trigger(
        fi_events[EV_FI_SRC_REMOVED], 
        T_NORMAL(fi_src_listener_t, fi->fi_handle, dl->src_handle));    

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

    if (fi->refcount == 0 && (discard || (fi->flags & FI_F_DISCARD))) {
		file_info_hash_remove(fi);
		fi_free(fi);
    }
}

static void fi_notify_helper(
    gpointer key, gpointer value, gpointer user_data)
{
    struct dl_file_info *fi = (struct dl_file_info *)value;

    if (!fi->dirty_status)
        return;

    fi->dirty_status = FALSE;

    event_trigger(
        fi_events[EV_FI_STATUS_CHANGED], 
        T_NORMAL(fi_listener_t, fi->fi_handle));    
}

void file_info_timer(void)
{
	g_hash_table_foreach(fi_by_outname, fi_notify_helper, NULL);
}

/*
 * fi_purge:
 *
 * Kill all downloads associated with a fi and remove the fi itself.
 */
void fi_purge(gnet_fi_t fih)
{
	GSList *sl;
	GSList *csl;
	struct dl_file_info *fi = file_info_find_by_handle(fih); 

	g_assert(fi != NULL);
	g_assert(fi->hashed);

	csl = g_slist_copy(fi->sources);	/* Clone list, orig can be modified */

	for(sl = csl; sl != NULL; sl = g_slist_next(sl)) {
		struct download *dl = (struct download *) sl->data;

		download_abort(dl);
		download_remove(dl);
	}

	g_slist_free(csl);

	/*
	 * Downloads not freed at this point, this will happen when the
	 * download_free_removed() is asynchronously called.  However, all
	 * references to the file info has been cleared, so we can remove it.
	 */

	g_assert(fi->refcount == 0);

	file_info_hash_remove(fi);
	fi_free(fi);
}

