/*
 * $Id$
 *
 * Copyright (c) 2002, Vidar Madsen & Raphael Manfredi
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
#include "getline.h"
#include "header.h"
#include "routing.h"
#include "routing.h"
#include "gmsg.h"
#include "bsched.h"
#include "regex.h"
#include "huge.h"
#include "dmesh.h"
#include "namesize.h"
#include "guid.h"
#include "misc.h"

#include "settings.h"
#include "nodes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>			/* For ctime() */
#include <netinet/in.h>		/* For ntohl() and friends... */

#define FI_MIN_CHUNK_SPLIT	512		/* Smallest chunk we can split */

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
static GHashTable *fi_by_outname = NULL;

static gchar *file_info_file = "fileinfo";
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
	FILE_INFO_FIELD_END,
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
	file_info_checksum(&checksum, (guchar *) &val, sizeof(val)); \
} while(0)

#define WRITE_STR(a, b) do {		\
	TBUF_WRITE(a, b);				\
	file_info_checksum(&checksum, (guchar *) a, b); \
} while(0)

/*
 * High-level read macros.
 */

#define READ_INT32(a) do {			\
	gint32 val;						\
	TBUF_GETINT32(&val);			\
	*a = ntohl(val);				\
	file_info_checksum(&checksum, (guchar *) &val, sizeof(val)); \
} while(0)

#define READ_STR(a, b) do {			\
	TBUF_READ(a, b);				\
	file_info_checksum(&checksum, (guchar *) a, b); \
} while(0)

/*
 * Addition of a variable-size trailer field.
 */

#define FIELD_ADD(a,b,c) do {		\
	guint32 len = (b);				\
	WRITE_INT32(a);					\
	WRITE_INT32(len);				\
	WRITE_STR(c, len);				\
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
}

static inline void file_info_checksum(guint32 *checksum, guchar *d, int len)
{
	while (len--)
		*checksum = (*checksum << 1) ^ (*checksum >> 31) ^ *d++;
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

	for (a = fi->alias; a; a = a->next)
		FIELD_ADD(FILE_INFO_FIELD_ALIAS, strlen(a->data)+1, a->data);

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
	WRITE_INT32(FILE_INFO_MAGIC);

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
static void file_info_store_binary(struct dl_file_info *fi)
{
	int fd;

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);

	/*
	 * We don't create the file if it does not already exist.  That way,
	 * a file is only created when at least one byte of data is downloaded,
	 * since then we'll go directly to file_info_fd_store_binary().
	 */

	fd = open(fi_tmp, O_WRONLY);

	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("file_info_store_binary(): "
				"can't open \"%s\" for writing: %s",
				fi_tmp, g_strerror(errno));
		return;
	}

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
	/* fixme: too quick'n'dirty? */
	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);
	truncate(fi_tmp, fi->size);
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
	if (fi->chunklist) {
		for (l = fi->chunklist; l; l = l->next)
			g_free(l->data);
		g_slist_free(fi->chunklist);
	}
	if (fi->alias) {
		for (l = fi->alias; l; l = l->next)
			atom_str_free(l->data);
		g_slist_free(fi->alias);
	}
	g_free(fi);
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

	fc = g_malloc0(sizeof(*fc));
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
static gboolean file_info_get_trailer(gint fd, struct trailer *tb, gchar *name)
{
	guint32 tr[5];
	struct stat buf;

	g_assert(fd >= 0);
	g_assert(tb);

	if (-1 == fstat(fd, &buf)) {
		g_warning("error fstat()ing \"%s\": %s", name, g_strerror(errno));
		return FALSE;
	}

	if (buf.st_size < sizeof(tr))
		return FALSE;

	if (lseek(fd, -sizeof(tr), SEEK_END) == -1) {
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
off_t file_info_filesize(gchar *path)
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
			gint score = 100 * fuzzy_compare(a->data, file);
			if (score >= fuzzy_threshold) {
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
	guchar *name, guint32 size, guchar *sha1)
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
static struct dl_file_info *file_info_retrieve_binary(gchar *file, gchar *path)
{
	guint32 tmpchunk[3];
	guint32 tmpguint;
	guint32 checksum = 0;
	struct dl_file_info *fi = NULL;
	struct dl_file_chunk *fc;
	enum dl_file_info_field field;
	gchar tmp[1024];
	gchar *reason;
	gint fd;
	guint32 version;
	struct trailer trailer;

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", path, file);
	
	fd = open(fi_tmp, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("can't open \"%s\" for reading: %s",
				fi_tmp, g_strerror(errno));
		return NULL;
	}

	if (!file_info_get_trailer(fd, &trailer, fi_tmp)) {
		reason = "could not find trailer";
		goto bailout;
	}

	if (-1 == lseek(fd, trailer.filesize, SEEK_SET)) {
		g_warning("seek to position %u within \"%s\" failed: %s",
			trailer.filesize, fi_tmp, g_strerror(errno));
		goto eof;
	}

	/*
	 * Now read the whole trailer in memory.
	 */

	if (-1 == tbuf_read(fd, trailer.length)) {
		g_warning("file_info_retrieve_binary(): "
			"unable to read whole trailer (%d bytes) from \"%s\": %s",
			trailer.filesize, fi_tmp, g_strerror(errno));
		goto eof;
	}

	/* Check version */
	READ_INT32(&version);
	if (version > FILE_INFO_VERSION) {
		g_warning("file_info_retrieve_binary(): strange version; %u", version);
		goto eof;
	}

	fi = g_malloc0(sizeof(struct dl_file_info));
   
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
			reason = "zero field size";
			goto bailout;
		}
		
		if (tmpguint > sizeof(tmp)) {
			reason = "too long a field";
			goto bailout;
		}

		READ_STR(tmp, tmpguint);

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
		case FILE_INFO_FIELD_CHUNK:
			memcpy(tmpchunk, tmp, sizeof(tmpchunk));
			fc = g_malloc0(sizeof(*fc));
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
			version, trailer.length, fi_tmp);

	return fi;

bailout:

	g_warning("file_info_retrieve_binary(): %s", reason);

eof:
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
		struct stat st;

		g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);
		if (-1 == stat(fi_tmp, &st)) {
			g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", move_file_path,
				fi->file_name);
			if (-1 == stat(fi_tmp, &st)) {
				/* Reference count is zero, and file does not exist. Skip it? */
				return;
			}
		}
	}
	
	fprintf(f, "# refcount %u\n", fi->refcount);
	fprintf(f, "NAME %s\n", fi->file_name);
	fprintf(f, "PATH %s\n", fi->path);
	fprintf(f, "GENR %u\n", fi->generation);
	for (a = fi->alias; a; a = a->next)
		fprintf(f, "ALIA %s\n", (gchar *)a->data);
	fprintf(f, "SHA1 %s\n", fi->sha1 ? sha1_base32(fi->sha1) : "");
	fprintf(f, "SIZE %u\n", fi->size);
	fprintf(f, "DONE %u\n", fi->done);
	fprintf(f, "TIME %lu\n", fi->stamp);
	fprintf(f, "SWRM %u\n", fi->use_swarming);
  
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
	gchar *file;
	FILE *f;
	time_t now = time((time_t *)NULL);

	file = g_strdup_printf("%s/%s", config_dir, file_info_file);
	f = fopen(file, "w");
	if (!f) {
		g_warning("file_info_store(): "
			"unable to open file \"%s\" for writing: %s",
			file, g_strerror(errno));
		g_free(file);
		return;
	}

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n#\n", f);
	fprintf(f, "# Saved on %s\n", ctime(&now));
	fputs("# Format is:\n", f);
	fputs("#	NAME <file name>\n", f);
	fputs("#	PATH <path>\n", f);
	fputs("#	GENR <generation number>\n", f);
	fputs("#	ALIA <alias file name>\n", f);
	fputs("#	SIZE <size>\n", f);
	fputs("#	SHA1 <sha1>\n", f);
	fputs("#	DONE <bytes done>\n", f);
	fputs("#	TIME <last update stamp>\n", f);
	fputs("#	SWRM <boolean; use_swarming>\n", f);
	fputs("#	<blank line>\n", f);
	fputs("#\n\n", f);

	g_hash_table_foreach(fi_by_size, file_info_store_list, f);

	fclose(f);
	g_free(file);

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
	guchar *sha1 = (guchar *) key;
	struct dl_file_info *fi = (struct dl_file_info *) val;

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
static void file_info_free_outname_kv(gpointer key, gpointer val, gpointer x)
{
	gchar *name = (gchar *) key;
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

	fi->hashed = FALSE;			/* Since we're clearing them! */
	fi_free(fi);
}

/*
 * file_info_close
 *
 * Close and free all file_info structs in the list.
 */
void file_info_close(void)
{
	/*
	 * Freeing callbacks expect that the freeing of the `fi_by_outname'
	 * table will free the referenced `fi' (since that table MUST contain
	 * all the known `fi' structs by definition).
	 */

	g_hash_table_foreach(fi_by_sha1, file_info_free_sha1_kv, NULL);
	g_hash_table_foreach(fi_by_namesize, file_info_free_namesize_kv, NULL);
	g_hash_table_foreach(fi_by_size, file_info_free_size_kv, NULL);
	g_hash_table_foreach(fi_by_outname, file_info_free_outname_kv, NULL);

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
}

/*
 * file_info_hash_remove
 *
 * Remove fileinfo data from all the hash tables.
 */
static void file_info_hash_remove(struct dl_file_info *fi)
{
	namesize_t nsk;
	namesize_t *ns;
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
		nsk.name = l->data;

		found = g_hash_table_lookup_extended(fi_by_namesize, &nsk,
			(gpointer *) &ns, &x);

		g_assert(found);
		g_assert(x == (gpointer) fi);
		g_assert(ns->size == fi->size);

		g_hash_table_remove(fi_by_namesize, ns);
		namesize_free(ns);
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
	g_assert(from->done == 0);
	g_assert(0 != strcmp(from->file_name, to->file_name));

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", from->path, from->file_name);

	if (-1 == unlink(fi_tmp))
		g_warning("cannot unlink \"%s\": %s", fi_tmp, g_strerror(errno));

	download_info_change_all(from, to);
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
gboolean file_info_got_sha1(struct dl_file_info *fi, guchar *sha1)
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
		file_info_reparent_all(xfi, fi);	/* All `xfi' replaced by `fi' */
	} else {
		g_assert(fi->done == 0);
		file_info_reparent_all(fi, xfi);	/* All `fi' replaced by `xfi' */
	}

	return TRUE;
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
	gchar filename[1024];
	struct stat buf;
	gboolean empty = TRUE;
	GSList *aliases = NULL;

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

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", config_dir, file_info_file);

	f = fopen(fi_tmp, "r");

	g_snprintf(filename, sizeof(filename), "%s/%s.orig",
		config_dir, file_info_file);

	if (f) {
		if (rename(fi_tmp, filename) == -1)
			g_warning("could not rename %s as %s: %s",
				fi_tmp, filename, g_strerror(errno));
	} else {
		const gchar *error = g_strerror(errno);
		gchar *instead = " instead";

		if (-1 == stat(fi_tmp, &buf))
			instead = "";
		else
			g_warning("unable to open \"%s\" to retrieve file info: %s",
				fi_tmp, error);

		f = fopen(filename, "r");
		if (!f)
			return;

		g_warning("retrieving file info from \"%s\"%s", filename, instead);
	}

	while (fgets(line, sizeof(line), f)) {
		if (*line == '#') continue;

		while (*line && line[strlen(line)-1] <= ' ')
			line[strlen(line)-1] = '\0';

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
			 * infrequently and the file's trailer can have more uptodate
			 * information.
			 */

			dfi = file_info_retrieve_binary(fi->file_name, fi->path);

			if (dfi == NULL) {
				g_snprintf(fi_tmp, sizeof(fi_tmp),
					"%s/%s", fi->path, fi->file_name);
				if (-1 != stat(fi_tmp, &buf))
					g_warning("got metainfo in fileinfo cache, "
						"but none in \"%s/%s\"", fi->path, fi->file_name);
			} else if (dfi->generation > fi->generation) {
				g_warning("found more recent metainfo in \"%s/%s\"",
					fi->path, fi->file_name);
				fi_free(fi);
				fi = dfi;
			} else if (dfi->generation < fi->generation) {
				g_warning("found OUTDATED metainfo in \"%s/%s\"",
					fi->path, fi->file_name);
				fi_free(dfi);
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

			for (l = aliases; l; l = l->next) {
				fi_alias(fi, (gchar *) l->data, TRUE);
				atom_str_free((gchar *) l->data);
			}
			g_slist_free(aliases);

			empty = FALSE;
			fi = NULL;

			continue;

		discard:
			for (l = aliases; l; l = l->next)
				atom_str_free((gchar *) l->data);
			fi_free(fi);
			fi = NULL;
			continue;
		}

		if (!fi) {
			fi = g_malloc0(sizeof(struct dl_file_info));
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
		else if (!strncmp(line, "SHA1 ", 5)) {
			guchar sha1_digest[SHA1_RAW_SIZE];

			if (
				line[5] && base32_decode_into(line + 5, SHA1_BASE32_SIZE,
					sha1_digest, sizeof(sha1_digest))
			)
				fi->sha1 = atom_sha1_get(sha1_digest);
		}
		else if (!strncmp(line, "CHNK ", 5)) {
			if (sscanf(line + 5, "%u %u %u", &from, &to, &status)) {
				fc = g_malloc0(sizeof(struct dl_file_chunk));
				fc->from = from;
				fc->to = to;
				if (status == DL_CHUNK_BUSY) status = DL_CHUNK_EMPTY;
				fc->status = status;
				fi->chunklist = g_slist_append(fi->chunklist, fc);
			}
		}
	}

	if (fi) {
		fi_free(fi);
		if (!empty)
			g_warning("file info repository was truncated!");
	}

	fclose(f);
	file_info_store();
}

/*
 * escape_filename
 *
 * Lazily replace all '/' if filename with '_': if a substitution needs to
 * be done, a copy of the original argument is made first.	Otherwise,
 * no change nor allocation occur.
 *
 * Returns the pointer to the escaped filename, or the original argument if
 * no escaping needed to be performed.
 */
static gchar *escape_filename(gchar *file)
{
	gchar *escaped = NULL;
	gchar *s;
	gchar c;

	s = file;
	while ((c = *s)) {
		if (c == '/') {
			if (escaped == NULL) {
				escaped = g_strdup(file);
				s = escaped + (s - file);	/* s now refers to escaped string */
				g_assert(*s == '/');
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
static guchar *file_info_new_outname(guchar *name)
{
	gint i;
	guchar xuid[16];
	gint flen;
	guchar *escaped = escape_filename(name);
	guchar *result;

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

	flen = g_snprintf(fi_tmp, sizeof(fi_tmp), "%s", escaped);

	for (i = 1; i < 100; i++) {
		g_snprintf(&fi_tmp[flen], sizeof(fi_tmp)-flen, ".%02d", i);
		if (NULL == g_hash_table_lookup(fi_by_outname, fi_tmp)) {
			result = atom_str_get(fi_tmp);
			goto ok;
		}
	}

	/*
	 * No luck, allocate random GUID and append it.
	 */

	guid_random_fill(xuid);

	g_snprintf(&fi_tmp[flen], sizeof(fi_tmp)-flen, "-%s", guid_hex_str(xuid));
	if (NULL == g_hash_table_lookup(fi_by_outname, fi_tmp)) {
		result = atom_str_get(fi_tmp);
		goto ok;
	}

	g_error("no luck with random number generator");	/* Should NOT happen */
	return NULL;

ok:
	if (escaped != name)
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
	gchar *file, gchar *path, guint32 size, guchar *sha1)
{
	struct dl_file_info *fi;
	struct dl_file_chunk *fc;
	struct stat st;

	fi = g_malloc0(sizeof(struct dl_file_info));
	fi->file_name = file_info_new_outname(file);	/* Get unique file name */
	fi->path = atom_str_get(path);
	if (sha1)
		fi->sha1 = atom_sha1_get(sha1);
	fi->size = 0;							/* Will be updated below */
	fi->done = 0;
	fi->use_swarming = use_swarming;

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);

	if (stat(fi_tmp, &st) != -1) {
		g_warning("file_info_get(): "
			"assuming file \"%s\" is complete up to %lu bytes",
			fi->file_name, (gulong) st.st_size);
		fc = g_malloc0(sizeof(struct dl_file_chunk));
		fc->from = 0;
		fi->size = fc->to = st.st_size;
		fc->status = DL_CHUNK_DONE;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
		fi->dirty = TRUE;
	} 

	fi->size_atom = atom_int_get(&fi->size);	/* Set now, for fi_resize() */

	if (size > fi->size)
		fi_resize(fi, size);

	return fi;
}

/*
 * file_info_recreate
 *
 * Existing fileinfo structure is obsolete. Recreate it from existing
 * file with no swarming info (i.e. a file with no free holes over its
 * completed range so far).
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
		gchar *alias = (gchar *) l->data;
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
	new_fi->refcount++;
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
	gchar *file, gchar *path, guint32 size, gchar *sha1)
{
	struct dl_file_info *fi;
	guchar *outname;

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
			guchar dead[1024];

			g_warning("found DEAD file \"%s\" bearing SHA1 %s",
				outname, sha1_base32(fi->sha1));

			g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", path, outname);
			g_snprintf(dead, sizeof(dead), "%s/%s.DEAD", path, outname);

			if (-1 == rename(fi_tmp, dead))
				g_warning("cannot rename \"%s\" as \"%s\": %s",
					fi_tmp, dead, g_strerror(errno));

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

	return fi;
}

/*
 * file_info_has_identical
 *
 * Returns a pointer to the file info struct if we have a file
 * identical to the given properties in the download queue already,
 * and NULL otherwise.
 */
static struct dl_file_info *file_info_has_identical(
	gchar *file, guint32 size, gchar *sha1, GSList *sizelist)
{
	GSList *p;
	struct dl_file_info *fi;
	namesize_t nsk;

	if (strict_sha1_matching) {
		if (!sha1)
			return NULL;
		return file_info_lookup(file, size, sha1);
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

		if (fi->refcount == 0)			/* No longer used by any download */
			continue;

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
 * file_info_check_results_set
 *
 * Check a results_set for matching entries in the download queue,
 * and generate new entries if we find a match.
 */
void file_info_check_results_set(gnet_results_set_t *rs)
{
	GSList *l;
	GSList *list;
	struct dl_file_info *fi;

	for (l = rs->records; l; l = l->next) {
		gnet_record_t *rc = (gnet_record_t *) l->data;

		list = g_hash_table_lookup(fi_by_size, &rc->size);
		if (list == NULL)
			continue;

		fi = file_info_has_identical(rc->name, rc->size, rc->sha1, list);

		if (fi) {
			gboolean need_push = (rs->status & ST_FIREWALL) ||
				!check_valid_host(rs->ip, rs->port);
			download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					rs->guid, rc->sha1, rs->stamp, need_push, fi);
            set_flags(rc->flags, SR_DOWNLOADED);
		}
	}
}

/*
 * file_info_free
 *
 * Free fileinfo, removing one reference.
 * When nobody references the fileinfo structure, discard it.
 */
void file_info_free(struct dl_file_info *fi)
{
	g_assert(fi->refcount > 0);
	g_assert(fi->hashed);

	if (fi->refcount-- == 1) {
		file_info_hash_remove(fi);
		fi_free(fi);
	}
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
				g_free(fc2);
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

	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);

	fi->stamp = time((time_t *)NULL);

	if (status == DL_CHUNK_DONE)
		fi->dirty = TRUE;

again:

	/* I think the algorithm is safe now, but hey... */
	if (++againcount > 10) {
		g_warning("Eek! Internal error! "
			"file_info_update() is looping! Man battle stations!");
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
			fc->download = d;
			found = TRUE;
			break;

		} else if ((fc->from == from) && (fc->to < to)) {

			fc->status = status;
			fc->download = d;
			from = fc->to;
			goto again;

		} else if ((fc->from == from) && (fc->to > to)) {

			nfc = g_malloc(sizeof(struct dl_file_chunk));
			nfc->from = to;
			nfc->to = fc->to;
			nfc->status = fc->status;
			nfc->download = fc->download;
			fc->to = to;
			fc->status = status;
			fc->download = d;
			g_slist_insert(fi->chunklist, nfc, n+1);
			found = TRUE;
			break;

		} else if ((fc->from < from) && (fc->to >= to)) {

			nfc = g_malloc(sizeof(struct dl_file_chunk));
			nfc->from = from;
			nfc->to = to;
			nfc->status = status;
			nfc->download = d;
			g_slist_insert(fi->chunklist, nfc, n+1);

			if (fc->to > to) {
				nfc = g_malloc(sizeof(struct dl_file_chunk));
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

			nfc = g_malloc(sizeof(struct dl_file_chunk));
			nfc->from = from;
			nfc->to = fc->to;
			nfc->status = status;
			nfc->download = d;
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

	file_info_merge_adjacent(fi);		/* Also updates fi->done */

	/*
	 * When status is DL_CHUNK_DONE, we're coming from an "active" download,
	 * i.e. we are writing to it, therefore we can reuse its file descriptor.
	 */

	if (status == DL_CHUNK_DONE)
		file_info_fd_store_binary(d->file_info, d->file_desc, FALSE);
	else
		file_info_store_binary(d->file_info);
}

/*
 * file_info_clear_download
 *
 * Go through all chunks that belong to the download,
 * and unmark them as busy.
 */
void file_info_clear_download(struct download *d)
{
	GSList *fclist;
	struct dl_file_chunk *fc;

	fclist = d->file_info->chunklist;

	for (fclist = d->file_info->chunklist; fclist; fclist = fclist->next) {
		fc = fclist->data;
		if (fc->download == d) {
			if (fc->status == DL_CHUNK_BUSY)
				fc->status = DL_CHUNK_EMPTY;
			fc->download = NULL;
		}
	}
	file_info_merge_adjacent(d->file_info);

	/* No need to flush data to disk, those are transient changes */
}

/*
 * file_info_reset
 *
 * Reset all chunks to EMPTY.
 */
static void file_info_reset(struct dl_file_info *fi)
{
	GSList *l;
	struct dl_file_chunk *fc;

	for (l = fi->chunklist; l; l = g_slist_next(l)) {
		fc = (struct dl_file_chunk *) l->data;
		fc->status = DL_CHUNK_EMPTY;
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

	file_info_merge_adjacent(fi);
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
	struct stat buf;
	guint busy = 0;

	g_assert(fi->refcount > 0);
	g_assert(fi->lifecount > 0);

	/*
	 * This routine is called each time we start a new download, before
	 * making the request to the remote server. If we detect that the
	 * file is "gone", then it means the user manually deleted the file.
	 * In that case, we need to reset all the chunks and mark the whole
	 * thing as being EMPTY.
	 *		--RAM, 21/08/2002.
	 */

	if (fi->done) {
		if (fi->done == fi->size)
			return DL_CHUNK_DONE;

		/*
		 * File should exist since fi->done > 0, and it was not completed.
		 */

		g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);

		if (-1 == stat(fi_tmp, &buf)) {
			g_warning("file %s removed, resetting swarming", fi_tmp);
			file_info_reset(fi);
		}
	}

	/*
	 * XXX Mirar reported that this assert sometimes fails.  Too close to
	 * XXX the release, and it's not something worth panicing.
	 * XXX This happens after "Requeued by file info change".
	 * XXX Replacing with a warning for now.
	 * XXX		--RAM, 17/10/2002
	 */

	//g_assert(fi->size >= d->file_size);

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
				busy++;		/* Will be used by aggressive code below */
			continue;
		}

		*from = fc->from;
		*to = fc->to;
		//if (*from && ((*to - *from) > (chunksize * 2)))
		//	*from = (*from + *to) / 2;
		if ((*to - *from) > chunksize)
			*to = *from + chunksize;

		file_info_update(d, *from, *to, DL_CHUNK_BUSY);
		return DL_CHUNK_EMPTY;
	}

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

		g_assert(fi->lifecount > busy);		/* Or we'd found a chunk before */

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
 * file_info_active
 *
 * Return a dl_file_info if there's an active one with the same sha1.
 */
static struct dl_file_info *file_info_active(guchar *sha1)
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
	gchar *file_name, guint32 idx, guint32 ip, guint32 port, guchar *sha1)
{
	static guchar blank_guid[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	struct dl_file_info *fi;

	if (!can_swarm)				/* Downloads not initialized yet */
		return;

	fi = file_info_active(sha1);
	if (!fi)
		return;

	download_auto_new(
		file_name, fi->size, idx, ip, port, blank_guid, sha1,
		time(NULL), FALSE, fi);
}

