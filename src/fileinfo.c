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
#include "misc.h"
#include "downloads_gui.h"
#include "sockets.h"
#include "downloads.h"
#include "hosts.h"
#include "getline.h"
#include "header.h"
#include "routing.h"
#include "url.h"
#include "routing.h"
#include "gmsg.h"
#include "bsched.h"
#include "regex.h"
#include "getdate.h"
#include "atoms.h"
#include "huge.h"
#include "base32.h"
#include "dmesh.h"
#include "http.h"
#include "version.h"
#include "fuzzy.h"

#include "gnet_property_priv.h"
#include "settings.h"
#include "nodes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>			/* For ctime() */
#include <netinet/in.h>		/* For ntohl() and friends... */

// XXX replace sl_file_info by a size-indexed hash, with linked items in values

static GSList *sl_file_info = NULL;
static gchar *file_info_file = "fileinfo";
static gboolean fileinfo_dirty = FALSE;

static gchar fi_tmp[4096];

#define FILE_INFO_MAGIC		0xD1BB1ED0
#define FILE_INFO_VERSION	2

enum dl_file_info_field {
	FILE_INFO_FIELD_NAME = 1,
	FILE_INFO_FIELD_ALIAS,
	FILE_INFO_FIELD_SHA1,
	FILE_INFO_FIELD_CHUNK,
	FILE_INFO_FIELD_END,
};

/*
 * The swarming trailer is built within a memory buffer first, to avoid having
 * to issue mutliple write() system calls.  We can't use stdio's buffering
 * since we can sometime reuse the download's file descriptor.
 */
static struct {
	gchar *arena;			/* Base arena */
	gchar *wptr;			/* Write pointer */
	gchar *rptr;			/* Read pointer */
	gchar *end;				/* First byte off arena */
	guint32 size;			/* Current size of arena */
} tbuf;

#define TBUF_SIZE			512			/* Initial trailing buffer size */
#define TBUF_GROW_BITS		9			/* Growing chunks */

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
	if (tbuf.rptr + sizeof(gint32) <= tbuf.end)	{ \
		if (int32_aligned(tbuf.rptr))	\
			*x = *(gint32 *) tbuf.rptr;	\
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

#define WRITE_INT32(a) do {				\
		gint32 val = htonl(a);			\
		TBUF_PUTINT32(val);				\
		file_info_checksum(&checksum, (guchar *) &val, sizeof(val)); \
} while(0)

#define WRITE_STR(a, b) do {			\
		TBUF_WRITE(a, b);				\
		file_info_checksum(&checksum, (guchar *) a, b); \
} while(0)

/*
 * High-level read macros.
 */

#define READ_INT32(a) do {				\
		gint32 val;						\
		TBUF_GETINT32(&val);			\
		*a = ntohl(val);				\
		file_info_checksum(&checksum, (guchar *) &val, sizeof(val)); \
} while(0)

#define READ_STR(a, b) do {				\
		TBUF_READ(a, b);				\
		file_info_checksum(&checksum, (guchar *) a, b); \
} while(0)

/*
 * Addition of a variable-size trailer field.
 */

#define FIELD_ADD(a,b,c) do {			\
		guint32 len = (b);				\
		WRITE_INT32(a);					\
		WRITE_INT32(len);				\
		WRITE_STR(c, len);				\
} while(0)


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
 */
static void file_info_fd_store_binary(struct dl_file_info *fi, int fd)
{
	GSList *fclist;
	GSList *a;
	struct dl_file_chunk *fc;
	guint32 checksum = 0;
	guint32 length;

	g_assert(fd >= 0);

	if (lseek(fd, fi->size, SEEK_SET) != fi->size) {
		g_warning("file_info_store_binary(): "
			"lseek() to offset %u in \"%s\" failed: %s",
			fi->size, fi->file_name, g_strerror(errno));
		return;
	}

	TBUF_INIT_WRITE();
	WRITE_INT32(FILE_INFO_VERSION);

	FIELD_ADD(FILE_INFO_FIELD_NAME, strlen(fi->file_name)+1, fi->file_name);

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

	file_info_fd_store_binary(fi, fd);
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
 * file_info_retrieve_binary
 *
 * Reads the file metainfo from the trailer of a file, if it exists.
 * Returns a pointer to the info structure if found, and NULL otherwise.
 */
static struct dl_file_info *file_info_retrieve_binary(gchar *file, gchar *path)
{
	guint32 tr[5];
	guint32 tmpchunk[3];
	guint32 tmpguint;
	guint32 checksum = 0;
	struct dl_file_info *fi = NULL;
	struct dl_file_chunk *fc;
	enum dl_file_info_field field;
	gchar tmp[1024];
	gchar *reason;
	int fd;
	struct stat buf;
	guint32 version;
	struct {
		guint32 filesize;
		guint32 generation;
		guint32 length;
		guint32 checksum;
		guint32 magic;
	} trailer;

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", path, file);
	
	fd = open(fi_tmp, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			g_warning("can't open \"%s\" for reading: %s",
				fi_tmp, g_strerror(errno));
		return NULL;
	}

	if (lseek(fd, -sizeof(tr), SEEK_END) == -1) {
		g_warning("file_info_retrieve_binary(): "
			"error seek()ing in file \"%s\": %s", fi_tmp, g_strerror(errno));
		goto eof;
	}

	if (-1 == read(fd, tr, sizeof(tr))) {
		g_warning("file_info_retrieve_binary(): "
			"error reading trailer in  \"%s\": %s", fi_tmp, g_strerror(errno));
		goto eof;
	}

	trailer.filesize	= ntohl(tr[0]);
	trailer.generation	= ntohl(tr[1]);
	trailer.length		= ntohl(tr[2]);
	trailer.checksum	= ntohl(tr[3]);
	trailer.magic		= ntohl(tr[4]);

	/*
	 * Now, sanity checks...  We must make sure this is a valid trailer.
	 */

	if (trailer.magic != FILE_INFO_MAGIC) {
		g_warning("file_info_retrieve_binary(): no magic found in \"%s\". "
			"Bailing out.", fi_tmp);
		goto eof;
	}

	if (-1 == fstat(fd, &buf)) {
		g_warning("error fstat()ing \"%s\": %s", fi_tmp, g_strerror(errno));
		goto eof;
	}

	if (buf.st_size != trailer.filesize + trailer.length) {
		g_warning("file_info_retrieve_binary(): "
			"trailer size mismatch in \"%s\". Bailing out.", fi_tmp);
		goto eof;
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
	fi->generation = trailer.generation;
	fi->use_swarming = 1;					/* Must assume swarming */
	fi->refcount = 0;
	
	for (;;) {
		tmpguint = FILE_INFO_FIELD_END;	/* in case read() fails. */
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
			/* Verify that the name is as expected, and warn if not. */
			if (strcmp(fi->file_name, tmp) != 0) {
				g_warning("file_info_retrieve_binary(): conflicting "
					"names in file info. preserving actual name.");
				g_warning("file_info_retrieve_binary(): name1 = %s",
					fi->file_name);
				g_warning("file_info_retrieve_binary(): name2 = %s", tmp);
				/* Add reported name as an alias instead. */
				fi->alias = g_slist_append(fi->alias, atom_str_get(tmp));
			}
			break;
		case FILE_INFO_FIELD_ALIAS:
			fi->alias = g_slist_append(fi->alias, atom_str_get(tmp));
			break;
		case FILE_INFO_FIELD_SHA1:
			fi->sha1 = atom_sha1_get(tmp);
			break;
		case FILE_INFO_FIELD_CHUNK:
			memcpy(tmpchunk, tmp, sizeof(tmpchunk));
			fc = g_malloc0(sizeof(*fc));
			/*
			 * In version 1, fields were written in native form.
			 * Starting at version 2, they are written in network order.
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

	if (!fi->keep && fi->refcount == 0) {
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
 * file_info_store
 *
 * Stores the list of output files and their metainfo to the
 * configdir/fileinfo database.
 */
void file_info_store(void)
{
	gchar *file;
	FILE *f;
	GSList *l;
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
	fputs("#	SWRM <boolean; use_swarming>\n", f);
	fputs("#	<blank line>\n", f);
	fputs("#\n\n", f);

	for (l = sl_file_info; l; l = l->next)
		file_info_store_one(f, (struct dl_file_info *) l->data);

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
 * file_info_close
 *
 * Close and free all file_info structs in the list.
 */
void file_info_close(void)
{
	GSList *l;

	file_info_store();

	for (l = sl_file_info; l; l = l->next) {
		struct dl_file_info *fi = (struct dl_file_info *) l->data;

		if (fi->refcount) 
			g_warning("file_info_close() refcount = %u", fi->refcount);

		fi_free(fi);
	}

	g_slist_free(sl_file_info);
	g_free(tbuf.arena);
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
			struct dl_file_info *dfi;

			/* 
			 * Check file trailer information.  The main file is only written
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
			}

			file_info_merge_adjacent(fi);
			sl_file_info = g_slist_append(sl_file_info, fi);
			fi = NULL;
		}

		if (!fi) {
			fi = g_malloc0(sizeof(struct dl_file_info));
			fi->refcount = 0;
		}

		if (!strncmp(line, "NAME ", 5))
			fi->file_name = atom_str_get(line + 5);
		else if (!strncmp(line, "PATH ", 5))
			fi->path = atom_str_get(line + 5);
		else if (!strncmp(line, "ALIA ", 5))
			fi->alias = g_slist_append(fi->alias, atom_str_get(line + 5));
		else if (!strncmp(line, "GENR ", 5))
			fi->generation = atoi(line + 5);
		else if (!strncmp(line, "SIZE ", 5))
			fi->size = atoi(line + 5);
		else if (!strncmp(line, "TIME ", 5))
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

	fclose(f);
	file_info_store();
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

	if (!strcasecmp(fi->file_name, file))
		return TRUE;

	for (a = fi->alias; a; a = a->next) {
		if (!strcasecmp((gchar *)a->data, file))
			return TRUE;
	}

	if (use_fuzzy_matching) {
		int score = 100 * fuzzy_compare(fi->file_name, file);
		if (score >= fuzzy_threshold) {
			g_warning("fuzzy: \"%s\"  ==  \"%s\" (score %f)",
				fi->file_name, file, score / 100.0);
			fi->alias = g_slist_append(fi->alias, atom_str_get(file));
			return TRUE;
		}
		for (a = fi->alias; a; a = a->next) {
			score = 100 * fuzzy_compare(a->data, file);
			if (score >= fuzzy_threshold) {
				g_warning("fuzzy: \"%s\"  ==  \"%s\" (score %f)",
					(gchar *) a->data, file, score / 100.0);
				fi->alias = g_slist_append(fi->alias, atom_str_get(file));
				return TRUE;
			}
		}
	}
	
	return FALSE;
}

/*
 * file_info_get
 *
 * Returns a pointer to file_info struct that matches the given file
 * name, size and/or SHA1. A new struct will be allocated if necessary.
 */ 
struct dl_file_info *file_info_get(
	gchar *file, gchar *path, guint32 size, gchar *sha1)
{
	GSList *p;
	struct dl_file_info *fi;
	struct dl_file_chunk *fc;
	struct stat st;
	guint32 pos = 0;

	/* See if we know anything about the file already. */
	for (p = sl_file_info; p; p = p->next) {

		fi = p->data;

		/*
		 * I'm not sure if size should be tested for here, since it's
		 * theorically possible to fetch from a partial file and use it to
		 * fill our gaps, but for now, require files to be of identical length.
		 */
		if (fi->size != size) continue;

		if (sha1 && fi->sha1) {

			if (memcmp(sha1, fi->sha1, SHA1_RAW_SIZE) == 0) {
				if (!file_info_has_filename(fi, file)) {
					fi->alias = g_slist_append(fi->alias, atom_str_get(file));
					fi->dirty = TRUE;
				}
				fi->refcount++;
				return fi;
			}
			
			/* In strick mode, we require the SHA1s to be identical. */
			if (strict_sha1_matching)
				continue;
		}

		if (file_info_has_filename(fi, file)) {
			/* Grab the sha1 if we don't have it. */
			if (sha1 && !fi->sha1) {
				fi->sha1 = atom_sha1_get(sha1);
				fi->dirty = TRUE;
			}
			fi->refcount++;
			return fi;
		}

	}

	/* Check if the file exists and has embedded meta info. */
	if ((fi = file_info_retrieve_binary(file, path)) != NULL) {
		g_warning("file_info_get(): "
			"successfully retrieved meta info from file \"%s\"", file);
		fi->refcount++;
		sl_file_info = g_slist_append(sl_file_info, fi);
		return fi;
	}

	/* New file; Allocate a new file structure */

	/*
	 * Potential problem situations:
	 *
	 *	- File exists, but we have no file_info struct for it.
	 * => Assume the file is complete up to filesize bytes.
	 *
	 *	- File with same name as another, but with a different size.
	 * => Use an alternative output name (fixme)
	 *
	 */
	
	fi = g_malloc0(sizeof(struct dl_file_info));
	fi->refcount = 1;
	fi->file_name = atom_str_get(file);
	fi->path = atom_str_get(path);
	if (sha1)
		fi->sha1 = atom_sha1_get(sha1);
	fi->size = size;
	fi->done = 0;
	fi->use_swarming = use_swarming;

	g_snprintf(fi_tmp, sizeof(fi_tmp), "%s/%s", fi->path, fi->file_name);

	if (stat(fi_tmp, &st) != -1) {
		g_warning("file_info_get(): "
			"assuming file \"%s\" is complete up to %lu bytes",
			fi->file_name, st.st_size);
		fc = g_malloc0(sizeof(struct dl_file_chunk));
		fc->from = 0;
		pos = fc->to = st.st_size;
		fc->status = DL_CHUNK_DONE;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
		fi->dirty = TRUE;
	} 

	if (size > pos) {	
		fc = g_malloc0(sizeof(struct dl_file_chunk));
		fc->from = pos;
		fc->to = size;
		fc->status = DL_CHUNK_EMPTY;
		fi->chunklist = g_slist_append(fi->chunklist, fc);
	}

	sl_file_info = g_slist_append(sl_file_info, fi);

	return fi;
}

/*
 * file_info_has_identical
 *
 * Returns TRUE if we have a file identical to the given properties
 * in the download queue already, and FALSE otherwise.
 */

static gboolean file_info_has_identical(gchar *file, guint32 size, gchar *sha1)
{
	GSList *p;
	struct dl_file_info *fi;
	gint incomplete;

	for (p = sl_file_info; p; p = p->next) {

		fi = p->data;

		if (fi->size != size) continue;

		/*
		 * No referencess means file isn't in queue anymore,
		 * and we won't start new ones from here.
		 */

		if (fi->refcount == 0) continue;

		/*
		 * Check whether file needs more data at all.
		 */

		incomplete = (fi->size != fi->done);

		if (sha1 && fi->sha1) {

			if (memcmp(sha1, fi->sha1, SHA1_RAW_SIZE) == 0)
				return incomplete;	

			/* In strict mode, we require the SHA1s to be identical. */
			if (strict_sha1_matching)
				continue;
		}

		if (file_info_has_filename(fi, file))
			return incomplete;
	}
	return FALSE;
}

/*
 * file_info_check_results_set
 *
 * Check a results_set for matching entries in the download queue,
 * and generate new entries if we find a match.
 */
void file_info_check_results_set(struct results_set *rs)
{
	GSList *l;

	for (l = rs->records; l; l = l->next) {
		struct record *rc = (struct record *) l->data;

		if (file_info_has_identical(rc->name, rc->size, rc->sha1)) {
			gboolean need_push = (rs->status & ST_FIREWALL) ||
				!check_valid_host(rs->ip, rs->port);
			download_auto_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
				rs->guid, rc->sha1, rs->stamp, need_push);
		}
	}
}

void file_info_free(struct dl_file_info *fi, gboolean keep)
{
	fi->refcount--;
	fi->keep = keep;
	return;
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

	file_info_merge_adjacent(fi);

	/*
	 * When status is DL_CHUNK_DONE, we're coming from an "active" download,
	 * i.e. we are writing to it, therefore we can reuse its file descriptor.
	 */

	if (status == DL_CHUNK_DONE)
		file_info_fd_store_binary(d->file_info, d->file_desc);
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
	file_info_store_binary(d->file_info);
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

	/* fixme: find a decent chunksize strategy */
	//chunksize = (d->file_info->size - d->file_info->done) /
	//		(d->file_info->refcount + 3);
	//chunksize = d->file_info->size / 3;
	chunksize = d->file_info->size / (d->file_info->refcount + 1);

	if (chunksize < dl_minchunksize) chunksize = dl_minchunksize;
	if (chunksize > dl_maxchunksize) chunksize = dl_maxchunksize;

	for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
		fc = fclist->data;

		if (fc->status != DL_CHUNK_EMPTY) continue;

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

		for (fclist = fi->chunklist; fclist; fclist = g_slist_next(fclist)) {
			fc = fclist->data;

			if (fc->status != DL_CHUNK_BUSY) continue;
			if ((fc->to - fc->from) < dl_minchunksize) continue;

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

