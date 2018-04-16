/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Input stream.
 *
 * An input stream has a stream-like interface: it can be opened, read from
 * and closed, but it is not seekable.  It also allows to "unread" a limited
 * amount of characters, which makes look-ahead parsers easier to write.
 *
 * It is a uniform input layer that can be tied to a file, a file descriptor
 * or even memory.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "istream.h"

#include "fd.h"
#include "halloc.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"	/* Must be the last header included */

#define ISTREAM_LOOKAHEAD	4	/**< How many characters we may look ahead */

/**
 * Input stream types.
 */
enum istream_type {
	ISTREAM_T_BSTR,			/**< Binary stream */
	ISTREAM_T_PMSG,			/**< PDU message stream */
	ISTREAM_T_FILE,			/**< FILE stream */
	ISTREAM_T_FD,			/**< File descriptor stream */
	ISTREAM_T_MAX
};

enum istream_magic { ISTREAM_MAGIC = 0x26d318dd };

/**
 * An iutput stream descriptor.
 */
struct istream {
	enum istream_magic magic;
	enum istream_type type;

	union {
		bstr_t *bs;			/**< bstr_read() */
		pmsg_t *mb;			/**< pmsg_read() */
		int fd;				/**< read() */
		FILE *f;			/**< fread() */
	} u;

	char unread[ISTREAM_LOOKAHEAD];		/**< Unread characters */
	uint unread_offset;					/**< Current offset in unread[] */
	size_t bytes_read;					/**< Amount of bytes read */

	unsigned ioerr:1;		/**< Set on I/O error */
};

static inline void
istream_check(const struct istream * const is)
{
	g_assert(is != NULL);
	g_assert(ISTREAM_MAGIC == is->magic);
}

/**
 * Allocate input stream descriptor of the specified type.
 */
static istream_t *
istream_alloc(enum istream_type type)
{
	istream_t *is;

	STATIC_ASSERT(ISTREAM_LOOKAHEAD <= MAX_INT_VAL(uint));

	WALLOC0(is);
	is->magic = ISTREAM_MAGIC;
	is->type = type;

	return is;
}

/**
 * Free input stream.
 */
static void
istream_free(istream_t *is)
{
	istream_check(is);

	switch (is->type) {
	case ISTREAM_T_BSTR:
	case ISTREAM_T_PMSG:
	case ISTREAM_T_FD:
	case ISTREAM_T_FILE:
		break;
	case ISTREAM_T_MAX:
		g_assert_not_reached();
	}

	is->magic = 0;
	WFREE(is);
}

/**
 * @return amount of characters read so far from stream.
 */
size_t
istream_bytes_read(const istream_t *is)
{
	istream_check(is);

	return is->bytes_read;
}

/**
 * Is stream opened with a file / file descriptor?
 */
bool
istream_is_file(const istream_t *is)
{
	istream_check(is);

	return ISTREAM_T_FILE == is->type || ISTREAM_T_FD == is->type;
}

/**
 * Is stream opened to memory?
 */
bool
istream_is_memory(const istream_t *is)
{
	istream_check(is);

	return ISTREAM_T_BSTR == is->type || ISTREAM_T_PMSG == is->type;
}

/**
 * Open stream from binary stream object.
 *
 * Stream must be closed with istream_close().
 */
istream_t *
istream_open_bstr(bstr_t *bs)
{
	istream_t *is;

	g_assert(!bstr_has_error(bs));	/* Validates bs as a side effect */

	is = istream_alloc(ISTREAM_T_BSTR);
	is->u.bs = bs;

	return is;
}

/**
 * Open stream from PDU message buffer.
 *
 * Stream must be closed with istream_close().
 */
istream_t *
istream_open_pmsg(pmsg_t *mb)
{
	istream_t *is;

	pmsg_check(mb);

	is = istream_alloc(ISTREAM_T_PMSG);
	is->u.mb = mb;

	return is;
}

/**
 * Open stream to specified file descriptor.
 */
istream_t *
istream_open_fd(int fd)
{
	istream_t *is;

	g_assert(is_valid_fd(fd));

	is = istream_alloc(ISTREAM_T_FD);
	is->u.fd = fd;

	return is;
}

/**
 * Open stream to specified FILE.
 */
istream_t *
istream_open_file(FILE *f)
{
	istream_t *is;

	g_assert(f != NULL);

	is = istream_alloc(ISTREAM_T_FILE);
	is->u.f = f;

	return is;
}

/**
 * Was an I/O error reported?
 */
bool
istream_has_ioerr(const istream_t *is)
{
	istream_check(is);

	return is->ioerr;
}

/**
 * Close stream opened to a file, along with the underlying FILE / fd.
 *
 * @return 0 on success, -1 on error.
 */
int
istream_close_file(istream_t *is)
{
	int ret = -1;

	g_assert(istream_is_file(is));

	switch (is->type) {
	case ISTREAM_T_FILE:
		ret = fclose(is->u.f);
		is->u.f = NULL;
		break;
	case ISTREAM_T_FD:
		ret = fd_close(&is->u.fd);
		break;
	case ISTREAM_T_BSTR:
	case ISTREAM_T_PMSG:
	case ISTREAM_T_MAX:
		g_assert_not_reached();
	}

	istream_free(is);
	return ret;
}

/**
 * Close stream, releasing memory.
 *
 * @return TRUE if OK, FALSE if there was a writing problem
 */
bool
istream_close(istream_t *is)
{
	bool ioerr;

	istream_check(is);

	ioerr = is->ioerr;
	istream_free(is);

	return !ioerr;
}

/**
 * Read data from stream.
 *
 * @param is		the input stream
 * @param data		start of buffer to put read data into
 * @param len		length of data buffer
 *
 * @return size of data read, -1 on error.
 */
ssize_t
istream_read(istream_t *is, void *data, size_t len)
{
	ssize_t r = 0;
	size_t toread = len;
	char *buf = data;

	istream_check(is);
	len = MIN(len, MAX_INT_VAL(ssize_t));

	/**
	 * First handle any unread characters we have, in a LIFO manner.
	 */

	if G_UNLIKELY(is->unread_offset != 0) {
		while (is->unread_offset != 0 && toread != 0) {
			*buf++ = is->unread[--(is->unread_offset)];
			toread--;
		}
		if (0 == toread)
			goto done;
	}

	switch (is->type) {
	case ISTREAM_T_FILE:
		{
			size_t n = fread(buf, toread, 1, is->u.f);
			r = (0 == n) ? -1 : (ssize_t) toread;
		}
		break;
	case ISTREAM_T_FD:
		r = read(is->u.fd, buf, toread);
		break;
	case ISTREAM_T_BSTR:
		{
			bool ok;
		   
			if (1 == toread)
				ok = bstr_read_u8(is->u.bs, (uint8 *) buf);	/* More efficient */
			else
				ok = bstr_read(is->u.bs, buf, toread);

			if (ok)
				r = toread;
			else
				r = -1;
		}
		break;
	case ISTREAM_T_PMSG:
		r = pmsg_read(is->u.mb, buf, toread);
		if (0 != toread && 0 == r)
			r = -1;		/* Reached end of message */
		break;
	case ISTREAM_T_MAX:
		g_assert_not_reached();
	}

	if G_UNLIKELY(-1 == r) {
		is->ioerr = TRUE;
		is->bytes_read += ptr_diff(buf, data);
		return -1;
	}

	/* FALL THROUGH */

done:
	is->bytes_read += r + ptr_diff(buf, data);

	return r + ptr_diff(buf, data);		/* Includes bytes read from unread[] */
}

/**
 * Read a single byte from the stream.
 *
 * @return the byte read, -1 on error.
 */
int
istream_getc(istream_t *is)
{
	uint8 c;

	istream_check(is);

	if G_UNLIKELY(istream_read(is, VARLEN(c)) <= 0)
		return -1;

	return c;
}

/**
 * Un-read a single byte.
 *
 * The unread byte is not given back to the source from which we are getting
 * data but is buffered locally and will be served back the next time we attempt
 * to read from the stream.
 *
 * Characters will be read back in a LIFO manner, so they must be unread
 * in the reverse order that they were read: most recently read first, then
 * previously read, etc..
 *
 * @param is	the input stream
 * @param c		the character we wish to unread (can be -1 for EOF)
 */
void
istream_ungetc(istream_t *is, int c)
{
	istream_check(is);
	g_assert(size_is_non_negative(is->unread_offset));
	g_assert(is->unread_offset < N_ITEMS(is->unread));

	/*
	 * We do not "unread" an EOF condition.  After hitting EOF, any further
	 * reading will return EOF anyway.
	 */

	if G_LIKELY(-1 != c) {
		g_assert(c <= 255);
		g_assert(is->bytes_read != 0);
		is->unread[is->unread_offset++] = c;
		is->bytes_read--;
	}
}

/* vi: set ts=4 sw=4 cindent: */
