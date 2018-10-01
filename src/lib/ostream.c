/*
 * Copyright (c) 2010, 2018 Raphael Manfredi
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
 * Output stream.
 *
 * An output stream has a stream-like interface: it can be opened, written
 * to, and closed, but it is not seekable.
 *
 * It is a uniform output layer that can be tied to a file, a file descriptor
 * or even memory.
 *
 * @author Raphael Manfredi
 * @date 2010, 2018
 */

#include "common.h"

#include "ostream.h"
#include "fd.h"
#include "halloc.h"
#include "hstrfn.h"
#include "pmsg.h"
#include "slist.h"
#include "str.h"
#include "walloc.h"

#include "override.h"	/* Must be the last header included */

/**
 * Output stream types.
 */
enum ostream_type {
	OSTREAM_T_MEM = 0,		/**< Memory stream */
	OSTREAM_T_PMSG,			/**< PDU message stream */
	OSTREAM_T_FILE,			/**< FILE stream */
	OSTREAM_T_FD,			/**< File descriptor stream */
	OSTREAM_T_STR,			/**< String stream */
	OSTREAM_T_MAX
};

enum ostream_magic { OSTREAM_MAGIC = 0x4eafc839 };

/**
 * An output stream descriptor.
 */
struct ostream {
	enum ostream_magic magic;
	enum ostream_type type;
	union {
		slist_t *sl;		/**< pmsg_slist_append() */
		pmsg_t *mb;			/**< pmsg_write() */
		int fd;				/**< write() */
		FILE *f;			/**< fwrite() */
		str_t *s;			/**< str_cat() */
	} u;
	unsigned ioerr:1;		/**< Set on I/O error */
};

static inline void
ostream_check(const struct ostream * const os)
{
	g_assert(os != NULL);
	g_assert(OSTREAM_MAGIC == os->magic);
}

/**
 * Allocate output stream descriptor of the specified type.
 */
static ostream_t *
ostream_alloc(enum ostream_type type)
{
	ostream_t *os;

	WALLOC0(os);
	os->magic = OSTREAM_MAGIC;
	os->type = type;

	return os;
}

/**
 * Free output stream.
 */
static void
ostream_free(ostream_t *os)
{
	ostream_check(os);

	switch (os->type) {
	case OSTREAM_T_MEM:
		pmsg_slist_free(&os->u.sl);
		break;
	case OSTREAM_T_PMSG:
	case OSTREAM_T_FD:
	case OSTREAM_T_FILE:
	case OSTREAM_T_STR:
		break;
	case OSTREAM_T_MAX:
		g_assert_not_reached();
	}

	os->magic = 0;
	WFREE(os);
}

/**
 * Is stream opened to a file / file descriptor?
 */
bool
ostream_is_file(const ostream_t *os)
{
	ostream_check(os);

	return OSTREAM_T_FILE == os->type || OSTREAM_T_FD == os->type;
}

/**
 * Is stream opened to memory?
 */
bool
ostream_is_memory(const ostream_t *os)
{
	ostream_check(os);

	return
		OSTREAM_T_MEM == os->type || OSTREAM_T_PMSG == os->type ||
		OSTREAM_T_STR == os->type;
}

/**
 * Open stream as memory.
 *
 * Stream must be closed with ostream_close_memory() to get back the list
 * of memory buffers.
 */
ostream_t *
ostream_open_memory(void)
{
	ostream_t *os;

	os = ostream_alloc(OSTREAM_T_MEM);
	os->u.sl = slist_new();

	return os;
}

/**
 * Close memory stream.
 *
 * @return the list of pmsg_t elements.  It can be written to a non-blocking
 * file descriptor through successive calls to pmsg_slist_to_iovec() to build
 * an I/O vector and pmsg_slist_discard() to remove from the list what was
 * written.
 */
slist_t *
ostream_close_memory(ostream_t *os)
{
	slist_t *result;

	ostream_check(os);
	g_assert(OSTREAM_T_MEM == os->type);

	result = os->u.sl;
	os->u.sl = NULL;
	ostream_free(os);

	return result;
}

/**
 * Open stream to PDU message buffer.
 *
 * Stream must be closed with ostream_close().
 */
ostream_t *
ostream_open_pmsg(pmsg_t *mb)
{
	ostream_t *os;

	g_assert(mb != NULL);
	g_assert(pmsg_is_writable(mb));

	os = ostream_alloc(OSTREAM_T_PMSG);
	os->u.mb = mb;

	return os;
}

/**
 * Open stream to string.
 *
 * Stream must be closed with ostream_close().
 */
ostream_t *
ostream_open_str(str_t *s)
{
	ostream_t *os;

	str_check(s);

	os = ostream_alloc(OSTREAM_T_STR);
	os->u.s = s;

	return os;
}

/**
 * Open stream to specified file descriptor.
 */
ostream_t *
ostream_open_fd(int fd)
{
	ostream_t *os;

	g_assert(is_valid_fd(fd));

	os = ostream_alloc(OSTREAM_T_FD);
	os->u.fd = fd;

	return os;
}

/**
 * Open stream to specified FILE.
 */
ostream_t *
ostream_open_file(FILE *f)
{
	ostream_t *os;

	g_assert(f != NULL);

	os = ostream_alloc(OSTREAM_T_FILE);
	os->u.f = f;

	return os;
}

/**
 * Was an I/O error reported?
 */
bool
ostream_has_ioerr(const ostream_t *os)
{
	ostream_check(os);

	return os->ioerr;
}

/**
 * Close stream opened to a file, along with the underlying FILE / fd.
 *
 * @return 0 on success, -1 on error.
 */
int
ostream_close_file(ostream_t *os)
{
	int ret = -1;

	g_assert(ostream_is_file(os));

	switch (os->type) {
	case OSTREAM_T_FILE:
		ret = fclose(os->u.f);
		os->u.f = NULL;
		break;
	case OSTREAM_T_FD:
		ret = fd_close(&os->u.fd);
		break;
	case OSTREAM_T_MEM:
	case OSTREAM_T_PMSG:
	case OSTREAM_T_STR:
	case OSTREAM_T_MAX:
		g_assert_not_reached();
	}

	ostream_free(os);
	return ret;
}

/**
 * Close stream, releasing memory.
 *
 * @return TRUE if OK, FALSE if there was a writing problem
 */
bool
ostream_close(ostream_t *os)
{
	bool ioerr;

	ostream_check(os);

	ioerr = os->ioerr;
	ostream_free(os);

	return !ioerr;
}

/**
 * Write data to stream.
 *
 * @param os		the output stream
 * @param data		start of data to write
 * @param len		length of data to write
 *
 * @return size of data written, -1 on error.
 */
ssize_t
ostream_write(ostream_t *os, const void *data, size_t len)
{
	ssize_t w = (ssize_t) -1;

	ostream_check(os);
	len = MIN(len, MAX_INT_VAL(ssize_t));

	switch (os->type) {
	case OSTREAM_T_FILE:
		{
			size_t n = fwrite(data, len, 1, os->u.f);
			w = (0 == n) ? -1 : (ssize_t) len;
		}
		break;
	case OSTREAM_T_FD:
		w = write(os->u.fd, data, len);
		break;
	case OSTREAM_T_MEM:
		pmsg_slist_append(os->u.sl, data, len);
		w = len;
		break;
	case OSTREAM_T_PMSG:
		w = pmsg_write(os->u.mb, data, len);
		w = (len == UNSIGNED(w)) ? w : -1;
		break;
	case OSTREAM_T_STR:
		str_cat_len(os->u.s, data, len);
		w = len;
		break;
	case OSTREAM_T_MAX:
		g_assert_not_reached();
	}

	if (-1 == w)
		os->ioerr = TRUE;

	return w;
}

/**
 * Format data to stream.
 *
 * @return the amount of bytes written, -1 on error.
 */
ssize_t
ostream_printf(ostream_t *os, const char *fmt, ...)
{
	va_list args, args2;
	char buf[1024];
	size_t len;
	char *data;
	ssize_t w;

	ostream_check(os);

	va_start(args, fmt);

	if (OSTREAM_T_STR == os->type) {
		/* Handled specially since way more efficient here */
		w = str_vcatf(os->u.s, fmt, args);
		goto done;
	}

	VA_COPY(args2, args);
	len = str_vbprintf(ARYLEN(buf), fmt, args2);
	va_end(args2);

	if (len >= sizeof buf - 1) {
		data = h_strdup_len_vprintf(fmt, args, &len);
	} else {
		data = buf;
	}

	w = ostream_write(os, data, len);

	if (data != buf)
		hfree(data);

	/* FALL THROUGH */
done:
	va_end(args);
	return w;
}

/**
 * Emit a single byte to the stream.
 *
 * @return the amount of bytes written, -1 on error.
 */
ssize_t
ostream_putc(ostream_t *os, int c)
{
	char buf[1];

	ostream_check(os);

	if (OSTREAM_T_STR == os->type) {
		/* Handled specially since more efficient here */
		str_putc(os->u.s, c);
		return 1;
	}

	buf[0] = c & 0xff;
	return ostream_write(os, ARYLEN(buf));
}

/**
 * Emit a NUL-terminated string to the stream.
 *
 * @return the amount of bytes written, -1 on error.
 */
ssize_t
ostream_puts(ostream_t *os, const char *s)
{
	ostream_check(os);

	return ostream_write(os, s, vstrlen(s));
}

/* vi: set ts=4 sw=4 cindent: */
