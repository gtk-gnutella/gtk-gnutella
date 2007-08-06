/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Line-oriented parsing from memory buffer.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#include "getline.h"
#include "walloc.h"
#include "misc.h"		/* For RCSID */
#include "override.h"	/* Must be the last header included */

/*
 * Those govern the allocation policy for the getline buffer.
 * We start at START_LENGTH, and we grow the buffer each time we need
 * more room by chunks of at least GROW_LENGTH.
 */
#define START_LENGTH 	512
#define GROW_LENGTH		1024

/**
 * Create a new line reading object, capable of holding a line of at most
 * `maxlen' bytes.
 */
getline_t *
getline_make(size_t maxlen)
{
	getline_t *o;

	g_assert(maxlen > 0);

	o = walloc0(sizeof *o);

	o->maxlen = maxlen;
	o->size = MIN(START_LENGTH, maxlen);
	o->line = g_malloc(o->size);

	return o;
}

void
getline_set_maxlen(getline_t *o, size_t maxlen)
{
	g_assert(o);
	o->maxlen = MAX(o->maxlen, maxlen);
}

/**
 * Destroy getline object.
 */
void
getline_free(getline_t *o)
{
	g_assert(o);
	g_assert(o->line);

	G_FREE_NULL(o->line);
	wfree(o, sizeof *o);
}

/**
 * Prepare getline object for a new read cycle by forgetting whatever it
 * currently holds.
 */
void
getline_reset(getline_t *o)
{
	g_assert(o);
	g_assert(o->line);

	o->pos = 0;
}

/**
 * Read line of a header from supplied buffer.
 *
 * We define a line as being something that ends with either "\r\n" or "\n".
 * Although in the Gnutella world, everything is specified to use "\r\n", we
 * must acknowledge the fact that we have to be liberal.  In the UNIX world,
 * lines end by "\n", and most Internet protocols (SMTP, NNTP, HTTP) allow
 * for both endings.
 *
 * We read from `data', at most `len' bytes.  If `used' is non-null, it is
 * filled with the amount of bytes we effectively used, unless an error occurs.
 * When READ_MORE is returned, it is guaranteed that used will be `len'.
 *
 * The trailing "\r\n" or "\n" is stripped from the accumulated line.
 */
getline_result_t
getline_read(getline_t *o, const gchar *data, size_t len, size_t *used)
{
	getline_result_t result = READ_MORE;
	size_t used_bytes, needed, missing;

	/*
	 * Make sure we have enough room to either grab all `len' bytes or
	 * read until we reach our configured limit.
	 */

	needed = o->maxlen - o->pos;
	missing = o->pos + MIN(len, needed) - o->size + 1;	/* Trailing NUL */

	if (missing > 0) {
		size_t new_size = o->size + MAX(missing, GROW_LENGTH);
		new_size = MIN(new_size, o->maxlen);

		g_assert(new_size <= INT_MAX);
		o->line = g_realloc(o->line, new_size);
		o->size = new_size;

		g_assert(o->size <= o->maxlen);
	}

	/*
	 * Read data until the end of the line.
	 */

	for (used_bytes = 0; used_bytes < len; /* NOTHING */) {
		gchar c;

		if (o->pos >= (o->size - 1))			/* Leave room for final NUL */
			return READ_OVERFLOW;
		c = data[used_bytes++];
		if (c == '\n') {
			/*
			 * Reached the end of the line.
			 */

			if (o->pos > 0 && o->line[o->pos - 1] == '\r')
				o->pos--;						/* We strip "\r" */
			o->line[o->pos] = '\0';				/* NUL-terminate string */
			result = READ_DONE;
			break;
		}
		o->line[o->pos++] = c;
	}

	/*
	 * At this point, len is -1 if we used all the input without seeing the
	 * end of the line.
	 */

	if (used)
		*used = used_bytes;

	return result;
}

/**
 * @return a C string (NUL-terminated) corresponding to the line we currently
 * have in the buffer.
 */
const gchar *
getline_str(getline_t *o)
{
	g_assert(o->pos < o->size);

	o->line[o->pos] = '\0';		/* Ensure it is NUL-terminated */
	return o->line;
}

/**
 * @return the length of the currently accumulated line.
 */
size_t
getline_length(getline_t *o)
{
	return o->pos;
}

/**
 * Copy source into dest.
 */
void
getline_copy(getline_t *source, getline_t *dest)
{
	g_assert(source);
	g_assert(dest);
	g_assert(source->pos < dest->maxlen);
	g_assert(source != dest);

	if (dest->size <= source->pos) {
		dest->size = source->pos + 1;		/* Trailing NUL */
		dest->line = g_realloc(dest->line, dest->size);
	}

	memmove(dest->line, source->line, source->pos);
	dest->pos = source->pos;

	g_assert(dest->pos < dest->size);
	g_assert(dest->size <= dest->maxlen);
}

/* vi: set ts=4: */
