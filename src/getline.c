/*
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include <string.h>		/* For memmove() */
#include "getline.h"

/*
 * getline_make
 *
 * Create a new line reading object.
 */
getline_t *getline_make(void)
{
	return (getline_t *) g_malloc0(sizeof(getline_t));
}

/*
 * getline_free
 *
 * Destroy getline object.
 */
void getline_free(getline_t *o)
{
	g_assert(o);
	g_free(o);
}

/*
 * getline_reset
 *
 * Prepare getline object for a new read cycle by forgetting whatever it
 * currently holds.
 */
void getline_reset(getline_t *o)
{
	g_assert(o);
	o->pos = 0;
}

/*
 * getline_read
 *
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
gint getline_read(getline_t *o, guchar *data, gint len, gint *used)
{
	guchar c;
	gint orig_len = len;
	gint used_bytes;

	while (len-- > 0) {
		if (o->pos >= MAX_LINE_SIZE)
			return READ_OVERFLOW;
		c = *data++;
		o->line[o->pos++] = c;
		if (c == '\n') {
			/*
			 * Reached the end of the line.
			 */

			o->pos--;							/* We strip "\n" */
			if (o->pos > 0 && o->line[o->pos - 1] == '\r')
				o->pos--;						/* We strip "\r" */
			o->line[o->pos] = '\0';				/* NUL-terminate string */
			break;
		}
	}

	/*
	 * At this point, len is -1 if we used all the input without seeing the
	 * end of the line.
	 */

	used_bytes = (len >= 0) ? orig_len - len : orig_len;
	if (used)
		*used = used_bytes;

	return (len >= 0) ? READ_DONE : READ_MORE;
}

/*
 * getline_str
 *
 * Returns a C string (NUL-terminated) corresponding to the line we currently
 * have in the buffer.
 */
guchar *getline_str(getline_t *o)
{
	o->line[o->pos] = '\0';		/* Ensure it is NUL-terminated */
	return o->line;
}

/*
 * getline_length
 *
 * Return the length of the currently accumulated line.
 */
gint getline_length(getline_t *o)
{
	return o->pos;
}

/*
 * getline_copy
 *
 * Copy source into dest.
 */
void getline_copy(getline_t *source, getline_t *dest)
{
	memmove(dest->line, source->line, source->pos);
	dest->pos = source->pos;
}

