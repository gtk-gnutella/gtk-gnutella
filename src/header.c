/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Header parsing routines.
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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>		/* for atoi() */
#include <string.h>

#include "header.h"

RCSID("$Id$");

/***
 *** Operating flags
 ***/

#define HEAD_F_EOH		0x00000001			/* EOH reached */
#define HEAD_F_SKIP		0x00000002			/* Skip continuations */

/***
 *** Error code management
 ***/

static const char *error_str[] = {
	"OK",									/* HEAD_OK */
	"Unexpected continuation line",			/* HEAD_CONTINUATION */
	"Malformed header line",				/* HEAD_MALFORMED */
	"Invalid characters in field name",		/* HEAD_BAD_CHARS */
	"End of header already reached",		/* HEAD_EOH_REACHED */
	"Skipped continuation line",			/* HEAD_SKIPPED */
	"Header too large",						/* HEAD_TOO_LARGE */
	"Header has too many lines",			/* HEAD_MANY_LINES */
	"End of header",						/* HEAD_EOH */
};

/*
 * header_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
const gchar *header_strerror(guint errnum)
{
	if (errnum >= G_N_ELEMENTS(error_str))
		return "Invalid error code";

	return error_str[errnum];
}

/*
 * XXX share normalized header strings into hash table?
 */

/***
 *** Utilities
 ***/

/*
 * normalize
 *
 * In-place normalize the header field name: all letters starting a word
 * are upper-cased, the others are lowercased.
 */
static void normalize(gchar *field)
{
	gboolean start_word = TRUE;
	gchar *s;
	guchar c;
	
	for (s = field, c = *s; c; c = *(++s)) {
		if (start_word) {
			if (isalnum(c)) {
				start_word = FALSE;
				*s = toupper(c);
			}
		} else {
			if (isalnum(c))
				*s = tolower(c);
			else
				start_word = TRUE;
		}
	}
}

/***
 *** header_field object
 ***/

/*
 * hfield_make
 *
 * Create a new empty header field, whose normalized name is `name'.
 * A private copy of `name' is done.
 */
static header_field_t *hfield_make(const gchar *name)
{
	header_field_t *h;

	h = (header_field_t *) g_malloc0(sizeof(header_field_t));
	h->name = g_strdup(name);

	return h;
}

/*
 * hfield_free
 *
 * Dispose of the header field.
 */
static void hfield_free(header_field_t *h)
{
	GSList *l;

	for (l = h->lines; l; l = l->next)
		g_free(l->data);
	g_slist_free(h->lines);

	g_free(h->name);
	g_free(h);
}

/*
 * hfield_append
 *
 * Append line of text to given header field.
 * A private copy of the data is made.
 */
static void hfield_append(header_field_t *h, const gchar *text)
{
	h->lines = g_slist_append(h->lines, g_strdup(text));
}

/*
 * hfield_dump
 *
 * Dump field on specified file descriptor.
 */
static void hfield_dump(const header_field_t *h, FILE *out)
{
	GSList *l;

	fprintf(out, "%s: ", h->name);

	g_assert(h->lines);

	for (l = h->lines; l; l = l->next) {
		if (l != h->lines)
			fputs("    ", out);			/* Continuation line */
		fputs(l->data, out);
		fputc('\n', out);
	}
}

/***
 *** header object
 ***/

/*
 * header_make
 *
 * Create a new header object.
 */
header_t *header_make(void)
{
	header_t *o;

	o = (header_t *) g_malloc0(sizeof(header_t));
	o->headers = g_hash_table_new(g_str_hash, g_str_equal);

	return o;
}

/*
 * free_header_data -- htable callback
 *
 * Frees the key/values from the headers hash.
 */
static gboolean free_header_data(gpointer key, gpointer value, gpointer udata)
{
	g_free(key);		/* XXX if shared, don't do that */
	g_string_free((GString *) value, TRUE);
	return TRUE;
}

/*
 * header_free
 *
 * Destroy header object.
 */
void header_free(header_t *o)
{
	g_assert(o);

	header_reset(o);

	g_hash_table_destroy(o->headers);
	g_free(o);
}

/*
 * header_reset
 *
 * Reset header object, for new header parsing.
 */
void header_reset(header_t *o)
{
	GSList *l;

	g_assert(o);

	g_hash_table_foreach_remove(o->headers, free_header_data, NULL);

	for (l = o->fields; l; l = l->next)
		hfield_free((header_field_t *) l->data);
	g_slist_free(o->fields);
	o->fields = NULL;

	o->size = o->lines = o->flags = 0;
}

/*
 * header_get
 *
 * Get field value, or NULL if not present.  The value returned is a
 * pointer to the internals of the header structure, so it must not be
 * kept around.
 *
 * The requested header field must be in normalized form since they are
 * stored that way.
 */
gchar *header_get(const header_t *o, const gchar *field)
{
	GString *v;

	v = g_hash_table_lookup(o->headers, (gpointer) field);

	return v ? v->str : NULL;
}

/*
 * header_getdup
 *
 * Get field value, or NULL if not present.  The value returned is a
 * copy of the internal value, so it may be kept around, but must be
 * freed by the caller.
 */
gchar *header_getdup(const header_t *o, const gchar *field)
{
	GString *v;

	v = g_hash_table_lookup(o->headers, (gpointer) field);
	if (!v)
		return NULL;

	return g_strdup(v->str);
}

/*
 * add_header
 *
 * Add header line to the `headers' hash for specified field name.
 * A private copy of the `field' name and of the `text' data is made.
 */
static void add_header(header_t *o, const gchar *field, const gchar *text)
{
	GHashTable *h = o->headers;
	GString *v;

	v = g_hash_table_lookup(h, field);

	if (v) {
		/*
		 * Header already exists, according to RFC2616 we need to append
		 * the value, comma-separated.
		 */

		g_string_append(v, ", ");
		g_string_append(v, text);

	} else {
		gchar *key;

		/*
		 * Create a new header entry in the hash table.
		 */

		key = g_strdup(field);
		v = g_string_new(text);
		g_hash_table_insert(h, (gpointer) key, (gpointer) v);
	}
}

/*
 * add_continuation
 *
 * Add continuation line to the `headers' hash for specified field name.
 * A private copy of the data is made.
 */
static void add_continuation(
	header_t *o, const gchar *field, const gchar *text)
{
	GHashTable *h = o->headers;
	GString *v;

	v = g_hash_table_lookup(h, field);
	g_assert(v);
	g_string_append_c(v, ' ');
	g_string_append(v, text);
}

/*
 * header_append
 *
 * Append a new line of text at the end of the header.
 * A private copy of the text is made.
 *
 * Returns an error code, or HEAD_OK if appending was successful.
 */
gint header_append(header_t *o, const gchar *text, gint len)
{
	gchar buf[MAX_LINE_SIZE];
	const gchar *p = text;
	guchar c;
	header_field_t *hf;

	if (o->flags & HEAD_F_EOH)
		return HEAD_EOH_REACHED;

	/*
	 * If empty line, we reached EOH.
	 */

	if (len == 0) {
		o->flags |= HEAD_F_EOH;				/* Mark we reached EOH */
		return HEAD_EOH;
	}

	/*
	 * Sanity checks.
	 */

	if (o->size >= HEAD_MAX_SIZE)
		return HEAD_TOO_LARGE;

	if (++(o->lines) >= HEAD_MAX_LINES)
		return HEAD_MANY_LINES;

	/*
	 * Detect whether line is a new header or a continuation.
	 */

	c = *p;
	if (isspace(c)) {

		/*
		 * It's a continuation.
		 *
		 * Make sure we already have recorded something, or we have
		 * an unexpected continuation line.
		 */

		if (o->fields == 0)
			return HEAD_CONTINUATION;		/* Unexpected continuation */

		/*
		 * When a previous header line was malformed, we cannot accept
		 * further continuation lines.
		 */

		if (o->flags & HEAD_F_SKIP)
			return HEAD_SKIPPED;

		/*
		 * We strip leading spaces of all continuations before storing
		 * them.  If we have to dump the header, we will have to put
		 * some spaces, but we don't guarantee we'll put the same amount.
		 */

		p++;								/* First char is known space */
		while ((c = *p)) {
			if (!isspace(c))
				break;
			p++;
		}

		/*
		 * If we've reached the end of the line, then the continuation
		 * line was made of spaces only.  Weird, but we can ignore it.
		 * Note that it's not an EOH mark.
		 */

		if (*p == '\0')
			return HEAD_OK;

		/*
		 * Save the continuation line by appending into the last header
		 * field we handled.
		 */

		hf = (header_field_t *) g_slist_last(o->fields)->data;
		hfield_append(hf, p);
		add_continuation(o, hf->name, p);
		o->size += len - (p - text);	/* Count only effective text */

		/*
		 * Also append the data in the hash table.
		 */

	} else {
		gchar *b;
		gboolean seen_space = FALSE;

		/*
		 * It's a new header line.
		 */

		o->flags &= ~HEAD_F_SKIP;		/* Assume this line will be OK */

		/*
		 * Parse header field.  Must be composed of ascii chars only.
		 * (no control characters, no space, no ISO Latin or other extension).
		 * The field name ends with ':', after possible white spaces.
		 */

		for (b = buf, c = *p; c; c = *(++p)) {
			if (c == ':') {
				*b++ = '\0';			/* Reached end of field */
				break;					/* Done, buf[] holds field name */
			}
			if (isspace(c)) {
				seen_space = TRUE;		/* Only trailing spaces allowed */
				continue;
			}
			if (
				seen_space ||
				((iscntrl(c) || !isascii(c) || ispunct(c)) && c != '-')
			) {
				o->flags |= HEAD_F_SKIP;
				return HEAD_BAD_CHARS;
			}
			*b++ = c;
		}

		/*
		 * If buf[] does not end with a NUL, we did not fully recognize
		 * the header: we reached the end of the line without encountering
		 * the ':' marker.
		 *
		 * If the buffer starts with a NUL char, it's also clearly malformed.
		 */

		g_assert(b > buf || (b == buf && *text == '\0'));

		if (b == buf || *(b-1) != '\0') {
			o->flags |= HEAD_F_SKIP;
			return HEAD_MALFORMED;
		}

		/*
		 * We have a valid header field in buf[].
		 */

		normalize(buf);
		hf = hfield_make(buf);

		/*
		 * Strip leading spaces in the value.
		 */

		g_assert(*p == ':');

		p++;							/* First char is field separator */
		while ((c = *p)) {
			if (!isspace(c))
				break;
			p++;
		}

		/*
		 * Record field value.
		 */

		hfield_append(hf, p);
		add_header(o, buf, p);
		o->fields = g_slist_append(o->fields, (gpointer) hf);
		o->size += len - (p - text);	/* Count only effective text */
	}

	return HEAD_OK;
}

/*
 * header_dump
 *
 * Dump whole header on specified file.
 */
void header_dump(const header_t *o, FILE *out)
{
	GSList *l;

	for (l = o->fields; l; l = l->next)
		hfield_dump((header_field_t *) l->data, out);
}

/***
 *** Header formatting with continuations.
 ***/

#define HEADER_FMT_MAGIC		0xf7a91c
#define HEADER_FMT_DFLT_LEN		256		/* Default line length if no hint */
#define HEADER_FMT_LINE_LEN		72		/* Try to never emit longer lines */
#define HEADER_FMT_MAX_SIZE		1024	/* Max line size for header */

/*
 * Header formatting context
 */
struct header_fmt {
	guint32 magic;
	GString *header;			/* Header being built */
	gint current_len;			/* Length of currently built line */
	gboolean data_emitted;		/* Whether data was ever emitted */
	gboolean frozen;			/* Header terminated */
};

/*
 * header_fmt_make
 *
 * Create a new formatting context for a header line.
 *
 * `field' is the header field name, without trailing ':'.
 * `len_hint' is the expected line size, for pre-sizing purposes. (0 to guess).
 *
 * Returns opaque pointer.
 */
gpointer header_fmt_make(gchar *field, gint len_hint)
{
	struct header_fmt *hf;

	hf = walloc(sizeof(*hf));
	hf->magic = HEADER_FMT_MAGIC;
	hf->header = g_string_sized_new(len_hint ? len_hint : HEADER_FMT_DFLT_LEN);
	hf->data_emitted = FALSE;
	hf->frozen = FALSE;

	g_string_append(hf->header, field);
	g_string_append(hf->header, ": ");

	hf->current_len = hf->header->len;

	return hf;
}

/*
 * header_fmt_free
 *
 * Dispose of header formatting context.
 */
void header_fmt_free(gpointer o)
{
	struct header_fmt *hf = (struct header_fmt *) o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	g_string_free(hf->header, TRUE);
	wfree(hf, sizeof(*hf));
}

/*
 * header_fmt_append
 *
 * Append data `str' to the header line, atomically.
 *
 * `separator' is an optional separator string that will be emitted BEFORE
 * outputting the data, and only when nothing has been emitted already.
 * Any trailing space will be stripped out of `separator' if emitting at the
 * end of a line.
 */
void header_fmt_append(gpointer o, gchar *str, gchar *separator)
{
	struct header_fmt *hf = (struct header_fmt *) o;
	gint len;
	gint curlen;
	gint seplen;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(!hf->frozen);

	len = strlen(str);
	curlen = hf->current_len;
	seplen = (separator == NULL) ? 0 : strlen(separator);

	if (curlen + len + seplen > HEADER_FMT_LINE_LEN) {
		/*
		 * Emit sperator, if any and data was already emitted.
		 */

		if (separator != NULL && hf->data_emitted) {
			gchar *end = separator + seplen;
			gchar *p;
			gint i;

			/*
			 * Locate last non-space char in separator.
			 */

			for (i = seplen - 1; i >= 0; i--) {
				if (separator[i] == ' ')
					end--;
			}

			for (p = separator; p < end; p++)
				g_string_append_c(hf->header, *p);
		}

		g_string_append(hf->header, "\r\n\t");	/* Includes continuation */
		curlen = 4;
	} else if (hf->data_emitted) {
		g_string_append(hf->header, separator);
		curlen += seplen;
	}

	hf->data_emitted = TRUE;
	g_string_append(hf->header, str);
	hf->current_len = curlen + len;
}

/*
 * header_fmt_length
 *
 * Returns length of currently formatted header.
 */
gint header_fmt_length(gpointer o)
{
	struct header_fmt *hf = (struct header_fmt *) o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	return hf->header->len;
}

/*
 * header_fmt_end
 *
 * Terminate header, emitting the trailing "\r\n".
 * Further appending is forbidden.
 */
void header_fmt_end(gpointer o)
{
	struct header_fmt *hf = (struct header_fmt *) o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(!hf->frozen);

	g_string_append(hf->header, "\r\n");
	hf->frozen = TRUE;
}

/*
 * header_fmt_string
 *
 * Return current header string.
 */
gchar *header_fmt_string(gpointer o)
{
	struct header_fmt *hf = (struct header_fmt *) o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	return hf->header->str;		/* Guaranteed to be always NUL-terminated */
}

/*
 * header_fmt_to_gchar
 *
 * Convert current header to a string.
 * NB: returns pointer to static data!
 */
gchar *header_fmt_to_gchar(gpointer o)
{
	static gchar line[HEADER_FMT_MAX_SIZE + 1];
	struct header_fmt *hf = (struct header_fmt *) o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	if (hf->header->len > HEADER_FMT_MAX_SIZE)
		g_warning("trying to format too long an HTTP line (%d bytes)",
			hf->header->len);

	strncpy(line, hf->header->str, HEADER_FMT_MAX_SIZE);
	line[HEADER_FMT_MAX_SIZE] = '\0';

	return line;
}

