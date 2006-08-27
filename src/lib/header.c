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
 * Header parsing routines.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$")

#include "header.h"
#include "glib-missing.h"
#include "misc.h"
#include "walloc.h"
#include "getline.h"		/* For MAX_LINE_SIZE */
#include "override.h"		/* Must be the last header included */

/*
 * The `headers' field is a hash table indexed by field name (normalized).
 * Each value (GString) holds a private copy of the string making that header,
 * with all continuations removed (leading spaces collapsed into one), and
 * indentical fields concatenated using ", " separators, per RFC2616.
 *
 * The `fields' field holds a list of all the fields, in the order they
 * appeared.  The value is a header_field_t structure.  It allows one to
 * dump the header exactly as it was read.
 */

struct header {
	GHashTable *headers;		/**< Indexed by name, normalized */
	GSList *fields;				/**< Ordered list of header_field_t */
	gint flags;					/**< Various operating flags */
	gint size;					/**< Total header size, in bytes */
	gint lines;					/**< Total header lines seen */
};

/***
 *** Operating flags
 ***/

enum {
	HEAD_F_EOH	= 0x00000001,	/**< EOH reached */
	HEAD_F_SKIP	= 0x00000002	/**< Skip continuations */
};

/***
 *** Error code management
 ***/

static const char *error_str[] = {
	"OK",									/**< HEAD_OK */
	"Unexpected continuation line",			/**< HEAD_CONTINUATION */
	"Malformed header line",				/**< HEAD_MALFORMED */
	"Invalid characters in field name",		/**< HEAD_BAD_CHARS */
	"End of header already reached",		/**< HEAD_EOH_REACHED */
	"Skipped continuation line",			/**< HEAD_SKIPPED */
	"Header too large",						/**< HEAD_TOO_LARGE */
	"Header has too many lines",			/**< HEAD_MANY_LINES */
	"End of header",						/**< HEAD_EOH */
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const gchar *
header_strerror(guint errnum)
{
	if (errnum >= G_N_ELEMENTS(error_str))
		return "Invalid error code";

	return error_str[errnum];
}

gint
header_lines(const header_t *h)
{
	return h->lines;
}

gint
header_size(const header_t *h)
{
	return h->size;
}

/*
 * XXX share normalized header strings into hash table?
 */

/***
 *** Utilities
 ***/

/**
 * In-place normalize the header field name: all letters starting a word
 * are upper-cased, the others are lowercased.
 */
static void
normalize(gchar *field)
{
	gboolean start_word = TRUE;
	gchar *s;
	gint c;

	for (s = field, c = *s; c; c = *(++s)) {
		if (start_word) {
			if (is_ascii_alnum(c)) {
				start_word = FALSE;
				*s = ascii_toupper(c);
			}
		} else {
			if (is_ascii_alnum(c))
				*s = ascii_tolower(c);
			else
				start_word = TRUE;
		}
	}
}

/***
 *** header_field object
 ***/

/**
 * Create a new empty header field, whose normalized name is `name'.
 * A private copy of `name' is done.
 */
static header_field_t *
hfield_make(const gchar *name)
{
	header_field_t *h;

	h = g_malloc0(sizeof *h);
	h->name = g_strdup(name);

	return h;
}

/**
 * Dispose of the header field.
 */
static void
hfield_free(header_field_t *h)
{
	GSList *sl;

	for (sl = h->lines; sl; sl = g_slist_next(sl))
		G_FREE_NULL(sl->data);
	g_slist_free(h->lines);

	G_FREE_NULL(h->name);
	G_FREE_NULL(h);
}

/**
 * Append line of text to given header field.
 * A private copy of the data is made.
 */
static void
hfield_append(header_field_t *h, const gchar *text)
{
	h->lines = g_slist_append(h->lines, g_strdup(text));
}

/**
 * Dump field on specified file descriptor.
 */
static void
hfield_dump(const header_field_t *h, FILE *out)
{
	const GSList *sl;

	fprintf(out, "%s: ", h->name);

	g_assert(h->lines);

	for (sl = h->lines; sl; sl = g_slist_next(sl)) {
		if (sl != h->lines)
			fputs("    ", out);			/* Continuation line */
		fputs(sl->data, out);
		fputc('\n', out);
	}
}

/***
 *** header object
 ***/

/**
 * Create a new header object.
 */
header_t *
header_make(void)
{
	header_t *o;

	o = g_malloc0(sizeof *o);
	o->headers = g_hash_table_new(g_str_hash, g_str_equal);

	return o;
}

/**
 * Frees the key/values from the headers hash.
 */
static gboolean
free_header_data(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;

	G_FREE_NULL(key);		/* XXX if shared, don't do that */
	g_string_free(value, TRUE);
	return TRUE;
}

/**
 * Destroy header object.
 */
void
header_free(header_t *o)
{
	g_assert(o);

	header_reset(o);

	g_hash_table_destroy(o->headers);
	G_FREE_NULL(o);
}

/**
 * Reset header object, for new header parsing.
 */
void
header_reset(header_t *o)
{
	GSList *sl;

	g_assert(o);

	g_hash_table_foreach_remove(o->headers, free_header_data, NULL);

	for (sl = o->fields; sl; sl = g_slist_next(sl))
		hfield_free(sl->data);
	g_slist_free(o->fields);
	o->fields = NULL;

	o->size = o->lines = o->flags = 0;
}

/**
 * Get field value, or NULL if not present.  The value returned is a
 * pointer to the internals of the header structure, so it must not be
 * kept around.
 *
 * The requested header field must be in normalized form since they are
 * stored that way.
 */
gchar *
header_get(const header_t *o, const gchar *field)
{
	GString *v;

	v = g_hash_table_lookup(o->headers, deconstify_gchar(field));

	return v ? v->str : NULL;
}

/**
 * Get field value, or NULL if not present.  The value returned is a
 * copy of the internal value, so it may be kept around, but must be
 * freed by the caller.
 */
gchar *
header_getdup(const header_t *o, const gchar *field)
{
	GString *v;

	v = g_hash_table_lookup(o->headers, (gpointer) field);
	if (!v)
		return NULL;

	return g_strdup(v->str);
}

/**
 * Add header line to the `headers' hash for specified field name.
 * A private copy of the `field' name and of the `text' data is made.
 */
static void
add_header(header_t *o, const gchar *field, const gchar *text)
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

/**
 * Add continuation line to the `headers' hash for specified field name.
 * A private copy of the data is made.
 */
static void
add_continuation(header_t *o, const gchar *field, const gchar *text)
{
	GHashTable *h = o->headers;
	GString *v;

	v = g_hash_table_lookup(h, field);
	g_assert(v);
	g_string_append_c(v, ' ');
	g_string_append(v, text);
}

/**
 * Append a new line of text at the end of the header.
 * A private copy of the text is made.
 *
 * @return an error code, or HEAD_OK if appending was successful.
 */
gint
header_append(header_t *o, const gchar *text, gint len)
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
	if (is_ascii_space(c)) {

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
			if (!is_ascii_space(c))
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

		hf = g_slist_last(o->fields)->data;
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
			if (is_ascii_space(c)) {
				seen_space = TRUE;		/* Only trailing spaces allowed */
				continue;
			}
			if (
				seen_space || (c != '-' &&
					(!isascii(c) || is_ascii_cntrl(c) || is_ascii_punct(c)))
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
		p = skip_ascii_spaces(p);

		/*
		 * Record field value.
		 */

		hfield_append(hf, p);
		add_header(o, buf, p);
		o->fields = g_slist_append(o->fields, hf);
		o->size += len - (p - text);	/* Count only effective text */
	}

	return HEAD_OK;
}

/**
 * Dump whole header on specified file.
 */
void
header_dump(const header_t *o, FILE *out)
{
	const GSList *sl;

	for (sl = o->fields; sl; sl = g_slist_next(sl))
		hfield_dump(sl->data, out);
}

/***
 *** Header formatting with continuations.
 ***/

#define HEADER_FMT_MAGIC		0xf7a91c
#define HEADER_FMT_DFLT_LEN		256		/**< Default field length if no hint */
#define HEADER_FMT_LINE_LEN		78		/**< Try to never emit longer lines */
#define HEADER_FMT_MAX_SIZE		1024	/**< Max line size for header */

/**
 * Header formatting context.
 */
struct header_fmt {
	guint32 magic;
	gint maxlen;			/**< Maximum line length before continuation */
	GString *header;		/**< Header being built */
	gchar sep[257];			/**< Optional separator */
	gint seplen;			/**< Length of separator string */
	gint stripped_seplen;	/**< Length of separator without trailing space */
	gint current_len;		/**< Length of currently built line */
	gboolean data_emitted;	/**< Whether data was ever emitted */
	gboolean frozen;		/**< Header terminated */
};

/**
 * Compute the length of the string `s' whose length is `len' with trailing
 * whitespace ignored.
 */
static gint
stripped_strlen(const gchar *s, gint len)
{
	const gchar *end = s + len;
	gint i;

	/*
	 * Locate last non-space char in separator.
	 */

	/* XXX: Shouldn't this allow at least \t or maybe use isspace()? */
	for (i = len - 1; i >= 0; i--, end--) {
		if (s[i] != ' ')
			return end - s;
	}

	return 0;
}

/**
 * Create a new formatting context for a header line.
 *
 * @param `field' is the header field name, without trailing ':'.
 *
 * @param `separator' is the optional default separator to emit between
 * the values added via header_fmd_append_value().  To supersede the
 * default separator, use header_fmd_append() and specify another separator
 * explicitly.  If set to NULL, there will be no default separator and
 * values will be simply concatenated together.  The value given must
 * NOT be freed before the header_fmt_end() call (usually it will just
 * be a static string).  Trailing spaces in the separator will be stripped
 * if it is emitted at the end of a line before a continuation.
 *
 * @param `len_hint' is the expected line size, for pre-sizing purposes.
 * (0 to guess).
 *
 * @return opaque pointer.
 */
gpointer
header_fmt_make(const gchar *field, const gchar *separator, gint len_hint)
{
	struct header_fmt *hf;
	size_t len;

	g_assert(!separator || strlen(separator) < sizeof(hf->sep));
	g_assert(len_hint >= 0);

	hf = walloc(sizeof(*hf));
	hf->magic = HEADER_FMT_MAGIC;
	hf->header = g_string_sized_new(len_hint ? len_hint : HEADER_FMT_DFLT_LEN);
	hf->maxlen = HEADER_FMT_LINE_LEN;
	hf->data_emitted = FALSE;
	hf->frozen = FALSE;
	len = g_strlcpy(hf->sep, separator ? separator : "", sizeof(hf->sep));
	hf->seplen = MIN(len, (sizeof hf->sep - 1));
	hf->stripped_seplen = stripped_strlen(hf->sep, hf->seplen);
	g_string_append(hf->header, field);
	g_string_append(hf->header, ": ");

	hf->current_len = hf->header->len;

	return hf;
}

/**
 * Set max line length.
 */
void
header_fmt_set_line_length(gpointer o, gint maxlen)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(maxlen > 0);

	hf->maxlen = maxlen;
}

/**
 * Dispose of header formatting context.
 */
void
header_fmt_free(gpointer o)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	g_string_free(hf->header, TRUE);
	hf->magic = 0;
	wfree(hf, sizeof *hf);
}

/**
 * Checks whether appending `len' bytes of data to the header would fit
 * within the `maxlen' total header size requirement in case a continuation
 * is emitted, and using the configured separator.
 *
 * @attention
 * NB: The `maxlen' parameter is the amount of data that can be generated for
 * the header string, not counting the final "\r\n" + the trailing NUL byte.
 */
gboolean
header_fmt_value_fits(gpointer o, gint len, gint maxlen)
{
	struct header_fmt *hf = o;
	gint final_len;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	/*
	 * If it fits on the line, no continuation will have to be emitted.
	 * Otherwise, we'll need the stripped version of the separator,
	 * followed by "\r\n\t" (3 chars).
	 */

	if (hf->current_len + len + hf->seplen <= hf->maxlen)
		final_len = hf->header->len + len + hf->seplen;
	else
		final_len = hf->header->len + len + hf->stripped_seplen + 3;

	return final_len < maxlen;	/* Could say "<=" perhaps, but let's be safe */
}

/**
 * Append data `str' to the header line, atomically.
 *
 * @param `hf' no brief description.
 * @param `str' no brief description.
 * @param `separator' is an optional separator string that will be emitted
 *         BEFORE outputting the data, and only when nothing has been emitted
 *         already.
 * @param `slen' is the separator length, 0 if empty.
 * @param `sslen' is the stripped separator length, -1 if unknown yet.
 */
static void
header_fmt_append_full(struct header_fmt *hf, const gchar *str,
	const gchar *separator, gint slen, gint sslen)
{
	size_t len;
	gint curlen;

	len = strlen(str);
	g_assert(len <= INT_MAX);	/* Legacy bug */
	curlen = hf->current_len;

	if (curlen + len + slen > (size_t) hf->maxlen) {
		/*
		 * Emit sperator, if any and data was already emitted.
		 */

		if (separator != NULL && hf->data_emitted) {
			gint s = sslen >= 0 ? sslen : stripped_strlen(separator, slen);
			const gchar *p;

			for (p = separator; s > 0; p++, s--)
				g_string_append_c(hf->header, *p);
		}

		g_string_append(hf->header, "\r\n\t");	/* Includes continuation */
		curlen = 1;								/* One tab */
	} else if (hf->data_emitted) {
		g_string_append(hf->header, separator);
		curlen += slen;
	}

	hf->data_emitted = TRUE;
	g_string_append(hf->header, str);
	hf->current_len = curlen + len;
}

/**
 * Append data `str' to the header line, atomically.
 *
 * `separator' is an optional separator string that will be emitted BEFORE
 * outputting the data, and only when nothing has been emitted already.
 * Any trailing space will be stripped out of `separator' if emitting at the
 * end of a line.  It supersedes any separator configured at make time.
 *
 * To use the standard separator, use header_fmt_append_value().
 */
void
header_fmt_append(gpointer o, const gchar *str, const gchar *separator)
{
	struct header_fmt *hf = o;
	gint seplen;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(!hf->frozen);

	seplen = (separator == NULL) ? 0 : strlen(separator);

	header_fmt_append_full(hf, str, separator, seplen, -1);
}

/**
 * Append data `str' to the header line, atomically.
 *
 * Values are separated using the string specified at make time, if any.
 * If emitted before a continuation, the version with stripped trailing
 * whitespaces is used.
 *
 * To supersede the default separator, use header_fmt_append().
 */
void
header_fmt_append_value(gpointer o, const gchar *str)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(!hf->frozen);

	header_fmt_append_full(hf, str, hf->sep, hf->seplen, hf->stripped_seplen);
}

/**
 * @return length of currently formatted header.
 */
gint
header_fmt_length(gpointer o)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	return hf->header->len;
}

/**
 * Terminate header, emitting the trailing "\r\n".
 * Further appending is forbidden.
 */
void
header_fmt_end(gpointer o)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);
	g_assert(!hf->frozen);

	g_string_append(hf->header, "\r\n");
	hf->frozen = TRUE;
}

/**
 * @return current header string.
 */
gchar *
header_fmt_string(gpointer o)
{
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	return hf->header->str;		/* Guaranteed to be always NUL-terminated */
}

/**
 * Convert current header to a string.
 *
 * @attention
 * NB: returns pointer to static data!
 */
gchar *
header_fmt_to_string(gpointer o)
{
	static gchar line[HEADER_FMT_MAX_SIZE + 1];
	struct header_fmt *hf = o;

	g_assert(hf->magic == HEADER_FMT_MAGIC);

	if (hf->header->len > HEADER_FMT_MAX_SIZE)
		g_warning("trying to format too long an HTTP line (%d bytes)",
			(int) hf->header->len);

	strncpy(line, hf->header->str, HEADER_FMT_MAX_SIZE);
	line[HEADER_FMT_MAX_SIZE] = '\0';

	return line;
}

/* vi: set ts=4 sw=4 cindent: */
