/*
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

#include "header.h"
#include "ascii.h"
#include "atoms.h"
#include "getline.h"		/* For MAX_LINE_SIZE */
#include "halloc.h"
#include "htable.h"
#include "log.h"			/* For log_file_printable() */
#include "misc.h"
#include "slist.h"
#include "str.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum header_magic { HEADER_MAGIC = 0x71b8484fU };

/*
 * The `headers' field is a hash table indexed by field name (case-insensitive).
 * Each value (str_t *) holds a private copy of the string making that header,
 * with all continuations removed (leading spaces collapsed into one), and
 * indentical fields concatenated using ", " separators, per RFC2616.
 *
 * The `fields' field holds a list of all the fields, in the order they
 * appeared.  The value is a header_field_t structure.  It allows one to
 * dump the header exactly as it was read.
 */

struct header {
	enum header_magic magic;
	htable_t *headers;			/**< Indexed by name (case-insensitively) */
	slist_t *fields;			/**< Ordered list of header_field_t */
	int flags;					/**< Various operating flags */
	int size;					/**< Total header size, in bytes */
	int num_lines;				/**< Total header lines seen */
	int refcnt;					/**< Reference count on the structure */
};

static inline void
header_check(const header_t * const h)
{
	g_assert(h != NULL);
	g_assert(HEADER_MAGIC == h->magic);
	g_assert(h->refcnt > 0);
}

enum header_field { HEADER_FIELD_MAGIC = 0x6e29aad7U };

/**
 * A header field.
 *
 * It holds the field name, and all the lines that make up that field.
 * The first line has the field name and the ":" stripped, as well as
 * all the leading spaces.  Continuations also have their leading spaces
 * stripped out.
 *
 * For instance, assume the following header field:
 *
 *    - X-Comment: first line
 *         and continuation of first line
 *
 * Then the structure would contain, with () denoting a list:
 *
 *    - name = "X-Comment"
 *    - lines = ("first line", "and continuation of first line")
 */

typedef struct {
	enum header_field magic;
	char *name;					/**< Field name */
	slist_t *lines;				/**< List of lines making this header */
} header_field_t;

static inline void
header_field_check(const header_field_t * const hf)
{
	g_assert(hf != NULL);
	g_assert(HEADER_FIELD_MAGIC == hf->magic);
}

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
const char *
header_strerror(uint errnum)
{
	if (errnum >= G_N_ELEMENTS(error_str))
		return "Invalid error code";

	return error_str[errnum];
}

int
header_num_lines(const header_t *h)
{
	return h->num_lines;
}

/***
 *** header_field object
 ***/

/**
 * Create a new empty header field, whose name is `name'.
 * A private copy of `name' is done.
 */
static header_field_t *
hfield_make(const char *name)
{
	header_field_t *h;

	WALLOC0(h);
	h->magic = HEADER_FIELD_MAGIC;
	h->name = h_strdup(name);

	return h;
}

static void
hfield_free_item(void *p)
{
	HFREE_NULL(p);
}

/**
 * Dispose of the header field.
 */
static void
hfield_free(header_field_t *h)
{
	header_field_check(h);

	slist_free_all(&h->lines, hfield_free_item);
	HFREE_NULL(h->name);
	h->magic = 0;
	WFREE(h);
}

/**
 * Append line of text to given header field.
 * A private copy of the data is made.
 */
static void
hfield_append(header_field_t *h, const char *text)
{
	header_field_check(h);

	if (!h->lines) {
		h->lines = slist_new();
	}
	slist_append(h->lines, h_strdup(text));
}

/**
 * Dump field on specified file descriptor.
 */
static void
hfield_dump(const header_field_t *h, FILE *out)
{
	slist_iter_t *iter;
	bool first;

	header_field_check(h);
	g_assert(h->lines);

	fprintf(out, "%s: ", h->name);

	first = TRUE;
	iter = slist_iter_on_head(h->lines);
	for (/* NOTHING */; slist_iter_has_item(iter); slist_iter_next(iter)) {
		const char *s;

		if (!first) {
			first = FALSE;
			fputs("    ", out);			/* Continuation line */
		}
		s = slist_iter_current(iter);
		if (is_printable_iso8859_string(s)) {
			fputs(s, out);
		} else {
			char buf[80];
			const char *p = s;
			int c;
			size_t len = strlen(s);
			str_bprintf(buf, sizeof buf, "<%u non-printable byte%s>",
				(unsigned) len, 1 == len ? "" : "s");
			fputs(buf, out);
			while ((c = *p++)) {
				if (is_ascii_print(c) || is_ascii_space(c))
					fputc(c, out);
				else
					fputc('.', out);	/* Less visual clutter than '?' */
			}
		}
		fputc('\n', out);
	}
	slist_iter_free(&iter);	
}

/***
 *** header object
 ***/

static htable_t *
header_get_table(header_t *o)
{
	header_check(o);

	if (NULL == o->headers) {
		o->headers = htable_create_any(ascii_strcase_hash,
			NULL, ascii_strcase_eq);
	}

	return o->headers;
}

/**
 * Create a new header object.
 */
header_t *
header_make(void)
{
	header_t *o;

	WALLOC0(o);
	o->magic = HEADER_MAGIC;
	o->refcnt = 1;
	return o;
}

/**
 * Frees the key/values from the headers hash.
 */
static bool
free_header_data(const void *key, void *value, void *unused_udata)
{
	void *k;

	(void) unused_udata;

	k = deconstify_pointer(key);
	hfree(k);					/* XXX if shared, don't do that */
	str_destroy(value);
	return TRUE;
}

/**
 * Take an extra reference on the header object.
 * @return the header object.
 */
header_t *
header_refcnt_inc(header_t *o)
{
	header_check(o);

	o->refcnt++;
	return o;
}

/**
 * Destroy header object.
 */
void
header_free(header_t *o)
{
	header_check(o);

	if (o->refcnt > 1) {
		o->refcnt--;
		return;
	}

	header_reset(o);
	o->magic = 0;
	WFREE(o);
}

/**
 * Destroy header object and nullify pointer holding it.
 */
void
header_free_null(header_t **o_ptr)
{
	header_t *o = *o_ptr;

	if (o != NULL) {
		header_free(o);
		*o_ptr = NULL;
	}
}

/**
 * Reset header object, for new header parsing.
 */
void
header_reset(header_t *o)
{
	header_check(o);

	if (o->headers != NULL) {
		htable_foreach_remove(o->headers, free_header_data, NULL);
		htable_free_null(&o->headers);
	}
	slist_free_all(&o->fields, cast_to_slist_destroy(hfield_free));
	o->flags = o->size = o->num_lines = 0;
}

/**
 * Get field value, or NULL if not present.  The value returned is a
 * pointer to the internals of the header structure, so it must not be
 * kept around.
 */
char *
header_get(const header_t *o, const char *field)
{
	str_t *v;

	header_check(o);

	if (o->headers) {
		v = htable_lookup(o->headers, deconstify_char(field));
	} else {
		v = NULL;
	}
	return str_2c(v);
}

/**
 * Get field value, or NULL if not present.  The value returned is a
 * pointer to the internals of the header structure, so it must not be
 * kept around.
 *
 * If the len_ptr pointer is not NULL, it is filled with the length
 * of the header string.
 */
char *
header_get_extended(const header_t *o, const char *field, size_t *len_ptr)
{
	str_t *v;

	header_check(o);

	if (o->headers) {
		v = htable_lookup(o->headers, deconstify_char(field));
	} else {
		v = NULL;
	}
	if (v && len_ptr != NULL) {
		*len_ptr = str_len(v);
	}
	return str_2c(v);
}

/**
 * Add header line to the `headers' hash for specified field name.
 * A private copy of the `field' name and of the `text' data is made.
 */
static void
add_header(header_t *o, const char *field, const char *text)
{
	htable_t *ht;
	str_t *v;

	header_check(o);

	ht = header_get_table(o);
	v = htable_lookup(ht, field);
	if (v) {
		/*
		 * Header already exists, according to RFC2616 we need to append
		 * the value, comma-separated.
		 */

		str_cat(v, ", ");
		str_cat(v, text);

	} else {
		char *key;

		/*
		 * Create a new header entry in the hash table.
		 */

		key = h_strdup(field);
		v = str_new_from(text);
		htable_insert(ht, key, v);
	}
}

/**
 * Add continuation line to the `headers' hash for specified field name.
 * A private copy of the data is made.
 */
static void
add_continuation(header_t *o, const char *field, const char *text)
{
	str_t *v;

	header_check(o);
	g_assert(o->headers);

	v = htable_lookup(o->headers, field);
	g_assert(v != NULL);
	str_putc(v, ' ');
	str_cat(v, text);
}

/**
 * Append a new line of text at the end of the header.
 * A private copy of the text is made.
 *
 * @return an error code, or HEAD_OK if appending was successful.
 */
int
header_append(header_t *o, const char *text, int len)
{
	char buf[MAX_LINE_SIZE];
	const char *p = text;
	uchar c;
	header_field_t *hf;

	header_check(o);
	g_assert(len >= 0);

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

	if (++(o->num_lines) >= HEAD_MAX_LINES)
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

		if (NULL == o->fields)
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

		hf = slist_tail(o->fields);
		hfield_append(hf, p);
		add_continuation(o, hf->name, p);
		o->size += len - (p - text);	/* Count only effective text */

		/*
		 * Also append the data in the hash table.
		 */

	} else {
		char *b;
		bool seen_space = FALSE;

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
		if (!o->fields) {
			o->fields = slist_new();
		}
		slist_append(o->fields, hf);
		o->size += len - (p - text);	/* Count only effective text */
	}

	return HEAD_OK;
}

static void
header_dump_item(void *p, void *user_data)
{
	hfield_dump(p, user_data);
}

/**
 * Dump whole header on specified file, followed by trailer string
 * (if not NULL) and a final "\n".
 */
void
header_dump(FILE *out, const header_t *o, const char *trailer)
{
	header_check(o);

	if (!log_file_printable(out))
		return;

	if (o->fields) {
		slist_foreach(o->fields, header_dump_item, out);
	}
	if (trailer)
		fprintf(out, "%s\n", trailer);
}

/***
 *** Header formatting with continuations.
 ***/

enum header_fmt_magic { HEADER_FMT_MAGIC = 0xf7a91cU };

#define HEADER_FMT_DFLT_LEN		256		/**< Default field length if no hint */
#define HEADER_FMT_LINE_LEN		78		/**< Try to never emit longer lines */
#define HEADER_FMT_MAX_SIZE		1024	/**< Max line size for header */

/**
 * Header formatting context.
 */
struct header_fmt {
	enum header_fmt_magic magic;
	size_t max_size;		/**< Maximum line length, including "\r\n" + NUL */
	size_t maxlen;			/**< Maximum line length before continuation */
	str_t *header;			/**< Header being built */
	const char *sep;		/**< Optional separator */
	size_t seplen;			/**< Length of separator string */
	size_t stripped_seplen;	/**< Length of separator without trailing space */
	size_t current_len;		/**< Length of currently built line */
	unsigned data_emitted:1;/**< Whether data was ever emitted */
	unsigned frozen:1;		/**< Header terminated */
	unsigned empty:1;		/**< Header max-size too small, must stay empty */
};

static inline void
header_fmt_check(const header_fmt_t *fmt)
{
	g_assert(fmt != NULL);
	g_assert(HEADER_FMT_MAGIC == fmt->magic);
}

/**
 * Compute the length of the string `s' whose length is `len' with trailing
 * blanks ignored.
 */
static size_t
stripped_strlen(const char *s, size_t len)
{
	const char *end;

	/*
	 * Locate last non-blank char in separator.
	 */

	for (end = &s[len]; end != s; end--) {
		if (!is_ascii_blank(end[-1]))
			break;
	}

	return end - s;
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
 * @param `max_size' is the maximum header size, including the final "\r\n"
 * and the trailing NUL.  If the initial field name is larger than the
 * configured maximum size, the header field will remain completely empty.
 *
 * @return pointer to the formatting object.
 */
header_fmt_t *
header_fmt_make(const char *field, const char *separator,
	size_t len_hint, size_t max_size)
{
	struct header_fmt *hf;

	g_assert(size_is_non_negative(len_hint));

	WALLOC(hf);
	hf->magic = HEADER_FMT_MAGIC;
	hf->header = str_new(len_hint ? len_hint : HEADER_FMT_DFLT_LEN);
	hf->maxlen = HEADER_FMT_LINE_LEN;
	hf->data_emitted = FALSE;
	hf->frozen = FALSE;
	hf->max_size = max_size;
	hf->sep = atom_str_get(separator ? separator : "");
	hf->seplen = strlen(hf->sep);
	hf->stripped_seplen = stripped_strlen(hf->sep, hf->seplen);
	str_cat(hf->header, field);
	str_cat(hf->header, ": ");

	hf->current_len = str_len(hf->header);

	/*
	 * If right from the start the header would be larger than the configured
	 * size, force it to stay empty.  That means, the final string returned
	 * will be "", the empty string.
	 */

	if (str_len(hf->header) + sizeof("\r\n") > hf->max_size) {
		hf->empty = TRUE;
		str_setlen(hf->header, 0);
	} else {
		hf->empty = FALSE;
	}

	header_fmt_check(hf);

	return hf;
}

/**
 * Set max line length.
 */
void
header_fmt_set_line_length(header_fmt_t *hf, size_t maxlen)
{
	header_fmt_check(hf);
	g_assert(size_is_positive(maxlen));

	hf->maxlen = maxlen;
}

/**
 * Dispose of header formatting context.
 */
void
header_fmt_free(header_fmt_t **hf_ptr)
{
	header_fmt_t *hf = *hf_ptr;

	if (hf) {
		header_fmt_check(hf);

		str_destroy_null(&hf->header);
		atom_str_free_null(&hf->sep);
		hf->magic = 0;
		WFREE(hf);
		*hf_ptr = NULL;
	}
}

/**
 * Checks whether appending `len' bytes of data to the header would fit
 * within the maximum header size requirement in case a continuation
 * is emitted, and using the configured separator.
 */
bool
header_fmt_value_fits(const header_fmt_t *hf, size_t len)
{
	size_t final_len;
	size_t maxlen, n;

	header_fmt_check(hf);

	if (hf->empty)
		return FALSE;

	maxlen = size_saturate_sub(hf->max_size, sizeof("\r\n"));

	/*
	 * If it fits on the line, no continuation will have to be emitted.
	 * Otherwise, we'll need the stripped version of the separator,
	 * followed by "\r\n\t" (3 chars).
	 */

	final_len = size_saturate_add(str_len(hf->header), len);

	n = size_saturate_add(hf->current_len, size_saturate_add(len, hf->seplen));
	if (n <= hf->maxlen) {
		final_len = size_saturate_add(final_len, hf->seplen);
	} else {
		final_len = size_saturate_add(final_len, hf->stripped_seplen);
		final_len = size_saturate_add(final_len, 3);
	}

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
 * @param `sslen' is the stripped separator length, (size_t)-1 if unknown yet.
 *
 * @return TRUE if we were able to fit the string, FALSE if it would have
 * resulted in the header being larger than the configured max size (the
 * header line is left in the state it was in upon entry, in that case).
 */
static bool
header_fmt_append_full(header_fmt_t *hf, const char *str,
	const char *separator, size_t slen, size_t sslen)
{
	size_t len, curlen;
	gsize gslen;
	bool success;

	header_fmt_check(hf);
	g_assert(size_is_non_negative(slen));
	g_assert((size_t)-1 == sslen || size_is_non_negative(sslen));

	if (hf->empty)
		return FALSE;

	gslen = str_len(hf->header);
	len = strlen(str);
	curlen = hf->current_len;
	g_assert(size_is_non_negative(curlen));

	g_assert(len <= INT_MAX);	/* Legacy bug */

	if (
		size_saturate_add(curlen, size_saturate_add(len, slen)) >
			UNSIGNED(hf->maxlen)
	) {
		/*
		 * Emit sperator, if any and data was already emitted.
		 */

		if (separator != NULL && hf->data_emitted) {
			sslen = (size_t)-1 != sslen ? sslen :
				stripped_strlen(separator, slen);
			str_cat_len(hf->header, separator, sslen);
		}

		str_cat(hf->header, "\r\n\t");			/* Includes continuation */
		curlen = 1;								/* One tab */
	} else if (hf->data_emitted) {
		str_cat(hf->header, separator);
		curlen += slen;
	}

	str_cat(hf->header, str);

	/*
	 * Check for overflows, undoing string changes if needed.
	 */

	if (str_len(hf->header) + sizeof("\r\n") > hf->max_size) {
		success = FALSE;
		str_setlen(hf->header, gslen);			/* Undo! */
	} else {
		success = TRUE;
		hf->data_emitted = TRUE;
		hf->current_len = curlen + len;
	}

	g_assert(str_len(hf->header) + sizeof("\r\n") <= hf->max_size);

	return success;
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
 *
 * @return TRUE if we were able to append the data whilst remaining under
 * the configured maximum length.
 */
bool
header_fmt_append(header_fmt_t *hf, const char *str, const char *separator)
{
	size_t seplen;

	header_fmt_check(hf);
	g_assert(!hf->frozen);

	seplen = (separator == NULL) ? 0 : strlen(separator);

	return header_fmt_append_full(hf, str, separator, seplen, (size_t)-1);
}

/**
 * Append data `str' to the header line, atomically.
 *
 * Values are separated using the string specified at make time, if any.
 * If emitted before a continuation, the version with stripped trailing
 * whitespaces is used.
 *
 * To supersede the default separator, use header_fmt_append().
 *
 * @return TRUE if we were able to append the data whilst remaining under
 * the configured maximum length.
 */
bool
header_fmt_append_value(header_fmt_t *hf, const char *str)
{
	header_fmt_check(hf);
	g_assert(!hf->frozen);

	return header_fmt_append_full(hf,
		str, hf->sep, hf->seplen, hf->stripped_seplen);
}

/**
 * @return length of currently formatted header.
 */
size_t
header_fmt_length(const header_fmt_t *hf)
{
	header_fmt_check(hf);

	return str_len(hf->header);
}

/**
 * Terminate header, emitting the trailing "\r\n".
 * Further appending is forbidden.
 */
void
header_fmt_end(header_fmt_t *hf)
{
	header_fmt_check(hf);
	g_assert(!hf->frozen);

	if (!hf->empty)
		str_cat(hf->header, "\r\n");
	hf->frozen = TRUE;

	g_assert(str_len(hf->header) < hf->max_size);
}

/**
 * @return current header string.
 */
const char *
header_fmt_string(const header_fmt_t *hf)
{
	header_fmt_check(hf);

	return str_2c(hf->header);	/* Guaranteed to be always NUL-terminated */
}

/**
 * Convert current header to a string.
 *
 * @attention
 * NB: returns pointer to static data!
 */
const char *
header_fmt_to_string(const header_fmt_t *hf)
{
	static char line[HEADER_FMT_MAX_SIZE + 1];

	header_fmt_check(hf);

	if (str_len(hf->header) >= sizeof line) {
		g_warning("trying to format too long an HTTP line (%zu bytes)",
			str_len(hf->header));
	}
	clamp_strncpy(line, sizeof line, str_2c(hf->header), str_len(hf->header));
	return line;
}

/* vi: set ts=4 sw=4 cindent: */
