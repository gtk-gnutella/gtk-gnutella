/*
 * Copyright (c) 2001, Raphael Manfredi
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>		/* for atoi() */
#include <string.h>

#include "header.h"
#include "getline.h"	/* for MAX_LINE_SIZE */

/***
 *** Operating flags
 ***/

#define HEAD_F_EOH		0x00000001			/* EOH reached */
#define HEAD_F_SKIP		0x00000002			/* Skip continuations */

/***
 *** Error code management
 ***/

static char *error_str[] = {
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

static gint max_errnum = sizeof(error_str) / sizeof(error_str[0]) - 1;

/*
 * header_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *header_strerror(gint errnum)
{
	if (errnum < 0 || errnum > max_errnum)
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
static void normalize(guchar *field)
{
	gboolean start_word = TRUE;
	guchar *s;
	gint c;
	
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
static header_field_t *hfield_make(guchar *name)
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
static void hfield_append(header_field_t *h, guchar *text)
{
	h->lines = g_slist_append(h->lines, g_strdup(text));
}

/*
 * hfield_dump
 *
 * Dump field on specified file descriptor.
 */
static void hfield_dump(header_field_t *h, FILE *out)
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
	g_free(key);		// XXX if shared, don't do that
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
gchar *header_get(header_t *o, gchar *field)
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
gchar *header_getdup(header_t *o, gchar *field)
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
static void add_header(header_t *o, guchar *field, guchar *text)
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
static void add_continuation(header_t *o, guchar *field, guchar *text)
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
gint header_append(header_t *o, guchar *text, gint len)
{
	guchar buf[MAX_LINE_SIZE];
	guchar *p = text;
	gint c;
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
		guchar *b;

		/*
		 * It's a new header line.
		 */

		o->flags &= ~HEAD_F_SKIP;		/* Assume this line will be OK */

		/*
		 * Parse header field.  Must be composed of ascii chars only.
		 * (no control characters, no space, no ISO Latin or other extension).
		 * The field name ends with ':'.
		 */

		for (b = buf, c = *p; c; c = *(++p)) {
			if (c == ':') {
				*b++ = '\0';			/* Reached end of field */
				break;					/* Done, buf[] holds field name */
			}
			if (
				(isspace(c) || iscntrl(c) || !isascii(c) || ispunct(c)) &&
				c != '-'
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
		 */

		g_assert(b > buf);

		if (*(b-1) != '\0') {
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
void header_dump(header_t *o, FILE *out)
{
	GSList *l;

	for (l = o->fields; l; l = l->next)
		hfield_dump((header_field_t *) l->data, out);
}

/***
 *** Header-related utilities
 ***/

/*
 * parse_code_message
 *
 * Parse status messages formed of leading digit numbers, then an optional
 * message.  The pointer to the start of the message is returned in `msg'
 * if it is non-null.
 *
 * Returns status code, -1 on error.
 */
static gint parse_code_message(gchar *line, gchar **msg)
{
	gchar *p;
	guchar code[4];
	gint c;
	gint i;
	gint status;

	/*
	 * We expect exactly 3 status digits.
	 */

	for (i = 0, p = line; i < 3; i++, p++) {
		c = *p;
		if (!isdigit(c))
			return -1;
		code[i] = c;
	}
	code[3] = '\0';

	status = atoi(code);
	if (!msg)
		return status;			/* No need to point to start of message */

	/*
	 * Now skip any space.
	 */

	for (c = *p; c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	*msg = p;					/* This is the beginning of the message */

	return status;
}

/*
 * parse_status_line
 *
 * Parse protocol status line, and return the status code, and optionally a
 * pointer within the string where the status message starts (if `msg' is
 * a non-null pointer), and the protocol major/minor (if `major' and `minor'
 * are non-null).
 *
 * If `proto' is non-null, then when there is a leading protocol string in
 * the reply, it must be equal to `proto'.
 *
 * Returns -1 if it fails to parse the status line correctly, the status code
 * otherwise.
 *
 * We recognize the following status lines:
 *
 *     ZZZ 403 message                        (major=-1, minor=-1)
 *     ZZZ/2.3 403 message                    (major=2, minor=3)
 *     403 message                            (major=-1, minor=-1)
 *
 * We don't yet handle "SMTP-like continuations":
 *
 *     403-message line #1
 *     403-message line #2
 *     403 last message line
 *
 * There is no way to return the value of "ZZZ" via this routine.
 */
gint parse_status_line(gchar *line,
	gchar *proto, gchar **msg, gint *major, gint *minor)
{
	gint c;
	gchar *p;

	/*
	 * Skip leading spaces.
	 */

	for (p = line, c = *p; c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	/*
	 * If first character is a digit, then we have simply:
	 *
	 *   403 message
	 *
	 * There's no known protocol information.
	 */

	if (c == '\0')
		return -1;					/* Empty line */

	if (isdigit(c)) {
		if (major)
			*major = -1;
		if (minor)
			*minor = -1;
		return parse_code_message(p, msg);
	}

	/*
	 * Check protocol.
	 */

	if (proto) {
		gint plen = strlen(proto);
		if (0 == strncmp(proto, line, plen)) {
			/*
			 * Protocol string matches, make sure it ends with a space or
			 * a "/" delimiter.
			 */

			p = &line[plen];
			c = *p;					/* Can dereference, at worst it's a NUL */
			if (c == '\0')			/* Only "protocol" name in status */
				return -1;
			if (!isspace(c) && c != '/')
				return -1;
		} else
			return -1;
	} else {
		/*
		 * Move along the string until we find a space or a "/".
		 */

		for (/* empty */; c; c = *(++p)) {
			if (c == '/' || isspace(c))
				break;
		}
	}

	if (c == '\0')
		return -1;

	/*
	 * We've got a "/", parse protocol version number, then move past
	 * to the first space.
	 */

	if (c == '/') {
		gint maj, min;
		if (major || minor) {
			if (sscanf(p+1, "%d.%d", &maj, &min)) {
				if (major)
					*major = maj;
				if (minor)
					*minor = min;
			} else
				return -1;
		}

		for (c = *(++p); c; c = *(++p)) {
			if (isspace(c))
				break;
		}

		if (c == '\0')
			return -1;
	}

	g_assert(isspace(c));

	/*
	 * Now strip leading spaces.
	 */

	for (c = *(++p); c; c = *(++p)) {
		if (!isspace(c))
			break;
	}

	if (c == '\0')
		return -1;

	if (!isdigit(c))
		return -1;

	return parse_code_message(p, msg);
}

