/*
 * Copyright (c) 2001, Raphael Manfredi
 */

#ifndef __header_h__
#define __header_h__

#include <glib.h>

/*
 * Header parsing and holding data structures.
 *
 * The `headers' field is a hash table indexed by field name (normalized).
 * Each value (GString) holds a private copy of the string making that header,
 * with all continuations removed (leading spaces collapsed into one), and
 * indentical fields concatenated using ", " separators, per RFC2616.
 *
 * The `fields' field holds a list of all the fields, in the order they
 * appeared.  The value is a header_field_t structure.  It allows one to
 * dump the header exactly as it was read.
 */

typedef struct header {
	GHashTable *headers;		/* Indexed by name, normalized */
	GSList *fields;				/* Ordered list of header_field_t */
	gint flags;					/* Various operating flags */
	gint size;					/* Total header size, in bytes */
	gint lines;					/* Total header lines seen */
} header_t;

/*
 * A header field.
 *
 * It holds the field name, and all the lines that make up that field.
 * The first line has the field name and the ":" stripped, as well as
 * all the leading spaces.  Continuations also have their leading spaces
 * stripped out.
 *
 * For instance, assume the following header field:
 *
 *     X-Comment: first line
 *         and continuation of first line
 *
 * Then the structure would contain, with () denoting a list:
 *
 *    name = "X-Comment"
 *    lines = ("first line", "and continuation of first line")
 */

typedef struct {
	guchar *name;				/* Field name */
	GSList *lines;				/* List of lines making this header */
} header_field_t;

/*
 * Error codes.
 */

#define HEAD_OK				0		/* OK */
#define HEAD_CONTINUATION	1		/* Unexpected continuation line */
#define HEAD_MALFORMED		2		/* Malformed header line */
#define HEAD_BAD_CHARS		3		/* Invalid characters in field name */
#define HEAD_EOH_REACHED	4		/* End of header already reached */
#define HEAD_SKIPPED		5		/* Skipped continuation line */
#define HEAD_TOO_LARGE		6		/* Header too large */
#define HEAD_MANY_LINES		7		/* Header has too many lines */
#define HEAD_EOH			8		/* End of header reached */

/*
 * Our sanity limits
 */

#define HEAD_MAX_LINES		64		/* Maximum amount of header lines */
#define HEAD_MAX_SIZE		4096	/* Maximum size of header data */

/*
 * Public interaface.
 */

header_t *header_make(void);
void header_free(header_t *o);
void header_reset(header_t *o);
gint header_append(header_t *o, guchar *text, gint len);
void header_dump(header_t *o, FILE *out);
gchar *header_strerror(gint errnum);
gchar *header_get(header_t *o, gchar *field);
gchar *header_getdup(header_t *o, gchar *field);

gint parse_status_line(gchar *line, gchar **msg, gint *major, gint *minor);

#endif	/* __header_h__ */

/* vi: set ts=4: */

