/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#include "common.h"

RCSID("$Id$")

#include "prop.h"
#include "file.h"
#include "misc.h"
#include "glib-missing.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

#define debug track_props
static guint32 track_props = 0;	/**< XXX need to init lib's props--RAM */
static guint32 common_dbg = 0;	/**< XXX -- need to init lib's props --RAM */

const struct {
	const gchar *name; 
} prop_type_str[] = {
	{ "boolean" 	},
	{ "guint32" 	},
	{ "guint64" 	},
	{ "ip" 			},
	{ "multichoice" },
	{ "storage" 	},
	{ "string"		},
	{ "timestamp"	},
};

/***
 *** Helpers
 ***/

#define prop_assert(ps, prop, x)									\
G_STMT_START {														\
	if (!(x)) {														\
		g_error("assertion failed for property \"%s\": %s",			\
			PROP(ps, prop).name, #x);								\
	}																\
} G_STMT_END

typedef gint (* prop_parse_func_t)(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i);

static gint
prop_parse_guint64(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i)
{
	gint error;
	guint64 u;
	
	u = parse_uint64(str, endptr, 10, &error);
	if (error) {
		g_warning("prop_parse_guint64: (prop=\"%s\") "
			"str=\"%s\": \"%s\"", name, str, g_strerror(error));
	} else if (vec) {
		((guint64 *) vec)[i] = u;
	}

	return error;
}

static gint
prop_parse_timestamp(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i)
{
	const gchar *ep;
	gint error = 0;
	guint64 u;
	time_t t;

	u = parse_uint64(str, &ep, 10, &error);
	if (error) {
		g_warning("prop_parse_timestamp: (prop=\"%s\") "
			"str=\"%s\": \"%s\"", name, str, g_strerror(error));
	}
	if (*ep != '-') {
		t = u;	/* For backwards-compatibility accept raw numeric timestamps */
	} else {
		static const struct tm zero_tm;
		struct tm tm;

		t = 0;
		tm = zero_tm;
		tm.tm_year = u - 1900;

		/* Parse an ISO 8601 date of the variant YYYY-MM-DD HH:MM:SS */
		if (!error && *ep == '-') {
			guint16 v;
			
			str = &ep[1];
			v = parse_uint16(str, &ep, 10, &error);
			if (!error && (v < 1 || v > 12))
				error = ERANGE;
			else
				tm.tm_mon = v - 1; 
		}
		if (!error && *ep == '-') {
			guint16 v;

			str = &ep[1];
			v = parse_uint16(str, &ep, 10, &error);
			if (!error && (v < 1 || v > 31))
				error = ERANGE;
			else
				tm.tm_mday = v;
		}
		if (!error && (is_ascii_blank(*ep) || *ep == 'T')) {
			str = skip_ascii_blanks(ep);
			if (str[0] == 'T')
				str++;
			tm.tm_hour = parse_uint16(str, &ep, 10, &error);
			if (!error && tm.tm_hour > 23)
				error = ERANGE;
		}
		if (!error && *ep == ':') {
			str = &ep[1];
			tm.tm_min = parse_uint16(str, &ep, 10, &error);
			if (!error && tm.tm_min > 59)
				error = ERANGE;
		}
		if (!error && *ep == ':') {
			str = &ep[1];
			tm.tm_sec = parse_uint16(str, &ep, 10, &error);
			if (!error && tm.tm_sec > 61)
				error = ERANGE;
		}
		if (!error) {
			errno = 0;
			if ((time_t) -1 == (t = mktime(&tm)))
				error = errno ? errno : EINVAL;
		}
	}
	
	if (!error && vec)
		((time_t *) vec)[i] = t;

	if (endptr)
		*endptr = ep;

	return error;
}


static gint
prop_parse_guint32(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i)
{
	gint error;
	guint32 u;
	
	u = parse_uint32(str, endptr, 10, &error);
	if (error) {
		g_warning("prop_parse_guint32: (prop=\"%s\") "
			"str=\"%s\": \"%s\"", name, str, g_strerror(error));
	} else if (vec) {
		((guint32 *) vec)[i] = u;
	}

	return error;
}

static gint
prop_parse_ip(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i)
{
	host_addr_t addr;
	gint error;
	const gchar *ep;
	
	g_assert(name);
	g_assert(str);

	ep = is_strprefix(str, "<none>");
	if (ep) {
		error = 0;
		addr = zero_host_addr;	
		if (endptr) {
			*endptr = ep;
		}
	} else {
		error = string_to_host_addr(str, endptr, &addr) ? 0 : EINVAL;
	}
	if (error) {
		g_warning("prop_parse_ip: (prop=\"%s\") "
			"str=\"%s\": \"%s\"", name, str, g_strerror(error));
	} else if (vec) {
		((host_addr_t *) vec)[i] = addr;
	}
	
	return error;
}

/**
 * Parse comma delimited boolean vector (TRUE/FALSE list).
 */
static gint
prop_parse_boolean(const gchar *name,
	const gchar *str, const gchar **endptr, gpointer vec, size_t i)
{
	static const struct {
		const gchar *s;
		const gboolean v;
	} tab[] = {
		{ "0",		FALSE },
		{ "1",		TRUE },
		{ "FALSE",	FALSE },
		{ "TRUE",	TRUE },
	};
	gboolean b = FALSE;
	const gchar *p = NULL;
	guint j;
	gint error = 0;
	
	g_assert(name);
	g_assert(str);

	for (j = 0; j < G_N_ELEMENTS(tab); j++) {
		if (NULL != (p = is_strcaseprefix(str, tab[j].s))) {
			b = tab[j].v;
			break;
		}
	}

	if (!p) {
		p = str;
		error = EINVAL;
	}

	if (error) {
		g_warning("Not a boolean value (prop=\"%s\"): \"%s\"", name, str);
	} else if (vec) {
		((gboolean *) vec)[i] = b;
	}

	if (endptr)
		*endptr = p;

	return error;
}

/**
 * Parse prop vector.
 */
static void
prop_parse_vector(const gchar *name, const gchar *str,
	size_t size, gpointer vec, prop_parse_func_t parser)
{
	const gchar *p = str;
	size_t i;

	g_assert(str != NULL);
	g_assert(vec != NULL);

	for (i = 0; i < size && p; i++) {
		const gchar *endptr;
		gint error;

		p = skip_ascii_spaces(p);
		if ('\0' == *p)
			break;

		error = (*parser)(name, p, &endptr, vec, i);
		endptr = skip_ascii_spaces(endptr);
		if (!error)
			error = ('\0' != *endptr && ',' != *endptr) ? EINVAL : 0;

		if (error)
			g_warning("prop_parse_vector: (prop=\"%s\") "
				"str=\"%s\": \"%s\"", name, p, g_strerror(error));

		p = strchr(endptr, ',');
		if (p)
			p++;
	}

	if (i < size)
		g_warning("prop_parse_vector: (prop=\"%s\") "
			"target initialization incomplete!", name);
}

static void
prop_parse_guint64_vector(const gchar *name, const gchar *str,
	size_t size, guint64 *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_guint64);
}

static void
prop_parse_timestamp_vector(const gchar *name, const gchar *str,
	size_t size, time_t *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_timestamp);
}


static void
prop_parse_guint32_vector(const gchar *name, const gchar *str,
	size_t size, guint32 *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_guint32);
}

static void
prop_parse_ip_vector(const gchar *name, const gchar *str,
	size_t size, host_addr_t *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_ip);
}

static void
prop_parse_boolean_vector(const gchar *name, const gchar *str,
	size_t size, gboolean *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_boolean);
}


/**
 * Parse a hex string into a gchar array.
 *
 * @return TRUE if the data was fully parsed. FALSE on failure.
 */
static gboolean 
prop_parse_storage(const gchar *name, const gchar *str, size_t size, gchar *t)
{
	size_t i;

	g_assert(size > 0);
	if (size * 2 != strlen(str)) {
		g_warning("prop_parse_storage: (prop=\"%s\") "
			"storage does not match requested size", name);
		return FALSE;
	}

	for (i = 0; i < size; i++) {
		gchar h, l;

		h = str[i * 2];
		l = str[i * 2 + 1];
		if (!is_ascii_xdigit(h) || !is_ascii_xdigit(l)) {
			t[i] = '\0';
			g_warning("prop_parse_storage: (prop=\"%s\") "
				"storage is damaged: \"%s\"", name, str);
			return FALSE;
		}
		t[i] = (hex2int(h) << 4) + hex2int(l);
	}
	return TRUE;
}



/***
 *** Properties
 ***/

/**
 * Copy the property definition from the property set and return it.
 * Use the prop_free_def call to free the memory again. A simple g_free
 * won't do, since there are lot's of pointers to allocated memory
 * in the definition structure.
 *
 * The prop_changed_listeners field will always be NULL in the copy.
 */
prop_def_t *
prop_get_def(prop_set_t *ps, property_t p)
{
	prop_def_t *buf;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, p))
		g_error("prop_get_def: unknown property %d", p);

	buf = g_memdup(&PROP(ps, p), sizeof(prop_def_t));
	buf->name = g_strdup(PROP(ps, p).name);
	buf->desc = g_strdup(PROP(ps, p).desc);
	buf->ev_changed = NULL;

	switch (buf->type) {
	case PROP_TYPE_BOOLEAN:
		buf->data.boolean.def = g_memdup(
			PROP(ps,p).data.boolean.def,
			sizeof(gboolean) * PROP(ps,p).vector_size);
		buf->data.boolean.value = g_memdup(
			PROP(ps,p).data.boolean.value,
			sizeof(gboolean) * PROP(ps,p).vector_size);
		break;
	case PROP_TYPE_MULTICHOICE: {
		guint n = 0;

		while (PROP(ps,p).data.guint32.choices[n].title != NULL)
			n++;

		n ++; /* Keep space for terminating {NULL, 0} field */

		buf->data.guint32.choices = g_memdup(
			PROP(ps,p).data.guint32.choices,
			sizeof(prop_def_choice_t) * n);

		buf->data.guint32.choices[n-1].title = NULL;
		buf->data.guint32.choices[n-1].value = 0;

		n = 0;
		while (PROP(ps,p).data.guint32.choices[n].title != NULL) {
			buf->data.guint32.choices[n].title =
				g_strdup(PROP(ps,p).data.guint32.choices[n].title);
			n++;
		}
		/* no break -> continue to PROP_TYPE_GUINT32 */
	}
	case PROP_TYPE_GUINT32:
		buf->data.guint32.def = g_memdup(
			PROP(ps,p).data.guint32.def,
			sizeof(guint32) * PROP(ps,p).vector_size);
		buf->data.guint32.value = g_memdup(
			PROP(ps,p).data.guint32.value,
			sizeof(guint32) * PROP(ps,p).vector_size);
		break;

	case PROP_TYPE_GUINT64:
		buf->data.guint64.def = g_memdup(
			PROP(ps,p).data.guint64.def,
			sizeof(guint64) * PROP(ps,p).vector_size);
		buf->data.guint64.value = g_memdup(
			PROP(ps,p).data.guint64.value,
			sizeof(guint64) * PROP(ps,p).vector_size);
		break;

	case PROP_TYPE_TIMESTAMP:
		buf->data.timestamp.def = g_memdup(
			PROP(ps,p).data.timestamp.def,
			sizeof(time_t) * PROP(ps,p).vector_size);
		buf->data.timestamp.value = g_memdup(
			PROP(ps,p).data.timestamp.value,
			sizeof(time_t) * PROP(ps,p).vector_size);
		break;

	case PROP_TYPE_IP:
		buf->data.ip.value = g_memdup(PROP(ps,p).data.ip.value,
			sizeof buf->data.ip.value * PROP(ps,p).vector_size);
		break;

	case PROP_TYPE_STRING:
		buf->data.string.def	= g_new(gchar*, 1);
		*buf->data.string.def   = g_strdup(*PROP(ps,p).data.string.def);
		buf->data.string.value  = g_new(gchar*, 1);
		*buf->data.string.value = g_strdup(*PROP(ps,p).data.string.value);
		break;

	case PROP_TYPE_STORAGE:
		buf->data.storage.value = g_memdup
			(PROP(ps,p).data.storage.value, PROP(ps,p).vector_size);
		break;
		
	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}

	return buf;
}

void
prop_free_def(prop_def_t *d)
{
	g_assert(d != NULL);

	switch (d->type) {
	case PROP_TYPE_BOOLEAN:
		G_FREE_NULL(d->data.boolean.value);
		G_FREE_NULL(d->data.boolean.def);
		break;
	case PROP_TYPE_MULTICHOICE: {
		guint n = 0;

		while (d->data.guint32.choices[n].title != NULL) {
			G_FREE_NULL(d->data.guint32.choices[n].title);
			n++;
		}

		G_FREE_NULL(d->data.guint32.choices);
		/* no break -> continue to PROP_TYPE_GUINT32 */
	}
	case PROP_TYPE_GUINT32:
		G_FREE_NULL(d->data.guint32.value);
		G_FREE_NULL(d->data.guint32.def);
		break;
	case PROP_TYPE_GUINT64:
		G_FREE_NULL(d->data.guint64.value);
		G_FREE_NULL(d->data.guint64.def);
		break;
	case PROP_TYPE_TIMESTAMP:
		G_FREE_NULL(d->data.timestamp.value);
		G_FREE_NULL(d->data.timestamp.def);
		break;
	case PROP_TYPE_IP:
		G_FREE_NULL(d->data.ip.value);
		break;
	case PROP_TYPE_STRING:
		G_FREE_NULL(*d->data.string.value);
		G_FREE_NULL(*d->data.string.def);
		G_FREE_NULL(d->data.string.value);
		G_FREE_NULL(d->data.string.def);
		break;
	case PROP_TYPE_STORAGE:
		G_FREE_NULL(d->data.storage.value);
		break;
	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}
	G_FREE_NULL(d->name);
	G_FREE_NULL(d->desc);
	G_FREE_NULL(d);
}

/**
 * Add a change listener to a given property. If init is TRUE then
 * the listener is immediately called.
 */
void
prop_add_prop_changed_listener(
	prop_set_t *ps, property_t prop, prop_changed_listener_t l, gboolean init)
{
	prop_add_prop_changed_listener_full(ps, prop, l, init, FREQ_SECS, 0);
}

/**
 * Add a change listener to a given property. If init is TRUE then
 * the listener is immediately called.
 */
void
prop_add_prop_changed_listener_full(
	prop_set_t *ps, property_t prop, prop_changed_listener_t l,
	gboolean init, enum frequency_type freq, guint32 interval)
{
	g_assert(ps != NULL);
	g_assert(prop_in_range(ps, prop));

	event_add_subscriber(
		PROP(ps,prop).ev_changed, (GCallback) l, freq, interval);

	if (init)
		(*l)(prop);
}

void
prop_remove_prop_changed_listener(
	prop_set_t *ps, property_t prop, prop_changed_listener_t l)
{
	g_assert(ps != NULL);
	g_assert(prop_in_range(ps, prop));

	event_remove_subscriber(PROP(ps,prop).ev_changed, (GCallback) l);
}

static void
prop_emit_prop_changed(prop_set_t *ps, property_t prop)
{
	g_assert(ps != NULL);

	event_trigger(PROP(ps,prop).ev_changed,
		T_VETO(prop_changed_listener_t, (prop)));

	if (PROP(ps,prop).save)
		ps->dirty = TRUE;
}

void
prop_set_boolean(prop_set_t *ps, property_t prop, const gboolean *src,
	size_t offset, size_t length)
{
	gboolean old;
	gboolean new;
	gboolean differ = FALSE;
	size_t n;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_boolean: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_BOOLEAN)
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_BOOLEAN].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	for (n = 0; (n < length) && !differ; n++) {
		old = PROP(ps,prop).data.boolean.value[n + offset] ? 1 : 0;
		new = src[n] ? 1 : 0;

		if (old != new)
			differ = TRUE;
	}

	if (!differ)
		return;

	memcpy(&PROP(ps,prop).data.boolean.value[offset], src,
		length * sizeof *src);

	if (debug >= 5) {
		size_t i;

		printf("updated property [%s] = ( ", PROP(ps,prop).name);

		for (i = 0; i < PROP(ps,prop).vector_size; i++)
			printf("%s%s ",
				PROP(ps,prop).data.boolean.value[i] ? "TRUE" : "FALSE",
				(i < (PROP(ps,prop).vector_size-1)) ? "," : "");

		printf(")\n");
	}

	prop_emit_prop_changed(ps, prop);
}

gboolean *
prop_get_boolean(prop_set_t *ps, property_t prop, gboolean *t,
	size_t offset, size_t length)
{
	gboolean *target;
	size_t n;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_boolean: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_BOOLEAN)
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_BOOLEAN].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	memcpy(target, &PROP(ps,prop).data.boolean.value[offset], n);

	return target;
}

void
prop_set_guint64(prop_set_t *ps, property_t prop, const guint64 *src,
	size_t offset, size_t length)
{
	gboolean differ = FALSE;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_guint64: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_GUINT64) )
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_GUINT64].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	differ = 0 != memcmp(&PROP(ps,prop).data.guint64.value[offset], src,
					length * sizeof *src);

	if (!differ)
		return;

	/*
	 * Only do bounds-checking on non-vector properties.
	 */
	if (PROP(ps,prop).vector_size == 1) {
		/*
		 * Either check multiple choices or min/max.
		 */
			prop_assert(ps, prop, PROP(ps,prop).data.guint64.choices == NULL);

			if (
				(PROP(ps,prop).data.guint64.min <= *src) &&
				(PROP(ps,prop).data.guint64.max >= *src)
			) {
				*PROP(ps,prop).data.guint64.value = *src;
			} else {
				gchar buf[64];
				guint64 newval = *src;

				if (newval > PROP(ps,prop).data.guint64.max)
					newval = PROP(ps,prop).data.guint64.max;
				if (newval < PROP(ps,prop).data.guint64.min)
					newval = PROP(ps,prop).data.guint64.min;

				concat_strings(buf, sizeof buf,
					uint64_to_string(PROP(ps,prop).data.guint64.min), "/",
					uint64_to_string2(PROP(ps,prop).data.guint64.max),
					(void *) 0);
				g_warning("prop_set_guint64: [%s] new value out of bounds "
					"(%s): %s (adjusting to %s)", PROP(ps,prop).name, buf,
					uint64_to_string(*src), uint64_to_string2(newval));

				*PROP(ps,prop).data.guint64.value = newval;
			}
	} else {
		memcpy(&PROP(ps,prop).data.guint64.value[offset], src,
			length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;

		printf("updated property [%s] = ( ", PROP(ps,prop).name);

		for (n = 0; n < PROP(ps,prop).vector_size; n++) {
			printf("%s%s ",
				uint64_to_string(PROP(ps,prop).data.guint64.value[n]),
				n < (PROP(ps,prop).vector_size-1) ? "," : "");
		}

		printf(")\n");
	}

	prop_emit_prop_changed(ps, prop);
}

guint64 *
prop_get_guint64(prop_set_t *ps, property_t prop, guint64 *t,
	size_t offset, size_t length)
{
	guint64 *target;
	size_t n;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_guint64: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_GUINT64))
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_GUINT64].name);

   if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	memcpy(target, &PROP(ps,prop).data.guint64.value[offset], n);

	return target;
}

void
prop_set_guint32(prop_set_t *ps, property_t prop, const guint32 *src,
	size_t offset, size_t length)
{
	gboolean differ = FALSE;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_guint32: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_GUINT32) &&
	   (PROP(ps,prop).type != PROP_TYPE_MULTICHOICE) )
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s or %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_GUINT32].name,
			prop_type_str[PROP_TYPE_MULTICHOICE].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	differ = 0 != memcmp(&PROP(ps,prop).data.guint32.value[offset], src,
					length * sizeof *src);

	if (!differ)
		return;

	/*
	 * Only do bounds-checking on non-vector properties.
	 */
	if (PROP(ps,prop).vector_size == 1) {
		/*
		 * Either check multiple choices or min/max.
		 */
		if (PROP(ps,prop).type == PROP_TYPE_MULTICHOICE) {
			guint n;
			gboolean invalid = TRUE;
			guint32 newval = *src;

			prop_assert(ps, prop, PROP(ps,prop).data.guint32.choices != NULL);

			for (n = 0; PROP(ps,prop).data.guint32.choices[n].title; n++) {
				if (PROP(ps,prop).data.guint32.choices[n].value == newval) {
					invalid = FALSE;
					break;
				}
			}

			if (invalid) {
				g_warning("prop_set_guint32: [%s] new value is invalid choice "
					"%u (leaving at %u)",
					PROP(ps,prop).name, newval,
					*PROP(ps,prop).data.guint32.value);
			} else {
				*PROP(ps,prop).data.guint32.value = newval;
			}
		} else {

			prop_assert(ps, prop, PROP(ps,prop).data.guint32.choices == NULL);

			if (
				(PROP(ps,prop).data.guint32.min <= *src) &&
				(PROP(ps,prop).data.guint32.max >= *src)
			) {
				*PROP(ps,prop).data.guint32.value = *src;
			} else {
				guint32 newval = *src;

				if (newval > PROP(ps,prop).data.guint32.max)
					newval = PROP(ps,prop).data.guint32.max;
				if (newval < PROP(ps,prop).data.guint32.min)
					newval = PROP(ps,prop).data.guint32.min;

				g_warning("prop_set_guint32: [%s] new value out of bounds "
					"(%u/%u): %u (adjusting to %u)",
					PROP(ps,prop).name,
					PROP(ps,prop).data.guint32.min,
					PROP(ps,prop).data.guint32.max,
					*src, newval );

				*PROP(ps,prop).data.guint32.value = newval;
			}
		}
	} else {
		memcpy(&PROP(ps,prop).data.guint32.value[offset], src,
			length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;

		printf("updated property [%s] = ( ", PROP(ps,prop).name);

		for (n = 0; n < PROP(ps,prop).vector_size; n++) {
			printf("%u%s ", PROP(ps,prop).data.guint32.value[n],
					(n < (PROP(ps,prop).vector_size-1)) ? "," : "");
		}

		printf(")\n");
	}

	prop_emit_prop_changed(ps, prop);
}

guint32 *
prop_get_guint32(prop_set_t *ps, property_t prop, guint32 *t,
	size_t offset, size_t length)
{
	guint32 *target;
	size_t n;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_guint32: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_GUINT32) &&
	   (PROP(ps,prop).type != PROP_TYPE_MULTICHOICE) )
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s or %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_GUINT32].name,
			prop_type_str[PROP_TYPE_MULTICHOICE].name);

   	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	memcpy(target, &PROP(ps,prop).data.guint32.value[offset], n);

	return target;
}

void
prop_set_timestamp(prop_set_t *ps, property_t prop, const time_t *src,
	size_t offset, size_t length)
{
	gboolean differ = FALSE;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_timestamp: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_TIMESTAMP) )
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_TIMESTAMP].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	differ = 0 != memcmp(&PROP(ps,prop).data.timestamp.value[offset], src,
					length * sizeof *src);

	if (!differ)
		return;

	/*
	 * Only do bounds-checking on non-vector properties.
	 */
	if (PROP(ps,prop).vector_size == 1) {
		/*
		 * Either check multiple choices or min/max.
		 */
			prop_assert(ps, prop, PROP(ps,prop).data.timestamp.choices == NULL);

			if (
				(PROP(ps,prop).data.timestamp.min <= *src) &&
				(PROP(ps,prop).data.timestamp.max >= *src)
			) {
				*PROP(ps,prop).data.timestamp.value = *src;
			} else {
				gchar buf[64];
				time_t newval = *src;

				if (newval > PROP(ps,prop).data.timestamp.max)
					newval = PROP(ps,prop).data.timestamp.max;
				if (newval < PROP(ps,prop).data.timestamp.min)
					newval = PROP(ps,prop).data.timestamp.min;

				concat_strings(buf, sizeof buf,
					uint64_to_string(PROP(ps,prop).data.timestamp.min), "/",
					uint64_to_string2(PROP(ps,prop).data.timestamp.max),
					(void *) 0);
				g_warning("prop_set_timestamp: [%s] new value out of bounds "
					"(%s): %s (adjusting to %s)", PROP(ps,prop).name, buf,
					uint64_to_string(*src), uint64_to_string2(newval));

				*PROP(ps,prop).data.timestamp.value = newval;
			}
	} else {
		memcpy(&PROP(ps,prop).data.timestamp.value[offset], src,
			length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;

		printf("updated property [%s] = ( ", PROP(ps,prop).name);

		for (n = 0; n < PROP(ps,prop).vector_size; n++) {
			printf("%s%s ",
				uint64_to_string(PROP(ps,prop).data.timestamp.value[n]),
				n < (PROP(ps,prop).vector_size-1) ? "," : "");
		}

		printf(")\n");
	}

	prop_emit_prop_changed(ps, prop);
}

time_t *
prop_get_timestamp(prop_set_t *ps, property_t prop, time_t *t,
	size_t offset, size_t length)
{
	time_t *target;
	size_t n;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_timestamp: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_TIMESTAMP))
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_TIMESTAMP].name);

   if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	memcpy(target, &PROP(ps,prop).data.timestamp.value[offset], n);

	return target;
}

void
prop_set_ip(prop_set_t *ps, property_t prop, const host_addr_t *src,
	size_t offset, size_t length)
{
	gboolean differ = FALSE;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_ip: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_IP) )
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_IP].name);

	if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	differ = 0 != memcmp(&PROP(ps,prop).data.ip.value[offset], src,
					length * sizeof *src);

	if (!differ)
		return;

	/*
	 * Only do bounds-checking on non-vector properties.
	 */
	memcpy(&PROP(ps,prop).data.ip.value[offset], src, length * sizeof *src);

	if (debug >= 5) {
		size_t n;

		printf("updated property [%s] = ( ", PROP(ps,prop).name);

		for (n = 0; n < PROP(ps,prop).vector_size; n++) {
			printf("%s%s ",
				host_addr_to_string(PROP(ps,prop).data.ip.value[n]),
				n < (PROP(ps,prop).vector_size-1) ? "," : "");
		}

		printf(")\n");
	}

	prop_emit_prop_changed(ps, prop);
}


host_addr_t *
prop_get_ip(prop_set_t *ps, property_t prop, host_addr_t *t,
	size_t offset, size_t length)
{
	host_addr_t *target;
	size_t n;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_ip: unknown property %d", prop);
	if ((PROP(ps,prop).type != PROP_TYPE_IP))
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_IP].name);

   if (length == 0)
		length = PROP(ps,prop).vector_size;

	prop_assert(ps, prop, offset + length <= PROP(ps,prop).vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	memcpy(target, &PROP(ps,prop).data.ip.value[offset], n);

	return target;
}


void
prop_set_storage(prop_set_t *ps, property_t prop, const gchar *src,
	size_t length)
{
	gboolean differ = FALSE;

	g_assert(ps != NULL);
	g_assert(src != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_set_storage: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_STORAGE)
		g_error("Type mismatch setting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_STORAGE].name);

	prop_assert(ps, prop, length == PROP(ps,prop).vector_size);

	differ = 0 != memcmp(PROP(ps,prop).data.storage.value, src, length);

	if (!differ)
		return;

	memcpy(PROP(ps,prop).data.storage.value, src, length);

	if (debug >= 5) {
		printf("updated property [%s] (binary)\n", PROP(ps,prop).name);
		dump_hex(stderr, PROP(ps,prop).name,
			(const gchar *) PROP(ps,prop).data.storage.value,
			PROP(ps,prop).vector_size);
	}

	prop_emit_prop_changed(ps, prop);
}

gchar *
prop_get_storage(prop_set_t *ps, property_t prop, gchar *t, size_t length)
{
	gpointer target;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_storage: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_STORAGE)
		g_error("Type mismatch getting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_STORAGE].name);

	prop_assert(ps, prop, length == PROP(ps,prop).vector_size);

	target = t != NULL ? (gpointer) t : g_malloc(length);
	memcpy(target, PROP(ps,prop).data.storage.value, length);

	return target;
}

void
prop_set_string(prop_set_t *ps, property_t prop, const gchar *val)
{
	gchar *old;
	gboolean differ = FALSE;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_gchar: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_STRING)
		g_error("Type mismatch getting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_STRING].name);

	prop_assert(ps, prop, PROP(ps,prop).vector_size == 1);

	old = *PROP(ps,prop).data.string.value;

	if (val == NULL) {
		/*
		 * Clear property.
		 */
		if (old != NULL) {
			G_FREE_NULL(old);
			differ = TRUE;
		}
	} else {
		/*
		 * Update property.
		 */
		if (old != NULL) {
			differ = strcmp(old, val) != 0;
			G_FREE_NULL(old);
		} else {
			differ = TRUE;
		}
		*PROP(ps,prop).data.string.value = g_strdup(val);
	}

	if (differ && debug >= 5)
		printf("updated property [%s] = \"%s\"\n",
			PROP(ps,prop).name,
			*PROP(ps,prop).data.string.value);

	if (differ)
		prop_emit_prop_changed(ps, prop);
}

/**
 * Fetches the value of a string property. If a string buffer is provided
 * (t != NULL), then this is used. The size indicates the size of the given
 * string buffer and may not be 0 in this case. The pointer which is
 * returned will point to the given buffer.
 *
 * If no string buffer is given (t == NULL), new memory is allocated and
 * returned. This memory must be free'ed later. The size parameter has
 * no effect in this case.
 */
gchar *
prop_get_string(prop_set_t *ps, property_t prop, gchar *t, size_t size)
{
	gchar *target;
	gchar *s;

	g_assert(ps != NULL);
	g_assert(NULL == t || size > 0);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_gchar: unknown property %d", prop);
	if (PROP(ps,prop).type != PROP_TYPE_STRING)
		g_error("Type mismatch getting value for [%s] of type"
			" %s when %s was expected",
			PROP(ps,prop).name,
			prop_type_str[PROP(ps,prop).type].name,
			prop_type_str[PROP_TYPE_STRING].name);

	s = *PROP(ps,prop).data.string.value;

	target = t;
	if (target == NULL) {
		/*
		 * Create new string.
		 */
		target = g_strdup(s);
	} else {
		/*
		 * Use given string buffer.
		 */
		if (s == NULL) {
			target[0] = '\0';
			target = NULL;
		} else {
			g_strlcpy(target, s, size);
		}
	}

	return target;
}

/**
 * Fetch the property name in the config files.
 *
 * @return The human-readable name of the property. There is not need
 *         to copy the returned string as it points to a "static const"
 *		   buffer.
 */
const gchar *
prop_name(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).name;
}

/**
 * Fetch the property description in the config files.
 *
 * @return The human-readable name of the property. There is not need
 *         to copy the returned string as it points to a "static const"
 *		   buffer.
 */
const gchar *
prop_description(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).desc;
}

/**
 * Fetch the property type.
 *
 * @return The human-readable name of the property. There is not need
 *         to copy the returned string as it points to a "static const"
 *		   buffer.
 */
const gchar *
prop_type_to_string(prop_set_t *ps, property_t prop)
{
	g_assert(PROP(ps,prop).type < NUM_PROP_TYPES);
	STATIC_ASSERT(NUM_PROP_TYPES == G_N_ELEMENTS(prop_type_str));
	return prop_type_str[PROP(ps,prop).type].name;
}

gboolean
prop_is_saved(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).save;
}

/**
 * Fetches the value of property as a string.
 */
const gchar *
prop_to_string(prop_set_t *ps, property_t prop)
{
	static gchar s[4096];

	g_assert(ps != NULL);

	if (!prop_in_range(ps, prop))
		g_error("prop_get_gchar: unknown property %u", prop);

	switch (PROP(ps,prop).type) {
	case PROP_TYPE_GUINT32:
		{
			guint32 val;

			prop_get_guint32(ps, prop, &val, 0, 1);
			gm_snprintf(s, sizeof(s), "%u", val);
		}
		break;
	case PROP_TYPE_GUINT64:
		{
			guint64 val;

			prop_get_guint64(ps, prop, &val, 0, 1);
			uint64_to_string_buf(val, s, sizeof s);
		}
		break;
	case PROP_TYPE_TIMESTAMP:
		{
			time_t val;

			prop_get_timestamp(ps, prop, &val, 0, 1);
			timestamp_to_string_buf(val, s, sizeof s);
		}
		break;
	case PROP_TYPE_STRING:
		{
			gchar *buf = prop_get_string(ps, prop, NULL, 0);

			g_strlcpy(s, buf ? buf : "", sizeof s);
			G_FREE_NULL(buf);
		}
		break;
	case PROP_TYPE_IP:
		{
			host_addr_t addr;

			prop_get_ip(ps, prop, &addr, 0, 1);
			host_addr_to_string_buf(addr, s, sizeof s);
		}
		break;
	case PROP_TYPE_BOOLEAN:
		{
			gboolean val;

			prop_get_boolean(ps, prop, &val, 0, 1);
			g_strlcpy(s, val ? "TRUE" : "FALSE", sizeof s);
		}
		break;
	case PROP_TYPE_MULTICHOICE:
		{
			guint n = 0;

			while (
				(PROP(ps, prop).data.guint32.choices[n].title != NULL) &&
				(PROP(ps, prop).data.guint32.choices[n].value !=
				 *(PROP(ps, prop).data.guint32.value))
			  )
				n++;

			if (PROP(ps, prop).data.guint32.choices[n].title != NULL)
				gm_snprintf(s, sizeof s, "%u: %s",
						*(PROP(ps, prop).data.guint32.value),
						PROP(ps,prop).data.guint32.choices[n].title);
			else
				gm_snprintf(s, sizeof s,
						"%u: No descriptive string found for this value",
						*(PROP(ps, prop).data.guint32.value));
		}
		break;
	case PROP_TYPE_STORAGE:
		g_strlcpy(s, guid_hex_str(prop_get_storage(ps, prop, NULL,
			PROP(ps,prop).vector_size)), sizeof s);
		break;
	default:
		s[0] = '\0';
		g_error("update_entry_gnet: incompatible type %s",
			prop_type_str[PROP(ps,prop).type].name);
	}

	return s;
}

/**
 * Fetches the default value of property as a string.
 */
const gchar *
prop_default_to_string(prop_set_t *ps, property_t prop)
{
	static gchar s[4096];
	const prop_def_t *p = &PROP(ps, prop);
	
	switch (p->type) {
	case PROP_TYPE_GUINT32:
		gm_snprintf(s, sizeof s, "%u", (guint) p->data.guint32.def[0]);
		break;
	case PROP_TYPE_GUINT64:
		uint64_to_string_buf(p->data.guint64.def[0], s, sizeof s);
		break;
	case PROP_TYPE_TIMESTAMP:
		uint64_to_string_buf(p->data.timestamp.def[0], s, sizeof s);
		break;
	case PROP_TYPE_STRING:
		g_strlcpy(s, *p->data.string.def ? *p->data.string.def : "", sizeof s);
		break;
	case PROP_TYPE_IP:
		g_strlcpy(s, "", sizeof s);
		break;
	case PROP_TYPE_BOOLEAN:
		g_strlcpy(s, p->data.boolean.def[0] ? "TRUE" : "FALSE", sizeof s);
		break;
	case PROP_TYPE_MULTICHOICE:
		{
			guint n = 0;

			while (
				p->data.guint32.choices[n].title != NULL &&
				p->data.guint32.choices[n].value != *p->data.guint32.def
			  )
				n++;

			if (p->data.guint32.choices[n].title != NULL)
				gm_snprintf(s, sizeof s, "%u: %s",
					*(p->data.guint32.def), p->data.guint32.choices[n].title);
			else
				gm_snprintf(s, sizeof s,
					"%u: No descriptive string found for this value",
					*(p->data.guint32.def));
		}
		break;
	case PROP_TYPE_STORAGE:
		g_strlcpy(s, guid_hex_str(prop_get_storage(ps, prop, NULL,
			PROP(ps,prop).vector_size)), sizeof s);
		break;
	default:
		s[0] = '\0';
		g_error("update_entry_gnet: incompatible type %s",
			prop_type_str[PROP(ps,prop).type].name);
	}

	return s;
}


/**
 * @return "TRUE" or "FALSE" depending on the given boolean value.
 */
static const gchar *
config_boolean(gboolean b)
{
	static const gchar b_true[] = "TRUE", b_false[] = "FALSE";
	return b ? b_true : b_false;
}

/**
 * Creates a string containing a set of lines from with words taken from s,
 * each line no longer than about 72 characters unless there is no whitespace
 * within 72 characters (e.g. Japanese). Every line is prepended with "# ".
 * A final newline is NOT appended.
 *
 * @return A newly allocated string holding the formatted comment.
 */
static gchar *
config_comment(const gchar *s)
{
	const gchar *word;
	size_t line_len;
	GString *out;

	g_assert(s != NULL);

	out = g_string_new(NULL);
	word = skip_ascii_spaces(s); /* Ignore leading whitespace. */
	line_len = 0;

	while ('\0' != word[0]) {
		static const size_t max_len = 72;
		const gchar *endptr;
		size_t word_len;

		endptr = skip_ascii_non_spaces(word);
		word_len = endptr - word;
		if (line_len >= max_len || word_len >= max_len - line_len) {
			if (line_len > 0)
				g_string_append_c(out, '\n');
			line_len = 0;
		}
		if (0 == line_len) {
			g_string_append_c(out, '#');
			line_len++;
		}
		/* All kind of ASCII whitespace is normalized to a single space. */
		g_string_append_c(out, ' ');
		line_len++;
		g_string_append_len(out, word, word_len);
		line_len += word_len;
		word = skip_ascii_spaces(endptr);
	}

	return gm_string_finalize(out);
}

/**
 * Like prop_save_to_file(), but only perform when dirty, i.e. when at least
 * one persisted property changed since the last time we saved.
 */
void
prop_save_to_file_if_dirty(prop_set_t *ps, const gchar *dir,
	const gchar *filename)
{
	if (!ps->dirty)
		return;

	prop_save_to_file(ps, dir, filename);
}

/**
 * Read the all properties from the given property set and stores them
 * along with their description to the given file in the given directory.
 * If this file was modified since the property set was read from it at
 * startup, the modifies file will be renamed to [filename].old before
 * saving.
 */
void
prop_save_to_file(prop_set_t *ps, const gchar *dir, const gchar *filename)
{
	FILE *config;
	struct stat sb;
	gchar *newfile;
	gchar *pathname;
	guint n;

	g_assert(filename != NULL);
	g_assert(ps != NULL);

	if (debug >= 2)
		printf("saving %s to %s%s%s\n", ps->name,
			dir, G_DIR_SEPARATOR_S, filename);

	if (!is_directory(dir))
		return;

	pathname = make_pathname(dir, filename);
	if (-1 == stat(pathname, &sb)) {
		g_warning("could not stat \"%s\": %s", pathname, g_strerror(errno));
	} else {
		/*
		 * Rename old config file if they changed it whilst we were running.
		 */

		if (ps->mtime && delta_time(sb.st_mtime, ps->mtime) > 0) {
			gchar *old = g_strconcat(pathname, ".old", (void *) 0);
			g_warning("config file \"%s\" changed whilst I was running",
				pathname);
			if (-1 == rename(pathname, old))
				g_warning("unable to rename as \"%s\": %s",
					old, g_strerror(errno));
			else
				g_warning("renamed old copy as \"%s\"", old);
			G_FREE_NULL(old);
		}
	}

	/*
	 * Create new file, which will be renamed at the end, so we don't
	 * clobber a good configuration file should we fail abruptly.
	 */

	newfile = g_strconcat(pathname, ".new", (void *) 0);
	config = file_fopen(newfile, "w");

	if (config == NULL)
		goto end;

	fprintf(config,
			"#\n# gtk-gnutella %s%s (%s) by Olrick & Co.\n# %s\n#\n",
			GTA_VERSION_NUMBER,
#ifdef GTA_REVISION
			" " GTA_REVISION,
#else
			"",
#endif
			GTA_RELEASE, GTA_WEBSITE);

	{
		gchar *comment = config_comment(ps->desc);

		fprintf(config,
			"#\n# Description of contents\n"
			"%s\n\n",
			comment);
		G_FREE_NULL(comment);
	}

	for (n = 0; n < ps->size; n++) {
		prop_def_t *p = &ps->props[n];
		gchar **vbuf;
		guint i;
		gchar sbuf[1024];
		gchar *val = NULL;
		gboolean quotes = FALSE;
		gboolean defaultvalue = TRUE;

		if (p->save == FALSE)
			continue;

		vbuf = g_new(gchar*, p->vector_size+1);
		vbuf[0] = NULL;

		{
			gchar *comment = config_comment(p->desc);

			fprintf(config, "%s\n", comment);
			G_FREE_NULL(comment);
		}

		switch (p->type) {
		case PROP_TYPE_BOOLEAN:
			for (i = 0; i < p->vector_size; i++) {
				gboolean v;

				v = p->data.boolean.value[i];
				if (v != p->data.boolean.def[i])
					defaultvalue = FALSE;
				vbuf[i] = g_strdup(config_boolean(v));
			}
			vbuf[p->vector_size] = NULL;

			val = g_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_MULTICHOICE:
		case PROP_TYPE_GUINT32:
			for (i = 0; i < p->vector_size; i++) {
				guint32 v;

				v = p->data.guint32.value[i];
				if (v != p->data.guint32.def[i])
					defaultvalue = FALSE;
				gm_snprintf(sbuf, sizeof(sbuf), "%u", v);
				vbuf[i] = g_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;

			val = g_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_GUINT64:
			for (i = 0; i < p->vector_size; i++) {
				guint64 v;

				v = p->data.guint64.value[i];
				if (v != p->data.guint64.def[i])
					defaultvalue = FALSE;

				uint64_to_string_buf(v, sbuf, sizeof sbuf);
				vbuf[i] = g_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;

			val = g_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_TIMESTAMP:
			for (i = 0; i < p->vector_size; i++) {
				time_t t;

				t = p->data.timestamp.value[i];
				if (t != p->data.timestamp.def[i])
					defaultvalue = FALSE;

				timestamp_to_string_buf(t, sbuf, sizeof sbuf);
				vbuf[i] = g_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;
			val = g_strjoinv(",", vbuf);
			quotes = TRUE;
			break;
		case PROP_TYPE_STRING:
			val = g_strdup(*p->data.string.value);
			if (
				(val == NULL && *p->data.string.def != NULL) ||
				(val != NULL && *p->data.string.def == NULL) ||
				0 != strcmp(val, *p->data.string.def)
			)
				defaultvalue = FALSE;
			quotes = TRUE;
			break;
		case PROP_TYPE_IP:
			for (i = 0; i < p->vector_size; i++) {
				host_addr_t addr;

				addr = p->data.ip.value[i];
				vbuf[i] = g_strdup(host_addr_to_string(addr));
			}
			vbuf[p->vector_size] = NULL;

			val = g_strjoinv(",", vbuf);
			quotes = TRUE;
			defaultvalue = FALSE;
			break;
		case PROP_TYPE_STORAGE:
			{
				const guchar *data = p->data.storage.value;

				val = g_malloc((p->vector_size * 2) + 1);

				for (i = 0; i < p->vector_size; i++) {
					static const char hex_alphabet_lower[] = "0123456789abcdef";
					gint c = data[i];

					val[i * 2] = hex_alphabet_lower[c >> 4];
					val[i * 2 + 1] = hex_alphabet_lower[c & 0x0f];
				}

				val[i * 2] = '\0';
				quotes = TRUE;

				/* No default values for storage type properties. */
				defaultvalue = FALSE;
			}
			break;
		case NUM_PROP_TYPES:
			g_assert_not_reached();
		}

		g_assert(val != NULL);

		fprintf(config, "%s%s = %s%s%s\n\n", defaultvalue ? "#" : "",
			p->name, quotes ? "\"" : "", val, quotes ? "\"" : "");

		G_FREE_NULL(val);
		g_strfreev(vbuf);
	}

	fprintf(config, "### End of configuration file ###\n");

	/*
	 * Rename saved configuration file on success.
	 */

	if (0 == fclose(config)) {
		ps->dirty = FALSE;
		if (-1 == rename(newfile, pathname))
			g_warning("could not rename %s as %s: %s",
				newfile, pathname, g_strerror(errno));
		ps->mtime = tm_time_exact();
	} else
		g_warning("could not flush %s: %s", newfile, g_strerror(errno));

end:
	G_FREE_NULL(newfile);
	G_FREE_NULL(pathname);
}

/**
 * Called by prop_load_from_file to actually set the properties.
 */
void
prop_set_from_string(prop_set_t *ps, property_t prop, const gchar *val,
	gboolean saved_only)
{
	prop_def_t *p;
	prop_set_stub_t *stub;
	static union {
		gboolean	boolean[100];
		guint32		uint32[100];
		guint64		uint64[100];
		time_t		timestamp[100];
		host_addr_t	addr[100];
	} vecbuf;

	g_assert(NULL != ps);
	g_assert(NULL != val);
	g_return_if_fail(prop >= ps->offset && prop < ps->offset + ps->size);

	p = &PROP(ps, prop);
	g_return_if_fail(NULL != p);

	if (!p->save && saved_only) {
		g_warning("Refusing to load run-time only property \"%s\"", p->name);
		return;
	}

	stub = ps->get_stub();

	switch (p->type) {
	case PROP_TYPE_BOOLEAN:
		prop_assert(ps, prop,
			p->vector_size * sizeof(gboolean) < sizeof(vecbuf.boolean));

		/* Initialize vector with defaults */
		stub->boolean.get(prop, vecbuf.boolean, 0, 0);
		prop_parse_boolean_vector(p->name, val, p->vector_size, vecbuf.boolean);
		stub->boolean.set(prop, vecbuf.boolean, 0, 0);
		break;
	case PROP_TYPE_MULTICHOICE:
	case PROP_TYPE_GUINT32:
		prop_assert(ps, prop,
			p->vector_size * sizeof(guint32) < sizeof(vecbuf.uint32));

		/* Initialize vector with defaults */
		stub->guint32.get(prop, vecbuf.uint32, 0, 0);
		prop_parse_guint32_vector(p->name, val, p->vector_size, vecbuf.uint32);
		stub->guint32.set(prop, vecbuf.uint32, 0, 0);
		break;
	case PROP_TYPE_GUINT64:
		prop_assert(ps, prop,
			p->vector_size * sizeof(guint64) < sizeof(vecbuf.uint64));

		/* Initialize vector with defaults */
		stub->guint64.get(prop, vecbuf.uint64, 0, 0);
		prop_parse_guint64_vector(p->name, val, p->vector_size, vecbuf.uint64);
		stub->guint64.set(prop, vecbuf.uint64, 0, 0);
		break;
	case PROP_TYPE_TIMESTAMP:
		prop_assert(ps, prop,
			p->vector_size * sizeof(time_t) < sizeof(vecbuf.timestamp));

		/* Initialize vector with defaults */
		stub->timestamp.get(prop, vecbuf.timestamp, 0, 0);
		prop_parse_timestamp_vector(p->name, val,
			p->vector_size, vecbuf.timestamp);
		stub->timestamp.set(prop, vecbuf.timestamp, 0, 0);
		break;
	case PROP_TYPE_STRING:
		stub->string.set(prop, val);
		break;
	case PROP_TYPE_IP:
		prop_assert(ps, prop,
			p->vector_size * sizeof(host_addr_t) < sizeof vecbuf.addr);

		/* Initialize vector with defaults */
		stub->ip.get(prop, vecbuf.addr, 0, 0);
		prop_parse_ip_vector(p->name, val, p->vector_size, vecbuf.addr);
		stub->ip.set(prop, vecbuf.addr, 0, 0);
		break;
	case PROP_TYPE_STORAGE:
		{
			gchar s[1024];
			gchar *d, *buf;

			if (p->vector_size > sizeof s) {
				d = g_malloc(p->vector_size);
				buf = d;
			} else {
				d = NULL;
				buf = s;
			}
			if (prop_parse_storage(p->name, val, p->vector_size, buf)) {
				stub->storage.set(prop, buf, p->vector_size);
			}

			G_FREE_NULL(d);
		}
		break;
	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}

	G_FREE_NULL(stub);
}
/**
 * Called by prop_load_from_file to actually set the properties.
 */
static void
load_helper(prop_set_t *ps, property_t prop, const gchar *val)
{
	prop_set_from_string(ps, prop, val, TRUE);
}

void
prop_load_from_file(prop_set_t *ps, const gchar *dir, const gchar *filename)
{
	static const char fmt[] = "Bad line %u in config file, ignored";
	static gchar prop_tmp[4096];
	FILE *config;
	gchar *path;
	guint n = 1;
	struct stat buf;
	gboolean truncated = FALSE;

	g_assert(dir != NULL);
	g_assert(filename != NULL);
	g_assert(ps != NULL);

	if (!is_directory(dir))
		return;

	path = make_pathname(dir, filename);
	config = file_fopen(path, "r");
	if (!config) {
		G_FREE_NULL(path);
		return;
	}

	if (-1 == fstat(fileno(config), &buf))
		g_warning("could open but not fstat \"%s\" (fd #%d): %s",
			path, fileno(config), g_strerror(errno));
	else
		ps->mtime = buf.st_mtime;

	G_FREE_NULL(path);

	/*
	 * Lines should match the following expression:
	 *
	 * ^<keyword>=<value>
	 *
	 * whereas:
	 *
	 * <keyword> matches
	 *
	 * ([[:blank:]]*)[[:alpha:]](([[:alnum:]]|_)*)([[:blank:]]*)
	 *
	 * and <value> matches
	 *
	 * ([[:blank:]]*)(("[^"]*")|([^[:space:]]*))
	 *
	 */
	while (fgets(prop_tmp, sizeof prop_tmp, config)) {
		property_t i;
		gchar *s, *k, *v;
		gint c;

		s = strchr(prop_tmp, '\n');
		if (!s) {
			g_warning("config file, line %u: line too long or unterminated, "
				"ignored", n);
			truncated = TRUE;
			continue;
		}
		n++; /* Increase line counter */
		if (truncated) {
			truncated = FALSE;
			continue;
		}
		*s = '\0';

		k = v = NULL;
		s = prop_tmp;
		/* Skip leading blanks */
		s = skip_ascii_blanks(s);
		c = (guchar) *s;
		if (!is_ascii_alpha(c))	/* <keyword> must start with a letter */
			continue;

		/* Here starts the <keyword> */
		k = s;
		while ((c = (guchar) *s) == '_' || is_ascii_alnum(c))
			s++;

		*s = '\0'; /* Terminate <keyword>, original value is stored in c */
		if (is_ascii_blank(c)) {
			s = skip_ascii_blanks(&s[1]);
			c = (guchar) *s;
		}
		if (c != '=') {
			/* <keyword> must be followed by a '=' and optional blanks */
			g_warning(fmt, n);
			continue;
		}

		g_assert(c == '=' && (*s == '\0' || *s == '='));
		s++; /* Skip '=' (maybe already overwritten with a '\0') */

		/* Skip optional blanks */
		s = skip_ascii_blanks(s);
		c = (guchar) *s;

		if (c == '"') {
			/* Here starts the <value> part (quoted) */
			v = ++s; /* Skip double-quote '"' */

			/* Scan for terminating double-quote '"' */
			s = strchr(s, '"');
			/* Check for proper quote termination */
			if (!s) {
				/* Missing terminating double-quote '"' */
				g_warning(fmt, n);
				continue;
			}
			g_assert(*s == '"');
		} else {
			/* Here starts the <value> part (unquoted) */
			v = s;
			/* The first space terminates the value */
			s = skip_ascii_non_spaces(s);
		}
		c = (guchar) *s;

		g_assert(*s == '\0' || *s == '"' || is_ascii_space(c));
		*s = '\0'; /* Terminate value in case of trailing characters */

		if (common_dbg > 5)
			g_message("k=\"%s\", v=\"%s\"", k, v);

		for (i = 0; i < ps->size; i++)
			if (!ascii_strcasecmp(k, (ps->props[i]).name)) {
				load_helper(ps, i + ps->offset, v);
				break;
			}

		if (i >= ps->size)
			g_warning("config file, line %u: unknown keyword '%s', ignored",
				n, k);
	}

	fclose(config);
}

property_t
prop_get_by_name(prop_set_t *ps, const gchar *name)
{
	g_assert(ps != NULL);

	return GPOINTER_TO_UINT(g_hash_table_lookup(ps->byName, name));
}

GSList *
prop_get_by_regex(prop_set_t *ps, const gchar *pattern, gint *error)
{
	GSList *sl = NULL;
	size_t i;
	regex_t re;
	gint ret;

	g_assert(NULL != ps);
	g_assert(NULL != pattern);

	ret = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB);
	if (0 != ret) {
		if (error)
			*error = ret;
		goto done;
	}

	g_assert(ps->offset + ps->size - 1 < (guint) -1);

	for (i = 0; i < ps->size; i++) {
		if (0 == regexec(&re, ps->props[i].name, 0, NULL, 0)) {
			guint n = ps->offset + i;
			sl = g_slist_prepend(sl, GUINT_TO_POINTER(n));
		}
	}

done:
	regfree(&re);
	return g_slist_reverse(sl);
}


/* vi: set ts=4 sw=4 cindent: */
