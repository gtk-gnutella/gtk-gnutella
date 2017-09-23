/*
 * Copyright (c) 2001-2003, Richard Eckart
 * Copyright (c) 2013, Raphael Manfredi
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

#include "prop.h"

#include "ascii.h"
#include "concat.h"
#include "debug.h"
#include "file.h"
#include "getdate.h"
#include "halloc.h"
#include "hstrfn.h"
#include "misc.h"
#include "mutex.h"
#include "parse.h"
#include "path.h"
#include "product.h"
#include "pslist.h"
#include "sha1.h"
#include "str.h"
#include "stringify.h"
#include "timestamp.h"
#include "tm.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define PROP_FILE_ID	"_id"

#define debug track_props
static guint32 track_props = 0;	/**< XXX need to init lib's props--RAM */

#define PROP_SET_LOCK(s)	spinlock_hidden(&s->lock)
#define PROP_SET_UNLOCK(s)	spinunlock_hidden(&s->lock)

#define PROP_DEF_LOCK(d)	mutex_lock(&d->lock)
#define PROP_DEF_UNLOCK(d)	mutex_unlock(&d->lock)

const struct {
	const char *name;
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
	g_assert_log(x, "property \"%s\"", PROP(ps, prop).name)

typedef int (* prop_parse_func_t)(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i);

static int
prop_parse_guint64(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i)
{
	int error;
	guint64 u;

	u = parse_uint64(str, endptr, 10, &error);
	if (error) {
		s_warning("%s(): (prop=\"%s\") str=\"%s\": %m", G_STRFUNC, name, str);
	} else if (vec) {
		((guint64 *) vec)[i] = u;
	}

	return error;
}

static int
prop_parse_timestamp(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i)
{
	const char *ep;
	int error = 0;
	guint64 u;
	time_t t;

	u = parse_uint64(str, &ep, 10, &error);
	if (error) {
		s_warning("%s(): (prop=\"%s\") str=\"%s\": %m", G_STRFUNC, name, str);
	}
	if (*ep != '-') {
		t = MIN(u + (time_t) 0, TIME_T_MAX + (guint64) 0);
		/* For backwards-compatibility accept raw numeric timestamps */
	} else {
		t = date2time(str, tm_time());
		if ((time_t)-1 == t) {
			error = EINVAL;
		}
		ep = strchr(str, ',');
		ep = ep ? ep : strchr(str, '\0');
	}

	if (!error && vec)
		((time_t *) vec)[i] = t;

	if (endptr)
		*endptr = ep;

	return error;
}


static int
prop_parse_guint32(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i)
{
	int error;
	guint32 u;

	u = parse_uint32(str, endptr, 10, &error);
	if (error) {
		s_warning("%s(): (prop=\"%s\") str=\"%s\": %m", G_STRFUNC, name, str);
	} else if (vec) {
		((guint32 *) vec)[i] = u;
	}

	return error;
}

static int
prop_parse_ip(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i)
{
	host_addr_t addr;
	int error;
	const char *ep;

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
		s_warning("%s(): (prop=\"%s\") str=\"%s\": %m", G_STRFUNC, name, str);
	} else if (vec) {
		((host_addr_t *) vec)[i] = addr;
	}

	return error;
}

/**
 * Parse comma delimited boolean vector (TRUE/FALSE list).
 */
static int
prop_parse_boolean(const char *name,
	const char *str, const char **endptr, gpointer vec, size_t i)
{
	static const struct {
		const char *s;
		const gboolean v;
	} tab[] = {
		{ "0",		FALSE },
		{ "1",		TRUE },
		{ "FALSE",	FALSE },
		{ "TRUE",	TRUE },
	};
	gboolean b = FALSE;
	const char *p = NULL;
	guint j;
	int error = 0;

	g_assert(name);
	g_assert(str);

	for (j = 0; j < N_ITEMS(tab); j++) {
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
		s_warning("%s(): (prop=\"%s\") "
			"str=\"%s\": \"%s\"", G_STRFUNC, name, str, "Not a boolean value");
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
prop_parse_vector(const char *name, const char *str,
	size_t size, gpointer vec, prop_parse_func_t parser)
{
	const char *p = str;
	size_t i;

	g_assert(str != NULL);
	g_assert(vec != NULL);

	for (i = 0; i < size && p; i++) {
		const char *endptr;
		int error;

		p = skip_ascii_spaces(p);
		if ('\0' == *p)
			break;

		error = (*parser)(name, p, &endptr, vec, i);
		endptr = skip_ascii_spaces(endptr);
		if (!error)
			error = ('\0' != *endptr && ',' != *endptr) ? EINVAL : 0;

		if (error)
			s_warning("%s(): (prop=\"%s\") str=\"%s\": %m", G_STRFUNC, name, p);

		p = strchr(endptr, ',');
		if (p)
			p++;
	}

	if (i < size)
		s_warning("%s(): (prop=\"%s\") "
			"target initialization incomplete!", G_STRFUNC, name);
}

static void
prop_parse_guint64_vector(const char *name, const char *str,
	size_t size, guint64 *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_guint64);
}

static void
prop_parse_timestamp_vector(const char *name, const char *str,
	size_t size, time_t *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_timestamp);
}


static void
prop_parse_guint32_vector(const char *name, const char *str,
	size_t size, guint32 *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_guint32);
}

static void
prop_parse_ip_vector(const char *name, const char *str,
	size_t size, host_addr_t *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_ip);
}

static void
prop_parse_boolean_vector(const char *name, const char *str,
	size_t size, gboolean *vec)
{
	prop_parse_vector(name, str, size, vec, prop_parse_boolean);
}


/**
 * Parse a hex string into a char array.
 *
 * @return TRUE if the data was fully parsed. FALSE on failure.
 */
static gboolean
prop_parse_storage(const char *name, const char *str, size_t size, char *t)
{
	size_t i;

	g_assert(size > 0);
	if (size * 2 != strlen(str)) {
		s_warning("%s(): (prop=\"%s\") %s (length=%zu, expected %zu): \"%s\"",
			G_STRFUNC, name, "storage does not match requested size",
			strlen(str), size * 2, str);
		return FALSE;
	}

	for (i = 0; i < size; i++) {
		char h, l;

		h = str[i * 2];
		l = str[i * 2 + 1];
		if (!is_ascii_xdigit(h) || !is_ascii_xdigit(l)) {
			t[i] = '\0';
			s_warning("%s(): (prop=\"%s\") "
				"storage is damaged: \"%s\"", G_STRFUNC, name, str);
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
 * Lock property.
 */
void
prop_lock(prop_set_t *ps, property_t p)
{
	prop_def_t *d;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, p))
		g_error("%s(): unknown property %u", G_STRFUNC, p);

	d = &PROP(ps, p);

	mutex_lock(&d->lock);
}

/**
 * Unlock property.
 */
void
prop_unlock(prop_set_t *ps, property_t p)
{
	prop_def_t *d;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, p))
		g_error("%s(): unknown property %u", G_STRFUNC, p);

	d = &PROP(ps, p);

	g_assert_log(mutex_is_owned(&d->lock),
		"%s(): attempt to unlock property %u which is not owned", G_STRFUNC, p);

	mutex_unlock(&d->lock);
}

/**
 * Copy the property definition from the property set and return it.
 * Use the prop_free_def call to free the memory again. A simple hfree
 * won't do, since there are lot's of pointers to allocated memory
 * in the definition structure.
 *
 * The prop_changed_listeners field will always be NULL in the copy.
 */
prop_def_t *
prop_get_def(prop_set_t *ps, property_t p)
{
	prop_def_t *d, *buf;

	g_assert(ps != NULL);

	if (!prop_in_range(ps, p))
		g_error("%s(): unknown property %u", G_STRFUNC, p);

	d = &PROP(ps, p);

	PROP_DEF_LOCK(d);

	buf = WCOPY(d);
	buf->name = h_strdup(d->name);
	buf->desc = h_strdup(d->desc);
	buf->ev_changed = NULL;
	mutex_init(&buf->lock);

	switch (buf->type) {
	case PROP_TYPE_BOOLEAN:
		buf->data.boolean.def =
			HCOPY_ARRAY(d->data.boolean.def, d->vector_size);
		buf->data.boolean.value =
			HCOPY_ARRAY(d->data.boolean.value, d->vector_size);
		break;
	case PROP_TYPE_MULTICHOICE: {
		guint n = 0;

		while (d->data.guint32.choices[n].title != NULL)
			n++;

		n ++; /* Keep space for terminating {NULL, 0} field */

		buf->data.guint32.choices = HCOPY_ARRAY(d->data.guint32.choices, n);

		buf->data.guint32.choices[n-1].title = NULL;
		buf->data.guint32.choices[n-1].value = 0;

		n = 0;
		while (d->data.guint32.choices[n].title != NULL) {
			buf->data.guint32.choices[n].title =
				h_strdup(d->data.guint32.choices[n].title);
			n++;
		}
		/* no break -> continue to PROP_TYPE_GUINT32 */
	}
	case PROP_TYPE_GUINT32:
		buf->data.guint32.def =
			HCOPY_ARRAY(d->data.guint32.def, d->vector_size);
		buf->data.guint32.value =
			HCOPY_ARRAY(d->data.guint32.value, d->vector_size);
		break;

	case PROP_TYPE_GUINT64:
		buf->data.guint64.def =
			HCOPY_ARRAY(d->data.guint64.def, d->vector_size);
		buf->data.guint64.value =
			HCOPY_ARRAY(d->data.guint64.value, d->vector_size);
		break;

	case PROP_TYPE_TIMESTAMP:
		buf->data.timestamp.def =
			HCOPY_ARRAY(d->data.timestamp.def, d->vector_size);
		buf->data.timestamp.value =
			HCOPY_ARRAY(d->data.timestamp.value, d->vector_size);
		break;

	case PROP_TYPE_IP:
		buf->data.ip.value = HCOPY_ARRAY(d->data.ip.value, d->vector_size);
		break;

	case PROP_TYPE_STRING:
		buf->data.string.def	= walloc(sizeof(char *));
		*buf->data.string.def   = h_strdup(*d->data.string.def);
		buf->data.string.value  = walloc(sizeof(char *));
		*buf->data.string.value = h_strdup(*d->data.string.value);
		break;

	case PROP_TYPE_STORAGE:
		buf->data.storage.value = hcopy(d->data.storage.value, d->vector_size);
		break;

	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}

	PROP_DEF_UNLOCK(d);

	return buf;
}

void
prop_free_def(prop_def_t *d)
{
	g_assert(d != NULL);

	mutex_destroy(&d->lock);

	switch (d->type) {
	case PROP_TYPE_BOOLEAN:
		HFREE_NULL(d->data.boolean.value);
		HFREE_NULL(d->data.boolean.def);
		break;
	case PROP_TYPE_MULTICHOICE: {
		guint n = 0;

		while (d->data.guint32.choices[n].title != NULL) {
			HFREE_NULL(d->data.guint32.choices[n].title);
			n++;
		}

		HFREE_NULL(d->data.guint32.choices);
		/* no break -> continue to PROP_TYPE_GUINT32 */
	}
	case PROP_TYPE_GUINT32:
		HFREE_NULL(d->data.guint32.value);
		HFREE_NULL(d->data.guint32.def);
		break;
	case PROP_TYPE_GUINT64:
		HFREE_NULL(d->data.guint64.value);
		HFREE_NULL(d->data.guint64.def);
		break;
	case PROP_TYPE_TIMESTAMP:
		HFREE_NULL(d->data.timestamp.value);
		HFREE_NULL(d->data.timestamp.def);
		break;
	case PROP_TYPE_IP:
		HFREE_NULL(d->data.ip.value);
		break;
	case PROP_TYPE_STRING:
		HFREE_NULL(*d->data.string.value);
		HFREE_NULL(*d->data.string.def);
		WFREE_NULL(d->data.string.value, sizeof(char *));
		WFREE_NULL(d->data.string.def, sizeof(char *));
		break;
	case PROP_TYPE_STORAGE:
		HFREE_NULL(d->data.storage.value);
		break;
	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}
	HFREE_NULL(d->name);
	HFREE_NULL(d->desc);
	WFREE_NULL(d, sizeof *d);
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
	prop_def_t *d;

	d = &PROP(ps, prop);

	PROP_DEF_LOCK(d);
	event_add_subscriber(d->ev_changed, (callback_fn_t) l, freq, interval);
	if (init)
		(*l)(prop);		/* Listener always called with the property locked */

	PROP_DEF_UNLOCK(d);
}

void
prop_remove_prop_changed_listener(
	prop_set_t *ps, property_t prop, prop_changed_listener_t l)
{
	prop_def_t *d;

	d = &PROP(ps, prop);

	PROP_DEF_LOCK(d);
	event_remove_subscriber(d->ev_changed, (callback_fn_t) l);
	PROP_DEF_UNLOCK(d);
}

/*
 * Invoke registered callbacks that trigger when the property is changed.
 */
static void
prop_emit_prop_changed(const prop_def_t *d, prop_set_t *ps, property_t prop)
{
	assert_mutex_is_owned(&d->lock);

	/*
	 * Triggering of callbacks happen with the property definition locked
	 * by the thread.  The callback does not need to bother with locking.
	 */

	event_trigger(d->ev_changed, T_VETO(prop_changed_listener_t, (prop)));

	if (d->save) {
		PROP_SET_LOCK(ps);
		ps->dirty = TRUE;
		PROP_SET_UNLOCK(ps);
	}
}

static void
prop_check_type(const prop_def_t *d, prop_type_t t, bool setting)
{
	/*
	 * For uint32 values, we can also have multi-choice (enum) properties.
	 */

	if (PROP_TYPE_GUINT32 == t) {
		if G_UNLIKELY(PROP_TYPE_MULTICHOICE == d->type)
			return;
	}

	if G_UNLIKELY(d->type != t) {
		g_error("type mismatch %s value for property \"%s\": requesting "
			" %s when actual property type is %s%s",
			setting ? "setting" : "getting",
			d->name, prop_type_str[t].name,
			PROP_TYPE_MULTICHOICE == d->type ? "(multichoice) " : "",
			PROP_TYPE_MULTICHOICE == d->type ?
				prop_type_str[PROP_TYPE_GUINT32].name :
				prop_type_str[d->type].name);
	}
}

void
prop_set_boolean(prop_set_t *ps, property_t prop, const gboolean *src,
	size_t offset, size_t length)
{
	prop_def_t *d;
	gboolean old, new, differ = FALSE;
	size_t n;

	g_assert(src != NULL);
	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_BOOLEAN, TRUE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	PROP_DEF_LOCK(d);

	for (n = 0; (n < length) && !differ; n++) {
		old = d->data.boolean.value[n + offset] ? 1 : 0;
		new = src[n] ? 1 : 0;

		if (old != new)
			differ = TRUE;
	}

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	memcpy(&d->data.boolean.value[offset], src, length * sizeof *src);

	if G_UNLIKELY(debug >= 5) {
		size_t i;
		str_t *s = str_new(120);

		str_printf(s, "updated property [%s] = ( ", d->name);

		for (i = 0; i < d->vector_size; i++)
			str_catf(s, "%s%s ",
				d->data.boolean.value[i] ? "TRUE" : "FALSE",
				i < d->vector_size - 1 ? "," : "");

		str_putc(s, ')');
		s_debug("PROP %s", str_2c(s));
		str_destroy_null(&s);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}

gboolean *
prop_get_boolean(prop_set_t *ps, property_t prop, gboolean *t,
	size_t offset, size_t length)
{
	prop_def_t *d;
	gboolean *target;
	size_t n;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_BOOLEAN, FALSE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	PROP_DEF_LOCK(d);
	memcpy(target, &d->data.boolean.value[offset], n);
	PROP_DEF_UNLOCK(d);

	return target;
}

void
prop_set_guint64(prop_set_t *ps, property_t prop, const guint64 *src,
	size_t offset, size_t length)
{
	prop_def_t *d;
	gboolean differ = FALSE;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_GUINT64, TRUE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	PROP_DEF_LOCK(d);

	differ = 0 != memcmp(&d->data.guint64.value[offset], src,
					length * sizeof *src);

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	/*
	 * Only do bounds-checking on non-vector properties.
	 */

	if (1 == d->vector_size) {
		prop_assert(ps, prop, d->data.guint64.choices == NULL);

		if (d->data.guint64.min <= *src && d->data.guint64.max >= *src) {
			*d->data.guint64.value = *src;
		} else {
			char buf[64];
			guint64 newval = *src;

			if (newval > d->data.guint64.max)
				newval = d->data.guint64.max;
			if (newval < d->data.guint64.min)
				newval = d->data.guint64.min;

			concat_strings(buf, sizeof buf,
				uint64_to_string(d->data.guint64.min), "/",
				uint64_to_string2(d->data.guint64.max),
				NULL_PTR);

			g_carp("%s(): [%s] new value out of bounds "
				"(%s): %s (adjusting to %s)", G_STRFUNC, d->name, buf,
				uint64_to_string(*src), uint64_to_string2(newval));

			*d->data.guint64.value = newval;
		}
	} else {
		memcpy(&d->data.guint64.value[offset], src, length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;
		str_t *s = str_new(120);

		str_printf(s, "updated property [%s] = ( ", d->name);

		for (n = 0; n < d->vector_size; n++) {
			str_catf(s, "%s%s ",
				uint64_to_string(d->data.guint64.value[n]),
				n < d->vector_size - 1 ? "," : "");
		}

		str_putc(s, ')');
		s_debug("PROP %s", str_2c(s));
		str_destroy_null(&s);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}

guint64 *
prop_get_guint64(prop_set_t *ps, property_t prop, guint64 *t,
	size_t offset, size_t length)
{
	prop_def_t *d;
	guint64 *target;
	size_t n;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_GUINT64, FALSE);

   if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	PROP_DEF_LOCK(d);
	memcpy(target, &d->data.guint64.value[offset], n);
	PROP_DEF_UNLOCK(d);

	return target;
}

void
prop_set_guint32(prop_set_t *ps, property_t prop, const guint32 *src,
	size_t offset, size_t length)
{
	prop_def_t *d;
	gboolean differ = FALSE;

	g_assert(src != NULL);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_GUINT32, TRUE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	PROP_DEF_LOCK(d);

	differ = 0 != memcmp(&d->data.guint32.value[offset], src,
					length * sizeof *src);

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	/*
	 * Only do bounds-checking on non-vector properties.
	 */

	if (1 == d->vector_size) {
		/*
		 * Either check multiple choices or min/max.
		 */

		if (PROP_TYPE_MULTICHOICE == d->type) {
			guint n;
			gboolean invalid = TRUE;
			guint32 newval = *src;

			prop_assert(ps, prop, d->data.guint32.choices != NULL);

			for (n = 0; d->data.guint32.choices[n].title; n++) {
				if (d->data.guint32.choices[n].value == newval) {
					invalid = FALSE;
					break;
				}
			}

			if (invalid) {
				s_warning("%s(): [%s] new value is invalid choice "
					"%u (leaving at %u)",
					G_STRFUNC, d->name, newval, *d->data.guint32.value);
			} else {
				*d->data.guint32.value = newval;
			}
		} else {
			prop_assert(ps, prop, d->data.guint32.choices == NULL);

			if (d->data.guint32.min <= *src && d->data.guint32.max >= *src) {
				*d->data.guint32.value = *src;
			} else {
				guint32 newval = *src;

				if (newval > d->data.guint32.max)
					newval = d->data.guint32.max;
				if (newval < d->data.guint32.min)
					newval = d->data.guint32.min;

				g_carp("%s(): [%s] new value out of bounds "
					"(%u/%u): %u (adjusting to %u)",
					G_STRFUNC, d->name,
					d->data.guint32.min, d->data.guint32.max,
					*src, newval);

				*d->data.guint32.value = newval;
			}
		}
	} else {
		memcpy(&d->data.guint32.value[offset], src, length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;
		str_t *s = str_new(120);

		str_printf(s, "updated property [%s] = ( ", d->name);

		for (n = 0; n < d->vector_size; n++) {
			str_catf(s, "%u%s ", d->data.guint32.value[n],
				n < d->vector_size - 1 ? "," : "");
		}

		str_putc(s, ')');
		s_debug("PROP %s", str_2c(s));
		str_destroy_null(&s);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}

guint32 *
prop_get_guint32(prop_set_t *ps, property_t prop, guint32 *t,
	size_t offset, size_t length)
{
	guint32 *target;
	size_t n;
	prop_def_t *d;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_GUINT32, FALSE);

   	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	PROP_DEF_LOCK(d);
	memcpy(target, &d->data.guint32.value[offset], n);
	PROP_DEF_UNLOCK(d);

	return target;
}

void
prop_set_timestamp(prop_set_t *ps, property_t prop, const time_t *src,
	size_t offset, size_t length)
{
	prop_def_t *d;
	gboolean differ = FALSE;

	g_assert(src != NULL);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_TIMESTAMP, TRUE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	PROP_DEF_LOCK(d);

	differ = 0 != memcmp(&d->data.timestamp.value[offset], src,
					length * sizeof *src);

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	/*
	 * Only do bounds-checking on non-vector properties.
	 */

	if (1 == d->vector_size) {
		prop_assert(ps, prop, d->data.timestamp.choices == NULL);

		if (d->data.timestamp.min <= *src && d->data.timestamp.max >= *src) {
			*d->data.timestamp.value = *src;
		} else {
			char buf[64];
			time_t newval = *src;

			if (newval > d->data.timestamp.max)
				newval = d->data.timestamp.max;
			if (newval < d->data.timestamp.min)
				newval = d->data.timestamp.min;

			concat_strings(buf, sizeof buf,
				timestamp_to_string(d->data.timestamp.min), "/",
				timestamp_to_string2(d->data.timestamp.max),
				NULL_PTR);

			g_carp("%s(): [%s] new value out of bounds "
				"(%s): %s (adjusting to %s)", G_STRFUNC, d->name, buf,
				timestamp_to_string(*src), timestamp_to_string2(newval));

			*d->data.timestamp.value = newval;
		}
	} else {
		memcpy(&d->data.timestamp.value[offset], src, length * sizeof *src);
	}

	if (debug >= 5) {
		size_t n;
		str_t *s = str_new(120);

		str_printf(s, "updated property [%s] = ( ", d->name);

		for (n = 0; n < d->vector_size; n++) {
			str_catf(s, "%s%s ",
				timestamp_to_string(d->data.timestamp.value[n]),
				n < d->vector_size - 1 ? "," : "");
		}

		str_putc(s, ')');
		s_debug("PROP %s", str_2c(s));
		str_destroy_null(&s);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}

time_t *
prop_get_timestamp(prop_set_t *ps, property_t prop, time_t *t,
	size_t offset, size_t length)
{
	time_t *target;
	size_t n;
	prop_def_t *d;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_TIMESTAMP, FALSE);

   if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	PROP_DEF_LOCK(d);
	memcpy(target, &d->data.timestamp.value[offset], n);
	PROP_DEF_UNLOCK(d);

	return target;
}

void
prop_set_ip(prop_set_t *ps, property_t prop, const host_addr_t *src,
	size_t offset, size_t length)
{
	gboolean differ = FALSE;
	prop_def_t *d;

	g_assert(src != NULL);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_IP, TRUE);

	if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	PROP_DEF_LOCK(d);

	differ = 0 != memcmp(&d->data.ip.value[offset], src, length * sizeof *src);

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	memcpy(&d->data.ip.value[offset], src, length * sizeof *src);

	if (debug >= 5) {
		size_t n;
		str_t *s = str_new(120);

		str_printf(s, "updated property [%s] = ( ", d->name);

		for (n = 0; n < d->vector_size; n++) {
			str_catf(s, "%s%s ",
				host_addr_to_string(d->data.ip.value[n]),
				n < d->vector_size - 1 ? "," : "");
		}

		str_putc(s, ')');
		s_debug("PROP %s", str_2c(s));
		str_destroy_null(&s);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}


host_addr_t *
prop_get_ip(prop_set_t *ps, property_t prop, host_addr_t *t,
	size_t offset, size_t length)
{
	prop_def_t *d;
	host_addr_t *target;
	size_t n;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_IP, FALSE);

   if (0 == length)
		length = d->vector_size;

	prop_assert(ps, prop, offset + length <= d->vector_size);

	n = length * sizeof *target;
	target = t != NULL ? (gpointer) t : g_malloc(n);
	PROP_DEF_LOCK(d);
	memcpy(target, &d->data.ip.value[offset], n);
	PROP_DEF_UNLOCK(d);

	return target;
}


void
prop_set_storage(prop_set_t *ps, property_t prop, const char *src,
	size_t length)
{
	prop_def_t *d;
	gboolean differ = FALSE;

	g_assert(src != NULL);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STORAGE, TRUE);

	prop_assert(ps, prop, length == d->vector_size);

	PROP_DEF_LOCK(d);

	differ = 0 != memcmp(d->data.storage.value, src, length);

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	memcpy(d->data.storage.value, src, length);

	if (debug >= 5) {
		s_debug("PROP updated property [%s] (binary):", d->name);
		dump_hex(stderr, d->name,
			(const char *) d->data.storage.value, d->vector_size);
	}

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
}

char *
prop_get_storage(prop_set_t *ps, property_t prop, char *t, size_t length)
{
	prop_def_t *d;
	gpointer target;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STORAGE, FALSE);

	prop_assert(ps, prop, length == d->vector_size);

	target = t != NULL ? (gpointer) t : g_malloc(length);
	PROP_DEF_LOCK(d);
	memcpy(target, d->data.storage.value, length);
	PROP_DEF_UNLOCK(d);

	return target;
}

const char *
prop_get_storage_const(prop_set_t *ps, property_t prop)
{
	prop_def_t *d;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STORAGE, FALSE);

	return d->data.storage.value;
}

void
prop_set_string(prop_set_t *ps, property_t prop, const char *val)
{
	prop_def_t *d;
	char *old;
	gboolean differ = FALSE;

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STRING, TRUE);

	prop_assert(ps, prop, d->vector_size == 1);

	PROP_DEF_LOCK(d);

	old = *d->data.string.value;
	if (old && val) {
		differ = 0 != strcmp(old, val);
	} else {
		differ = old != val;
	}

	if (!differ) {
		PROP_DEF_UNLOCK(d);
		return;
	}

	*d->data.string.value = g_strdup(val);
	G_FREE_NULL(old);

	if (debug >= 5)
		s_debug("PROP updated property [%s] = \"%s\"",
			d->name, NULL_STRING(*d->data.string.value));

	prop_emit_prop_changed(d, ps, prop);
	PROP_DEF_UNLOCK(d);
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
char *
prop_get_string(prop_set_t *ps, property_t prop, char *t, size_t size)
{
	prop_def_t *d;
	char *target;
	char *s;

	g_assert(NULL == t || size > 0);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STRING, FALSE);

	PROP_DEF_LOCK(d);

	s = *d->data.string.value;

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
			clamp_strcpy(target, size, s);
		}
	}

	PROP_DEF_UNLOCK(d);
	return target;
}

/**
 * Copy string property to supplied str_t.
 */
static void
prop_string_copy(prop_set_t *ps, property_t prop, str_t *s)
{
	prop_def_t *d;
	char *v;

	str_check(s);

	d = &PROP(ps, prop);

	prop_check_type(d, PROP_TYPE_STRING, FALSE);

	PROP_DEF_LOCK(d);

	v = *d->data.string.value;
	str_cpy(s, v != NULL ? v : "");

	PROP_DEF_UNLOCK(d);
}

/**
 * Fetch the property name in the config files.
 *
 * @return The human-readable name of the property. There is not need
 *         to copy the returned string as it points to a "static const"
 *		   buffer.
 */
const char *
prop_name(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).name;
}

/**
 * Fetch the property type in the config files.
 *
 * @return property type code.
 */
prop_type_t
prop_type(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).type;
}

/**
 * Fetch the property description in the config files.
 *
 * @return The human-readable name of the property. There is not need
 *         to copy the returned string as it points to a "static const"
 *		   buffer.
 */
const char *
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
const char *
prop_type_to_string(prop_set_t *ps, property_t prop)
{
	g_assert(PROP(ps,prop).type < NUM_PROP_TYPES);
	STATIC_ASSERT(NUM_PROP_TYPES == N_ITEMS(prop_type_str));
	return prop_type_str[PROP(ps,prop).type].name;
}

gboolean
prop_is_saved(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).save;
}

gboolean
prop_is_internal(prop_set_t *ps, property_t prop)
{
	return PROP(ps,prop).internal;
}

/**
 * Pretty formatting of property string, with enclosing type markers.
 *
 * @return value from a thread-static buffer.
 */
const char *
prop_to_typed_string(prop_set_t *ps, property_t prop)
{
	str_t *s = str_private(G_STRFUNC, 128);
	const char *before = "", *after = "";

	switch (prop_type(ps, prop)) {
	case PROP_TYPE_BOOLEAN:
	case PROP_TYPE_GUINT32:
	case PROP_TYPE_GUINT64:
		break;
	case PROP_TYPE_STORAGE:
		before = "'"; after = "'";
		break;
	case PROP_TYPE_IP:
		before = "< "; after = " >";
		break;
	case PROP_TYPE_TIMESTAMP:
	case PROP_TYPE_STRING:
		before = after = "\"";
		break;
	case PROP_TYPE_MULTICHOICE:
		before = "{ "; after = " }";
		break;
	case NUM_PROP_TYPES:
		g_assert_not_reached();
	}

	str_printf(s, "%s%s%s", before, prop_to_string(ps, prop), after);

	return str_2c(s);
}

/**
 * Fetches the value of property as a string.
 *
 * @return value from a thread-static buffer.
 */
const char *
prop_to_string(prop_set_t *ps, property_t prop)
{
	prop_def_t *d;
	str_t *s = str_private(G_STRFUNC, 128);
	size_t n;

	d = &PROP(ps, prop);

	switch (d->type) {
	case PROP_TYPE_GUINT32:
		str_reset(s);
		if (d->vector_size != 1)
			str_putc(s, '[');

		for (n = 0; n < d->vector_size; n++) {
			char buf[UINT32_DEC_BUFLEN];
			uint32 val;

			if (n != 0)
				STR_CAT(s, ", ");

			prop_get_guint32(ps, prop, &val, n, 1);
			uint32_to_string_buf(val, buf, sizeof buf);
			str_cat(s, buf);
		}

		if (d->vector_size != 1)
			str_putc(s, ']');
		goto done;
	case PROP_TYPE_GUINT64:
		str_reset(s);
		if (d->vector_size != 1)
			str_putc(s, '[');

		for (n = 0; n < d->vector_size; n++) {
			char buf[UINT64_DEC_BUFLEN];
			uint64 val;

			if (n != 0)
				STR_CAT(s, ", ");

			prop_get_guint64(ps, prop, &val, n, 1);
			uint64_to_string_buf(val, buf, sizeof buf);
			str_cat(s, buf);
		}

		if (d->vector_size != 1)
			str_putc(s, ']');
		goto done;
	case PROP_TYPE_TIMESTAMP:
		str_reset(s);
		if (d->vector_size != 1)
			str_putc(s, '[');

		for (n = 0; n < d->vector_size; n++) {
			char buf[TIMESTAMP_BUFLEN];
			time_t val;

			if (n != 0)
				STR_CAT(s, ", ");

			prop_get_timestamp(ps, prop, &val, n, 1);
			timestamp_to_string_buf(val, buf, sizeof buf);
			str_cat(s, buf);
		}

		if (d->vector_size != 1)
			str_putc(s, ']');
		goto done;
	case PROP_TYPE_STRING:
		prop_string_copy(ps, prop, s);
		goto done;
	case PROP_TYPE_IP:
		str_reset(s);
		if (d->vector_size != 1)
			str_putc(s, '[');

		for (n = 0; n < d->vector_size; n++) {
			char buf[IPV6_ADDR_BUFLEN];		/* Assume the longest (IPv6) */
			host_addr_t addr;

			if (n != 0)
				STR_CAT(s, ", ");

			prop_get_ip(ps, prop, &addr, n, 1);
			host_addr_to_string_buf(addr, buf, sizeof buf);
			str_cat(s, buf);
		}

		if (d->vector_size != 1)
			str_putc(s, ']');
		goto done;
	case PROP_TYPE_BOOLEAN:
		str_reset(s);
		if (d->vector_size != 1)
			str_putc(s, '[');

		for (n = 0; n < d->vector_size; n++) {
			gboolean val;

			if (n != 0)
				STR_CAT(s, ", ");

			prop_get_boolean(ps, prop, &val, n, 1);
			if (val)
				STR_CAT(s, "TRUE");
			else
				STR_CAT(s, "FALSE");
		}

		if (d->vector_size != 1)
			str_putc(s, ']');
		goto done;
	case PROP_TYPE_MULTICHOICE:
		{
			uint i = 0;

			while (
				d->data.guint32.choices[i].title != NULL &&
				d->data.guint32.choices[i].value != *d->data.guint32.value
			  )
				i++;		/* There is a { NULL, 0 } sentinel at the end */

			if (d->data.guint32.choices[i].title != NULL)
				str_printf(s, "%u: %s",
						*d->data.guint32.value,
						d->data.guint32.choices[i].title);
			else
				str_printf(s, "%u: No descriptive string found for this value",
						*d->data.guint32.value);
		}
		goto done;
	case PROP_TYPE_STORAGE:
		{
			size_t len = d->vector_size * 2 + 1;
			char *buf = xmalloc(len);

			bin_to_hex_buf(prop_get_storage_const(ps, prop),
				d->vector_size, buf, len);
			str_cpy(s, buf);
			XFREE_NULL(buf);
		}
		goto done;
	case NUM_PROP_TYPES:
		break;
	}

	s_error("%s(): unknown type %d", G_STRFUNC, d->type);

done:
	return str_2c(s);
}

/**
 * Fetches the default value of property as a string.
 */
const char *
prop_default_to_string(prop_set_t *ps, property_t prop)
{
	str_t *s = str_private(G_STRFUNC, 128);
	const prop_def_t *p = &PROP(ps, prop);

	/* Default value is a constant, no need to lock */

	switch (p->type) {
	case PROP_TYPE_GUINT32:
		str_printf(s, "%u", (guint) p->data.guint32.def[0]);
		goto done;
	case PROP_TYPE_GUINT64:
		{
			char buf[UINT64_DEC_BUFLEN];
			uint64_to_string_buf(p->data.guint64.def[0], buf, sizeof buf);
			str_cpy(s, buf);
		}
		goto done;
	case PROP_TYPE_TIMESTAMP:
		{
			char buf[UINT64_DEC_BUFLEN];
			uint64_to_string_buf(p->data.timestamp.def[0], buf, sizeof buf);
			str_cpy(s, buf);
		}
		goto done;
	case PROP_TYPE_STRING:
		str_cpy(s, *p->data.string.def ? *p->data.string.def : "");
		goto done;
	case PROP_TYPE_IP:
	case PROP_TYPE_STORAGE:
		str_reset(s);		/* No default value for these types */
		goto done;
	case PROP_TYPE_BOOLEAN:
		if (p->data.boolean.def[0])
			STR_CPY(s, "TRUE");
		else
			STR_CPY(s, "FALSE");
		goto done;
	case PROP_TYPE_MULTICHOICE:
		{
			guint n = 0;

			while (
				p->data.guint32.choices[n].title != NULL &&
				p->data.guint32.choices[n].value != *p->data.guint32.def
			  )
				n++;

			if (p->data.guint32.choices[n].title != NULL)
				str_printf(s, "%u: %s",
					*(p->data.guint32.def), p->data.guint32.choices[n].title);
			else
				str_printf(s, "%u: No descriptive string found for this value",
					*(p->data.guint32.def));
		}
		goto done;
	case NUM_PROP_TYPES:
		break;
	}

	s_error("%s(): unknown type %d", G_STRFUNC, p->type);

done:
	return str_2c(s);
}

/**
 * @return "TRUE" or "FALSE" depending on the given boolean value.
 */
static inline const char *
config_boolean(gboolean b)
{
	static const char b_true[] = "TRUE", b_false[] = "FALSE";
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
static char *
config_comment(const char *s)
{
	const char *word;
	size_t line_len;
	str_t *out;

	g_assert(s != NULL);

	out = str_new(0);
	word = skip_ascii_spaces(s); /* Ignore leading whitespace. */
	line_len = 0;

	while ('\0' != word[0]) {
		static const size_t max_len = 72;
		const char *endptr;
		size_t word_len;

		endptr = skip_ascii_non_spaces(word);
		word_len = endptr - word;
		if (line_len >= max_len || word_len >= max_len - line_len) {
			if (line_len > 0)
				str_putc(out, '\n');
			line_len = 0;
		}
		if (0 == line_len) {
			str_putc(out, '#');
			line_len++;
		}
		/* All kind of ASCII whitespace is normalized to a single space. */
		str_putc(out, ' ');
		line_len++;
		str_cat_len(out, word, word_len);
		line_len += word_len;
		word = skip_ascii_spaces(endptr);
	}

	return str_s2c_null(&out);
}

/**
 * Generate a unique token representative of the file on the filesystem,
 * based on the device ID and inode number.
 */
static const char *
unique_file_token(const filestat_t *st)
{
	char buf[SHA1_BASE16_SIZE + 1];		/* Hexadecimal format */
	str_t *s = str_private(G_STRFUNC, sizeof buf);
	SHA1_context ctx;
	struct sha1 digest;
	const char *hostname;

	/*
	 * We now include the hostname into the unique file ID to make sure
	 * the internal ID changes even if the file is indirectly copied
	 * through virtual machine cloning for instance (where the device and
	 * inode number would stay the same).
	 *		--RAM, 2015-12-04
	 */

	hostname = local_hostname();

	SHA1_reset(&ctx);
	SHA1_INPUT(&ctx, st->st_dev);
	SHA1_INPUT(&ctx, st->st_ino);
	SHA1_input(&ctx, hostname, strlen(hostname));
	SHA1_result(&ctx, &digest);

	bin_to_hex_buf(digest.data, sizeof digest.data, buf, sizeof buf);
	buf[SHA1_BASE16_SIZE] = '\0';

	str_cpy(s, buf);
	return str_2c(s);
}

/**
 * Like prop_save_to_file(), but only perform when dirty, i.e. when at least
 * one persisted property changed since the last time we saved.
 */
void
prop_save_to_file_if_dirty(prop_set_t *ps, const char *dir,
	const char *filename)
{
	/* NB: we don't take the lock to read the `dirty' flag */

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
prop_save_to_file(prop_set_t *ps, const char *dir, const char *filename)
{
	FILE *config;
	filestat_t sb;
	char *newfile;
	char *pathname;
	guint n;

	g_assert(filename != NULL);
	g_assert(ps != NULL);

	if (debug >= 2) {
		s_debug("PROP saving %s to %s%s%s", ps->name,
			dir, G_DIR_SEPARATOR_S, filename);
	}

	if (!is_directory(dir))
		return;

	pathname = make_pathname(dir, filename);
	if (-1 == stat(pathname, &sb)) {
		s_warning("%s(): could not stat \"%s\": %m", G_STRFUNC, pathname);
	} else {
		/*
		 * Rename old config file if they changed it whilst we were running.
		 */

		if (ps->mtime && delta_time(sb.st_mtime, ps->mtime) > 0) {
			char *old = h_strconcat(pathname, ".old", NULL_PTR);
			s_warning("%s(): config file \"%s\" changed whilst I was running",
				G_STRFUNC, pathname);
			if (-1 == rename(pathname, old))
				s_warning("%s(): unable to rename \"%s\" as \"%s\": %m",
					G_STRFUNC, pathname, old);
			else
				s_warning("%s(): renamed old copy as \"%s\"", G_STRFUNC, old);
			HFREE_NULL(old);
		}
	}

	/*
	 * Create new file, which will be renamed at the end, so we don't
	 * clobber a good configuration file should we fail abruptly.
	 */

	newfile = h_strconcat(pathname, ".new", NULL_PTR);
	config = file_fopen(newfile, "w");

	if (config == NULL)
		goto end;

	{
		const char *revision = product_revision();

		fprintf(config,
			"#\n# gtk-gnutella %s%s%s (%s) by Olrick & Co.\n# %s\n#\n",
			product_version(),
			*revision != '\0' ? " " : "", revision,
			product_date(), product_website());
	}
	{
		char *comment = config_comment(ps->desc);

		fprintf(config,
			"#\n# Description of contents\n"
			"%s\n\n",
			comment);
		HFREE_NULL(comment);
	}

	/*
	 * We're about to save the properties.
	 * Because some properties could be changed during saving by other
	 * threads, we need to clear the dirty indication before starting to
	 * iterate on the properties.
	 */

	PROP_SET_LOCK(ps);
	ps->dirty = FALSE;
	PROP_SET_UNLOCK(ps);

	for (n = 0; n < ps->size; n++) {
		prop_def_t *p = &ps->props[n];
		char **vbuf;
		guint i;
		char sbuf[1024];
		char *val = NULL;
		gboolean quotes = FALSE;
		gboolean defaultvalue = TRUE;

		if (p->save == FALSE)
			continue;

		PROP_DEF_LOCK(p);

		HALLOC_ARRAY(vbuf, p->vector_size + 1);
		vbuf[0] = NULL;

		{
			char *comment = config_comment(p->desc);

			fprintf(config, "%s\n", comment);
			HFREE_NULL(comment);
		}

		switch (p->type) {
		case PROP_TYPE_BOOLEAN:
			for (i = 0; i < p->vector_size; i++) {
				gboolean v;

				v = p->data.boolean.value[i];
				if (v != p->data.boolean.def[i])
					defaultvalue = FALSE;
				vbuf[i] = h_strdup(config_boolean(v));
			}
			vbuf[p->vector_size] = NULL;

			val = h_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_MULTICHOICE:
		case PROP_TYPE_GUINT32:
			for (i = 0; i < p->vector_size; i++) {
				guint32 v;

				v = p->data.guint32.value[i];
				if (v != p->data.guint32.def[i])
					defaultvalue = FALSE;
				str_bprintf(sbuf, sizeof(sbuf), "%u", v);
				vbuf[i] = h_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;

			val = h_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_GUINT64:
			for (i = 0; i < p->vector_size; i++) {
				guint64 v;

				v = p->data.guint64.value[i];
				if (v != p->data.guint64.def[i])
					defaultvalue = FALSE;

				uint64_to_string_buf(v, sbuf, sizeof sbuf);
				vbuf[i] = h_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;

			val = h_strjoinv(",", vbuf);
			break;
		case PROP_TYPE_TIMESTAMP:
			for (i = 0; i < p->vector_size; i++) {
				time_t t;

				t = p->data.timestamp.value[i];
				if (t != p->data.timestamp.def[i])
					defaultvalue = FALSE;

				timestamp_utc_to_string_buf(t, sbuf, sizeof sbuf);
				vbuf[i] = h_strdup(sbuf);
			}
			vbuf[p->vector_size] = NULL;
			val = h_strjoinv(",", vbuf);
			quotes = TRUE;
			break;
		case PROP_TYPE_STRING:
			val = h_strdup(*p->data.string.value);
			if (
				val != *p->data.string.def &&
				NULL != val &&
				NULL != *p->data.string.def &&
				0 != strcmp(val, *p->data.string.def)
			) {
				defaultvalue = FALSE;
			}
			if (NULL == val) {
				val = h_strdup("");
				defaultvalue = FALSE;
			}
			quotes = TRUE;
			break;
		case PROP_TYPE_IP:
			for (i = 0; i < p->vector_size; i++) {
				host_addr_t addr;

				addr = p->data.ip.value[i];
				vbuf[i] = h_strdup(host_addr_to_string(addr));
			}
			vbuf[p->vector_size] = NULL;

			val = h_strjoinv(",", vbuf);
			quotes = TRUE;
			defaultvalue = FALSE;
			break;
		case PROP_TYPE_STORAGE:
			{
				size_t hex_size = (p->vector_size * 2) + 1;

				val = halloc(hex_size);
				bin_to_hex_buf(p->data.storage.value, p->vector_size,
					val, hex_size);
				quotes = TRUE;

				/* No default values for storage type properties. */
				defaultvalue = FALSE;
			}
			break;
		case NUM_PROP_TYPES:
			g_assert_not_reached();
		}

		PROP_DEF_UNLOCK(p);

		g_assert(val != NULL);

		fprintf(config, "%s%s = %s%s%s\n\n", defaultvalue ? "#" : "",
			p->name, quotes ? "\"" : "", val, quotes ? "\"" : "");

		HFREE_NULL(val);
		h_strfreev(vbuf);
	}

	/*
	 * Write a unique token identifying this file, kept accross rename()
	 * but not if the file is copied.
	 */

	if (-1 != fstat(fileno(config), &sb)) {
		const char *id = unique_file_token(&sb);
		fprintf(config, "# File ID (internal)\n");
		fprintf(config, "%s = \"%s\"\n\n", PROP_FILE_ID, id);
	}

	fprintf(config, "### End of configuration file ###\n");

	/*
	 * Rename saved configuration file on success.
	 *
	 * We are extra careful and sync data blocks to disk before closing the
	 * file, to protect against crashes when running on a filesytem with
	 * delayed block allocation strategy.  See alos file_config_close().
	 */

	if (0 == file_sync_fclose(config)) {
		if (-1 == rename(newfile, pathname)) {
			s_warning("%s(): could not rename \"%s\" as \"%s\": %m",
				G_STRFUNC, newfile, pathname);
		} else {
			if (-1 == stat(pathname, &sb)) {
				s_warning("%s(): could not stat \"%s\": %m",
					G_STRFUNC, pathname);
				PROP_SET_LOCK(ps);
				ps->mtime = tm_time_exact();
				PROP_SET_UNLOCK(ps);
			} else {
				PROP_SET_LOCK(ps);
				ps->mtime = sb.st_mtime;
				PROP_SET_UNLOCK(ps);
			}
		}
	} else {
		s_warning("%s(): could not flush \"%s\": %m", G_STRFUNC, newfile);
	}

end:
	HFREE_NULL(newfile);
	HFREE_NULL(pathname);
}

/**
 * Called by prop_load_from_file to actually set the properties.
 */
void
prop_set_from_string(prop_set_t *ps, property_t prop, const char *val,
	gboolean saved_only)
{
	prop_def_t *p;
	const prop_set_stub_t *stub;
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
		s_warning("%s(): refusing to load runtime-only property \"%s\"",
			G_STRFUNC, p->name);
		return;
	}

	stub = ps->get_stub();

	PROP_DEF_LOCK(p);

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
			char s[1024];
			char *d, *buf;

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

	PROP_DEF_UNLOCK(p);
}

/**
 * Called by prop_load_from_file to actually set the properties.
 */
static void
load_helper(prop_set_t *ps, property_t prop, const char *val)
{
	prop_set_from_string(ps, prop, val, TRUE);
}

/**
 * Load properties from file.
 *
 * @param ps		the property set associated with the file
 * @param dir		directory where file lies
 * @param filename	basename of file to load properties from
 *
 * @return FALSE if we have reasons to believe that the property file was
 * not generated for this instance of gtk-gnutella but copied from another
 * instance, TRUE otherwise.
 */
gboolean
prop_load_from_file(prop_set_t *ps, const char *dir, const char *filename)
{
	static const char fmt[] = "bad line %u in config file \"%s\", ignored";
	static char prop_tmp[4096];
	FILE *config;
	char *path;
	guint n = 1;
	filestat_t buf;
	gboolean truncated = FALSE;
	gboolean good_id = FALSE;
	const char *file_id;
	static spinlock_t prop_load_slk = SPINLOCK_INIT;

	g_assert(dir != NULL);
	g_assert(filename != NULL);
	g_assert(ps != NULL);

	if (!is_directory(dir))
		return TRUE;

	path = make_pathname(dir, filename);
	config = file_fopen(path, "r");
	if (!config) {
		HFREE_NULL(path);
		return TRUE;
	}

	if (-1 == fstat(fileno(config), &buf)) {
		s_warning("%s(): could open but not fstat \"%s\" (fd #%d): %m",
			G_STRFUNC, path, fileno(config));
		file_id = "";
	} else {
		PROP_SET_LOCK(ps);
		ps->mtime = buf.st_mtime;
		PROP_SET_UNLOCK(ps);
		file_id = unique_file_token(&buf);
	}

	HFREE_NULL(path);

	spinlock(&prop_load_slk);		/* Using global prop_tmp[] */

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
		char *s, *k, *v;
		int c;
		property_t prop;

		if (!file_line_chomp_tail(prop_tmp, sizeof prop_tmp, NULL)) {
			s_warning("%s(): config file \"%s\", line %u: "
				"too long a line, ignored", G_STRFUNC, filename, n);
			truncated = TRUE;
			continue;
		}
		n++; /* Increase line counter */
		if (truncated) {
			truncated = FALSE;
			continue;
		}

		k = v = NULL;
		s = prop_tmp;
		/* Skip leading blanks */
		s = skip_ascii_blanks(s);
		c = (uchar) *s;

		/* <keyword> starts with _ or letter  */
		if (!is_ascii_alpha(c) && c != '_')
			continue;

		/* Here starts the <keyword> */
		k = s;
		while ((c = (uchar) *s) == '_' || is_ascii_alnum(c))
			s++;

		*s = '\0'; /* Terminate <keyword>, original value is stored in c */
		if (is_ascii_blank(c)) {
			s = skip_ascii_blanks(&s[1]);
			c = (uchar) *s;
		}
		if (c != '=') {
			/* <keyword> must be followed by a '=' and optional blanks */
			s_warning(fmt, n, path);
			continue;
		}

		g_assert(c == '=' && (*s == '\0' || *s == '='));
		s++; /* Skip '=' (maybe already overwritten with a '\0') */

		/* Skip optional blanks */
		s = skip_ascii_blanks(s);
		c = (uchar) *s;

		if (c == '"') {
			/* Here starts the <value> part (quoted) */
			v = ++s; /* Skip double-quote '"' */

			/* Scan for terminating double-quote '"' */
			s = strchr(s, '"');
			/* Check for proper quote termination */
			if (!s) {
				/* Missing terminating double-quote '"' */
				s_warning(fmt, n, path);
				continue;
			}
			g_assert(*s == '"');
		} else {
			/* Here starts the <value> part (unquoted) */
			v = s;
			/* The first space terminates the value */
			s = skip_ascii_non_spaces(s);
		}
		c = (uchar) *s;

		g_assert(*s == '\0' || *s == '"' || is_ascii_space(c));
		*s = '\0'; /* Terminate value in case of trailing characters */

		if (debug > 5)
			s_debug("%s(): k=\"%s\", v=\"%s\"", G_STRFUNC, k, v);

		prop = prop_get_by_name(ps, k);
		if (NO_PROP != prop) {
			load_helper(ps, prop, v);
		} else if (0 == strcmp(k, PROP_FILE_ID)) {
			if (0 == strcmp(file_id, v))
				good_id = TRUE;
		} else {
			s_warning("\"%s%c%s\", line %u: unknown property '%s' -- ignored",
				dir, G_DIR_SEPARATOR, filename, n, k);
		}
	}

	spinunlock(&prop_load_slk);
	fclose(config);

	return good_id;
}

/**
 * Maps a property name to a numeric property ID.
 * @param ps A valid property context.
 * @parma name A string to look up.
 * @return The property ID or NO_PROP if the given name maps to none.
 */
property_t
prop_get_by_name(prop_set_t *ps, const char *name)
{
	g_assert(ps != NULL);

	return pointer_to_uint(htable_lookup(ps->by_name, name));
}

pslist_t *
prop_get_by_regex(prop_set_t *ps, const char *pattern, int *error)
{
	pslist_t *sl = NULL;
	size_t i;
	regex_t re;
	int ret;

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
			sl = pslist_prepend(sl, uint_to_pointer(n));
		}
	}

done:
	regfree(&re);
	return pslist_reverse(sl);
}

/* vi: set ts=4 sw=4 cindent: */
