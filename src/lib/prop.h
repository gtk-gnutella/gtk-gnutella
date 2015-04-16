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

#ifndef _prop_h_
#define _prop_h_

#include "common.h"
#include "event.h"
#include "host_addr.h"
#include "htable.h"
#include "mutex.h"
#include "spinlock.h"

#define NO_PROP (0)

/*
 * Handle types.
 */
typedef guint32 property_t;
typedef guint32 property_set_t;

/**
 * Available property types.
 */
typedef enum {
    PROP_TYPE_BOOLEAN,
    PROP_TYPE_GUINT32,
    PROP_TYPE_GUINT64,
    PROP_TYPE_IP,
    PROP_TYPE_MULTICHOICE,
    PROP_TYPE_STORAGE,
    PROP_TYPE_STRING,
    PROP_TYPE_TIMESTAMP,

	NUM_PROP_TYPES
} prop_type_t;

/**
 * Callback signature definition.
 */
typedef gboolean (*prop_changed_listener_t) (property_t);

/*
 * Event subscription control call signatures.
 */
typedef void (*prop_add_prop_changed_listener_t)
    (property_t, prop_changed_listener_t, gboolean);
typedef void (*prop_add_prop_changed_listener_full_t)
    (property_t, prop_changed_listener_t, gboolean,
		enum frequency_type, guint32);
typedef void (*prop_remove_prop_changed_listener_t)
    (property_t, prop_changed_listener_t);

/**
 * Container struct definitions for the different property types
 */
typedef struct prop_def_choice {
    char *title;
    guint32 value;
} prop_def_choice_t;


typedef struct prop_def_guint32 {
    guint32 *def;		/**< default value */
    guint32 *value;		/**< current value */
    guint32 min;		/**< minimal value */
    guint32 max;		/**< maximal value */
    prop_def_choice_t *choices;
} prop_def_guint32_t;

typedef void (*prop_set_guint32_t)
    (property_t, const guint32 *, size_t, size_t);
typedef guint32 *(*prop_get_guint32_t)
    (property_t, guint32 *, size_t, size_t);


typedef struct prop_def_guint64 {
    guint64 *def;		/**< default value */
    guint64 *value;		/**< current value */
    guint64 min;		/**< minimal value */
    guint64 max;		/**< maximal value */
    prop_def_choice_t *choices;
} prop_def_guint64_t;

typedef void (*prop_set_guint64_t)
    (property_t, const guint64 *, size_t, size_t);
typedef guint64 *(*prop_get_guint64_t)
    (property_t, guint64 *, size_t, size_t);

typedef struct prop_def_timestamp {
    time_t *def;	/**< default value */
    time_t *value;	/**< current value */
    time_t min;		/**< minimal value */
    time_t max;		/**< maximal value */
    prop_def_choice_t *choices;
} prop_def_timestamp_t;

typedef void (*prop_set_timestamp_t)
    (property_t, const time_t *, size_t, size_t);
typedef time_t *(*prop_get_timestamp_t)
    (property_t, time_t *, size_t, size_t);

typedef struct prop_def_ip {
    host_addr_t *value;		/**< current value */
} prop_def_ip_t;

typedef void (*prop_set_ip_t)
    (property_t, const host_addr_t *, size_t, size_t);
typedef host_addr_t *(*prop_get_ip_t)
    (property_t, host_addr_t *, size_t, size_t);

typedef struct prop_def_storage {
    gpointer value;		/**< current data */
} prop_def_storage_t;

typedef void (*prop_set_storage_t)(property_t, const void *, size_t);
typedef gpointer (*prop_get_storage_t)(property_t, gpointer, size_t);


typedef struct prop_def_string {
    char **def;		/**< default value */
    char **value;		/**< current value */
} prop_def_string_t;

typedef void (*prop_set_string_t)(property_t, const char *);
typedef char *(*prop_get_string_t)(property_t, char *, size_t);


typedef struct prop_def_boolean {
    gboolean *def;		/**< default value */
    gboolean *value;	/**< current value */
} prop_def_boolean_t;

typedef void (*prop_set_boolean_t)
    (property_t, const gboolean *, size_t, size_t);
typedef gboolean *(*prop_get_boolean_t)
    (property_t, gboolean *, size_t, size_t);

/**
 * Property definition.
 */
typedef struct prop_def {
    char *name;		/**< key used in the config file */
    char *desc;		/**< description of the property */
    prop_type_t type;
    union {
        prop_def_guint32_t  guint32;
        prop_def_guint64_t  guint64;
        prop_def_string_t   string;
        prop_def_boolean_t  boolean;
        prop_def_storage_t  storage;
        prop_def_timestamp_t  timestamp;
        prop_def_ip_t  ip;
    } data;
	mutex_t lock;		/* thread-safe access */
    uint save:1; 		/* persist across sessions */
    uint internal:1;	/* if set, users cannot modify the property */
    size_t vector_size; /* number of items in array, 1 for non-vector */
    struct event *ev_changed;
} prop_def_t;

/**
 * Property set stub to access property set.
 */
typedef struct prop_set_stub {
    size_t size;
    size_t offset;
    prop_def_t *(*get_def)(property_t);
    property_t (*get_by_name)(const char *);
    const char *(*to_string)(property_t);
    struct {
        prop_add_prop_changed_listener_t add;
        prop_add_prop_changed_listener_full_t add_full;
        prop_remove_prop_changed_listener_t remove;
    } prop_changed_listener;
    struct {
        prop_get_boolean_t get;
        prop_set_boolean_t set;
    } boolean;
    struct {
        prop_get_guint32_t get;
        prop_set_guint32_t set;
    } guint32;
    struct {
        prop_get_guint64_t get;
        prop_set_guint64_t set;
    } guint64;
    struct {
        prop_get_storage_t get;
        prop_set_storage_t set;
    } storage;
    struct {
        prop_get_string_t get;
        prop_set_string_t set;
    } string;
    struct {
        prop_get_timestamp_t get;
        prop_set_timestamp_t set;
    } timestamp;
    struct {
        prop_get_ip_t get;
        prop_set_ip_t set;
    } ip;
} prop_set_stub_t;

/**
 * Stub-fetcher signature.
 */
typedef const prop_set_stub_t *(*prop_set_get_stub_t)(void);

/**
 * Property set definition.
 */
typedef struct prop_set {
    char *name;			/**< name of the property set */
    char *desc;			/**< description of what the set contains */
    size_t size;		/**< number of properties in the set */
    size_t offset;		/**< properties start numbering from here */
    prop_def_t *props;	/**< Array of prop_def_t, one entry per property */
    htable_t *by_name;	/**< hashtable to quickly look up props by name */
    time_t mtime;		/**< modification time of the associated file */
	gboolean dirty;		/**< property set needs flushing to disk */
	spinlock_t lock;	/**< thread-safe access to structure */
    prop_set_get_stub_t get_stub;
} prop_set_t;

/*
 * Helpers
 */

prop_def_t *prop_get_def(prop_set_t *, property_t);
void prop_free_def(prop_def_t *);

const char *prop_name(prop_set_t *ps, property_t prop);
const char *prop_description(prop_set_t *ps, property_t prop);
const char *prop_to_string(prop_set_t *ps, property_t prop);
const char *prop_type_to_string(prop_set_t *ps, property_t prop);
const char *prop_default_to_string(prop_set_t *ps, property_t prop);
prop_type_t prop_type(prop_set_t *ps, property_t prop);
gboolean prop_is_saved(prop_set_t *ps, property_t prop);
gboolean prop_is_internal(prop_set_t *ps, property_t prop);

void prop_lock(prop_set_t *ps, property_t p);
void prop_unlock(prop_set_t *ps, property_t p);

void prop_add_prop_changed_listener(
    prop_set_t *, property_t, prop_changed_listener_t, gboolean);
void prop_add_prop_changed_listener_full(
    prop_set_t *, property_t, prop_changed_listener_t, gboolean,
    enum frequency_type, guint32);
void prop_remove_prop_changed_listener(
    prop_set_t *, property_t, prop_changed_listener_t);

void prop_save_to_file_if_dirty(
    prop_set_t *ps, const char *dir, const char *filename);
void prop_save_to_file(
    prop_set_t *ps, const char *dir, const char *filename);
gboolean prop_load_from_file(
    prop_set_t *ps, const char *dir, const char *filename);

/*
 * get/set functions
 */
void prop_set_boolean(
    prop_set_t *, property_t, const gboolean *, size_t, size_t);
gboolean *prop_get_boolean(
    prop_set_t *, property_t, gboolean *, size_t, size_t);

void prop_set_string(prop_set_t *, property_t, const char *);
char *prop_get_string(prop_set_t *, property_t, char *, size_t);

void prop_set_guint32(
    prop_set_t *, property_t, const guint32 *, size_t, size_t);
guint32 *prop_get_guint32(
    prop_set_t *, property_t, guint32 *, size_t, size_t);

void prop_set_guint64(
    prop_set_t *, property_t, const guint64 *, size_t, size_t);
guint64 *prop_get_guint64(
    prop_set_t *, property_t, guint64 *, size_t, size_t);

void prop_set_timestamp(
    prop_set_t *, property_t, const time_t *, size_t, size_t);
time_t *prop_get_timestamp(
    prop_set_t *, property_t, time_t *, size_t, size_t);

void prop_set_ip(
    prop_set_t *, property_t, const host_addr_t *, size_t, size_t);
host_addr_t *prop_get_ip(
    prop_set_t *, property_t, host_addr_t *, size_t, size_t);

void prop_set_storage(prop_set_t *, property_t, const char *, size_t);
char *prop_get_storage(prop_set_t *, property_t, char *, size_t);

property_t prop_get_by_name(prop_set_t *ps, const char *name);
struct pslist *prop_get_by_regex(prop_set_t *ps,
	const char *pattern, int *error);
void prop_set_from_string(prop_set_t *ps, property_t prop, const char *val,
	gboolean saved_only);

/*
 * Checks if a property is part of a property set.
 */
static inline gboolean
prop_in_range(const prop_set_t *ps, property_t prop)
{
	return prop >= ps->offset && prop < ps->size + ps->offset;
}

static inline prop_def_t *
get_prop(prop_set_t *ps, property_t prop, const char *loc)
{
	if (!ps)
		g_error("%s: ps != NULL failed", loc);
	if (!prop_in_range(ps, prop))
		g_error("%s: unknown property %u", loc, (guint) prop);
	return &ps->props[prop - ps->offset];
}

/**
 * Use this macro access a property instead of ps->props[prop]. It will
 * hide the offset of the properties, so the property array can be
 * accessed.
 */
#define PROP(ps, p) (* get_prop((ps), (p), G_STRLOC))

/*
 * Casts, since property_t is an opaque type, for using properties as keys.
 */

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE void *
property_to_pointer(property_t value)
{
	return ulong_to_pointer(value);
}

static inline G_GNUC_CONST WARN_UNUSED_RESULT ALWAYS_INLINE property_t
pointer_to_property(const void *p)
{
	return pointer_to_ulong(p);
}

#endif /* _prop_h_ */
/* vi: set ts=4 sw=4 cindent: */
