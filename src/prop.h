/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#ifndef __prop_h__
#define __prop_h__

#include "gnutella.h"
#include "listener.h"

/*
 * Use this macro access a property instead of ps->props[prop]. It will
 * hide the offset of the properties, so the property array can be 
 * accessed.
 */
#define PROP(ps, p) (ps->props[p-ps->offset])

/*
 * Handle types
 */
typedef guint32 property_t;
typedef guint32 property_set_t;

/*
 * Available property types
 */
typedef enum {
    PROP_TYPE_BOOLEAN,
    PROP_TYPE_GUINT32,
    PROP_TYPE_STRING,
    PROP_TYPE_IP,
    PROP_TYPE_STORAGE
} prop_type_t;

extern gchar *prop_type_str[];

/*
 * Callback signature definition
 */
typedef gboolean (*prop_changed_listener_t) (property_t);

/*
 * Listener access call signatures.
 */
typedef void (*prop_add_prop_changed_listener_t)
    (property_t, prop_changed_listener_t, gboolean);
typedef void (*prop_remove_prop_changed_listener_t)
    (property_t, prop_changed_listener_t);

/*
 * Container struct definitions for the different property types
 */
typedef struct prop_def_guint32 {
    guint32 *def;    /* default value */
    guint32 *value;  /* current value */
    guint32 min;     /* minimal value */
    guint32 max;     /* maximal value */
} prop_def_guint32_t;
typedef void (*prop_set_guint32_t)
    (property_t, const guint32 *, gsize, gsize);
typedef guint32 *(*prop_get_guint32_t)
    (property_t, guint32 *, gsize, gsize);

typedef struct prop_def_storage {
    guint8 *value;  /* current data */
} prop_def_storage_t;
typedef void (*prop_set_storage_t)(property_t, const guint8 *, gsize);
typedef guint8 *(*prop_get_storage_t)(property_t, guint8 *, gsize);

typedef struct prop_def_string {
    gchar **def;      /* default value */
    gchar **value;   /* current value */
} prop_def_string_t;
typedef void (*prop_set_string_t)(property_t, const gchar *);
typedef gchar *(*prop_get_string_t)(property_t, gchar *, gsize);

typedef struct prop_def_boolean {
    gboolean *def;    /* default value */
    gboolean *value; /* current value */
} prop_def_boolean_t;
typedef void (*prop_set_boolean_t)
    (property_t, const gboolean *, gsize, gsize);
typedef gboolean *(*prop_get_boolean_t)
    (property_t, gboolean *, gsize, gsize);

/*
 * Property definition
 */
typedef struct prop_def {
    gchar *name; /* key used in the config file */
    gchar *desc; /* description of the property */
    prop_type_t type;
    union {
        prop_def_guint32_t  guint32;
        prop_def_string_t   string;
        prop_def_boolean_t  boolean;
        prop_def_storage_t  storage;
    } data;
    gboolean save; /* persist across sessions */
    guint32  vector_size; /* number of items in array, 1 for non-vector */
    listeners_t prop_changed_listeners;
} prop_def_t;
typedef prop_def_t *(*prop_get_def_t)(property_t);

/*
 * Property set stub to access property set.
 */
typedef struct prop_set_stub {
    guint32 size;
    guint32 offset;
    prop_get_def_t get_def;
    struct {
        prop_add_prop_changed_listener_t add;
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
        prop_get_storage_t get;
        prop_set_storage_t set;
    } storage;
    struct {
        prop_get_string_t get;
        prop_set_string_t set;
    } string;
} prop_set_stub_t;

/*
 * Stub-fetcher signature
 */
typedef prop_set_stub_t *(*prop_set_get_stub_t)(void);

/*
 * Property set definition
 */
typedef struct prop_set {
    gchar *name;       /* name of the property set */
    gchar *desc;       /* description of what the set contains */
    guint32 size;      /* number of properties in the set */
    guint32 offset;    /* properties start numbering from here */
    prop_def_t *props; /* Pointer to first item in array of prop_def_t */
    time_t mtime;      /* modification time of the associated file */
    prop_set_get_stub_t get_stub;
} prop_set_t;


/*
 * Helpers
 */
void prop_parse_guint32_vector(const gchar *str, gsize size, guint32 *t);
void prop_parse_boolean_vector(const gchar *str, gsize size, gboolean *t);
void prop_parse_storage(const gchar *str, gsize size, guint8 *t);

prop_def_t *prop_get_def(prop_set_t *, property_t);
void prop_free_def(prop_def_t *);

void prop_add_prop_changed_listener
    (prop_set_t *, property_t, prop_changed_listener_t, gboolean);
void prop_remove_prop_changed_listener
    (prop_set_t *, property_t, prop_changed_listener_t);

void prop_save_to_file
    (prop_set_t *ps, const gchar *dir, const gchar *filename);
void prop_load_from_file
    (prop_set_t *ps, const gchar *dir, const gchar *filename);

/*
 * get/set functions
 */
void prop_set_boolean
    (prop_set_t *, property_t, const gboolean *, guint32, guint32);
gboolean *prop_get_boolean
    (prop_set_t *, property_t, gboolean *, guint32, guint32);

void prop_set_string(prop_set_t *, property_t, const gchar *);
gchar *prop_get_string(prop_set_t *, property_t, gchar *, guint32);

void prop_set_guint32
    (prop_set_t *, property_t, const guint32 *, guint32, guint32);
guint32 *prop_get_guint32
    (prop_set_t *, property_t, guint32 *, guint32, guint32);

void prop_set_storage
    (prop_set_t *, property_t, const guint8 *, gsize);
guint8 *prop_get_storage
    (prop_set_t *, property_t, guint8 *, gsize);

#endif /* __prop_h__ */

