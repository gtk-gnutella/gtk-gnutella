[= AutoGen5 Template =][=
#
# $Id$
#
=][=
(define license (sprintf
"/*
 * Copyright (c) 2001-2003, Richard Eckart
 *
 * THIS FILE IS AUTOGENERATED! DO NOT EDIT!
 * This file is generated from %s using autogen.
 * Autogen is available at http://autogen.sourceforge.net/.
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
 */" (def-file)))
(define prop-max (sprintf "%s_MAX" (string-upcase (get "property_set"))))
(define prop-min (sprintf "%s_MIN" (string-upcase (get "property_set"))))
(define prop-num (sprintf "%s_NUM" (string-upcase (get "property_set"))))
(define prop-end (sprintf "%s_END" (string-upcase (get "property_set"))))
(define private-src (get "private_src"))
(define set-name-down (string-downcase (get "property_set")))
(define prop-set (. set-name-down))
(define prop-array (sprintf "%s->props" (. prop-set)))
(define prop-offset (get "offset"))
(define (type_ok? type)
    (cond
        ((= type "boolean") #t)
        ((= type "guint32") #t)
        ((= type "guint64") #t)
        ((= type "ip") #t)
        ((= type "string") #t)
        ((= type "storage") #t)
        ((= type "multichoice") #t)
        (else #f)))
=][=
IF (exist? "func_prefix")=][=
    (define func-prefix (get "func_prefix"))=][=
ELSE=][=
    (define func-prefix (. prop-set))=][=
ENDIF=][=
IF (not (exist? "property_set"))=][=
    (error "property set has no name")=][=
ENDIF=][=
IF (not (exist? "offset"))=][=
    (error "no offset for property numbering given")=][=
ENDIF=]
Generating files:
[= (sprintf "%s.h" (. set-name-down)) =]
[= (sprintf "%s_priv.h" (. set-name-down)) =]
[= (sprintf "%s.c" (. set-name-down)) =]

[=
(out-switch (sprintf "%s.h" (. set-name-down)))
(. license)
=]

#ifndef _[=(. set-name-down)=]_h_
#define _[=(. set-name-down)=]_h_

#include "lib/prop.h"

#define [=(. prop-min)=] ([=offset=])
#define [=(. prop-max)=] ([=offset=]+[=(. prop-end)=]-1)
#define [=(. prop-num)=] ([=(. prop-end)=]-[=offset=])

typedef enum {[=
    FOR prop =]
    PROP_[=(string-upcase (get "name"))=][=
        IF (= (for-index) 0)=]=[=(. prop-offset)=][=ENDIF=],[=
    ENDFOR prop =]
    [=(. prop-end)=]
} [= (. set-name-down) =]_t;

/*
 * Property set stub
 */
prop_set_stub_t *[=(. func-prefix)=]_get_stub(void);

/*
 * Property definition
 */
prop_def_t *[=(. func-prefix)=]_get_def(property_t);
property_t [=(. func-prefix)=]_get_by_name(const gchar *);
gchar *[=(. func-prefix)=]_name(property_t);

/*
 * Property-change listeners
 */
void [=(. func-prefix)=]_add_prop_changed_listener(
    property_t, prop_changed_listener_t, gboolean);
void [=(. func-prefix)=]_remove_prop_changed_listener(
    property_t, prop_changed_listener_t);

/*
 * get/set functions
 *
 * The *_val macros are shortcuts for single scalar properties.
 */
void [=(. func-prefix)=]_set_boolean(
    property_t, const gboolean *, gsize, gsize);
gboolean *[=(. func-prefix)=]_get_boolean(
    property_t, gboolean *, gsize, gsize);

#define [=(. func-prefix)=]_set_boolean_val(p, v) do { \
	gboolean value = v; \
	[=(. func-prefix)=]_set_boolean(p, &value, 0, 1); \
} while (0)

#define [=(. func-prefix)=]_get_boolean_val(p, v) do { \
	[=(. func-prefix)=]_get_boolean(p, v, 0, 1); \
} while (0)


void [=(. func-prefix)=]_set_string(property_t, const gchar *);
gchar *[=(. func-prefix)=]_get_string(property_t, gchar *, gsize);

void [=(. func-prefix)=]_set_guint32(
    property_t, const guint32 *, gsize, gsize);
guint32 *[=(. func-prefix)=]_get_guint32(
    property_t, guint32 *, gsize, gsize);

#define [=(. func-prefix)=]_set_guint32_val(p, v) do { \
	guint32 value = v; \
	[=(. func-prefix)=]_set_guint32(p, &value, 0, 1); \
} while (0)

#define [=(. func-prefix)=]_get_guint32_val(p, v) do { \
	[=(. func-prefix)=]_get_guint32(p, v, 0, 1); \
} while (0)

void [=(. func-prefix)=]_set_guint64(
    property_t, const guint64 *, gsize, gsize);
guint64 *[=(. func-prefix)=]_get_guint64(
    property_t, guint64 *, gsize, gsize);

#define [=(. func-prefix)=]_set_guint64_val(p, v) do { \
	guint64 value = v; \
	[=(. func-prefix)=]_set_guint64(p, &value, 0, 1); \
} while (0)

#define [=(. func-prefix)=]_get_guint64_val(p, v) do { \
	[=(. func-prefix)=]_get_guint64(p, v, 0, 1); \
} while (0)

void [=(. func-prefix)=]_set_storage(property_t, const guint8 *, gsize);
guint8 *[=(. func-prefix)=]_get_storage(property_t, guint8 *, gsize);

gchar *[=(. func-prefix)=]_to_string(property_t prop);

#endif /* _[=(. set-name-down)=]_h_ */

[=
(out-switch (sprintf "%s_priv.h" (. set-name-down)))
(. license)
=]

#ifndef _[=(. set-name-down)=]_priv_h_
#define _[=(. set-name-down)=]_priv_h_

#include <glib.h>

#include "lib/prop.h"

#ifdef [=(. private-src)=]

/*
 * Includes specified by "uses"-statement in .ag file
 */
[= FOR uses =]#include "[=uses=]"
[= ENDFOR uses =]

[= FOR prop =][=
IF (exist? "data.value") =][=
(define item (get "data.value")) =][=
ELSE =][=
(define item (string-downcase (get "name"))) =][=
ENDIF=][=
CASE type=][=
= boolean=]extern const gboolean [=(. item)=][=
= guint32=]extern const guint32  [=(. item)=][=
= guint64=]extern const guint64  [=(. item)=][=
= ip     =]extern const guint32  [=(. item)=][=
= multichoice=]extern const guint32  [=(. item)=][=
= string =]extern const gchar   *[=(. item)=][=
= storage=]extern const guint8   [=(. item)=][=
ESAC =][=
IF (exist? "vector_size") =][[=vector_size=]][=ENDIF=];
[= ENDFOR prop =]

prop_set_t *[=(. func-prefix)=]_init(void);
void [=(. func-prefix)=]_shutdown(void);

#endif /* [=(. private-src)=] */

#endif /* _[=(. set-name-down)=]_priv_h_ */

[=
(out-switch (sprintf "%s.c" (. set-name-down)))
(. license)
=]

#include "lib/prop.h"
#include "lib/eval.h"
#include "[=(sprintf "%s.h" (. set-name-down))=]"

/*
 * Includes specified by "uses"-statement in .ag file
 */
[= FOR uses =]#include "[=uses=]"
[= ENDFOR uses =]
#include "lib/override.h"		/* Must be the last header included */

[=
FOR prop =][=
    (if (exist? "data.value")
        (define item (get "data.value"))
        (define item (string-downcase (get "name"))))=][=
    IF (= (get "type") "storage")=]
guint8   [=(. item)=][[=vector_size=]];[=
    ELSE=][=
        (cond
            ((= (get "type") "boolean")
                (define vtype "gboolean ")
                (define vdef (get "data.default")))
            ((= (get "type") "guint32")
                (define vtype "guint32  ")
                (define vdef (get "data.default")))
            ((= (get "type") "guint64")
                (define vtype "guint64  ")
                (define vdef (get "data.default")))
            ((= (get "type") "ip")
                (define vtype "guint32  ")
                (define vdef (get "data.default")))
            ((= (get "type") "multichoice")
                (define vtype "guint32  ")
                (define vdef (get "data.default")))
            ((= (get "type") "string")
                (define vtype "gchar   *")
                (if (= (get "data.default") "NULL")
                    (define vdef (sprintf "NULL"))
                    (define vdef (sprintf "\"%s\"" (get "data.default"))))))
        =][=
        IF (exist? "vector_size")=]
[=  (. vtype)=][=(. item)=][[=vector_size=]]     = [=(. vdef)=];
[=  (. vtype)=][=(. item)=]_def[[=vector_size=]] = [=(. vdef)=];[=
        ELSE=]
[=  (. vtype)=][=(. item)=]     = [=(. vdef)=];
[=  (. vtype)=][=(. item)=]_def = [=(. vdef)=];[=
        ENDIF=][=
        IF (= (get "type") "multichoice")=]
prop_def_choice_t [=(. item)=]_choices[] = { [=
            FOR choice =]
    {N_("[=name=]"), [=value=]},[=
            ENDFOR choice =]
    {NULL, 0}
};[=
        ENDIF =][=
    ENDIF=][=
ENDFOR prop =]

static prop_set_t *[=(. prop-set)=] = NULL;

prop_set_t *[=(. func-prefix)=]_init(void) {
    guint32 n;

    [=(. prop-set)=] = g_new(prop_set_t, 1);
    [=(. prop-set)=]->name   = "[=property_set=]";
    [=(. prop-set)=]->desc   = "";
    [=(. prop-set)=]->size   = [=(. prop-num)=];
    [=(. prop-set)=]->offset = [=offset=];
    [=(. prop-set)=]->mtime  = 0;
    [=(. prop-set)=]->props  = g_new(prop_def_t, [=(. prop-num)=]);
    [=(. prop-set)=]->get_stub = [=(. func-prefix)=]_get_stub;
    [=(. prop-set)=]->dirty = FALSE;
    [=(. prop-set)=]->byName = NULL;[=

FOR prop =][=
    (define current-prop (sprintf "%s[%u]"
        (. prop-array) (for-index)))

    (if (not (and (exist? "type") (type_ok? (get "type"))))
        (error "type missing or invalid"))

    (if (not (exist? "name"))
        (error "no name given"))

    (if (not (exist? "desc"))
        (error "no description given"))

    (if (exist? "data.value")
        (define prop-var-name (get "data.value"))
        (define prop-var-name (string-downcase (get "name"))))

    (if (and (not (exist? "data.default")) (not (= (get "type") "storage")))
        (error "no default value given"))

    (if (and (not (exist? "vector_size")) (= (get "type") "storage"))
        (error "must give vector_size for a storage-type property"))
    =]


    /*
     * PROP_[=(string-upcase (get "name"))=]:
     *
     * General data:
     */
    [= IF (exist? "cfgvar") =][=
        (. current-prop) =].name = "[= cfgvar =]";[=
    ELSE =][=
        (. current-prop) =].name = "[= name =]";[=
    ENDIF =]
    [=(. current-prop)=].desc = _("[=desc=]");
    [=(. current-prop)=].ev_changed = event_new("[= name =]_changed");[=
    IF (exist? "save") =]
    [=  (. current-prop) =].save = [=save=];[=
    ELSE =]
    [=  (. current-prop) =].save = TRUE;[=
    ENDIF =][=
    IF (exist? "vector_size") =]
    [=  (. current-prop) =].vector_size = [=vector_size=];[=
        (define prop-var (sprintf "%s" (. prop-var-name)))=][=
    ELSE =]
    [=  (. current-prop) =].vector_size = 1;[=
        (define prop-var (sprintf "&%s" (. prop-var-name)))=][=
    ENDIF =][=
    (define prop-def-var (sprintf "%s_def" (. prop-var)))
    =]

    /* Type specific data: */[=
    CASE type =][=

    = boolean =][=
    IF (not (exist? "data.default")) =][=
        (error "no default given")=][=
    ENDIF=]
    [=(. current-prop)=].type               = PROP_TYPE_BOOLEAN;
    [=(. current-prop)=].data.boolean.def   = [=(. prop-def-var)=];
    [=(. current-prop)=].data.boolean.value = [=(. prop-var)=];[=

    = storage =]
    [=(. current-prop)=].type               = PROP_TYPE_STORAGE;
    [=(. current-prop)=].data.storage.value = [=(. prop-var)=];
    memset([=(. prop-var)=], 0, [=(. current-prop)=].vector_size);[=

    = guint32 =]
    [=(. current-prop)=].type               = PROP_TYPE_GUINT32;
    [=(. current-prop)=].data.guint32.def   = [=(. prop-def-var)=];
    [=(. current-prop)=].data.guint32.value = [=(. prop-var)=];
    [=(. current-prop)=].data.guint32.choices = NULL;[=
    IF (exist? "data.max")=]
    [=(. current-prop)=].data.guint32.max   = [=data.max=];[=
    ELSE=]
    [=(. current-prop)=].data.guint32.max   = 0xFFFFFFFF;[=
    ENDIF=][=
    IF (exist? "data.min")=]
    [=(. current-prop)=].data.guint32.min   = [=data.min=];[=
    ELSE=]
    [=(. current-prop)=].data.guint32.min   = 0x00000000;[=
    ENDIF=][=

    = guint64 =]
    [=(. current-prop)=].type               = PROP_TYPE_GUINT64;
    [=(. current-prop)=].data.guint64.def   = [=(. prop-def-var)=];
    [=(. current-prop)=].data.guint64.value = [=(. prop-var)=];
    [=(. current-prop)=].data.guint64.choices = NULL;[=
    IF (exist? "data.max")=]
    [=(. current-prop)=].data.guint64.max   = [=data.max=];[=
    ELSE=]
    [=(. current-prop)=].data.guint64.max   = (guint64) -1;[=
    ENDIF=][=
    IF (exist? "data.min")=]
    [=(. current-prop)=].data.guint64.min   = [=data.min=];[=
    ELSE=]
    [=(. current-prop)=].data.guint64.min   = 0x0000000000000000;[=
    ENDIF=][=

	= ip =]
    [=(. current-prop)=].type               = PROP_TYPE_IP;
    [=(. current-prop)=].data.guint32.def   = [=(. prop-def-var)=];
    [=(. current-prop)=].data.guint32.value = [=(. prop-var)=];
    [=(. current-prop)=].data.guint32.choices = NULL;
    [=(. current-prop)=].data.guint32.max   = 0xFFFFFFFF;
    [=(. current-prop)=].data.guint32.min   = 0x00000000;[=

    = multichoice =]
    [=(. current-prop)=].type               = PROP_TYPE_MULTICHOICE;
    [=(. current-prop)=].data.guint32.def   = [=(. prop-def-var)=];
    [=(. current-prop)=].data.guint32.value = [=(. prop-var)=];
    [=(. current-prop)=].data.guint32.max   = 0xFFFFFFFF;
    [=(. current-prop)=].data.guint32.min   = 0x00000000;
    [=(. current-prop)=].data.guint32.choices = [=
        (sprintf "%s_choices" (. prop-var-name    ))=];[=

    = string =]
    [=(. current-prop)=].type               = PROP_TYPE_STRING;
    [=(. current-prop)=].data.string.def    = [=(. prop-def-var)=];
    [=(. current-prop)=].data.string.value  = [=(. prop-var)=];
    if ([=(. current-prop)=].data.string.def) {
        *[=(. current-prop)=].data.string.value =
            g_strdup(eval_subst(*[=(. current-prop)=].data.string.def));
    }[=
    ESAC =][=
ENDFOR prop=]

    [=(. prop-set)=]->byName = g_hash_table_new(g_str_hash, g_str_equal);
    for (n = 0; n < [=(. prop-num)=]; n ++) {
        g_hash_table_insert([=(. prop-set)=]->byName,
            [=(. prop-array)=][n].name, GINT_TO_POINTER(n+[=offset=]));
    }

    return [=(. prop-set)=];
}

/*
 * [=(. func-prefix)=]_shutdown:
 *
 * Free memory allocated by the property set.
 */
void [=(. func-prefix)=]_shutdown(void) {
    gint n;

    if ([=(. prop-set)=]->byName) {
        g_hash_table_destroy([=(. prop-set)=]->byName);
        [=(. prop-set)=]->byName = NULL;
    }

    for (n = 0; n < [=(. prop-num)=]; n ++) {
        if ([=(. prop-set)=]->props[n].type == PROP_TYPE_STRING) {
			gchar **p = [=(. prop-array)=][n].data.string.value;
            struct event *e = [=(. prop-array)=][n].ev_changed;
			if (*p)
				G_FREE_NULL(*p);
            if (e)
                event_destroy(e);
        }
    }

    G_FREE_NULL([=(. prop-array)=]);
    G_FREE_NULL([=(. prop-set)=]);
}

prop_def_t *[=(. func-prefix)=]_get_def(property_t p)
{
    return prop_get_def([=(. prop-set)=], p);
}

/*
 * [=(. func-prefix)=]_add_prop_changed_listener:
 *
 * Add a change listener to a given property. If init is TRUE then
 * the listener is immediately called.
 */
void [=(. func-prefix)=]_add_prop_changed_listener(
    property_t prop, prop_changed_listener_t l, gboolean init)
{
    prop_add_prop_changed_listener([=(. prop-set)=], prop, l, init);
}

/*
 * [=(. func-prefix)=]_add_prop_changed_listener_full:
 *
 * Add a change listener to a given property. If init is TRUE then
 * the listener is immediately called.
 */
void [=(. func-prefix)=]_add_prop_changed_listener_full(
    property_t prop, prop_changed_listener_t l, gboolean init,
    enum frequency_type freq, guint32 interval)
{
    prop_add_prop_changed_listener_full([=(. prop-set)=], prop, l, init,
        freq, interval);
}

void [=(. func-prefix)=]_remove_prop_changed_listener(
    property_t prop, prop_changed_listener_t l)
{
    prop_remove_prop_changed_listener([=(. prop-set)=], prop, l);
}

void [=(. func-prefix)=]_set_boolean(
    property_t prop, const gboolean *src, gsize offset, gsize length)
{
    prop_set_boolean([=(. prop-set)=], prop, src, offset, length);
}

gboolean *[=(. func-prefix)=]_get_boolean(
    property_t prop, gboolean *t, gsize offset, gsize length)
{
    return prop_get_boolean([=(. prop-set)=], prop, t, offset, length);
}

void [=(. func-prefix)=]_set_guint32(
    property_t prop, const guint32 *src, gsize offset, gsize length)
{
    prop_set_guint32([=(. prop-set)=], prop, src, offset, length);
}

guint32 *[=(. func-prefix)=]_get_guint32(
    property_t prop, guint32 *t, gsize offset, gsize length)
{
    return prop_get_guint32([=(. prop-set)=], prop, t, offset, length);
}

void [=(. func-prefix)=]_set_guint64(
    property_t prop, const guint64 *src, gsize offset, gsize length)
{
    prop_set_guint64([=(. prop-set)=], prop, src, offset, length);
}

guint64 *[=(. func-prefix)=]_get_guint64(
    property_t prop, guint64 *t, gsize offset, gsize length)
{
    return prop_get_guint64([=(. prop-set)=], prop, t, offset, length);
}

void [=(. func-prefix)=]_set_string(property_t prop, const gchar *val)
{
    prop_set_string([=(. prop-set)=], prop, val);
}

gchar *[=(. func-prefix)=]_get_string(property_t prop, gchar *t, gsize size)
{
    return prop_get_string([=(. prop-set)=], prop, t, size);
}

void [=(. func-prefix)=]_set_storage(property_t p, const guint8 *v, gsize l)
{
    prop_set_storage([=(. prop-set)=], p, v, l);
}

guint8 *[=(. func-prefix)=]_get_storage(property_t p, guint8 *t, gsize l)
{
    return prop_get_storage([=(. prop-set)=], p, t, l);
}

gchar *[=(. func-prefix)=]_to_string(property_t prop)
{
    return prop_to_string([=(. prop-set)=], prop);
}

gchar *[=(. func-prefix)=]_name(property_t p)
{
    return prop_name([=(. prop-set)=], p);
}

property_t [=(. func-prefix)=]_get_by_name(const gchar *name)
{
    return GPOINTER_TO_UINT(
        g_hash_table_lookup([=(. prop-set)=]->byName, name));
}


/*
 * [=(. func-prefix)=]_get_stub:
 *
 * Returns a new stub struct for this property set. Just g_free it
 * when it is no longer needed. All fields are read only!
 */
prop_set_stub_t *[=(. func-prefix)=]_get_stub(void)
{
    prop_set_stub_t *stub;

    stub          = g_new0(prop_set_stub_t, 1);
    stub->size    = [=(. prop-num)=];
    stub->offset  = [=(. prop-min)=];
    stub->get_def = [=(. func-prefix)=]_get_def;
    stub->get_by_name = [=(. func-prefix)=]_get_by_name;
    stub->to_string = [=(. func-prefix)=]_to_string;

    stub->prop_changed_listener.add =
        [=(. func-prefix)=]_add_prop_changed_listener;
    stub->prop_changed_listener.add_full =
        [=(. func-prefix)=]_add_prop_changed_listener_full;
    stub->prop_changed_listener.remove =
        [=(. func-prefix)=]_remove_prop_changed_listener;

    stub->boolean.get = [=(. func-prefix)=]_get_boolean;
    stub->boolean.set = [=(. func-prefix)=]_set_boolean;

    stub->guint32.get = [=(. func-prefix)=]_get_guint32;
    stub->guint32.set = [=(. func-prefix)=]_set_guint32;

    stub->guint64.get = [=(. func-prefix)=]_get_guint64;
    stub->guint64.set = [=(. func-prefix)=]_set_guint64;

    stub->string.get = [=(. func-prefix)=]_get_string;
    stub->string.set = [=(. func-prefix)=]_set_string;

    stub->storage.get = [=(. func-prefix)=]_get_storage;
    stub->storage.set = [=(. func-prefix)=]_set_storage;

    return stub;
}
