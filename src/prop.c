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

#include <sys/stat.h>
#include <stdio.h>

#include "prop.h"
#include "misc.h"

#define debug 1

/*
 * Checks if a property is part of a property set.
 */
#define prop_in_range(ps, p) ((p >= ps->offset) && (p < ps->size+ps->offset))

gchar *prop_type_str[] = {
    "boolean",
    "guint32",
    "string",
    "ip",
    "storage"
};

static gchar prop_tmp[4096];

/***
 *** Helpers
 ***/

/*
 * prop_parse_guint32_vector:
 *
 * Parse comma delimited numeric vector.
 */
void prop_parse_guint32_vector(const gchar *str, gsize size, guint32 *t)
{
	/* Parse comma delimited settings */

	gchar **h;
	gsize i;

    g_assert(str != NULL);
    g_assert(t != NULL);

    h = g_strsplit(str, ",", size + 1);

	for (i = 0; i < size; i++) {
		if (!h[i])
			break;

		t[i] = atol(h[i]);
	}

    if (i < size)
        g_warning("prop_parse_guint32_vector: "
            "target initialization incomplete!");

	g_strfreev(h);
}

/*
 * prop_parse_boolean_vector:
 *
 * Parse comma delimited boolean vector (TRUE/FALSE list).
 */
void prop_parse_boolean_vector(const gchar *str, gsize size, gboolean *t)
{
	/* Parse comma delimited settings */

	gchar **h;
	gsize i;

    g_assert(str != NULL);
    g_assert(t != NULL);

    h = g_strsplit(str, ",", size + 1);

	for (i = 0; i < size; i++) {
		if (!h[i])
			break;

		t[i] = (gboolean) (g_strcasecmp(str, "TRUE") == 0);
	}

    if (i < size)
        g_warning("prop_parse_boolean_vector: "
            "target initialization incomplete!");

	g_strfreev(h);
}

/*
 * prop_parse_storage:
 *
 * Parse a hex string into a guint8 array.
 */
void prop_parse_storage(const gchar *str, gsize size, guint8 *t)
{
    gsize i;

    if ((size*2) != strlen(str))
        g_error("prop_parse_storage: storage does not match requested size");

    for (i = 0; i < size; i ++)
        t[i] = (hex2dec(str[i*2]) << 4) + hex2dec(str[i*2+1]);
}


/***
 *** Properties
 ***/

/*
 * prop_get_def:
 *
 * Copy the property definition from the property set and return it. 
 * Use the prop_free_def call to free the memory again. A simple g_free
 * won't do, since there are lot's of pointers to allocated memory
 * in the definition structure.
 */
prop_def_t *prop_get_def(prop_set_t *ps, property_t p)
{
    prop_def_t *buf;

    g_assert(ps != NULL);

    if(!prop_in_range(ps, p))
        g_error("prop_get_def: unknown property %d", p);

    buf = g_memdup(&PROP(ps, p), sizeof(prop_def_t));

    switch(buf->type) {
    case PROP_TYPE_BOOLEAN:
        buf->data.boolean.def = g_memdup(
            PROP(ps,p).data.boolean.def,
            sizeof(gboolean) * PROP(ps,p).vector_size);
        buf->data.boolean.value = g_memdup(
            PROP(ps,p).data.boolean.value,
            sizeof(gboolean) * PROP(ps,p).vector_size);
        break;
    case PROP_TYPE_IP:
    case PROP_TYPE_GUINT32:
        buf->data.guint32.def = g_memdup(
            PROP(ps,p).data.guint32.def, 
            sizeof(guint32) * PROP(ps,p).vector_size);
        buf->data.guint32.value = g_memdup(
            PROP(ps,p).data.guint32.value, 
            sizeof(guint32) * PROP(ps,p).vector_size);
        break;
    case PROP_TYPE_STRING:
        buf->data.string.def    = g_new(gchar*, 1);
        *buf->data.string.def   = g_strdup(*PROP(ps,p).data.string.def);
        buf->data.string.value  = g_new(gchar*, 1);
        *buf->data.string.value = g_strdup(*PROP(ps,p).data.string.value);
        break;
    case PROP_TYPE_STORAGE:
        buf->data.storage.value = g_memdup
            (PROP(ps,p).data.storage.value, PROP(ps,p).vector_size);
    }

    return buf;
}

void prop_free_def(prop_def_t *d)
{
    g_assert(d != NULL);

    switch(d->type) {
    case PROP_TYPE_BOOLEAN:
        g_free(d->data.boolean.value);
        g_free(d->data.boolean.def);
        break;
    case PROP_TYPE_IP:
    case PROP_TYPE_GUINT32:
        g_free(d->data.guint32.value);
        g_free(d->data.guint32.def);
        break;
    case PROP_TYPE_STRING:
        g_free(*d->data.string.value);
        g_free(*d->data.string.def);
        g_free(d->data.string.value);
        g_free(d->data.string.def);
        break;
    case PROP_TYPE_STORAGE:
        g_free(d->data.storage.value);
    }
    g_free(d);
} 

/*
 * prop_add_prop_changed_listener:
 *
 * Add a change listener to a given property. If init is TRUE then
 * the listener is immediately called.
 */
void prop_add_prop_changed_listener
    (prop_set_t *ps, property_t prop, prop_changed_listener_t l, gboolean init)
{
    g_assert(ps != NULL);
    g_assert(prop_in_range(ps, prop));
    
    LISTENER_ADD(PROP(ps,prop).prop_changed, l);
    
    if (init)
        (*l)(prop);
}

void prop_remove_prop_changed_listener
    (prop_set_t *ps, property_t prop, prop_changed_listener_t l)
{
    g_assert(ps != NULL);
    g_assert(prop_in_range(ps, prop));
    
    LISTENER_REMOVE(PROP(ps,prop).prop_changed, l);
}

static void prop_emit_prop_changed(prop_set_t *ps, property_t prop)
{
    GSList *l;

    g_assert(ps != NULL);

    for (
        l = PROP(ps,prop).prop_changed_listeners; 
        l != NULL; l = g_slist_next(l)
    ) {
        prop_changed_listener_t fn = (prop_changed_listener_t) l->data;   
        if ((*fn)(prop))
            break;
    }      
}

void prop_set_boolean(
    prop_set_t *ps, property_t prop, const gboolean *src,
    guint32 offset, guint32 length)
{
    gboolean old;
    gboolean new;
    gboolean differ = FALSE;
    guint32 n;

    g_assert(ps != NULL);
    g_assert(src != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_set_boolean: unknown property %d", prop);
    if(PROP(ps,prop).type != PROP_TYPE_BOOLEAN)
        g_error("Type mismatch setting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_BOOLEAN]);

    if (length == 0)
        length = PROP(ps,prop).vector_size;

    g_assert(offset+length <= PROP(ps,prop).vector_size);

    for (n = offset; (n < length) && !differ; n ++) {
        old = PROP(ps,prop).data.boolean.value[n] ? 1 : 0;
        new = src[n] ? 1 : 0;
        
        if (old != new)
            differ = TRUE;
    }

    if (!differ)
        return;

    memcpy(&PROP(ps,prop).data.boolean.value[offset], src, 
        length * sizeof(gboolean));

    if (debug >= 5) {
        guint32 n;

        printf("updated property [%s] = ( ", PROP(ps,prop).name);
            
        for(n = 0; n < PROP(ps,prop).vector_size; n ++)
            printf("%s%s ", 
                *PROP(ps,prop).data.boolean.value ? "TRUE" : "FALSE",
                (n < (PROP(ps,prop).vector_size-1)) ? "," : "");

        printf(")\n");
    }
    
    prop_emit_prop_changed(ps, prop);
}

gboolean *prop_get_boolean(
    prop_set_t *ps, property_t prop, gboolean *t, 
    guint32 offset, guint32 length)
{
    gboolean *target;

    g_assert(ps != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_get_boolean: unknown property %d", prop);
    if(PROP(ps,prop).type != PROP_TYPE_BOOLEAN)
        g_error("Type mismatch setting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_BOOLEAN]);

    if (length == 0)
        length = PROP(ps,prop).vector_size;

    g_assert(offset+length <= PROP(ps,prop).vector_size);

    target = t;
    if (target == NULL)
        target = g_new(gboolean, length);

    memcpy(target, &PROP(ps,prop).data.boolean.value[offset],
        sizeof(gboolean) * length);

    return target;
}

void prop_set_guint32(
    prop_set_t *ps, property_t prop, const guint32 *src,
    guint32 offset, guint32 length)
{
    gboolean differ = FALSE;

    g_assert(ps != NULL);
    g_assert(src != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_set_guint32: unknown property %d", prop);
    if((PROP(ps,prop).type != PROP_TYPE_GUINT32) &&
       (PROP(ps,prop).type != PROP_TYPE_IP))
        g_error("Type mismatch setting value for [%s] of type" 
            " %s when %s or %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_GUINT32],
            prop_type_str[PROP_TYPE_IP]);

    if (length == 0)
        length = PROP(ps,prop).vector_size;

    g_assert(offset+length <= PROP(ps,prop).vector_size);

    differ = (memcmp(&PROP(ps,prop).data.guint32.value[offset], src,
        length * sizeof(guint32)) != 0);

    if (!differ)
        return;

    /*
     * Only do bounds-checking on non-vector properties.
     */
    if (PROP(ps,prop).vector_size == 1) {
        if (
            (PROP(ps,prop).data.guint32.min <= *src) &&
            (PROP(ps,prop).data.guint32.max >= *src)
        ) {
            *PROP(ps,prop).data.guint32.value = *src;
        } else {
            g_warning("prop_set_guint32: [%s] new value of ouf bounds (%u/%u): %u",
                PROP(ps,prop).name,
                PROP(ps,prop).data.guint32.min,
                PROP(ps,prop).data.guint32.max,
                *src );
        }
    } else {
        memcpy(&PROP(ps,prop).data.guint32.value[offset], src,
            sizeof(guint32) * length);
    }

    if (debug >= 5) {
        guint32 n;

        printf("updated property [%s] = ( ", PROP(ps,prop).name);

        for (n = 0; n < PROP(ps,prop).vector_size; n ++) {
            if (PROP(ps,prop).type == PROP_TYPE_GUINT32) {
                printf("%u%s ", PROP(ps,prop).data.guint32.value[n],
                    (n < (PROP(ps,prop).vector_size-1)) ? "," : "");
            }
            if (PROP(ps,prop).type == PROP_TYPE_IP) {
                printf("%s%s ", ip_to_gchar(
                    PROP(ps,prop).data.guint32.value[n]),
                    (n < (PROP(ps,prop).vector_size-1)) ? "," : "");
            }
        }
    
        printf(")\n");
    }
    
    prop_emit_prop_changed(ps, prop);
}

guint32 *prop_get_guint32(
    prop_set_t *ps, property_t prop, guint32 *t,
    guint32 offset, guint32 length)
{
    guint32 *target;

    g_assert(ps != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_get_guint32: unknown property %d", prop);
    if((PROP(ps,prop).type != PROP_TYPE_GUINT32) &&
       (PROP(ps,prop).type != PROP_TYPE_IP))
        g_error("Type mismatch getting value for [%s] of type" 
            " %s when %s or %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_GUINT32],
            prop_type_str[PROP_TYPE_IP]);

   if (length == 0)
        length = PROP(ps,prop).vector_size;

    g_assert(offset+length <= PROP(ps,prop).vector_size);

    target = t;
    if (target == NULL)
        target = g_new(guint32, length);

    memcpy(target, &PROP(ps,prop).data.guint32.value[offset],
        sizeof(guint32) * length);

    return target;
}

void prop_set_storage
    (prop_set_t *ps, property_t prop, const guint8 *src, gsize length)
{
    gboolean differ = FALSE;

    g_assert(ps != NULL);
    g_assert(src != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_set_storage: unknown property %d", prop);
    if(PROP(ps,prop).type != PROP_TYPE_STORAGE)
        g_error("Type mismatch setting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_STORAGE]);

    g_assert(length == PROP(ps,prop).vector_size);

    differ = (memcmp(PROP(ps,prop).data.storage.value, src, length) != 0);

    if (!differ)
        return;

    memcpy(PROP(ps,prop).data.storage.value, src, length);

    if (debug >= 5) {
        printf("updated property [%s] (binary)\n", PROP(ps,prop).name);
        dump_hex(stderr, PROP(ps,prop).name, 
            PROP(ps,prop).data.storage.value, PROP(ps,prop).vector_size);
    }

    prop_emit_prop_changed(ps, prop);
}

guint8 *prop_get_storage
    (prop_set_t *ps, property_t prop, guint8 *t, gsize length)
{
    gpointer target;
   
    g_assert(ps != NULL);

    if (!prop_in_range(ps, prop))
        g_error("prop_get_storage: unknown property %d", prop);
    if (PROP(ps,prop).type != PROP_TYPE_STORAGE)
        g_error("Type mismatch getting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_STORAGE]);

    g_assert(length == PROP(ps,prop).vector_size);

    target = t;
    if (target == NULL)
        target = g_new(guint8, length);

    memcpy(target, PROP(ps,prop).data.storage.value, length);

    return target;
}

void prop_set_string(prop_set_t *ps, property_t prop, const gchar *val)
{
    gchar *old;
    gboolean differ = FALSE;

    g_assert(ps != NULL);

    if(!prop_in_range(ps, prop))
        g_error("prop_get_gchar: unknown property %d", prop);
    if(PROP(ps,prop).type != PROP_TYPE_STRING)
        g_error("Type mismatch getting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_STRING]);

    g_assert(PROP(ps,prop).vector_size == 1);

    old = *PROP(ps,prop).data.string.value;

    if (val == NULL) {
        /*
         * Clear property.
         */
        if (old != NULL) {
            g_free(old);
            differ = TRUE;
        }
    } else {
        /*
         * Update property.
         */
        if (old != NULL) {
            differ = strcmp(old, val) != 0;
            g_free(old);
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

/*
 * prop_get_string:
 *
 * Fetches the value of a string property. If a string buffer is provided
 * (t != NULL), then this is used. The size indicates the size of the given
 * string buffer and may not be 0 in this case. The pointer which is 
 * returned will point to the given buffer.
 * If no string buffer isgiven (t == NULL), new memory is allocated and 
 * returned. This memory must be free'ed later. The size parameter has
 * no effect in this case.
 */
gchar *prop_get_string
    (prop_set_t *ps, property_t prop, gchar *t, guint32 size)
{
    gchar *target;
    gchar *s;

    g_assert(ps != NULL);
    
    if (t != NULL)
        g_assert(size > 0);

    if(!prop_in_range(ps, prop))
        g_error("prop_get_gchar: unknown property %d", prop);
    if(PROP(ps,prop).type != PROP_TYPE_STRING)
        g_error("Type mismatch getting value for [%s] of type" 
            " %s when %s was expected",
            PROP(ps,prop).name,
            prop_type_str[PROP(ps,prop).type],
            prop_type_str[PROP_TYPE_STRING]);

    s = *PROP(ps,prop).data.string.value;

    target = t;
    if (target == NULL) {
        /*
         * Create new string.
         */
        target = (s != NULL) ? g_strdup(s) : NULL;
    } else {
        /*
         * Use given string buffer.
         */
        if (s == NULL) {
            target[0] = '\0';
            target = NULL;
        } else {
            g_snprintf(target, size, "%s", s);
        }
    }
        
    return target;
}


/*
 * config_boolean:
 *
 * Returns "TRUE" or "FALSE" depending on the given boolean value.
 */
static gchar *config_boolean(gboolean b)
{
	static gchar *b_true = "TRUE";
	static gchar *b_false = "FALSE";
	return (b) ? b_true : b_false;
}

/*
 * config_comment:
 *
 * Creates a string containing aset of lines from with words taken from s, 
 * each line no longerthen 80 chars (except when a single words is very long)
 * and prepended with "# ".
 */
static gchar *config_comment(const gchar *s)
{
    gchar **sv;
    gchar *tok;
    gint n;
    gint len = 0; /* length without "# " at the beginning */
    GString *out;
    static gchar result[2048];
    
    g_assert(s != NULL);

    out = g_string_new("# ");
    sv = g_strsplit(s, " ", 0);

    for(tok = sv[0], n = 0; tok != NULL; ++n, tok = sv[n]) {
        if ((len == 0) || ((len + strlen(sv[n]) < 78))) {
            /* append to this line */
            g_string_append(out, sv[n]);
            g_string_append_c(out, ' ');
            len += strlen(sv[n]);
        } else {
            /* end line and append to new line */
            g_string_append(out, "\n# ");
            g_string_append(out, sv[n]);
            len = strlen(sv[n]);
        }
    }

    g_snprintf(result, sizeof(result), "%s", out->str);

    g_string_free(out, TRUE);
    
    return result;
}

/*
 * prop_save_to_file:
 *
 * Read the all properties from the given property set and stores them
 * along with thier description to the given file in the given directory.
 * If this file was modified since the property set was read from it at
 * startup, the modifies file will be renamed to [filename].old before
 * saving.
 */
void prop_save_to_file
    (prop_set_t *ps, const gchar *dir, const gchar *_filename)
{
	FILE *config;
	time_t mtime = 0;
	struct stat buf;
	gchar *newfile;
    gchar *filename;
    gint n;

    g_assert(_filename != NULL);
    g_assert(ps != NULL);

    if (debug >= 2)
        printf("saving %s to %s/%s\n", ps->name, dir, _filename);

    if (!is_directory(dir))
        return;

    g_snprintf(prop_tmp, sizeof(prop_tmp), "%s/%s", dir, _filename);
    filename = g_strdup(prop_tmp);

    if (-1 == stat(filename, &buf))
		g_warning("could not stat \"%s\": %s", filename, g_strerror(errno));
	else
		mtime = buf.st_mtime;

    /*
	 * Rename old config file if they changed it whilst we were running.
	 */
	if (ps->mtime && mtime > ps->mtime) {
		gchar *old = g_strconcat(filename, ".old", NULL);
		g_warning("config file \"%s\" changed whilst I was running", filename);
		if (-1 == rename(filename, old))
			g_warning("unable to rename as \"%s\": %s", old, g_strerror(errno));
		else
			g_warning("renamed old copy as \"%s\"", old);
		g_free(old);
	}

	/*
	 * Create new file, which will be renamed at the end, so we don't
	 * clobber a good configuration file should we fail abrupbtly.
	 */
	newfile = g_strconcat(filename, ".new", NULL);

    config = fopen(newfile, "w");

	if (!config) {
		fprintf(stderr, "\nfopen(): %s\n"
			"\nUnable to write your configuration in %s\n"
			"Preferences have not been saved.\n\n",
				g_strerror(errno), newfile);
		goto end;
	}

#ifdef GTA_REVISION
	fprintf(config,
			"#\n# Gtk-Gnutella %u.%u %s (%s) by Olrick & Co.\n# %s\n#\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_REVISION, GTA_RELEASE,
			GTA_WEBSITE);
#else
	fprintf(config,
			"#\n# Gtk-Gnutella %u.%u (%s) by Olrick & Co.\n# %s\n#\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_RELEASE, GTA_WEBSITE);
#endif

    fprintf(config, "#\n# Description of contents\n");
    fprintf(config, "%s\n\n", config_comment(ps->desc));

    for (n = 0; n < ps->size; n ++) {
        prop_def_t *p = &ps->props[n];
        gchar **vbuf;
        gint i;
        gchar sbuf[1024];
        gchar *val = NULL;
        gboolean quotes = FALSE;

        if (p->save == FALSE)
            continue;

        vbuf = g_new(gchar*, p->vector_size+1);
        vbuf[0] = NULL;

        fprintf(config, "%s\n", config_comment(p->desc));

        switch(p->type) {
        case PROP_TYPE_BOOLEAN:
            for (i = 0; i < p->vector_size; i ++) {
                g_snprintf(sbuf, sizeof(sbuf), "%s", 
                    config_boolean(p->data.boolean.value[i]));
                vbuf[i] = g_strdup(sbuf);
            }
            vbuf[p->vector_size] = NULL;
                
            val = g_strjoinv(",", vbuf);
            break;
        case PROP_TYPE_GUINT32:
            for (i = 0; i < p->vector_size; i ++) {
                g_snprintf(sbuf, sizeof(sbuf), "%u", 
                        p->data.guint32.value[i]);
                vbuf[i] = g_strdup(sbuf);
            }
            vbuf[p->vector_size] = NULL;
                
            val = g_strjoinv(",", vbuf);
            break;
        case PROP_TYPE_STRING:
            val = g_strdup(*p->data.string.value);
            quotes = TRUE;
            break;
        case PROP_TYPE_IP:
            for (i = 0; i < p->vector_size; i ++) {
                g_snprintf(sbuf, sizeof(sbuf), "%s", 
                        ip_to_gchar(p->data.guint32.value[i]));
                vbuf[i] = g_strdup(sbuf);
            }
            vbuf[p->vector_size] = NULL;
                
            val = g_strjoinv(",", vbuf);
            break;
        case PROP_TYPE_STORAGE:
            val = g_new(guint8, (p->vector_size*2)+1);

            /*
             * This may not be entirely portable to architectures where
             * a byte is not 8 bits. Also see guid_hex_str in misc.c
             *      -- Richard, 12/08/200
             */
            for (i = 0; i < p->vector_size; i ++)
                g_snprintf(&val[(i*2)], 3, "%02x", p->data.storage.value[i]);
    
            val[(p->vector_size*2)] = '\0';
            quotes = TRUE;
            break;
        };

        g_assert(val != NULL);

        fprintf(config, "%s = %s%s%s\n\n", p->name, 
            quotes ? "\"" : "", val, quotes ? "\"" : "");
    
        g_free(val);
        g_strfreev(vbuf);
    }
    
    fprintf(config, "### End of configuration file ###\n");

	/*
	 * Rename saved configuration file on success.
	 */

	if (0 == fclose(config)) {
		if (-1 == rename(newfile, filename))
			g_warning("could not rename %s as %s: %s",
				newfile, filename, g_strerror(errno));
	} else
		g_warning("could not flush %s: %s", newfile, g_strerror(errno));

end:
	g_free(newfile);
    g_free(filename);
}

/*
 * load_helper:
 *
 * Called by prop_load_from_file to actually set the properties.
 */
static void load_helper(prop_set_t *ps, property_t prop, const gchar *val)
{
    prop_def_t *p = &PROP(ps,prop);
    prop_set_stub_t *stub;
    static guchar vecbuf[100];

    stub = ps->get_stub();

    switch(p->type) {
    case PROP_TYPE_BOOLEAN:
        g_assert(
            (p->vector_size * sizeof(gboolean)) < 
            (sizeof(vecbuf) * sizeof(vecbuf[0])));
    
        prop_parse_boolean_vector(val, p->vector_size, (gboolean *)vecbuf);
        stub->boolean.set(prop, (gboolean *)&vecbuf, 0, 0);
        break;
    case PROP_TYPE_GUINT32:
        g_assert(
            (p->vector_size * sizeof(guint32)) < 
            (sizeof(vecbuf) * sizeof(vecbuf[0])));

        prop_parse_guint32_vector(val, p->vector_size, (guint32 *)vecbuf);
        stub->guint32.set(prop, (guint32 *)&vecbuf, 0, 0);
        break;
    case PROP_TYPE_STRING:
        stub->string.set(prop, val);
        break;
    case PROP_TYPE_IP:
        g_assert(
            (p->vector_size * sizeof(guint32)) < 
            (sizeof(vecbuf) * sizeof(vecbuf[0])));

        prop_parse_guint32_vector(val, p->vector_size, (guint32 *)vecbuf);
        stub->guint32.set(prop, (guint32 *)&vecbuf, 0, 0);
        break;
    case PROP_TYPE_STORAGE: {
        guint8 *buf = g_new(guint8, p->vector_size);
    
        prop_parse_storage(val, p->vector_size, buf);
        stub->storage.set(prop, buf, p->vector_size);

        g_free(buf);
        break;
    }
    };

    g_free(stub);
}

void prop_load_from_file
    (prop_set_t *ps, const gchar *dir, const gchar *filename)
{
	FILE *config;
	gchar *s, *k, *v;
	property_t i;
	guint32 n = 0;
	struct stat buf;

	static gchar *err = "Bad line %u in config file, ignored\n";

    g_assert(dir != NULL);
    g_assert(filename != NULL);
    g_assert(ps != NULL);

    if (!is_directory(dir))
        return;

    g_snprintf(prop_tmp, sizeof(prop_tmp), "%s/%s", dir, filename);

	config = fopen(prop_tmp, "r");
	if (!config)
		return;

	if (-1 == fstat(fileno(config), &buf))
		g_warning("could open but not fstat \"%s\" (fd #%d): %s",
			prop_tmp, fileno(config), g_strerror(errno));
    else
		ps->mtime = buf.st_mtime;

	while (fgets(prop_tmp, sizeof(prop_tmp), config)) {
		n++;
		s = prop_tmp;
		while (*s && (*s == ' ' || *s == '\t'))
			s++;
		if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')))
			continue;
		k = s;
		while (*s == '_' || (*s >= 'A' && *s <= 'Z')
			   || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9'))
			s++;
		if (*s != '=' && *s != ' ' && *s != '\t') {
			fprintf(stderr, err, n);
			continue;
		}
		v = s;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s != '=') {
			fprintf(stderr, err, n);
			continue;
		}
		*v = 0;
		s++;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '"') {
			v = ++s;
			while (*s && *s != '\n' && *s != '"')
				s++;
			if (!*s || *s == '\n') {
				fprintf(stderr, err, n);
				continue;
			}
		} else {
			v = s;
			while (*s && *s != '\n' && *s != ' ' && *s != '\t')
				s++;
		}
		*s = 0;


		for (i = 0; i < ps->size; i++)
			if (!g_strcasecmp(k, (ps->props[i]).name)) {
                load_helper(ps, i+ps->offset, v);
				break;
			}

		if (i >= ps->size)
			fprintf(stderr,
					"config file, line %u: unknown keyword '%s', ignored\n",
					n, k);
	}

	fclose(config);
}
