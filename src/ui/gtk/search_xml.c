/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Richard Eckart
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
 * @ingroup gtk
 * @file
 *
 * Persistance for searches and filters in XML format.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "gui.h"

RCSID("$Id$");

#include <libxml/tree.h>
#include <libxml/parser.h>

#include "filter_core.h"
#include "search_xml.h"
#include "settings.h"
#include "search.h"

#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"

#include "lib/getdate.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"		/* Must be the last header included */

#define GLOBAL_PRE 0
#define GLOBAL_POST 1

#define TO_BOOL(v) ((v) != 0 ? TRUE : FALSE)

typedef struct node_parser {
    const gchar *name;
    void (*parser_func)(xmlNodePtr, gpointer);
} node_parser_t;


/*
 * The rulesets are defined in filter.c, but I don't want
 * them to be public. They are only needed here. As are
 * global_ruleset_pre and global_ruleset_post.
 */
extern void dump_ruleset(GList *ruleset);
extern void dump_filter(filter_t *filter);

extern GList *filters;
extern GList *filters_current;

/*
 * Private function prototypes
 */
static void parse_xml(xmlNodePtr xmlnode, gpointer user_data);
static void builtin_to_xml(xmlNodePtr);
static void search_to_xml(xmlNodePtr, search_t *);
static void filter_to_xml(xmlNodePtr, filter_t *);
static void rule_to_xml(xmlNodePtr, rule_t *);
static void xml_to_builtin(xmlNodePtr, gpointer);
static void xml_to_search(xmlNodePtr, gpointer);
static void xml_to_filter(xmlNodePtr, gpointer);
static void xml_to_text_rule(xmlNodePtr, gpointer);
static void xml_to_ip_rule(xmlNodePtr, gpointer);
static void xml_to_size_rule(xmlNodePtr, gpointer);
static void xml_to_jump_rule(xmlNodePtr, gpointer);
static void xml_to_sha1_rule(xmlNodePtr, gpointer);
static void xml_to_flag_rule(xmlNodePtr, gpointer);
static void xml_to_state_rule(xmlNodePtr, gpointer);
static guint16 get_rule_flags_from_xml(xmlNodePtr);
static xmlAttrPtr xml_prop_printf(xmlNodePtr node, const gchar *name,
	const char *fmt, ...) G_GNUC_PRINTF(3, 4);

/*
 * Private variables
 */
static const gchar NODE_BUILTIN[]     = "BuiltIn";
static const gchar NODE_SEARCH[]      = "Search";
static const gchar NODE_FILTER[]      = "Filter";
static const gchar NODE_RULE_TEXT[]   = "TextRule";
static const gchar NODE_RULE_IP[]     = "IpRule";
static const gchar NODE_RULE_SIZE[]   = "SizeRule";
static const gchar NODE_RULE_JUMP[]   = "JumpRule";
static const gchar NODE_RULE_SHA1[]   = "SHA1Rule";
static const gchar NODE_RULE_FLAG[]   = "FlagRule";
static const gchar NODE_RULE_STATE[]  = "StateRule";

static const gchar TAG_BUILTIN_SHOW_UID[]       = "ShowUID";
static const gchar TAG_BUILTIN_DROP_UID[]       = "DropUID";
static const gchar TAG_BUILTIN_DOWNLOAD_UID[]   = "DownloadUID";
static const gchar TAG_BUILTIN_NODOWNLOAD_UID[] = "NoDownloadUID";
static const gchar TAG_BUILTIN_RETURN_UID[]     = "ReturnUID";
static const gchar TAG_FILTER_NAME[]            = "Name";
static const gchar TAG_FILTER_GLOBAL[]          = "Global";
static const gchar TAG_FILTER_UID[]             = "UID";
static const gchar TAG_FILTER_ACTIVE[]          = "Active";
static const gchar TAG_SEARCH_QUERY[]           = "Query";
static const gchar TAG_SEARCH_ENABLED[]         = "Enabled";
static const gchar TAG_SEARCH_SPEED[]           = "Speed";
static const gchar TAG_SEARCH_PASSIVE[]         = "Passive";
static const gchar TAG_SEARCH_REISSUE_TIMEOUT[] = "ReissueTimeout";
static const gchar TAG_SEARCH_CREATE_TIME[] 	= "CreateTime";
static const gchar TAG_SEARCH_LIFETIME[] 		= "LifeTime";
static const gchar TAG_SEARCH_SORT_COL[]        = "SortCol";
static const gchar TAG_SEARCH_SORT_ORDER[]      = "SortOrder";
static const gchar TAG_RULE_TEXT_CASE[]         = "Case";
static const gchar TAG_RULE_TEXT_MATCH[]        = "Match";
static const gchar TAG_RULE_TEXT_TYPE[]         = "Type";
static const gchar TAG_RULE_IP_ADDR[]           = "Address";
static const gchar TAG_RULE_IP_MASK[]           = "Netmask";
static const gchar TAG_RULE_SIZE_LOWER[]        = "Lower";
static const gchar TAG_RULE_SIZE_UPPER[]        = "Upper";
static const gchar TAG_RULE_SHA1_HASH[]         = "Hash";
static const gchar TAG_RULE_SHA1_FILENAME[]     = "OriginalFilename";
static const gchar TAG_RULE_NEGATE[]            = "Negate";
static const gchar TAG_RULE_ACTIVE[]            = "Active";
static const gchar TAG_RULE_SOFT[]              = "Soft";
static const gchar TAG_RULE_TARGET[]            = "Target";
static const gchar TAG_RULE_FLAG_BUSY[]         = "Busy";
static const gchar TAG_RULE_FLAG_PUSH[]         = "Push";
static const gchar TAG_RULE_FLAG_STABLE[]       = "Stable";
static const gchar TAG_RULE_STATE_DISPLAY[]     = "Display";
static const gchar TAG_RULE_STATE_DOWNLOAD[]    = "Download";

static const gchar search_file_xml[] = "searches.xml";
static const gchar search_file_xml_new[] = "searches.xml.new";
static const gchar search_file_xml_old[] = "searches.xml.orig";

static GHashTable *target_map = NULL;
static GHashTable *id_map = NULL;

static node_parser_t parser_map[] = {
    { NODE_BUILTIN,     xml_to_builtin },
    { NODE_SEARCH,      xml_to_search },
    { NODE_FILTER,      xml_to_filter },
    { NODE_RULE_TEXT,   xml_to_text_rule },
    { NODE_RULE_IP,     xml_to_ip_rule },
    { NODE_RULE_SIZE,   xml_to_size_rule },
    { NODE_RULE_JUMP,   xml_to_jump_rule },
    { NODE_RULE_SHA1,   xml_to_sha1_rule },
    { NODE_RULE_FLAG,   xml_to_flag_rule },
    { NODE_RULE_STATE,  xml_to_state_rule },
    { NULL, NULL }
};

/** Get rid of the obnoxious (xmlChar *) */
static inline gchar *
xml_get_string(xmlNode *node, const gchar *id)
{
	return (gchar *) xmlGetProp(node, (const xmlChar *) id);
}

static inline const xmlChar *
string_to_xmlChar(const gchar *p)
{
	return (const xmlChar *) p;
}

static inline xmlNodePtr
xml_new_empty_child(xmlNodePtr parent, const gchar *name)
{
	return xmlNewChild(parent, NULL, string_to_xmlChar(name), NULL);
}


/**
 * A wrapper around parse_uint64. It's a little stricter, so that trailing
 * characters enforce an error. It accepts base 10 (decimal) only. On failure
 * *error will be set to a non-zero "errno" value.
 *
 * @param buf the string to parse.
 * @param error an int variable which will indicate success or failure.
 * @return On success, the parsed value is returned.
 */
static guint64
parse_number(const gchar *buf, gint *error)
{
	const gchar *endptr;
	guint64 ret;

	g_assert(buf != NULL);
	g_assert(error != NULL);

	ret = parse_uint64(buf, &endptr, 10, error);
	if (0 == *error && *endptr != '\0') {
		*error = EINVAL;
	}
	if (0 != *error) {
		g_message("buf=\"%s\"", buf);
		return 0;
	}

	return ret;
}

/**
 * A wrapper around parse_uint64. It's a little stricter, so that trailing
 * characters enforce an error. It accepts base 16 (decimal) only. On failure
 * *error will be set to a non-zero "errno" value. The value is casted to
 * a pointer.
 *
 * @param buf the string to parse.
 * @param error an int variable which will indicate success or failure.
 * @return On success, the parsed value is returned as a pointer.
 */
static gpointer
parse_target(const gchar *buf, gint *error)
{
	const gchar *endptr;
	guint64 v;
	gulong target; /* Not guint32! for backwards compatibility. See below. */

	g_assert(buf != NULL);
	g_assert(error != NULL);

	if ('0' == buf[0] && 'x' == buf[1]) {
		/*
		 * In previous versions, targets were printed using "%p". This format
		 * is implementation-specific and thus causes a non-portable
		 * configuration. We expect a hexadecimal value that is optionally
		 * preceded by "0x".
		 */
		buf += 2;
	}

	v = parse_uint64(buf, &endptr, 16, error);
	if (0 == *error && *endptr != '\0') {
		*error = EINVAL;
	}
	/*
	 * For backwards compatibility we allow values above 2^32-1 if the
	 * machine doesn't use 32-bit wide pointers. Older versions used
	 * the pointer casted to an integer type as target ID.
	 */
	if (0 == *error && 4 == sizeof(gpointer) && v > (~(guint32) 0)) {
		*error = ERANGE;
	}
	if (0 != *error) {
		g_message("buf=\"%s\"", buf);
		return NULL;
	}

	target = v;

	/* Not using GUINT_TO_POINTER() is intentional to prevent truncation
	 * to 32-bit for backwards compability as explained above. */
	return (gpointer) target;
}

/**
 * Returns the next available target ID.
 *
 * @param do_reset if TRUE, the ID counter is reset to an initial value.
 * @return a 32-bit integer stuffed into a pointer
 */
static gpointer 
target_new_id(gboolean do_reset)
{
	static guint32 id_counter;
	guint32 ret;

	/* If target_map is NULL, the counter is reset */
	if (do_reset) {
		id_counter = 0;
	} else {
		id_counter++;
		/* 4 billion filters/searches should be enough for everyone */
		g_assert(0 != id_counter);
	}

	ret = id_counter;
	return GUINT_TO_POINTER(ret);
}

/**
 * Resets the target ID counter and frees target_map if it was created.
 */
static void
target_map_reset(void)
{
	target_new_id(TRUE); /* Reset */
	if (target_map) {
		g_hash_table_destroy(target_map);
		target_map = NULL;
	}
}

/**
 * Creates a string representation of a ``target''.
 *
 * @param target a filter target
 * @return a static buffer holding the string representation
 */
static const gchar *
target_to_string(filter_t *target)
{
	gpointer value;
	static gchar buf[128];

	if (!target_map) {
		target_new_id(TRUE); /* Reset */
		target_map = g_hash_table_new(NULL, NULL);
	}

	if (!g_hash_table_lookup_extended(target_map, target, NULL, &value)) {
		value = target_new_id(FALSE);
		g_hash_table_insert(target_map, target, value);
	}

    gm_snprintf(buf, sizeof buf, "0x%x", GPOINTER_TO_UINT(value));

	return buf;
}

/**
 * A wrapper around xmlSetProp() to get rid of (xmlChar *).
 *
 * @param node the node
 * @param name the attribute name
 * @param value an UTF-8 encoded string
 * @return the result of xmlSetProp().
 */
static inline xmlAttrPtr
xml_prop_set(xmlNodePtr node, const gchar *name, const char *value)
{
    return xmlSetProp(node, string_to_xmlChar(name), string_to_xmlChar(value));
}

/**
 * A wrapper to set use xmlSetProp() through a printf-like interface. The
 * length of the created string is limited to 4096 byte and truncation occurs
 * if this limit is exceeded. For mere strings or longer values use
 * xml_prop_set() instead.
 *
 * @param node the node
 * @param name the attribute name
 * @param fmt the format string
 * @return the result of xmlSetProp().
 */
static xmlAttrPtr
xml_prop_printf(xmlNodePtr node, const gchar *name, const char *fmt, ...)
{
	va_list ap;
	gchar buf[4096];

	va_start(ap, fmt);
	gm_vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
    return xml_prop_set(node, name, buf);
}

/**
 * Store pending searches.
 */
void
search_store_xml(void)
{
	const GList *l;
	time_t now = tm_time();
    xmlDocPtr doc;
    xmlNodePtr root;
	gchar *filename_new;


	/* Free target_map and reset the target ID counter */
	target_map_reset();

    /*
     * Create new xml document with version 1.0
     */
    doc = xmlNewDoc(string_to_xmlChar("1.0"));

    /*
     * Create a new root node "gtkGnutella searches"
     */
    root = xmlNewDocNode(doc, NULL, string_to_xmlChar("Searches"), NULL);
    xmlDocSetRootElement(doc, root);
	/* Discard the newline of the ctime string */
    xml_prop_printf(root, "Time", "%24.24s", ctime(&now));
    xml_prop_printf(root, "Version", "%s", GTA_VERSION_NUMBER);

    /*
     * Store UIDs for the builtin targets
     */
    builtin_to_xml(root);

    /*
     * Iterate over the searches and add them to the tree
     */
    for (l = search_gui_get_searches(); l; l = g_list_next(l))
        search_to_xml(root, l->data);

    /*
     * Iterate over the rulesets and add them to the tree.
     * Only those that are not bound to a search.
     */
    for (l = filters; l; l = g_list_next(l))
        filter_to_xml(root, l->data);

    /*
     * Try to save the file
     */

    xmlKeepBlanksDefault(0);
    filename_new = make_pathname(settings_gui_config_dir(),
						search_file_xml_new);

    if (
		NULL == filename_new ||
		-1 == xmlSaveFormatFile(filename_new, doc, TRUE)
	) {
        g_warning("Unable to create %s to persist search: %s",
			filename_new, g_strerror(errno));
    } else {
		gchar *filename;

        if (gui_debug >= 3)
            g_message("saved searches file: %s", filename_new);

		filename = make_pathname(settings_gui_config_dir(), search_file_xml);

		if (
			NULL == filename ||
			NULL == filename_new ||
			-1 == rename(filename_new, filename)
		)
			g_warning("could not rename %s as %s: %s",
				filename_new, filename, g_strerror(errno));

		G_FREE_NULL(filename);
    }

	G_FREE_NULL(filename_new);

	xmlFreeDoc(doc);

	/* Free target_map and reset the target ID counter */
	target_map_reset();
}

/**
 * Retrieve search list and restart searches.
 * This is the new xml version. The searches are normally
 * retrieved from  ~/.gtk-gnutella/searches.xml.
 */
gboolean
search_retrieve_xml(void)
{
	xmlDocPtr doc;
    xmlNodePtr node;
    xmlNodePtr root;
	GList  *f, *f_next;
	gchar *path = NULL;
	gchar *path_orig = NULL;

	/*
	 * We can't use routines from file.c here because libxml2 only defines
	 * interfaces for parsing a path or memory, but not for parsing a FILE
	 * stream!  Unbelievable.
	 *		--RAM, 16/07/2003
	 */

  	path = make_pathname(settings_gui_config_dir(), search_file_xml);
	if (NULL == path)
		goto out;

  	path_orig = make_pathname(settings_gui_config_dir(), search_file_xml_old);
	if (NULL == path_orig)
		goto out;

	/*
     * If the file doesn't exist, try retrieving from the .orig version.
     */

	if (file_exists(path)) {
		if (-1 == rename(path, path_orig)) {
			g_warning("could not rename \"%s\" as \"%s\": %s",
				path, path_orig, g_strerror(errno));
			G_FREE_NULL(path_orig);
			path_orig = path;
			path = NULL;
		} else {
			G_FREE_NULL(path);
		}
	} else {
        g_warning("searches file does not exist: %s", path);
		G_FREE_NULL(path);

		if (!file_exists(path_orig))
			goto out;

		g_warning("retrieving searches from %s instead", path_orig);
    }

	/*
     * parse the file and put the result into newdoc
     */
	doc = xmlParseFile(path_orig);
    root = xmlDocGetRootElement(doc);

	/*
     * in case something went wrong
     */
    if (!doc) {
        g_warning("error parsing searches file: %s", path_orig);
		goto out;
    }

	if (/* if there is no root element */
        (root == NULL) ||
	    /* if it doesn't have a name */
	    (root->name == NULL) ||
	    /* if it isn't a Genealogy node */
	    g_ascii_strcasecmp((const gchar *) root->name, "Searches") != 0
    ) {
        g_warning("searches file has invalid format: %s", path);
		xmlFreeDoc(doc);
		goto out;
	}
	G_FREE_NULL(path_orig);

    id_map = g_hash_table_new(NULL, NULL);

    /*
     * find nodes and add them to the list, this just
	 * loops through all the children of the root of the document
     */
	for (node = root->children; node != NULL; node = node->next)
        parse_xml(node, NULL);

    /*
     * We should have collected all ruleset UIDs now. So we can
     * now resolve the UIDs to the actual pointers we use now.
     * We need to commit before we do this, because we want to
     * interate over the rulesets and don't want to cope with
     * shadows.
     */

    if (gui_debug >= 6)
        g_message("resolving UIDs");

    for (f = filters; f != NULL; f = f_next) {
		gboolean damaged = FALSE;
        filter_t *filter = f->data;
        GList *r;
        gint n = 0;

		f_next = g_list_next(f);

        if (gui_debug >= 6) {
            g_message("\n\nresolving on filter:");
            dump_filter(filter);
        }

        if (!filter_is_builtin(filter)) {

            for (r = filter->ruleset; r != NULL; r = g_list_next(r)) {
                rule_t *rule = r->data;
                gpointer new_target;

                g_assert(rule->target != NULL);
                new_target = g_hash_table_lookup(id_map, rule->target);
                if (new_target == NULL) {
                    g_warning("Failed to resolve rule %d in \"%s\": "
						"missing key %p",
                        n, filter->name,
						cast_to_gconstpointer(filter_rule_to_string(rule)));

					/* Remove the corrupted filter, we can't handle it */
					damaged = TRUE;
					break;
				}
                rule->target = new_target;
                set_flags(rule->flags, RULE_FLAG_VALID);

                /*
                 * We circumvent the shadows, so we must do refcounting
                 * manually here.
                 */
                if (gui_debug >= 7) {
                    g_message("increasing refcount on \"%s\" to %d",
                        rule->target->name, rule->target->refcount + 1);
				}
                rule->target->refcount++;
                n++;
            }
        }

        if (gui_debug >= 6) {
			g_message("resolved filter:");
            dump_filter(filter);
        }

		if (damaged) {
			g_warning("Removing damaged ruleset from filter (name=\"%s\")",
				filter->name);
			/* This causes a little memory leak but the priority is
			 * not to crash. */
			filter->ruleset = NULL;
		}
    }

	/*
     * Verify bindings.
     */
    {
        gboolean borked = FALSE;
        const GList *s;

        if (gui_debug >= 6)
            g_message("verifying bindings...");

        for (s = search_gui_get_searches(); s != NULL; s = g_list_next(s)) {
            search_t *search = s->data;

            if (search->filter->search == search) {
                if (gui_debug >= 6)
                    g_message("binding ok for: %s", search->query);
            } else {
                g_warning("binding broken for: %s", search->query);
                borked = TRUE;
            }
        }

        g_assert(!borked);
    }

    g_list_free(filters_current);
    filters_current = g_list_copy(filters);

    g_hash_table_destroy(id_map);

	xmlFreeDoc(doc);
    xmlCleanupParser();

	return TRUE;

out:
	G_FREE_NULL(path);
	G_FREE_NULL(path_orig);

	return FALSE;
}

static void
builtin_to_xml(xmlNodePtr parent)
{
	const struct {
		const gchar *tag;
		filter_t * (* target)(void);
	} builtins[] = {
		{ TAG_BUILTIN_SHOW_UID, filter_get_show_target },
		{ TAG_BUILTIN_DROP_UID, filter_get_drop_target },
		{ TAG_BUILTIN_DOWNLOAD_UID, filter_get_download_target },
		{ TAG_BUILTIN_NODOWNLOAD_UID, filter_get_nodownload_target },
		{ TAG_BUILTIN_RETURN_UID, filter_get_return_target },
	};
    xmlNodePtr newxml;
	guint i;

    g_assert(parent != NULL);

    newxml = xml_new_empty_child(parent, NODE_BUILTIN);
	for (i = 0; i < G_N_ELEMENTS(builtins); i++) {
    	xml_prop_set(newxml, builtins[i].tag,
			target_to_string(builtins[i].target()));
	}
}

static void
search_to_xml(xmlNodePtr parent, search_t *s)
{
    xmlNodePtr newxml;
    GList *iter;

    g_assert(s != NULL);
    g_assert(s->query != NULL);
    g_assert(parent != NULL);

	if (s->browse)
		return;			/* Don't persist "browse host" searches. */

    if (gui_debug >= 6) {
        g_message(
			"saving search: %s (%p enabled=%d)\n"
			"  -- filter is bound to: %p\n"
			"  -- search is         : %p",
			s->query, cast_to_gconstpointer(s), s->enabled,
			cast_to_gconstpointer(s->filter->search),
			cast_to_gconstpointer(s));
    }

    newxml = xml_new_empty_child(parent, NODE_SEARCH);
    xml_prop_set(newxml, TAG_SEARCH_QUERY, s->query);

	xml_prop_printf(newxml, TAG_SEARCH_ENABLED, "%u", s->enabled);
    xml_prop_printf(newxml, TAG_SEARCH_PASSIVE, "%u", TO_BOOL(s->passive));
    xml_prop_printf(newxml, TAG_SEARCH_REISSUE_TIMEOUT, "%u",
		guc_search_get_reissue_timeout(s->search_handle));
    xml_prop_printf(newxml, TAG_SEARCH_CREATE_TIME, "%s",
		timestamp_to_string(guc_search_get_create_time(s->search_handle)));
    xml_prop_printf(newxml, TAG_SEARCH_LIFETIME, "%u",
		guc_search_get_lifetime(s->search_handle));
    xml_prop_printf(newxml, TAG_SEARCH_SORT_COL, "%d", s->sort_col);
    xml_prop_printf(newxml, TAG_SEARCH_SORT_ORDER, "%d", s->sort_order);

    for (iter = s->filter->ruleset; iter != NULL; iter = g_list_next(iter))
        rule_to_xml(newxml, iter->data);
}


static void
filter_to_xml(xmlNodePtr parent, filter_t *f)
{
    xmlNodePtr newxml;
    GList *l;

    g_assert(f != NULL);
    g_assert(f->name != NULL);
    g_assert(parent != NULL);

    /*
     * Don't store the builtin targets or bound rulesets
     */
    if (filter_is_builtin(f) || filter_is_bound(f)) {
        if (gui_debug >= 7)
            g_message("not saving bound/builtin: %s", f->name);
        return;
    }

    if (gui_debug >= 6) {
		g_message(
			"saving filter: %s\n"
			"  -- bound   : %p",
			f->name,
			cast_to_gconstpointer(f->search));
    }

	g_assert(utf8_is_valid_string(f->name));
    newxml = xml_new_empty_child(parent, NODE_FILTER);
    xml_prop_set(newxml, TAG_FILTER_NAME, f->name);
    xml_prop_printf(newxml, TAG_FILTER_ACTIVE,
		"%u", TO_BOOL(filter_is_active(f)));

    /*
     * We take the pointer as a unique id which
     * we use during read-in for setting the
     * destination of JUMP actions.
     */
    xml_prop_set(newxml, TAG_FILTER_UID, target_to_string(f));

    if (filter_get_global_pre() == f) {
        xml_prop_printf(newxml, TAG_FILTER_GLOBAL, "%u", GLOBAL_PRE);
    }

    if (filter_get_global_post() == f) {
        xml_prop_printf(newxml, TAG_FILTER_GLOBAL, "%u", GLOBAL_POST);
    }

    /*
     * Since free rulesets don't have bound searches,
     * we need not save the ->search member.
     * Visited is only used internally during filter
     * application.
     */
    for (l = f->ruleset; l != NULL; l = g_list_next(l))
        rule_to_xml(newxml, l->data);
}

static void
rule_to_xml(xmlNodePtr parent, rule_t *r)
{
    xmlNodePtr newxml = NULL;

    g_assert(parent != NULL);

    /*
     * We create no node when there is no filter rule.
     */
    if (r == NULL)
        return;

    switch (r->type) {
    case RULE_TEXT:
		g_assert(utf8_is_valid_string(r->u.text.match));
		newxml = xml_new_empty_child(parent, NODE_RULE_TEXT);
       	xml_prop_set(newxml, TAG_RULE_TEXT_CASE,
			r->u.text.case_sensitive ? "1" : "0");
       	xml_prop_set(newxml, TAG_RULE_TEXT_MATCH, r->u.text.match);
       	xml_prop_printf(newxml, TAG_RULE_TEXT_TYPE, "%u", r->u.text.type);
        break;
    case RULE_IP:
        newxml = xml_new_empty_child(parent, NODE_RULE_IP);
        xml_prop_set(newxml, TAG_RULE_IP_ADDR,
			host_addr_to_string(r->u.ip.addr));
        xml_prop_printf(newxml, TAG_RULE_IP_MASK, "%u", r->u.ip.mask);
        break;
    case RULE_SIZE:
		{
			gchar buf[UINT64_DEC_BUFLEN];

			uint64_to_string_buf(r->u.size.lower, buf, sizeof buf);
        	newxml = xml_new_empty_child(parent, NODE_RULE_SIZE);
        	xml_prop_printf(newxml, TAG_RULE_SIZE_LOWER, "%s", buf);
			uint64_to_string_buf(r->u.size.upper, buf, sizeof buf);
        	xml_prop_printf(newxml, TAG_RULE_SIZE_UPPER, "%s", buf);
		}
        break;
    case RULE_JUMP:
        newxml = xml_new_empty_child(parent, NODE_RULE_JUMP);

        /*
         * Only need target to this rule and that's done below.
         */
        break;
    case RULE_SHA1:
       	newxml = xml_new_empty_child(parent, NODE_RULE_SHA1);

       	if (r->u.sha1.hash != NULL)
           	xml_prop_set(newxml, TAG_RULE_SHA1_HASH,
				sha1_base32(r->u.sha1.hash));

		g_assert(utf8_is_valid_string(r->u.sha1.filename));
		xml_prop_set(newxml, TAG_RULE_SHA1_FILENAME, r->u.sha1.filename);
        /*
         * r->u.sha1.hash is NULL, we just omit the hash.
         */
        break;
    case RULE_FLAG:
        newxml = xml_new_empty_child(parent, NODE_RULE_FLAG);

        xml_prop_printf(newxml, TAG_RULE_FLAG_STABLE, "%u", r->u.flag.stable);
        xml_prop_printf(newxml, TAG_RULE_FLAG_BUSY, "%u", r->u.flag.busy);
        xml_prop_printf(newxml, TAG_RULE_FLAG_PUSH, "%u", r->u.flag.push);
        break;
    case RULE_STATE:
        newxml = xml_new_empty_child(parent, NODE_RULE_STATE);
        xml_prop_printf(newxml, TAG_RULE_STATE_DISPLAY,
			"%u", r->u.state.display);
        xml_prop_printf(newxml, TAG_RULE_STATE_DOWNLOAD,
			"%u", r->u.state.download);
        break;
    default:
        g_error("Unknown rule type: 0x%x", r->type);
    }

    xml_prop_printf(newxml, TAG_RULE_NEGATE, "%u", TO_BOOL(RULE_IS_NEGATED(r)));
    xml_prop_printf(newxml, TAG_RULE_ACTIVE, "%u", TO_BOOL(RULE_IS_ACTIVE(r)));
    xml_prop_printf(newxml, TAG_RULE_SOFT, "%u", TO_BOOL(RULE_IS_SOFT(r)));
    xml_prop_set(newxml, TAG_RULE_TARGET, target_to_string(r->target));
}

static void
parse_xml(xmlNodePtr xmlnode, gpointer user_data)
{
    gint n;

    g_assert(xmlnode != NULL);

    if (xmlIsBlankNode(xmlnode))
        return;

    if (!xmlnode->name) {
        g_warning("Unnamed node: ignored");
	    return;
    }

    for (n = 0; parser_map[n].name != NULL; n ++) {
        if (
			0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					(const gchar *) parser_map[n].name)
		) {
            parser_map[n].parser_func(xmlnode, user_data);
            return;
        }
    }

    g_warning("Unknown node: \"%s\"", xmlnode->name);
}

static void
xml_to_builtin(xmlNodePtr xmlnode, gpointer unused_udata)
{
    gchar *buf;
    gpointer target;
	gint error;

	(void) unused_udata;
    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_BUILTIN));
    g_assert(filter_get_show_target() != NULL);
    g_assert(filter_get_drop_target() != NULL);
    g_assert(filter_get_download_target() != NULL);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_BUILTIN_SHOW_UID));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_builtin: %s", g_strerror(error));
		goto failure;
	}
    g_hash_table_insert(id_map, target, filter_get_show_target());
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_BUILTIN_DROP_UID));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_builtin: %s", g_strerror(error));
		goto failure;
	}
    g_hash_table_insert(id_map, target, filter_get_drop_target());
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_BUILTIN_DOWNLOAD_UID));
    if (buf != NULL) {
    	target = parse_target(buf, &error);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			goto failure;
		}
        g_hash_table_insert(id_map, target, filter_get_download_target());
    } else {
        g_warning("xml_to_builtin: no \"DOWNLOAD\" target");
    }
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_BUILTIN_NODOWNLOAD_UID));
    if (buf != NULL) {
    	target = parse_target(buf, &error);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			goto failure;
		}
        g_hash_table_insert(id_map, target, filter_get_nodownload_target());
    } else {
        g_warning("xml_to_builtin: no \"DON'T DOWNLOAD\" target");
    }
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_BUILTIN_RETURN_UID));
    if (buf != NULL) {
    	target = parse_target(buf, &error);
        G_FREE_NULL(buf);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			return;
		}
        g_hash_table_insert(id_map, target, filter_get_return_target());
    } else {
        g_warning("xml_to_builtin: no \"RETURN\" target");
    }

failure:
	G_FREE_NULL(buf);
}

static void
xml_to_search(xmlNodePtr xmlnode, gpointer unused_udata)
{
    gchar *buf;
    gchar *query;
    gint sort_col = SORT_NO_COL, sort_order = SORT_NONE;
    guint32 reissue_timeout;
    xmlNodePtr node;
    search_t * search;
    guint flags = 0;
	guint lifetime;
	time_t create_time;

	(void) unused_udata;
    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_SEARCH));

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &reissue_timeout);

	buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_QUERY));
    if (!buf) {
        g_warning("Ignored search without query");
        return;
    }
	query = buf;

    buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_ENABLED));
    if (buf) {
        if (atoi(buf) == 1) {
			flags |= SEARCH_F_ENABLED;
		}
        G_FREE_NULL(buf);
    } else
		flags |= SEARCH_F_ENABLED;	 /* Compatibility: searches always began */

    buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_SPEED));
    if (buf) {
		g_warning("xml_to_search: Found deprecated speed attribute.");
        G_FREE_NULL(buf);
    }

    buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_REISSUE_TIMEOUT));
    if (buf) {
        reissue_timeout = atol(buf);
        G_FREE_NULL(buf);
    }

    buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_PASSIVE));
    if (buf) {
        if (atol(buf) == 1)
			flags |= SEARCH_F_PASSIVE;
        G_FREE_NULL(buf);
    }

    buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_SORT_COL));
    if (buf) {
        sort_col = atol(buf);
        G_FREE_NULL(buf);
    }

	buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_SORT_ORDER));
    if (buf) {
        sort_order = atol(buf);
        G_FREE_NULL(buf);
    }

	create_time = (time_t) -1;
	buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_CREATE_TIME));
    if (buf) {
		create_time = date2time(buf, tm_time());
		if (create_time == (time_t) -1)
			g_warning("xml_to_search: Unparseable \"%s\" attribute.",
				TAG_SEARCH_CREATE_TIME);
        G_FREE_NULL(buf);
    }
		/* consider legacy searches as created right now */
	if (create_time == (time_t) -1)
		create_time = tm_time();

	lifetime = (guint) -1;
	buf = STRTRACK(xml_get_string(xmlnode, TAG_SEARCH_LIFETIME));
    if (buf) {
		gint error;
		lifetime = parse_uint16(buf, NULL, 10, &error);
		if (error)
			g_warning("xml_to_search: Unparseable \"%s\" attribute.",
				TAG_SEARCH_LIFETIME);
        G_FREE_NULL(buf);
	}
	/* legacy searches get a 2 week expiration time */
	lifetime = MIN(14 * 24, lifetime);

	/* A zero lifetime means the search expired with the previous session */
	if (0 == lifetime && 0 == (flags & SEARCH_F_PASSIVE))
		flags &= ~SEARCH_F_ENABLED;

    if (gui_debug >= 4) {
        g_message("adding new %s %s search: %s",
			(flags & SEARCH_F_ENABLED) ? "enabled" : "disabled",
			(flags & SEARCH_F_PASSIVE) ? "passive" : "active",
			query);
	}

	flags |= SEARCH_F_LITERAL;
	search_gui_new_search_full(query, create_time, lifetime, reissue_timeout,
		sort_col, sort_order, flags, &search);

    G_FREE_NULL(query);

    /*
     * Also parse all children.
     */
	for (node = xmlnode->children; node != NULL; node = node->next)
        parse_xml(node, search->filter);
}

static void
xml_to_filter(xmlNodePtr xmlnode, gpointer unused_udata)
{
    gchar *buf;
    gchar *name = NULL;
    xmlNodePtr node;
    filter_t *filter;
    gpointer dest;
    gboolean active = TRUE;
	gint error;
	guint64 v;

	(void) unused_udata;
    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_FILTER));

	buf = STRTRACK(xml_get_string(xmlnode, TAG_FILTER_NAME));
    if (!buf) {
        g_warning("Ignored unnamed filter");
		goto failure;
    }
    name = buf;

    buf = STRTRACK(xml_get_string(xmlnode, TAG_FILTER_GLOBAL));
    if (buf) {
    	v = parse_number(buf, &error);
        G_FREE_NULL(buf);
        if (error) {
            g_warning("xml_to_filter: %s", g_strerror(error));
			goto failure;
		}

        switch (v) {
        case GLOBAL_PRE:
            filter = filter_get_global_pre();
            break;
        case GLOBAL_POST:
            filter = filter_get_global_post();
            break;
        default:
            filter = NULL;
            g_warning("xml_to_filter: Invalid filter");
			goto failure;
        }
    } else {
        if (gui_debug >= 4)
            g_message("adding new filter: %s", name);
        filter = filter_new(name);
        filters = g_list_append(filters, filter);
    }

    buf = STRTRACK(xml_get_string(xmlnode, TAG_FILTER_ACTIVE));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
        G_FREE_NULL(buf);
		if (error || v > 1) {
        	g_warning("xml_to_filter: Invalid \"active\" tag");
			goto failure;
		}
        active = 0 != v;
    }
    if (active)
        set_flags(filter->flags, FILTER_FLAG_ACTIVE);
    else
        clear_flags(filter->flags, FILTER_FLAG_ACTIVE);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_FILTER_UID));
    g_assert(buf);
    dest = parse_target(buf, &error);
    G_FREE_NULL(buf);
    if (error) {
        g_warning("xml_to_filter: %s", g_strerror(error));
		goto failure;
	}
    g_hash_table_insert(id_map, dest, filter);

    /*
     * Also parse all children.
     */
	for (node = xmlnode->children; node != NULL; node = node->next) {
        parse_xml(node, filter);
	}

failure:
    G_FREE_NULL(name);
    G_FREE_NULL(buf);

}

static void
xml_to_text_rule(xmlNodePtr xmlnode, gpointer data)
{
    gchar *match;
    enum rule_text_type type;
    gboolean case_sensitive;
    gchar *buf = NULL;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	guint64 v;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_TEXT));

    match = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TEXT_MATCH));
    if (match == NULL) {
        g_warning("xml_to_text_rule: rule without match string");
		goto failure;
	}

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TEXT_CASE));
    v = parse_number(buf, &error);
    G_FREE_NULL(buf);
	if (error || v > 1) {
        g_warning("xml_to_text_rule: invalid \"text case\" tag");
		goto failure;
	}

    case_sensitive = 0 != v;
    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TEXT_TYPE));
    type = (enum rule_text_type) atol(buf);
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    target = parse_target(buf, &error);
    G_FREE_NULL(buf);
    if (error) {
        g_warning("xml_to_text_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_text_rule(match, type, case_sensitive, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);

failure:
    G_FREE_NULL(match);
    G_FREE_NULL(buf);
}

static void
xml_to_ip_rule(xmlNodePtr xmlnode, gpointer data)
{
    host_addr_t addr;
    guint32 mask;
    gchar *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_IP));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_IP_ADDR));
    if (buf == NULL) {
        g_warning("xml_to_ip_rule: rule without ip address");
		goto failure;
	}
	error = !string_to_host_addr(buf, NULL, &addr);
    G_FREE_NULL(buf);
	if (error) {
        g_warning("xml_to_ip_rule: rule with unparseable ip address");
		goto failure;
	}

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_IP_MASK));
    if (buf == NULL) {
        g_warning("xml_to_ip_rule: rule without netmask");
		goto failure;
	}
	mask = string_to_ip(buf);
	if (mask == 0) {
		gint error;
		mask = parse_uint16(buf, NULL, 10, &error);
		if (error)
			goto failure;
	} else {
		/* For backwards-compatibility */
		mask = netmask_to_cidr(mask);
	}
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    target = parse_target(buf, &error);
    if (error) {
        g_warning( "xml_to_ip_rule: %s", g_strerror(error));
		goto failure;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_ip_rule(addr, mask, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);

failure:
    G_FREE_NULL(buf);
}

static void
xml_to_size_rule(xmlNodePtr xmlnode, gpointer data)
{
    filter_t *target = NULL, *filter = data;
    filesize_t lower, upper;
    gchar *buf;
    rule_t *rule;
    guint16 flags;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_SIZE));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_SIZE_LOWER));
    if (buf == NULL) {
        g_warning("xml_to_size_rule: rule without lower bound");
		goto failure;
	}
    lower = parse_number(buf, &error);
	if (error) {
        g_warning("xml_to_size_rule: invalid lower bound");
		goto failure;
	}
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_SIZE_UPPER));
    if (buf == NULL) {
        g_warning("xml_to_size_rule: rule without upper bound");
		goto failure;
	}
    upper = parse_number(buf, &error);
	if (error) {
        g_warning("xml_to_size_rule: invalid upper bound");
		goto failure;
	}
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_size_rule: %s (%p)",
			g_strerror(error), cast_to_gconstpointer(target));
		goto failure;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_size_rule(lower, upper, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);

failure:
	G_FREE_NULL(buf);
}

static void
xml_to_jump_rule(xmlNodePtr xmlnode, gpointer data)
{
    gchar *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_JUMP));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning( "xml_to_jump_rule: %s", g_strerror(error));
		goto failure;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_jump_rule(target,flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	
failure:
    G_FREE_NULL(buf);
}

static void
xml_to_sha1_rule(xmlNodePtr xmlnode, gpointer data)
{
    const gchar *hash = NULL;
    gchar *filename = NULL;
    gchar *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_SHA1));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_SHA1_FILENAME));
    filename = buf != NULL ? buf : g_strdup("[Unknown]");

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_SHA1_HASH));
    if (buf != NULL) {
		hash = strlen(buf) == SHA1_BASE32_SIZE ? base32_sha1(buf) : NULL;
    	G_FREE_NULL(buf);
		if (!hash) {
        	g_warning("xml_to_sha1_rule: Invalidly encoded SHA1");
			return;
		}
	} else {
		hash = NULL;
	}

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_sha1_rule: %s", g_strerror(error));
		goto failure;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_sha1_rule(hash, filename, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	
failure:
    G_FREE_NULL(filename);
    G_FREE_NULL(buf);
}

static void
xml_to_flag_rule(xmlNodePtr xmlnode, gpointer data)
{
    enum rule_flag_action stable = RULE_FLAG_IGNORE;
    enum rule_flag_action busy   = RULE_FLAG_IGNORE;
    enum rule_flag_action push   = RULE_FLAG_IGNORE;
    gchar *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	guint64 v;
	gint error;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_FLAG));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_FLAG_STABLE));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            stable = v;
		}
    }
	G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_FLAG_BUSY));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            busy = v;
		}
    }
	G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_FLAG_PUSH));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            push = v;
		}
    }
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning( "xml_to_flag_rule: %s", g_strerror(error));
		goto failure;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_flag_rule(stable, busy, push, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);

failure:
    G_FREE_NULL(buf);
}

static void
xml_to_state_rule(xmlNodePtr xmlnode, gpointer data)
{
    enum filter_prop_state display = FILTER_PROP_STATE_UNKNOWN;
    enum filter_prop_state download = FILTER_PROP_STATE_UNKNOWN;
    gchar *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	gint error;
	guint64 v;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
					NODE_RULE_STATE));

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_STATE_DISPLAY));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error) {
        	g_warning( "xml_to_state_rule: %s", g_strerror(error));
		}
        if (v <= MAX_FILTER_PROP_STATE || v == FILTER_PROP_STATE_IGNORE) {
            display = v;
		}
    }
   	G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_STATE_DOWNLOAD));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error) {
        	g_warning( "xml_to_state_rule: %s", g_strerror(error));
			return;
		}
        if (v <= MAX_FILTER_PROP_STATE || v == FILTER_PROP_STATE_IGNORE) {
            download = v;
		}
    }
   	G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_TARGET));
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning( "xml_to_state_rule: %s", g_strerror(error));
		return;
	}
    G_FREE_NULL(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_state_rule(display, download, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4) {
        g_message("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
}

static guint16
get_rule_flags_from_xml(xmlNodePtr xmlnode)
{
    gboolean negate = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;
    guint16 flags;
    gchar *buf;
	gint error;
	guint64 v;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_NEGATE));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"negate\" tag");
		} else {
        	negate = 0 != v;
		}
    }
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_ACTIVE));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"active\" tag");
		} else {
	    	active = 0 != v;
		}
    }
    G_FREE_NULL(buf);

    buf = STRTRACK(xml_get_string(xmlnode, TAG_RULE_SOFT));
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"soft\" tag");
		} else {
        	soft = 0 != v;
		}
    }
    G_FREE_NULL(buf);

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    return flags;
}

/* vi: set ts=4 sw=4 cindent: */
