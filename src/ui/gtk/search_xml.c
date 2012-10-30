/*
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

#include "filter_core.h"
#include "search_xml.h"
#include "settings.h"
#include "search.h"

#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/bridge/ui2c.h"

#include "xml/vxml.h"
#include "xml/xnode.h"
#include "xml/xfmt.h"

#include "lib/ascii.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/htable.h"
#include "lib/parse.h"
#include "lib/product.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/utf8.h"

#include "lib/override.h"		/* Must be the last header included */

#define GLOBAL_PRE 0
#define GLOBAL_POST 1

typedef struct node_parser {
    const char *name;
    void (*parser_func)(xnode_t *, void *);
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
static void parse_xml(xnode_t *xn, void *user_data);
static void builtin_to_xml(xnode_t *);
static void search_to_xml(xnode_t *, const struct search *);
static void filter_to_xml(xnode_t *, filter_t *);
static void rule_to_xml(xnode_t *, rule_t *);
static void xml_to_builtin(xnode_t *, void *);
static void xml_to_search(xnode_t *, void *);
static void xml_to_sha1s(xnode_t *, void *);
static void xml_to_filter(xnode_t *, void *);
static void xml_to_text_rule(xnode_t *, void *);
static void xml_to_ip_rule(xnode_t *, void *);
static void xml_to_size_rule(xnode_t *, void *);
static void xml_to_jump_rule(xnode_t *, void *);
static void xml_to_sha1_rule(xnode_t *, void *);
static void xml_to_flag_rule(xnode_t *, void *);
static void xml_to_state_rule(xnode_t *, void *);
static guint16 get_rule_flags_from_xml(xnode_t *);

/*
 * Private variables
 */
static const char NODE_SEARCHES[]    = "Searches";
static const char NODE_BUILTIN[]     = "BuiltIn";
static const char NODE_SEARCH[]      = "Search";
static const char NODE_FILTER[]      = "Filter";
static const char NODE_RULE_TEXT[]   = "TextRule";
static const char NODE_RULE_IP[]     = "IpRule";
static const char NODE_RULE_SIZE[]   = "SizeRule";
static const char NODE_RULE_JUMP[]   = "JumpRule";
static const char NODE_RULE_SHA1[]   = "SHA1Rule";
static const char NODE_RULE_FLAG[]   = "FlagRule";
static const char NODE_RULE_STATE[]  = "StateRule";
static const char NODE_SHA1S[]       = "SHA1s";
static const char NODE_SHA1[]        = "SHA1";

static const char TAG_BUILTIN_SHOW_UID[]       = "ShowUID";
static const char TAG_BUILTIN_DROP_UID[]       = "DropUID";
static const char TAG_BUILTIN_DOWNLOAD_UID[]   = "DownloadUID";
static const char TAG_BUILTIN_NODOWNLOAD_UID[] = "NoDownloadUID";
static const char TAG_BUILTIN_RETURN_UID[]     = "ReturnUID";
static const char TAG_FILTER_NAME[]            = "Name";
static const char TAG_FILTER_GLOBAL[]          = "Global";
static const char TAG_FILTER_UID[]             = "UID";
static const char TAG_FILTER_ACTIVE[]          = "Active";
static const char TAG_SEARCH_QUERY[]           = "Query";
static const char TAG_SEARCH_MEDIA_TYPE[]      = "MediaType";
static const char TAG_SEARCH_ENABLED[]         = "Enabled";
static const char TAG_SEARCH_SPEED[]           = "Speed";
static const char TAG_SEARCH_PASSIVE[]         = "Passive";
static const char TAG_SEARCH_REISSUE_TIMEOUT[] = "ReissueTimeout";
static const char TAG_SEARCH_CREATE_TIME[]     = "CreateTime";
static const char TAG_SEARCH_LIFETIME[]        = "LifeTime";
static const char TAG_SEARCH_SORT_COL[]        = "SortCol";
static const char TAG_SEARCH_SORT_ORDER[]      = "SortOrder";
static const char TAG_RULE_TEXT_CASE[]         = "Case";
static const char TAG_RULE_TEXT_MATCH[]        = "Match";
static const char TAG_RULE_TEXT_TYPE[]         = "Type";
static const char TAG_RULE_IP_ADDR[]           = "Address";
static const char TAG_RULE_IP_MASK[]           = "Netmask";
static const char TAG_RULE_SIZE_LOWER[]        = "Lower";
static const char TAG_RULE_SIZE_UPPER[]        = "Upper";
static const char TAG_RULE_SHA1_HASH[]         = "Hash";
static const char TAG_RULE_SHA1_FILENAME[]     = "OriginalFilename";
static const char TAG_RULE_NEGATE[]            = "Negate";
static const char TAG_RULE_ACTIVE[]            = "Active";
static const char TAG_RULE_SOFT[]              = "Soft";
static const char TAG_RULE_TARGET[]            = "Target";
static const char TAG_RULE_FLAG_BUSY[]         = "Busy";
static const char TAG_RULE_FLAG_PUSH[]         = "Push";
static const char TAG_RULE_FLAG_STABLE[]       = "Stable";
static const char TAG_RULE_STATE_DISPLAY[]     = "Display";
static const char TAG_RULE_STATE_DOWNLOAD[]    = "Download";

static const char search_file_xml[] = "searches.xml";
static const char search_file_type[] = "searches";

static htable_t *target_map;
static htable_t *id_map;

static node_parser_t parser_map[] = {
    { NODE_BUILTIN,     xml_to_builtin },
    { NODE_SEARCH,      xml_to_search },
    { NODE_SHA1S,       xml_to_sha1s },
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

static inline xnode_t *
xml_new_empty_child(xnode_t *parent, const char *name)
{
	return xnode_new_element(parent, NULL, name);
}

static inline xnode_t *
xml_new_child(xnode_t *parent, const char *name, const char *content)
{
	xnode_t *cn;

	cn = xnode_new_element(parent, NULL, name);
	xnode_new_text(cn, content, FALSE);

	return cn;
}

/**
 * Compare two SHA1s for GSList sorting.
 */
static int
sha1_sort_cmp(const void *a, const void *b)
{
	return memcmp(a, b, SHA1_RAW_SIZE);
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
parse_number(const char *buf, int *error)
{
	const char *endptr;
	guint64 ret;

	g_assert(buf != NULL);
	g_assert(error != NULL);

	ret = parse_uint64(buf, &endptr, 10, error);
	if (0 == *error && *endptr != '\0') {
		*error = EINVAL;
	}
	if (0 != *error) {
		g_warning("parse_number(): error with buf=\"%s\"", buf);
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
static void *
parse_target(const char *buf, gint *error)
{
	const char *endptr;
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
	if (4 == sizeof(void *)) {
		if (0 == *error && v > (~(guint32) 0)) {
			*error = ERANGE;
		}
	}
	if (0 != *error) {
		g_warning("parse_target(): error with buf=\"%s\"", buf);
		return NULL;
	}

	target = v;

	/* Not using GUINT_TO_POINTER() is intentional to prevent truncation
	 * to 32-bit for backwards compability as explained above. */
	return (void *) target;
}

/**
 * Returns the next available target ID.
 *
 * @param do_reset if TRUE, the ID counter is reset to an initial value.
 * @return a 32-bit integer stuffed into a pointer
 */
static void * 
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
	return uint_to_pointer(ret);
}

/**
 * Resets the target ID counter and frees target_map if it was created.
 */
static void
target_map_reset(void)
{
	target_new_id(TRUE); /* Reset */
	htable_free_null(&target_map);
}

/**
 * Creates a string representation of a ``target''.
 *
 * @param target a filter target
 * @return a static buffer holding the string representation
 */
static const char *
target_to_string(filter_t *target)
{
	void *value;
	static char buf[128];

	if (!target_map) {
		target_new_id(TRUE); /* Reset */
		target_map = htable_create(HASH_KEY_SELF, 0);
	}

	if (!htable_lookup_extended(target_map, target, NULL, &value)) {
		value = target_new_id(FALSE);
		htable_insert(target_map, target, value);
	}

    gm_snprintf(buf, sizeof buf, "0x%x", GPOINTER_TO_UINT(value));

	return buf;
}

/**
 * Store pending searches.
 */
void
search_store_xml(void)
{
	const GList *iter;
	time_t now = tm_time();
    xnode_t *root;
	file_path_t fp;
	FILE *out;

	file_path_set(&fp, settings_gui_config_dir(), search_file_xml);
	out = file_config_open_write(search_file_type, &fp);

	if (NULL == out)
		return;

	/* Free target_map and reset the target ID counter */
	target_map_reset();

    /*
     * Create a new root node.
     */

    root = xnode_new_element(NULL, NULL, NODE_SEARCHES);
    xnode_prop_printf(root, "Time", "%s", timestamp_to_string(now));
    xnode_prop_printf(root, "Version", "%s", product_get_version());

    /*
     * Store UIDs for the builtin targets
     */
    builtin_to_xml(root);

    /*
     * Iterate over the searches and add them to the tree
     */
    for (iter = search_gui_get_searches(); iter; iter = g_list_next(iter)) {
        search_to_xml(root, iter->data);
	}

    /*
     * Iterate over the rulesets and add them to the tree.
     * Only those that are not bound to a search.
     */
    for (iter = filters; NULL != iter; iter = g_list_next(iter)) {
        filter_to_xml(root, iter->data);
	}

	/*
	 * Save the XML tree we built.
	 */

	xfmt_tree_prologue_dump(root, out);
	file_config_close(out, &fp);
	xnode_tree_free(root);

	/* Free target_map and reset the target ID counter */
	target_map_reset();
}

/**
 * Retrieve search list and restart searches.
 * This is the new xml version. The searches are normally
 * retrieved from  ~/.gtk-gnutella/searches.xml.
 */
G_GNUC_COLD gboolean
search_retrieve_xml(void)
{
    xnode_t *root, *xn;
	GList  *f, *f_next;
	file_path_t fp[1];
	FILE *fd;
	vxml_parser_t *vp;
	vxml_error_t e;

	file_path_set(&fp[0], settings_gui_config_dir(), search_file_xml);
	fd = file_config_open_read(search_file_type, fp, G_N_ELEMENTS(fp));
	if (NULL == fd)
		return FALSE;

	/*
     * Parse the XML file.
     */

	vp = vxml_parser_make(search_file_type, VXML_O_STRIP_BLANKS);
	vxml_parser_add_file(vp, fd);
	e = vxml_parse_tree(vp, &root);
	vxml_parser_free(vp);
	fclose(fd);

	/*
     * In case something obvious went wrong
     */

    if (e != VXML_E_OK) {
        g_warning("error parsing %s file: %s",
			search_file_xml, vxml_strerror(e));
		return FALSE;
    }

	if (/* if there is no root element */
        (NULL == root) ||
	    /* if it doesn't have a name */
	    (NULL == xnode_element_name(root)) ||
	    /* if it isn't a Genealogy node */
	    0 != ascii_strcasecmp(xnode_element_name(root), NODE_SEARCHES)
    ) {
        g_warning("searches file has invalid format: invalid root node");
		xnode_tree_free(root);
		return FALSE;
	}

    id_map = htable_create(HASH_KEY_SELF, 0);

    /*
     * find nodes and add them to the list, this just
	 * loops through all the children of the root of the document
     */
	for (xn = xnode_first_child(root); xn != NULL; xn = xnode_next_sibling(xn))
        parse_xml(xn, NULL);

	xnode_tree_free(root);

    /*
     * We should have collected all ruleset UIDs now. So we can
     * now resolve the UIDs to the actual pointers we use now.
     * We need to commit before we do this, because we want to
     * interate over the rulesets and don't want to cope with
     * shadows.
     */

    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("resolving UIDs");

    for (f = filters; f != NULL; f = f_next) {
		gboolean damaged = FALSE;
        filter_t *filter = f->data;
        GList *r;
        gint n = 0;

		f_next = g_list_next(f);

        if (GUI_PROPERTY(gui_debug) >= 6) {
            g_debug("\n\nresolving on filter:");
            dump_filter(filter);
        }

        if (!filter_is_builtin(filter)) {

            for (r = filter->ruleset; r != NULL; r = g_list_next(r)) {
                rule_t *rule = r->data;
                void *new_target;

                g_assert(rule->target != NULL);
                new_target = htable_lookup(id_map, rule->target);
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
                rule->flags |= RULE_FLAG_VALID;

                /*
                 * We circumvent the shadows, so we must do refcounting
                 * manually here.
                 */
                if (GUI_PROPERTY(gui_debug) >= 7) {
                    g_debug("increasing refcount on \"%s\" to %d",
                        rule->target->name, rule->target->refcount + 1);
				}
                rule->target->refcount++;
                n++;
            }
        }

        if (GUI_PROPERTY(gui_debug) >= 6) {
			g_debug("resolved filter:");
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

        if (GUI_PROPERTY(gui_debug) >= 6)
            g_debug("verifying bindings...");

        for (s = search_gui_get_searches(); s != NULL; s = g_list_next(s)) {
            const struct search *search = s->data;
            const struct filter *filter;

			filter = search_gui_get_filter(search);
            if (filter->search == search) {
                if (GUI_PROPERTY(gui_debug) >= 6)
                    g_debug("binding ok for: %s", search_gui_query(search));
            } else {
                g_warning("binding broken for: %s", search_gui_query(search));
                borked = TRUE;
            }
        }

        g_assert(!borked);
    }

    g_list_free(filters_current);
    filters_current = g_list_copy(filters);

    htable_free_null(&id_map);

	return TRUE;
}

static void
builtin_to_xml(xnode_t *parent)
{
	const struct {
		const char *tag;
		filter_t * (*target)(void);
	} builtins[] = {
		{ TAG_BUILTIN_SHOW_UID,			filter_get_show_target },
		{ TAG_BUILTIN_DROP_UID,			filter_get_drop_target },
		{ TAG_BUILTIN_DOWNLOAD_UID,		filter_get_download_target },
		{ TAG_BUILTIN_NODOWNLOAD_UID,	filter_get_nodownload_target },
		{ TAG_BUILTIN_RETURN_UID,		filter_get_return_target },
	};
    xnode_t *xn;
	guint i;

    g_assert(parent != NULL);

    xn = xml_new_empty_child(parent, NODE_BUILTIN);
	for (i = 0; i < G_N_ELEMENTS(builtins); i++) {
    	xnode_prop_set(xn, builtins[i].tag,
			target_to_string(builtins[i].target()));
	}
}

static void
sha1s_to_xml(xnode_t *parent, GSList *sha1s)
{
    xnode_t *xn;
	GSList *sl;

	if (NULL == sha1s)
		return;

    xn = xml_new_empty_child(parent, NODE_SHA1S);

	GM_SLIST_FOREACH(sha1s, sl) {
		const struct sha1 *sha1 = sl->data;
		xml_new_child(xn, NODE_SHA1, sha1_to_string(sha1));
	}
}

static void
search_to_xml(xnode_t *parent, const struct search *search)
{
	gnet_search_t search_handle;
    xnode_t *newxml;
    GList *iter;
	GSList *sha1s;

    g_assert(search != NULL);
	search_handle = search_gui_get_handle(search);
    g_assert(guc_search_query(search_handle) != NULL);
    g_assert(parent != NULL);

	if (guc_search_is_browse(search_handle))
		return;	

	if (guc_search_is_local(search_handle))
		return;

	if (guc_search_is_whats_new(search_handle))
		return;

    if (GUI_PROPERTY(gui_debug) >= 6) {
        g_debug(
			"saving search: %s (enabled=%d)\n"
			"  -- filter is bound to: %p\n"
			"  -- search is         : %p",
			guc_search_query(search_handle),
			!guc_search_is_frozen(search_handle),
			cast_to_gconstpointer(search_gui_get_filter(search)->search),
			cast_to_gconstpointer(search));
    }

    newxml = xml_new_empty_child(parent, NODE_SEARCH);
    xnode_prop_set(newxml, TAG_SEARCH_QUERY,
		guc_search_query(search_handle));
	xnode_prop_printf(newxml, TAG_SEARCH_ENABLED, "%u",
		!guc_search_is_frozen(search_handle));
    xnode_prop_printf(newxml, TAG_SEARCH_PASSIVE, "%u",
		guc_search_is_passive(search_handle));
    xnode_prop_printf(newxml, TAG_SEARCH_MEDIA_TYPE, "%u",
		guc_search_get_media_type(search_handle));
    xnode_prop_printf(newxml, TAG_SEARCH_REISSUE_TIMEOUT, "%u",
		guc_search_get_reissue_timeout(search_handle));
    xnode_prop_printf(newxml, TAG_SEARCH_CREATE_TIME, "%s",
		timestamp_to_string(guc_search_get_create_time(search_handle)));
    xnode_prop_printf(newxml, TAG_SEARCH_LIFETIME, "%u",
		guc_search_get_lifetime(search_handle));
    xnode_prop_printf(newxml, TAG_SEARCH_SORT_COL, "%d",
		search_gui_get_sort_column(search));
    xnode_prop_printf(newxml, TAG_SEARCH_SORT_ORDER, "%d",
		search_gui_get_sort_order(search));

	sha1s = guc_search_associated_sha1(search_handle);
	sha1s = g_slist_sort(sha1s, sha1_sort_cmp);
	sha1s_to_xml(newxml, sha1s);
	g_slist_free(sha1s);

    iter = search_gui_get_filter(search)->ruleset;
    for (/* NOTHING */; iter != NULL; iter = g_list_next(iter)) {
        rule_to_xml(newxml, iter->data);
	}
}


static void
filter_to_xml(xnode_t *parent, filter_t *f)
{
    xnode_t *newxml;
    GList *l;

    g_assert(f != NULL);
    g_assert(f->name != NULL);
    g_assert(parent != NULL);

    /*
     * Don't store the builtin targets or bound rulesets
     */
    if (filter_is_builtin(f) || filter_is_bound(f)) {
        if (GUI_PROPERTY(gui_debug) >= 7)
            g_debug("not saving bound/builtin: %s", f->name);
        return;
    }

    if (GUI_PROPERTY(gui_debug) >= 6) {
		g_debug(
			"saving filter: %s\n"
			"  -- bound   : %p",
			f->name,
			cast_to_gconstpointer(f->search));
    }

	g_assert(utf8_is_valid_string(f->name));
    newxml = xml_new_empty_child(parent, NODE_FILTER);
    xnode_prop_set(newxml, TAG_FILTER_NAME, f->name);
    xnode_prop_printf(newxml, TAG_FILTER_ACTIVE, "%u",
		booleanize(filter_is_active(f)));

    /*
     * We take the pointer as a unique id which
     * we use during read-in for setting the
     * destination of JUMP actions.
     */
    xnode_prop_set(newxml, TAG_FILTER_UID, target_to_string(f));

    if (filter_get_global_pre() == f) {
        xnode_prop_printf(newxml, TAG_FILTER_GLOBAL, "%u", GLOBAL_PRE);
    }

    if (filter_get_global_post() == f) {
        xnode_prop_printf(newxml, TAG_FILTER_GLOBAL, "%u", GLOBAL_POST);
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
rule_to_xml(xnode_t *parent, rule_t *r)
{
    xnode_t *newxml = NULL;

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
       	xnode_prop_set(newxml, TAG_RULE_TEXT_CASE,
			r->u.text.case_sensitive ? "1" : "0");
       	xnode_prop_set(newxml, TAG_RULE_TEXT_MATCH, r->u.text.match);
       	xnode_prop_printf(newxml, TAG_RULE_TEXT_TYPE, "%u", r->u.text.type);
        break;
    case RULE_IP:
        newxml = xml_new_empty_child(parent, NODE_RULE_IP);
        xnode_prop_set(newxml, TAG_RULE_IP_ADDR,
			host_addr_to_string(r->u.ip.addr));
        xnode_prop_printf(newxml, TAG_RULE_IP_MASK, "%u", r->u.ip.cidr);
        break;
    case RULE_SIZE:
		{
			char buf[UINT64_DEC_BUFLEN];

			uint64_to_string_buf(r->u.size.lower, buf, sizeof buf);
        	newxml = xml_new_empty_child(parent, NODE_RULE_SIZE);
        	xnode_prop_printf(newxml, TAG_RULE_SIZE_LOWER, "%s", buf);
			uint64_to_string_buf(r->u.size.upper, buf, sizeof buf);
        	xnode_prop_printf(newxml, TAG_RULE_SIZE_UPPER, "%s", buf);
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

        /*
         * If r->u.sha1.hash is NULL, we just omit the hash.
         */
       	if (r->u.sha1.hash != NULL)
           	xnode_prop_set(newxml, TAG_RULE_SHA1_HASH,
				sha1_base32(r->u.sha1.hash));

		g_assert(utf8_is_valid_string(r->u.sha1.filename));
		xnode_prop_set(newxml, TAG_RULE_SHA1_FILENAME, r->u.sha1.filename);
        break;
    case RULE_FLAG:
        newxml = xml_new_empty_child(parent, NODE_RULE_FLAG);

        xnode_prop_printf(newxml, TAG_RULE_FLAG_STABLE, "%u", r->u.flag.stable);
        xnode_prop_printf(newxml, TAG_RULE_FLAG_BUSY, "%u", r->u.flag.busy);
        xnode_prop_printf(newxml, TAG_RULE_FLAG_PUSH, "%u", r->u.flag.push);
        break;
    case RULE_STATE:
        newxml = xml_new_empty_child(parent, NODE_RULE_STATE);
        xnode_prop_printf(newxml, TAG_RULE_STATE_DISPLAY,
			"%u", r->u.state.display);
        xnode_prop_printf(newxml, TAG_RULE_STATE_DOWNLOAD,
			"%u", r->u.state.download);
        break;
    default:
        g_error("Unknown rule type: 0x%x", r->type);
    }

    xnode_prop_printf(newxml, TAG_RULE_NEGATE, "%u",
		booleanize(RULE_IS_NEGATED(r)));
    xnode_prop_printf(newxml, TAG_RULE_ACTIVE, "%u",
		booleanize(RULE_IS_ACTIVE(r)));
    xnode_prop_printf(newxml, TAG_RULE_SOFT, "%u", booleanize(RULE_IS_SOFT(r)));
    xnode_prop_set(newxml, TAG_RULE_TARGET, target_to_string(r->target));
}

static void
parse_xml(xnode_t *xn, void *user_data)
{
    gint n;
	const char *name;

    g_assert(xn != NULL);

	name = xnode_element_name(xn);

    if (NULL == name) {
        g_carp("unnamed XML node ignored: %s", xnode_to_string(xn));
	    return;
    }

    for (n = 0; parser_map[n].name != NULL; n ++) {
        if (0 == ascii_strcasecmp(name, parser_map[n].name)) {
            parser_map[n].parser_func(xn, user_data);
            return;
        }
    }

    g_carp("unknown XML node: %s", xnode_to_string(xn));
}

static void
xml_to_builtin(xnode_t *xn, void *unused_udata)
{
    const char *buf;
    void *target;
	gint error;

	(void) unused_udata;
    g_assert(xn != NULL);
    g_assert(NULL != xnode_element_name(xn));
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_BUILTIN));
	g_assert(filter_get_show_target() != NULL);
    g_assert(filter_get_drop_target() != NULL);
    g_assert(filter_get_download_target() != NULL);

    buf = xnode_prop_get(xn, TAG_BUILTIN_SHOW_UID);
	if (NULL == buf)
		goto failure;
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_builtin: %s", g_strerror(error));
		goto failure;
	}
    htable_insert(id_map, target, filter_get_show_target());

    buf = xnode_prop_get(xn, TAG_BUILTIN_DROP_UID);
	if (NULL == buf)
		goto failure;
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_builtin: %s", g_strerror(error));
		goto failure;
	}
    htable_insert(id_map, target, filter_get_drop_target());

    buf = xnode_prop_get(xn, TAG_BUILTIN_DOWNLOAD_UID);
    if (buf != NULL) {
    	target = parse_target(buf, &error);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			goto failure;
		}
        htable_insert(id_map, target, filter_get_download_target());
    } else {
        g_warning("xml_to_builtin: no \"DOWNLOAD\" target");
    }

    buf = xnode_prop_get(xn, TAG_BUILTIN_NODOWNLOAD_UID);
    if (buf != NULL) {
    	target = parse_target(buf, &error);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			goto failure;
		}
        htable_insert(id_map, target, filter_get_nodownload_target());
    } else {
        g_warning("xml_to_builtin: no \"DON'T DOWNLOAD\" target");
    }

    buf = xnode_prop_get(xn, TAG_BUILTIN_RETURN_UID);
    if (buf != NULL) {
    	target = parse_target(buf, &error);
    	if (error) {
            g_warning("xml_to_builtin: %s", g_strerror(error));
			goto failure;
		}
        htable_insert(id_map, target, filter_get_return_target());
    } else {
        g_warning("xml_to_builtin: no \"RETURN\" target");
    }

	return;

failure:
	g_warning("could not parse XML node %s", xnode_to_string(xn));
}

static void
xml_to_search(xnode_t *xn, void *unused_udata)
{
    const char *buf;
    const char *query;
    gint sort_col = SORT_NO_COL, sort_order = SORT_NONE;
    guint32 reissue_timeout;
	unsigned media_type = 0;
    xnode_t *xc;
    struct search *search;
    unsigned flags = 0;
	unsigned lifetime;
	time_t create_time;
	bool clean_restart;

	(void) unused_udata;
    g_assert(xn != NULL);
    g_assert(NULL != xnode_element_name(xn));
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_SEARCH));

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &reissue_timeout);
    gnet_prop_get_boolean_val(PROP_CLEAN_RESTART, &clean_restart);

	query = xnode_prop_get(xn, TAG_SEARCH_QUERY);
    if (NULL == query) {
        g_warning("ignoring search without query");
        return;
    }

    buf = xnode_prop_get(xn, TAG_SEARCH_ENABLED);
    if (buf) {
        if (atoi(buf) == 1) {
			flags |= SEARCH_F_ENABLED;
		}
    } else
		flags |= SEARCH_F_ENABLED;	 /* Compatibility: searches always began */

    buf = xnode_prop_get(xn, TAG_SEARCH_SPEED);
    if (buf) {
		g_warning("%s(): found deprecated speed attribute.", G_STRFUNC);
    }

    buf = xnode_prop_get(xn, TAG_SEARCH_REISSUE_TIMEOUT);
    if (buf) {
        reissue_timeout = atol(buf);
    }

    buf = xnode_prop_get(xn, TAG_SEARCH_MEDIA_TYPE);
    if (buf) {
        media_type = atol(buf);
    }

    buf = xnode_prop_get(xn, TAG_SEARCH_PASSIVE);
    if (buf) {
        if (atol(buf) == 1)
			flags |= SEARCH_F_PASSIVE;
    }

    buf = xnode_prop_get(xn, TAG_SEARCH_SORT_COL);
    if (buf) {
        sort_col = atol(buf);
    }

	buf = xnode_prop_get(xn, TAG_SEARCH_SORT_ORDER);
    if (buf) {
        sort_order = atol(buf);
    }

	create_time = (time_t) -1;
	buf = xnode_prop_get(xn, TAG_SEARCH_CREATE_TIME);
    if (buf) {
		create_time = date2time(buf, tm_time());
		if (create_time == (time_t) -1)
			g_warning("%s(): unparseable \"%s\" attribute",
				G_STRFUNC, TAG_SEARCH_CREATE_TIME);
    }

	/* consider legacy searches as created right now */
	if (create_time == (time_t) -1)
		create_time = tm_time();

	lifetime = (guint) -1;
	buf = xnode_prop_get(xn, TAG_SEARCH_LIFETIME);
    if (buf) {
		gint error;
		lifetime = parse_uint16(buf, NULL, 10, &error);
		if (error)
			g_warning("%s(): unparseable \"%s\" attribute",
				G_STRFUNC, TAG_SEARCH_LIFETIME);
	}
	/* legacy searches get a 2 week expiration time */
	lifetime = MIN(14 * 24, lifetime);

	/*
	 * A zero lifetime means the search expired with the previous session.
	 * However, when we're resuming from a crash, let the search continue.
	 */
	if (0 == lifetime && 0 == (flags & SEARCH_F_PASSIVE) && clean_restart)
		flags &= ~SEARCH_F_ENABLED;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("adding new %s %s search: %s",
			(flags & SEARCH_F_ENABLED) ? "enabled" : "disabled",
			(flags & SEARCH_F_PASSIVE) ? "passive" : "active",
			query);
	}

	flags |= SEARCH_F_LITERAL;
	search_gui_new_search_full(query, media_type,
		create_time, lifetime, reissue_timeout,
		sort_col, sort_order, flags, &search);

	if (search) {
		/*
		 * Also parse all children.
		 */
		for (xc = xnode_first_child(xn); xc; xc = xnode_next_sibling(xc)) {
			parse_xml(xc, search_gui_get_filter(search));
		}

		/*
		 * If search has a zero lifetime and was not passive, re-enable it
		 * if it has pending downloads and they want to restart these
		 * searches.
		 */

		if (
			0 == lifetime &&
			0 == (flags & SEARCH_F_PASSIVE) &&
			GUI_PROPERTY(search_restart_when_pending) &&
			search_gui_has_pending_downloads(search)
		) {
			search_gui_start_search(search);
		}
	}
}

static void
xml_to_sha1(xnode_t *xn, const struct search *search)
{
	xnode_t *value;

    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_SHA1));

	value = xnode_first_child(xn);
	if (!xnode_is_text(value)) {
		g_warning("first XML child node for %s is not text but %s",
			xnode_to_string(xn), xnode_to_string2(value));
		goto no_content;
	}

	if (value != NULL) {
		const char *b32 = xnode_text(value);

		if (b32 != NULL) {
			const struct sha1 *sha1;

			b32 = skip_ascii_spaces(b32);
			sha1 = base32_sha1(b32);

			if (sha1 != NULL) {
				guc_search_associate_sha1(search_gui_get_handle(search), sha1);
			}
		} else {
			goto no_content;
		}
	} else {
		goto no_content;
	}

	return;

no_content:
	g_warning("XML node has no content: %s", xnode_to_string(xn));
}

static void
xml_to_sha1s(xnode_t *xn, void *data)
{
	const filter_t *filter = data;
	const struct search *search = filter->search;
    xnode_t *xc;

    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_SHA1S));

	/*
	 * Parse all <SHA1> children.
	 */

	for (xc = xnode_first_child(xn); xc != NULL; xc = xnode_next_sibling(xc)) {
    	if (0 == ascii_strcasecmp(xnode_element_name(xc), NODE_SHA1)) {
			xml_to_sha1(xc, search);
		}
	}
}

static void
xml_to_filter(xnode_t *xn, void *unused_data)
{
    const char *buf;
    const char *name = NULL;
    xnode_t *xc;
    filter_t *filter;
    void *dest;
    gboolean active = TRUE;
	int error;
	guint64 v;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_FILTER));

	(void) unused_data;

	name = xnode_prop_get(xn, TAG_FILTER_NAME);
    if (NULL == name) {
        g_warning("%s(): ignoring unnamed filter", G_STRFUNC);
		goto failure;
    }

    buf = xnode_prop_get(xn, TAG_FILTER_GLOBAL);
    if (buf) {
    	v = parse_number(buf, &error);
        if (error) {
            g_warning("%s(): cannot parse \"%s\" value (%s): %s",
				G_STRFUNC, TAG_FILTER_GLOBAL, buf, g_strerror(error));
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
            g_warning("%s(): invalid filter value %s in \"%s\" tag",
				G_STRFUNC, uint64_to_string(v), TAG_FILTER_GLOBAL);
			goto failure;
        }
    } else {
        if (GUI_PROPERTY(gui_debug) >= 4)
            g_debug("adding new filter: %s", name);
        filter = filter_new(name);
        filters = g_list_append(filters, filter);
    }

    buf = xnode_prop_get(xn, TAG_FILTER_ACTIVE);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
        	g_warning("%s(): invalid \"%s\" tag value %s",
				G_STRFUNC, TAG_FILTER_ACTIVE, buf);
			goto failure;
		}
        active = 0 != v;
    }
    if (active) {
        filter->flags |= FILTER_FLAG_ACTIVE;
	} else {
        filter->flags &= ~FILTER_FLAG_ACTIVE;
	}
    buf = xnode_prop_get(xn, TAG_FILTER_UID);
    g_assert(buf);
    dest = parse_target(buf, &error);
    if (error) {
        g_warning("%s(): unparseable \"%s\" tag value %s: %s",
			G_STRFUNC, TAG_FILTER_UID, buf, g_strerror(error));
		goto failure;
	}
    htable_insert(id_map, dest, filter);

    /*
     * Also parse all children.
     */
	for (xc = xnode_first_child(xn); xc != NULL; xc = xnode_next_sibling(xc)) {
        parse_xml(xc, filter);
	}

	return;

failure:
	g_warning("%s(): unable to parse XML node: %s",
		G_STRFUNC, xnode_to_string(xn));
}

static void
xml_to_text_rule(xnode_t *xn, void *data)
{
    const char *match;
    enum rule_text_type type;
    gboolean case_sensitive;
    const char *buf = NULL;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	guint64 v;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_TEXT));

    match = xnode_prop_get(xn, TAG_RULE_TEXT_MATCH);
    if (match == NULL) {
        g_warning("xml_to_text_rule: rule without match string");
		goto failure;
	}

    buf = xnode_prop_get(xn, TAG_RULE_TEXT_CASE);
    v = parse_number(buf, &error);
	if (error || v > 1) {
        g_warning("xml_to_text_rule: invalid \"text case\" tag");
		goto failure;
	}

    case_sensitive = 0 != v;
    buf = xnode_prop_get(xn, TAG_RULE_TEXT_TYPE);
	if (buf != NULL) {
		type = (enum rule_text_type) atol(buf);
	} else {
		g_warning("xml_to_text_rule: no \"text type\" tag");
		goto failure;
	}

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_text_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_text_rule(match, type, case_sensitive, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;

failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_ip_rule(xnode_t *xn, void *data)
{
    host_addr_t addr;
    guint32 mask;
    const char *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_IP));

    buf = xnode_prop_get(xn, TAG_RULE_IP_ADDR);
    if (buf == NULL) {
        g_warning("xml_to_ip_rule: rule without ip address");
		goto failure;
	}
	error = !string_to_host_addr(buf, NULL, &addr);
	if (error) {
        g_warning("xml_to_ip_rule: rule with unparseable ip address");
		goto failure;
	}

    buf = xnode_prop_get(xn, TAG_RULE_IP_MASK);
    if (buf == NULL) {
        g_warning("xml_to_ip_rule: rule without netmask");
		goto failure;
	}
	mask = string_to_ip(buf);
	if (mask == 0) {
		mask = parse_uint16(buf, NULL, 10, &error);
		if (error)
			goto failure;
	} else {
		/* For backwards-compatibility */
		mask = netmask_to_cidr(mask);
	}

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_ip_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_ip_rule(addr, mask, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;

failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_size_rule(xnode_t *xn, void *data)
{
    filter_t *target = NULL, *filter = data;
    filesize_t lower, upper;
    const char *buf;
    rule_t *rule;
    guint16 flags;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_SIZE));

    buf = xnode_prop_get(xn, TAG_RULE_SIZE_LOWER);
    if (buf == NULL) {
        g_warning("xml_to_size_rule: rule without lower bound");
		goto failure;
	}
    lower = parse_number(buf, &error);
	if (error) {
        g_warning("xml_to_size_rule: invalid lower bound");
		goto failure;
	}

    buf = xnode_prop_get(xn, TAG_RULE_SIZE_UPPER);
    if (buf == NULL) {
        g_warning("xml_to_size_rule: rule without upper bound");
		goto failure;
	}
    upper = parse_number(buf, &error);
	if (error) {
        g_warning("xml_to_size_rule: invalid upper bound");
		goto failure;
	}

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_size_rule: %s (%p)",
			g_strerror(error), cast_to_gconstpointer(target));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_size_rule(lower, upper, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;

failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_jump_rule(xnode_t *xn, void *data)
{
    const char *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_JUMP));

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_jump_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_jump_rule(target,flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;
	
failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_sha1_rule(xnode_t *xn, void *data)
{
    const struct sha1 *sha1 = NULL;
    const char *filename = NULL;
    const char *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_SHA1));

    filename = xnode_prop_get(xn, TAG_RULE_SHA1_FILENAME);
    filename = filename != NULL ? filename : "[Unknown]";

    buf = xnode_prop_get(xn, TAG_RULE_SHA1_HASH);
    if (buf != NULL) {
		sha1 = strlen(buf) == SHA1_BASE32_SIZE ? base32_sha1(buf) : NULL;
		if (!sha1) {
        	g_warning("xml_to_sha1_rule: Invalidly encoded SHA1");
			goto failure;
		}
	} else {
		sha1 = NULL;
	}

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
	if (NULL == buf) {
       	g_warning("xml_to_sha1_rule: no target");
		goto failure;
	}
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_sha1_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_sha1_rule(sha1, filename, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;
	
failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_flag_rule(xnode_t *xn, void *data)
{
    enum rule_flag_action stable = RULE_FLAG_IGNORE;
    enum rule_flag_action busy   = RULE_FLAG_IGNORE;
    enum rule_flag_action push   = RULE_FLAG_IGNORE;
    const char *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	guint64 v;
	int error;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_FLAG));

    buf = xnode_prop_get(xn, TAG_RULE_FLAG_STABLE);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            stable = v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_FLAG_BUSY);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            busy = v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_FLAG_PUSH);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
    	if (error) {
        	g_warning("xml_to_flag_rule: %s", g_strerror(error));
			goto failure;
		} else if (v == RULE_FLAG_SET || v == RULE_FLAG_UNSET) {
            push = v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_flag_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_flag_rule(stable, busy, push, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;

failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static void
xml_to_state_rule(xnode_t *xn, void *data)
{
    enum filter_prop_state display = FILTER_PROP_STATE_UNKNOWN;
    enum filter_prop_state download = FILTER_PROP_STATE_UNKNOWN;
    const char *buf;
    rule_t *rule;
    filter_t *target, *filter = data;
    guint16 flags;
	int error;
	guint64 v;

    g_assert(xn != NULL);
    g_assert(xnode_element_name(xn) != NULL);
    g_assert(filter != NULL);
    g_assert(0 == ascii_strcasecmp(xnode_element_name(xn), NODE_RULE_STATE));

    buf = xnode_prop_get(xn, TAG_RULE_STATE_DISPLAY);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error) {
        	g_warning("xml_to_state_rule: %s", g_strerror(error));
			goto failure;
		}
        if (v <= MAX_FILTER_PROP_STATE || v == FILTER_PROP_STATE_IGNORE) {
            display = v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_STATE_DOWNLOAD);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error) {
        	g_warning("xml_to_state_rule: %s", g_strerror(error));
			goto failure;
		}
        if (v <= MAX_FILTER_PROP_STATE || v == FILTER_PROP_STATE_IGNORE) {
            download = v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_TARGET);
    if (NULL == buf) {
		g_warning("xml_to_state_rule: no target");
		goto failure;
	}
    target = parse_target(buf, &error);
    if (error) {
        g_warning("xml_to_state_rule: %s", g_strerror(error));
		goto failure;
	}

    flags = get_rule_flags_from_xml(xn);
    rule = filter_new_state_rule(display, download, target, flags);
    rule->flags &= ~RULE_FLAG_VALID;

    if (GUI_PROPERTY(gui_debug) >= 4) {
        g_debug("added to filter \"%s\" rule with target %p",
            filter->name, cast_to_gconstpointer(rule->target));
	}

    filter->ruleset = g_list_append(filter->ruleset, rule);
	return;

failure:
	g_warning("unable to parse XML node: %s", xnode_to_string(xn));
}

static guint16
get_rule_flags_from_xml(xnode_t *xn)
{
    gboolean negate = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;
    guint16 flags;
    const char *buf;
	int error;
	guint64 v;

    g_assert(xn != NULL);

    buf = xnode_prop_get(xn, TAG_RULE_NEGATE);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"negate\" tag");
		} else {
        	negate = 0 != v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_ACTIVE);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"active\" tag");
		} else {
	    	active = 0 != v;
		}
    }

    buf = xnode_prop_get(xn, TAG_RULE_SOFT);
    if (buf != NULL) {
    	v = parse_number(buf, &error);
		if (error || v > 1) {
			g_warning("get_rule_flags_from_xml: Invalid \"soft\" tag");
		} else {
        	soft = 0 != v;
		}
    }

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    return flags;
}

/* vi: set ts=4 sw=4 cindent: */
