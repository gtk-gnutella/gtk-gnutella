/*
 * $Id$
 *
 * Copyright (c) 2002, Richard Eckart
 *
 * Persistance for searches and filters in XML format.
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

#include "gui.h"

#include <libxml/tree.h>
#include <libxml/parser.h>

#include "filter.h"
#include "search_xml.h"

#include "settings_gui.h"
#include "search_gui.h"
#include "version.h"
#include "utf8.h"

RCSID("$Id$");

#define GLOBAL_PRE 0
#define GLOBAL_POST 1

#define TO_BOOL(v) (v == 0 ? 0 : 1)

typedef struct node_parser {
    const xmlChar * name;
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

/*
 * Private variables
 */
static const xmlChar NODE_BUILTIN[]     = "BuiltIn";
static const xmlChar NODE_SEARCH[]      = "Search";
static const xmlChar NODE_FILTER[]      = "Filter";
static const xmlChar NODE_RULE_TEXT[]   = "TextRule";
static const xmlChar NODE_RULE_IP[]     = "IpRule";
static const xmlChar NODE_RULE_SIZE[]   = "SizeRule";
static const xmlChar NODE_RULE_JUMP[]   = "JumpRule";
static const xmlChar NODE_RULE_SHA1[]   = "SHA1Rule";
static const xmlChar NODE_RULE_FLAG[]   = "FlagRule";
static const xmlChar NODE_RULE_STATE[]  = "StateRule";

static const xmlChar TAG_BUILTIN_SHOW_UID[]       = "ShowUID";
static const xmlChar TAG_BUILTIN_DROP_UID[]       = "DropUID";
static const xmlChar TAG_BUILTIN_DOWNLOAD_UID[]   = "DownloadUID";
static const xmlChar TAG_BUILTIN_NODOWNLOAD_UID[] = "NoDownloadUID";
static const xmlChar TAG_BUILTIN_RETURN_UID[]     = "ReturnUID";
static const xmlChar TAG_FILTER_NAME[]            = "Name";
static const xmlChar TAG_FILTER_GLOBAL[]          = "Global";
static const xmlChar TAG_FILTER_UID[]             = "UID";
static const xmlChar TAG_FILTER_ACTIVE[]          = "Active";
static const xmlChar TAG_SEARCH_QUERY[]           = "Query";
static const xmlChar TAG_SEARCH_ENABLED[]         = "Enabled";
static const xmlChar TAG_SEARCH_SPEED[]           = "Speed";
static const xmlChar TAG_SEARCH_PASSIVE[]         = "Passive";
static const xmlChar TAG_SEARCH_REISSUE_TIMEOUT[] = "ReissueTimeout";
static const xmlChar TAG_SEARCH_SORT_COL[]        = "SortCol";
static const xmlChar TAG_SEARCH_SORT_ORDER[]      = "SortOrder";
static const xmlChar TAG_RULE_TEXT_CASE[]         = "Case";
static const xmlChar TAG_RULE_TEXT_MATCH[]        = "Match";
static const xmlChar TAG_RULE_TEXT_TYPE[]         = "Type";
static const xmlChar TAG_RULE_IP_ADDR[]           = "Address";
static const xmlChar TAG_RULE_IP_MASK[]           = "Netmask";
static const xmlChar TAG_RULE_SIZE_LOWER[]        = "Lower";
static const xmlChar TAG_RULE_SIZE_UPPER[]        = "Upper";
static const xmlChar TAG_RULE_SHA1_HASH[]         = "Hash";
static const xmlChar TAG_RULE_SHA1_FILENAME[]     = "OriginalFilename";
static const xmlChar TAG_RULE_NEGATE[]            = "Negate";
static const xmlChar TAG_RULE_ACTIVE[]            = "Active";
static const xmlChar TAG_RULE_SOFT[]              = "Soft";
static const xmlChar TAG_RULE_TARGET[]            = "Target";
static const xmlChar TAG_RULE_FLAG_BUSY[]         = "Busy";
static const xmlChar TAG_RULE_FLAG_PUSH[]         = "Push";
static const xmlChar TAG_RULE_FLAG_STABLE[]       = "Stable";
static const xmlChar TAG_RULE_STATE_DISPLAY[]     = "Display";
static const xmlChar TAG_RULE_STATE_DOWNLOAD[]    = "Download";



static gchar x_tmp[4096];
static const gchar *search_file_xml = "searches.xml";
static GHashTable *id_map = NULL;
static node_parser_t parser_map[] = {
    {NODE_BUILTIN,     xml_to_builtin},
    {NODE_SEARCH,      xml_to_search},
    {NODE_FILTER,      xml_to_filter},
    {NODE_RULE_TEXT,   xml_to_text_rule},
    {NODE_RULE_IP,     xml_to_ip_rule},
    {NODE_RULE_SIZE,   xml_to_size_rule},
    {NODE_RULE_JUMP,   xml_to_jump_rule},
    {NODE_RULE_SHA1,   xml_to_sha1_rule},
    {NODE_RULE_FLAG,   xml_to_flag_rule},
    {NODE_RULE_STATE,  xml_to_state_rule},
    {NULL, NULL}
};


/*
 * search_store_xml
 *
 * Store pending searches.
 */
void search_store_xml(void)
{
	GList *l;
	time_t now = time((time_t *) NULL);
    xmlDocPtr doc;
    xmlNodePtr root;
	gchar *filename_new;

    /* 
     * Create new xml document with version 1.0 
     */
    doc = xmlNewDoc((const xmlChar *) "1.0");

    /* 
     * Create a new root node "gtkGnutella searches" 
     */
    root = xmlNewDocNode(doc, NULL, (const xmlChar *) "Searches", NULL);
    xmlDocSetRootElement(doc, root);
    xmlSetProp(root, (const xmlChar *) "Time", (const xmlChar *) ctime(&now));

	g_strlcpy(x_tmp, version_number, sizeof(x_tmp));
    xmlSetProp(root, (const xmlChar *) "Version", (const xmlChar *) x_tmp);

    /*
     * Store UIDs for the builtin targets
     */
    builtin_to_xml(root);

    /*
     * Iterate over the searches and add them to the tree
     */
    for (l = searches; l; l = g_list_next(l))
        search_to_xml(root, (search_t *) l->data);

    /*
     * Iterate over the rulesets and add them to the tree.
     * Only those that are not bound to a search.
     */
    for (l = filters; l; l = g_list_next(l))
        filter_to_xml(root, (filter_t *) l->data);

    /* 
     * Try to save the file 
     */

    xmlKeepBlanksDefault(0);
    filename_new = g_strdup_printf("%s/%s.new",
						settings_gui_config_dir(), search_file_xml);

    if (
		NULL == filename_new ||
		xmlSaveFormatFile(filename_new, doc, TRUE) == -1
	) {
        g_warning("Unable to create %s to persist search: %s",
			filename_new, g_strerror(errno));
    } else {
		gchar *filename;

        if (gui_debug >= 3)
            printf("saved searches file: %s\n", x_tmp);

		filename = g_strdup_printf("%s/%s",
						settings_gui_config_dir(), search_file_xml);

		if (
			NULL == filename ||
			NULL == filename_new ||
			-1 == rename(filename_new, filename)
		)
			g_warning("could not rename %s as %s: %s",
				filename_new, filename, g_strerror(errno));

		if (NULL != filename)
			G_FREE_NULL(filename);
    }

	if (NULL != filename_new)
		G_FREE_NULL(filename_new);

	xmlFreeDoc(doc);
}

/*
 * search_retrieve_xml:
 *
 * Retrieve search list and restart searches.
 * This is the new xml version. The searches are normally
 * retrieved from  ~/.gtk-gnutella/searches.xml.
 */
gboolean search_retrieve_xml(void)
{
	xmlDocPtr doc;
    xmlNodePtr node;
    xmlNodePtr root;
    GList *f;
	gchar *path;
    
  	path = g_strdup_printf("%s/%s", settings_gui_config_dir(),
			search_file_xml);
	g_return_val_if_fail(NULL != path, FALSE);
	
	/* 
     * if the file doesn't exist 
     */
	if (!file_exists(path)) {
        g_warning("Searches file does not exist: %s", path);
		G_FREE_NULL(path);
		return FALSE;
    }
	

	/* 
     * parse the new file and put the result into newdoc 
     */
	doc = xmlParseFile(path);
    root = xmlDocGetRootElement(doc);

	/* 
     * in case something went wrong 
     */
    if(!doc) {
        g_warning("Error parsing searches file: %s", path);
		G_FREE_NULL(path);
		return FALSE;
    }

	if (/* if there is no root element */
        (root == NULL) ||
	    /* if it doesn't have a name */
	    (root->name == NULL) ||
	    /* if it isn't a Genealogy node */
	    g_ascii_strcasecmp((const gchar *) root->name, "Searches") != 0
    ) {
        g_warning("Searches file has invalid format: %s", path);
		xmlFreeDoc(doc);
		G_FREE_NULL(path);
		return FALSE;
	}
	G_FREE_NULL(path);

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
        printf("resolving UIDs\n");

    for (f = filters; f != NULL; f = g_list_next(f)) {
        filter_t *filter = (filter_t *) f->data;
        GList *r;
        gint n = 0;

        if (gui_debug >= 6) {
            printf("\n\nresolving on filter:\n");
            dump_filter(filter);
        }
        
        if (!filter_is_builtin(filter)) {
            for (r = filter->ruleset; r != NULL; r = g_list_next(r)) {
                rule_t *rule = (rule_t *)r->data;
                gpointer new_target;

                g_assert(rule->target != NULL);
                new_target = g_hash_table_lookup(id_map, rule->target);
                if (new_target == NULL)
                    g_error("Failed to resolve rule %d in \"%s\": "
						"missing key %p",
                        n, filter->name, filter_rule_to_gchar(rule));
                rule->target = new_target;
                set_flags(rule->flags, RULE_FLAG_VALID);
            
                /*
                 * We circumwent the shadows, so we must do refcounting
                 * manually here.
                 */
                if (gui_debug >= 7)
                    printf("increasing refcount on \"%s\" to %d\n",
                        rule->target->name, rule->target->refcount+1);
                rule->target->refcount ++;
                n ++;
            }
        }

        if (gui_debug >= 6) {
            printf("resolved filter:\n");
            dump_filter(filter);
        }
    }

    /*
     * Verify bindings.
     */
    {
        gboolean borked = FALSE;
        GList *s;

        if (gui_debug >= 6)
            printf("verifying bindings...\n");

        for (s = searches; s != NULL; s = g_list_next(s)) {
            search_t *search = (search_t *) s->data;

            if (search->filter->search == search) {
                if (gui_debug >= 6)
                    printf("binding ok for: %s\n", search->query);
            } else {
                g_warning("binding broken for: %s\n", search->query);
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
}

static void builtin_to_xml(xmlNodePtr parent)
{
    xmlNodePtr newxml;
    
    g_assert(parent != NULL);

    newxml = xmlNewChild(parent,NULL,NODE_BUILTIN, NULL);
    
  	gm_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_get_show_target());
    xmlSetProp(newxml, TAG_BUILTIN_SHOW_UID, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_get_drop_target());
    xmlSetProp(newxml, TAG_BUILTIN_DROP_UID, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_get_download_target());
    xmlSetProp(newxml, TAG_BUILTIN_DOWNLOAD_UID, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_get_nodownload_target());
    xmlSetProp(newxml, TAG_BUILTIN_NODOWNLOAD_UID, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_get_return_target());
    xmlSetProp(newxml, TAG_BUILTIN_RETURN_UID, (const xmlChar *) x_tmp);
}

static void search_to_xml(xmlNodePtr parent, search_t *s)
{
    xmlNodePtr newxml;
    GList *l;

    g_assert(s != NULL);
    g_assert(s->query != NULL);
    g_assert(parent != NULL);

    if (gui_debug >= 6) {
        printf("saving search: %s (%p enabled=%d)\n", s->query, s, s->enabled);
        printf("  -- filter is bound to: %p\n", s->filter->search);
        printf("  -- search is         : %p\n", s);
    }

    newxml = xmlNewChild(parent, NULL, NODE_SEARCH, NULL);

#ifndef USE_GTK2   
	if (!is_ascii_string(s->query) && !utf8_is_valid_string(s->query, 0))
	    xmlSetProp(newxml, TAG_SEARCH_QUERY,
			(const xmlChar *) locale_to_utf8(s->query, 0));
	else
#endif
	    xmlSetProp(newxml, TAG_SEARCH_QUERY, (const xmlChar *) s->query);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", s->enabled);
    xmlSetProp(newxml, TAG_SEARCH_ENABLED, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%u", 
        search_get_minimum_speed(s->search_handle));
    xmlSetProp(newxml, TAG_SEARCH_SPEED, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(s->passive));
    xmlSetProp(newxml, TAG_SEARCH_PASSIVE, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%u", 
        search_get_reissue_timeout(s->search_handle));
    xmlSetProp(newxml, TAG_SEARCH_REISSUE_TIMEOUT, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%i", s->sort_col);
    xmlSetProp(newxml, TAG_SEARCH_SORT_COL, (const xmlChar *) x_tmp);

  	gm_snprintf(x_tmp, sizeof(x_tmp), "%i", s->sort_order);
    xmlSetProp(newxml, TAG_SEARCH_SORT_ORDER, (const xmlChar *) x_tmp);

    for (l = s->filter->ruleset; l != NULL; l = g_list_next(l))
        rule_to_xml(newxml, (rule_t *) l->data);
}


static void filter_to_xml(xmlNodePtr parent, filter_t *f)
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
            printf("not saving bound/builtin: %s\n", f->name);
        return;
    }

    if (gui_debug >= 6) {
        printf("saving filter: %s\n", f->name);
        printf("  -- bound   : %p\n", f->search);
    }

    newxml = xmlNewChild(parent, NULL, NODE_FILTER, NULL);
    
    xmlSetProp(newxml, TAG_FILTER_NAME, (const xmlChar *) f->name);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(filter_is_active(f)));
    xmlSetProp(newxml, TAG_FILTER_ACTIVE, (const xmlChar *) x_tmp);

    /*
     * We take the pointer as a unique id which
     * we use during read-in for setting the
     * destination of JUMP actions.
     */
  	gm_snprintf(x_tmp, sizeof(x_tmp), "%p", f);
    xmlSetProp(newxml, TAG_FILTER_UID, (const xmlChar *) x_tmp);

    if (filter_get_global_pre() == f) {
    	gm_snprintf(x_tmp, sizeof(x_tmp), "%u", GLOBAL_PRE);
        xmlSetProp(newxml, TAG_FILTER_GLOBAL, (const xmlChar *) x_tmp); 
    }

    if (filter_get_global_post() == f) {
    	gm_snprintf(x_tmp, sizeof(x_tmp), "%u", GLOBAL_POST);
        xmlSetProp(newxml, TAG_FILTER_GLOBAL, (const xmlChar *) x_tmp); 
    }

    /* 
     * Since free rulesets don't have bound searches,
     * we need not save the ->search member.
     * Visited is only used internally during filter
     * application.
     */
    for (l = f->ruleset; l != NULL; l = g_list_next(l))
        rule_to_xml(newxml, (rule_t *) l->data);
}

static void rule_to_xml(xmlNodePtr parent, rule_t *r)
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
        newxml = xmlNewChild(parent, NULL, NODE_RULE_TEXT, NULL);

        xmlSetProp(newxml, TAG_RULE_TEXT_CASE, 
            (const xmlChar *) (r->u.text.case_sensitive ? "1" : "0"));
        xmlSetProp(newxml, TAG_RULE_TEXT_MATCH,
			(const xmlChar *) r->u.text.match);

        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.text.type);
        xmlSetProp(newxml, TAG_RULE_TEXT_TYPE, (const xmlChar *) x_tmp);
        break;
    case RULE_IP:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_IP, NULL);

        xmlSetProp(newxml, TAG_RULE_IP_ADDR,
			(const xmlChar *) ip_to_gchar(r->u.ip.addr));
        xmlSetProp(newxml, TAG_RULE_IP_MASK,
			(const xmlChar *) ip_to_gchar(r->u.ip.mask));
        break;
    case RULE_SIZE:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_SIZE, NULL);
        
        gm_snprintf(x_tmp, sizeof(x_tmp), "%lu", (gulong) r->u.size.lower);
        xmlSetProp(newxml, TAG_RULE_SIZE_LOWER, (const xmlChar *) x_tmp);

        gm_snprintf(x_tmp, sizeof(x_tmp), "%lu", (gulong) r->u.size.upper);
        xmlSetProp(newxml, TAG_RULE_SIZE_UPPER, (const xmlChar *) x_tmp);
        break;
    case RULE_JUMP:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_JUMP, NULL);
        
        /*
         * Only need target to this rule and that's done below.
         */
        break;
    case RULE_SHA1:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_SHA1, NULL);

        if (r->u.sha1.hash != NULL)
            xmlSetProp(newxml, TAG_RULE_SHA1_HASH,
				(const xmlChar *) sha1_base32(r->u.sha1.hash));

        xmlSetProp(newxml, TAG_RULE_SHA1_FILENAME,
			(const xmlChar *) r->u.sha1.filename);
        
        /*
         * r->u.sha1.hash is NULL, we just omit the hash.
         */
        break;
    case RULE_FLAG:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_FLAG, NULL);
        
        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.flag.stable);
        xmlSetProp(newxml, TAG_RULE_FLAG_STABLE, (const xmlChar *) x_tmp);

        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.flag.busy);
        xmlSetProp(newxml, TAG_RULE_FLAG_BUSY, (const xmlChar *) x_tmp);

        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.flag.push);
        xmlSetProp(newxml, TAG_RULE_FLAG_PUSH, (const xmlChar *) x_tmp);
        break;
    case RULE_STATE:
         newxml = xmlNewChild(parent, NULL, NODE_RULE_STATE, NULL);
        
        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.state.display);
        xmlSetProp(newxml, TAG_RULE_STATE_DISPLAY, (const xmlChar *) x_tmp);

        gm_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.state.download);
        xmlSetProp(newxml, TAG_RULE_STATE_DOWNLOAD, (const xmlChar *) x_tmp);
        break;
    default:
        g_error("Unknown rule type: %d", r->type);
    }

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(RULE_IS_NEGATED(r)));
    xmlSetProp(newxml, TAG_RULE_NEGATE, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(RULE_IS_ACTIVE(r)));
    xmlSetProp(newxml, TAG_RULE_ACTIVE, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(RULE_IS_SOFT(r)));
    xmlSetProp(newxml, TAG_RULE_SOFT, (const xmlChar *) x_tmp);

    gm_snprintf(x_tmp, sizeof(x_tmp), "%p", r->target);
    xmlSetProp(newxml, TAG_RULE_TARGET, (const xmlChar *) x_tmp);
}

static void parse_xml(xmlNodePtr xmlnode, gpointer user_data)
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
    
    g_error("Unknown node: %s", xmlnode->name);
}

static void xml_to_builtin(xmlNodePtr xmlnode, gpointer user_data)
{
    gchar *buf;
    gpointer target;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_BUILTIN));
    g_assert(filter_get_show_target() != NULL);
    g_assert(filter_get_drop_target() != NULL);
    g_assert(filter_get_download_target() != NULL);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_BUILTIN_SHOW_UID);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_builtin: %s", g_strerror(errno));
    g_free(buf);
    g_hash_table_insert(id_map, target, filter_get_show_target());

    buf = (gchar *) xmlGetProp(xmlnode, TAG_BUILTIN_DROP_UID);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_builtin: %s", g_strerror(errno));
    g_free(buf);
    g_hash_table_insert(id_map, target, filter_get_drop_target());

    buf = (gchar *) xmlGetProp(xmlnode, TAG_BUILTIN_DOWNLOAD_UID);
    if (buf != NULL) {
        errno = 0;
        target = (gpointer) strtoul(buf, 0, 16);
        if (errno != 0)
            g_error( "xml_to_builtin: %s", g_strerror(errno));
        g_free(buf);
        g_hash_table_insert(id_map, target, filter_get_download_target());
    } else {
        g_warning("xml_to_builtin: no \"DOWNLOAD\" target");
    }
    
    buf = (gchar *) xmlGetProp(xmlnode, TAG_BUILTIN_NODOWNLOAD_UID);
    if (buf != NULL) {
        errno = 0;
        target = (gpointer) strtoul(buf, 0, 16);
        if (errno != 0)
            g_error( "xml_to_builtin: %s", g_strerror(errno));
        g_free(buf);
        g_hash_table_insert(id_map, target, filter_get_nodownload_target());
    } else {
        g_warning("xml_to_builtin: no \"DON'T DOWNLOAD\" target");
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_BUILTIN_RETURN_UID);
    if (buf != NULL) {
        errno = 0;
        target = (gpointer) strtoul(buf, 0, 16);
        if (errno != 0)
            g_error( "xml_to_builtin: %s", g_strerror(errno));
        g_free(buf);
        g_hash_table_insert(id_map, target, filter_get_return_target());
    } else {
        g_warning("xml_to_builtin: no \"RETURN\" target");
    }
}

static void xml_to_search(xmlNodePtr xmlnode, gpointer user_data)
{
    gchar *buf;
    gchar *query;
    gint sort_col = SORT_NO_COL, sort_order = SORT_NONE;
    guint32 speed;
    guint32 reissue_timeout;
    xmlNodePtr node;
    search_t * search;
    guint flags = 0;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_SEARCH));

    gui_prop_get_guint32_val(PROP_DEFAULT_MINIMUM_SPEED, &speed);
    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &reissue_timeout);

	buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_QUERY);
    if (!buf) {
        g_warning("Ignored search without query");
        return;
    }
#ifdef USE_GTK2
	query = buf;
#else
    query = g_strdup(utf8_to_locale(buf, 0));
	g_free(buf);
#endif

    buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_ENABLED);
    if (buf) {
        if (atoi(buf) == 1)
			flags |= SEARCH_ENABLED;
        g_free(buf);
    } else
		flags |= SEARCH_ENABLED;	 /* Compatibility: searches always began */

    buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_SPEED);
    if (buf) {
        speed = atol(buf);
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_REISSUE_TIMEOUT);
    if (buf) {
        reissue_timeout = atol(buf);
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_PASSIVE);
    if (buf) {
        if (atol(buf) == 1)
			flags |= SEARCH_PASSIVE;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_SORT_COL);
    if (buf) {
        sort_col = atol(buf);
        g_free(buf);
    }

	buf = (gchar *) xmlGetProp(xmlnode, TAG_SEARCH_SORT_ORDER);
    if (buf) {
        sort_order = atol(buf);
        g_free(buf);
    }

    if (gui_debug >= 4)
        printf("adding new %s %s search: %s\n",
			(flags & SEARCH_ENABLED) ? "enabled" : "disabled",
			(flags & SEARCH_PASSIVE) ? "passive" : "active",
			query);

	search_gui_new_search_full(query, (gint32) speed, reissue_timeout,
		sort_col, sort_order, flags, &search);

    g_free(query);

    /*
     * Also parse all children.
     */
	for (node = xmlnode->children; node != NULL; node = node->next)
        parse_xml(node, search->filter);
}

static void xml_to_filter(xmlNodePtr xmlnode, gpointer user_data)
{
    gchar *buf;
    gchar *name;
    xmlNodePtr node;
    filter_t *filter;
    gpointer dest;
    gboolean active = TRUE;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_FILTER));

	buf = (gchar *) xmlGetProp(xmlnode, TAG_FILTER_NAME);
    if (!buf) {
        g_warning("Ignored unnamed filter");
        return;
    }
    name = buf;

    buf = (gchar *) xmlGetProp(xmlnode, TAG_FILTER_GLOBAL);
    if (buf) {
        gint t;
        errno = 0;
        t = strtoul(buf, 0, 10);
        if (errno != 0)
            g_error("xml_to_filter: %s", g_strerror(errno));
        switch(t) {
        case GLOBAL_PRE:
            filter = filter_get_global_pre();
            break;
        case GLOBAL_POST:
            filter = filter_get_global_post();
            break;
        default:
            filter = NULL;
            g_assert_not_reached();
        };
        g_free(buf);
    } else {
        if (gui_debug >= 4)
            printf("adding new filter: %s\n", name);
        filter = filter_new(name);
        filters = g_list_append(filters, filter);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_FILTER_ACTIVE);
    if (buf != NULL) {
        active = atol(buf) == 1 ? TRUE : FALSE;
        g_free(buf);
    }
    if (active)
        set_flags(filter->flags, FILTER_FLAG_ACTIVE);
    else
        clear_flags(filter->flags, FILTER_FLAG_ACTIVE);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_FILTER_UID);
    g_assert(buf);
    errno = 0;
    dest = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_filter: %s", g_strerror(errno));
    g_free(buf);
    g_hash_table_insert(id_map, dest, filter);

    g_free(name);

    /*
     * Also parse all children.
     */
	for(node = xmlnode->children; node != NULL; node = node->next)
        parse_xml(node, filter);
}

static void xml_to_text_rule(xmlNodePtr xmlnode, gpointer filter)
{
    gchar *match;
    enum rule_text_type type;
    gboolean case_sensitive;
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_TEXT));

    match = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TEXT_MATCH);
    if (match == NULL)
        g_error("xml_to_text_rule: rule without match string");

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TEXT_CASE);
    case_sensitive = atol(buf) == 1 ? TRUE : FALSE;
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TEXT_TYPE);
    type = (enum rule_text_type) atol(buf);
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_text_rule: %s", g_strerror(errno));
    g_free(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_text_rule
        (match, type, case_sensitive, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);

    g_free(match);
}

static void xml_to_ip_rule(xmlNodePtr xmlnode, gpointer filter)
{
    guint32 addr;
    guint32 mask;
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_IP));

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_IP_ADDR);
    if (buf == NULL)
        g_error("xml_to_ip_rule: rule without ip address");
    addr = gchar_to_ip(buf);
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_IP_MASK);
    if (buf == NULL)
        g_error("xml_to_ip_rule: rule without netmask");
    mask = gchar_to_ip(buf);
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_ip_rule: %s", g_strerror(errno));
    g_free(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_ip_rule(addr, mask, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_size_rule(xmlNodePtr xmlnode, gpointer filter)
{
    size_t lower;
    size_t upper;
    gchar *buf;
    rule_t *rule;
    filter_t *target = NULL;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_SIZE));

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_SIZE_LOWER);
    if (buf == NULL)
        g_error("xml_to_size_rule: rule without lower bound");
    lower = atol(buf);
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_SIZE_UPPER);
    if (buf == NULL)
        g_error("xml_to_size_rule: rule without upper bound");
    upper = atol(buf);
    g_free(buf);
 
    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_size_rule: %s (%p)", g_strerror(errno), target);
    g_free(buf);
       
    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_size_rule(lower, upper, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_jump_rule(xmlNodePtr xmlnode, gpointer filter)
{
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_JUMP));

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_jump_rule: %s", g_strerror(errno));
    g_free(buf);
       
    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_jump_rule(target,flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_sha1_rule(xmlNodePtr xmlnode, gpointer filter)
{
    gchar *hash = NULL;
    gchar *filename = NULL;
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(g_ascii_strcasecmp((const gchar *) xmlnode->name, (const gchar *) NODE_RULE_SHA1) == 0);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_SHA1_FILENAME);
    filename = buf != NULL ? buf : g_strdup("[Unknown]");

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_SHA1_HASH);
    if (buf != NULL && strlen(buf) == SHA1_BASE32_SIZE)
        hash = (gchar *) base32_sha1(buf);
    g_free(buf);

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_sha1_rule: %s", g_strerror(errno));
    g_free(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_sha1_rule(hash, filename, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    g_free(filename);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_flag_rule(xmlNodePtr xmlnode, gpointer filter)
{
    enum rule_flag_action stable = RULE_FLAG_IGNORE;
    enum rule_flag_action busy   = RULE_FLAG_IGNORE;
    enum rule_flag_action push   = RULE_FLAG_IGNORE;
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_FLAG));

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_FLAG_STABLE);
    if (buf != NULL) {
        gint val = atol(buf);
        if ((val == RULE_FLAG_SET) || (val == RULE_FLAG_UNSET))
            stable = val;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_FLAG_BUSY);
    if (buf != NULL) {
        gint val = atol(buf);
        if ((val == RULE_FLAG_SET) || (val == RULE_FLAG_UNSET))
            busy = val;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_FLAG_PUSH);
    if (buf != NULL) {
        gint val = atol(buf);
        if ((val == RULE_FLAG_SET) || (val == RULE_FLAG_UNSET))
            push = val;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_flag_rule: %s", g_strerror(errno));
    g_free(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_flag_rule(stable, busy, push, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_state_rule(xmlNodePtr xmlnode, gpointer filter)
{
    enum filter_prop_state display = FILTER_PROP_STATE_UNKNOWN;
    enum filter_prop_state download = FILTER_PROP_STATE_UNKNOWN;
    gchar *buf;
    rule_t *rule;
    filter_t *target;
    guint16 flags;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(0 == g_ascii_strcasecmp((const gchar *) xmlnode->name,
		(const gchar *) NODE_RULE_STATE));

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_STATE_DISPLAY);
    if (buf != NULL) {
        gint val = atol(buf);
        if (((val >= 0) && (val <= MAX_FILTER_PROP_STATE)) ||
            (val == FILTER_PROP_STATE_IGNORE))
            display = val;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_STATE_DOWNLOAD);
    if (buf != NULL) {
        gint val = atol(buf);
        if (((val >= 0) && (val <= MAX_FILTER_PROP_STATE)) ||
            (val == FILTER_PROP_STATE_IGNORE))
            download = val;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_TARGET);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_state_rule: %s", g_strerror(errno));
    g_free(buf);

    flags = get_rule_flags_from_xml(xmlnode);
    rule = filter_new_state_rule(display, download, target, flags);
    clear_flags(rule->flags, RULE_FLAG_VALID);

    if (gui_debug >= 4)
        printf( "added to filter \"%s\" rule with target %p\n",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static guint16 get_rule_flags_from_xml(xmlNodePtr xmlnode)
{
    gboolean negate = FALSE;
    gboolean active = TRUE;
    gboolean soft   = FALSE;
    guint16 flags;  
    gchar *buf;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    
    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_NEGATE);
    if (buf != NULL) {
        negate = atol(buf) == 1 ? TRUE : FALSE;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_ACTIVE);
    if (buf != NULL) {
        active = atol(buf) == 1 ? TRUE : FALSE;
        g_free(buf);
    }

    buf = (gchar *) xmlGetProp(xmlnode, TAG_RULE_SOFT);
    if (buf != NULL) {
        soft = atol(buf) == 1 ? TRUE : FALSE;
        g_free(buf);
    }

    flags =
        (negate ? RULE_FLAG_NEGATE : 0) |
        (active ? RULE_FLAG_ACTIVE : 0) |
        (soft   ? RULE_FLAG_SOFT   : 0);

    return flags;
}
