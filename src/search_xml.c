/*
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

#include <gnome-xml/tree.h>
#include <gnome-xml/parser.h>

#include "gnutella.h"
#include "gmsg.h"
#include "misc.h"
#include "filter.h"
#include "search.h"
#include "search_xml.h"

#define GLOBAL_PRE 0
#define GLOBAL_POST 1

#define TO_BOOL(v) (v == 0 ? 0 : 1)

typedef struct node_parser {
    gchar * name;
    void (*parser_func)(xmlNodePtr, gpointer);
} node_parser_t;


/*
 * The rulesets are defined in filter.c, but I don't want
 * them to be public. They are only needed here. As are
 * global_ruleset_pre and global_ruleset_post.
 */
extern gchar *rule_to_gchar(rule_t *);
extern void dump_ruleset(GList *ruleset);
extern void dump_filter(filter_t *filter);

extern GList *filters;
extern filter_t *filter_global_pre;
extern filter_t *filter_global_post;
extern filter_t *filter_show;
extern filter_t *filter_drop;

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

static const gchar PROP_BUILTIN_SHOW_UID[] = "ShowUID";
static const gchar PROP_BUILTIN_DROP_UID[] = "DropUID";
static const gchar PROP_FILTER_NAME[]      = "Name";
static const gchar PROP_FILTER_GLOBAL[]    = "Global";
static const gchar PROP_FILTER_UID[]       = "UID";
static const gchar PROP_SEARCH_QUERY[]     = "Query";
static const gchar PROP_SEARCH_SPEED[]     = "Speed";
static const gchar PROP_RULE_TEXT_CASE[]   = "Case";
static const gchar PROP_RULE_TEXT_MATCH[]  = "Match";
static const gchar PROP_RULE_TEXT_TYPE[]   = "Type";
static const gchar PROP_RULE_IP_ADDR[]     = "Address";
static const gchar PROP_RULE_IP_MASK[]     = "Netmask";
static const gchar PROP_RULE_SIZE_LOWER[]  = "Lower";
static const gchar PROP_RULE_SIZE_UPPER[]  = "Upper";
static const gchar PROP_RULE_NEGATE[]      = "Negate";
static const gchar PROP_RULE_TARGET[]      = "Target";


static gchar x_tmp[4096];
static gchar *search_file_xml = "searches.xml";
static GHashTable *id_map = NULL;
static node_parser_t parser_map[] = {
    {(gchar *)NODE_BUILTIN,     xml_to_builtin},
    {(gchar *)NODE_SEARCH,      xml_to_search},
    {(gchar *)NODE_FILTER,      xml_to_filter},
    {(gchar *)NODE_RULE_TEXT,   xml_to_text_rule},
    {(gchar *)NODE_RULE_IP,     xml_to_ip_rule},
    {(gchar *)NODE_RULE_SIZE,   xml_to_size_rule},
    {(gchar *)NODE_RULE_JUMP,   xml_to_jump_rule},
    {NULL, NULL}
};


/*
 * search_store_xml
 *
 * Store pending non-passive searches.
 */
void search_store_xml(void)
{
	GList *l;
	time_t now = time((time_t *) NULL);
    xmlDocPtr doc;

    /* 
     * create new xml document with version 1.0 
     */
    doc = xmlNewDoc("1.0");

    /* 
     *create a new root node "gtkGnutella searches" 
     */
    doc->root = xmlNewDocNode(doc, NULL, "Searches", NULL);
    xmlSetProp(doc->root,"Time", ctime(&now));

	g_snprintf(x_tmp, sizeof(x_tmp), "%u.%u", 
        GTA_VERSION, GTA_SUBVERSION);
    xmlSetProp(doc->root,"Version", x_tmp);

    /*
     * Store UIDs for the builtin targets
     */
    builtin_to_xml(doc->root);

    /*
     * Iterate over the searches and add them to the tree
     */
    for (l = searches; l; l = l->next) {
		search_t *sch = (search_t *) l->data;
		if (!sch->passive)
			search_to_xml(doc->root, sch);
	}

    /*
     * Iterate over the rulesets and add them to the tree.
     * Only those that are not bound to a search.
     */
    for (l = filters; l; l = l->next)
        filter_to_xml(doc->root, (filter_t *) l->data);

    /* 
     *try to save the file 
     */
    g_snprintf(x_tmp, sizeof(x_tmp), "%s/%s", config_dir, search_file_xml);
    if(xmlSaveFile(x_tmp,doc) == -1) {
        g_warning("Unable to create %s to persist search: %s",
			x_tmp, g_strerror(errno));
    } else {
        if (dbg >= 3)
            g_message("saved searches file: %s", x_tmp);
    }


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
    GList *f;
    
  	g_snprintf(x_tmp, sizeof(x_tmp), "%s/%s", config_dir, search_file_xml);

	/* 
     * if the file doesn't exist 
     */
	if(!file_exists(x_tmp)) {
        g_warning("Searches file does not exist: %s", x_tmp);
		return FALSE;
    }

	/* 
     * parse the new file and put the result into newdoc 
     */
	doc = xmlParseFile(x_tmp);

	/* 
     * in case something went wrong 
     */
    if(!doc) {
        g_warning("Error parsing searches file: %s", x_tmp);
		return FALSE;
    }

	if (/* if there is no root element */
        !doc->root ||
	    /* if it doesn't have a name */
	    !doc->root->name ||
	    /* if it isn't a Genealogy node */
	    g_strcasecmp(doc->root->name,"Searches") != 0
    ) {
        g_warning("Searches file has invalid format: %s", x_tmp);
		xmlFreeDoc(doc);
		return FALSE;
	}

    id_map = g_hash_table_new(NULL, NULL);

    /* 
     * find nodes and add them to the list, this just
	 * loops through all the children of the root of the document 
     */
	for (node = doc->root->childs; node != NULL; node = node->next)
        parse_xml(node, NULL);

    /*
     * We should have collected all ruleset UIDs now. So we can 
     * now resolve the UIDs to the actual pointers we use now.
     * We need to commit before we do this, because we want to 
     * interate over the rulesets and don't want to cope with
     * shadows.
     */

    if (dbg >= 6)
        g_message("resolving UIDs");

    for (f = filters; f != NULL; f = f->next) {
        filter_t *filter = (filter_t *)f->data;
        GList *r;
        gint n = 0;

        if (dbg >= 6) {
            g_message("\n\nresolving on filter:");
            dump_filter(filter);
        }
        
        if ((filter != filter_drop) && (filter != filter_show)) {
            for (r = filter->ruleset; r != NULL; r = r->next) {
                rule_t *rule = (rule_t *)r->data;
                gpointer new_target;

                g_assert(rule->target != NULL);
                new_target = g_hash_table_lookup(id_map, rule->target);
                if (new_target == NULL)
                    g_error("Failed to resolve rule %d in \"%s\": missing key %p",
                        n, filter->name, rule_to_gchar(rule));
                rule->target = new_target;
                rule->valid = TRUE;
            
                /*
                 * We circumwent the shadows, so we must do refcounting
                 * manually here.
                 */
                if (dbg >= 7)
                    g_message("increasing refcount on \"%s\" to %d",
                        rule->target->name, rule->target->refcount+1);
                rule->target->refcount ++;
                n ++;
            }
        }

        if (dbg >= 6) {
            g_message("resolved filter:");
            dump_filter(filter);
        }
    }

    /*
     * Verify bindings.
     */
    {
        gboolean borked = FALSE;
        GList *s;

        if (dbg >= 6)
            g_message("verifying bindings...");

        for (s = searches; s != NULL; s = s->next) {
            search_t * search = (search_t *)s->data;

            if (search->filter->search == search) {
                if (dbg >= 6)
                    g_message("binding ok for: %s", search->query);
            } else {
                g_warning("binding broken for: %s", search->query);
                borked = TRUE;
            }
        }

        g_assert(!borked);
    }


    g_hash_table_destroy(id_map);

	xmlFreeDoc(doc);

	return TRUE;
}

static void builtin_to_xml(xmlNodePtr parent)
{
    xmlNodePtr newxml;
    
    g_assert(parent != NULL);
    g_assert(filter_show != filter_drop);

    newxml = xmlNewChild(parent,NULL,NODE_BUILTIN, NULL);
    
  	g_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_show);
    xmlSetProp(newxml,PROP_BUILTIN_SHOW_UID, x_tmp);

  	g_snprintf(x_tmp, sizeof(x_tmp), "%p", filter_drop);
    xmlSetProp(newxml,PROP_BUILTIN_DROP_UID, x_tmp);
}

static void search_to_xml(xmlNodePtr parent, search_t *s)
{
    xmlNodePtr newxml;
    GList *l;

    g_assert(s != NULL);
    g_assert(s->query != NULL);
    g_assert(parent != NULL);

    if (dbg >= 6) {
        g_message("saving search: %s", s->query);
        g_message("  -- filter is bound to: %p", s->filter->search);
        g_message("  -- search is         : %p", s);
    }

    newxml = xmlNewChild(parent, NULL, NODE_SEARCH, NULL);
    
    xmlSetProp(newxml, PROP_SEARCH_QUERY, s->query);

  	g_snprintf(x_tmp, sizeof(x_tmp), "%u", s->speed);
    xmlSetProp(newxml, PROP_SEARCH_SPEED, x_tmp);
    
    for (l = s->filter->ruleset; l != NULL; l = l->next)
        rule_to_xml(newxml, (rule_t *)l->data);
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
    if ((f == filter_show) || (f == filter_drop) || f->search != NULL) {
        if (dbg >= 7)
            g_message("not saving bound/builtin: %s", f->name);
        return;
    }

    if (dbg >= 6) {
        g_message("saving filter: %s", f->name);
        g_message("  -- bound   : %p", f->search);
    }

    newxml = xmlNewChild(parent, NULL, NODE_FILTER, NULL);
    
    xmlSetProp(newxml, PROP_FILTER_NAME, f->name);

    /*
     * We take the pointer as a unique id which
     * we use during read-in for setting the
     * destination of JUMP actions.
     */
  	g_snprintf(x_tmp, sizeof(x_tmp), "%p", f);
    xmlSetProp(newxml, PROP_FILTER_UID, x_tmp);

    if (filter_global_pre == f) {
    	g_snprintf(x_tmp, sizeof(x_tmp), "%u", GLOBAL_PRE);
        xmlSetProp(newxml, PROP_FILTER_GLOBAL, x_tmp); 
    }

    if (filter_global_post == f) {
    	g_snprintf(x_tmp, sizeof(x_tmp), "%u", GLOBAL_POST);
        xmlSetProp(newxml, PROP_FILTER_GLOBAL, x_tmp); 
    }

    /* 
     * Since free rulesets don't have bound searches,
     * we need not save the ->search member.
     * Visited is only used internally during filter
     * application.
     */
    for (l = f->ruleset; l != NULL; l = l->next)
        rule_to_xml(newxml, (rule_t *)l->data);
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

        xmlSetProp(newxml, PROP_RULE_TEXT_CASE, 
            r->u.text.case_sensitive ? "1" : "0");
        xmlSetProp(newxml, PROP_RULE_TEXT_MATCH, r->u.text.match);

        g_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.text.type);
        xmlSetProp(newxml, PROP_RULE_TEXT_TYPE, x_tmp);
        break;
    case RULE_IP:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_IP, NULL);

        xmlSetProp(newxml,PROP_RULE_IP_ADDR, ip_to_gchar(r->u.ip.addr));
        xmlSetProp(newxml,PROP_RULE_IP_MASK, ip_to_gchar(r->u.ip.mask));
        break;
    case RULE_SIZE:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_SIZE, NULL);
        
        g_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.size.lower);
        xmlSetProp(newxml, PROP_RULE_SIZE_LOWER, x_tmp);

        g_snprintf(x_tmp, sizeof(x_tmp), "%u", r->u.size.upper);
        xmlSetProp(newxml, PROP_RULE_SIZE_UPPER, x_tmp);
        break;
    case RULE_JUMP:
        newxml = xmlNewChild(parent, NULL, NODE_RULE_JUMP, NULL);
        
        /*
         * Only need target to this rule and that's done below.
         */
        break;
    default:
        g_error("Unknown rule type: %d", r->type);
    }

    g_snprintf(x_tmp, sizeof(x_tmp), "%u", TO_BOOL(r->negate));
    xmlSetProp(newxml, PROP_RULE_NEGATE, x_tmp);

    g_snprintf(x_tmp, sizeof(x_tmp), "%p", r->target);
    xmlSetProp(newxml, PROP_RULE_TARGET, x_tmp);
}

static void parse_xml(xmlNodePtr xmlnode, gpointer user_data)
{
    gint n;

    g_assert(xmlnode != NULL);

    if (!xmlnode->name) {
        g_warning("Unnamed node: ignored");
	    return;
    } 

    for (n = 0; parser_map[n].name != NULL; n ++) {
        if (g_strcasecmp(xmlnode->name, parser_map[n].name) == 0) {
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
    g_assert(g_strcasecmp(xmlnode->name, NODE_BUILTIN) == 0);
    g_assert(filter_show != NULL);
    g_assert(filter_drop != NULL);

    buf = xmlGetProp(xmlnode, PROP_BUILTIN_SHOW_UID);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_builtin: %s", g_strerror(errno));
    g_free(buf);
    g_hash_table_insert(id_map, target, filter_show);

    buf = xmlGetProp(xmlnode, PROP_BUILTIN_DROP_UID);
    g_assert(buf != NULL);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_builtin: %s", g_strerror(errno));
    g_free(buf);
    g_hash_table_insert(id_map, target, filter_drop);
}

static void xml_to_search(xmlNodePtr xmlnode, gpointer user_data)
{
    gchar *buf;
    gchar *query;
    gint32 speed = 0;
    xmlNodePtr node;
    search_t * search;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_SEARCH) == 0);

	buf = xmlGetProp(xmlnode, PROP_SEARCH_QUERY);
    if (!buf) {
        g_warning("Ignored search without query");
        return;
    }
    query = buf;

    buf = xmlGetProp(xmlnode, PROP_SEARCH_SPEED);
    if (buf) {
        speed = atol(buf);
        g_free(buf);
    }

    if (dbg >= 4)
        g_message("adding new search: %s", query);
    search = new_search(speed, query);

    g_free(query);

    /*
     * Also parse all children.
     */
	for(node = xmlnode->childs; node != NULL; node = node->next)
        parse_xml(node, search->filter);
}

static void xml_to_filter(xmlNodePtr xmlnode, gpointer user_data)
{
    gchar *buf;
    gchar *name;
    xmlNodePtr node;
    filter_t *filter;
    gpointer dest;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_FILTER) == 0);

	buf = xmlGetProp(xmlnode, PROP_FILTER_NAME);
    if (!buf) {
        g_warning("Ignored unnamed filter");
        return;
    }
    name = buf;

    buf = xmlGetProp(xmlnode, PROP_FILTER_GLOBAL);
    if (buf) {
        gint t;
        errno = 0;
        t = strtoul(buf, 0, 10);
        if (errno != 0)
            g_error( "xml_to_filter: %s", g_strerror(errno));
        switch(t) {
        case GLOBAL_PRE:
            filter = filter_global_pre;
            break;
        case GLOBAL_POST:
            filter = filter_global_post;
            break;
        default:
            filter = NULL;
            g_assert_not_reached();
        };
    } else {
        if (dbg >= 4)
            g_message("adding new filter: %s", name);
        filter = filter_new(name);
    }

    buf = xmlGetProp(xmlnode, PROP_FILTER_UID);
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
	for(node = xmlnode->childs; node != NULL; node = node->next)
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
    gboolean negate;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_RULE_TEXT) ==0);

    match = xmlGetProp(xmlnode, PROP_RULE_TEXT_MATCH);

    buf = xmlGetProp(xmlnode, PROP_RULE_TEXT_CASE);
    case_sensitive = atol(buf) == 1 ? TRUE : FALSE;
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_NEGATE);
    negate = atol(buf) == 1 ? TRUE : FALSE;
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_TEXT_TYPE);
    type = (enum rule_text_type) atol(buf);
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_text_rule: %s", g_strerror(errno));
    g_free(buf);

    rule = filter_new_text_rule
        (match, type, case_sensitive, target, negate);
    rule->valid = FALSE;

    if (dbg >= 4)
        g_message( "added to filter \"%s\" rule with target %p",
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
    gboolean negate;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_RULE_IP) ==0);

    buf = xmlGetProp(xmlnode, PROP_RULE_IP_ADDR);
    addr = gchar_to_ip(buf);
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_IP_MASK);
    mask = gchar_to_ip(buf);
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_NEGATE);
    negate = atol(buf) == 1 ? TRUE : FALSE;
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_ip_rule: %s", g_strerror(errno));
    g_free(buf);

    rule = filter_new_ip_rule(addr, mask, target, negate);
    rule->valid = FALSE;

    if (dbg >= 4)
        g_message( "added to filter \"%s\" rule with target %p",
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
    gboolean negate;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_RULE_SIZE) ==0);

    buf = xmlGetProp(xmlnode, PROP_RULE_SIZE_LOWER);
    lower = atol(buf);
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_SIZE_UPPER);
    upper = atol(buf);
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_NEGATE);
    negate = atol(buf) == 1 ? TRUE : FALSE;
    g_free(buf);

    buf = xmlGetProp(xmlnode, PROP_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_size_rule: %s (%p)", g_strerror(errno), target);
    g_free(buf);
       
    rule = filter_new_size_rule(lower, upper, target, negate);
    rule->valid = FALSE;

    if (dbg >= 4);
        g_message( "added to filter \"%s\" rule with target %p",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}

static void xml_to_jump_rule(xmlNodePtr xmlnode, gpointer filter)
{
    gchar *buf;
    rule_t *rule;
    filter_t *target;

    g_assert(xmlnode != NULL);
    g_assert(xmlnode->name != NULL);
    g_assert(filter != NULL);
    g_assert(g_strcasecmp(xmlnode->name, NODE_RULE_JUMP) ==0);

    buf = xmlGetProp(xmlnode, PROP_RULE_TARGET);
    errno = 0;
    target = (gpointer) strtoul(buf, 0, 16);
    if (errno != 0)
        g_error( "xml_to_jump_rule: %s", g_strerror(errno));
    g_free(buf);
       
    rule = filter_new_jump_rule(target);
    rule->valid = FALSE;

    if (dbg >= 4)
        g_message( "added to filter \"%s\" rule with target %p",
            ((filter_t *)filter)->name, rule->target);

    ((filter_t *) filter)->ruleset =
        g_list_append(((filter_t *) filter)->ruleset, rule);
}
