/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

#include "gtk/filter.h"
#include "gtk/filter_core.h"
#include "gtk/search.h"
#include "gtk/search_result.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "if/core/search.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/**
 * If FILTER_HIDE_ON_CLOSE is defined, the filter dialog is only hidden
 * when the dialog is closed instead the of the dialog being destroyed.
 */
#define FILTER_HIDE_ON_CLOSE

typedef struct shadow {
    filter_t *filter;
    GList *current;
    GList *removed;
    GList *added;
    gint32 refcount;
    guint16 flags;
    guint32 match_count;
    guint32 fail_count;
} shadow_t;

#ifdef TRACK_MALLOC
typedef GList *filter_add_rule_func_t(GList *, gpointer, const char *, int);
#else
typedef GList *filter_add_rule_func_t(GList *, gpointer);
#endif

/**
 * Structure holding "global" variables during filtering.
 */
struct filter_context {
	const struct record *rec;		/* From the GUI */
	
	/*
	 * Cache for filtering: avoids recomputation at each filtering rule.
	 * Those variables are initialized as needed.
	 */

	const gchar *l_name;		/**< Lower-cased file name; atom */
	size_t l_len;				/**< Length of lower-cased representation */
	const gchar *utf8_name;		/**< Normalized UTF-8 version of name; atom */
	size_t utf8_len;			/**< Length of UTF-8 name representation */
};

/*
 * Private functions prototypes
 */
void filter_remove_rule(filter_t *f, rule_t *r);
static void filter_free(filter_t *f);

/**
 * Public variables.
 */
filter_t *work_filter;

/*
 * Private variables
 */
static GList *shadow_filters;
static GList *filters_added;
static GList *filters_removed;

/* built-in targets */
static filter_t *filter_drop;
static filter_t *filter_show;
static filter_t *filter_download;
static filter_t *filter_nodownload;
static filter_t *filter_return;

/* global filters */
static filter_t *filter_global_pre;
static filter_t *filter_global_post;

/* not static because needed in search_xml. */
GList *filters;
GList *filters_current;


/***
 *** Implementation
 ***/

#define WIDGET(name) \
static GtkWidget * name ## _protected_ ; \
 \
GtkWidget *gui_ ## name (void) \
{ \
	return name ## _protected_ ; \
} \
 \
void \
gui_ ## name ## _set (GtkWidget *w) \
{ \
	name ## _protected_ = w; \
} \
 \
GtkWidget * \
gui_ ## name ## _lookup(const gchar *id) \
{ \
	return lookup_widget(gui_ ## name (), id); \
}

WIDGET(filter_dialog)
WIDGET(popup_filter_rule)
#undef WIDGET

void
dump_ruleset(const GList *ruleset)
{
    const GList *r;
    gint i;

    for (r = ruleset, i = 0; r != NULL; r = g_list_next(r), i++)
        g_debug("       rule %3d : %s", i, filter_rule_to_string(r->data));
}

void
dump_filter(const filter_t *filter)
{
    g_assert(filter != NULL);
    g_debug(
		"Filter name     : %s\n"
		"       bound    : %p\n"
		"       refcount : %d",
		filter->name,
		cast_to_gconstpointer(filter->search),
		filter->refcount);
    dump_ruleset(filter->ruleset);
}

void
dump_shadow(const shadow_t *shadow)
{
    g_assert(shadow != NULL);
    g_debug(
		"Shadow for filt.: %s\n"
		"       bound    : %p\n"
		"       refcount : %d\n"
		"       flt. ref : %d\n"
		"  Added:",
		shadow->filter->name,
		cast_to_gconstpointer(shadow->filter->search),
		shadow->refcount,
		shadow->filter->refcount);

    dump_ruleset(shadow->added);
    g_debug("  Removed:");
    dump_ruleset(shadow->removed);
    g_debug("  Current:");
    dump_ruleset(shadow->current);
    g_debug("  Original:");
    dump_ruleset(shadow->filter->ruleset);
}



/**
 * Comparator function to match a shadow and a filter.
 */
static gint
shadow_filter_eq(gconstpointer a, gconstpointer b)
{
	return a == NULL || b == NULL || ((const shadow_t *) a)->filter != b;
}



/**
 * Get the shadow for the given filter. Returns NULL if the filter
 * does not have a shadow yet.
 */
static shadow_t *
shadow_find(filter_t *f)
{
    GList * l;

    g_assert(f != NULL);

    l = g_list_find_custom(shadow_filters, f, shadow_filter_eq);
    if (l != NULL) {
        if (GUI_PROPERTY(gui_debug) >= 6)
            g_debug("shadow found for: %s", f->name);
        return l->data;
    } else {
        if (GUI_PROPERTY(gui_debug) >= 6)
            g_debug("no shadow found for: %s", f->name);
        return NULL;
    }
}



/**
 * Creates a new shadow for a given filter and registers it with
 * our current shadow list.
 */
static shadow_t *
shadow_new(filter_t *f)
{
    shadow_t *shadow;

    g_assert(f != NULL);
    g_assert(f->name != NULL);

    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("creating shadow for: %s", f->name);

    WALLOC0(shadow);
    shadow->filter   = f;
    shadow->current  = g_list_copy(f->ruleset);
    shadow->added    = NULL;
    shadow->removed  = NULL;
    shadow->refcount = f->refcount;
    shadow->flags    = f->flags;

    shadow_filters = g_list_append(shadow_filters, shadow);

    return shadow;
}



/**
 * Forgets all about a given shadow and free's ressourcs for it.
 *
 * At this point we can no longer assume that the shadow->current
 * field contains a valid pointer. We may have been called to
 * clean up a shadow for a filter whose ruleset has already been
 * cleared. We don't clean up any memory that is owned by the
 * associated filter.
 */
static void
shadow_cancel(shadow_t *shadow)
{
    GList *r;

    g_assert(shadow != NULL);
    g_assert(shadow->filter != NULL);

    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("cancel shadow for filter: %s", shadow->filter->name);

    for (r = shadow->added; r != NULL; r = r->next)
        filter_free_rule(r->data);

    /*
     * Since we cancel the shadow, we also free the added,
     * removed and current lists now. Then we remove the shadow
     * kill it also.
     */
    gm_list_free_null(&shadow->removed);
    gm_list_free_null(&shadow->added);
    gm_list_free_null(&shadow->current);

    shadow_filters = g_list_remove(shadow_filters, shadow);
    WFREE(shadow);
}



/**
 * Commit all the changes for a given shadow and then forget and free
 * it.
 */
static void
shadow_commit(shadow_t *shadow)
{
    GList *f;
    filter_t *realf;

    g_assert(shadow != NULL);
    g_assert(shadow->filter != NULL);

    realf = shadow->filter;

    if (GUI_PROPERTY(gui_debug) >= 6) {
        g_debug("committing shadow for filter:");
        dump_shadow(shadow);
    }

    /*
     * Free memory for all removed rules
     */
    for (f = shadow->removed; f != NULL; f = f->next) {
        filter_free_rule(f->data);
	}
    /*
     * Remove the SHADOW flag from all new rules.
     */
    for (f = shadow->added; f != NULL; f = f->next) {
        rule_t *r = f->data;
		r->flags &= ~RULE_FLAG_SHADOW;
	}
    /*
     * We also free the memory of the filter->ruleset GList.
     * We don't need them anymore.
     */
    gm_list_free_null(&shadow->filter->ruleset);

    /*
     * Now the actual filter is corrupted, because
     * we have freed memory its rules.
     * But we have a copy of the ruleset without exactly those
     * rules we freed now. We use this as new ruleset.
     */
    shadow->filter->ruleset = shadow->current;

    /*
     * Not forgetting to update the refcount. There is a chance
     * that this shadow only existed because of a change in the
     * refcount.
     */
    shadow->filter->refcount = shadow->refcount;

    shadow->filter->flags = shadow->flags;

    /*
     * Now that we have actually commited the changes for this
     * shadow, we remove this shadow from our shadow list
     * and free it's ressources. Note that we do not free
     * shadow->current because this is the new filter ruleset.
     */
    gm_list_free_null(&shadow->added);
    gm_list_free_null(&shadow->removed);
    shadow->current = NULL;
    shadow->filter = NULL;
    shadow_filters = g_list_remove(shadow_filters, shadow);
    WFREE(shadow);

    if (GUI_PROPERTY(gui_debug) >= 6) {
        g_debug("after commit filter looks like this");
        dump_filter(realf);
    }
}



/**
 * Regenerates the filter tree and rules display from after a apply/revert.
 */
static void
filter_refresh_display(GList *filter_list)
{
    GList *l;

    filter_gui_freeze_filters();
    filter_gui_filter_clear_list();
    for (l = filter_list; l != NULL; l = l->next) {
        filter_t *filter = (filter_t *)l->data;
        shadow_t *shadow;
        GList *ruleset;
        gboolean enabled;

        shadow = shadow_find(filter);
        ruleset = (shadow != NULL) ? shadow->current : filter->ruleset;
        enabled = (shadow != NULL) ?
            filter_is_active(shadow) :
            filter_is_active(filter);

        filter_gui_filter_add(filter, ruleset);
        filter_gui_filter_set_enabled(filter, enabled);
    }
    filter_gui_thaw_filters();
}



/**
 * Open and initialize the filter dialog.
 */
void
filter_open_dialog(void)
{
    struct search *current_search;

    current_search = search_gui_get_current_search();

    if (gui_filter_dialog() == NULL) {
        gui_filter_dialog_set(filter_gui_create_dlg_filters());
        g_assert(gui_filter_dialog() != NULL);

        filter_gui_init();
        filter_refresh_display(filters_current);
    }

	if (current_search) {
    	filter_set(search_gui_get_filter(current_search));
	} else {
    	filter_set(NULL);
	}
    filter_gui_show_dialog();
}



/**
 * Close the filter dialog. If commit is TRUE the changes
 * are committed, otherwise dropped.
 */
void
filter_close_dialog(gboolean commit)
{
    if (commit) {
        filter_apply_changes();
		search_gui_store_searches();
    } else
        filter_revert_changes();

    if (gui_filter_dialog() != NULL) {
        gint32 coord[4] = {0, 0, 0, 0};

        gdk_window_get_root_origin(gui_filter_dialog()->window, &coord[0], &coord[1]);
        gdk_drawable_get_size(gui_filter_dialog()->window, &coord[2], &coord[3]);

        gui_prop_set_guint32(PROP_FILTER_DLG_COORDS, (guint32 *) coord, 0, 4);

        *(guint32 *) &GUI_PROPERTY(filter_main_divider_pos) =
            gtk_paned_get_position
                (GTK_PANED(gui_filter_dialog_lookup("hpaned_filter_main")));

#ifdef FILTER_HIDE_ON_CLOSE
        gtk_widget_hide(gui_filter_dialog());
#else
        gtk_object_destroy(GTK_OBJECT(gui_filter_dialog()));
        gui_filter_dialog() = NULL;
#endif /* FILTER_HIDE_ON_CLOSE */
    }
}



/**
 * returns a new rule created with information based on the given rule
 * with the appropriate filter_new_*_rule call. Defaults set by those
 * calls (like RULE_FLAG_VALID) will also apply to the the returned rule.
 */
rule_t *
filter_duplicate_rule(const rule_t *r)
{
    g_assert(r != NULL);

    switch (r->type) {
    case RULE_TEXT:
        return filter_new_text_rule(r->u.text.match, r->u.text.type,
					r->u.text.case_sensitive, r->target, r->flags);
    case RULE_IP:
        return filter_new_ip_rule(r->u.ip.addr, r->u.ip.cidr,
					r->target, r->flags);
    case RULE_SIZE:
        return filter_new_size_rule(r->u.size.lower, r->u.size.upper,
					r->target, r->flags);
    case RULE_JUMP:
        return filter_new_jump_rule(r->target, r->flags);
    case RULE_SHA1:
        return filter_new_sha1_rule(r->u.sha1.hash, r->u.sha1.filename,
					r->target, r->flags);
    case RULE_FLAG:
        return filter_new_flag_rule(r->u.flag.stable, r->u.flag.busy,
				r->u.flag.push, r->target, r->flags);
    case RULE_STATE:
        return filter_new_state_rule(r->u.state.display, r->u.state.download,
				r->target, r->flags);
    }

	g_error("filter_duplicate_rule: unknown rule type: %d", r->type);
	return NULL;
}



rule_t *
filter_new_text_rule(const gchar *match, gint type,
    gboolean case_sensitive, filter_t *target, guint16 flags)
{
  	rule_t *r;
	gchar *buf;

    g_assert(match != NULL);
    g_assert(target != NULL);
    g_assert(utf8_is_valid_string(match));

  	WALLOC0(r);
   	r->type                  = RULE_TEXT;
    r->flags                 = flags;
    r->target                = target;
    r->u.text.case_sensitive = case_sensitive;
    r->u.text.type           = type;
    r->flags |= RULE_FLAG_VALID;

    buf = r->u.text.case_sensitive
		? h_strdup(match)
		: utf8_strlower_copy(match);

	r->u.text.match = buf;
	r->u.text.match_len = strlen(buf);

    buf = h_strdup(r->u.text.match);

  	if (r->u.text.type == RULE_TEXT_WORDS) {
		gchar *s;
		GList *l = NULL;

		for (s = strtok(buf, " \t\n"); s; s = strtok(NULL, " \t\n"))
			l = g_list_prepend(l, pattern_compile(s));

		r->u.text.u.words = g_list_reverse(l);
	} else if (r->u.text.type == RULE_TEXT_REGEXP) {
		int err;
		regex_t *re;

		WALLOC0(re);
		err = regcomp(re, buf,
			REG_EXTENDED|REG_NOSUB|(r->u.text.case_sensitive ? 0 : REG_ICASE));

		if (err) {
			gchar regbuf[1000];

			regerror(err, re, regbuf, sizeof(regbuf));
			g_warning("problem in regular expression: %s"
				"; falling back to substring match", buf);

			r->u.text.type = RULE_TEXT_SUBSTR;
			regfree(re);
            WFREE(re);
		} else {
			r->u.text.u.re = re;
		}
	}

	/* no "else" because REGEXP can fall back here */
	if (r->u.text.type == RULE_TEXT_SUBSTR) {
		r->u.text.u.pattern = pattern_compile(buf);
	}
    hfree(buf);

    return r;
}



rule_t *
filter_new_ip_rule(const host_addr_t addr, guint8 cidr,
	filter_t *target, guint16 flags)
{
	rule_t *r;

    g_assert(target != NULL);

	WALLOC0(r);
   	r->type = RULE_IP;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:	cidr = MIN(cidr, 32); break;
	case NET_TYPE_IPV6:	cidr = MIN(cidr, 128); break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	r->u.ip.addr  = addr;
	r->u.ip.cidr  = cidr;
    r->target     = target;
    r->flags      = flags;
    r->flags |= RULE_FLAG_VALID;

    return r;
}



rule_t *
filter_new_size_rule(filesize_t lower, filesize_t upper,
	filter_t *target, guint16 flags)
{
   	rule_t *f;

    g_assert(target != NULL);

    WALLOC0(f);
    f->type = RULE_SIZE;

    if (lower > upper) {
        f->u.size.lower = upper;
        f->u.size.upper = lower;
    } else {
        f->u.size.lower = lower;
        f->u.size.upper = upper;
    }

  	f->target = target;
    f->flags  = flags;
    f->flags |= RULE_FLAG_VALID;

    return f;
}




rule_t *
filter_new_jump_rule(filter_t *target, guint16 flags)
{
   	rule_t *f;

    g_assert(target != NULL);

    WALLOC0(f);
    f->type = RULE_JUMP;

  	f->target = target;
    f->flags  = flags;
    f->flags |= RULE_FLAG_VALID;

    return f;
}




rule_t *
filter_new_sha1_rule(const struct sha1 *sha1, const gchar *filename,
	filter_t *target, guint16 flags)
{
   	rule_t *f;

    g_assert(target != NULL);
    g_assert(NULL == filename || utf8_is_valid_string(filename));

    WALLOC0(f);
    f->type = RULE_SHA1;

  	f->target = target;
    f->u.sha1.hash = sha1 != NULL ? atom_sha1_get(sha1) : NULL;
    f->u.sha1.filename = h_strdup(filename ? filename : "");
    f->flags = flags;
    f->flags |= RULE_FLAG_VALID;

    return f;
}



rule_t *
filter_new_flag_rule(enum rule_flag_action stable, enum rule_flag_action busy,
     enum rule_flag_action push, filter_t *target, guint16 flags)
{
   	rule_t *f;

    g_assert(target != NULL);

    WALLOC0(f);
    f->type = RULE_FLAG;

    f->u.flag.stable = stable;
    f->u.flag.busy = busy;
    f->u.flag.push = push;
  	f->target = target;
    f->flags  = flags;
    f->flags |= RULE_FLAG_VALID;

    return f;
}



rule_t *
filter_new_state_rule(enum filter_prop_state display,
	enum filter_prop_state download, filter_t *target, guint16 flags)
{
       	rule_t *f;

    g_assert(target != NULL);

    WALLOC0(f);
    f->type = RULE_STATE;

    f->u.state.display = display;
    f->u.state.download = download;
  	f->target = target;
    f->flags  = flags;
    f->flags |= RULE_FLAG_VALID;

    return f;
}



/**
 * Start working on the given filter. Set this filter as
 * work_filter so we can commit the changed rules to this
 * filter.
 */
void
filter_set(filter_t *f)
{
    if (f) {
        shadow_t *shadow;
        gboolean removable;
        gboolean active;
        GList *ruleset;

		removable = filter_is_modifiable(f) &&
			!filter_is_global(f) &&
			!filter_is_bound(f);

        shadow = shadow_find(f);
        if (shadow != NULL) {
            removable = removable && 0 == shadow->refcount;
            active = filter_is_active(shadow);
            ruleset = shadow->current;
        } else {
            removable = removable && 0 == f->refcount;
            active = filter_is_active(f);
            ruleset = f->ruleset;
        }

        filter_gui_filter_set(f, removable, active, ruleset);
    } else {
        filter_gui_filter_set(NULL, FALSE, FALSE, NULL);
    }

    /*
     * don't want the work_filter to be selectable as a target
     * so we changed it... we have to rebuild.
     */
    filter_update_targets();
}



/**
 * Clear the searches shadow, update the combobox and the filter
 * bound to this search (search->ruleset).
 */
void
filter_close_search(struct search *s)
{
    shadow_t *shadow;
	filter_t *filter;

	g_return_if_fail(s);
	filter = search_gui_get_filter(s);
	g_return_if_fail(filter);

    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("closing search (freeing filter): %s", search_gui_query(s));

    shadow = shadow_find(filter);
    if (shadow != NULL) {
		GList *copy;

		copy = g_list_copy(shadow->removed);
		G_LIST_FOREACH_SWAPPED(copy, filter_append_rule_to_session, filter);
        g_list_free(copy);

		copy = g_list_copy(shadow->added);
		G_LIST_FOREACH_SWAPPED(copy, filter_remove_rule_from_session, filter);
        g_list_free(copy);

        shadow_cancel(shadow);
    }

    /*
     * If this is the filter currently worked on, clear the display.
     */
    if (filter == work_filter) {
        filter_set(NULL);
	}
    filter_gui_filter_remove(filter);

    filter_free(filter);
	search_gui_set_filter(s, NULL);
}

/**
 * Go through all the shadow filters, and commit the recorded
 * changes to the associated filter. We walk through the
 * shadow->current list. Every item in shadow->removed will be
 * removed from the searchs filter and the memory will be freed.
 * Then shadow->current will be set as the new filter for that
 * search.
 */
void
filter_apply_changes(void)
{
    GList *iter;

	filter_adapt_order();

    /*
     * Free memory for all removed filters;
     */
    for (iter = shadow_filters; iter != NULL; iter = shadow_filters)
        shadow_commit(iter->data);

    g_list_free(filters);
    filters = g_list_copy(filters_current);

    /*
     * Remove the SHADOW flag from all added filters
     */
    for (iter = filters_added; iter != NULL; iter = g_list_next(iter)) {
		filter_t *f = iter->data;
        f->flags &= ~FILTER_FLAG_SHADOW;
	}

    g_list_free(filters_added);
    filters_added = NULL;

    /*
     * Free all removed filters. Don't iterate since filter_free removes
     * the filter from filters_removed.
     */
    for (iter = filters_removed; iter != NULL; iter = filters_removed) {
        filter_free(iter->data);
    }
    g_assert(filters_removed == NULL);

    filter_update_targets();
    filter_set(work_filter);
}



/**
 * Free the ressources for all added filters and forget all shadows.
 * A running session will not be ended by this.
 */
void
filter_revert_changes(void)
{
    GList *iter;

    if (GUI_PROPERTY(gui_debug) >= 5)
        g_debug("Canceling all changes to filters/rules");

    filter_gui_freeze_filters();
    filter_gui_freeze_rules();

    /*
     * Free memory for all added filters and for the shadows.
     */
    for (iter = shadow_filters; iter != NULL; iter = shadow_filters)
        shadow_cancel(iter->data);

    if (g_list_find(filters, work_filter) != NULL)
        filter_set(work_filter);
    else
        filter_set(NULL);

    g_list_free(filters_current);
    filters_current = g_list_copy(filters);

    /*
     * Free and remove all added filters. We don't iterate explicitly,
     * because filter_free removes the added filter from filters_added
     * for us.
     */
    for (iter = filters_added; iter != NULL; iter = filters_added) {
        filter_t *filter = iter->data;

        filter_gui_filter_remove(filter);
        filter_free(filter);
    }
    g_assert(filters_added == NULL);

    /*
     * Restore all removed filters.
     */
    for (iter = filters_removed; iter != NULL; iter = g_list_next(iter)) {
        filter_t *filter = iter->data;

        filter_gui_filter_add(filter, filter->ruleset);
    }
    gm_list_free_null(&filters_removed);

    /*
     * Update the rulecounts. Since we don't have any shadows anymore, we
     * can just use f->ruleset. Also update the 'enabled' state of the
     * filters while we are at it.
     */
    for (iter = filters_current; iter != NULL; iter = g_list_next(iter)) {
        filter_t *filter = iter->data;

        filter_gui_update_rule_count(filter, filter->ruleset);
        filter_gui_filter_set_enabled(filter, filter_is_active(filter));
    }

    filter_gui_thaw_rules();
    filter_gui_thaw_filters();

    filter_update_targets();
}

static const gchar *
filter_lazy_utf8_to_ui_string(const gchar *src)
{
	static gchar *prev;
	gchar *dst;

	g_assert(src);	
	g_assert(prev != src);

	dst = utf8_to_ui_string(src);
	G_FREE_NULL(prev);
	if (dst != src)
		prev = dst;
	return NOT_LEAKING(dst);
}

/**
 * Convert a rule condition to a human readable string.
 */
gchar *
filter_rule_condition_to_string(const rule_t *r)
{
    static gchar tmp[4096];

    g_assert(r != NULL);

    switch (r->type) {
    case RULE_TEXT:
		{
			const gchar *match, *cs;
			
			match = filter_lazy_utf8_to_ui_string(r->u.text.match);
			cs = r->u.text.case_sensitive ? _("(case-sensitive)") : "";
			
			switch (r->u.text.type) {
			case RULE_TEXT_PREFIX:
				str_bprintf(tmp, sizeof tmp,
					_("If filename begins with \"%s\" %s"), match, cs);
				break;
			case RULE_TEXT_WORDS:
				str_bprintf(tmp, sizeof tmp,
					_("If filename contains the words \"%s\" %s"), match, cs);
				break;
			case RULE_TEXT_SUFFIX:
				str_bprintf(tmp, sizeof tmp,
					_("If filename ends with \"%s\" %s"), match, cs);
				break;
			case RULE_TEXT_SUBSTR:
				str_bprintf(tmp, sizeof tmp,
					_("If filename contains the substring \"%s\" %s"),
					match, cs);
				break;
			case RULE_TEXT_REGEXP:
				str_bprintf(tmp, sizeof tmp,
					_("If filename matches the regex pattern \"%s\" %s"),
					match, cs);
				break;
			case RULE_TEXT_EXACT:
				str_bprintf(tmp, sizeof tmp, _("If filename is \"%s\" %s"),
					match, cs);
				break;
			default:
				g_error("filter_rule_condition_to_string:"
					"unknown text rule type: %d", r->u.text.type);
			}
		}
        break;
    case RULE_IP:
		str_bprintf(tmp, sizeof tmp, _("If IP address matches %s/%u"),
			host_addr_to_string(r->u.ip.addr), r->u.ip.cidr);
        break;
    case RULE_SIZE:
		if (r->u.size.upper == r->u.size.lower) {
            gchar smax_64[UINT64_DEC_BUFLEN];

			uint64_to_string_buf(r->u.size.upper, smax_64, sizeof smax_64);
			str_bprintf(tmp, sizeof tmp , _("If filesize is exactly %s (%s)"),
				smax_64,
				short_size(r->u.size.upper, show_metric_units()));
		} else if (r->u.size.lower == 0) {
            gchar smax_64[UINT64_DEC_BUFLEN];

			uint64_to_string_buf(r->u.size.upper + 1, smax_64, sizeof smax_64);
			str_bprintf(tmp, sizeof tmp,
				_("If filesize is smaller than %s (%s)"),
				smax_64,
				short_size(r->u.size.upper + 1, show_metric_units()));
		} else {
            gchar smin[256], smax[256];
            gchar smin_64[UINT64_DEC_BUFLEN], smax_64[UINT64_DEC_BUFLEN];

            g_strlcpy(smin,
				short_size(r->u.size.lower, show_metric_units()),
				sizeof smin);
            g_strlcpy(smax,
				short_size(r->u.size.upper, show_metric_units()),
				sizeof smax);
			uint64_to_string_buf(r->u.size.lower, smin_64, sizeof smin_64);
			uint64_to_string_buf(r->u.size.upper, smax_64, sizeof smax_64);

			str_bprintf(tmp, sizeof tmp,
				_("If filesize is between %s and %s (%s - %s)"),
				smin_64, smax_64, smin, smax);
        }
        break;
    case RULE_SHA1:
        if (r->u.sha1.hash != NULL) {
            str_bprintf(tmp, sizeof tmp,
				_("If urn:sha1 is same as for \"%s\""),
				filter_lazy_utf8_to_ui_string(r->u.sha1.filename));
        } else {
            str_bprintf(tmp, sizeof tmp, "%s",
				_("If urn:sha1 is not available"));
		}
        break;
    case RULE_JUMP:
       	str_bprintf(tmp, sizeof tmp, "%s", _("Always"));
        break;
    case RULE_FLAG:
        {
            const gchar *busy_str = "";
            const gchar *push_str = "";
            const gchar *stable_str = "";
            const gchar *s1 = "";
            const gchar *s2 = "";
            gboolean b = FALSE;

            switch (r->u.flag.busy) {
            case RULE_FLAG_SET:
                busy_str = _("busy is set");
                b = TRUE;
                break;
            case RULE_FLAG_UNSET:
                busy_str = _("busy is not set");
                b = TRUE;
                break;
            case RULE_FLAG_IGNORE:
                break;
            }

            switch (r->u.flag.push) {
            case RULE_FLAG_SET:
                if (b) s1 = ", ";
                push_str = _("push is set");
                b = TRUE;
                break;
            case RULE_FLAG_UNSET:
                if (b) s1 = ", ";
                push_str = _("push is not set");
                b = TRUE;
                break;
            case RULE_FLAG_IGNORE:
                break;
            }

            switch (r->u.flag.stable) {
            case RULE_FLAG_SET:
                if (b) s2 = ", ";
                stable_str = _("stable is set");
                b = TRUE;
                break;
            case RULE_FLAG_UNSET:
                if (b) s2 = ", ";
                stable_str = _("stable is not set");
                b = TRUE;
                break;
            case RULE_FLAG_IGNORE:
                break;
            }

            if (b) {
                str_bprintf(tmp, sizeof tmp, _("If flag %s%s%s%s%s"),
                    busy_str, s1, push_str, s2, stable_str);
			} else {
                 str_bprintf(tmp, sizeof tmp, "%s",
					_("Always (all flags ignored)"));
			}
        }
        break;
    case RULE_STATE:
        {
            const gchar *display_str = "";
            const gchar *download_str = "";
            const gchar *s1 = "";
            gboolean b = FALSE;

            switch (r->u.state.display) {
            case FILTER_PROP_STATE_UNKNOWN:
                display_str = _("DISPLAY is undefined");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_DO:
                display_str = _("DISPLAY");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_DONT:
                display_str = _("DON'T DISPLAY");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_IGNORE:
                break;
            default:
                g_assert_not_reached();
            }

            switch (r->u.state.download) {
            case FILTER_PROP_STATE_UNKNOWN:
                if (b) s1 = ", ";
                download_str = _("DOWNLOAD is undefined");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_DO:
                if (b) s1 = ", ";
                download_str = _("DOWNLOAD");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_DONT:
                if (b) s1 = ", ";
                download_str = _("DON'T DOWNLOAD");
                b = TRUE;
                break;
            case FILTER_PROP_STATE_IGNORE:
                break;
            default:
                g_assert_not_reached();
            }

            if (b) {
                str_bprintf(tmp, sizeof tmp , _("If flag %s%s%s"),
                    display_str, s1, download_str);
			} else {
	             str_bprintf(tmp, sizeof tmp, "%s",
					_("Always (all states ignored)"));
			}
        }
        break;
    default:
        g_error("filter_rule_condition_to_string: unknown rule type: %d",
			r->type);
        return NULL;
    }

    return tmp;
}



/**
 * Convert the filter to a human readable string.
 */
gchar *
filter_rule_to_string(const rule_t *r)
{
	static gchar tmp[4096];

    g_assert(r != NULL);

	str_bprintf(tmp, sizeof tmp, _("%s%s %s jump to \"%s\""),
        RULE_IS_NEGATED(r) ? _("(Negated) ") : "",
        RULE_IS_ACTIVE(r) ? "" : _("(deactivated)"),
        filter_rule_condition_to_string(r),
        RULE_IS_VALID(r) ? r->target->name : _("(invalid)"));

    return tmp;
}



/**
 * Create a new filter with the given name.
 *
 * @param name	The name for the filter; must be UTF-8 encoded; the string
 *				will be copied.
 *
 * @return an initialized filter context.
 */
filter_t *
filter_new(const gchar *name)
{
    filter_t *f;

    g_assert(name);
    g_assert(utf8_is_valid_string(name));

    WALLOC0(f);
    f->name = atom_str_get(name);
    f->ruleset = NULL;
    f->search = NULL;
    f->visited = FALSE;
    f->flags |= FILTER_FLAG_ACTIVE;

    return f;
}



/**
 * Add a filter to the current editing session. Never try to add
 * a filter twice. Returns a error code on failure and 0 on success.
 */
void
filter_add_to_session(filter_t *f)
{
    g_assert(g_list_find(filters_current, f) == NULL);
    g_assert(f != NULL);


    /*
     * Either remove from removed or add to added list.
     */
    if (g_list_find(filters_removed, f) != NULL)
        filters_removed = g_list_remove(filters_removed, f);
    else {
        filters_added = g_list_append(filters_added, f);

        /*
         * Since the filter is new and not yet used for filtering
         * we set the FILTER_FLAG_SHADOW flag.
         */
        f->flags |= FILTER_FLAG_SHADOW;
    }

    filters_current = g_list_append(filters_current, f);

    filter_gui_filter_add(f, f->ruleset);
}



/**
 * Create a new filter bound to a search and register it.
 */
void
filter_new_for_search(struct search *s)
{
	const gchar *query;
    filter_t *f;

    g_assert(s != NULL);

	query = search_gui_query(s);
    g_assert(query);
    g_assert(utf8_is_valid_string(query));

    WALLOC0(f);
    f->name = atom_str_get(query);
    f->ruleset = NULL;
    f->search = NULL;
    f->visited = FALSE;
    f->flags |= FILTER_FLAG_ACTIVE;

    /*
     * Add filter to current and session lists
     */
    filters = g_list_append(filters, f);
    filters_current = g_list_append(filters_current, f);

    /*
     * Crosslink filter and search
     */
    f->search = s;
	search_gui_set_filter(s, f);

    /*
     * It's important to add the filter here, because it was not
     * bound before and would have been sorted in as a free filter.
     */
    filter_gui_filter_add(f, f->ruleset);
}



/**
 * Mark the given filter as removed and delete it when the
 * dialog changes are committed.
 */
void
filter_remove_from_session(filter_t *f)
{
    g_assert(g_list_find(filters_removed, f) == NULL);
    g_assert(g_list_find(filters_current, f) != NULL);

    /*
     * Either remove from added list or add to removed list.
     */
    if (g_list_find(filters_added, f) != NULL)
        filters_added = g_list_remove(filters_added, f);
    else
        filters_removed = g_list_append(filters_removed, f);

    filters_current = g_list_remove(filters_current, f);

    /*
     * If this is the filter currently worked on, clear the display.
     */
    if (work_filter == f)
        filter_set(NULL);

    filter_gui_filter_remove(f);
}



/**
 * Frees a filter and the filters assiciated with it and
 * unregisters it from current and session filter lists.
 */
static void
filter_free(filter_t *f)
{
    GList *copy;

    g_assert(f != NULL);

    if (shadow_find(f) != NULL)
        g_error("Unable to free shadowed filter \"%s\" with refcount %d",
            f->name, f->refcount);

    if (f->refcount != 0)
        g_error("Unable to free referenced filter \"%s\" with refcount %d",
            f->name, f->refcount);

    /*
     * Remove the filter from current and session data
     */
    if (g_list_find(filters, f) != NULL)
        filters = g_list_remove(filters, f);
    if (g_list_find(filters_current, f) != NULL)
        filters_current = g_list_remove(filters_current, f);
    if (g_list_find(filters_added, f) != NULL)
        filters_added = g_list_remove(filters_added, f);
    if (g_list_find(filters_removed, f) != NULL)
        filters_removed = g_list_remove(filters_removed, f);

	copy = g_list_copy(f->ruleset);
	G_LIST_FOREACH_SWAPPED(copy, filter_remove_rule, f);
    g_list_free(copy);

    atom_str_free_null(&f->name);
    WFREE(f);
}

/**
 * Free memory reserved by rule respecting the type of the rule.
 */
void
filter_free_rule(rule_t *r)
{
    g_assert(r != NULL);

    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("freeing rule: %s", filter_rule_to_string(r));

    switch (r->type) {
    case RULE_TEXT:
        HFREE_NULL(r->u.text.match);

        switch (r->u.text.type) {
        case RULE_TEXT_WORDS:
            g_list_foreach(r->u.text.u.words, (GFunc)pattern_free, NULL);
            gm_list_free_null(&r->u.text.u.words);
            break;
        case RULE_TEXT_SUBSTR:
            pattern_free(r->u.text.u.pattern);
            r->u.text.u.pattern = NULL;
            break;
        case RULE_TEXT_REGEXP:
            regfree(r->u.text.u.re);
            WFREE(r->u.text.u.re);
			r->u.text.u.re = NULL;
            break;
        case RULE_TEXT_PREFIX:
        case RULE_TEXT_SUFFIX:
        case RULE_TEXT_EXACT:
            break;
        default:
            g_error("filter_free_rule: unknown text rule type: %d",
				r->u.text.type);
        }
        break;
    case RULE_SHA1:
        atom_sha1_free_null(&r->u.sha1.hash);
        HFREE_NULL(r->u.sha1.filename);
        break;
    case RULE_SIZE:
    case RULE_JUMP:
    case RULE_IP:
    case RULE_FLAG:
    case RULE_STATE:
        break;
    default:
        g_error("filter_free_rule: unknown rule type: %d", r->type);
    }
	WFREE(r);
}



/**
 * Add a new rule to a filter. If necessary also update the shadow.
 * The addition of the rule cannot be cancelled by canceling the
 * shadow. If no shadow for the filters exists, none is created.
 */
void
filter_add_rule(filter_t *f, rule_t * const r, filter_add_rule_func_t func)
{
    shadow_t *shadow;
    shadow_t *target_shadow;

    g_assert(f != NULL);
    g_assert(r != NULL);
    g_assert(func);
    g_assert(r->target != NULL);

    shadow = shadow_find(f);
    target_shadow = shadow_find(r->target);

    if (g_list_find(f->ruleset, r) != NULL)
        g_error("rule already exists in filter \"%s\"", f->name);

    if ((shadow != NULL) && g_list_find(shadow->current, r))
        g_error("rule already exists in shadow for filter \"%s\"",
            f->name);

    /*
     * We add the rule to the filter increase the refcount on the target.
     */

#ifdef TRACK_MALLOC
    f->ruleset = (*func)(f->ruleset, r, _WHERE_, __LINE__);
#else
    f->ruleset = (*func)(f->ruleset, r);
#endif
    r->target->refcount ++;
    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("increased refcount on \"%s\" to %d",
            r->target->name, r->target->refcount);

    /*
     * If a shadow for our filter exists, we add it there also.
     */
    if (shadow != NULL) {
#ifdef TRACK_MALLOC
        shadow->current = (*func)(shadow->current, r, _WHERE_, __LINE__);
#else
        shadow->current = (*func)(shadow->current, r);
#endif
	}

    /*
     * If a shadow for the target exists, we increase refcount there too.
     */
    if (target_shadow != NULL) {
        target_shadow->refcount ++;

        if (GUI_PROPERTY(gui_debug) >= 6)
            g_debug("increased refcount on shadow of \"%s\" to %d",
                target_shadow->filter->name, target_shadow->refcount);
    }

    /*
     * Update dialog if necessary.
     */
    {
        GList *ruleset;

        ruleset = (shadow != NULL) ? shadow->current : f->ruleset;

        if (work_filter == f)
            filter_gui_set_ruleset(ruleset);
        filter_gui_update_rule_count(f, ruleset);
    }
}

/**
 * Append a new rule to a filter. If necessary also update the shadow.
 */
void
filter_append_rule(filter_t *f, rule_t * const r)
{
#ifdef TRACK_MALLOC
  filter_add_rule(f, r, track_list_append);
#else
  filter_add_rule(f, r, g_list_append);
#endif
}

/**
 * Prepend a new rule to a filter. If necessary also update the shadow.
 */
void
filter_prepend_rule(filter_t *f, rule_t * const r)
{
#ifdef TRACK_MALLOC
  filter_add_rule(f, r, track_list_prepend);
#else
  filter_add_rule(f, r, g_list_prepend);
#endif
}

/**
 * Append a new rule to the filter shadow. This call will fail
 * with an assertion error if the rule is already existing in
 * the shadow.
 */
void
filter_append_rule_to_session(filter_t *f, rule_t * const r)
{
    shadow_t *shadow = NULL;
    shadow_t *target_shadow = NULL;

    g_assert(r != NULL);
    g_assert(f != NULL);
    g_assert(r->target != NULL);

    if (GUI_PROPERTY(gui_debug) >= 4)
        g_debug("appending rule to filter: %s <- %s (%p)",
            f->name, filter_rule_to_string(r),
			cast_to_gconstpointer(r->target));

    /*
     * The rule is added to a session, so we set the shadow flag.
     */
    r->flags |= RULE_FLAG_SHADOW;

    /*
     * Create a new shadow if necessary.
     */
    shadow = shadow_find(f);
    if (shadow == NULL)
        shadow = shadow_new(f);
    else {
        /*
         * You can never add a filter to a shadow or filter
         * twice!
         */
        g_assert(g_list_find(shadow->current, r) == NULL);
    }

    if (g_list_find(shadow->removed, r) == NULL) {
        shadow->added = g_list_append(shadow->added, r);
    } else {
        shadow->removed = g_list_remove(shadow->removed, r);
    }
    shadow->current = g_list_append(shadow->current, r);

    /*
     * We need to increase the refcount on the target.
     */
    target_shadow = shadow_find(r->target);
    if (target_shadow == NULL)
        target_shadow = shadow_new(r->target);

    target_shadow->refcount ++;
    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("increased refcount on shadow of \"%s\" to %d",
            target_shadow->filter->name, target_shadow->refcount);

    /*
     * Update dialog if necessary.
     */
    if (work_filter == f)
        filter_gui_set_ruleset(shadow->current);
    filter_gui_update_rule_count(f, shadow->current);
}



/**
 * Removes a rule directly. The removal cannot be reversed by
 * cancelling the shadow. The filter is removed from the active
 * filter and from a potentially existing shadow as well.
 * If no shadow exists, no shadow is created.
 */
void
filter_remove_rule(filter_t *f, rule_t *r)
{
    shadow_t *shadow;
    shadow_t *target_shadow;
    gboolean in_shadow_current;
    gboolean in_shadow_removed;
    gboolean in_filter;

    g_assert(f != NULL);
    g_assert(r != NULL);
    g_assert(r->target != NULL);

    shadow = shadow_find(f);
    target_shadow = shadow_find(r->target);

    in_filter = g_list_find(f->ruleset, r) != NULL;

    /*
     * We need to check where the rule is actually located... in the
     * shadow, in the real filter or in both.
     */
    if (shadow != NULL) {
        in_shadow_current = g_list_find(shadow->current, r) != NULL;
        in_shadow_removed = g_list_find(shadow->removed, r) != NULL;
    } else {
        /*
         * If there is no shadow, we pretend that the shadow is
         * equal to the filter, so we set in_shadow_current to in_filter.
         */
        in_shadow_current = in_filter;
        in_shadow_removed = FALSE;
    }

    /*
     * We have to purge the rule from the shadow where necessary.
     */
    if (in_shadow_current && (shadow != NULL)) {
        shadow->current = g_list_remove(shadow->current, r);
        shadow->added = g_list_remove(shadow->added, r);
    }

    if (in_shadow_removed && (shadow != NULL))
       shadow->removed = g_list_remove(shadow->removed, r);

    if (in_filter)
        f->ruleset = g_list_remove(f->ruleset, r);

    /*
     * Now we need to clean up the refcounts that may have been
     * caused by this rule. We have these possibilities:
     *
     *   in    in shadow   in shadow  in shadow   |   refcounted in
     * filter   current      added     removed    |  filter | shadow
     * ------------------------------------------------------------
     *   yes     yes          yes        yes      |   - failure A -
     *   yes     yes          yes        no       |   - failure C -
     *   yes     yes          no         yes      |   - failure D -
     * 1 yes     yes          no         no       |   yes       yes
     *   yes     no           yes        yes      |   - failure A -
     *   yes     no           yes        no       |   - failure B -
     * 2 yes     no           no         yes      |   yes       no
     *   yes     no           no         no       |   - failure E -
     *   no      yes          yes        yes      |   - failure A -
     * 3 no      yes          yes        no       |   no        yes
     *   no      yes          no         yes      |   - failure D -
     *   no      yes          no         no       |   - failure F -
     *   no      no           yes        yes      |   - failure A -
     *   no      no           yes        no       |   - failure B -
     *   no      no           no         yes      |   - failure G -
     * 4 no      no           no         no       |   no        no
     *
     * Possibilities:
     * 1) the rule has been there when the shadow was created and
     *    has not been removed since then. (Or has been removed and
          added back)
     * 2) the rule has been there when the shadow was created, but
     *    was removed from the shadow. The target shadow already
     *    knows that so we only need to remove from the target filter
     *    to bring the target shadow and the target filter in sync.
     * 3) the rule was added during the session. When it was added
     *    a shadow for the target has also been created to increase
     *    the refcount on that. We don't know wether the shadow contains
     *    other changes, but we must reduce the refcount on that shadow.
     * 4) the rule is neither in the shadow nor in the filter, we
     *    issue a warning and do nothing.
     *
     * Failures:
     * A) a rule can never be in shadow->added and shadow->removed at
     *    the same time.
     * B) a rule cannot be in added but not in current
     * C) a rule can't be added if it was already in the original filter
     * D) a rule can't be in current and also in removed
     * E) if a rule is in the original filter but not in current it
     *    must have been removed
     * F) if the rule is in current but not in the original filter, it
     *    must have been added.
     * G) if a rule is in removed, it must have been in the original
     *    filter.
     */
    if (in_filter) {
        r->target->refcount --;

        if (GUI_PROPERTY(gui_debug) >= 6)
            g_debug("decreased refcount on \"%s\" to %d",
                r->target->name, r->target->refcount);
    }

    if (in_shadow_current) {
        if (target_shadow != NULL) {
            target_shadow->refcount --;

            if (GUI_PROPERTY(gui_debug) >= 6)
                g_debug("decreased refcount on shadow of \"%s\" to %d",
                    target_shadow->filter->name, target_shadow->refcount);
        }
    }

    if (!in_filter && !in_shadow_current) {
        g_warning("rule unknown in context: aborting removal without freeing");
        return;
    }

    filter_free_rule(r);

    /*
     * Update dialog if necessary.
     */
     {
        GList *ruleset;

        ruleset = (shadow != NULL) ? shadow->current : f->ruleset;

        if (work_filter == f)
            filter_gui_set_ruleset(ruleset);
        filter_gui_update_rule_count(f, ruleset);
    }
}


/**
 * Remove rule from a filter shadow. This call will fail
 * with an assertion error if the rule has already been
 * removed from the shadow or if it never was in the shadow.
 * The memory associated with the rule will be freed.
 */
void
filter_remove_rule_from_session(filter_t *f, rule_t * const r)
{
    shadow_t *shadow;
    shadow_t *target_shadow;
    GList *l = NULL;

    g_assert(r != NULL);
    g_assert(f != NULL);

    if (GUI_PROPERTY(gui_debug) >= 4)
        g_debug("removing rule in filter: %s -> %s",
            f->name, filter_rule_to_string(r));

    /*
     * Create a new shadow if necessary.
     */
    shadow = shadow_find(f);
    if (shadow == NULL)
        shadow = shadow_new(f);

    g_assert(g_list_find(shadow->current, r) != NULL);

    shadow->current = g_list_remove(shadow->current, r);

    /*
     * We need to decrease the refcount on the target. We need to do this
     * now because soon the rule may be freed and we may not access it
     * after that.
     */
    target_shadow = shadow_find(r->target);
    if (target_shadow == NULL)
        target_shadow = shadow_new(r->target);

    target_shadow->refcount --;
    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("decreased refcount on shadow of \"%s\" to %d",
            target_shadow->filter->name, target_shadow->refcount);

    l = g_list_find(shadow->added, r);
    if (l != NULL) {
        /*
         * The rule was added only to the shadow and was
         * not committed. We removed it from the added list
         * and free the ressources.
         */
        if (GUI_PROPERTY(gui_debug) >= 4)
            g_debug("while removing from %s: removing from added: %s",
                f->name, filter_rule_to_string(r));
        shadow->added = g_list_remove(shadow->added, r);
        filter_free_rule(r);
    } else {
        /*
         * The rule was not added, so it must be existent.
         * If it is, we remember it on shadow->removed.
         */
        g_assert(g_list_find(shadow->removed, r) == NULL);

        if (GUI_PROPERTY(gui_debug) >= 4)
            g_debug("while removing from %s: adding to removed: %s",
                f->name, filter_rule_to_string(r));

        shadow->removed = g_list_append(shadow->removed, r);
    }

    /*
     * Update dialog if necessary.
     */
    if (work_filter == f)
        filter_gui_set_ruleset(shadow->current);
    filter_gui_update_rule_count(f, shadow->current);
}



/**
 * Replaces filter rule A with filter rule B in filter . A
 * must already be in the shadow and B must not!
 *
 * CAUTION: ACTUALLY B MUST NOT BE IN ANY OTHER SEARCH !!!
 *
 * The memory for A is freed in the process.
 */
void
filter_replace_rule_in_session(filter_t *f,
    rule_t * const old_rule, rule_t * const new_rule)
{
    GList *filter;
    GList *added;
    shadow_t *shadow;
    shadow_t *target_shadow;

    g_assert(old_rule != new_rule);
    g_assert(old_rule != NULL);
    g_assert(new_rule != NULL);

    /*
     * Create a new shadow if necessary.
     */
    shadow = shadow_find(f);
    if (shadow == NULL)
        shadow = shadow_new(f);

    /*
     * Find the list node where we have to replace the
     * rule.
     */
    filter = g_list_find(shadow->current, old_rule);
    g_assert(filter != NULL);

    if (GUI_PROPERTY(gui_debug) >= 4) {
        gchar f1[4096];
		const gchar *f2;

		g_strlcpy(f1, filter_rule_to_string(old_rule), sizeof f1);
        f2 = filter_rule_to_string(new_rule);

        g_debug("replacing rules (old <- new): %s <- %s", f1, f2);
    }

    /*
     * In any case we have to reduce the refcount on the old rule's
     * target.
     */
    target_shadow = shadow_find(old_rule->target);
    if (target_shadow == NULL)
        target_shadow = shadow_new(old_rule->target);

    target_shadow->refcount --;
    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("decreased refcount on shadow of \"%s\" to %d",
            target_shadow->filter->name, target_shadow->refcount);

    /*
     * Find wether the node to be replaced is in shadow->added.
     * If so, we may free the memory of the old rule.
     */
    added = g_list_find(shadow->added, old_rule);

    if (added != NULL) {
        /*
         * If it was added, then free and remove the rule.
         */
        shadow->added = g_list_remove(shadow->added, old_rule);
        filter_free_rule(old_rule);
    } else {
        /*
         * If the filter was not added, then it must be marked
         * for begin removed.
         */
        shadow->removed = g_list_append(shadow->removed, old_rule);
    }

    /*
     * The new rule can't be in the original filter, so we mark it
     * as added.
     */
    shadow->added = g_list_append(shadow->added, new_rule);
    new_rule->flags |= RULE_FLAG_SHADOW;

    /*
     * And we also need to increase the refcount on the new rule's
     * target
     */
    target_shadow = shadow_find(new_rule->target);
    if (target_shadow == NULL)
        target_shadow = shadow_new(new_rule->target);

    target_shadow->refcount ++;
    if (GUI_PROPERTY(gui_debug) >= 6)
        g_debug("increased refcount on shadow of \"%s\" to %d",
            target_shadow->filter->name, target_shadow->refcount);

    /*
     * In shadow->current we just replace the rule.
     */
    filter->data = new_rule;

    /*
     * Update dialog if necessary.
     */
    if (work_filter == f)
        filter_gui_set_ruleset(shadow->current);
}

#ifdef USE_GTK2
static gboolean
filter_adapt_order_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer list_ptr)
{
	GList **list = list_ptr;
	gpointer p;
	
	(void) unused_path;
	
   	gtk_tree_model_get(model, iter, 0, &p, (-1));
	if (p)
        *list = g_list_prepend(*list, p);
	
	return FALSE; /* continue traversal */
}
#endif /* USE_GTK2 */


/**
 * Reorders the filter according to the order in the user's
 * table in the gui. This should only be used after the
 * user has reordered the table. It cannot properly cope
 * with added or deleted items. This will also only work
 * if a filter is currently being displayed in the table.
 * If the filter dialog has not been initialized or not
 * filter is currently worked on, it will silently fail.
 */
void
filter_adapt_order(void)
#ifdef USE_GTK1
{
    GList *neworder = NULL;
    gint row;
    shadow_t *shadow;
    GtkCList *clist;

    if (!work_filter || gui_filter_dialog() == NULL)
        return;

    clist = GTK_CLIST(gui_filter_dialog_lookup("clist_filter_rules"));

    /*
     * Create a new shadow if necessary.
     */
    shadow = shadow_find(work_filter);
    if (shadow == NULL)
        shadow = shadow_new(work_filter);

    /*
     * Assumption: every rule in shadow->current is also
     * bound to a row in the filter table. So we can free
     * this list and rebuild it in the right order from the
     * row data.
     */
    g_list_free(shadow->current);

    for (row = 0; row < clist->rows; row ++) {
        filter_t *f;

        f = gtk_clist_get_row_data(clist, row);
        g_assert(f != NULL);

        neworder = g_list_append(neworder, f);
    }

    shadow->current = neworder;
}
#endif /* USE_GTK1 */
#ifdef USE_GTK2
{
    GList *new_order = NULL;
    shadow_t *shadow;
    GtkTreeView *tv;
	GtkTreeModel *model;

    if (!work_filter || gui_filter_dialog() == NULL)
        return;

    tv = GTK_TREE_VIEW(gui_filter_dialog_lookup("treeview_filter_rules"));
	model = gtk_tree_view_get_model(tv);

    /*
     * Create a new shadow if necessary.
     */
    shadow = shadow_find(work_filter);
    if (shadow == NULL)
        shadow = shadow_new(work_filter);

    /*
     * Assumption: every rule in shadow->current is also
     * bound to a row in the filter table. So we can free
     * this list and rebuild it in the right order from the
     * row data.
     */
    g_list_free(shadow->current);

	gtk_tree_model_foreach(model, filter_adapt_order_helper, &new_order);
    shadow->current = g_list_reverse(new_order);
}
#endif /* USE_GTK2 */


#define MATCH_RULE(filter, r, res)									\
do {																\
    (res)->props_set++;												\
    (r)->match_count++;												\
    (prop_count)++;													\
    (r)->target->match_count++;										\
    if (GUI_PROPERTY(gui_debug) >= 10)											\
        g_debug("matched rule: %s", filter_rule_to_string((r)));	\
} while (0)

/**
 * returns the number of properties set with this filter chain.
 * a property which was already set is not set again. The res
 * argument is changed depending on the rules that match.
 */
static int
filter_apply(filter_t *filter, struct filter_context *ctx, filter_result_t *res)
{
    GList *list;
    gint prop_count = 0;
    gboolean do_abort = FALSE;
	const struct record *rec;

    g_assert(filter != NULL);
    g_assert(ctx != NULL);
	rec = ctx->rec;
	record_check(rec);
    g_assert(res != NULL);

    /*
     * We only try to prevent circles or the filter is inactive.
     */

    if (filter->visited || !filter_is_active(filter))
        return 0;

    filter->visited = TRUE;

    list = filter->ruleset;

	list = g_list_first(list);
	while (list != NULL && res->props_set < MAX_FILTER_PROP && !do_abort) {
        gboolean match = FALSE;
		rule_t *r;
		gint i;

        r = list->data;
        if (GUI_PROPERTY(gui_debug) >= 10)
            g_debug("trying to match against: %s", filter_rule_to_string(r));

        if (RULE_IS_ACTIVE(r)) {
            switch (r->type){
            case RULE_JUMP:
                match = TRUE;
                break;
            case RULE_TEXT: {
				const gchar *l_name = ctx->l_name;
				const gchar *utf8_name = ctx->utf8_name;

				if (utf8_name == NULL) {
					ctx->utf8_name = utf8_name = atom_str_get(rec->utf8_name);
					ctx->utf8_len = strlen(utf8_name);
				}

				if (l_name == NULL) {
					gchar *s = utf8_strlower_copy(utf8_name);

					/*
					 * Cache for further rules, to avoid costly utf8
					 * lowercasing transformation for each text-matching
					 * rule they have configured.
					 */

					ctx->l_name = atom_str_get(s);
					ctx->l_len = strlen(ctx->l_name);
					l_name = ctx->l_name;

					hfree(s);
				}

                switch (r->u.text.type) {
                case RULE_TEXT_EXACT:
                    if (
						0 == strcmp(r->u.text.case_sensitive ?
							ctx->utf8_name : ctx->l_name, r->u.text.match)
					)
                        match = TRUE;
                    break;
                case RULE_TEXT_PREFIX:
                    if (
						0 == strncmp(r->u.text.case_sensitive ?
							ctx->utf8_name : ctx->l_name,
							r->u.text.match, r->u.text.match_len)
					)
                        match = TRUE;
                    break;
                case RULE_TEXT_WORDS:	/* Contains ALL the words */
                    {
                        GList *iter;
						gboolean failed = FALSE;

                        for (
                            iter = g_list_first(r->u.text.u.words);
                            iter && !failed;
                            iter = g_list_next(iter)
                        ) {
                            if (
								NULL == pattern_qsearch(iter->data,
									r->u.text.case_sensitive ?
										ctx->utf8_name : ctx->l_name,
									0, 0, qs_any)
							)
                                failed = TRUE;
                        }

						match = !failed;
                    }
                    break;
                case RULE_TEXT_SUFFIX: {
					size_t namelen = r->u.text.case_sensitive ?
						ctx->utf8_len : ctx->l_len;
					size_t n;
                    n = r->u.text.match_len;
					/* FIXME: > is WRONG, isn't that OBVIOUS?!!?!*/
                    if (namelen > n
                        && strcmp((r->u.text.case_sensitive
                               ? utf8_name : l_name) + namelen
                              - n, r->u.text.match) == 0)
                        match = TRUE;
				   }
                    break;
                case RULE_TEXT_SUBSTR:
                    if (
						NULL != pattern_qsearch(
							r->u.text.u.pattern,
							r->u.text.case_sensitive ?
								ctx->utf8_name : ctx->l_name,
							0, 0, qs_any)
					)
                        match = TRUE;
                    break;
                case RULE_TEXT_REGEXP:
                    if (
						0 == (i = regexec(r->u.text.u.re,
							r->u.text.case_sensitive ?
								ctx->utf8_name : ctx->l_name, 0, NULL, 0))
					)
                        match = TRUE;
                    if (i == REG_ESPACE)
                        g_warning("%s(): regexp memory overflow", G_STRFUNC);
                    break;
                default:
                    g_error("%s(): unknown text rule type: %d",
						G_STRFUNC, r->u.text.type);
                }
                break;
			}
            case RULE_IP:
				match = host_addr_matches(rec->results_set->addr,
							r->u.ip.addr, r->u.ip.cidr);
                break;
            case RULE_SIZE:
                if (rec->size >= r->u.size.lower &&
                    rec->size <= r->u.size.upper)
                    match = TRUE;
                break;
            case RULE_SHA1:
                if (rec->sha1 == r->u.sha1.hash)
                    match = TRUE;
                else if (rec->sha1 != NULL && r->u.sha1.hash != NULL)
                    if (sha1_eq(rec->sha1, r->u.sha1.hash))
                        match = TRUE;
                break;
            case RULE_FLAG:
                {
                    gboolean stable_match;
                    gboolean busy_match;
                    gboolean push_match;

                    stable_match =
                        (
							r->u.flag.busy == RULE_FLAG_SET &&
							(rec->results_set->status & ST_BUSY)
						) ||
                        (
							r->u.flag.busy == RULE_FLAG_UNSET &&
							!(rec->results_set->status & ST_BUSY)
						) ||
                        r->u.flag.busy == RULE_FLAG_IGNORE;

                    busy_match =
                        (
							r->u.flag.push == RULE_FLAG_SET &&
							(rec->results_set->status & ST_FIREWALL)
						) ||
                        (
							(r->u.flag.push == RULE_FLAG_UNSET) &&
							!(rec->results_set->status & ST_FIREWALL)
						) ||
                        r->u.flag.push == RULE_FLAG_IGNORE;

                    push_match =
                        (
							r->u.flag.stable == RULE_FLAG_SET &&
							(rec->results_set->status & ST_UPLOADED)
						) ||
                        (
							r->u.flag.stable == RULE_FLAG_UNSET &&
							!(rec->results_set->status & ST_UPLOADED)
						) ||
						r->u.flag.stable == RULE_FLAG_IGNORE;

                    match = stable_match && busy_match && push_match;
                }
                break;
            case RULE_STATE:
                {
                    gboolean display_match;
                    gboolean download_match;

                    display_match =
                        (r->u.state.display == FILTER_PROP_STATE_IGNORE) ||
                        (res->props[FILTER_PROP_DISPLAY].state
                            == r->u.state.display);

                    download_match =
                        (r->u.state.download == FILTER_PROP_STATE_IGNORE) ||
                        (res->props[FILTER_PROP_DOWNLOAD].state
                            == r->u.state.download);

                    match = display_match && download_match;
                }
                break;
            default:
                g_error("Unknown rule type: %d", r->type);
                break;
            }
        }
        /*
         * If negate is set, we invert the meaning of match.
         */

		if (RULE_IS_NEGATED(r) && RULE_IS_ACTIVE(r))
			match = !match;

        /*
         * Try to match the builtin rules, but don't act on matches
         * that would change a result property that was already
         * defined.
         */
        if (match) {
            if (r->target == filter_return) {
                do_abort = TRUE;
                r->match_count ++;
                r->target->match_count ++;
            } else if (r->target == filter_show) {
                if (!res->props[FILTER_PROP_DISPLAY].state) {

                    res->props[FILTER_PROP_DISPLAY].state =
                        FILTER_PROP_STATE_DO;

                    MATCH_RULE(filter, r, res);
                }
            } else if (r->target == filter_drop) {
                if (!res->props[FILTER_PROP_DISPLAY].state) {

                    res->props[FILTER_PROP_DISPLAY].state =
                        FILTER_PROP_STATE_DONT;
                    res->props[FILTER_PROP_DISPLAY].user_data =
                        GINT_TO_POINTER(RULE_IS_SOFT(r) ? 1 : 0);

                    MATCH_RULE(filter, r, res);
                }
            } else if (r->target == filter_download) {
                if (!res->props[FILTER_PROP_DOWNLOAD].state) {

                    res->props[FILTER_PROP_DOWNLOAD].state =
                        FILTER_PROP_STATE_DO;

                    MATCH_RULE(filter, r, res);
                }
            } else if (r->target == filter_nodownload) {
                if (!res->props[FILTER_PROP_DOWNLOAD].state) {

                    res->props[FILTER_PROP_DOWNLOAD].state =
                        FILTER_PROP_STATE_DONT;

                    MATCH_RULE(filter, r, res);
                }
            } else {
                /*
                 * We have a matched rule the target is not a builtin
                 * rule, so it must be a subchain. We gosub.
                 */
                prop_count += filter_apply(r->target, ctx, res);
                r->match_count ++;
            }
        } else {
            r->fail_count ++;
        }

		list = g_list_next(list);
	}

    filter->visited = FALSE;
    filter->fail_count += MAX_FILTER_PROP - prop_count;
    filter->match_count += prop_count;
    return prop_count;
}

/**
 * Check a particular record against the search filter and the global
 * filters. Returns a filter_property_t array with MAX_FILTER_PROP
 * rows. This must be freed with filter_free_properties.
 */
filter_result_t *
filter_record(struct search *search, const struct record *rec)
{
    filter_result_t *result;
	struct filter_context ctx;
    gint i;

    g_assert(search != NULL);
	record_check(rec);

	ctx.rec = rec;
	ctx.l_name = ctx.utf8_name = NULL;
	ctx.l_len = ctx.utf8_len = 0;

    /*
     * Initialize all properties with FILTER_PROP_STATE_UNKNOWN and
     * the props_set count with 0;
     */

    WALLOC0(result);
    filter_apply(filter_global_pre, &ctx, result);

    /*
     * If not decided check if the filters for this search apply.
     */
    if (result->props_set < MAX_FILTER_PROP)
        filter_apply(search_gui_get_filter(search), &ctx, result);

    /*
     * If it has not yet been decided, try the global filter
     */
	if (result->props_set < MAX_FILTER_PROP)
		filter_apply(filter_global_post, &ctx, result);

    /*
     * Set the defaults for the props that are still in UNKNOWN state.
     */
    for (i = 0; i < MAX_FILTER_PROP; i ++) {
        switch (i) {
        case FILTER_PROP_DISPLAY:
            if (!result->props[i].state) {
                result->props[i].state =
                    FILTER_PROP_STATE_DO;
                result->props_set ++;
            }
            break;
        case FILTER_PROP_DOWNLOAD:
            if (!result->props[i].state) {
                result->props[i].state =
                    FILTER_PROP_STATE_DONT;
                result->props_set ++;
            }
            break;
        }
    }

	/*
	 * Cleanup cached variables.
	 */

	atom_str_free_null(&ctx.utf8_name);
	atom_str_free_null(&ctx.l_name);

	return result;
}



/**
 * Free global filters and save state.
 */
G_GNUC_COLD void
filter_shutdown(void)
{
    GList *f;

    if (GUI_PROPERTY(gui_debug) >= 5)
        g_debug("shutting down filters");

	filter_gui_shutdown();

    /*
     * It is important that all searches have already been closed.
     * Since it is not allowd to use a bound filter as a target,
     * a bound filter will always have a refcount of 0. So it is
     * not a problem just closing the searches.
     * But for the free filters, we have to prune all rules before
     * we may free the filers, because we have to reduce the
     * refcount on every filter to 0 before we are allowed to free it.
     */
    for (f = filters; f != NULL; f = f->next) {
        filter_t *filter = (filter_t*) f->data;
        GList *copy = g_list_copy(filter->ruleset);

        /*
         * Since filter_remove_rule modifies filter->ruleset, we
         * have to copy the ruleset before we start puring.
         */

        /*
         * We don't want to create any shadows again since a
         * shadowed filter may not be freed, so we use
         * filter_remove_rule.
         */

 		G_LIST_FOREACH_SWAPPED(copy, filter_remove_rule, filter);
        g_list_free(copy);
    }

    /*
     * Now we remove the filters. So we may not traverse. We just
     * free the first filter until none is left. This will also
     * clean up the builtin filters (filter_drop/show) and the
     * global filters;
     */
    for (f = filters; f != NULL; f = filters)
        filter_free(f->data);
}

static G_GNUC_COLD void
filter_preset_init(const char *name, const char *regexp, filesize_t minsize)
{
	filter_t *filter;

	filter = filter_find_by_name_in_session(name);
	if (filter) {
		/* Remove all rules, we want to keep this filters up-to-date */
		while (NULL != filter->ruleset) {
			rule_t *rule;
		
			rule = g_list_nth_data(filter->ruleset, 0);
			g_assert(rule->target);
			g_assert(rule->target->refcount > 0);
			rule->target->refcount--;

			filter->ruleset = g_list_remove(filter->ruleset, rule);
			filter_free_rule(rule);
		}
		filter_remove_from_session(filter);
	} else {
		filter = filter_new(lazy_ui_string_to_utf8(name));
	}

	if (minsize > 0) {
		rule_t *rule;

		rule = filter_new_size_rule(0, minsize - 1,
				filter_get_drop_target(),
				RULE_FLAG_ACTIVE);
		filter_append_rule(filter, rule);
	}

	if (regexp) {
		rule_t *rule;

		rule = filter_new_text_rule(regexp,
			RULE_TEXT_REGEXP,
			FALSE,	/* case-insensitive */
			filter_get_drop_target(),
			RULE_FLAG_ACTIVE | RULE_FLAG_NEGATE);
		filter_append_rule(filter, rule);
	}

	filter_add_to_session(filter);
	filter->flags |= FILTER_FLAG_PRESET;
}

/**
 *  Adds simple filter rules, for use by novice users.
 */
G_GNUC_COLD void
filter_init_presets(void)
{
	static const struct {
		const char *name;
		const char *regex;
		filesize_t minsize;
	} tab[] = {
		{ N_("<Archive>"),	  "[.](bz2|gz|zip|rar|iso|7z)$", 0 },
		{ N_("<Audio>"), 	  "[.](mp3|m4a|ogg|oga|opus|flac)$", 1000000 },
		{ N_("<Image>"), 	  "[.](bmp|gif|jpg|jpeg|png|psd|tif|tiff)$", 0 },
		{ N_("<Literature>"), "[.](pdf|doc|lit|djvu|ps|txt)$", 10000 },
		{ N_("<Video>"), 	  "[.](avi|mpg|mp4|mpeg|mkv|ogm|ogv|webm)$", 10000000 },
	};
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(tab); i++) {
		filter_preset_init(_(tab[i].name), tab[i].regex, tab[i].minsize);
	}
	filter_apply_changes();
}

static filter_t *
filters_add(const char *name, unsigned flags)
{
	filter_t *filter;

    filter = filter_new(lazy_ui_string_to_utf8(name));
	filter->flags |= flags;
    filters = g_list_append(filters, filter);
	return filter;
}

static G_GNUC_COLD void
filter_init_globals(void)
{
	const unsigned flags = FILTER_FLAG_GLOBAL;

    filter_global_pre  = filters_add(_("Global (pre)"), flags);
    filter_global_post = filters_add(_("Global (post)"), flags);
}

static G_GNUC_COLD void
filter_init_builtins(void)
{
	const unsigned flags = FILTER_FLAG_BUILTIN;

    filter_show        = filters_add(_("DISPLAY"), flags);
    filter_drop        = filters_add(_("DON'T DISPLAY"), flags);
    filter_download    = filters_add(_("DOWNLOAD"), flags);
    filter_nodownload  = filters_add(_("DON'T DOWNLOAD"), flags);
    filter_return      = filters_add(_("RETURN"), flags);
}

/**
 * Initialize global filters.
 */
G_GNUC_COLD void
filter_init(void)
{
	filter_init_globals();
	filter_init_builtins();
    filters_current = g_list_copy(filters);

    gui_popup_filter_rule_set(create_popup_filter_rule());
}

/**
 * Trigger a rebuild of the target combos.
 */
void
filter_update_targets(void)
{
    filter_gui_rebuild_target_combos(filters_current);
}

/**
 * Reset the rule stats for a given rule.
 */
void
filter_rule_reset_stats(rule_t *rule)
{
    g_assert(rule != NULL);

    rule->match_count = rule->fail_count = 0;
}



/**
 * Reset the stats for a given filter.
 */
void
filter_reset_stats(filter_t *filter)
{
    g_assert(filter != NULL);

    filter->match_count = filter->fail_count = 0;
}



/**
 * Change the "enabled" flag of a filter.
 */
void
filter_set_enabled(filter_t *filter, gboolean active)
{
    shadow_t *shadow;
    static gboolean locked = FALSE;

    g_assert(filter != NULL);

    if (locked)
        return;

    locked = TRUE;

    shadow = shadow_find(filter);
    if (shadow == NULL)
        shadow = shadow_new(filter);

    if (active) {
        shadow->flags |= FILTER_FLAG_ACTIVE;
    } else {
		shadow->flags &= ~FILTER_FLAG_ACTIVE;
    }

    filter_gui_filter_set_enabled(work_filter, active);

    locked = FALSE;
}

/**
 * Free a filter_result returned by filter_record
 * after it has been processed.
 */
void
filter_free_result(filter_result_t *res)
{
    gint i;

    g_assert(res != NULL);

    /*
     * Since every property type can need a special handling
     * for freeing the user data, we handle that here. Currently
     * no property needs this.
     */
    for (i = 0; i < MAX_FILTER_PROP; i ++) {
        switch (i) {
        case FILTER_PROP_DISPLAY:
            break;
        case FILTER_PROP_DOWNLOAD:
            break;
        default:
            g_assert_not_reached();
        };
    }

    WFREE(res);
}

/**
 * Checks wether a filter is existant in a filter editing session.
 * If no session is started it checks wether the filter is valid
 * in outside the session.
 */
gboolean
filter_is_valid_in_session(const filter_t *f)
{
    return f && g_list_find(filters_current, deconstify_gpointer(f));
}

/**
 * Returns the filter with the given name in the session if it
 * exists, otherwise returns NULL. If no session is started, it
 * looks in the normal filter list.
 */
filter_t *
filter_find_by_name_in_session(const gchar *name)
{
    GList *iter;

    for (iter = filters_current; iter != NULL; iter = g_list_next(iter)) {
        filter_t *filter = iter->data;

        if (strcmp(filter->name, name) == 0)
            return filter;
    }
    return NULL;
}

gboolean
filter_is_global(const filter_t *f)
{
	g_return_val_if_fail(f, FALSE);
    return 0 != (FILTER_FLAG_GLOBAL & f->flags);
}

gboolean
filter_is_builtin(const filter_t *f)
{
	g_return_val_if_fail(f, FALSE);
    return 0 != (FILTER_FLAG_BUILTIN & f->flags);
}

gboolean
filter_is_modifiable(const filter_t *f)
{
	g_return_val_if_fail(f, FALSE);
    return !((FILTER_FLAG_BUILTIN | FILTER_FLAG_PRESET) & f->flags);
}

filter_t *
filter_get_drop_target(void)
{
    return filter_drop;
}

filter_t *
filter_get_show_target(void)
{
    return filter_show;
}

filter_t *
filter_get_download_target(void)
{
    return filter_download;
}

filter_t *
filter_get_nodownload_target(void)
{
    return filter_nodownload;
}

filter_t *
filter_get_return_target(void)
{
    return filter_return;
}

filter_t *
filter_get_global_pre(void)
{
    return filter_global_pre;
}

filter_t *
filter_get_global_post(void)
{
    return filter_global_post;
}

/**
 * Adds a drop SHA1 rule to specified filter.
 */
void
filter_add_drop_sha1_rule(const struct record *rec, filter_t *filter)
{
    rule_t *rule;
	gchar *s;

	record_check(rec);
    g_assert(filter != NULL);

	s = unknown_to_utf8_normalized(rec->name, UNI_NORM_GUI, FALSE);
    rule = filter_new_sha1_rule(rec->sha1, s,
        filter_get_drop_target(), RULE_FLAG_ACTIVE);

    filter_prepend_rule(filter, rule);
	if (s != rec->name) {
		G_FREE_NULL(s);
	}
}

/**
 * Adds a drop filename rule to specified filter.
 */
void
filter_add_drop_name_rule(const struct record *rec, filter_t *filter)
{
    rule_t *rule;
	gchar *s;

	record_check(rec);
    g_assert(filter != NULL);

	s = unknown_to_utf8_normalized(rec->name, UNI_NORM_GUI, FALSE);
    rule = filter_new_text_rule(s, RULE_TEXT_EXACT, TRUE,
        filter_get_drop_target(), RULE_FLAG_ACTIVE);

    filter_prepend_rule(filter, rule);
	if (s != rec->name) {
		G_FREE_NULL(s);
	}
}

/**
 * Adds a drop host rule to specified filter.
 */
void
filter_add_drop_host_rule(const struct record *rec, filter_t *filter)
{
    rule_t *rule;

	record_check(rec);
    g_assert(filter != NULL);

    rule = filter_new_ip_rule(rec->results_set->addr, -1,
        		filter_get_drop_target(), RULE_FLAG_ACTIVE);

    filter_prepend_rule(filter, rule);
}

/**
 * Adds a download SHA1 rule to specified filter.
 */
void
filter_add_download_sha1_rule(const struct record *rec, filter_t *filter)
{
	record_check(rec);
    g_assert(filter != NULL);

    if (rec->sha1) {
        rule_t *rule;
		gchar *s;

		s = unknown_to_utf8_normalized(rec->name, UNI_NORM_GUI, FALSE);
        rule = filter_new_sha1_rule(rec->sha1, s,
            filter_get_download_target(), RULE_FLAG_ACTIVE);

        filter_append_rule(filter, rule);
		if (s != rec->name) {
			G_FREE_NULL(s);
		}
    }
}

/**
 * Adds a download filename rule to specified filter.
 */
void
filter_add_download_name_rule(const struct record *rec, filter_t *filter)
{
    rule_t *rule;
	gchar *s;

	record_check(rec);
    g_assert(filter != NULL);

	s = unknown_to_utf8_normalized(rec->name, UNI_NORM_GUI, FALSE);
    rule = filter_new_text_rule(s, RULE_TEXT_EXACT, TRUE,
        filter_get_download_target(), RULE_FLAG_ACTIVE);

    filter_append_rule(filter, rule);
	if (s != rec->name) {
		G_FREE_NULL(s);
	}
}

/* vi: set ts=4 sw=4 cindent: */
