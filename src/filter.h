/*
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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

#ifndef __filter_h__
#define __filter_h__

#include <regex.h>

#include "gnutella.h"
#include "matching.h"

/*
 * Needed stuff from search.h
 */
struct record;
struct search;

enum rule_type {
    RULE_TEXT = 0,
    RULE_IP,
    RULE_SIZE,
    RULE_JUMP
};

enum rule_text_type {
    RULE_TEXT_PREFIX,
    RULE_TEXT_WORDS,
    RULE_TEXT_SUFFIX,
    RULE_TEXT_SUBSTR,
    RULE_TEXT_REGEXP
};

typedef struct filter {
    gchar *name;
    GList *ruleset;
    struct search *search;
    gboolean visited;
    gint32 refcount;
} filter_t;



#define RULE_FLAG_NEGATE (1 << 0)
#define RULE_FLAG_VALID  (1 << 1)
#define RULE_FLAG_ACTIVE (1 << 2)
#define RULE_FLAG_SOFT   (1 << 3)

#define RULE_IS_VALID(r) ((r != NULL) && (r->flags & RULE_FLAG_VALID))
#define RULE_IS_NEGATED(r) ((r != NULL) && (r->flags & RULE_FLAG_NEGATE))
#define RULE_IS_ACTIVE(r) ((r != NULL) && (r->flags & RULE_FLAG_ACTIVE))
#define RULE_IS_SOFT(r) ((r != NULL) && (r->flags & RULE_FLAG_SOFT))

#define rule_set_flags(r,f) (r->flags = r->flags | (f))
#define rule_clear_flags(r,f) (r->flags = r->flags & ~(f))


/* 
 * Definition of a filter rule
 */
typedef struct rule {
    enum rule_type type;	            /* type of rule, see above */
    guint16 flags;
    guint32 match_count;
    guint32 fail_count;
    filter_t *target;
    union {
        struct _f_text {
            int case_sensitive:1;	    /* case sensitive (true) or not (false) */
            enum rule_text_type type; /* type of match, see above */
            char *match; 	            /* match string */
            union {
                cpattern_t *pattern;	/* substring pattern */
                GList *words;		    /* a list of substring patterns */
                regex_t *re;		    /* regular expression match */
            } u;
        } text;
        struct _f_ip {
            guint32 addr;		        /* IP address */
            guint32 mask;		        /* netmask */
        } ip;
        struct _f_size {
            size_t lower;		        /* lower limit or 0 */
            size_t upper;		        /* upper limit or ~0 */
        } size;
    } u;
} rule_t;



/*
 * Notebook tabs in the filter detail notebook.
 */
enum {
    nb_filt_page_buttons = 0,
    nb_filt_page_text,
    nb_filt_page_ip,
    nb_filt_page_size,
    nb_filt_page_jump
};



/*
 * Public variables.
 */
extern filter_t *work_filter;



/*
 * Public interface.
 */

rule_t *filter_new_ip_rule(guint32, guint32, filter_t *, guint16);
rule_t *filter_new_size_rule(size_t, size_t, filter_t *, guint16);
rule_t *filter_new_text_rule(gchar *, gint, gboolean, filter_t *, guint16);
rule_t *filter_new_jump_rule(filter_t *,guint16);
filter_t *filter_new(gchar *);
gboolean filter_record(struct search *, struct record *);
rule_t *filter_get_rule();
void filter_adapt_order(void);
void filter_append_rule(filter_t *, rule_t *);
void filter_cancel_changes();
void filter_close_dialog();
void filter_close_search(struct search *);
void filter_commit_changes();
void filter_edit_ip_rule(rule_t *);
void filter_edit_rule(rule_t *f);
void filter_edit_size_rule(rule_t *);
void filter_edit_text_rule(rule_t *);
void filter_edit_jump_rule(rule_t *);
void filter_free(filter_t *r);
void filter_init(void);
void filter_new_for_search(struct search *s);
void filter_open_dialog();
void filter_remove_rule(filter_t *, rule_t *);
void filter_replace_rule(filter_t *, rule_t *, rule_t *);
void filter_set(filter_t *);
void filter_shutdown(void);
void filter_update_filters(void);
#endif /* __filter_h__ */
