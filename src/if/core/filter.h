/*
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifndef _if_core_filter_h_
#define _if_core_filter_h_

/*
 * XXX Currently, filters are part of the GUI sources, but they should be
 * XXX move to the core, because it is the core who will decide on
 * XXX creating a new download when auto-download is set, or which knows
 * XXX the set of files it downloaded and which should be ignored.
 * XXX Because I anticipate that move, I'm putting this interface file here.
 * XXX		--RAM, 2004-08-22
 */

/***
 *** Filters
 ***/
enum rule_type {
	RULE_TEXT = 0,
	RULE_IP,
	RULE_SIZE,
	RULE_JUMP,
	RULE_SHA1,
	RULE_FLAG,
	RULE_STATE
};

enum rule_text_type {
	RULE_TEXT_PREFIX,
	RULE_TEXT_WORDS,
	RULE_TEXT_SUFFIX,
	RULE_TEXT_SUBSTR,
	RULE_TEXT_REGEXP,
	RULE_TEXT_EXACT
};

enum rule_flag_action {
	RULE_FLAG_SET = 0,
	RULE_FLAG_UNSET = 1,
	RULE_FLAG_IGNORE = 2
};

/**
 * MAX_FILTER_PROP is used to know how many FILTER_PROPS there are.
 */
typedef enum filter_prop {
	FILTER_PROP_DISPLAY = 0,
	FILTER_PROP_DOWNLOAD,
	MAX_FILTER_PROP
} filter_prop_t;

/**
 * The states a filter_property. I chose 0 for UNKNOWN because that
 * makes it easy to initialize the property array with g_new0 and
 * it's easy to check if the state is still unset by !.
 * FILTER_PROP_IGNORE is needed because we also want filter rules
 * that allow to act only on one property and ignores the other.
 */
typedef enum filter_prop_state {
	FILTER_PROP_STATE_UNKNOWN = 0,
	FILTER_PROP_STATE_DO,
	FILTER_PROP_STATE_DONT,
	MAX_FILTER_PROP_STATE,
	FILTER_PROP_STATE_IGNORE
} filter_prop_state_t;

#endif /* _if_core_filter_h_ */

/* vi: set ts=4 sw=4 cindent: */
