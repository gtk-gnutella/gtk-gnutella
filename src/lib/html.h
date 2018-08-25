/*
 * Copyright (c) 2007 Christian Biere
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
 * @ingroup lib
 * @file
 *
 * Simple HTML handling.
 *
 * @author Christian Biere
 * @date 2007
 */

#ifndef _html_h_
#define _html_h_

#include "common.h"

#include "lib/array.h"

enum html_attr {
	HTML_ATTR_UNKNOWN,

	HTML_ATTR_ALT,
	HTML_ATTR_HEIGHT,
	HTML_ATTR_HREF,
	HTML_ATTR_LANG,
	HTML_ATTR_NAME,
	HTML_ATTR_SRC,
	HTML_ATTR_TARGET,
	HTML_ATTR_WIDTH,

	NUM_HTML_ATTR
};

enum html_tag {
	HTML_TAG_UNKNOWN,

	HTML_TAG_A,
	HTML_TAG_B,
	HTML_TAG_BODY,
	HTML_TAG_BR,
	HTML_TAG_CODE,
	HTML_TAG_COL,
	HTML_TAG_COMMENT,
	HTML_TAG_DOCTYPE,
	HTML_TAG_DD,
	HTML_TAG_DIV,
	HTML_TAG_DL,
	HTML_TAG_DT,
	HTML_TAG_EM,
	HTML_TAG_H1,
	HTML_TAG_H2,
	HTML_TAG_H3,
	HTML_TAG_H4,
	HTML_TAG_H5,
	HTML_TAG_H6,
	HTML_TAG_HEAD,
	HTML_TAG_HTML,
	HTML_TAG_HR,
	HTML_TAG_I,
	HTML_TAG_IMG,
	HTML_TAG_KBD,
	HTML_TAG_LI,
	HTML_TAG_META,
	HTML_TAG_OL,
	HTML_TAG_P,
	HTML_TAG_PRE,
	HTML_TAG_Q,
	HTML_TAG_SPAN,
	HTML_TAG_STRONG,
	HTML_TAG_TABLE,
	HTML_TAG_TBODY,
	HTML_TAG_TD,
	HTML_TAG_TH,
	HTML_TAG_THEAD,
	HTML_TAG_TITLE,
	HTML_TAG_TR,
	HTML_TAG_TT,
	HTML_TAG_UL,

	NUM_HTML_TAG
};

struct html_output;

struct html_output *html_output_alloc(void);
void html_output_set_udata(struct html_output *output, void *udata);
void html_output_set_print(struct html_output *output,
	void (*print)(struct html_output *, const struct array *));
void html_output_set_tag(struct html_output *output,
	void (*tag)(struct html_output *, const struct array *));
void *html_output_get_udata(struct html_output *output);
enum html_tag html_parse_tag(const struct array *tag);
bool html_tag_is_closing(const struct array *tag);
struct array html_get_attribute(const struct array *tag,
			enum html_attr attribute);
void html_output_free(struct html_output **output_ptr);

int html_load_file(struct html_output *output, int fd);
int html_load_memory(struct html_output *output, const struct array data);

#endif	/* _html_h_ */

/* vi: set ts=4 sw=4 cindent: */
