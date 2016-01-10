/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * @ingroup xml
 * @file
 *
 * Versatile XML processing.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _xml_vxml_h_
#define _xml_vxml_h_

#include "common.h"
#include "xattr.h"
#include "xnode.h"

#include "if/gen/vxml.h"

struct vxml_parser;
typedef struct vxml_parser vxml_parser_t;

/**
 * Parsing options.
 */
#define VXML_O_NO_NAMESPACES	(1 << 0)  /**< Ignore namespaces */
#define VXML_O_STRICT_COMMENTS	(1 << 1)  /**< Disable '--' in comments */
#define VXML_O_FATAL			(1 << 2)  /**< Abort on fatal error */
#define VXML_O_STRIP_BLANKS		(1 << 3)  /**< Strip leading/ending blanks */
#define VXML_O_NO_DUP_ATTR		(1 << 4)  /**< Forbid duplicate attributes */

/**
 * Start plain element callback signature.
 *
 * @param vp		the parser
 * @param name		the element name (UTF-8 string)
 * @param attrs		element attributes (name/value pair table)
 * @param data		user-specified callback argument
 */
typedef void (*vxml_p_element_start_cb_t)(vxml_parser_t *vp,
	const char *name, const xattr_table_t *attrs, void *data);

/**
 * Start tokenized element callback signature.
 *
 * @param vp		the parser
 * @param id		the element token ID (user-defined)
 * @param attrs		element attributes (name/value pair table)
 * @param data		user-specified callback argument
 */
typedef void (*vxml_t_element_start_cb_t)(vxml_parser_t *vp,
	unsigned id, const xattr_table_t *attrs, void *data);

/**
 * Plain element text callback signature.
 *
 * @param vp		the parser
 * @param name		the element name (UTF-8 string)
 * @param text		the text data (NUL-terminated, in UTF-8)
 * @param len		length of text data
 * @param data		user-specified callback argument
 */
typedef void (*vxml_p_text_cb_t)(vxml_parser_t *vp,
	const char *name, const char *text, size_t len, void *data);

/**
 * Tokenized element text callback signature.
 *
 * @param vp		the parser
 * @param id		the element token ID (user-defined)
 * @param text		the text data (NUL-terminated, in UTF-8)
 * @param len		length of text data
 * @param data		user-specified callback argument
 */
typedef void (*vxml_t_text_cb_t)(vxml_parser_t *vp,
	unsigned id, const char *text, size_t len, void *data);

/**
 * End plain element callback signature.
 *
 * @param vp		the parser
 * @param name		the element name (UTF-8 string)
 * @param data		user-specified callback argument
 */
typedef void (*vxml_p_element_end_cb_t)(vxml_parser_t *vp,
	const char *name, void *data);

/**
 * End tokenized element callback signature.
 *
 * @param vp		the parser
 * @param id		the element token ID (user-defined)
 * @param data		user-specified callback argument
 */
typedef void (*vxml_t_element_end_cb_t)(vxml_parser_t *vp,
	unsigned id, void *data);

/**
 * Regroups the parsing callbacks on elements.
 *
 * Any callback can be specified as NULL in which case it will not be
 * invoked.
 *
 * When both a tokenized and a non-tokenized (plain) element callback are
 * defined, the tokenized one is invoked if the parser is able to tokenize
 * the element.
 */
struct vxml_ops {
	vxml_p_element_start_cb_t plain_start;
	vxml_p_text_cb_t plain_text;
	vxml_p_element_end_cb_t plain_end;
	vxml_t_element_start_cb_t tokenized_start;
	vxml_t_text_cb_t tokenized_text;
	vxml_t_element_end_cb_t tokenized_end;
};

/**
 * A tokenized element.
 */
struct vxml_token {
	const char *name;		/**< Element name (UTF-8) */
	unsigned id;			/**< Corresponding token */
};

/*
 * Public constants.
 */

extern const char VXS_XMLNS[];		/* "xmlns" */
extern const char VXS_XML[];		/* "xml" */
extern const char VXS_XML_URI[];	/* "http://www.w3.org/XML/1998/namespace" */

/*
 * Public interface.
 */

void vxml_test(void);
void set_vxml_debug(uint32 level);
bool vxml_debugging(uint32 level) G_PURE;

const char *vxml_parser_strerror(const vxml_parser_t *vp, vxml_error_t error);
vxml_parser_t *vxml_parser_make(const char *name, uint32 options);
void vxml_parser_free(vxml_parser_t *vp);
void vxml_parser_add_data(vxml_parser_t *vp, const char *data, size_t length);
void vxml_parser_add_file(vxml_parser_t *vp, FILE *fd);
bool vxml_parser_set_charset(vxml_parser_t *vp, const char *charset);
void vxml_parser_set_tokens(vxml_parser_t *vp,
	struct vxml_token *tvec, size_t tlen);
vxml_error_t vxml_parse(vxml_parser_t *vp);
vxml_error_t vxml_parse_callbacks(vxml_parser_t *vp,
	const struct vxml_ops *ops, void *data);
vxml_error_t vxml_parse_callbacks_tokens(vxml_parser_t *vp,
	const struct vxml_ops *ops,
	struct vxml_token *tvec, size_t tlen, void *data);
vxml_error_t vxml_parse_tree(vxml_parser_t *vp, xnode_t **root);

void vxml_parser_error(vxml_parser_t *vp,
		const char *errstr, ...) G_GNUC_PRINTF(2, 3);
unsigned vxml_parser_depth(const vxml_parser_t *vp);
size_t vxml_parser_offset(const vxml_parser_t *vp);
size_t vxml_parser_line(const vxml_parser_t *vp);
const char *vxml_parser_current_element(const vxml_parser_t *vp);
const char *vxml_parser_parent_element(const vxml_parser_t *vp);
const char *vxml_parser_nth_parent_element(const vxml_parser_t *vp, size_t n);
const char *vxml_parser_current_namespace(const vxml_parser_t *vp);

#endif /* _xml_vxml_h_ */

/* vi: set ts=4 sw=4 cindent: */
