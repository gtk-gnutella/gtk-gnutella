/*
 * $Id$
 *
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

#include "common.h"

RCSID("$Id$")

#include "lib/html.h"
#include "lib/html_entities.h"
#include "lib/misc.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum html_node_type {
	HTML_NODE_ROOT,
	HTML_NODE_TAG,
	HTML_NODE_TEXT
};

struct html_node {
	struct array array;
	struct html_node *next;
	enum html_node_type type;
};

static const struct html_node zero_html_node;

static struct html_node *
html_node_alloc(void)
{
	struct html_node *node = walloc(sizeof *node);
	*node = zero_html_node;
	return node;
}

static void
html_node_free(struct html_node **node_ptr)
{
	struct html_node *node = *node_ptr;
	if (node) {
		wfree(node, sizeof *node);
		*node_ptr = NULL;
	}
}

struct html_output {
	void (*print)(struct html_output *, const struct array *);
	void (*tag)(struct html_output *, const struct array *);
	void *udata;
};

struct render_context {
	struct html_output *output;
	struct html_node *root;
	gboolean preformatted;
	gboolean closing;
};

static const struct render_context zero_render_context;

static void
html_output_print(struct html_output *output, const struct array text)
{
	if (output->print)
		output->print(output, &text);
}

static void
html_output_tag(struct html_output *output, const struct array tag)
{
	if (output->tag)
		output->tag(output, &tag);
}


struct html_output *
html_output_alloc(void)
{
	static const struct html_output zero_output;
	struct html_output *output;
	output = walloc(sizeof *output);
	*output = zero_output;
	return output;
}

void
html_output_free(struct html_output **output_ptr)
{
	struct html_output *output = *output_ptr;
	if (output) {
		wfree(output, sizeof *output);
		*output_ptr = NULL;
	}
}


void
html_output_set_udata(struct html_output *output, void *udata)
{
	output->udata = udata;
}

void
html_output_set_print(struct html_output *output,
	void (*print)(struct html_output *, const struct array *))
{
	output->print = print;
}

void
html_output_set_tag(struct html_output *output,
	void (*tag)(struct html_output *, const struct array *))
{
	output->tag = tag;
}


void *
html_output_get_udata(struct html_output *output)
{
	return output->udata;
}

static enum html_attr
parse_attribute(const struct array attr)
{
	static const struct {
		const char *name;
		enum html_attr attr;
	} tab[] = {
#define D(x) { #x, HTML_ATTR_ ## x, }
		D(ALT),
		D(HEIGHT),
		D(HREF),
		D(NAME),
		D(SRC),
		D(TARGET),
		D(WIDTH),
#undef D
	};
	size_t i, len;
	char name[32];

	STATIC_ASSERT(G_N_ELEMENTS(tab) == NUM_HTML_ATTR - 1);
	
	len = 0;
	for (i = 0; i < attr.size; i++) {
		const unsigned char c = attr.data[i];

		if (G_N_ELEMENTS(name) == len || !is_ascii_alpha(c))
			break;

		name[len] = ascii_toupper(c);
		len++;
	}

	if (len > 0 && len < (int)G_N_ELEMENTS(name)) {
		name[len] = '\0';
		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (0 == strcmp(name, tab[i].name))
				return tab[i].attr;
		}
		g_warning("Unknown attribute: \"%s\"", name);
	}
	return HTML_ATTR_UNKNOWN;
}

static enum html_tag
parse_tag(const struct array tag)
{
	static const struct {
		const char *name;
		enum html_tag tag;
	} tab[] = {
#define D(x) { #x, HTML_TAG_ ## x, }
		D(UNKNOWN),
		D(A),
		D(B),
		D(BODY),
		D(BR),
		D(COL),
		D(CODE),
		D(DD),
		D(DIV),
		D(DL),
		D(DT),
		D(EM),
		D(H1),
		D(H2),
		D(H3),
		D(H4),
		D(H5),
		D(H6),
		D(HR),
		D(HEAD),
		D(HTML),
		D(I),
		D(IMG),
		D(KBD),
		D(LI),
		D(META),
		D(OL),
		D(P),
		D(PRE),
		D(Q),
		D(SPAN),
		D(STRONG),
		D(TABLE),
		D(TBODY),
		D(TD),
		D(TH),
		D(THEAD),
		D(TITLE),
		D(TR),
		D(TT),
		D(UL),
		{ "!--",		HTML_TAG_COMMENT },
		{ "!DOCTYPE",	HTML_TAG_DOCTYPE },
#undef D
	};
	size_t i, len;
	char name[32];

	STATIC_ASSERT(G_N_ELEMENTS(tab) == NUM_HTML_TAG);
	
	len = 0;
	for (i = 0; i < tag.size; i++) {
		const unsigned char c = tag.data[i];

		if (G_N_ELEMENTS(name) == len)
			break;

		if (0 == len) {
			if ('/' == c && 0 == i)
				continue;
			if (!is_ascii_alnum(c) && '!' != c && '?' != c)
				break;
		} else if (!is_ascii_alnum(c) && '-' != c) {
			break;
		}
		name[len] = ascii_toupper(c);
		len++;
	}

	if (len > 0 && len < (int)G_N_ELEMENTS(name)) {
		name[len] = '\0';
		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (0 == strcmp(name, tab[i].name))
				return tab[i].tag;
		}
		g_warning("Unknown tag: \"%s\"", name);
	}
	return HTML_TAG_UNKNOWN;
}

gboolean
html_tag_is_closing(const struct array *tag)
{
	return	tag &&
			tag->data &&
			tag->size > 0 &&
			('/' == tag->data[tag->size - 1] || '/' == tag->data[0]);
}

enum html_tag
html_parse_tag(const struct array *tag)
{
	if (tag && tag->data) {
		return parse_tag(*tag);
	} else {
		return HTML_TAG_UNKNOWN;
	}
}

struct array
html_get_attribute(const struct array *tag, enum html_attr attribute)
{
	size_t i = 0;

	if (
		!tag || !tag->data ||
		NUM_HTML_ATTR == attribute || HTML_ATTR_UNKNOWN == attribute
	)
		goto not_found;

	/**
	   <tag-name>([<space>][<attr>[<space>]'='[<space>]'"'<value>'"'])*
	 */
			
	/* skip <tag-name> */
	while (i < tag->size && !is_ascii_space(tag->data[i]))
		i++;

	while (i < tag->size) {
		struct array value, attr;

		/* skip <space> */
		while (i < tag->size && is_ascii_space(tag->data[i]))
			i++;

		attr = array_init(&tag->data[i], tag->size - i);

		/* skip <attr> */
		while (i < tag->size) {
			const unsigned char c = tag->data[i];
			if ('=' == c || is_ascii_space(c))
				break;
			i++;
		}

		/* skip <space> */
		while (i < tag->size && is_ascii_space(tag->data[i]))
			i++;

		if (i < tag->size && '=' == tag->data[i]) {
			gboolean quoted;
			size_t start;

			i++;

			/* skip <space> */
			while (i < tag->size && is_ascii_space(tag->data[i]))
				i++;

			if (i < tag->size && '"' == tag->data[i]) {
				i++;
				quoted = TRUE;
			}
			start = i;

			/* skip <value> */
			while (i < tag->size) {
				const unsigned char c = tag->data[i];
				if (quoted) {
					if ('"' == c)
						break;
				} else if (is_ascii_space(c)) {
					break;
				}
				i++;
			}
			value = array_init(&tag->data[start], i - start);
		} else {
			value = array_init(&tag->data[i], 0);
		}

		if (attribute == parse_attribute(attr))
			return value;
	}

not_found:	
	return zero_array;
}

static void
render_tag(struct render_context *ctx, const struct array tag)
{
	if (tag.size > 0) {
		ctx->closing = html_tag_is_closing(&tag);
		html_output_tag(ctx->output, tag);
		if (HTML_TAG_PRE == parse_tag(tag)) {
			ctx->preformatted = !ctx->closing;
		}
	}
}

static guint32
parse_named_entity(const struct array entity)
{
	size_t i, len;
	char name[16];

	len = 0;
	for (i = 0; i < entity.size; i++) {
		const unsigned char c = entity.data[i];

		if (len >= G_N_ELEMENTS(name) - 1 || !is_ascii_alnum(c))
			goto error;
		name[len] = ascii_toupper(c);
		len++;
	}

	if (len > 0) {
		name[len] = '\0';

		for (i = 0; i < G_N_ELEMENTS(html_entities); i++) {
			if (strlen(html_entities[i].name) == len
				&& 0 == strcasecmp(html_entities[i].name, name)
			   )
				return html_entities[i].uc;
		}
	}

error:
	return -1;
}

static guint32
parse_numeric_entity(const struct array entity)
{
	if (entity.size > 1 && '#' == entity.data[0]) {
		unsigned base;
		guint32 v;
		size_t i;

		switch (entity.data[0]) {
		case 'x':
		case 'X':
			base = 16;
			i = 1;
			break;
		default:
			base = 10;
			i = 0;
		}
		v = 0;
		while (i < entity.size) {
			int d;
			
			d = hex2int_inline(entity.data[i++]);
			if (d < 0 || d + 0U > base)
				goto error;

			v = v * base + d;
			if (v >= 0x10ffffU)
				goto error;
		}
		if (0 == utf8_encoded_len(v))
			goto error;
		return v;
	}

error:
	return -1;
}

static guint32
parse_entity(const struct array entity)
{
	if (entity.size > 0) {
		const unsigned char c = entity.data[0];

		if ('#' == c) {
			return parse_numeric_entity(entity);
		} else if (is_ascii_alpha(c)) {
			return parse_named_entity(entity);
		}
	}
	return -1;
}

static void
render_entity(struct render_context *ctx, const struct array entity)
{
	guint32 c;

	c = parse_entity(entity);
	if ((guint32)-1 == c) {
		html_output_print(ctx->output, array_from_string("&"));
		html_output_print(ctx->output, array_init(entity.data, entity.size));
		html_output_print(ctx->output, array_from_string(";"));
	} else {
		size_t len;
		char buf[4];

		len = utf8_encode(c, buf);
		html_output_print(ctx->output, array_init(buf, len));
	}
}

static void
render_text(struct render_context *ctx, const struct array text)
{
	unsigned c_len;
	size_t i;
	gboolean whitespace = FALSE;
	struct array entity, current;

	entity = zero_array;
	current = zero_array;

	for (i = 0; i < text.size; i += c_len) {
		const unsigned char c = text.data[i];
		gboolean is_whitespace;

		is_whitespace = FALSE;
		c_len = utf8_first_byte_length_hint(c);
		if (!ctx->preformatted && is_ascii_space(c)) {
			if (whitespace)
				continue;
			is_whitespace = TRUE;
			whitespace = TRUE;
			if (0x20 == c && i > 0 && i < text.size - c_len) {
				const unsigned char next_c = text.data[i + c_len];

				if (!is_ascii_space(next_c))
					is_whitespace = FALSE;
			}
		} else {
			whitespace = FALSE;
		}
		if ('&' == c || ';' == c || is_whitespace) {
			if (current.size > 0) {
				html_output_print(ctx->output, current);
				current = zero_array;
			}
		}
		if (is_whitespace) {
			if (i > 0 || ctx->closing)
				html_output_print(ctx->output, array_from_string(" "));
		} else if ('&' == c) {
			if (entity.data) {
				render_entity(ctx, entity);
			}
			entity.data = deconstify_gchar(&text.data[i + c_len]);
			entity.size = 0;
			continue;
		} else if (';' == c) {
			if (entity.data) {
				render_entity(ctx, entity);
				entity = zero_array;
				continue;
			}
		} else if (entity.data) {
			entity.size += c_len;
		} else {
			if (!current.data)
				current.data = &text.data[i];
			current.size += c_len;
		}
	}
	if (current.size > 0) {
		html_output_print(ctx->output, current);
	}
}

static void
render(struct render_context *ctx)
{
	const struct html_node *node;

	for (node = ctx->root; node != NULL; node = node->next) {	
		switch (node->type) {
		case HTML_NODE_ROOT:
			break;
		case HTML_NODE_TAG:
			render_tag(ctx, node->array);
			break;
		case HTML_NODE_TEXT:
			render_text(ctx, node->array);
			break;
		}
	}
}

static int
parse(struct html_output *output, const struct array array)
{
	size_t i, line_num;
	const char *msg;
	guint32 c;
	unsigned c_len;
	struct array tag, text;
	struct html_node *nodes, *root;

	line_num = 1;

	root = html_node_alloc();
	nodes = root;

	tag = zero_array;
	text = array_init(deconstify_gchar(array.data), 0); 

	for (i = 0; i < array.size; i += c_len) {
		const char *next_ptr;

		c = utf8_decode(&array.data[i], i - array.size);
		if ((guint32)-1 == c) {
			msg = "Invalid UTF-8 encoding";
			goto error;
		}
		c_len = utf8_encoded_len(c);
		next_ptr = &array.data[i + c_len];

		switch (c) {
		case '<':
			if (tag.data) {
				tag.size += c_len;
			} else {
				if (text.data && text.size > 0) {
					struct html_node *node;

					node = html_node_alloc();
					node->type = HTML_NODE_TEXT;
					node->array = text;
					node->next = NULL;
					nodes->next = node;
					nodes = node;
					text = zero_array;
				}
				tag.data = deconstify_gchar(next_ptr);
				tag.size = 0;
			}
			break;
			
		case '>':
			if (!tag.data) {
				g_warning("'>' but no open tag");
				if (text.data)
					text.size += c_len;
			} else if (
				HTML_TAG_COMMENT == parse_tag(tag) &&
				0 != memcmp(&tag.data[tag.size - 2], "--", 2)
			) {
				tag.size += c_len;
			} else {
				struct html_node *node;

				node = html_node_alloc();
				node->type = HTML_NODE_TAG;
				node->array = tag;
				node->next = NULL;
				nodes->next = node;
				nodes = node;
				tag = zero_array;
				text = array_init(deconstify_gchar(next_ptr), 0); 
			}
			break;

		case '\n':
			line_num++;
			/* FALL THROUGH */
		default:
			if (tag.data) {
				tag.size += c_len;
			} else if (text.data) {
				text.size += c_len;
			}
		}
	}

	{
		struct render_context ctx;

		ctx = zero_render_context;
		ctx.output = output;
		ctx.root = root;
		render(&ctx);
	}

	{
		struct html_node *node, *next;

		for (node = root; NULL != node; node = next) {
			next = node->next;
			html_node_free(&node);
		}
	}

	return 0;

error:
	g_warning("line %lu: error: %s", (unsigned long)line_num, msg);
	return -1;
}

int
html_load_memory(struct html_output *output, const struct array data)
{
	return parse(output, data);
}

int
html_load_file(struct html_output *output, int fd)
{
	struct stat sb;
	size_t size = 0;
	void *p = MAP_FAILED;
	int ret = -1;

	if (fstat(fd, &sb)) {
		perror("open");
		goto error;
	}
	if (!S_ISREG(sb.st_mode)) {
		g_warning("not a regular file");
		goto error;
	}
	if (sb.st_size < 0 || sb.st_size + (size_t)0 >= (size_t)-1) {
		g_warning("file is too large");
		goto error;
	}
	size = sb.st_size;
	p = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == p) {
		perror("open");
		goto error;
	}
	close(fd);
	fd = -1;

	ret = html_load_memory(output, array_init(deconstify_gchar(p), size));

error:
	if (fd >= 0) {
		close(fd);
	}
	if (MAP_FAILED != p) {
		munmap(p, size);
	}
	return ret;
}

/* vi: set ts=4 sw=4 cindent: */
