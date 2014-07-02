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

#include "common.h"

#include "ascii.h"
#include "fd.h"
#include "html.h"
#include "html_entities.h"
#include "misc.h"
#include "utf8.h"
#include "walloc.h"
#include "vmm.h"

#include "override.h"		/* Must be the last header included */

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
	struct html_node *node;

	WALLOC(node);
	*node = zero_html_node;
	return node;
}

static void
html_node_free(struct html_node **node_ptr)
{
	struct html_node *node = *node_ptr;
	if (node) {
		WFREE(node);
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
	bool preformatted;
	bool closing;
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

	WALLOC(output);
	*output = zero_output;
	return output;
}

void
html_output_free(struct html_output **output_ptr)
{
	struct html_output *output = *output_ptr;
	if (output) {
		WFREE(output);
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
		D(LANG),
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

	if (len > 0 && len < G_N_ELEMENTS(name)) {
		name[len] = '\0';
		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (0 == strcmp(name, tab[i].name))
				return tab[i].attr;
		}
		g_warning("%s(): unknown attribute: \"%s\"", G_STRFUNC, name);
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

	if (len > 0 && len < G_N_ELEMENTS(name)) {
		name[len] = '\0';
		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (0 == strcmp(name, tab[i].name))
				return tab[i].tag;
		}
		g_warning("%s(): unknown tag: \"%s\"", G_STRFUNC, name);
	}
	return HTML_TAG_UNKNOWN;
}

bool
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
			bool quoted = FALSE;
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
html_render_tag(struct render_context *ctx, const struct array tag)
{
	if (tag.size > 0) {
		ctx->closing = html_tag_is_closing(&tag);
		html_output_tag(ctx->output, tag);
		if (HTML_TAG_PRE == parse_tag(tag)) {
			ctx->preformatted = !ctx->closing;
		}
	}
}

static uint32
parse_named_entity(const struct array entity)
{
	size_t i, len;
	char name[16 + 2];

	if (entity.size >= G_N_ELEMENTS(name) - 2)
		goto error;

	len = 0;
	name[len++] = '&';

	for (i = 0; i < entity.size; i++) {
		const unsigned char c = entity.data[i];

		if (!is_ascii_alnum(c))
			goto error;
		name[len++] = c;
	}

	name[len++] = ';';
	name[len] = '\0';

	return html_decode_entity(name, NULL);

error:
	return -1;
}

static uint32
parse_numeric_entity(const struct array entity)
{
	size_t i = 0;

	if (i < entity.size && '#' == entity.data[i]) {
		unsigned base;
		uint32 v;

		i++;
		switch (entity.data[i]) {
		case 'x':
		case 'X':
			base = 16;
			i++;
			break;
		default:
			base = 10;
		}
		v = 0;
		while (i < entity.size) {
			unsigned d;
			
			d = hex2int_inline(entity.data[i++]);
			if (d >= base)
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

static uint32
html_parse_entity(const struct array entity)
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
html_render_entity(struct render_context *ctx, const struct array entity)
{
	uint32 c;

	c = html_parse_entity(entity);
	if ((uint32)-1 == c) {
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
html_render_text(struct render_context *ctx, const struct array text)
{
	unsigned c_len;
	size_t i;
	bool whitespace = FALSE;
	struct array entity, current;

	entity = zero_array;
	current = zero_array;

	for (i = 0; i < text.size; i += c_len) {
		const unsigned char c = text.data[i];
		bool is_whitespace;

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
				html_render_entity(ctx, entity);
			}
			entity.data = deconstify_gchar(&text.data[i + c_len]);
			entity.size = 0;
			continue;
		} else if (';' == c) {
			if (entity.data) {
				html_render_entity(ctx, entity);
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
html_render(struct render_context *ctx)
{
	const struct html_node *node;

	for (node = ctx->root; node != NULL; node = node->next) {	
		switch (node->type) {
		case HTML_NODE_ROOT:
			break;
		case HTML_NODE_TAG:
			html_render_tag(ctx, node->array);
			break;
		case HTML_NODE_TEXT:
			html_render_text(ctx, node->array);
			break;
		}
	}
}

static void
html_free(struct html_node *root)
{
	struct html_node *node, *next;

	for (node = root; NULL != node; node = next) {
		next = node->next;
		html_node_free(&node);
	}
}

static int
html_parse(struct html_output *output, const struct array array)
{
	size_t i, line_num;
	const char *msg;
	uint32 c;
	unsigned c_len;
	struct array tag, text;
	struct html_node *nodes, *root;

	line_num = 1;

	root = html_node_alloc();
	nodes = root;

	tag = zero_array;
	text = array_init(array.data, 0); 

	for (i = 0; i < array.size; i += c_len) {
		const char *next_ptr;

		c = utf8_decode(&array.data[i], i - array.size);
		if ((uint32)-1 == c) {
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
				text = array_init(next_ptr, 0); 
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
		html_render(&ctx);
	}

	html_free(root);
	return 0;

error:
	g_warning("line %zu: error: %s", line_num, msg);
	html_free(root);
	return -1;
}

int
html_load_memory(struct html_output *output, const struct array data)
{
	return html_parse(output, data);
}

int
html_load_file(struct html_output *output, int fd)
{
	filestat_t sb;
	size_t size = 0;
	void *p = MAP_FAILED;
	char *buf = NULL;
	int ret = -1;

	if (fstat(fd, &sb)) {
		perror("open");
		goto error;
	}
	if (!S_ISREG(sb.st_mode)) {
		g_warning("not a regular file");
		goto error;
	}
	if (sb.st_size < 0 || UNSIGNED(sb.st_size) >= (size_t)-1) {
		g_warning("file is too large");
		goto error;
	}
	size = sb.st_size;

#ifdef HAS_MMAP
	/* FIXME: Not available on MINGW! Replace with vmm_loadfile() */
	p = vmm_mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == p) {
		perror("open");
		goto error;
	}
	fd_forget_and_close(&fd);
#else
	{
		size_t left = size;

		buf = g_malloc(size);
		p = buf;

		while (left > 0) {
			ssize_t n = read(fd, &buf[size - left], left);
			if ((ssize_t) -1 == n || 0 == n)
				goto error;
			left -= n;
		}
	}
#endif

	ret = html_load_memory(output, array_init(p, size));

error:
	fd_forget_and_close(&fd);
	G_FREE_NULL(buf);

#ifdef HAS_MMAP
	if (MAP_FAILED != p) {
		vmm_munmap(p, size);
	}
#endif	/* HAS_MMAP*/

	return ret;
}

/* vi: set ts=4 sw=4 cindent: */
