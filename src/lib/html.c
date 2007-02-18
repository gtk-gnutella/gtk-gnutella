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
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static inline gboolean 
utf32_is_surrogate(guint32 cp)
{
  return cp > 0xd7ff && cp < 0xe000;
}

static inline gboolean
utf32_is_non_character(guint32 cp)
{
  return ((0xfffeU == (0xffeffffeU & cp) || (cp >= 0xfdd0U && cp <= 0xfdefU)));
}

static inline gboolean
utf32_is_valid(guint32 cp)
{
  return cp < 0x10ffffU && !utf32_is_non_character(cp);
}

static inline unsigned
utf8_encoded_len(guint32 cp)
{
  if (cp < 0x80U) {
    return 1;
  } else if (cp < 0x800U) {
    return 2;
  } else if (!utf32_is_valid(cp) || utf32_is_surrogate(cp)) {
    return 0;
  } else if (cp < 0x10000U) {
    return 3;
  } else {
    return 4;
  }
}

static inline unsigned
utf8_first_byte_length_hint(unsigned char ch)
{
  switch (ch & ~0x0fU) {
  case 0x00:
  case 0x10:
  case 0x20:
  case 0x30:
  case 0x40:
  case 0x50:
  case 0x60:
  case 0x70: return 1;
  case 0xc0: return ch >= 0xc2 ? 2 : 0;
  case 0xd0: return 2;
  case 0xe0: return 3;
  case 0xf0: return ch <= 0xf4 ? 4 : 0;
  default:   return 0;
  }
}

static inline gboolean
utf8_first_byte_valid(unsigned char ch)
{
  return 0 != utf8_first_byte_length_hint(ch);
}

static inline gboolean
utf8_first_bytes_valid(unsigned char ch1, unsigned char ch2)
{
  if (ch1 < 0x80) {
    return TRUE;
  } else if (0x80 == (ch2 & 0xc0)) {
    /* 0x80..0xbf */
    switch (ch1) {
    case 0xe0: return ch2 >= 0xa0;
    case 0xed: return ch2 <= 0x9f;
    case 0xf0: return ch2 >= 0x90;
    case 0xf4: return ch2 <= 0x8f;
    }
    return TRUE;
  }
  return FALSE;
}

/**
 * @return (guint32)-1 on failure. On success the decoded Unicode codepoint
 *         is returned.
 */
static inline guint32
utf8_decode(const char *src, size_t size)
{
  guint32 cp;
  unsigned n;

  if (0 == size)
    goto failure;

  cp = (unsigned char) *src;
  n = utf8_first_byte_length_hint(cp);
  if (1 != n) {
    unsigned char x;

    if (0 == n || n > size)
      goto failure;
    
    x = *++src;
    if (!utf8_first_bytes_valid(cp, x))
      goto failure;

    n--;
    cp &= 0x3f >> n;

    for (;;) {
      cp = (cp << 6) | (x & 0x3f);
      if (--n == 0)
        break;
      x = *++src;
      if (0x80 != (x & 0xc0))
        goto failure;
    }
    if (utf32_is_non_character(cp))
      goto failure;
  }
  return cp;

failure:
  return (guint32) -1;
}

static inline unsigned
utf8_encode(guint32 cp, char *buf)
{
  unsigned n = utf8_encoded_len(cp);

  if (n > 0) {
    static const unsigned char first_byte[] = {
      0xff, 0x00, 0xc0, 0xe0, 0xf0
    };
    unsigned i = n;

    while (--i > 0) {
      buf[i] = (cp & 0x3f) | 0x80;
      cp >>= 6;
    }
    buf[0] = cp | first_byte[n];
  }
  return n;
}


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
	void (*tag)(struct html_output *, enum html_tag, gboolean closing);
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
html_output_tag(struct html_output *output, enum html_tag tag, gboolean closing)
{
	if (output->tag)
		output->tag(output, tag, closing);
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
	void (*tag)(struct html_output *, enum html_tag, gboolean closing))
{
	output->tag = tag;
}


void *
html_output_get_udata(struct html_output *output)
{
	return output->udata;
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
		D(UL),
#undef D
	};
	size_t i, len;
	char name[16];

	STATIC_ASSERT(G_N_ELEMENTS(tab) == NUM_HTML_TAGS);
	
	len = 0;
	for (i = 0; i < tag.size; i++) {
		const unsigned char c = tag.data[i];

		if (len >= G_N_ELEMENTS(name))
			goto done;

		if (!isascii(c))
			goto done;

		if (0 == len) {
			if (isspace(c))
				continue;
			if ('/' == c && 0 == i)
				continue;
		}

		if (!isalnum(c))
			break;
		name[len] = isupper(c) ? c : toupper(c);
		len++;
	}

	if (len > 0) {
		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (strlen(tab[i].name) == len
			    && 0 == memcmp(tab[i].name, name, len)
			) {
				return tab[i].tag;
			}		
		}
		g_warning("Unknown tag: \"%.*s\"", (int)len, name);
	}
done:
	return HTML_TAG_UNKNOWN;
}

static void
render_tag(struct render_context *ctx, const struct array tag)
{
	enum html_tag id;
	const char *str;

	if (tag.size <= 0)
		return;

	ctx->closing = '/' == tag.data[tag.size - 1] || '/' == tag.data[0];
	id = parse_tag(tag);
	str = NULL;

	html_output_tag(ctx->output, id, ctx->closing);

	switch (id) {
	case HTML_TAG_PRE:
		ctx->preformatted = !ctx->closing;
		break;
	case HTML_TAG_A:
	case HTML_TAG_B:
	case HTML_TAG_BODY:
	case HTML_TAG_BR:
	case HTML_TAG_CODE:
	case HTML_TAG_COL:
	case HTML_TAG_DD:
	case HTML_TAG_DIV:
	case HTML_TAG_DL:
	case HTML_TAG_DT:
	case HTML_TAG_EM:
	case HTML_TAG_H1:
	case HTML_TAG_H2:
	case HTML_TAG_H3:
	case HTML_TAG_H4:
	case HTML_TAG_H5:
	case HTML_TAG_HEAD:
	case HTML_TAG_HR:
	case HTML_TAG_HTML:
	case HTML_TAG_I:
	case HTML_TAG_IMG:
	case HTML_TAG_KBD:
	case HTML_TAG_LI:
	case HTML_TAG_META:
	case HTML_TAG_OL:
	case HTML_TAG_P:
	case HTML_TAG_Q:
	case HTML_TAG_SPAN:
	case HTML_TAG_STRONG:
	case HTML_TAG_TABLE:
	case HTML_TAG_TBODY:
	case HTML_TAG_TD:
	case HTML_TAG_TH:
	case HTML_TAG_THEAD:
	case HTML_TAG_TITLE:
	case HTML_TAG_TR:
	case HTML_TAG_UL:
	case HTML_TAG_UNKNOWN:
		break;
	case NUM_HTML_TAGS:
		g_assert_not_reached();
	}
	if (str)
		html_output_print(ctx->output, array_from_string(str));
}

static guint32
parse_named_entity(const struct array entity)
{
	size_t i, len;
	char name[16];

	len = 0;
	for (i = 0; i < entity.size; i++) {
		const unsigned char c = entity.data[i];

		if (len >= G_N_ELEMENTS(name) - 1 || !isascii(c) || !isalnum(c))
			goto error;
		name[len] = isupper(c) ? c : toupper(c);
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
		unsigned char c;
		unsigned base;
		guint32 v;
		size_t i;

		i = 1;
		c = entity.data[i];
		if ('x' == c || 'X' == c) {
			base = 16;
			i++;
		} else {
			base = 10;
		}
		v = 0;
		for (/* NOTHING */; i < entity.size; i++) {
			static const char hexa[] = "0123456789abcdef";
			const char *p;

			c = entity.data[i];
			if (!isascii(c))
				goto error;
			p = memchr(hexa, tolower(c), sizeof hexa - 1);
			if (!p)
				goto error;
			c = p - hexa;
			if (c > base)
				goto error;

			v = v * 10 + c;
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
		} else if (isascii(c) && isalpha(c)) {
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
		if (!ctx->preformatted && isascii(c) && isspace(c)) {
			if (whitespace)
				continue;
			is_whitespace = TRUE;
			whitespace = TRUE;
			if (0x20 == c && i > 0 && i < text.size - c_len) {
				const unsigned char next_c = text.data[i + c_len];

				if (!(isascii(next_c) && isspace(next_c)))
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
			if (i > 0)
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
				msg = "'<' inside tag";
				goto error;
			}
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
			break;
			
		case '>':
			if (tag.data) {
				struct html_node *node;

				node = html_node_alloc();
				node->type = HTML_NODE_TAG;
				node->array = tag;
				node->next = NULL;
				nodes->next = node;
				nodes = node;
			} else {
				msg = "'>' but no open tag";
				goto error;
			}
			tag = zero_array;
			text = array_init(deconstify_gchar(next_ptr), 0); 
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
html_handle_file(struct html_output *output, int fd)
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
	ret = parse(output, array_init(deconstify_gchar(p), size));

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
