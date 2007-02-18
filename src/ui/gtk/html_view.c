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
 * @ingroup gtk
 * @file
 *
 * Simple HTML view.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "gui.h"

RCSID("$Id$")

#include "lib/glib-missing.h"
#include "lib/html.h"
#include "lib/misc.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

struct html_context {
	struct html_output *output;
	GString *text;
	enum html_tag tag;

#if GTK_CHECK_VERSION(2,0,0)
	GtkTextView *view;
	GtkTextBuffer *buffer;
	GtkTextIter iter;
	GtkTextMark *start[NUM_HTML_TAGS];
#else	/* Gtk+ < 2.0 */
	GtkText *view;
#endif	/* Gtk+ >= 2.0 */
};

static struct html_context *
html_context_alloc(void)
{
	static const struct html_context zero_html_context;
	struct html_context *ctx;

	ctx = walloc(sizeof *ctx);
	*ctx = zero_html_context;
	return ctx;
}

static void
html_context_free(struct html_context **ctx_ptr)
{
	struct html_context *ctx = *ctx_ptr;
	if (ctx) {
		html_output_free(&ctx->output);
		*ctx_ptr = NULL;
	}
}
	
static void
html_output_print(struct html_output *output, const struct array *text)
{
	struct html_context *ctx;
   
	ctx = html_output_get_udata(output);
	if (!ctx->text) {
		ctx->text = g_string_new("");
	}
	g_string_append_len(ctx->text, text->data, text->size);
}

static void
html_output_tag(struct html_output *output, enum html_tag tag, gboolean closing)
{
	static gboolean initialized;
	static gchar centre_line[5];
	static gchar list_item_prefix[7];
	struct html_context *ctx;
	const gchar *style, *text, *attr;
 
	if (!initialized) {
		static gchar bullet[5];

		initialized = TRUE;
		utf8_encode_char(locale_is_utf8() ? 0x2022 : 0x002D,
			bullet, sizeof bullet);
		utf8_encode_char(0xFE4E, centre_line, sizeof centre_line);
		concat_strings(list_item_prefix, sizeof list_item_prefix,
			" ", bullet, " ", (void *) 0);
	}
	
	style = NULL;
	text = NULL;
	attr = NULL;
	ctx = html_output_get_udata(output);
	ctx->tag = tag;

	switch (tag) {
	case HTML_TAG_BODY:
		style = "word_wrap";
		break;
	case HTML_TAG_A:
		style = "anchor";
		break;
	case HTML_TAG_B:
	case HTML_TAG_STRONG:
	case HTML_TAG_THEAD:
		style = "bold";
		break;
	case HTML_TAG_TH:
		if (closing)
			text = "\t";
		break;
	case HTML_TAG_EM:
	case HTML_TAG_DD:
		style = "underline";
		break;
	case HTML_TAG_I:
	case HTML_TAG_Q:
		style = "italic";
		break;
	case HTML_TAG_IMG:
		text = "\n[image]\n";
		attr = "bold";
		break;
	case HTML_TAG_TD:
		if (closing)
			text = "\t";
		break;
	case HTML_TAG_P:
	case HTML_TAG_DIV:
		text = closing ? "\n\n" : "\n";
		break;
	case HTML_TAG_DL:
	case HTML_TAG_TABLE:
	case HTML_TAG_TR:
	case HTML_TAG_UL:
	case HTML_TAG_OL:
	case HTML_TAG_BR:
		text = "\n";
		break;
	case HTML_TAG_DT:
	case HTML_TAG_LI:
		if (closing) {
			text = "\n";
		} else {
			text = list_item_prefix;
			attr = "bold";
		}
		break;
	case HTML_TAG_CODE:
	case HTML_TAG_KBD:
	case HTML_TAG_PRE:
		style = "monospace";
		break;
	case HTML_TAG_H1:
	case HTML_TAG_H2:
	case HTML_TAG_H3:
	case HTML_TAG_H4:
	case HTML_TAG_H5:
		style = "heading";
		text = closing ? "\n\n" : "\n";
		break;
	case HTML_TAG_TITLE:
		if (ctx->text) {
			GtkWidget *window;

			window = gtk_widget_get_toplevel(GTK_WIDGET(ctx->view));
			gtk_window_set_title(GTK_WINDOW(window), ctx->text->str);
			g_string_free(ctx->text, TRUE);
			ctx->text = NULL;
		}
		break;
	case HTML_TAG_HR:
#if GTK_CHECK_VERSION(2,0,0)
		ctx->start[tag] = gtk_text_buffer_create_mark(ctx->buffer, NULL,
								&ctx->iter, TRUE);
		gtk_text_buffer_insert_with_tags_by_name(ctx->buffer, &ctx->iter,
			centre_line, (-1), "center", (void *) 0);
		style = "heading";
		closing = TRUE;
		text = "\n";
#else
#endif
		break;
	case HTML_TAG_HTML:
	case HTML_TAG_HEAD:
	case HTML_TAG_META:
	case HTML_TAG_SPAN:
	case HTML_TAG_COL:
	case HTML_TAG_TBODY:
	case HTML_TAG_UNKNOWN:
		break;
	case NUM_HTML_TAGS:
		g_assert_not_reached();
	}

	if (ctx->text) {
#if GTK_CHECK_VERSION(2,0,0)
		gtk_text_buffer_insert(ctx->buffer, &ctx->iter,
			ctx->text->str, ctx->text->len);
#else
		{
			struct array str;

			if (locale_is_utf8()) {
				str = array_init(ctx->text->str, ctx->text->len);
			} else {
				str = array_from_string(lazy_utf8_to_ui_string(ctx->text->str));
			}
			gtk_text_insert(ctx->view, NULL, NULL, NULL, str.data, str.size);
		}
#endif

		g_string_free(ctx->text, TRUE);
		ctx->text = NULL;
	}
	if (style) {
		if (closing) {
#if GTK_CHECK_VERSION(2,0,0)
			GtkTextIter start;
		
			if (ctx->start[tag]) {
				gtk_text_buffer_get_iter_at_mark(ctx->buffer,
						&start, ctx->start[tag]);
				gtk_text_buffer_apply_tag_by_name(ctx->buffer, style,
						&start, &ctx->iter);
				ctx->start[tag] = NULL;
			}
#else
#endif
		} else {
#if GTK_CHECK_VERSION(2,0,0)
			ctx->start[tag] = gtk_text_buffer_create_mark(ctx->buffer, NULL,
								&ctx->iter, TRUE);
#else
#endif
		}
	}
	if (text) {
#if GTK_CHECK_VERSION(2,0,0)
		gtk_text_buffer_insert_with_tags_by_name(ctx->buffer, &ctx->iter,
			text, (-1), attr, (void *) 0);
#else
		gtk_text_insert(ctx->view, NULL, NULL, NULL, text, (-1));
#endif
	}
}

static struct html_context *
html_view_load(GtkWidget *widget)
{
	struct html_context *ctx;

	g_return_val_if_fail(widget, NULL);

	ctx = html_context_alloc();

#if GTK_CHECK_VERSION(2,0,0)
	ctx->view = GTK_TEXT_VIEW(widget);
	gtk_text_view_set_buffer(ctx->view, NULL);
	ctx->buffer = gtk_text_view_get_buffer(ctx->view);

	gtk_text_buffer_get_start_iter(ctx->buffer, &ctx->iter);

	gtk_text_buffer_create_tag(ctx->buffer, "word_wrap",
		"wrap_mode",		GTK_WRAP_WORD,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "monospace",
		"family",			"monospace",
		NULL);
	gtk_text_buffer_create_tag(ctx->buffer,	"anchor", 
		"foreground",		"blue", 
		"underline",		PANGO_UNDERLINE_SINGLE, 
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "bold",
		"weight",			PANGO_WEIGHT_BOLD,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "italic",
		"style",			PANGO_STYLE_ITALIC,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "center",
		"justification",	GTK_JUSTIFY_CENTER,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "underline",
		"underline",		PANGO_UNDERLINE_SINGLE,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "title",
		"justification",	GTK_JUSTIFY_CENTER,
		"weight",			PANGO_WEIGHT_BOLD,
		"size",				15 * PANGO_SCALE,
		(void *) 0);
	gtk_text_buffer_create_tag(ctx->buffer, "heading",
		"weight",			PANGO_WEIGHT_BOLD,
		"size",				15 * PANGO_SCALE,
		(void *) 0);


#else	/* Gtk+ < 2.0 */

	ctx->view = GTK_TEXT(widget);
	gtk_text_set_word_wrap(ctx->view, TRUE);
	
#endif	/* Gtk+ >= 2.0 */

	ctx->output = html_output_alloc();
	html_output_set_udata(ctx->output, ctx);
	html_output_set_print(ctx->output, html_output_print);
	html_output_set_tag(ctx->output, html_output_tag);

	return ctx;
}

void
html_view_load_file(GtkWidget *widget, int fd)
{
	struct html_context *ctx;

	g_return_if_fail(widget);
	g_return_if_fail(fd >= 0);
	
	ctx = html_view_load(widget);
	if (ctx) {
		html_load_file(ctx->output, fd);
		html_context_free(&ctx);
	}
}

void
html_view_load_memory(GtkWidget *widget, const struct array memory)
{
	struct html_context *ctx;
	
	g_return_if_fail(widget);
	g_return_if_fail(memory.data);

	ctx = html_view_load(widget);
	if (ctx) {
		html_load_memory(ctx->output, memory);
		html_context_free(&ctx);
	}
}

/* vi: set ts=4 sw=4 cindent: */
