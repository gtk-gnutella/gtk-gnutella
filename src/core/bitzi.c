/*
 * $Id$
 *
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
 *
 * Bitzi search code
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

#include "common.h"

#ifdef HAS_LIBXML2

RCSID("$Id$");

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "http.h"			/* http async stuff */
#include "bitzi.h"			/* bitzi metadata */

#include "lib/atoms.h"
#include "lib/misc.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"	/* Must be the last header included */

/*
 * Bitzi Meta-data structure
 *
 */

typedef struct {
    xmlChar	*judgement;
} bitzi_data_t;

/*
 * The bitzi_request_t structure ties together each Bitzi request
 * which are stored in the request queue.
 *
 */

typedef struct {
	guchar			*bitzi_url;		/* request URL */
	bitzi_data_t	*bitzi_data;	/* extracted data */
	guchar          *sha1;			/* The SHA1 atom */
	xmlParserCtxt	*ctxt;		   	/* libxml parser context */
} bitzi_request_t;

static GSList *bitzi_request_queue = NULL;

static bitzi_request_t	*current_bitzi_request = NULL;
static gpointer	 current_bitzi_request_handle;

static void process_meta_data(bitzi_request_t *request);

/**
 * Check whether we have requests pending.
 */
gboolean bitzi_has_pending(void)
{
	return current_bitzi_request != NULL;
}

/**
 * Populate callback: more data available. When called with 0 it stops
 * the parsing of the document tree.
 */
static void
bitzi_host_data_ind(gpointer handle, gchar *data, gint len)
{
	int result;

	if (len > 0) {
		g_message("bitzi_host_data_ind: %d bytes", len);
		result = xmlParseChunk(current_bitzi_request->ctxt, data, len, 0);

		if (result != 0)
			g_warning("bitzi_host_data_ind, bad xml result %d", result);
	} else {

		g_message("bitzi_host_data_ind: end of data (len=%d)", len);
		result = xmlParseChunk(current_bitzi_request->ctxt, data, 0, 1);

		if (result != 0)
			g_warning("bitzi_host_data_ind - end, bad xml result %d", result);

		/* process what we had and clear up */
		process_meta_data(current_bitzi_request);

		g_message("processed current_bitzi_request=%p", current_bitzi_request);

		current_bitzi_request = NULL;
		current_bitzi_request_handle = NULL;
	} 
}

/**
 * HTTP request is being stopped.
 */
static void
bitzi_host_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	g_warning("bitzi_host_error_ind: failed!");

	g_assert(handle == current_bitzi_request_handle);

	/* process what we had and clear up */
	process_meta_data(current_bitzi_request);

	current_bitzi_request = NULL;
	current_bitzi_request_handle = NULL;
}

/*
 * These XML parsing routines are hacked up versions of those from the
 * libxml2 examples.
 */


/**
 * Parse (and eventually fill in) the bitzi specific data.
 *
 * The fields are defined at: 
 *	schema: http://bitzi.com/developer/bitzi-ticket.rng
 *	notes: http://bitzi.com/openbits/datadump
 *
 * The ones we have most interest in are:
 *
 * 	bz:fileGoodness="2.1"
 * 	bz:fileJudgement="Complete"
 *
 * Although the other could be used to verify size data and such.
 */
static void
process_rdf_description(xmlNode *a_node, bitzi_data_t *data)
{
	xmlNode *cur_node = NULL;
	xmlAttr	*cur_attr = NULL;

	/* process the attributes of the rdf:Description element */
	for (cur_attr = a_node->properties; cur_attr; cur_attr = cur_attr->next) {

	  g_message("process_rdf_description (attributes): name %s, type %d",
			  cur_attr->name,
			  cur_attr->type);
  	}

	/* process all the child elements of rdf:Description */

	for (cur_node = a_node->children; cur_node; cur_node = cur_node->next) {

		g_message("process_rdf_description (children): name: %s, type %d",
				cur_node->name,
				cur_node->type);

	}
}

/**
 * Iterates through the XML/RDF ticket calling various process
 * functions to read the data into the bitzi_data_t.
 *
 * This function is recursive, if the element is not explicity know we
 * just recurse down a level.
 */
static void
process_bitzi_ticket(xmlNode * a_node, bitzi_data_t *data)
{
	xmlNode *cur_node = NULL;

	for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			g_message("node type: Element, name: %s, children %p",
				cur_node->name,cur_node->children);

			if (xmlStrcmp(cur_node->name, (const xmlChar *) "Description") == 0)
				process_rdf_description(cur_node, data);
			else
				process_bitzi_ticket(cur_node->children, data);
		}
	}
}


/**
 * Walk the parsed document tree and free up the data
 */
static void
process_meta_data(bitzi_request_t *request)
{
	xmlDoc	*doc = NULL; 	/* the resulting document tree */
	xmlNode	*root = NULL;
	int result;

	g_message("process_meta_data: %p", request);

	g_assert(request != NULL);

	/* get the document and free context */

	doc = request->ctxt->myDoc;
	result = request->ctxt->wellFormed;
	xmlFreeParserCtxt(request->ctxt);

	/* Now we can have a look at the data */
	if (!result) {
		g_message("process_meta_data: doc = %p, result = %d", doc, result);
	} else {

		/* this just dumps the data */

		root = xmlDocGetRootElement(doc);

		g_message("process_meta_data: root=%p",root);

		/* FIXME: allocate and pass bitzi_data_t when ready */
		process_bitzi_ticket(root, NULL);

		/* free it */
		xmlFreeDoc(doc);
	}

	/* free used memory by the request */
	g_free(request->bitzi_url);
	atom_sha1_free(request->sha1);
#if 0
	g_free(request->bitzi_data);
#endif /* 0 */

	wfree(request, sizeof(*request));

	/* set the next query up as a timeout */
	if (bitzi_request_queue != NULL) {
	  g_timeout_add(1 * 10000, (GSourceFunc) bitzi_metadata_query, NULL);
	}

}

/**
 * Send a meta-data query if none is currently active
 *
 * Called as a timeout or direct from the click events
 */
gboolean
bitzi_metadata_query(gpointer ptr)
{
	g_message("bitzi_metadata_query");

	if (current_bitzi_request == NULL && bitzi_request_queue != NULL) {
		current_bitzi_request = bitzi_request_queue->data;
		bitzi_request_queue = g_slist_remove(bitzi_request_queue,
				current_bitzi_request);

		/*
		 * Create the XML Parser
		 */

		current_bitzi_request->ctxt = xmlCreatePushParserCtxt(NULL, NULL,
				NULL, 0, current_bitzi_request->bitzi_url);

		g_assert(current_bitzi_request->ctxt!=NULL);

		/*
		 * Launch the asynchronous request and attach parsing
		 * information.
		 *
		 * We don't care about headers
		 */

		current_bitzi_request_handle = http_async_get(
			current_bitzi_request->bitzi_url, NULL,
			bitzi_host_data_ind, bitzi_host_error_ind);

		if (!current_bitzi_request_handle) {
			g_warning("could not launch a \"GET %s\" request: %s",
					current_bitzi_request->bitzi_url,
					http_async_strerror(http_async_errno));
		} else {
			g_message("bitzi_metadata_query: request %s launched",
					current_bitzi_request->bitzi_url);
		}

	}

	/* always dequeue the timeout */

	return FALSE;
}

/**
 * Queue on entry on the metadata search queue
 */
void bitzi_queue_metadata_search(guchar *sha1)
{
	bitzi_request_t	*request;

	g_assert(sha1 != NULL);

	request = walloc0(sizeof *request);
	request->sha1 = atom_sha1_get(sha1);
	request->bitzi_url = g_strdup_printf(
		"http://ticket.bitzi.com/rdf/urn:sha1:%s", sha1_base32(sha1));

	if (dbg)
		g_message("queue_metadat_search request=%s (%p)",
			request->bitzi_url, request->bitzi_url);

	bitzi_request_queue = g_slist_append(bitzi_request_queue, request);
}

#endif	/* HAS_LIBXML2 */

/* vi: set ts=4: */
