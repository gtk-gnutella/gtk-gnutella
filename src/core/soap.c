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
 * @ingroup core
 * @file
 *
 * Simple Object Access Protocol (SOAP).
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "soap.h"
#include "http.h"
#include "sockets.h"
#include "version.h"

#include "if/gnet_property_priv.h"

#include "xml/vxml.h"
#include "xml/xfmt.h"
#include "xml/xnode.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/host_addr.h"
#include "lib/log.h"			/* For log_printable() */
#include "lib/misc.h"			/* For EMPTY_STRING() */
#include "lib/ostream.h"
#include "lib/parse.h"
#include "lib/pmsg.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

enum soap_rpc_magic { SOAP_RPC_MAGIC = 0x27b48f96U };

/**
 * A SOAP request.
 */
struct soap_rpc {
	enum soap_rpc_magic magic;
	const char *url;			/**< SOAP URL for request (atom) */
	const char *action;			/**< SOAP action to request (atom) */
	char *reply_data;			/**< The reply data we get back */
	size_t maxlen;				/**< Max length of data expected back */
	size_t content_len;			/**< Promised reply length, or maxlen if none */
	size_t reply_size;			/**< Size of the reply_data buffer */
	size_t reply_len;			/**< Length of the data in the reply */
	host_addr_t local_addr;		/**< Local IP address */
	http_async_t *ha;			/**< Underlying HTTP request */
	header_t *header;			/**< HTTP reply headers */
	cevent_t *delay_ev;			/**< Delay event */
	pmsg_t *mb;					/**< Payload data */
	soap_reply_cb_t reply_cb;	/**< Reply callback */
	soap_error_cb_t error_cb;	/**< Error callback */
	uint32 options;				/**< User-supplied options */
	int http_code;				/**< HTTP status code */
	void *arg;					/**< User-supplied callback argument */
	unsigned regular:1;			/**< Whether we sent a regular POST */
	unsigned mandatory:1;		/**< Whether we sent a mandatory POST */
	unsigned retry:1;			/**< Whether we should retry */
	unsigned got_local_addr:1;	/**< Whether we got the local IP address */
};

static inline void
soap_rpc_check(const struct soap_rpc * const sr)
{
	g_assert(sr != NULL);
	g_assert(SOAP_RPC_MAGIC == sr->magic);
}

#define SOAP_MAX_PAYLOAD	2048

static const char SOAP_CONTENT_TYPE[]	= "text/xml; charset=\"utf-8\"";
static const char SOAP_X_ENVELOPE[]		= "Envelope";
static const char SOAP_X_BODY[]			= "Body";
static const char SOAP_X_FAULT[]		= "Fault";
static const char SOAP_X_PREFIX[]		= "SOAP";
static const char SOAP_X_ENC_STYLE[]	= "encodingStyle";

static const char SOAP_NAMESPACE[] =
	"http://schemas.xmlsoap.org/soap/envelope/";
static const char SOAP_ENCODING[] =
	"http://schemas.xmlsoap.org/soap/encoding/";

/*
 * Possible Content-Type in replies indicating that we got XML to parse...
 */
static const char SOAP_TEXT_REPLY[]			= "text/xml";
static const char SOAP_APPLICATION_REPLY[]	= "application/soap+xml";

static void soap_rpc_launch(cqueue_t *cq, void *obj);

/**
 * Provides human-readable error string out of an error code.
 */
const char *
soap_strerror(soap_error_t errnum)
{
	switch (errnum) {
	case SOAP_E_OK:					return "OK";
	case SOAP_E_CANCELLED:			return "Cancelled by user";
	case SOAP_E_CONTACT:			return "HTTP establishment error";
	case SOAP_E_TIMEOUT:			return "HTTP timeout";
	case SOAP_E_TRANSPORT:			return "HTTP transport error";
	case SOAP_E_DATA2BIG:			return "Data exceeds maximum size";
	case SOAP_E_FAILED:				return "Request failed";
	case SOAP_E_FAULT:				return "SOAP fault";
	case SOAP_E_PROTOCOL:			return "SOAP protocol error";
	case SOAP_E_PROCESSING:			return "SOAP processing error";
	case SOAP_E_MAX:
		break;
	}

	return "Invalid SOAP error code";
}

/**
 * Allocate a new SOAP request.
 */
static soap_rpc_t *
soap_rpc_alloc(void)
{
	soap_rpc_t *sr;

	WALLOC0(sr);
	sr->magic = SOAP_RPC_MAGIC;

	return sr;
}

/**
 * Free a SOAP request.
 */
static void
soap_rpc_free(soap_rpc_t *sr)
{
	soap_rpc_check(sr);

	atom_str_free_null(&sr->url);
	atom_str_free_null(&sr->action);
	cq_cancel(&sr->delay_ev);
	http_async_cancel_null(&sr->ha);
	header_free_null(&sr->header);
	pmsg_free_null(&sr->mb);
	HFREE_NULL(sr->reply_data);

	sr->magic = 0;
	WFREE(sr);
}

/**
 * Signal an error to user and destroy SOAP request.
 */
static void
soap_error(soap_rpc_t *sr, soap_error_t err)
{
	soap_rpc_check(sr);

	if (sr->error_cb != NULL)
		(*sr->error_cb)(sr, err, NULL, sr->arg);

	soap_rpc_free(sr);
}

/**
 * Signal we got a reply from the SOAP request.
 */
static void
soap_reply(soap_rpc_t *sr, xnode_t *xn)
{
	soap_rpc_check(sr);

	if (sr->reply_cb != NULL)
		(*sr->reply_cb)(sr, xn, sr->arg);

	xnode_tree_free(xn);
	soap_rpc_free(sr);
}

/**
 * Signal an error to user and destroy SOAP request.
 */
static void
soap_fault(soap_rpc_t *sr, xnode_t *xn)
{
	soap_rpc_check(sr);

	if (GNET_PROPERTY(soap_debug)) {
		g_warning("SOAP \"%s\" at \"%s\": got a SOAP fault:",
			sr->action, sr->url);
		xfmt_tree_dump(xn, stderr);
	}

	if (sr->error_cb != NULL)
		(*sr->error_cb)(sr, SOAP_E_FAULT, xn, sr->arg);

	xnode_tree_free(xn);
	soap_rpc_free(sr);
}

/**
 * Cancel a SOAP RPC.
 */
void
soap_rpc_cancel(soap_rpc_t *sr)
{
	soap_rpc_check(sr);

	soap_error(sr, SOAP_E_CANCELLED);
}

/**
 * Process the SOAP reply from the server.
 */
static void
soap_process_reply(soap_rpc_t *sr)
{
	const char *buf;
	vxml_parser_t *vp;
	vxml_error_t e;
	xnode_t *root = NULL;
	xnode_t *xn = NULL;
	const char *charset;

	soap_rpc_check(sr);

	if (sr->reply_len != 0 && (GNET_PROPERTY(soap_trace) & SOCK_TRACE_IN)) {
		g_debug("----Got SOAP HTTP reply data from %s:", sr->url);
		if (log_printable(LOG_STDERR)) {
			fwrite(sr->reply_data, sr->reply_len, 1, stderr);
			fputs("----End SOAP HTTP reply\n", stderr);
		}
	}

	if (GNET_PROPERTY(soap_debug) > 2) {
		g_debug("SOAP \"%s\" at \"%s\": processing reply (%zu byte%s) HTTP %d",
			sr->action, sr->url, sr->reply_len,
			1 == sr->reply_len ? "" : "s", sr->http_code);
	}

	/*
	 * If we got a 2xx reply, we need to parse up to the <Body> element
	 * and then pass up the remaining to the user for parsing specific
	 * elemnts accordingly.
	 *
	 * Other reply codes indicate an error.  On 4xx replies we may not
	 * have any XML to parse.  On 5xx replies, we should usually have
	 * a <Fault> indication under the <Body>.
	 *
	 * The strategy used here is to parse the XML reply into a tree and then
	 * analyse the tree, ignoring the HTTP status code which is redundant.
	 */

	buf = header_get(sr->header, "Content-Type");
	if (NULL == buf)
		goto no_xml;

	/*
	 * MIME type and subtypes are case-insensitive (see RFC 2616, section 3.7).
	 */

	if (
		!http_field_starts_with(buf, SOAP_TEXT_REPLY, FALSE) &&
		!http_field_starts_with(buf, SOAP_APPLICATION_REPLY, FALSE)
	) {
		if (GNET_PROPERTY(soap_debug)) {
			g_debug("SOAP \"%s\" at \"%s\": got unexpected Content-Type: %s",
				sr->action, sr->url, buf);
		}
		goto no_xml;
	}

	/*
	 * Extract charset if given.
	 */

	charset = http_parameter_get(buf, "charset");

	/*
	 * Parse the SOAP envelope.
	 */

	vp = vxml_parser_make(sr->action, VXML_O_STRIP_BLANKS);
	vxml_parser_add_data(vp, sr->reply_data, sr->reply_len);

	if (!vxml_parser_set_charset(vp, charset)) {
		g_warning("SOAP \"%s\" at \"%s\": ignoring unknown charset \"%s\"",
			sr->action, sr->url, charset);
	}

	e = vxml_parse_tree(vp, &root);
	vxml_parser_free(vp);

	if (e != VXML_E_OK) {
		if (GNET_PROPERTY(soap_debug)) {
			g_debug("SOAP \"%s\" at \"%s\": cannot parse XML reply: %s",
				sr->action, sr->url, vxml_strerror(e));
		}
		goto bad_xml;
	}

	g_assert(root != NULL);

	/*
	 * Make sure we got a SOAP reply.
	 */

	if (!xnode_is_element_named(root, SOAP_NAMESPACE, SOAP_X_ENVELOPE))
		goto not_soap;

	/*
	 * Look for the <SOAP:Body> element.
	 */

	for (xn = xnode_first_child(root); TRUE; xn = xnode_next_sibling(xn)) {
		if (NULL == xn || !xnode_within_namespace(xn, SOAP_NAMESPACE))
			goto bad_soap;
		if (0 == strcmp(SOAP_X_BODY, xnode_element_name(xn)))
			break;
	}

	/*
	 * Inspect the first child of the <SOAP:Body> element.
	 *
	 * If it's a <SOAP:Fault>, go process it and return an error.
	 * If it's another SOAP tag, we have an unknown structure.
	 * Otherwise it's the reply, for user code to handle.
	 */

	xn = xnode_first_child(xn);

	if (NULL == xn)
		goto bad_soap;

	if (xnode_is_element_named(xn, SOAP_NAMESPACE, SOAP_X_FAULT)) {
		xnode_detach(xn);
		soap_fault(sr, xn);
	} else if (xnode_within_namespace(xn, SOAP_NAMESPACE)) {
		goto bad_soap;
	} else {
		xnode_detach(xn);
		soap_reply(sr, xn);
	}

	xnode_tree_free(root);
	return;

not_soap:
	if (GNET_PROPERTY(soap_debug)) {
		g_debug("SOAP \"%s\" at \"%s\": unexpected root XML "
			"element <%s:%s>",
			sr->action, sr->url, EMPTY_STRING(xnode_element_ns(root)),
			xnode_element_name(root));
	}
	xnode_tree_free(root);
	/* FALL THROUGH */

no_xml:
	soap_error(sr, SOAP_E_PROTOCOL);
	return;

bad_soap:
	if (GNET_PROPERTY(soap_debug)) {
		g_debug("SOAP \"%s\" at \"%s\": unexpected XML structure",
			sr->action, sr->url);
	}
	if (GNET_PROPERTY(soap_debug) > 1) {
		g_debug("SOAP current node is %s", xnode_to_string(xn));
	}
	if (GNET_PROPERTY(soap_debug) > 2)
		xfmt_tree_dump(root, stderr);

	xnode_tree_free(root);
	/* FALL THROUGH */

bad_xml:
	soap_error(sr, SOAP_E_PROCESSING);
	return;
}

/**
 * HTTP async callback, invoked when all the headers have been read.
 *
 * @return TRUE if we can continue with the request.
 */
static bool
soap_header_ind(http_async_t *ha, header_t *header,
	int code, const char *message)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);
	const char *buf;

	soap_rpc_check(sr);
	g_assert(ha == sr->ha);

	if (GNET_PROPERTY(soap_debug) > 2) {
		g_debug("SOAP \"%s\" at \"%s\": got HTTP %d %s", sr->action, sr->url,
			code, message);
	}

	/*
	 * Grab local socket address if they are interested.
	 */

	if (sr->options & SOAP_RPC_O_LOCAL_ADDR)
		sr->got_local_addr = http_async_get_local_addr(ha, &sr->local_addr);

	/*
	 * If we sent a non-mandatory request and get a 405 "Method not allowed"
	 * error, retry with M-POST.  Likewise, a 510 "Not extended" reply is an
	 * invitation to use the HTTP Extension Framework (RFC 2774).
	 */

	if (
		(405 == code || 510 == code) &&
		!sr->mandatory && !sr->retry &&
		(sr->options & SOAP_RPC_O_MAN_RETRY)
	) {
		if (GNET_PROPERTY(soap_debug) > 1) {
			g_message("SOAP \"%s\" at \"%s\": will be retrying with M-POST",
				sr->action, sr->url);
		}
		sr->retry = TRUE;			/* Signal we should retry */
		http_async_cancel(ha);
		return FALSE;
	}

	/*
	 * If we sent a mandatory request, there needs to be an "Ext:" header
	 * in the reply to show that the mandatory request was understood as such.
	 */

	if (sr->mandatory && 200 == code) {
		const char *ext = header_get(header, "Ext");

		if (NULL == ext) {
			if (GNET_PROPERTY(soap_debug)) {
				g_warning("SOAP \"%s\" at \"%s\": M-POST not understood",
					sr->action, sr->url);
			}
			http_async_error(ha, HTTP_ASYNC_MAN_FAILURE);
			return FALSE;
		}
	}

	/*
	 * Save the HTTP headers and code to be able to analyze the reply payload.
	 *
	 * Since the option HTTP_O_READ_REPLY is used, we'll get the reply data
	 * from the server even if the status code is not 200 and we need to be
	 * able to differentiate between a success report and an error.
	 */

	sr->header = header_refcnt_inc(header);
	sr->http_code = code;

	/*
	 * See whether they advertise a Content-Length, which may not be the
	 * case if chunked transfer encoding is used for the reply.  In that
	 * case, we shall dynamically adjust the reception buffer size.
	 */

	buf = header_get(header, "Content-Length");
	if (buf != NULL) {
		uint32 len;
		int error;

		len = parse_uint32(buf, NULL, 10, &error);
		if (error) {
			if (GNET_PROPERTY(soap_debug)) {
				errno = error;
				g_warning("SOAP \"%s\" at \"%s\": "
					"cannot parse Content-Length header: "
					"value is \"%s\", error is %m",
					sr->action, sr->url, buf);
			}
			http_async_error(ha, HTTP_ASYNC_BAD_HEADER);
			return FALSE;
		}

		if (len > sr->maxlen) {
			http_async_error(ha, HTTP_ASYNC_DATA2BIG);
			return FALSE;
		}

		sr->content_len = len;
	}

	/*
	 * Allocate data buffer: either they advertised content length, or 1/16th
	 * of the maximum data length we accept to grab from the server.
	 */

	sr->reply_size = (buf != NULL) ? sr->content_len : (sr->maxlen >> 4);
	sr->reply_data = halloc(sr->reply_size);

	return TRUE;	/* OK, go on */
}

/**
 * HTTP async callback, invoked when new HTTP data is read.
 * The EOF condition is indicated by data being NULL.
 */
static void
soap_data_ind(http_async_t *ha, char *data, int len)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);
	size_t new_length;

	soap_rpc_check(sr);

	/*
	 * When data is NULL, we reached EOF and we're done.  Time to process
	 * the data we got back.
	 *
	 * The HTTP asynchronous handle is nullified since it is about to be
	 * closed by the HTTP layer upon return.
	 */

	if (NULL == data) {
		sr->ha = NULL;
		soap_process_reply(sr);
		return;
	}

	/*
	 * Ensure we don't get too much and resize the memory buffer where
	 * we store the reply if needed.
	 */

	new_length = size_saturate_add(sr->reply_len, len);

	if (new_length > sr->content_len) {
		http_async_error(ha, HTTP_ASYNC_DATA2BIG);
		return;
	}

	if (new_length > sr->reply_size) {
		size_t new_size = size_saturate_mult(sr->reply_size, 2);

		sr->reply_data = hrealloc(sr->reply_data, new_size);
		sr->reply_size = new_size;
	}

	/*
	 * Append new data.
	 */

	memcpy(&sr->reply_data[sr->reply_len], data, len);
	sr->reply_len = new_length;
}

/**
 * HTTP async callback, invoked on errors.
 */
static void
soap_error_ind(http_async_t *ha, http_errtype_t type, void *val)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);
	soap_error_t err = SOAP_E_OK;

	soap_rpc_check(sr);

	if (GNET_PROPERTY(soap_debug)) {
		http_async_log_error_dbg(ha, type, val, "SOAP",
			GNET_PROPERTY(soap_debug) > 1);
	}

	if (HTTP_ASYNC_ERROR == type) {
		switch (GPOINTER_TO_INT(val)) {
		case HTTP_ASYNC_CANCELLED:
			/*
			 * Retry with M-POST if cancelled with sr->retry set to TRUE.
			 */
			if (sr->retry) {
				g_assert(NULL == sr->delay_ev);
				sr->delay_ev = cq_main_insert(1, soap_rpc_launch, sr);

				if (GNET_PROPERTY(soap_debug) > 1) {
					g_message("SOAP \"%s\" at \"%s\": retrying with M-POST",
						sr->action, sr->url);
				}
			}
			break;		/* No callback on explicit user cancel */
		case HTTP_ASYNC_DATA2BIG:
			err = SOAP_E_DATA2BIG;
			break;
		case HTTP_ASYNC_CONN_TIMEOUT:
		case HTTP_ASYNC_TIMEOUT:
			err = SOAP_E_TIMEOUT;
			break;
		default:
			err = SOAP_E_TRANSPORT;
			break;
		}
	} else {
		err = SOAP_E_TRANSPORT;
	}

	if (err != SOAP_E_OK)
		soap_error(sr, err);
}

/**
 * Build our own HTTP request.
 *
 * See http_async_build_post_request() for the model and details about
 * the various parameters.
 *
 * @return length of generated request.
 */
static size_t
soap_build_request(const http_async_t *ha,
	char *buf, size_t len, const char *verb, const char *path,
	const char *content_type, size_t content_len)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);
	size_t rw;
	const char *fixed_header;

	soap_rpc_check(sr);
	g_assert(len <= INT_MAX);

	if (sr->options & SOAP_RPC_O_MAN_FORCE) {
		sr->mandatory = TRUE;
	} else if ((sr->options & SOAP_RPC_O_MAN_RETRY) && sr->regular) {
		sr->mandatory = TRUE;
	} else {
		sr->mandatory = FALSE;
		sr->regular = TRUE;
	}

	if (sr->options & SOAP_RPC_O_ALL_CAPS) {
		fixed_header =
			"ACCEPT-ENCODING: deflate\r\n"
			"CONNECTION: close\r\n"
			"CACHE-CONTROL: no-cache\r\n"
			"PRAGMA: no-cache\r\n";
	} else {
		fixed_header =
			"Accept-Encoding: deflate\r\n"
			"Connection: close\r\n"
			"Cache-Control: no-cache\r\n"
			"Pragma: no-cache\r\n";
	}

	if (sr->mandatory) {
		if (sr->options & SOAP_RPC_O_ALL_CAPS) {
			rw = str_bprintf(buf, len,
				"M-%s %s HTTP/1.1\r\n"
				"HOST: %s\r\n"
				"USER-AGENT: %s\r\n"
				"CONTENT-TYPE: %s\r\n"
				"CONTENT-LENGTH: %s\r\n"
				"%s"						/* Fixed header part */
				"MAN: \"%s\"; ns=01\r\n"
				"01-SOAPACTION: \"%s\"\r\n"
				"\r\n",
				verb, path,
				http_async_remote_host_port(ha),
				version_string, content_type, size_t_to_string(content_len),
				fixed_header, SOAP_NAMESPACE, sr->action);
		} else {
			rw = str_bprintf(buf, len,
				"M-%s %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: %s\r\n"
				"Content-Type: %s\r\n"
				"Content-Length: %s\r\n"
				"%s"						/* Fixed header part */
				"Man: \"%s\"; ns=01\r\n"
				"01-SOAPAction: \"%s\"\r\n"
				"\r\n",
				verb, path,
				http_async_remote_host_port(ha),
				version_string, content_type, size_t_to_string(content_len),
				fixed_header, SOAP_NAMESPACE, sr->action);
		}
	} else {
		if (sr->options & SOAP_RPC_O_ALL_CAPS) {
			rw = str_bprintf(buf, len,
				"%s %s HTTP/1.1\r\n"
				"HOST: %s\r\n"
				"USER-AGENT: %s\r\n"
				"CONTENT-TYPE: %s\r\n"
				"CONTENT-LENGTH: %s\r\n"
				"%s"						/* Fixed header part */
				"SOAPACTION: \"%s\"\r\n"
				"\r\n",
				verb, path,
				http_async_remote_host_port(ha),
				version_string, content_type, size_t_to_string(content_len),
				fixed_header, sr->action);
		} else {
			rw = str_bprintf(buf, len,
				"%s %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: %s\r\n"
				"Content-Type: %s\r\n"
				"Content-Length: %s\r\n"
				"%s"						/* Fixed header part */
				"SOAPAction: \"%s\"\r\n"
				"\r\n",
				verb, path,
				http_async_remote_host_port(ha),
				version_string, content_type, size_t_to_string(content_len),
				fixed_header, sr->action);
		}
	}

	return rw;
}

/**
 * Callback invoked when the HTTP header of the request has been sent.
 */
static void
soap_sent_head(const struct http_async *ha,
	const struct gnutella_socket *s, const char *req, size_t len,
	bool deferred)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);

	soap_rpc_check(sr);

	if (GNET_PROPERTY(soap_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent SOAP HTTP request%s to %s (%u bytes):",
			deferred ? " completely" : "",
			host_addr_port_to_string(s->addr, s->port), (unsigned) len);
		dump_string(stderr, req, len, "----");
	}
}

/**
 * Callback invoked when the HTTP data of the request have been sent.
 */
static void
soap_sent_data(const struct http_async *ha,
	const struct gnutella_socket *s, const char *data, size_t len,
	bool deferred)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);

	soap_rpc_check(sr);

	if (GNET_PROPERTY(soap_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent SOAP HTTP data%s to %s (%u bytes):",
			deferred ? " completely" : "",
			host_addr_port_to_string(s->addr, s->port), (unsigned) len);
		dump_string(stderr, data, len, "----");
	}
}

/**
 * Redefine callback invoked when we got the whole HTTP reply.
 */
static void
soap_got_reply(const http_async_t *ha,
	const struct gnutella_socket *s, const char *status, const header_t *header)
{
	soap_rpc_t *sr = http_async_get_opaque(ha);

	soap_rpc_check(sr);
	
	if (GNET_PROPERTY(soap_trace) & SOCK_TRACE_IN) {
		g_debug("----Got SOAP HTTP reply from %s:",
			host_addr_to_string(s->addr));
		if (log_printable(LOG_STDERR)) {
			fprintf(stderr, "%s\n", status);
			header_dump(stderr, header, "----");
		}
	}
}

/**
 * Delayed RPC start.
 */
static void
soap_rpc_launch(cqueue_t *cq, void *obj)
{
	soap_rpc_t *sr = obj;
	http_post_data_t post;

	soap_rpc_check(sr);

	cq_zero(cq, &sr->delay_ev);

	if (GNET_PROPERTY(soap_debug) > 4) {
		g_debug("SOAP \"%s\" at \"%s\": launching (%s)",
			sr->action, sr->url, sr->retry ? "retry" : "initial");
	}

	sr->reply_len = 0;		/* In case we retry, clear out older data */

	/*
	 * Launch the asynchronous POST request.
	 */

	post.content_type = SOAP_CONTENT_TYPE;
	post.data = pmsg_start(sr->mb);
	post.datalen = pmsg_size(sr->mb);
	post.data_free = NULL;
	post.data_free_arg = NULL;

	sr->ha = http_async_post(sr->url, &post, soap_header_ind,
				soap_data_ind, soap_error_ind);

	/*
	 * If we cannot create the HTTP request, it can be the URL is wrong,
	 * or no connection can be established to the host.  Hence it's a
	 * contacting error, not an I/O error at this stage.
	 */

	if (sr->ha == NULL) {
		if (GNET_PROPERTY(soap_debug)) {
			g_warning("SOAP cannot contact \"%s\": %s",
				sr->url, http_async_strerror(http_async_errno));
		}
		soap_error(sr, SOAP_E_CONTACT);
		return;
	}

	/*
	 * Customize the HTTP layer.
	 */

	http_async_set_opaque(sr->ha, sr, NULL);
	http_async_set_op_post_request(sr->ha, soap_build_request);
	http_async_set_op_headsent(sr->ha, soap_sent_head);
	http_async_set_op_datasent(sr->ha, soap_sent_data);
	http_async_set_op_gotreply(sr->ha, soap_got_reply);
	http_async_option_ctl(sr->ha, HTTP_O_READ_REPLY, HTTP_CTL_ADD);
}

/**
 * Initiate a SOAP remote procedure call.
 *
 * Call will be launched asynchronously, not immediately upon return so that
 * callbacks are never called on the same stack frame and to allow further
 * options to be set on the handle before the call begins.
 *
 * Initially the request is sent as a regular POST.  It is possible to force
 * the usage of the HTTP Extension Framework by using the SOAP_RPC_O_MAN_FORCE
 * option, in which case an M-POST will be sent with the proper SOAP Man:
 * header.  Finally, automatic retry of the request can be requested via the
 * SOAP_RPC_O_MAN_RETRY option: it will start with POST and switch to M-POST
 * on 405 or 510 errors.
 *
 * @param url		the HTTP URL to contact for the RPC
 * @param action	the SOAP action to perform
 * @param maxlen	maximum length of data we accept to receive
 * @param options	user-supplied options
 * @param xn		SOAP RPC data payload (XML tree root, will be freed)
 * @param soap_ns	requested SOAP namespace prefix, NULL to use default
 * @param reply_cb	callback to invoke when we get a reply
 * @param error_cb	callback to invoke on error
 * @param arg		additional user-defined callback parameter
 *
 * @return a SOAP RPC handle, NULL if the request cannot be initiated (XML
 * payload too large).  In any case, the XML tree is freed.
 */
soap_rpc_t *
soap_rpc(const char *url, const char *action, size_t maxlen, uint32 options,
	xnode_t *xn, const char *soap_ns,
	soap_reply_cb_t reply_cb, soap_error_cb_t error_cb, void *arg)
{
	soap_rpc_t *sr;
	xnode_t *root, *body;
	pmsg_t *mb;
	ostream_t *os;
	bool failed = FALSE;

	g_assert(url != NULL);
	g_assert(action != NULL);

	/*
	 * Create the SOAP XML request.
	 */

	root = xnode_new_element(NULL, SOAP_NAMESPACE, SOAP_X_ENVELOPE);
	xnode_add_namespace(root, soap_ns ? soap_ns : "SOAP", SOAP_NAMESPACE);
	xnode_prop_ns_set(root, SOAP_NAMESPACE, SOAP_X_ENC_STYLE, SOAP_ENCODING);

	body = xnode_new_element(root, SOAP_NAMESPACE, SOAP_X_BODY);
	xnode_add_child(body, xn);

	/*
	 * Serialize the XML tree to a PDU message buffer.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, SOAP_MAX_PAYLOAD);
	os = ostream_open_pmsg(mb);
	xfmt_tree(root, os, XFMT_O_NO_INDENT);

	if (!ostream_close(os)) {
		failed = TRUE;
		g_warning("SOAP unable to serialize payload within %d bytes",
			SOAP_MAX_PAYLOAD);
		if (GNET_PROPERTY(soap_debug) > 1)
			xfmt_tree_dump(root, stderr);
	}

	/*
	 * Free the XML tree, including the supplied user nodes.
	 */

	xnode_tree_free(root);

	if (failed) {
		pmsg_free(mb);
		return NULL;
	}

	/*
	 * Serialization of the XML payload was successful, prepare the
	 * asynchronous SOAP request.
	 */

	sr = soap_rpc_alloc();
	sr->url = atom_str_get(url);
	sr->action = atom_str_get(action);
	sr->maxlen = maxlen;
	sr->content_len = maxlen;		/* Until we see a Content-Length */
	sr->options = options;
	sr->mb = mb;
	sr->reply_cb = reply_cb;
	sr->error_cb = error_cb;
	sr->arg = arg;

	/*
	 * Make sure the error callback is not called synchronously, and give
	 * them time to supply other options after creating the request before
	 * it starts.
	 */

	sr->delay_ev = cq_main_insert(1, soap_rpc_launch, sr);

	return sr;
}

/**
 * If the SOAP_RPC_O_LOCAL_ADDR option was sepcified, fetch the local IP
 * address of the host into specified ``addrp''.
 *
 * @return TRUE if we successfully grabbed a local address.
 */
bool
soap_rpc_local_addr(const soap_rpc_t *sr, host_addr_t *addrp)
{
	if (sr->got_local_addr) {
		*addrp = sr->local_addr;		/* Struct copy */
		return TRUE;
	} else {
		return FALSE;
	}
}

/* vi: set ts=4 sw=4 cindent: */
