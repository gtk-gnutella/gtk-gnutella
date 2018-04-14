/*
 * Copyright (c) 2010, 2012 Raphael Manfredi
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
 * @ingroup upnp
 * @file
 *
 * UPnP service control.
 *
 * @author Raphael Manfredi
 * @date 2010, 2012
 */

#include "common.h"

#include "control.h"
#include "service.h"
#include "error.h"
#include "upnp.h"

#include "core/soap.h"

#include "if/gnet_property_priv.h"

#include "xml/xnode.h"
#include "xml/xfmt.h"

#include "lib/atoms.h"
#include "lib/nv.h"
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define UPNP_REPLY_MAXSIZE	16384

static const char UPNP_NS_BASE[]		= "urn:schemas-upnp-org:service:";
static const char UPNP_PREFIX[]			= "u";
static const char UPNP_SOAP_PREFIX[]	= "s";

static const char UPNP_NS_ERROR[]		= "urn:schemas-upnp-org:control-1-0";
static const char SOAP_FAULT_STRING[]	= "faultstring";
static const char SOAP_FAULT_CODE[]		= "faultcode";
static const char SOAP_FAULT_DETAIL[]	= "detail";
static const char SOAP_CLIENT_FAULT[]	= "Client";
static const char SOAP_UPNP_ERROR[]		= "UPnPError";
static const char UPNP_ERROR_CODE[]		= "errorCode";
static const char UPNP_ERROR_DESC[]		= "errorDescription";

static const char ARG_REMOTE_HOST[]		= "NewRemoteHost";
static const char ARG_EXTERNAL_PORT[]	= "NewExternalPort";
static const char ARG_PROTOCOL[]		= "NewProtocol";
static const char ARG_INTERNAL_PORT[]	= "NewInternalPort";
static const char ARG_INTERNAL_CLIENT[]	= "NewInternalClient";
static const char ARG_ENABLED[]			= "NewEnabled";
static const char ARG_PORTMAP_DESC[]	= "NewPortMappingDescription";
static const char ARG_LEASE_DURATION[]	= "NewLeaseDuration";

static const char EMPTY[]				= "";
static const char ZERO[]				= "0";
static const char ONE[]					= "1";

/**
 * Launch completion callback.
 *
 * This maps the returned name/value pairs from the SOAP request into
 * values in a structure, which is dynamically allocated by the callback
 * through walloc().
 *
 * @param ret		returned values, in an ordered name/value table
 * @param len_ptr	where callback must fill size of returned structure
 *
 * @return allocated structure to return to user, containing decompiled
 * returned values, or NULL if the values could not be processed correctly.
 */
typedef void *(*upnp_ctrl_launch_cb_t)(nv_table_t *ret, size_t *len_ptr);

enum upnp_ctrl_magic { UPNP_CTRL_MAGIC = 0x6fbd23b5 };

/**
 * UPnP control request descriptor.
 */
struct upnp_ctrl {
	enum upnp_ctrl_magic magic;
	const char *action;			/**< The SOAP action */
	soap_rpc_t *sr;				/**< SOAP request handle */
	upnp_ctrl_launch_cb_t lcb;	/**< Launch callback to handle replied values */
	upnp_ctrl_cb_t cb;			/**< User callback to invoke on control reply */
	void *cb_arg;				/**< Additional callback argument */
};

static inline void
upnp_ctrl_check(const struct upnp_ctrl * const ucd)
{
	g_assert(ucd != NULL);
	g_assert(UPNP_CTRL_MAGIC == ucd->magic);
}

/**
 * Free an UPnP control request.
 */
static void
upnp_ctrl_free(upnp_ctrl_t *ucd)
{
	upnp_ctrl_check(ucd);
	g_assert(NULL == ucd->sr);

	atom_str_free_null(&ucd->action);
	ucd->magic = 0;
	WFREE(ucd);
}

/**
 * Is XML node name matching?
 */
static bool
node_named_as(const void *node, void *data)
{
	const xnode_t *xn = node;
	const char *name = xnode_element_name(xn);

	return (name != NULL) ? 0 == strcmp(name, cast_to_char_ptr(data)) : FALSE;
}

/**
 * Extract information from SOAP fault tree.
 *
 * @param fault		the XML <Fault> tree
 * @param code		where UPnP error code is written, if non-NULL
 * @param error		where address of UPnP error string is written, if non-NULL
 *
 * @attention
 * The error string is pointing in the XML tree and will become invalid as
 * soon as the tree is freed so it needs to be duplicated if it must persist.
 *
 * @return TRUE if OK, FALSE on error.
 */
static bool
upnp_ctrl_extract_fault(xnode_t *fault, int *code, const char **error)
{
	xnode_t *fcode, *fstring, *detail, *uerror;
	const char *parse_error = NULL;

	g_assert(fault != NULL);

	/*
	 * The SOAP specification for the <faultcode> element are very bad.
	 * Indeed, the content is a string bearing the *prefix* of the SOAP
	 * namespace, which is completely arbitrary and not accessible at this
	 * level since all nodes are normalized with their namespace, the prefix
	 * string being irrelevant once parsing is done.  And namespace have no
	 * meaning in element *content*.
	 *
	 * Sure, we know we force the "s" prefix for SOAP, and most UPnP stacks
	 * are going to use that prefix as well, but matching the <faultcode>
	 * content to look for "s:Client" or "s:MustUnderstand" is just plain
	 * wrong, and a blatant encapsulation violation.
	 *
	 * So instead we look backwards in the string to find the first ':' and
	 * consider the tail part of the string, totally ignoring the prefix.
	 * That's a lousy parsing, but in practice it's going to work and should
	 * be safe since there's little choice anyway according to the SOAP
	 * specifications (meaning they could have just as well ignored the
	 * prefix in this string and just mandate "Client" or "MustUnderstand").
	 *
	 * Also note that <faultcode>, <faultstring> and <detail> elements are
	 * architected without any SOAP namespace.  That's surprising.
	 */

	fcode = xnode_tree_find_depth(fault, 1, node_named_as,
		deconstify_char(SOAP_FAULT_CODE));

	if (NULL == fcode) {
		parse_error = "cannot find <faultcode>";
		goto error;
	} else {
		const char *value;
		const char *name;

		value = xnode_first_text(fcode);
		if (NULL == value) {
			parse_error = "<faultcode> does not contain text";
			goto error;
		}

		/*
		 * We're only handling "Client" errors.
		 */

		name = strrchr(value, ':');
		if (NULL == name) {
			parse_error = "no ':' in fault code name";
			goto error;
		}

		name++;

		if (0 != strcmp(name, SOAP_CLIENT_FAULT)) {
			parse_error = "not a Client fault";
			goto error;
		}
	}

	/*
	 * Here is a sample fault tree from the UPnP 1.0 architecture:
	 *
	 * <s:Fault>
	 *   <faultcode>s:Client</faultcode>
	 *   <faultstring>UPnPError</faultstring>
	 *   <detail>
	 *     <UPnpError xmlns="urn:schemas-upnp-org:control-1-0">
	 *       <errorCode>error code</errorCode>
	 *       <errorDescription>error string</errorDescription>
	 *     </UPnPError>
	 *   </detail>
	 * <s:Fault>
	 *
	 * Note that the UPnP tags are in the "urn:schemas-upnp-org:control-1-0"
	 * namespace.
	 */

	fstring = xnode_tree_find_depth(fault, 1, node_named_as,
		deconstify_char(SOAP_FAULT_STRING));

	if (NULL == fstring) {
		parse_error = "no <faultstring> found";
		goto error;
	} else {
		const char *value;

		value = xnode_first_text(fstring);
		if (NULL == value) {
			parse_error = "<faultstring> does not contain text";
			goto error;
		}

		if (0 != strcmp(value, SOAP_UPNP_ERROR)) {
			parse_error = "<faultstring> is not an UPnP error";
			goto error;
		}
	}

	detail = xnode_tree_find_depth(fault, 1, node_named_as,
		deconstify_char(SOAP_FAULT_DETAIL));

	if (NULL == detail) {
		parse_error = "no <detail> found";
		goto error;
	}

	/*
	 * First child must be a <UPnpError> tag.
	 */

	uerror = xnode_first_child(detail);
	if (xnode_is_element_named(uerror, UPNP_NS_ERROR, SOAP_UPNP_ERROR)) {
		xnode_t *xn;

		if (code != NULL) {
			const char *value;
			int err;

			xn = xnode_tree_find_depth(uerror, 1,
				node_named_as, deconstify_char(UPNP_ERROR_CODE));

			if (NULL == xn) {
				parse_error = "no <errorCode> found";
				goto error;
			}

			value = xnode_first_text(xn);
			if (NULL == value) {
				parse_error = "<errorCode> doest not contain text";
				goto error;
			}

			*code = parse_uint32(value, NULL, 10, &err);
			if (err) {
				parse_error = "cannot parse <errorCode> value";
				goto error;
			}
		}

		if (error != NULL) {
			xn = xnode_tree_find_depth(uerror, 1,
				node_named_as, deconstify_char(UPNP_ERROR_DESC));

			*error = (NULL == xn) ? NULL : xnode_first_text(xn);
		}
	} else {
		parse_error = "no <UPnPError> found";
		goto error;
	}

	return TRUE;

error:
	if (GNET_PROPERTY(upnp_debug))
		g_warning("UPNP fault parsing error: %s", EMPTY_STRING(parse_error));

	return FALSE;
}

/**
 * Successful SOAP RPC reply callback.
 *
 * @param sr	the SOAP RPC request
 * @param root	XML tree of SOAP reply
 * @param arg	the UPnP control request
 */
static void
upnp_ctrl_soap_reply(const soap_rpc_t *sr, xnode_t *root, void *arg)
{
	upnp_ctrl_t *ucd = arg;
	xnode_t *xn;
	nv_table_t *nvt;
	void *reply;
	size_t reply_len;
	host_addr_t local_addr;
	int code;

	upnp_ctrl_check(ucd);

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_debug("UPNP got SOAP reply for %s", ucd->action);

		if (GNET_PROPERTY(upnp_debug) > 2)
			xfmt_tree_dump(root, stderr);
	}

	ucd->sr = NULL;		/* Done with SOAP request */

	if (soap_rpc_local_addr(sr, &local_addr))
		upnp_set_local_addr(local_addr);

	/*
	 * Decompile the returned values.
	 *
	 * <u:actionResponse xmlns:u="urn:schemas-upnp-org:service:serviceType:v">
	 *	 <arg1>out value1</arg1>
	 *	 <arg2>out value2</arg2>
	 *       :  :  :  :
	 *   <argn>out valuen</argn>
	 * </u:actionResponse>
	 *
	 * Values are inserted in name / value pairs: "arg1" -> "out value 1" and
	 * given to the launch callback for extracting and decompiling the values.
	 */

	nvt = nv_table_make(TRUE);

	for (xn = xnode_first_child(root); xn; xn = xnode_next_sibling(xn)) {
		nv_pair_t *nv;
		xnode_t *xt;

		if (!xnode_is_element(xn)) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP \"%s\" skipping XML node %s",
					ucd->action, xnode_to_string(xn));
			}
			continue;
		}

		xt = xnode_first_child(xn);

		if (NULL == xt || !xnode_is_text(xt)) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP \"%s\" bad child node %s in %s",
					ucd->action, xnode_to_string(xt), xnode_to_string2(xn));
			}
		} else {
			/*
			 * Name/value strings point in the tree, which is going to be
			 * alive for the duration of the processing, so we can use the
			 * strings without copying them.
			 */

			nv = nv_pair_make_static_str(
				xnode_element_name(xn), xnode_text(xt));

			nv_table_insert_pair(nvt, nv);

			if (xnode_next_sibling(xt) != NULL) {
				if (GNET_PROPERTY(upnp_debug)) {
					g_warning("UPNP \"%s\" content of %s is not pure text",
						ucd->action, xnode_to_string(xt));
				}
			}
		}
	}

	/*
	 * Attempt to decompile the replied values, if any are expected.
	 *
	 * Allocated data is done via walloc(), and the returned structure is flat.
	 * It will be freed after invoking the user callback.
	 */

	if (ucd->lcb != NULL) {
		reply = (*ucd->lcb)(nvt, &reply_len);
		code = NULL == reply ? UPNP_ERR_OK : UPNP_ERR_BAD_REPLY;
	} else {
		code = UPNP_ERR_OK;
		reply = NULL;
		reply_len = 0;
	}

	/*
	 * Let UPnP control invoker know about the result of the query.
	 */

	(*ucd->cb)(code, reply, reply_len, ucd->cb_arg);

	/*
	 * Done, final cleanup.
	 */

	WFREE_NULL(reply, reply_len);
	nv_table_free(nvt);
	upnp_ctrl_free(ucd);
}

/**
 * Callback invoked on SOAP error (or cancel).
 *
 * @param sr		the SOAP request
 * @param err		the SOAP error code
 * @paran fault		the XML tree root of fault description (may be NULL)
 * @param arg		user-supplied callback
 */
static void
upnp_ctrl_soap_error(const soap_rpc_t *sr,
	soap_error_t err, xnode_t *fault, void *arg)
{
	upnp_ctrl_t *ucd = arg;
	host_addr_t local_addr;
	int code = UPNP_ERR_SOAP;

	upnp_ctrl_check(ucd);

	if (GNET_PROPERTY(upnp_debug)) {
		g_message("UPNP \"%s\" failed: %s", ucd->action, soap_strerror(err));
	}

	ucd->sr = NULL;		/* Done with SOAP request */

	if (soap_rpc_local_addr(sr, &local_addr))
		upnp_set_local_addr(local_addr);

	if (fault != NULL) {
		const char *error;

		if (upnp_ctrl_extract_fault(fault, &code, &error)) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_message("UPNP \"%s\" fault: %s (%d => \"%s\")",
					ucd->action, error, code, upnp_strerror(code));
			}
		} else {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP \"%s\" un-parseable SOAP fault:", ucd->action);
				xfmt_tree_dump(fault, stderr);
			}
			code = UPNP_ERR_UNPARSEABLE;
		}
	}

	if (ucd->cb != NULL)
		(*ucd->cb)(code, NULL, 0, ucd->cb_arg);

	upnp_ctrl_free(ucd);
}

/**
 * Cancel UPnP control request, optionally disabling UPnP callbacks.
 *
 * @param ucd		the UPnP request to cancel
 * @param callback	whether to invoke the completion callback
 */
void
upnp_ctrl_cancel(upnp_ctrl_t *ucd, bool callback)
{
	upnp_ctrl_check(ucd);
	g_return_if_fail(ucd->sr != NULL);

	/*
	 * Cancelling the SOAP RPC will trigger the upnp_ctrl_soap_error()
	 * callback with a SOAP_E_CANCELLED error, which will in turn invoke
	 * the error calback for the UPnP request and free up the descriptor.
	 */

	if (!callback)
		ucd->cb = NULL;		/* Disable callback in upnp_ctrl_soap_error() */

	soap_rpc_cancel(ucd->sr);
}

/**
 * Cancel UPnP control request, optionally disabling UPnP callbacks, and
 * nullify the control request pointer.
 */
void
upnp_ctrl_cancel_null(upnp_ctrl_t **ucd_ptr, bool callback)
{
	upnp_ctrl_t *ucd = *ucd_ptr;

	if (ucd != NULL) {
		upnp_ctrl_cancel(ucd, callback);
		*ucd_ptr = NULL;
	}
}

/**
 * Launch UPnP control request.
 *
 * The argv[] vector (with argc entries) contains the arguments and their
 * values to send to the remote UPnP device.
 *
 * If a structured reply is expected (and not just a returned status code),
 * a launch_cb callback must be provided to process the arguments returned
 * by the control request and populate a structure that will be passed to the
 * user callback to propagate the result of the control request.
 *
 * @param usd		the service to contact
 * @param action	the action to request
 * @param argv		the argument list for the request
 * @param argc		amount of arguments in argv[]
 * @param cb		user-callback when action is completed
 * @param cb_arg	additional callback argument
 * @param launch_cb	internal launch callback invoked on SOAP reply
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
static upnp_ctrl_t *
upnp_ctrl_launch(const upnp_service_t *usd, const char *action,
	nv_pair_t **argv, size_t argc, upnp_ctrl_cb_t cb, void *cb_arg,
	upnp_ctrl_launch_cb_t launch_cb)
{
	upnp_ctrl_t *ucd;
	xnode_t *root;
	size_t i;
	soap_rpc_t *sr;

	g_assert(usd != NULL);
	g_assert(action != NULL);
	g_assert(0 == argc || argv != NULL);

	WALLOC0(ucd);
	ucd->magic = UPNP_CTRL_MAGIC;
	ucd->lcb = launch_cb;
	ucd->cb = cb;
	ucd->cb_arg = cb_arg;

	/*
	 * The root element of the UPnP request.
	 *
	 * Its serialized form looks like this:
	 *
	 * <u:action xmlns:u="urn:schemas-upnp-org:service:serviceType:v">
	 *	 <arg1>in value1</arg1>
	 *	 <arg2>in value2</arg2>
	 *       :  :  :  :
	 *   <argn>in valuen</argn>
	 * </u:action>
	 *
	 * The "u" prefix is arbitrary but it is the one used in all examples
	 * presented in the UPnP architecture, and naive implementations within
	 * devices could choke on anything else.
	 */

	{
		char ns[256];

		str_bprintf(ARYLEN(ns), "%s%s:%u",
			UPNP_NS_BASE,
			upnp_service_type_to_string(upnp_service_type(usd)),
			upnp_service_version(usd));

		root = xnode_new_element(NULL, ns, action);
		xnode_add_namespace(root, UPNP_PREFIX, ns);
	}

	/*
	 * Attach each argument to the root.
	 */

	for (i = 0; i < argc; i++) {
		nv_pair_t *nv = argv[i];
		xnode_t *xargs;

		xargs = xnode_new_element(root, NULL, nv_pair_name(nv));
		xnode_new_text(xargs, nv_pair_value_str(nv), FALSE);
	}

	/*
	 * Launch the SOAP RPC.
	 *
	 * We force "s" as the SOAP prefix.  It shouldn't matter at all, but
	 * since the UPnP architecture documents its examples with "s", naive
	 * implementations in devices could choke on anything else.
	 *
	 * Likewise, since the UPnP architecture document uses all-caps HTTP header
	 * names, we can expect that some implementations within devices will
	 * not properly understand headers spelt with traditional mixed-cased,
	 * although it mentions that headers are case-insensitive names.  Hence,
	 * force all-caps header names.
	 *
	 * If the SOAP RPC cannot be launched (payload too large), the XML tree
	 * built above was freed anyway.
	 */

	{
		char action_uri[256];
		uint32 options = SOAP_RPC_O_MAN_RETRY | SOAP_RPC_O_ALL_CAPS;

		/*
		 * Grab our local IP address if it is unknown so far.
		 */

		if (host_addr_net(upnp_get_local_addr()) == NET_TYPE_NONE)
			options |= SOAP_RPC_O_LOCAL_ADDR;

		str_bprintf(ARYLEN(action_uri), "%s#%s",
			xnode_element_ns(root), action);

		ucd->action = atom_str_get(action_uri);

		sr = soap_rpc(upnp_service_control_url(usd), action_uri,
			UPNP_REPLY_MAXSIZE, options, root, UPNP_SOAP_PREFIX,
			upnp_ctrl_soap_reply, upnp_ctrl_soap_error, ucd);
	}

	/*
	 * We no longer need the arguments.
	 */

	for (i = 0; i < argc; i++) {
		nv_pair_free_null(&argv[i]);
	}

	/*
	 * Cleanup if we were not able to launch the request because the
	 * serialized XML payload is too large.
	 */

	if (NULL == sr) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP SOAP RPC \"%s\" to \"%s\" not launched: "
				"payload is too large", action, upnp_service_control_url(usd));
		}
		upnp_ctrl_free(ucd);
		return NULL;
	}

	ucd->sr = sr;		/* So that we may cancel it if needed */

	return ucd;
}

/**
 * Parse argument from specified name/value table into an IP address.
 *
 * @param nvt		the name/value table holding arguments
 * @param name		the argument name whose value we need to parse
 * @param addrp		where to put the parsed address
 *
 * @return TRUE if OK with the address filled in, FALSE on failure.
 */
static bool
upnp_ctrl_get_addr(nv_table_t *nvt, const char *name, host_addr_t *addrp)
{
	const char *ip;

	ip = nv_table_lookup_str(nvt, name);
	if (NULL == ip)
		return FALSE;

	return string_to_host_addr(ip, NULL, addrp);
}

/**
 * Parse argument from specified name/value table into an unsigned 16-bit int.
 *
 * @param nvt		the name/value table holding arguments
 * @param name		the argument name whose value we need to parse
 * @param valp		where to put the parsed value
 *
 * @return TRUE if OK with the value filled in, FALSE on failure.
 */
static bool
upnp_ctrl_get_uint16(nv_table_t *nvt, const char *name, uint16 *valp)
{
	const char *value;
	uint16 val;
	int error;

	value = nv_table_lookup_str(nvt, name);
	if (NULL == value)
		return FALSE;

	val = parse_uint16(value, NULL, 10, &error);
	if (error)
		return FALSE;

	*valp = val;
	return TRUE;
}

/**
 * Parse argument from specified name/value table into an unsigned 32-bit.
 *
 * @param nvt		the name/value table holding arguments
 * @param name		the argument name whose value we need to parse
 * @param valp		where to put the parsed value
 *
 * @return TRUE if OK with the value filled in, FALSE on failure.
 */
static bool
upnp_ctrl_get_uint32(nv_table_t *nvt, const char *name, uint32 *valp)
{
	const char *value;
	uint32 val;
	int error;

	value = nv_table_lookup_str(nvt, name);
	if (NULL == value)
		return FALSE;

	val = parse_uint32(value, NULL, 10, &error);
	if (error)
		return FALSE;

	*valp = val;
	return TRUE;
}

/**
 * Parse argument from specified name/value table into a time_delta_t.
 *
 * @param nvt		the name/value table holding arguments
 * @param name		the argument name whose value we need to parse
 * @param valp		where to put the parsed value
 *
 * @return TRUE if OK with the value filled in, FALSE on failure.
 */
static bool
upnp_ctrl_get_time_delta(nv_table_t *nvt, const char *name, time_delta_t *valp)
{
	uint32 val;

	if (upnp_ctrl_get_uint32(nvt, name, &val)) {
		*valp = val;
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Parse argument from specified name/value table into a boolean.
 *
 * @param nvt		the name/value table holding arguments
 * @param name		the argument name whose value we need to parse
 * @param valp		where to put the parsed value
 *
 * @return TRUE if OK with the boolean filled in, FALSE on failure.
 */
static bool
upnp_ctrl_get_boolean(nv_table_t *nvt, const char *name, bool *valp)
{
	const char *value;
	bool val;

	value = nv_table_lookup_str(nvt, name);
	if (NULL == value)
		return FALSE;

	if (0 == strcmp(value, ZERO))
		val = FALSE;
	else if (0 == strcmp(value, ONE))
		val = TRUE;
	else if (0 == strcasecmp(value, "false"))
		val = FALSE;
	else if (0 == strcasecmp(value, "true"))
		val = TRUE;
	else if (0 == strcasecmp(value, "no"))
		val = FALSE;
	else if (0 == strcasecmp(value, "yes"))
		val = TRUE;
	else
		return FALSE;

	*valp = val;
	return TRUE;
}

/**
 * Process returned value from GetExternalIPAddress().
 *
 * @return walloc()'ed structure (whose size is written in lenp) containing
 * the decompiled arguments, or NULL if the returned arguments cannot be
 * processed.
 */
static void *
upnp_ctrl_ret_GetExternalIPAddress(nv_table_t *ret, size_t *lenp)
{
	struct upnp_GetExternalIPAddress *r;
	host_addr_t addr;

	if (!upnp_ctrl_get_addr(ret, "NewExternalIPAddress", &addr))
		return NULL;

	WALLOC(r);
	r->external_ip = addr;
	*lenp = sizeof *r;

	return r;
}

/**
 * Get external IP address [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_GetExternalIPAddress(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg)
{
	return upnp_ctrl_launch(usd, "GetExternalIPAddress", NULL, 0, cb, arg,
		upnp_ctrl_ret_GetExternalIPAddress);
}

/**
 * Process returned value from GetConnectionTypeInfo().
 *
 * @return walloc()'ed structure (whose size is written in lenp) containing
 * the decompiled arguments, or NULL if the returned arguments cannot be
 * processed.
 */
static void *
upnp_ctrl_ret_GetConnectionTypeInfo(nv_table_t *ret, size_t *lenp)
{
	struct upnp_GetConnectionTypeInfo *r;
	const char *type, *possible;

	type = nv_table_lookup_str(ret, "NewConnectionType");
	if (NULL == type)
		return NULL;

	possible = nv_table_lookup_str(ret, "NewPossibleConnectionTypes");
	if (NULL == possible)
		return NULL;

	/*
	 * We can freely reference the memory from the name/value table since
	 * that table will remain alive until we are done with user notification.
	 */

	WALLOC(r);
	r->connection_type = type;
	r->possible_types = possible;

	*lenp = sizeof *r;

	return r;
}

/**
 * Get connection type information [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_GetConnectionTypeInfo(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg)
{
	return upnp_ctrl_launch(usd, "GetConnectionTypeInfo", NULL, 0, cb, arg,
		upnp_ctrl_ret_GetConnectionTypeInfo);
}

/**
 * Process returned value from GetSpecificPortMappingEntry().
 *
 * @return walloc()'ed structure (whose size is written in lenp) containing
 * the decompiled arguments, or NULL if the returned arguments cannot be
 * processed.
 */
static void *
upnp_ctrl_ret_GetSpecificPortMappingEntry(nv_table_t *ret, size_t *lenp)
{
	struct upnp_GetSpecificPortMappingEntry *r;
	host_addr_t addr;
	uint16 port;
	bool enabled;
	const char *description;
	time_delta_t lease;

	if (!upnp_ctrl_get_uint16(ret, ARG_INTERNAL_PORT, &port))
		return NULL;

	if (!upnp_ctrl_get_addr(ret, ARG_INTERNAL_CLIENT, &addr))
		return NULL;

	if (!upnp_ctrl_get_boolean(ret, ARG_ENABLED, &enabled))
		return NULL;

	description = nv_table_lookup_str(ret, ARG_PORTMAP_DESC);
	if (NULL == description)
		return NULL;

	if (!upnp_ctrl_get_time_delta(ret, ARG_LEASE_DURATION, &lease))
		return NULL;

	/*
	 * We can freely reference the memory from the name/value table since
	 * that table will remain alive until we are done with user notification.
	 */

	WALLOC(r);
	r->internal_port = port;
	r->internal_client = addr;
	r->enabled = enabled;
	r->description = description;
	r->lease_duration = lease;
	*lenp = sizeof *r;

	return r;
}

/**
 * Get information about a specific port mapping [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param proto		mapping protocol
 * @param port		the mapped external port for which we want the mapping
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_GetSpecificPortMappingEntry(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 port,
	upnp_ctrl_cb_t cb, void *arg)
{
	nv_pair_t *argv[3];
	char buf[UINT16_DEC_BUFLEN];
	const char *protocol;

	int32_to_string_buf(port, ARYLEN(buf));
	protocol = upnp_map_proto_to_string(proto);

	argv[0] = nv_pair_make_static_str(ARG_REMOTE_HOST, EMPTY);	/* Wildcard */
	argv[1] = nv_pair_make_static_str(ARG_EXTERNAL_PORT, buf);
	argv[2] = nv_pair_make_static_str(ARG_PROTOCOL, protocol);

	return upnp_ctrl_launch(usd, "GetSpecificPortMappingEntry",
		argv, N_ITEMS(argv), cb, arg,
		upnp_ctrl_ret_GetSpecificPortMappingEntry);
}

/**
 * Add a port forwarding (*:ext_port -> addr:port) [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param proto		mapping protocol
 * @param ext_port	the mapped external port for which we want the mapping
 * @param int_addr	the internal client address
 * @param int_port	the internal port for which we want the mapping
 * @param desc		comment description
 * @param lease		lease duration (0 = permanent)
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_AddPortMapping(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 ext_port,
	host_addr_t int_addr, uint16 int_port,
	const char *desc, time_delta_t lease,
	upnp_ctrl_cb_t cb, void *arg)
{
	nv_pair_t *argv[8];
	char ext_port_buf[UINT16_DEC_BUFLEN];
	char int_port_buf[UINT16_DEC_BUFLEN];
	char int_addr_buf[HOST_ADDR_BUFLEN];
	char lease_buf[UINT32_DEC_BUFLEN];
	const char *protocol;
	const char *description;

	g_assert(lease >= 0);
	g_assert(lease <= MAX_INT_VAL(int32));
	g_assert(ext_port != 0);
	g_assert(int_port != 0);

	int32_to_string_buf(ext_port, ARYLEN(ext_port_buf));
	int32_to_string_buf(int_port, ARYLEN(int_port_buf));
	host_addr_to_string_buf(int_addr, ARYLEN(int_addr_buf));
	protocol = upnp_map_proto_to_string(proto);
	int32_to_string_buf(lease, ARYLEN(lease_buf));
	description = str_smsg("%s (%s)", desc, protocol);

	argv[0] = nv_pair_make_static_str(ARG_REMOTE_HOST, EMPTY);	/* Wildcard */
	argv[1] = nv_pair_make_static_str(ARG_EXTERNAL_PORT, ext_port_buf);
	argv[2] = nv_pair_make_static_str(ARG_PROTOCOL, protocol);
	argv[3] = nv_pair_make_static_str(ARG_INTERNAL_PORT, int_port_buf);
	argv[4] = nv_pair_make_static_str(ARG_INTERNAL_CLIENT, int_addr_buf);
	argv[5] = nv_pair_make_static_str(ARG_ENABLED, ONE);		/* Enable! */
	argv[6] = nv_pair_make_static_str(ARG_PORTMAP_DESC, description);
	argv[7] = nv_pair_make_static_str(ARG_LEASE_DURATION, lease_buf);

	/*
	 * TODO: when talking to a v2 WANIPConnection service, we can use
	 * the AddAnyPortMapping() call.  This will require that GTKG maintains
	 * knowledge about the remote port so that it can advertise that remote
	 * port instead of the local listening port.
	 *
	 * Attempts must be made to get the same external port for both TCP and UDP,
	 * or this will create problems to servents assuming that they will always
	 * be identical (like GTKG does when it uses the TCP listening port of
	 * a remote host to send a push-proxy request via UDP)..
	 *		--RAM, 2011-01-18
	 */

	return upnp_ctrl_launch(usd, "AddPortMapping",
		argv, N_ITEMS(argv), cb, arg,
		NULL);
}

/**
 * Delete a port mapping [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param proto		mapping protocol
 * @param port		the mapped external port which we want to remove
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_DeletePortMapping(const upnp_service_t *usd,
	enum upnp_map_proto proto, uint16 port,
	upnp_ctrl_cb_t cb, void *arg)
{
	nv_pair_t *argv[3];
	char buf[UINT16_DEC_BUFLEN];
	const char *protocol;

	int32_to_string_buf(port, ARYLEN(buf));
	protocol = upnp_map_proto_to_string(proto);

	argv[0] = nv_pair_make_static_str(ARG_REMOTE_HOST, EMPTY);	/* Wildcard */
	argv[1] = nv_pair_make_static_str(ARG_EXTERNAL_PORT, buf);
	argv[2] = nv_pair_make_static_str(ARG_PROTOCOL, protocol);

	return upnp_ctrl_launch(usd, "DeletePortMapping",
		argv, N_ITEMS(argv), cb, arg,
		NULL);
}

/**
 * Process returned value from GetStatusInfo().
 *
 * @return walloc()'ed structure (whose size is written in lenp) containing
 * the decompiled arguments, or NULL if the returned arguments cannot be
 * processed.
 */
static void *
upnp_ctrl_ret_GetStatusInfo(nv_table_t *ret, size_t *lenp)
{
	struct upnp_GetStatusInfo *r;
	const char *status;
	time_delta_t uptime;

	status = nv_table_lookup_str(ret, "NewConnectionStatus");
	if (NULL == status)
		return NULL;

	if (!upnp_ctrl_get_time_delta(ret, "NewUptime", &uptime))
		return NULL;

	WALLOC(r);
	r->connection_status = status;
	r->uptime = uptime;
	*lenp = sizeof *r;

	return r;
}

/**
 * Get status information [IP or PPP connection].
 *
 * @param usd		the UPnP service to contact
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_GetStatusInfo(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg)
{
	return upnp_ctrl_launch(usd, "GetStatusInfo",
		NULL, 0, cb, arg,
		upnp_ctrl_ret_GetStatusInfo);
}

/**
 * Process returned value from GetTotalPacketsReceived().
 *
 * @return walloc()'ed structure (whose size is written in lenp) containing
 * the decompiled arguments, or NULL if the returned arguments cannot be
 * processed.
 */
static void *
upnp_ctrl_ret_GetTotalPacketsReceived(nv_table_t *ret, size_t *lenp)
{
	struct upnp_counter *r;
	uint32 value;

	if (!upnp_ctrl_get_uint32(ret, "NewTotalPacketsReceived", &value))
		return NULL;

	WALLOC(r);
	r->value = value;
	*lenp = sizeof *r;

	return r;
}

/**
 * Get amount of received packets [config interface].
 *
 * @param usd		the UPnP service to contact
 * @param cb		callback to invoke when reply is available
 * @param arg		additional callback argument
 *
 * @return UPnP request handle if the SOAP RPC was initiated, NULL otherwise
 * (in which case callbacks will never be called).
 */
upnp_ctrl_t *
upnp_ctrl_GetTotalPacketsReceived(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg)
{
	return upnp_ctrl_launch(usd, "GetTotalPacketsReceived", NULL, 0, cb, arg,
		upnp_ctrl_ret_GetTotalPacketsReceived);
}

/* vi: set ts=4 sw=4 cindent: */
