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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup upnp
 * @file
 *
 * UPnP service discovery.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "service.h"

#include "if/gnet_property_priv.h"

#include "xml/vxml.h"
#include "xml/xnode.h"

#include "lib/atoms.h"
#include "lib/buf.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/nv.h"
#include "lib/once.h"
#include "lib/parse.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/tokenizer.h"
#include "lib/unsigned.h"
#include "lib/url.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static const char UPNP_SVC_NS[]			= "urn:schemas-upnp-org:service-1-0";
static const char UPNP_SVC_ACTIONLIST[] = "actionList";
static const char UPNP_SVC_ACTION[]		= "action";
static const char UPNP_SVC_NAME[]		= "name";

enum upnp_service_msgic { UPNP_SVC_DESC_MAGIC = 0x6c960b68U };

/**
 * A service description.
 */
struct upnp_service {
	enum upnp_service_msgic magic;
	enum upnp_service_type type;	/**< Service type */
	unsigned version;				/**< Service version */
	const char *control_url;		/**< Control URL (atom) */
	const char *scpd_url;			/**< SCPD URL (atom) */
	nv_table_t *api;				/**< The actions available in the API */
};

static inline void
upnp_service_check(const struct upnp_service * const usd)
{
	g_assert(usd != NULL);
	g_assert(UPNP_SVC_DESC_MAGIC == usd->magic);
}

/**
 * @return service type.
 */
enum upnp_service_type
upnp_service_type(const upnp_service_t *usd)
{
	upnp_service_check(usd);

	return usd->type;
}

/**
 * @return service version.
 */
unsigned
upnp_service_version(const upnp_service_t *usd)
{
	upnp_service_check(usd);

	return usd->version;
}

/**
 * @return service control URL.
 */
const char *
upnp_service_control_url(const upnp_service_t *usd)
{
	upnp_service_check(usd);

	return usd->control_url;
}

/**
 * @return Service Control Protocol Definition (SCPD) URL.
 */
const char *
upnp_service_scpd_url(const upnp_service_t *usd)
{
	upnp_service_check(usd);

	return usd->scpd_url;
}

/**
 * Allocate a new service description.
 *
 * The control URL is copied.
 *
 * @param type		service type
 * @param version	service version number
 * @param ctrl_url	control URL
 * @param scpd_url	SCPD URL
 */
static upnp_service_t *
upnp_service_alloc(enum upnp_service_type type, unsigned version,
	const char *ctrl_url, const char *scpd_url)
{
	upnp_service_t *usd;

	WALLOC0(usd);
	usd->magic = UPNP_SVC_DESC_MAGIC;
	usd->type = type;
	usd->version = version;
	usd->control_url = atom_str_get(ctrl_url);
	usd->scpd_url = atom_str_get(scpd_url);

	return usd;
}

/**
 * Free service description.
 */
static void
upnp_service_free(upnp_service_t *usd)
{
	upnp_service_check(usd);

	atom_str_free_null(&usd->control_url);
	atom_str_free_null(&usd->scpd_url);
	nv_table_free_null(&usd->api);
	usd->magic = 0;
	WFREE(usd);
}

/**
 * Maps a service type to a string.
 */
const char *
upnp_service_type_to_string(enum upnp_service_type type)
{
	g_assert(uint_is_non_negative(type) && type < UPNP_SCV_MAX);

	switch (type) {
	case UPNP_SVC_UNKNOWN:		return "Unknown";
	case UPNP_SVC_WAN_CIF:		return "WANCommonInterfaceConfig";
	case UPNP_SVC_WAN_IP:		return "WANIPConnection";
	case UPNP_SVC_WAN_PPP:		return "WANPPPConnection";
	case UPNP_SCV_MAX:
		g_assert_not_reached();
	}

	return NULL;
}

/**
 * Stringify an UPnP service.
 *
 * @return pointer to static buffer.
 */
const char *
upnp_service_to_string(const upnp_service_t *usd)
{
	buf_t *b = buf_private(G_STRFUNC, 128);

	upnp_service_check(usd);

	buf_printf(b, "\"%s\" v%u at %s",
		upnp_service_type_to_string(usd->type), usd->version, usd->control_url);

	return buf_data(b);
}

/**
 * Free list of upnp_service_t and nullify its pointer.
 */
void
upnp_service_pslist_free_null(pslist_t **list_ptr)
{
	pslist_t *list = *list_ptr;

	if (list != NULL) {
		pslist_t *sl;

		PSLIST_FOREACH(list, sl) {
			upnp_service_free(sl->data);
		}
		pslist_free(list);
		*list_ptr = NULL;
	}
}

/**
 * Lookup in the list of services for a specific service type.
 *
 * @return the first service matching the type requested, or NULL if there
 * are no such service offered.
 */
upnp_service_t *
upnp_service_pslist_find(pslist_t *services, enum upnp_service_type type)
{
	pslist_t *sl;

	PSLIST_FOREACH(services, sl) {
		upnp_service_t *usd = sl->data;

		upnp_service_check(usd);

		if (usd->type == type)
			return usd;
	}

	return NULL;
}

/**
 * Fetch WAN connection service (preferably IP, falling back on PPP).
 *
 * @return a WAN service if found, NULL if no such service is available.
 */
upnp_service_t *
upnp_service_get_wan_connection(pslist_t *services)
{
	upnp_service_t *usd;

	usd = upnp_service_pslist_find(services, UPNP_SVC_WAN_IP);
	if (NULL == usd)
		usd = upnp_service_pslist_find(services, UPNP_SVC_WAN_PPP);

	return usd;
}

/**
 * Fetch the common interface config service.
 *
 * @return a WAN_CIF service if found, NULL if no such service is available.
 */
upnp_service_t *
upnp_service_get_common_if(pslist_t *services)
{
	return upnp_service_pslist_find(services, UPNP_SVC_WAN_CIF);
}

/**
 * Known service types we can interact with.
 *
 * The leading "urn:" string is removed from the names since it is a
 * constant part.  The trailing ":<version>" is also removed since we are
 * identifying service types.
 */
static tokenizer_t upnp_services[] = {
	/* Sorted array */
	{ "schemas-upnp-org:service:WANCommonInterfaceConfig",	UPNP_SVC_WAN_CIF },
	{ "schemas-upnp-org:service:WANIPConnection",			UPNP_SVC_WAN_IP },
	{ "schemas-upnp-org:service:WANPPPConnection",			UPNP_SVC_WAN_PPP },
};

static once_flag_t upnp_services_checked;

static void G_COLD
upnp_services_check(void)
{
	TOKENIZE_CHECK_SORTED(upnp_services);
}

/**
 * Parse service type ("urn:schemas-dummy-com:service:Dummy:1").
 *
 * Extract the service type and version into supplied pointers.
 *
 * @param text		the service type string
 * @param type		where the type of service is written
 * @param version	where the service version is written
 *
 * @return TRUE if parsing was successful, FALSE otherwise
 */
static bool
upnp_service_parse_type(const char *text,
	enum upnp_service_type *type, unsigned *version)
{
	char *dtext = NULL;
	char *p;
	bool ok = FALSE;

	/*
	 * Before the trailing ':' we must find a valid version number.
	 */

	p = vstrrchr(text, ':');
	if (p != NULL) {
		uint32 v;
		int error;

		v = parse_uint32(p + 1, NULL, 10, &error);
		if (error)
			goto done;

		*version = v;
	} else {
		goto done;
	}

	/*
	 * Copy text and end string at the last ':'.
	 */

	dtext = h_strdup(text);
	p = dtext + (p - text);
	g_assert(':' == *p);
	*p = '\0';

	/*
	 * Skip the leading "urn:" prefix.
	 */

	p = is_strprefix(dtext, "urn:");
	if (NULL == p)
		goto done;

	/*
	 * Lookup the service type.
	 */

	ONCE_FLAG_RUN(upnp_services_checked, upnp_services_check);

	*type = TOKENIZE(p, upnp_services);
	ok = TRUE;

	/* FALL THROUGH */

done:
	HFREE_NULL(dtext);
	return ok;
}

/**
 * For each service in the list, adjust relative URLs to use the base URL,
 * if specified, otherwise the base of the description URL.
 *
 * @param services		the list of services
 * @param desc_url		description URL of the device
 * @param base_url		if non-NULL, base URL to use for relative URLs
 */
static void
upnp_service_adjust_urls(pslist_t *services,
	const char *desc_url, const char *base_url)
{
	pslist_t *sl;

	g_assert(desc_url != NULL);

	PSLIST_FOREACH(services, sl) {
		upnp_service_t *usd = sl->data;
		const char *base = base_url != NULL ? base_url : desc_url;
		char *absolute;

		upnp_service_check(usd);

		absolute = url_absolute_within(base, usd->control_url);
		if (absolute != usd->control_url) {
			atom_str_change(&usd->control_url, absolute);
			hfree(absolute);

			if (GNET_PROPERTY(upnp_debug) > 2) {
				g_debug("UPNP service with absolute URL is %s",
					upnp_service_to_string(usd));
			}
		}

		absolute = url_absolute_within(base, usd->scpd_url);
		if (absolute != usd->scpd_url) {
			atom_str_change(&usd->scpd_url, absolute);
			hfree(absolute);
		}
	}
}

/**
 * Context for service parsing.
 */
struct upnp_service_ctx {
	const char *desc_url;			/**< URL we got service info from */
	pslist_t *services;				/**< Services already parsed */
	const char *base_url;			/**< Base URL, if specified (atom) */
	/* Current service being analyzed */
	enum upnp_service_type type;	/**< Service type */
	unsigned version;				/**< Service version */
	const char *control_url;		/**< Control URL (atom) */
	const char *scpd_url;			/**< SCPD URL (atom) */
	unsigned in_service:1;			/**< Within a <service> tag? */
};

/**
 * Token IDs for service parsing.
 */
enum upnp_srvtok {
	UPNP_SRVTOK_URL_BASE = 1,		/* URLBase */
	UPNP_SRVTOK_SERVICE,			/* service */
	UPNP_SRVTOK_SERVICE_TYPE,		/* serviceType */
	UPNP_SRVTOK_CONTROL_URL,		/* controlURL */
	UPNP_SRVTOK_SCPD_URL			/* SCPDURL */
};

/**
 * Tokens for service parsing: elements which we are interested in.
 */
static struct vxml_token upnp_service_tokens[] = {
	{ "URLBase",		UPNP_SRVTOK_URL_BASE },
	{ "service",		UPNP_SRVTOK_SERVICE },
	{ "serviceType",	UPNP_SRVTOK_SERVICE_TYPE },
	{ "controlURL",		UPNP_SRVTOK_CONTROL_URL },
	{ "SCPDURL",		UPNP_SRVTOK_SCPD_URL },
};

/*
 * Start of tokenized element (XML parser callback).
 */
static void
upnp_service_xml_start(vxml_parser_t *vp,
	unsigned id, const xattr_table_t *attrs, void *data)
{
	struct upnp_service_ctx *ctx = data;

	(void) vp;
	(void) attrs;

	if (UPNP_SRVTOK_SERVICE == id)
		ctx->in_service = TRUE;
}

/*
 * Text within tokenized element (XML parser callback).
 */
static void
upnp_service_xml_text(vxml_parser_t *vp,
	unsigned id, const char *text, size_t len, void *data)
{
	struct upnp_service_ctx *ctx = data;

	(void) len;

	switch (id) {
	case UPNP_SRVTOK_URL_BASE:
		if (
			2 == vxml_parser_depth(vp) &&
			(0 == strcmp("root", vxml_parser_parent_element(vp)))
		) {
			if (!url_is_absolute(text)) {
				vxml_parser_error(vp, "URL base \"%s\" is not absolute", text);
				return;
			}
			atom_str_change(&ctx->base_url, text);
		}
		break;
	case UPNP_SRVTOK_SERVICE_TYPE:
		if (ctx->in_service) {
			if (!upnp_service_parse_type(text, &ctx->type, &ctx->version)) {
				if (GNET_PROPERTY(upnp_debug)) {
					g_warning("UPNP ignoring incorrect service \"%s\" from %s",
						text, ctx->desc_url);
				}
				ctx->type = UPNP_SVC_UNKNOWN;
			}
		}
		break;
	case UPNP_SRVTOK_CONTROL_URL:
		if (ctx->in_service) {
			atom_str_change(&ctx->control_url, text);
		}
		break;
	case UPNP_SRVTOK_SCPD_URL:
		if (ctx->in_service) {
			atom_str_change(&ctx->scpd_url, text);
		}
		break;
	default:
		break;
	}
}

/*
 * End of tokenized element (XML parser callback).
 */
static void
upnp_service_xml_end(vxml_parser_t *vp, unsigned id, void *data)
{
	struct upnp_service_ctx *ctx = data;

	(void) vp;

	if (UPNP_SRVTOK_SERVICE == id) {
		if (
			ctx->control_url != NULL &&
			ctx->scpd_url != NULL &&
			ctx->type != UPNP_SVC_UNKNOWN
		) {
			upnp_service_t *usd;

			usd = upnp_service_alloc(ctx->type, ctx->version,
				ctx->control_url, ctx->scpd_url);
			ctx->services = pslist_prepend(ctx->services, usd);

			if (GNET_PROPERTY(upnp_debug) > 1)
				g_debug("UPNP found service %s", upnp_service_to_string(usd));
		}

		ctx->type = UPNP_SVC_UNKNOWN;
		atom_str_free_null(&ctx->control_url);
		atom_str_free_null(&ctx->scpd_url);
		ctx->in_service = FALSE;
	}
}

/**
 * Callbacks used to parse services.
 */
static struct vxml_ops upnp_service_ops = {
	NULL,						/* plain_start */
	NULL,						/* plain_text */
	NULL,						/* plain_end */
	upnp_service_xml_start,		/* tokenized_start */
	upnp_service_xml_text,		/* tokenized_text */
	upnp_service_xml_end,		/* tokenized_end */
};

/**
 * Extract the available services from the UPnP device description.
 *
 * @param data		the XML payload data
 * @param len		length of the data
 * @param desc_url	the description URL from which the XML comes
 *
 * @return a list of upnp_service_t, NULL if no services were found.
 */
pslist_t *
upnp_service_extract(const char *data, size_t len, const char *desc_url)
{
	vxml_parser_t *vp;
	vxml_error_t e;
	struct upnp_service_ctx ctx;

	g_assert(data != NULL);
	g_assert(size_is_positive(len));
	g_assert(desc_url != NULL);

	vp = vxml_parser_make(desc_url, VXML_O_STRIP_BLANKS);
	vxml_parser_add_data(vp, data, len);

	ZERO(&ctx);
	ctx.desc_url = desc_url;		/* For logging */

	e = vxml_parse_callbacks_tokens(vp,
		&upnp_service_ops,
		upnp_service_tokens, N_ITEMS(upnp_service_tokens),
		&ctx);

	if (VXML_E_OK == e) {
		/*
		 * We wait until the end to adjust the relative URLs because there is
		 * no guarantee the base URL will be given before relative URLs are
		 * seen.  Although it would be logical, but the specifications do
		 * not mandate any order in the XML file.
		 */

		upnp_service_adjust_urls(ctx.services, desc_url, ctx.base_url);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP error parsing XML description from \"%s\": %s",
				desc_url, vxml_parser_strerror(vp, e));
		}
	}

	vxml_parser_free(vp);
	atom_str_free_null(&ctx.base_url);
	atom_str_free_null(&ctx.control_url);
	atom_str_free_null(&ctx.scpd_url);

	return ctx.services;
}

/**
 * Does service provide the action?
 */
bool
upnp_service_can(const upnp_service_t *usd, const char *action)
{
	upnp_service_check(usd);

	if (NULL == usd->api)
		return TRUE;			/* We don't know, assume it can */

	return NULL != nv_table_lookup(usd->api, action);
}

/**
 * Marks a given action as unsupported, despite it having been mentionned
 * in the SCPD (liar!, you copied and pasted a default SCPD from the specs?).
 */
void
upnp_service_cannot(upnp_service_t *usd, const char *action)
{
	upnp_service_check(usd);

	if (usd->api != NULL) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_carp("UPNP %s if not really supporting %s()",
				upnp_service_to_string(usd), action);
		}

		nv_table_remove(usd->api, action);
	}
}

/**
 * Is XML node an action name?
 */
static bool
node_is_action_name(const void *node, void *unused_data)
{
	const xnode_t *xn = node;
	const char *name = xnode_element_name(xn);
	const char *ns = xnode_element_ns(xn);

	(void) unused_data;

	if (NULL == name || NULL == ns || 0 != strcmp(name, UPNP_SVC_NAME))
		return FALSE;

	return 0 == strcmp(ns, UPNP_SVC_NS);
}

/**
 * Record action names that make up the service API.
 */
static void
upnp_service_add_action(void *node, void *data)
{
	xnode_t *xn = node;
	upnp_service_t *usd = data;
	const char *ns = xnode_element_ns(xn);
	const char *name = xnode_element_name(xn);
	xnode_t *aname;
	const char *action;

	upnp_service_check(usd);

	/*
	 * We're going to parse the <actionList> element that looks like:
	 *
	 *    <actionList>
	 *      <action>
	 *        <name>AddPortMapping</name>
	 *        ....
	 *      </action>
	 *      ...
	 *    </actionList>
	 *
	 * We're only interested in knowning the names of the services that
	 * are offered, so we fetch the <name> items that apply to each <action>.
	 */

	if (NULL == name || NULL == ns)
		return;

	if (0 != strcmp(name, UPNP_SVC_ACTION) || 0 != strcmp(ns, UPNP_SVC_NS))
		return;

	/*
	 * There are several items in the tree that bear the tag <name>, but the
	 * one we are interested in will be an immediate child of <action>.
	 */

	aname = xnode_tree_find_depth(xn, 1, node_is_action_name, NULL);

	if (NULL == aname)
		return;

	action = xnode_first_text(aname);
	if (NULL == action)
		return;

	/*
	 * Avoid duplicate actions.
	 */

	if (NULL != nv_table_lookup(usd->api, action))
		return;

	/*
	 * Found a new action name provided by this service.
	 */

	if (GNET_PROPERTY(upnp_debug)) {
		g_info("UPNP %s supports %s()", upnp_service_to_string(usd), action);
	}

	nv_table_insert_nocopy(usd->api, action, NULL, 0);
}

/**
 * Is XML node the root of the action list?
 */
static bool
node_is_actionlist(const void *node, void *unused_data)
{
	const xnode_t *xn = node;
	const char *name = xnode_element_name(xn);
	const char *ns = xnode_element_ns(xn);

	(void) unused_data;

	if (NULL == name || NULL == ns || 0 != strcmp(name, UPNP_SVC_ACTIONLIST))
		return FALSE;

	return 0 == strcmp(ns, UPNP_SVC_NS);
}

/**
 * Extract the service API from the SCPD XML tree.
 *
 * @param usd		the UPnP service
 * @param root		the root of the SCPD tree
 */
static void
upnp_service_scpd_extract(upnp_service_t *usd, xnode_t *root)
{
	xnode_t *actions;

	actions = xnode_tree_find_depth(root, 1, node_is_actionlist, NULL);

	if (NULL == actions) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP no <%s> element found in SCPD for %s",
				UPNP_SVC_ACTIONLIST, upnp_service_to_string(usd));
		}
		return;
	}

	if (NULL == usd->api)
		usd->api = nv_table_make(FALSE);

	xnode_tree_foreach_children(actions, upnp_service_add_action, usd);
}

/**
 * Parse the SCPD to get the service API.
 *
 * @param usd		the UPnP service
 * @param data		data making up the SCPD
 * @param len		data length
 */
void
upnp_service_scpd_parse(upnp_service_t *usd, const char *data, size_t len)
{
	vxml_parser_t *vp;
	vxml_error_t e;
	xnode_t *root;

	upnp_service_check(usd);
	g_assert(data != NULL);
	g_assert(size_is_non_negative(len));

	vp = vxml_parser_make("SCPD", VXML_O_STRIP_BLANKS);
	vxml_parser_add_data(vp, data, len);

	e = vxml_parse_tree(vp, &root);

	if (VXML_E_OK == e) {
		upnp_service_scpd_extract(usd, root);
		xnode_tree_free(root);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP error parsing XML description from \"%s\": %s",
				upnp_service_scpd_url(usd), vxml_parser_strerror(vp, e));
		}
	}

	vxml_parser_free(vp);
}

/* vi: set ts=4 sw=4 cindent: */
