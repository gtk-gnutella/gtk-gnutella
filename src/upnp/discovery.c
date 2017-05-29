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
 * UPnP device discovery.
 *
 * @author Raphael Manfredi
 * @date 2010, 2012
 */

#include "common.h"

#ifdef I_NETDB
#include <netdb.h>		/* For getaddrinfo() */
#endif

#include "discovery.h"
#include "control.h"
#include "error.h"
#include "service.h"
#include "upnp.h"

#include "core/sockets.h"
#include "core/http.h"
#include "core/version.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/gnet_host.h"
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/host_addr.h"
#include "lib/htable.h"
#include "lib/misc.h"
#include "lib/parse.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define UPNP_PORT		1900
#define UPNP_MCAST_ADDR	"239.255.255.250"	/* Multicast address */
#define UPNP_XML_MAXLEN	65536

static htable_t *pending;		/**< Pending M-SEARCHes (socket -> upnp_mcb) */

enum upnp_mcb_magic { UPNP_MCB_MAGIC = 0x0fa85631U };

/**
 * An UPnP M-SEARCH callback descriptor.
 */
struct upnp_mcb {
	enum upnp_mcb_magic magic;		/**< magic */
	upnp_discover_cb_t cb;			/**< Completion callback */
	void *arg;						/**< User-defined callback parameter */
	struct gnutella_socket *s;		/**< Socket used to send/receive */
	cevent_t *timeout_ev;			/**< Callout queue timeout event */
	pslist_t *devices;				/**< List of upnp_dscv structs */
	pslist_t *upnp_rpcs;			/**< List of pending UPnP RPCs */
	unsigned pending_probes;		/**< Amount of pending HTTP probes */
	unsigned replies;				/**< Total amount of replies */
	unsigned valid;					/**< Total amount of valid replies */
};

static inline void
upnp_mcb_check(const struct upnp_mcb * const mcb)
{
	g_assert(mcb != NULL);
	g_assert(UPNP_MCB_MAGIC == mcb->magic);
	g_assert(mcb->cb != NULL);
	g_assert(mcb->s != NULL);
}

enum upnp_dscv_magic { UPNP_DSCV_MAGIC = 0x169f438bU };

/**
 * A discovered device / service who replied to an initial M-SEARCH
 * is probed to grab its service description and identify whether it will
 * be a suitable gateway for us to be able to install port mappings.
 */
struct upnp_dscv {
	enum upnp_dscv_magic magic;
	host_addr_t external_ip;	/**< Reported external IP address */
	const char *desc_url;		/**< Description URL (atom) */
	struct http_async *ha;		/**< Asynchronous HTTP request in progress */
	pslist_t *services;			/**< List of upnp_service_t discovered */
	unsigned major;				/**< UPnP architecture major */
	unsigned minor;				/**< UPnP architecture minor */
};

static inline void
upnp_dscv_check(const struct upnp_dscv * const ud)
{
	g_assert(ud != NULL);
	g_assert(UPNP_DSCV_MAGIC == ud->magic);
}

/**
 * Device probe context.
 */
struct upnp_dscv_context {
	struct upnp_mcb *mcb;		/**< The M-SEARCH context we're in */
	struct upnp_dscv *ud;		/**< The device being probed */
};

/**
 * Argumenent-less querying UPnP control request.
 */
typedef upnp_ctrl_t *(*upnp_argless_ctrl_t)(const upnp_service_t *usd,
	upnp_ctrl_cb_t cb, void *arg);

/**
 * Local control RPC context completion callback.
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param ud		discovered device to whom control RPC was sent
 *
 * @return TRUE if we can keep the device in our discovery list.
 */
typedef bool (*upnp_dscv_ctrl_cb_t)(
	int code, void *value, size_t size, struct upnp_dscv *ud);

static bool upnp_dscv_got_connection_type(
	int code, void *value, size_t size, struct upnp_dscv *ud);
static bool upnp_dscv_got_external_ip(
	int code, void *value, size_t size, struct upnp_dscv *ud);

/**
 * List of probes to perform on discovered devices.
 */
static struct upnp_dscv_ctrl {
	upnp_argless_ctrl_t ctrl;	/**< control request */
	upnp_dscv_ctrl_cb_t cb;		/**< request-specific callback */
} upnp_dscv_probes[] = {
	{ upnp_ctrl_GetConnectionTypeInfo,	upnp_dscv_got_connection_type },
	{ upnp_ctrl_GetExternalIPAddress,	upnp_dscv_got_external_ip },
};

/**
 * Device control RPC context.
 */
struct upnp_ctrl_context {
	upnp_ctrl_t *ucd;			/**< control request */
	struct upnp_mcb *mcb;		/**< search context it belongs to */
	struct upnp_dscv *ud;		/**< device to whom control was sent */
	upnp_service_t *usd;		/**< service to interact with */
	size_t probe_idx;			/**< next probe in upnp_dscv_probes[] */
};

/**
 * Device SCPD RPC context.
 */
struct upnp_scpd_context {
	struct upnp_mcb *mcb;		/**< search context it belongs to */
	struct upnp_dscv *ud;		/**< device to whom HTTP request was sent */
	pslist_t *services;			/**< services to fetch SCPDs for */
	struct http_async *ha;		/**< Asynchronous HTTP request in progress */
};

/**
 * Free the UPnP discovery description.
 */
static void
upnp_dscv_free(struct upnp_dscv *ud)
{
	upnp_dscv_check(ud);

	atom_str_free_null(&ud->desc_url);
	upnp_service_pslist_free_null(&ud->services);
	if (ud->ha != NULL)
		http_async_cancel(ud->ha);

	WFREE(ud);
}

/**
 * Free UPnP M-SEARCH callback descriptor.
 */
static void
upnp_mcb_free(struct upnp_mcb *mcb, bool in_shutdown)
{
	pslist_t *sl;

	upnp_mcb_check(mcb);

	if (in_shutdown) {
		(*mcb->cb)(NULL, mcb->arg);		/* Signal error / timeout */
	} else {
		htable_remove(pending, mcb->s);
	}

	PSLIST_FOREACH(mcb->upnp_rpcs, sl) {
		upnp_ctrl_t *ucd = sl->data;
		upnp_ctrl_cancel(ucd, !in_shutdown);
	}
	pslist_free_null(&mcb->upnp_rpcs);

	PSLIST_FOREACH(mcb->devices, sl) {
		struct upnp_dscv *ud = sl->data;
		upnp_dscv_free(ud);
	}
	pslist_free_null(&mcb->devices);

	cq_cancel(&mcb->timeout_ev);
	socket_free_null(&mcb->s);
	mcb->magic = 0;
	WFREE(mcb);
}

/**
 * After a probe update, check whether discovery is done.
 */
static void
upnp_dscv_updated(struct upnp_mcb *mcb)
{
	upnp_mcb_check(mcb);

	if (0 == mcb->pending_probes) {
		pslist_t *devlist = NULL;
		pslist_t *sl;

		if (GNET_PROPERTY(upnp_debug) > 3) {
			size_t count = pslist_length(mcb->devices);
			g_message("UPNP discovery completed: kept %zu device%s",
				count, plural(count));
		}

		/*
		 * Build retained device list, then invoke user callback.
		 */

		PSLIST_FOREACH(mcb->devices, sl) {
			struct upnp_dscv *ud = sl->data;
			upnp_device_t *udev;

			udev = upnp_dev_igd_make(ud->desc_url, ud->services,
				ud->external_ip, ud->major, ud->minor);

			devlist = pslist_prepend(devlist, udev);

			/*
			 * The service list is shallow-cloned by the IGD device we
			 * created above, so we must only free the list container,
			 * not the underlying objects.
			 *
			 * Do that now so that upnp_dscv_free() does not attempt
			 * to free the underlying objects as well.
			 */

			pslist_free_null(&ud->services);
		}

		/*
		 * It is up to the callback to free up the allocated device list.
		 */

		(*mcb->cb)(devlist, mcb->arg);
		upnp_mcb_free(mcb, FALSE);
	}
}

/**
 * Completion callback for upnp_ctrl_GetConnectionTypeInfo().
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param ud		the queried device
 *
 * @return TRUE if we can keep this device.
 */
static bool
upnp_dscv_got_connection_type(
	int code, void *value, size_t size, struct upnp_dscv *ud)
{
	struct upnp_GetConnectionTypeInfo *ret = value;

	g_assert(NULL == value || size == sizeof *ret);

	/*
	 * Make sure the device is an IGD capable of doing NAT.
	 */

	if (ret != NULL) {
		bool suitable;

		suitable = 0 == strcmp(ret->connection_type, upnp_igd_ip_routed());

		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_message("UPNP connection type of \"%s\" is %s (supports: %s): %s",
				ud->desc_url, ret->connection_type, ret->possible_types,
				suitable ? "OK" : "no NAT support");
		}

		return suitable;
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP device \"%s\" reports no connection type "
				"(error %d => \"%s\")",
				ud->desc_url, code, upnp_strerror(code));
		}
		return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

/**
 * Completion callback for upnp_ctrl_GetExternalIPAddress().
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param ud		the queried device
 *
 * @return TRUE if we can keep this device.
 */
static bool
upnp_dscv_got_external_ip(
	int code, void *value, size_t size, struct upnp_dscv *ud)
{
	struct upnp_GetExternalIPAddress *ret = value;

	g_assert(NULL == value || size == sizeof *ret);

	/*
	 * Make sure we did get a routable IP address, otherwise remove the device.
	 */

	if (ret != NULL) {
		bool routable;

		routable = host_addr_is_routable(ret->external_ip);

		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_message("UPNP external IP reported by \"%s\" is %s (%sroutable)",
				ud->desc_url, host_addr_to_string(ret->external_ip),
				routable ? "" : "non-");
		}

		if (!routable)
			return FALSE;
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP device \"%s\" reports no external IP "
				"(error %d => \"%s\")",
				ud->desc_url, code, upnp_strerror(code));
		}
		return FALSE;
	}

	/*
	 * We got a routable external IP address for the device.
	 */

	ud->external_ip = ret->external_ip;

	return TRUE;
}

static void upnp_dscv_scpd_iterate(struct upnp_scpd_context *uscpd);

/**
 * Got result of SCPD fetch for a service offered by the device.
 *
 * This is an http_async_wget() completion callback.
 */
static void
upnp_dscv_scpd_result(char *data, size_t len, int code,
	header_t *header, void *arg)
{
	struct upnp_scpd_context *uscpd = arg;
	struct upnp_dscv *ud = uscpd->ud;
	struct upnp_mcb *mcb = uscpd->mcb;
	upnp_service_t *usd;

	upnp_dscv_check(ud);
	upnp_mcb_check(mcb);
	g_assert(uint_is_positive(mcb->pending_probes));
	g_assert(uscpd->services != NULL);
	g_assert(ud->ha != NULL);		/* Pending HTTP request */

	mcb->pending_probes--;
	ud->ha = NULL;			/* Request ending with this callback */
	usd = uscpd->services->data;

	if (NULL == data) {
		g_warning("UPNP SCPD fetch \"%s\" failed (HTTP %d) for %s",
			upnp_service_scpd_url(usd), code,
			upnp_service_to_string(usd));
		goto next;
	}

	if (GNET_PROPERTY(upnp_debug) > 5) {
		g_debug("UPNP SCPD fetch \"%s\" returned %zu byte%s for %s",
			upnp_service_scpd_url(usd), len, plural(len),
			upnp_service_to_string(usd));
		if (GNET_PROPERTY(upnp_debug) > 8) {
			g_debug("UPNP got HTTP %u:", code);
			header_dump(stderr, header, "----");
		}
		if (len > 1U && GNET_PROPERTY(upnp_debug) > 9) {
			char *xml = xml_indent(data);
			g_debug("UPNP HTTP payload start:");
			fwrite(xml, strlen(xml), 1, stderr);
			g_debug("UPNP HTTP payload end (%zu bytes).", len);
			HFREE_NULL(xml);
		}
	}

	/*
	 * Parse the XML to extract the service API.
	 */

	upnp_service_scpd_parse(usd, data, len);

	/* FALL THROUGH */

next:
	HFREE_NULL(data);
	uscpd->services = pslist_remove(uscpd->services, usd);
	upnp_dscv_scpd_iterate(uscpd);

}

/**
 * Iterate to fetch SCPD for the next service listed.
 */
static void
upnp_dscv_scpd_iterate(struct upnp_scpd_context *uscpd)
{
	struct http_async *ha;
	const char *url;
	upnp_service_t *usd;
	struct upnp_dscv *ud = uscpd->ud;
	struct upnp_mcb *mcb = uscpd->mcb;

	upnp_dscv_check(ud);
	upnp_mcb_check(mcb);

	g_assert(NULL == ud->ha);		/* No pending HTTP request */

	/*
	 * If we exhausted the list of services to probe, we're done.
	 */

next:
	if (NULL == uscpd->services) {
		WFREE(uscpd);
		upnp_dscv_updated(mcb);
		return;
	}

	usd = uscpd->services->data;
	url = upnp_service_scpd_url(usd);

	ha = http_async_wget(url, UPNP_XML_MAXLEN, upnp_dscv_scpd_result, uscpd);

	if (NULL == ha) {
		g_warning("UPNP cannot fetch \"%s\": %s",
			url, http_async_strerror(http_async_errno));
		uscpd->services = pslist_remove(uscpd->services, usd);
		goto next;
	}

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_debug("UPNP getting SCPD [%s] from %s",
			upnp_service_to_string(usd), url);
	}

	ud->ha = ha;
	mcb->pending_probes++;
}

/**
 * Fetch the SCPD descriptions for all the services discovered on the device.
 *
 * @param mcb		the overall M-SEARCH context for discovered devices
 * @param ud		the device for which we want to fetch SCPDs
 */
static void
upnp_dscv_scpd_fetch(struct upnp_mcb *mcb, struct upnp_dscv *ud)
{
	struct upnp_scpd_context *uscpd;

	WALLOC0(uscpd);

	uscpd->mcb = mcb;
	uscpd->ud = ud;
	uscpd->services = pslist_copy(ud->services);

	upnp_dscv_scpd_iterate(uscpd);
}

static bool upnp_dscv_next_ctrl(struct upnp_ctrl_context *ucd_ctx);

/**
 * Completion callback for upnp_ctrl_*() routines launched through the
 * upnp_dscv_next_ctrl() wrapper.
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
static void
upnp_dscv_got_ctrl_reply(int code, void *value, size_t size, void *arg)
{
	struct upnp_ctrl_context *ucd_ctx = arg;
	struct upnp_dscv_ctrl *dc;
	upnp_ctrl_t *ucd;
	struct upnp_mcb *mcb;
	struct upnp_dscv *ud;
	upnp_dscv_ctrl_cb_t cb;

	g_assert(size_is_non_negative(ucd_ctx->probe_idx));
	g_assert(ucd_ctx->probe_idx < N_ITEMS(upnp_dscv_probes));

	dc = &upnp_dscv_probes[ucd_ctx->probe_idx++];

	ucd = ucd_ctx->ucd;			/* The UPnP RPC control request handle */
	mcb = ucd_ctx->mcb;			/* The search context we're in */
	ud = ucd_ctx->ud;			/* The UPnP device we queried */
	cb = dc->cb;				/* The request-specific callback */

	upnp_mcb_check(mcb);
	g_assert(uint_is_positive(mcb->pending_probes));

	mcb->pending_probes--;
	mcb->upnp_rpcs = pslist_remove(mcb->upnp_rpcs, ucd);

	/*
	 * Process the reply.
	 */

	if (!(*cb)(code, value, size, ud)) {
		/* SOAP error, remove the device */
		mcb->devices = pslist_remove(mcb->devices, ud);
		upnp_dscv_free(ud);
		goto done;
	}

	/*
	 * Move on to the next control probe if any left.
	 */

	if (N_ITEMS(upnp_dscv_probes) == ucd_ctx->probe_idx) {
		/*
		 * All probes were successful, so we have a device with which we
		 * can interact to do port mappings.
		 *
		 * We now need to fetch the SCPD URLs of the services to know for
		 * each service what is the appropriate web API.
		 */

		WFREE(ucd_ctx);
		upnp_dscv_scpd_fetch(mcb, ud);
	} else {
		if (upnp_dscv_next_ctrl(ucd_ctx))
			return;
	}

done:
	upnp_dscv_updated(mcb);
}

/**
 * Launch next argumentless control probe on discovered device, as listed
 * in the upnp_dscv_probes[] array.
 *
 * @return TRUE if we can launch the action, FALSE otherwise.
 */
static bool
upnp_dscv_next_ctrl(struct upnp_ctrl_context *ucd_ctx)
{
	struct upnp_dscv_ctrl *dc;
	struct upnp_mcb *mcb;

	g_assert(size_is_non_negative(ucd_ctx->probe_idx));
	g_assert(ucd_ctx->probe_idx <= N_ITEMS(upnp_dscv_probes));

	mcb = ucd_ctx->mcb;
	upnp_mcb_check(mcb);

	/*
	 * The index of the next command to launch is given by ucd_ctx->probe_idx.
	 */

	if (N_ITEMS(upnp_dscv_probes) == ucd_ctx->probe_idx)
		return FALSE;

	/*
	 * Launch the probe, recording the pending control action in the mcb.
	 */

	dc = &upnp_dscv_probes[ucd_ctx->probe_idx];

	ucd_ctx->ucd = (*dc->ctrl)(ucd_ctx->usd, upnp_dscv_got_ctrl_reply, ucd_ctx);

	if (NULL == ucd_ctx->ucd) {
		if (GNET_PROPERTY(upnp_debug))
			g_warning("UPNP cannot control \"%s\", discarding",
				ucd_ctx->ud->desc_url);
		WFREE(ucd_ctx);
		return FALSE;		/* Cannot interact with it */
	}

	mcb->pending_probes++;
	mcb->upnp_rpcs = pslist_prepend(mcb->upnp_rpcs, ucd_ctx->ucd);
	return TRUE;
}

/**
 * Got final probe status for a device.
 *
 * This is an http_async_wget() completion callback.
 */
static void
upnp_dscv_probed(char *data, size_t len, int code, header_t *header, void *arg)
{
	struct upnp_dscv_context *dctx = arg;
	struct upnp_dscv *ud;
	struct upnp_mcb *mcb;		/* The M-SEARCH context we're in */
	upnp_service_t *usd;
	char *buf;

	mcb = dctx->mcb;
	ud = dctx->ud;
	WFREE_NULL(dctx, sizeof *dctx);

	upnp_mcb_check(mcb);
	upnp_dscv_check(ud);

	g_assert(uint_is_positive(mcb->pending_probes));
	g_assert(ud->ha != NULL);

	mcb->pending_probes--;
	ud->ha = NULL;			/* Request ending with this callback */

	if (NULL == data) {
		g_warning("UPNP probe of \"%s\" failed (HTTP %d)", ud->desc_url, code);
		goto remove_device;
	}

	if (GNET_PROPERTY(upnp_debug) > 5) {
		g_debug("UPNP probe of \"%s\" returned %zu byte%s",
			ud->desc_url, len, plural(len));
		if (GNET_PROPERTY(upnp_debug) > 8) {
			g_debug("UPNP got HTTP %u:", code);
			header_dump(stderr, header, "----");
		}
		if (len > 1U && GNET_PROPERTY(upnp_debug) > 9) {
			char *xml = xml_indent(data);
			g_debug("UPNP HTTP payload start:");
			fwrite(xml, strlen(xml), 1, stderr);
			g_debug("UPNP HTTP payload end (%zu bytes).", len);
			HFREE_NULL(xml);
		}
	}

	/*
	 * Check the Server: header, which is going to be a string such as:
	 *
	 *	"OS/version, UPnP/major.minor, product/version"
	 *
	 * We want to make sure that the UPnP architecture supported by the
	 * device is compatible with ours.
	 *
	 * Some devices (e.g. the D-Link DI-520 wireless router) do not report
	 * any Server header, so we assume they support UPnP/1.0 when it's missing.
	 */

	buf = header_get(header, "Server");
	if (NULL == buf) {
		g_warning("UPNP probe reply for \"%s\" lacks Server header, "
			"assuming UPnP 1.0", ud->desc_url);
		ud->major = 1;
		ud->minor = 0;
	} else {
		const char *p = strstr(buf, "UPnP/");
		bool ok = FALSE;

		if (p != NULL) {
			unsigned major, minor;

			p = is_strprefix(p, "UPnP/");
			g_assert(p != NULL);
			if (0 == parse_major_minor(p, NULL, &major, &minor)) {
				if (major > UPNP_MAJOR) {
					g_warning("UPNP \"%s\" at unsupported UPnP architecture %u",
						ud->desc_url, major);
					goto remove_device;
				} else if (!uint_is_non_negative(minor - UPNP_MINOR)) {
					g_warning("UPNP \"%s\" at older UPnP architecture %u/%u",
						ud->desc_url, major, minor);
				}
				ok = TRUE;
				ud->major = major;
				ud->minor = minor;
			}
		}

		if (!ok) {
			g_warning("UPNP \"%s\" has unparseable UPnP architecture, "
				"assuming 1.0 is supported", ud->desc_url);
			ud->major = 1;
			ud->minor = 0;
		}
	}

	/*
	 * Make sure we got "text/xml" output.
	 */

	buf = header_get(header, "Content-Type");
	if (NULL == buf || !strtok_case_has(buf, ";", "text/xml")) {
		g_warning("UPNP probe of \"%s\" failed: did not get text/xml back",
			ud->desc_url);
		goto remove_device;
	}

	/*
	 * Parse the XML sent by the device.
	 */

	ud->services = upnp_service_extract(data, len, ud->desc_url);
	HFREE_NULL(data);

	/*
	 * If the services do not contain UPNP_SVC_WAN_CIF and at least one
	 * of UPNP_SVC_WAN_IP or UPNP_SVC_WAN_PPP, then it's no good to us.
	 */

	if (NULL == upnp_service_pslist_find(ud->services, UPNP_SVC_WAN_CIF)) {
		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_message("UPNP probed \"%s\" does not support the \"%s\" service",
				ud->desc_url, upnp_service_type_to_string(UPNP_SVC_WAN_CIF));
		}
		goto remove_device;
	}

	if (
		NULL == upnp_service_pslist_find(ud->services, UPNP_SVC_WAN_IP) &&
		NULL == upnp_service_pslist_find(ud->services, UPNP_SVC_WAN_PPP)
	) {
		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_message("UPNP probed \"%s\" lacks IP or PPP connection services",
				ud->desc_url);
		}
		goto remove_device;
	}

	if (GNET_PROPERTY(upnp_debug) > 2)
		g_info("UPNP probed \"%s\" offers the services we need with UPnP/%u.%u",
			ud->desc_url, ud->major, ud->minor);

	/*
	 * We found a suitable WAN device.
	 *
	 * Initiate the series of control probes described in upnp_dscv_probes[]
	 * to make sure the device is a proper Internet Gateway Device capable
	 * of doing NAT.
	 */

	usd = upnp_service_get_wan_connection(ud->services);

	g_assert(usd != NULL);		/* Device offers one of IP or PPP */

	{
		struct upnp_ctrl_context *ucd_ctx;

		WALLOC(ucd_ctx);
		ucd_ctx->mcb = mcb;
		ucd_ctx->ud = ud;
		ucd_ctx->usd = usd;
		ucd_ctx->probe_idx = 0;

		if (!upnp_dscv_next_ctrl(ucd_ctx))
			goto remove_device;
	}

done:
	upnp_dscv_updated(mcb);
	return;

remove_device:
	HFREE_NULL(data);
	mcb->devices = pslist_remove(mcb->devices, ud);
	upnp_dscv_free(ud);
	goto done;
}

/**
 * Notification from the socket layer that we got a new datagram.
 * If `truncated' is true, then the message was too large for the
 * socket buffer.
 */
static void
upnp_msearch_reply(const gnutella_socket_t *s,
	const void *data, size_t len, bool truncated)
{
	int code;
	header_t *header;
	char *location;
	char *st;
	struct upnp_mcb *mcb;
	struct upnp_dscv *udev;
	pslist_t *sl;

	/*
	 * Fetch UPnP discovery descriptor, attached to the socket.
	 */

	mcb = htable_lookup(pending, s);

	if (NULL == mcb) {
		g_warning("unexpected UPnP reply from %s",
			host_addr_to_string(s->addr));
		return;
	}

	mcb->replies++;

	/*
	 * Logging.
	 */

	if (GNET_PROPERTY(upnp_debug) > 5) {
		g_debug("UPNP %sM-SEARCH reply from %s",
			truncated ? "truncated " : "", host_addr_to_string(s->addr));
	}

	if (GNET_PROPERTY(http_trace) & SOCK_TRACE_IN) {
		g_debug("----Got HTTP reply (UDP) from %s (%zu bytes):",
			host_addr_to_string(s->addr), len);
		dump_string(stderr, data, len, "----");
	}

	/*
	 * Parse the HTTP reply we got via UDP.
	 */

	header = http_header_parse(data, len, &code, NULL, NULL, NULL, NULL);

	if (NULL == header)
		return;

	if (code != 200)
		goto done;

	/*
	 * RFC 2774 mandates the empty Ext: header (usually made non-cacheable via
	 * a 'Cache-Control: no-cache="Ext"' header line) in the response to
	 * show that the server did understand and obey to the mandatory extensions
	 * specified in Man: headers and is not replying mechanically without
	 * fully understanding the nature of the mandatory request.
	 */

	if (NULL == header_get(header, "Ext"))
		goto done;

	location = header_get(header, "Location");
	st = header_get(header, "ST");

	if (NULL == location || NULL == st)
		goto done;

	/*
	 * OK, we got a useable and valid reply to our M-SEARCH.
	 */

	if (GNET_PROPERTY(upnp_debug) > 5) {
		g_debug("UPNP M-SEARCH found \"%s\" at %s", st, location);
	}

	mcb->valid++;

	/*
	 * Record device, avoiding duplicates.
	 *
	 * The location URL identifies the device, and this is the string used
	 * to spot identical devices in the list.  We don't care about the
	 * search type which brought back a given device.
	 */

	PSLIST_FOREACH(mcb->devices, sl) {
		struct upnp_dscv *ud = sl->data;

		if (0 == strcmp(location, ud->desc_url))
			goto done;		/* Duplicate */
	}

	/*
	 * Found a new device on the network.
	 */

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_message("UPNP M-SEARCH discovered device %s", location);
	}

	/*
	 * Probe device to check whether it is connected and supports the
	 * services we're interested in.
	 */

	{
		struct upnp_dscv_context *dctx;
		struct http_async *ha;

		WALLOC0(udev);
		udev->magic = UPNP_DSCV_MAGIC;
		udev->desc_url = atom_str_get(location);

		WALLOC0(dctx);
		dctx->mcb = mcb;
		dctx->ud = udev;

		ha = http_async_wget(location, UPNP_XML_MAXLEN, upnp_dscv_probed, dctx);

		if (NULL == ha) {
			g_warning("UPNP cannot probe \"%s\": %s",
				location, http_async_strerror(http_async_errno));
			WFREE(dctx);
			upnp_dscv_free(udev);
			goto done;
		}

		udev->ha = ha;
	}

	/*
	 * Record the device.
	 */

	mcb->devices = pslist_prepend(mcb->devices, udev);
	mcb->pending_probes++;

done:
	header_free(header);
}

/**
 * Send M-SEARCH message to specified address.
 *
 * @param s			Socket on which message should be sent
 * @param addr		Address to which message should be sent
 * @param type		Type of device/service we're looking for
 * @param mx		Maximum waiting time, in seconds
 *
 * @return TRUE if message was successfully sent.
 */
static bool
upnp_msearch_send(struct gnutella_socket *s, host_addr_t addr,
	const char *type, unsigned mx)
{
	size_t len;
	gnet_host_t to;
	ssize_t r;
	char req[1536];

	/*
	 * Broadcast mandatory HTTP SEARCH request "ssdp:discover".
	 * Mandatory requests are described in RFC 2774: HTTP Extension Framework.
	 *
	 * The UPnP architecture specifications display HTTP examples with
	 * all-caps headers.  Since we can expect moronic implementations in
	 * the devices (with plain string comparisons instead of true parsing),
	 * it's best to adhere to the examples to maximize the success rate.
	 */

	len = str_bprintf(req, sizeof req,
		"M-SEARCH * HTTP/1.1\r\n"
		"HOST: " UPNP_MCAST_ADDR ":" STRINGIFY(UPNP_PORT) "\r\n"
		"USER-AGENT: %s\r\n"
		"MAN: \"ssdp:discover\"\r\n"	/* Mandatory extension name */
		"ST: %s\r\n"					/* Search type */
		"MX: %u\r\n"	/* Max wait time -- reply randomly within time range */
		"\r\n",
		version_short_string, type, mx);

	gnet_host_set(&to, addr, UPNP_PORT);
	r = s->wio.sendto(&s->wio, &to, req, len);

	if (UNSIGNED(r) != len) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP cannot send M-SEARCH for %s to %s: %s",
				type, host_addr_to_string(addr),
				-1 == r ? english_strerror(errno) : "Partial send");
		}
	} else {
		if (GNET_PROPERTY(upnp_debug) > 5) {
			g_debug("UPNP sent M-SEARCH (%zu bytes) for %s to %s",
				len, type, host_addr_to_string(addr));
		}
		if (GNET_PROPERTY(http_trace) & SOCK_TRACE_OUT) {
			g_debug("----Sent HTTP request (UDP) to %s (%zu bytes):",
				host_addr_port_to_string(addr, UPNP_PORT), len);
			dump_string(stderr, req, len, "----");
		}
	}

	return UNSIGNED(r) == len;
}

/**
 * Discovery timed out.
 */
static void
upnp_dscv_timeout(cqueue_t *cq, void *obj)
{
	struct upnp_mcb *mcb = obj;

	upnp_mcb_check(mcb);

	cq_zero(cq, &mcb->timeout_ev);

	/*
	 * If we already received one reply to our M-SEARCH, then it's OK and
	 * we need to continue the discovery process.  Otherwise, signal
	 * that we found nothing.
	 */

	if (mcb->devices != NULL)
		return;						/* OK, discovery in progress */

	if (GNET_PROPERTY(upnp_debug)) {
		g_warning("UPNP discovery timed out after %u repl%s",
			mcb->replies, plural_y(mcb->replies));
	}

	(*mcb->cb)(NULL, mcb->arg);		/* Signals timeout */
	upnp_mcb_free(mcb, FALSE);
}

/**
 * Initiate a discovery of all UPnP devices on the LAN network.
 * Upon completion, the callback is called with the results and the
 * user-supplied argument.
 *
 * @param timeout		timeout in milliseconds
 * @param cb			callback to invoke on completion / timeout
 * @param arg			user-defined callback argument
 */
void
upnp_discover(unsigned timeout, upnp_discover_cb_t cb, void *arg)
{
	static host_addr_t mcast;
	size_t devidx = 0;
	struct gnutella_socket *s;
	host_addr_t bind_addr;
	unsigned mx;
	struct upnp_mcb *mcb;
	bool sent = FALSE;
	static const char * const devlist[] = {
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"upnp:rootdevice",
	};

	if (!host_addr_initialized(mcast)) {
		mcast = host_addr_get_ipv4(string_to_ip(UPNP_MCAST_ADDR));
	}

	/*
	 * We discover even if UPnP support is disabled: we won't publish
	 * mappings via UPnP, but we want to know whether we have a UPnP
	 * device available.
	 */

	if (GNET_PROPERTY(upnp_debug) > 3) {
		g_message("UPNP initating discovery (timeout %u ms)", timeout);
	}

	/*
	 * Create anonymous socket to send/receive M-SEARCH messages.
	 */

	bind_addr = ipv4_unspecified;
	s = socket_udp_listen(bind_addr, 0, upnp_msearch_reply);

	if (NULL == s) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("unable to create anonymous UDP %s socket for "
				"UPnP discovery: %m",
				net_type_to_string(host_addr_net(bind_addr)));
		}
		goto failed;
	}

	mx = timeout / 1000;		/* Timeout in seconds */

#ifdef HAS_GETADDRINFO
	{
		struct addrinfo hints, *serv, *p;
		int r;

		ZERO(&hints);
		hints.ai_family = AF_INET;		/* IPv4 UDP socket */
		hints.ai_socktype = SOCK_DGRAM;

		r = getaddrinfo(UPNP_MCAST_ADDR, STRINGIFY(UPNP_PORT), &hints, &serv);
		if (r != 0) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP getaddrinfo(\"%s\", \"%d\") failed: %s",
					UPNP_MCAST_ADDR, UPNP_PORT, gai_strerror(r));
			}
			goto no_getaddrinfo;
		}


		for (p = serv; p != NULL; p = p->ai_next) {
			host_addr_t addr;

			addr = addrinfo_to_addr(p);

			while (devidx < N_ITEMS(devlist)) {
				const char *type = devlist[devidx++];

				if (upnp_msearch_send(s, addr, type, mx))
					sent = TRUE;
			}
		}

		freeaddrinfo(serv);
		goto broadcasted;
	}

#define LABEL(x) x:
#else	/* !HAS_GETADDRINFO */
#define LABEL(x)
#endif	/* HAS_GETADDRINFO */

LABEL(no_getaddrinfo)
	while (devidx < N_ITEMS(devlist)) {
		const char *type = devlist[devidx++];

		if (upnp_msearch_send(s, mcast, type, mx))
			sent = TRUE;
	}

LABEL(broadcasted)
	if (!sent) {
		socket_free_null(&s);
		g_warning("unable to broadcast any UPnP search request");
		goto failed;
	}

#undef LABEL

	/*
	 * Message was sent, wait for the answer(s).
	 */

	WALLOC0(mcb);
	mcb->magic = UPNP_MCB_MAGIC;
	mcb->cb = cb;
	mcb->arg = arg;
	mcb->s = s;
	mcb->devices = NULL;
	mcb->timeout_ev = cq_main_insert(timeout + 1000, upnp_dscv_timeout, mcb);

	htable_insert(pending, s, mcb);
	return;

	/*
	 * This is a synchronous callback, invoked before this function returns.
	 */
failed:
	(*cb)(NULL, arg);		/* Signal error / timeout */
}

/**
 * Initialize the UPnP discovery layer.
 */
void
upnp_discovery_init(void)
{
	pending = htable_create(HASH_KEY_SELF, 0);
}

static void
upnp_discovery_free_kv(const void *unused_key, void *val, void *unused_x)
{
	(void) unused_key;
	(void) unused_x;

	upnp_mcb_free(val, TRUE);
}

/*
 * Shutdown the UPnP discovery layer.
 */
void
upnp_discovery_close(void)
{
	htable_foreach(pending, upnp_discovery_free_kv, NULL);
	htable_free_null(&pending);
}

/* vi: set ts=4 sw=4 cindent: */
