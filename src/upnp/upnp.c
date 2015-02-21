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
 * Universal Plug and Play, for handling port mappings.
 *
 * We handle both UPnP and NAT-PMP here, and give preference to NAT-PMP if
 * supported because it is much more efficient in terms of resources.
 *
 * Conceptually, there are two different layers in this single file:
 *
 * - The port mapping layer (upnp_map_xxx() routines)
 * - The driver layers (UPnP and NAT-PMP)
 *
 * The port mapping layer sits on top of the other two and uses one of the
 * drivers to publish the mappings.
 *
 * @author Raphael Manfredi
 * @date 2010, 2012
 */

#include "common.h"

#include "upnp.h"
#include "control.h"
#include "discovery.h"
#include "error.h"
#include "natpmp.h"
#include "service.h"

#include "core/inet.h"			/* For inet_router_configured() */
#include "core/settings.h"		/* For listen_addr() */

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/hashing.h"
#include "lib/host_addr.h"
#include "lib/htable.h"
#include "lib/product.h"		/* For product_get_build() */
#include "lib/stacktrace.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For compact_time() and plural() */
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define UPNP_DISCOVERY_TIMEOUT	3000	/**< Timeout in ms */
#define UPNP_MONITOR_DELAY		300		/**< Every 5 minutes */
#define UPNP_CHECK_DELAY		1800	/**< Every 30 minutes */
#define UPNP_MAPPING_CAUTION	120		/**< 2 minutes */
#define UPNP_PUBLISH_RETRY		2		/**< 2 seconds */
#define UPNP_REDISCOVER			3600	/**< 1 hour (seconds) */

#define UPNP_MONITOR_DELAY_MS	(UPNP_MONITOR_DELAY * 1000)
#define UPNP_PUBLISH_RETRY_MS	(UPNP_PUBLISH_RETRY * 1000)
#define UPNP_CHECK_DELAY_MS		(UPNP_CHECK_DELAY * 1000)

#define UPNP_UNDEFINED_LEASE ((time_delta_t) -1)

/*
 * Monitoring calls we can use on the Internet Gateway Device.
 */
static const char UPNP_GET_TOTAL_RX_PACKETS[]	= "GetTotalPacketsReceived";
static const char UPNP_GET_STATUS_INFO[]		= "GetStatusInfo";

/**
 * The local Internet Gateway Device, for UPnP.
 */
static struct {
	upnp_device_t *dev;			/**< Our Internet Gateway Device */
	upnp_ctrl_t *monitor;		/**< Regular monitoring event */
	uint32 rcvd_pkts;			/**< Amount of received packets */
	unsigned delete_pending;	/**< Amount of pending mapping deletes */
	time_delta_t uptime;		/**< Connection uptime */
	unsigned discover:1;		/**< Force discovery again */
	unsigned discovery_done:1;	/**< Was discovery completed? */
	unsigned only_permanent:1;	/**< Only permanent mappings supported */
} igd;

/**
 * The local gateway, for NAT-PMP.
 */
static struct {
	natpmp_t *gateway;			/**< The NAT-PMP gateway */
	unsigned discover:1;		/**< Force discovery again */
	unsigned discovery_done:1;	/**< Was discovery completed? */
} gw;

/**
 * Method used to publish a port mapping.
 */
enum upnp_method {
	UPNP_M_ANY = 0,				/**< Not attempted or no success yet */
	UPNP_M_UPNP,				/**< UPnP */
	UPNP_M_NATPMP,				/**< NAT-PMP */
	
	UPNP_M_MAX
};

enum upnp_mapping_magic { UPNP_MAPPING_MAGIC = 0x463a8514 };

/**
 * A requested port-mapping.
 */
struct upnp_mapping {
	enum upnp_mapping_magic magic;
	enum upnp_map_proto proto;	/**< Network protocol used */
	enum upnp_method method;	/**< Method used to publish mapping */
	uint16 port;				/**< Port to map */
	cevent_t *install_ev;		/**< Periodic install event */
	upnp_ctrl_t *rpc;			/**< Pending control RPC */
	time_delta_t lease_time;	/**< Requested lease time */
	unsigned published:1;		/**< Was mapping successfully published? */
};

static inline void
upnp_mapping_check(const struct upnp_mapping * const um)
{
	g_assert(um != NULL);
	g_assert(UPNP_MAPPING_MAGIC == um->magic);
}

static htable_t *upnp_mappings;		/**< Tracks requested UPnP mappings */
static host_addr_t upnp_local_addr;	/**< Computed local IP address */

static const char UPNP_CONN_IP_ROUTED[]	= "IP_Routed";

static void upnp_map_publish_all(void);

/**
 * The state an Internet Gateway Device must be in to allow NAT.
 */
const char *
upnp_igd_ip_routed(void)
{
	return UPNP_CONN_IP_ROUTED;
}

/**
 * Do we have port mapping deletion in progress?
 */
bool
upnp_delete_pending(void)
{
	if (GNET_PROPERTY(shutdown_debug) > 1) {
		static time_t last;
		if (last != tm_time()) {
			unsigned nat = natpmp_pending();
			g_debug("SHUTDOWN %u pending IDG delete%s and %u NAT-PMP delete%s",
				igd.delete_pending, plural(igd.delete_pending),
				nat, plural(nat));
			last = tm_time();
		}
	}

	return igd.delete_pending != 0 || natpmp_pending();
}

/**
 * Builds a suitable description string for port mappings.
 *
 * @return pointer to static string.
 */
static const char *
upnp_mapping_description(void)
{
	static char buf[32];

	if ('\0' == buf[0])
		str_bprintf(buf, sizeof buf, "gtk-gnutella/r%u", product_get_build());

	return buf;
}

/**
 * Hash a UPnP mapping.
 */
static unsigned
upnp_mapping_hash(const void *p)
{
	const struct upnp_mapping *um = p;

	return integer_hash2(um->proto) ^ port_hash(um->port);
}

/**
 * Hash a UPnP mapping (secondary hash).
 */
static unsigned
upnp_mapping_hash2(const void *p)
{
	const struct upnp_mapping *um = p;

	return integer_hash(um->proto) ^ port_hash2(um->port);
}

/**
 * Equality testing for UPnP mappings.
 */
static int
upnp_mapping_eq(const void *a, const void *b)
{
	const struct upnp_mapping *uma = a;
	const struct upnp_mapping *umb = b;

	return uma->proto == umb->proto && uma->port == umb->port;
}

/**
 * Create a new UPnP mapping record.
 */
static struct upnp_mapping *
upnp_mapping_alloc(enum upnp_map_proto proto, uint16 port)
{
	struct upnp_mapping * um;

	WALLOC0(um);
	um->magic = UPNP_MAPPING_MAGIC;
	um->method = UPNP_M_ANY;
	um->proto = proto;
	um->port = port;

	return um;
}

/**
 * Free a UPnP mapping record.
 */
static void
upnp_mapping_free(struct upnp_mapping *um, bool in_shutdown)
{
	upnp_mapping_check(um);

	cq_cancel(&um->install_ev);
	upnp_ctrl_cancel_null(&um->rpc, !in_shutdown);
	WFREE0(um);
}

/**
 * Convert protocol type to string.
 */
const char *
upnp_map_proto_to_string(const enum upnp_map_proto proto)
{
	switch (proto) {
	case UPNP_MAP_TCP:	return "TCP";
	case UPNP_MAP_UDP:	return "UDP";
	case UPNP_MAP_MAX:	g_assert_not_reached();
	}

	return NULL;
}

/**
 * Convert method type to string.
 */
static const char *
upnp_method_to_string(const enum upnp_method method)
{
	switch (method) {
	case UPNP_M_ANY:	return "firewall";
	case UPNP_M_UPNP:	return "UPnP";
	case UPNP_M_NATPMP:	return "NAT-PMP";
	case UPNP_M_MAX:	g_assert_not_reached();
	}

	return NULL;
}

/**
 * Allocate a new UPnP device of a particular type.
 *
 * @param type			the device type
 * @param desc_url		the description URL for the device
 * @param services		a list of upnp_service_t
 * @param major			UPnP architecture major
 * @param minor			UPnP architecture minor
 *
 * @return the newly created UPnP device structure.
 */
static upnp_device_t *
upnp_dev_alloc(enum upnp_device_type type, const char *desc_url,
	pslist_t *services, unsigned major, unsigned minor)
{
	upnp_device_t *ud;

	WALLOC0(ud);
	ud->magic = UPNP_DEVICE_MAGIC;
	ud->type = type;
	ud->desc_url = atom_str_get(desc_url);
	ud->services = pslist_copy(services);
	ud->major = major;
	ud->minor = minor;

	return ud;
}

/**
 * Free up a device.
 */
void
upnp_dev_free(upnp_device_t *ud)
{
	upnp_device_check(ud);

	atom_str_free_null(&ud->desc_url);
	upnp_service_pslist_free_null(&ud->services);
	WFREE0(ud);
}

/**
 * Free up a device, nullifying the pointer.
 */
void
upnp_dev_free_null(upnp_device_t **ud_ptr)
{
	upnp_device_t *ud = *ud_ptr;

	if (ud != NULL) {
		upnp_dev_free(ud);
		*ud_ptr = NULL;
	}
}

/**
 * Record the gateway device to whom we need to speak.
 */
static void
upnp_record_igd(upnp_device_t *ud)
{
	upnp_device_check(ud);

	upnp_dev_free_null(&igd.dev);
	igd.rcvd_pkts = 0;
	igd.dev = ud;
	igd.uptime = 0;
	igd.only_permanent = FALSE;

	if (GNET_PROPERTY(upnp_debug)) {
		g_info("UPNP using Internet Gateway Device at \"%s\" (WAN IP: %s)",
			ud->desc_url, host_addr_to_string(ud->u.igd.wan_ip));
	}

	gnet_prop_set_boolean_val(PROP_UPNP_POSSIBLE, TRUE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, TRUE);

	if (GNET_PROPERTY(enable_upnp))
		upnp_map_publish_all();		/* Unconditionally publish all mappings */
}

/**
 * Allocate a new UPnP Internet Gateway Device.
 *
 * All the data is copied, the caller can free-up its data structures
 * afterwards if needed.
 *
 * @param desc_url		the description URL for the device
 * @param services		a list of upnp_service_t (list copied, not its data)
 * @param wan_ip		the advertised external IP for the device
 * @param major			UPnP architecture major
 * @param minor			UPnP architecture minor
 *
 * @return the newly created UPnP device structure.
 */
upnp_device_t *
upnp_dev_igd_make(const char *desc_url, pslist_t *services, host_addr_t wan_ip,
	unsigned major, unsigned minor)
{
	upnp_device_t *ud;

	ud = upnp_dev_alloc(UPNP_DEV_IGD, desc_url, services, major, minor);
	ud->u.igd.wan_ip = wan_ip;

	return ud;
}

/**
 * Check whether the external WAN IP address of the IGD is a new one.
 */
static void
upnp_check_new_wan_addr(host_addr_t addr)
{
	bool learnt_external_ip = FALSE;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (!host_addr_equiv(addr, GNET_PROPERTY(local_ip))) {
			gnet_prop_set_ip_val(PROP_LOCAL_IP, addr);
			learnt_external_ip = TRUE;
		}
		break;
	case NET_TYPE_IPV6:
		if (!host_addr_equiv(addr, GNET_PROPERTY(local_ip6))) {
			gnet_prop_set_ip_val(PROP_LOCAL_IP6, addr);
			learnt_external_ip = TRUE;
		}
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}

	if (GNET_PROPERTY(upnp_debug) && learnt_external_ip)
		g_info("UPNP learnt our external IP is %s", host_addr_to_string(addr));
}

/**
 * UPnP device discovery callback, invoked when discovery is done.
 *
 * @param devlist		a list of upnp_device_t (owned by callback)
 * @param arg			user-supplied argument
 */
static void
upnp_discovered(pslist_t *devlist, void *unused_arg)
{
	upnp_device_t *selected = NULL;
	size_t count;
	pslist_t *sl;

	(void) unused_arg;

	igd.discovery_done = TRUE;
	count = pslist_length(devlist);

	if (0 == count)
		return;

	if (count > 1) {
		/*
		 * Since we found more than one IGD, try to keep the one bearing our
		 * external IP, if known.
		 */

		PSLIST_FOREACH(devlist, sl) {
			upnp_device_t *ud = sl->data;

			if (ud->type != UPNP_DEV_IGD)
				continue;

			if (
				host_addr_equiv(ud->u.igd.wan_ip, listen_addr()) ||
				host_addr_equiv(ud->u.igd.wan_ip, listen_addr6())
			) {
				selected = ud;
				break;
			} else {
				if (GNET_PROPERTY(upnp_debug) > 3) {
					g_debug("UPNP discovered device \"%s\" has unknown IP %s",
						ud->desc_url, host_addr_to_string(ud->u.igd.wan_ip));
				}
			}
		}

		if (selected != NULL) {
			if (GNET_PROPERTY(upnp_debug) > 2) {
				g_message("UPNP selecting device \"%s\" among the "
					"%zu discovered, bearing known external IP %s",
					selected->desc_url, count,
					host_addr_to_string(selected->u.igd.wan_ip));
			}
		} else {
			selected = sl->data;		/* Pick the first */

			if (GNET_PROPERTY(upnp_debug) > 2) {
				g_message("UPNP randomly picking device \"%s\" among the "
					"%zu discovered, has external IP %s",
					selected->desc_url, count,
					host_addr_to_string(selected->u.igd.wan_ip));
			}
		}
	} else {
		upnp_device_t *ud = devlist->data;

		if (UPNP_DEV_IGD == ud->type)
			selected = ud;			/* Only member of the list */
	}

	if (NULL == selected)
		goto done;

	/*
	 * If our external IP address is not matching that of the IGD device,
	 * we just discovered our external IP.
	 */

	upnp_check_new_wan_addr(selected->u.igd.wan_ip);

	/*
	 * Record the selected device as the IGD to contact for port mappings.
	 */

	upnp_record_igd(selected);

	/* FALL THROUGH */

done:

	/*
	 * Cleanup the list, freeing all the devices but the one we selected.
	 */

	if (selected != NULL)
		devlist = pslist_remove(devlist, selected);

	PSLIST_FOREACH(devlist, sl) {
		upnp_dev_free(sl->data);
	}

	pslist_free_null(&devlist);
}

/**
 * NAT-PMP device discovery callback, invoked when discovery is done.
 *
 * @param ok		TRUE if succeeded, FALSE if unsuccessful
 * @param gateway	the gateway supporting NAT-PMP
 * @param arg		user-defined argument
 */
static void
upnp_natpmp_discovered(bool ok, natpmp_t *gateway, void *arg)
{
	(void) arg;

	gw.discovery_done = TRUE;

	if (!ok)
		goto upnp_discover;

	gw.gateway = gateway;
	upnp_check_new_wan_addr(natpmp_wan_ip(gateway));

	gnet_prop_set_boolean_val(PROP_NATPMP_POSSIBLE, TRUE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, TRUE);

	if (GNET_PROPERTY(enable_natpmp)) {
		upnp_map_publish_all();		/* Unconditionally publish all mappings */
		return;
	}

	/* FALL THROUGH */

upnp_discover:
	/*
	 * If there's no NAT-PMP available, or they do not want to publish
	 * port mappings via NAT-PMP, see whether we can do UPnP.
	 */

	upnp_discover(UPNP_DISCOVERY_TIMEOUT, upnp_discovered, NULL);
}

/**
 * Launch a NAT-PMP and UPnP discovery.
 */
static void
upnp_launch_discovery(void)
{
	static bool retrying;

	igd.discovery_done = FALSE;
	gw.discovery_done = FALSE;

	/*
	 * Give priority to NAT-PMP.
	 *
	 * The first time we're trying to discover NAT-PMP, limit the number
	 * of retries before timeouting to 3, so that we can quickly fallback
	 * to UPnP if we get no answers.
	 *
	 * Note that we are always attempting to discover port mapping devices,
	 * even though support for UPnP or NAT-PMP is disabled (meaning we won't
	 * publish mappings).  This is to be able to signal them that we found
	 * port-mapping devices.
	 */

	natpmp_discover(retrying ? 0 : 3, upnp_natpmp_discovered, NULL);
	retrying = TRUE;
}

/**
 * Completion callback for IGD packet received requests.
 *
 * @param code		UPnP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
static void
upnp_packets_igd_callback(int code, void *value, size_t size, void *unused_arg)
{
	struct upnp_counter *ret = value;

	(void) unused_arg;

	g_assert(NULL == value || size == sizeof *ret);

	igd.monitor = NULL;		/* Mark request completed */

	if (NULL == igd.dev)
		return;				/* We lost our IGD */

	if (NULL == ret) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP device \"%s\" reports no total packets received "
				"(error %d => \"%s\")",
				igd.dev->desc_url, code, upnp_strerror(code));
		}
		if (UPNP_ERR_INVALID_ACTION == code) {
			upnp_service_t *usd; /* They lied about supporting this action */
			
			usd = upnp_service_get_common_if(igd.dev->services);
			upnp_service_cannot(usd, UPNP_GET_TOTAL_RX_PACKETS);
		}
	} else {
		if (GNET_PROPERTY(upnp_debug) > 5) {
			g_debug("UPNP device \"%s\" reports %u received packets",
				igd.dev->desc_url, ret->value);
		}

		/*
		 * Treat amount of received packets as a monotonically increasing
		 * value.  If it falls (including a possible roll-over once in a
		 * while), assume the device rebooted.
		 */

		if (ret->value < igd.rcvd_pkts) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP device \"%s\" may have been rebooted",
					igd.dev->desc_url);
			}
			upnp_map_publish_all();		/* Unconditionally publish mappings */
		}
		igd.rcvd_pkts = ret->value;
	}
}

/**
 * Completion callback for IGD connection status info requests.
 *
 * @param code		UPnP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
static void
upnp_status_igd_callback(int code, void *value, size_t size, void *unused_arg)
{
	struct upnp_GetStatusInfo *ret = value;

	(void) unused_arg;

	g_assert(NULL == value || size == sizeof *ret);

	igd.monitor = NULL;		/* Mark request completed */

	if (NULL == igd.dev)
		return;				/* We lost our IGD */

	if (NULL == ret) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP device \"%s\" reports no status information "
				"(error %d => \"%s\")",
				igd.dev->desc_url, code, upnp_strerror(code));
		}
		if (UPNP_ERR_INVALID_ACTION == code) {
			upnp_service_t *usd; /* They lied about supporting this action */

			usd = upnp_service_get_wan_connection(igd.dev->services);
			upnp_service_cannot(usd, UPNP_GET_STATUS_INFO);
		}
	} else {
		if (GNET_PROPERTY(upnp_debug) > 5) {
			g_debug("UPNP device \"%s\" reports uptime of %s, status \"%s\"",
				igd.dev->desc_url, compact_time(ret->uptime),
				ret->connection_status);
		}

		/*
		 * Treat uptime as a monotonically increasing value.
		 * If it falls (including a possible roll-over once in a while),
		 * assume the device rebooted.
		 */

		if (ret->uptime < igd.uptime) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP device \"%s\" may have been rebooted",
					igd.dev->desc_url);
			}
			upnp_map_publish_all();		/* Unconditionally publish mappings */
		}
		igd.uptime = ret->uptime;
	}
}

/**
 * Completion callback for NAT-PMP monitoring.
 *
 * @param ok		TRUE if succeeded, FALSE if unsuccessful
 * @param gateway	the gateway supporting NAT-PMP
 * @param arg		user-defined argument
 */
static void
upnp_monitor_natpmp_callback(bool ok, natpmp_t *gateway, void *unused_arg)
{
	(void) unused_arg;

	gw.discovery_done = TRUE;

	if (!ok) {
		/*
		 * On error, force re-discovery of the device.
		 */

		if (GNET_PROPERTY(upnp_debug) && gw.gateway != NULL) {
			g_warning("UPNP gateway %s failed its NAT-PMP health check",
				host_addr_to_string(natpmp_gateway_addr(gw.gateway)));
		}

		goto rediscover;
	} else {
		host_addr_t wan_ip;

		g_assert(gateway != NULL);
		g_assert(gw.gateway == gateway);

		wan_ip = natpmp_wan_ip(gateway);

		/*
		 * Check for external address change.
		 */

		if (host_addr_is_routable(wan_ip)) {
			upnp_check_new_wan_addr(wan_ip);

			if (GNET_PROPERTY(upnp_debug) > 5) {
				g_debug("UPNP gateway %s still alive, WAN IP %s",
					host_addr_to_string(natpmp_gateway_addr(gateway)),
					host_addr_to_string2(wan_ip));
			}
		} else {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP gateway %s reports unroutable WAN IP %s",
					host_addr_to_string(natpmp_gateway_addr(gateway)),
					host_addr_to_string2(wan_ip));
			}
			goto rediscover;
		}
	}

	/*
	 * Check for gateway reboots.
	 */

	g_assert(gateway != NULL);

	if (natpmp_has_rebooted(gateway)) {
		natpmp_clear_rebooted(gateway);
		upnp_map_publish_all();		/* Unconditionally publish all mappings */
	}

	return;

rediscover:
	/*
	 * Initiate a re-discovery of NAT-PMP devices on the network.
	 */

	gnet_prop_set_boolean_val(PROP_NATPMP_POSSIBLE, FALSE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, igd.dev != NULL);

	natpmp_free_null(&gw.gateway);
	gw.discover = TRUE;
}

/**
 * Completion callback for IGD monitoring.
 *
 * @param code		UPnP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
static void
upnp_monitor_igd_callback(int code, void *value, size_t size, void *unused_arg)
{
	struct upnp_GetExternalIPAddress *ret = value;

	(void) unused_arg;

	g_assert(NULL == value || size == sizeof *ret);

	igd.monitor = NULL;		/* Mark request completed */

	if (NULL == ret) {
		/*
		 * On error, force re-discovery of the device.
		 */

		if (GNET_PROPERTY(upnp_debug) && igd.dev != NULL) {
			g_warning("UPNP device \"%s\" reports no external IP "
				"(error %d => \"%s\")",
				igd.dev->desc_url, code, upnp_strerror(code));
		}

		goto rediscover;
	} else if (igd.dev != NULL) {
		/*
		 * Check for external address change.
		 */

		if (host_addr_is_routable(ret->external_ip)) {
			upnp_check_new_wan_addr(ret->external_ip);
			igd.dev->u.igd.wan_ip = ret->external_ip;

			if (GNET_PROPERTY(upnp_debug) > 5) {
				g_debug("UPNP device \"%s\" still alive, WAN IP %s",
					igd.dev->desc_url,
					host_addr_to_string(igd.dev->u.igd.wan_ip));
			}
		} else {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP device \"%s\" reports unroutable WAN IP %s",
					igd.dev->desc_url, host_addr_to_string(ret->external_ip));
			}
			goto rediscover;
		}
	} else {
		return;		/* We lost our IGD */
	}

	g_assert(igd.dev != NULL);

	/*
	 * Monitor total amount of packets received by the IGD, or the uptime
	 * of the IGD connection if the former is not available (since it is
	 * an optional feature).
	 *
	 * The idea is that if we find out the amount is suddenly less than the
	 * previous amount, chances are that the device has been rebooted (or
	 * the counter rolled-over, but for our purpose it does not matter).
	 *
	 * If we think the device might have been rebooted, chances are the
	 * previous port mappings were lost, so we'll re-install them.
	 */

	{
		upnp_service_t *usd;

		/*
		 * We prefer to monitor the amount of RX packets as opposed to the
		 * connection uptime because we're interested in detecting device
		 * reboots.  The connection uptime may fluctuate if the WAN signal
		 * is lost but the device not otherwise rebooted, in which case the
		 * UPnP mappings should stay active.
		 */

		usd = upnp_service_get_common_if(igd.dev->services);
		if (upnp_service_can(usd, UPNP_GET_TOTAL_RX_PACKETS)) {
			igd.monitor = upnp_ctrl_GetTotalPacketsReceived(usd,
					upnp_packets_igd_callback, NULL);
			goto done;
		}

		usd = upnp_service_get_wan_connection(igd.dev->services);
		if (upnp_service_can(usd, UPNP_GET_STATUS_INFO)) {
			igd.monitor = upnp_ctrl_GetStatusInfo(usd,
					upnp_status_igd_callback, NULL);
			goto done;
		}

		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP cannot monitor device \"%s\", republishing",
				igd.dev->desc_url);
		}

		upnp_map_publish_all();		/* Unconditionally publish mappings */
	}

done:
	return;

rediscover:
	/*
	 * Initiate a re-discovery of UPnP devices on the network.
	 */

	gnet_prop_set_boolean_val(PROP_UPNP_POSSIBLE, FALSE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, gw.gateway != NULL);

	upnp_dev_free_null(&igd.dev);
	igd.discover = TRUE;
}

/**
 * Check whether we appear to be firewalled, either for TCP or UDP,
 * updating the "port_mapping_required" property accordingly.
 *
 * @return TRUE when we are firewalled and in need for port mappings.
 */
static bool
upnp_port_mapping_required(void)
{
	if (GNET_PROPERTY(is_firewalled) || GNET_PROPERTY(is_udp_firewalled)) {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, TRUE);
	} else {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, FALSE);
	}

	return GNET_PROPERTY(port_mapping_required);
}

static void
upnp_count_mapping_kv(const void *key, void *u_value, void *data)
{
	const struct upnp_mapping *um = key;
	unsigned *count = data;

	(void) u_value;

	if (um->published)
		(*count)++;
}

/**
 * Returns amount of published mappings.
 */
static unsigned
upnp_published_mappings(void)
{
	unsigned count;

	g_assert(upnp_mappings != NULL);

	count = 0;
	htable_foreach(upnp_mappings, upnp_count_mapping_kv, &count);
	return count;
}

/**
 * Re-issue a discovery if neeeded.
 */
static void
upnp_launch_discovery_if_needed(void)
{
	static unsigned counter;

	/*
	 * We don't have any known Internet Gateway Device, look whether
	 * they plugged one in, but not at every wakeup...
	 *
	 * When ``igd.discover'' is TRUE, we force the discovery.
	 * This is used to rediscover devices after monitoring of the known
	 * IGD failed at the last period, in case they replaced the IGD with
	 * a new box.
	 *
	 * Same logic for ``gw.discover''.
	 */

	if (igd.discover) {
		counter = 0;
		igd.discover = FALSE;
	} else if (gw.discover) {
		counter = 0;
		gw.discover = FALSE;
	} else {
		counter++;
	}

	/*
	 * We're scheduled once every UPNP_MONITOR_DELAY seconds, and we wish
	 * to rediscover only once every UPNP_REDISCOVER seconds, hence the
	 * modulo check below.
	 */

	if (0 == counter % (UPNP_REDISCOVER / UPNP_MONITOR_DELAY)) {
		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_debug("UPNP initiating discovery");
		}
		upnp_launch_discovery();
	}
}

/**
 * Attempt to publish mappings.
 */
static void
upnp_map_try_publish_all(void)
{
	if (gw.gateway != NULL && GNET_PROPERTY(natpmp_possible)) {
		upnp_map_publish_all();
	} else if (igd.dev != NULL && GNET_PROPERTY(upnp_possible)) {
		upnp_map_publish_all();
	}
}

/**
 * Callout queue periodic event to monitor presence of the Internet Gateway
 * Device or the NAT-PMP gateway we are using and detect configuration changes.
 */
static bool
upnp_monitor_drivers(void *unused_obj)
{
	(void) unused_obj;

	/*
	 * We always give priority to NAT-PMP because the protocol is more
	 * efficient.
	 */

	if (!GNET_PROPERTY(enable_natpmp))
		goto no_natpmp;

	if (NULL == gw.gateway) {
		if (igd.dev != NULL)
			goto no_natpmp;
		upnp_launch_discovery_if_needed();
	} else {
		/*
		 * Check our external IP address, since we're not listening to
		 * NAT-PMP broadcasts, and see whether the gateway has been rebooted.
		 */

		natpmp_monitor(gw.gateway, upnp_monitor_natpmp_callback, NULL);
	}

	goto done;

no_natpmp:

	/*
	 * When UPnP support is disabled, there is nothing to do.
	 *
	 * We do not remove the periodic monitoring callback since the condition
	 * can change dynamically and this prevents additional bookkeeping.
	 */

	if (!GNET_PROPERTY(enable_upnp))
		return TRUE;		/* Keep calling, nonetheless */

	if (NULL == igd.dev) {
		upnp_launch_discovery_if_needed();
	} else {
		upnp_service_t *usd;

		/*
		 * Check our external IP address, and at the same time make sure
		 * the IGD is still there.
		 */

		usd = upnp_service_get_wan_connection(igd.dev->services);

		g_assert(usd != NULL);		/* Or device would not be an IGD */

		if (GNET_PROPERTY(upnp_debug) > 5)
			g_debug("UPNP monitoring IGD at \"%s\"", igd.dev->desc_url);

		upnp_ctrl_cancel_null(&igd.monitor, FALSE);
		igd.monitor = upnp_ctrl_GetExternalIPAddress(usd,
			upnp_monitor_igd_callback, NULL);
	}

done:
	/*
	 * Make sure all mappings are still correctly published.
	 */

	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL,
		htable_count(upnp_mappings) == upnp_published_mappings());

	/*
	 * Publish mappings if needed.
	 */

	if (!GNET_PROPERTY(port_mapping_successful) && upnp_port_mapping_required())
		upnp_map_try_publish_all();

	return TRUE;		/* Keep calling */
}

/**
 * Callback on upnp_ctrl_AddPortMapping() completion.
 */
static void
upnp_map_publish_reply(int code, void *value, size_t size, void *arg)
{
	struct upnp_mapping *um = arg;

	g_assert(NULL == value);
	g_assert(0 == size);
	upnp_mapping_check(um);

	um->rpc = NULL;		/* RPC completed */

	if (UPNP_ERR_OK == code) {
		if (GNET_PROPERTY(upnp_debug) > 2) {
			g_message("UPNP successfully published UPnP mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
		if (!um->published)
			inet_router_configured();	/* First time we're publishing */
		um->published = TRUE;
		um->method = UPNP_M_UPNP;
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not publish UPnP mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
		um->published = FALSE;
		um->method = UPNP_M_ANY;
		um->lease_time = UPNP_UNDEFINED_LEASE;

		/*
		 * Handle devices supporting only permanent leases.
		 *
		 * Otherwise, on publishing error, retry periodically every
		 * UPNP_CHECK_DELAY seconds.
		 */

		if (UPNP_ERR_ONLY_PERMANENT_LEASE == code && 0 != um->lease_time) {
			igd.only_permanent = TRUE;
			um->lease_time = 0;
			cq_resched(um->install_ev, 1);	/* Re-publish immediately */
		} else {
			cq_resched(um->install_ev, UPNP_CHECK_DELAY_MS);
		}
	}

	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL,
		htable_count(upnp_mappings) == upnp_published_mappings());
}

/**
 * Callback on natpmp_map() completion.
 */
static void
upnp_map_natpmp_publish_reply(int code,
	uint16 port, unsigned lifetime, void *arg)
{
	struct upnp_mapping *um = arg;

	upnp_mapping_check(um);

	if (NATPMP_E_OK == code && port == um->port) {
		if (GNET_PROPERTY(upnp_debug) > 2) {
			g_message("UPNP successfully published NAT-PMP mapping "
				"for %s port %u, lease = %u s",
				upnp_map_proto_to_string(um->proto), um->port, lifetime);
		}
		if (!um->published)
			inet_router_configured();	/* First time we're publishing */
		um->published = TRUE;
		um->method = UPNP_M_NATPMP;
		cq_resched(um->install_ev, lifetime / 2 * 1000);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not publish NAT-PMP mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, natpmp_strerror(code));
		}
		um->published = FALSE;
		um->method = UPNP_M_ANY;
		um->lease_time = UPNP_UNDEFINED_LEASE;
		cq_resched(um->install_ev, UPNP_CHECK_DELAY_MS);
	}

	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL,
		htable_count(upnp_mappings) == upnp_published_mappings());
}

/**
 * Callout queue callback to publish a UPnP mapping to the IGD.
 */
static void
upnp_map_publish(cqueue_t *cq, void *obj)
{
	struct upnp_mapping *um = obj;
	int delay;

	upnp_mapping_check(um);

	cq_zero(cq, &um->install_ev);

	/*
	 * Re-install callback for next time.
	 *
	 * At the beginning, we may still be looking for an IGD, so retry
	 * regularily the first few times before waiting for a looong time.
	 */

	if (NULL == igd.dev && NULL == gw.gateway) {
		if (!GNET_PROPERTY(enable_upnp) && !GNET_PROPERTY(enable_natpmp))
			delay = 0;
		else if (!igd.discovery_done || !gw.discovery_done)
			delay = UPNP_PUBLISH_RETRY_MS;
		else if (upnp_port_mapping_required())
			delay = UPNP_MONITOR_DELAY_MS;
		else
			delay = UPNP_CHECK_DELAY_MS;
	} else {
		if (0 == um->lease_time) {
			delay = MAX_INT_VAL(int);
		} else {
			delay = (um->lease_time - UPNP_MAPPING_CAUTION) * 1000;
			delay = MAX(delay, UPNP_MAPPING_CAUTION * 1000);
			delay /= 2;		/* Republish at the half of the lease period */
		}
	}

	if (GNET_PROPERTY(upnp_debug) > 15) {
		g_debug("UPNP publish callout delay for %s port %u set to %d seconds",
			upnp_map_proto_to_string(um->proto), um->port, delay / 1000);
	}

	um->install_ev = delay ? cq_main_insert(delay, upnp_map_publish, um) : NULL;
	um->published = FALSE;

	/*
	 * When UPnP support is disabled, we record port mappings internally
	 * but do not publish them to the IGD.
	 */

	if (!GNET_PROPERTY(enable_upnp) && !GNET_PROPERTY(enable_natpmp)) {
		if (GNET_PROPERTY(upnp_debug) > 10) {
			g_debug("UPNP support is disabled, "
				"not publishing mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
		return;
	}

	if (GNET_PROPERTY(upnp_debug) > 2) {
		g_message("UPNP publishing %s mapping for %s port %u",
			upnp_method_to_string(um->method),
			upnp_map_proto_to_string(um->proto), um->port);
	}

	/*
	 * Prefer NAT-PMP if available since the protocol is more efficient.
	 */

	if (gw.gateway != NULL && GNET_PROPERTY(enable_natpmp)) {
		/*
		 * No permanent mappings with NAT-PMP.
		 */

		um->lease_time = GNET_PROPERTY(upnp_mapping_lease_time);
		um->lease_time = MAX(UPNP_MAPPING_CAUTION, um->lease_time);

		natpmp_map(gw.gateway, um->proto, um->port, um->lease_time,
			upnp_map_natpmp_publish_reply, um);
	} else if (igd.dev != NULL) {
		const upnp_service_t *usd;

		usd = upnp_service_get_wan_connection(igd.dev->services);
		upnp_ctrl_cancel_null(&um->rpc, TRUE);

		/*
		 * Impose minimal UPNP_MAPPING_CAUTION lease time if not permanent.
		 * When the IGD only supports permanent mappings, there is no need
		 * to request anything else!
		 */

		um->lease_time = igd.only_permanent ? 0 :
			GNET_PROPERTY(upnp_mapping_lease_time);

		if (um->lease_time != 0)
			um->lease_time = MAX(UPNP_MAPPING_CAUTION, um->lease_time);

		um->rpc = upnp_ctrl_AddPortMapping(usd, um->proto, um->port,
			upnp_get_local_addr(), um->port,
			upnp_mapping_description(), um->lease_time,
			upnp_map_publish_reply, um);

		if (NULL == um->rpc) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning(
					"UPNP could not launch UPnP publishing for %s port %u",
					upnp_map_proto_to_string(um->proto), um->port);
			}
		}
	} else {
		/*
		 * Mappings can be recorded at startup before we had a chance to
		 * discover the NAT device, which is why we retry more often at the
		 * beginning (every UPNP_PUBLISH_RETRY_MS for a while).
		 */

		if (GNET_PROPERTY(upnp_debug) > 5) {
			g_message("UPNP no device yet to publish mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
	}
}

/**
 * Record port mapping addition.
 */
static void
upnp_map_add(enum upnp_map_proto proto, uint16 port)
{
	struct upnp_mapping key;
	struct upnp_mapping *um;

	key.proto = proto;
	key.port = port;

	if (htable_contains(upnp_mappings, &key))
		return;		/* Already known */

	/*
	 * We're installing a new mapping, will be asynchronously published.
	 */

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_message("UPNP adding new mapping for %s port %u",
			upnp_map_proto_to_string(proto), port);
	}

	um = upnp_mapping_alloc(proto, port);
	um->install_ev = cq_main_insert(1, upnp_map_publish, um);
	um->lease_time = UPNP_UNDEFINED_LEASE;

	htable_insert(upnp_mappings, um, um);
}

/**
 * Callback on upnp_ctrl_DeletePortMapping() completion.
 */
static void
upnp_map_delete_reply(int code, void *value, size_t size, void *arg)
{
	struct upnp_mapping *um = arg;

	g_assert(NULL == value);
	g_assert(0 == size);
	g_assert(uint_is_positive(igd.delete_pending));

	um->rpc = NULL;			/* RPC completed */
	igd.delete_pending--;

	if (UPNP_ERR_OK == code) {
		if (GNET_PROPERTY(upnp_debug) > 2)
			g_message("UPNP successfully deleted UPnP mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not remove UPnP mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
	}

	upnp_mapping_free(um, FALSE);
}

/**
 * Unpublish port mapping.
 *
 * @return TRUE if we can dispose of the mapping record.
 */
static bool
upnp_map_unpublish(struct upnp_mapping *um)
{
	upnp_mapping_check(um);

	if (!um->published)
		return TRUE;			/* Nothing to do, was never published */

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_debug("UPNP removing %spublished %s mapping for %s port %u",
			um->published ? "" : "un",
			upnp_method_to_string(um->method),
			upnp_map_proto_to_string(um->proto), um->port);
	}

	if (UPNP_M_NATPMP == um->method) {
		if (NULL == gw.gateway) {
			g_warning("UPNP cannot remove published mapping "
				"for %s port %u "
				"since NAT-PMP gateway is not available",
				upnp_map_proto_to_string(um->proto), um->port);
		} else {
			/* Advisory unmapping, no callback on completion or error */
			natpmp_unmap(gw.gateway, um->proto, um->port);
		}
		return TRUE;
	} else {
		const upnp_service_t *usd;

		if (NULL == igd.dev) {
			g_warning("UPNP cannot remove published mapping "
				"for %s port %u "
				"since Internet Gateway Device is not available",
				upnp_map_proto_to_string(um->proto), um->port);
			return TRUE;
		}

		usd = upnp_service_get_wan_connection(igd.dev->services);
		upnp_ctrl_cancel_null(&um->rpc, TRUE);

		/* Freeing of ``um'' will happen in upnp_map_delete_reply() */
		um->rpc = upnp_ctrl_DeletePortMapping(usd, um->proto, um->port,
			upnp_map_delete_reply, um);

		if (um->rpc != NULL)
			igd.delete_pending++;

		return FALSE;		/* ``um'' still needed for UPnP callback */
	}

	g_assert_not_reached();
}

/**
 * Remove port mapping.
 */
static void
upnp_map_remove(enum upnp_map_proto proto, uint16 port)
{
	struct upnp_mapping key;
	struct upnp_mapping *um;

	key.proto = proto;
	key.port = port;

	um = htable_lookup(upnp_mappings, &key);

	if (NULL == um) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_carp("UPNP removing unknown mapping for %s port %u",
				upnp_map_proto_to_string(proto), port);
		}
	} else {
		upnp_mapping_check(um);
		htable_remove(upnp_mappings, um);

		if (upnp_map_unpublish(um)) {
			upnp_mapping_free(um, FALSE);
		}
	}
}

/**
 * Callback on upnp_ctrl_DeletePortMapping() completion.
 */
static void
upnp_map_mapping_deleted(int code, void *value, size_t size, void *arg)
{
	struct upnp_mapping *um = arg;

	g_assert(NULL == value);
	g_assert(0 == size);

	um->rpc = NULL;			/* RPC completed */

	if (UPNP_ERR_OK == code) {
		if (GNET_PROPERTY(upnp_debug) > 2)
			g_message("UPNP successfully deleted UPnP mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not remove UPnP mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
	}

	/*
	 * We keep the mapping around, in case UPnP is re-enabled.
	 */

	um->published = FALSE;
	um->lease_time = UPNP_UNDEFINED_LEASE;
}

/**
 * Remove published mapping of the specified kind.
 */
static void
upnp_remove_mapping_kv(const void *key, void *u_value, void *data)
{
	struct upnp_mapping *um = deconstify_gpointer(key);
	enum upnp_method method = pointer_to_int(data);

	(void) u_value;

	if (!um->published || um->method != method)
		return;

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_message("UPNP removing %s mapping for %s port %u",
			upnp_method_to_string(um->method),
			upnp_map_proto_to_string(um->proto), um->port);
	}

	if (UPNP_M_UPNP == um->method) {
		const upnp_service_t *usd;

		usd = upnp_service_get_wan_connection(igd.dev->services);
		upnp_ctrl_cancel_null(&um->rpc, TRUE);

		um->rpc = upnp_ctrl_DeletePortMapping(usd, um->proto, um->port,
			upnp_map_mapping_deleted, um);

		if (NULL == um->rpc) {
			if (GNET_PROPERTY(upnp_debug)) {
				g_warning("UPNP cannot remove UPnP mapping for %s port %u",
					upnp_map_proto_to_string(um->proto), um->port);
			}
		}
	} else {
		/* Advisory unmapping, no callback on completion or error */
		natpmp_unmap(gw.gateway, um->proto, um->port);
	}
}

/**
 * UPnP support was disabled, so remove all the mappings we may have
 * installed so far, but keep them locally (i.e. we unmap the ports at
 * the IDG, but still remember which ports are mapped).
 */
void
upnp_disabled(void)
{
	if (igd.dev != NULL) {
		htable_foreach(upnp_mappings, upnp_remove_mapping_kv,
			int_to_pointer(UPNP_M_UPNP));
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL, FALSE);
	}

	if (GNET_PROPERTY(enable_natpmp)) {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, TRUE);
		upnp_launch_discovery();
	} else {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, FALSE);
	}
}

/**
 * UPnP support was disabled, so remove all the mappings we may have
 * installed so far, but keep them locally (i.e. we unmap the ports at
 * the IDG, but still remember which ports are mapped).
 */
void
upnp_natpmp_disabled(void)
{
	if (gw.gateway != NULL) {
		htable_foreach(upnp_mappings, upnp_remove_mapping_kv,
			int_to_pointer(UPNP_M_NATPMP));
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_SUCCESSFUL, FALSE);
	}

	if (GNET_PROPERTY(enable_upnp)) {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, TRUE);
		upnp_launch_discovery();
	} else {
		gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, FALSE);
	}
}

/**
 * Request immediate (asynchronous) mapping publishing for all the mappings
 * we may have recorded, regardless of whether they were already published
 * before.
 */
static void
upnp_publish_mapping_kv(const void *key, void *u_value, void *u_data)
{
	struct upnp_mapping *um = deconstify_gpointer(key);

	(void) u_value;
	(void) u_data;

	/*
	 * Schedule publishing to happen at next callout queue tick.
	 */

	cq_cancel(&um->install_ev);
	um->install_ev = cq_main_insert(1, upnp_map_publish, um);

	if (GNET_PROPERTY(upnp_debug) > 2) {
		g_message("UPNP requested immediate %s publishing for %s port %u",
			upnp_method_to_string(um->method),
			upnp_map_proto_to_string(um->proto), um->port);
	}
}

/**
 * UPnP or NAT-PMP was discovered.
 * If we have mappings to install, do so immediately.
 */
static void
upnp_map_publish_all(void)
{
	g_assert(igd.dev != NULL || gw.gateway != NULL);

	htable_foreach(upnp_mappings, upnp_publish_mapping_kv, NULL);
}

/**
 * Add TCP port redirection on the IGD device to this machine.
 */
void
upnp_map_tcp(uint16 port)
{
	upnp_map_add(UPNP_MAP_TCP, port);
}

/**
 * Add UDP port redirection on the IGD device to this machine.
 */
void
upnp_map_udp(uint16 port)
{
	upnp_map_add(UPNP_MAP_UDP, port);
}

/**
 * Remove TCP port redirection on the IGD device.
 */
void
upnp_unmap_tcp(uint16 port)
{
	upnp_map_remove(UPNP_MAP_TCP, port);
}

/**
 * Remove UDP port redirection on the IGD device.
 */
void
upnp_unmap_udp(uint16 port)
{
	upnp_map_remove(UPNP_MAP_UDP, port);
}

/**
 * Record local IP address.
 */
void
upnp_set_local_addr(host_addr_t addr)
{
	if (host_addr_equiv(addr, upnp_local_addr))
		return;

	if (GNET_PROPERTY(upnp_debug) > 1)
		g_info("UPNP local IP address is %s", host_addr_to_string(addr));

	upnp_local_addr = addr;
}

/**
 * Get local IP address.
 */
host_addr_t
upnp_get_local_addr(void)
{
	return upnp_local_addr;
}

/**
 * UPnP initialization.
 */
void
upnp_init(void)
{
	upnp_discovery_init();

	cq_periodic_main_add(UPNP_MONITOR_DELAY_MS,
		upnp_monitor_drivers, NULL);

	upnp_mappings = htable_create_any(upnp_mapping_hash,
		upnp_mapping_hash2, upnp_mapping_eq);
}

/**
 * UPnP post initialization.
 */
void
upnp_post_init(void)
{
	upnp_launch_discovery();		/* NAT-PMP and UPnP discovery */
}

/**
 * Free mappings still present, warning about them since normal cleanup
 * should remove them.
 */
static bool
upnp_free_mapping_kv(const void *key, void *u_value, void *u_data)
{
	struct upnp_mapping *um = deconstify_gpointer(key);

	(void) u_value;
	(void) u_data;

	g_warning("UPNP %spublished %s mapping for %s port %u still present",
		um->published ? "" : "un",
		upnp_method_to_string(um->method),
		upnp_map_proto_to_string(um->proto), um->port);

	upnp_mapping_free(um, TRUE);

	return TRUE;				/* Remove from table */
}

/**
 * UPnP shutdown.
 */
void
upnp_close(void)
{
	upnp_discovery_close();
	upnp_dev_free_null(&igd.dev);
	natpmp_free_null(&gw.gateway);
	upnp_ctrl_cancel_null(&igd.monitor, FALSE);
	htable_foreach_remove(upnp_mappings, upnp_free_mapping_kv, NULL);
	htable_free_null(&upnp_mappings);
}

/* vi: set ts=4 sw=4 cindent: */
