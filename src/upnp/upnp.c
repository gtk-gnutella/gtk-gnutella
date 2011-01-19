/*
 * $Id$
 *
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
 * @ingroup upnp
 * @file
 *
 * UPnP data structures and high-level routines.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

#include "upnp.h"
#include "control.h"
#include "discovery.h"
#include "error.h"
#include "service.h"

#include "core/settings.h"		/* For listen_addr() */
#include "core/version.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/glib-missing.h"
#include "lib/host_addr.h"
#include "lib/stacktrace.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define UPNP_DISCOVERY_TIMEOUT	3000	/**< Timeout in ms */
#define UPNP_MONITOR_DELAY		300		/**< Every 5 minutes */
#define UPNP_MAPPING_LIFE		3600	/**< 1 hour */
#define UPNP_MAPPING_CAUTION	120		/**< 2 minutes */
#define UPNP_PUBLISH_RETRY		10		/**< 10 seconds */
#define UPNP_PUBLISH_RETRY_CNT	12		/**< 2 ports 6 times, ~ 1 minute */

#define UPNP_MONITOR_DELAY_MS	(UPNP_MONITOR_DELAY * 1000)
#define UPNP_PUBLISH_RETRY_MS	(UPNP_PUBLISH_RETRY * 1000)

#define UPNP_MAPPING_LIFE_MS \
	((UPNP_MAPPING_LIFE - UPNP_MAPPING_CAUTION) * 1000)

/**
 * The local Internet Gateway Device.
 */
static struct {
	upnp_device_t *dev;			/**< Our Internet Gateway Device */
	upnp_ctrl_t *monitor;		/**< Regular monitoring event */
	gboolean discover;			/**< Force discovery again */
	unsigned delete_pending;	/**< Amount of pending mapping deletes */
} igd;

enum upnp_mapping_magic { UPNP_MAPPING_MAGIC = 0x463a8514 };

/**
 * A requested port-mapping.
 */
struct upnp_mapping {
	enum upnp_mapping_magic magic;
	enum upnp_map_proto proto;	/**< Network protocol used */
	guint16 port;				/**< Port to map */
	cevent_t *install_ev;		/**< Periodic install event */
	upnp_ctrl_t *rpc;			/**< Pending control RPC */
	unsigned published:1;		/**< Was mapping successfully published? */
};

static inline void
upnp_mapping_check(const struct upnp_mapping * const um)
{
	g_assert(um != NULL);
	g_assert(UPNP_MAPPING_MAGIC == um->magic);
}

static GHashTable *upnp_mappings;	/**< Tracks requested UPnP mappings */
static host_addr_t upnp_local_addr;	/**< Computed local IP address */

static const char UPNP_CONN_IP_ROUTED[]	= "IP_Routed";

static void upnp_idg_discovered(void);

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
gboolean
upnp_delete_pending(void)
{
	return igd.delete_pending != 0;
}

/**
 * Hash an UPnP mapping.
 */
static unsigned
upnp_mapping_hash(const void *p)
{
	const struct upnp_mapping *um = p;

	return ((unsigned) um->proto * 0xa79dU) ^ (unsigned) um->port;
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
upnp_mapping_alloc(enum upnp_map_proto proto, guint16 port)
{
	struct upnp_mapping * um;

	um = walloc0(sizeof *um);
	um->magic = UPNP_MAPPING_MAGIC;
	um->proto = proto;
	um->port = port;

	return um;
}

/**
 * Free an UPnP mapping record.
 */
static void
upnp_mapping_free(struct upnp_mapping *um, gboolean in_shutdown)
{
	upnp_mapping_check(um);

	cq_cancel(&um->install_ev);
	upnp_ctrl_cancel_null(&um->rpc, !in_shutdown);
	wfree0(um, sizeof *um);
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
	GSList *services, unsigned major, unsigned minor)
{
	upnp_device_t *ud;

	ud = walloc0(sizeof *ud);
	ud->magic = UPNP_DEVICE_MAGIC;
	ud->type = type;
	ud->desc_url = atom_str_get(desc_url);
	ud->services = g_slist_copy(services);
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
	upnp_service_gslist_free_null(&ud->services);
	wfree0(ud, sizeof *ud);
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
	igd.dev = ud;

	if (GNET_PROPERTY(upnp_debug)) {
		g_info("UPNP using Internet Gateway Device at \"%s\" (WAN IP: %s)",
			ud->desc_url, host_addr_to_string(ud->u.igd.wan_ip));
	}

	gnet_prop_set_boolean_val(PROP_UPNP_POSSIBLE, TRUE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, TRUE);

	upnp_idg_discovered();		/* Unconditionally publish all mappings */
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
upnp_dev_igd_make(const char *desc_url, GSList *services, host_addr_t wan_ip,
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
	gboolean learnt_external_ip = FALSE;

	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		if (!host_addr_equal(addr, GNET_PROPERTY(local_ip))) {
			gnet_prop_set_ip_val(PROP_LOCAL_IP, addr);
			learnt_external_ip = TRUE;
		}
		break;
	case NET_TYPE_IPV6:
		if (!host_addr_equal(addr, GNET_PROPERTY(local_ip6))) {
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
upnp_discovered(GSList *devlist, void *unused_arg)
{
	upnp_device_t *selected = NULL;
	size_t count;
	GSList *sl;

	(void) unused_arg;

	count = g_slist_length(devlist);

	if (0 == count)
		return;

	if (count > 1) {
		/*
		 * Since we found more than one IGD, try to keep the one bearing our
		 * external IP, if known.
		 */

		GM_SLIST_FOREACH(devlist, sl) {
			upnp_device_t *ud = sl->data;

			if (ud->type != UPNP_DEV_IGD)
				continue;

			if (
				host_addr_equal(ud->u.igd.wan_ip, listen_addr()) ||
				host_addr_equal(ud->u.igd.wan_ip, listen_addr6())
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
					"%lu discovered, bearing known external IP %s",
					selected->desc_url, (unsigned long) count,
					host_addr_to_string(selected->u.igd.wan_ip));
			}
		} else {
			selected = sl->data;		/* Pick the first */

			if (GNET_PROPERTY(upnp_debug) > 2) {
				g_message("UPNP randomly picking device \"%s\" among the "
					"%lu discovered, has external IP %s",
					selected->desc_url, (unsigned long) count,
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
		devlist = g_slist_remove(devlist, selected);

	GM_SLIST_FOREACH(devlist, sl) {
		upnp_dev_free(sl->data);
	}

	gm_slist_free_null(&devlist);
}

/**
 * Completion callback for IGD monitoring.
 *
 * @param code		UPNP error code, 0 for OK
 * @param value		returned value structure
 * @param size		size of structure, for assertions
 * @param arg		user-supplied callback argument
 */
static void
upnp_monitor_igd_callback(int code, void *value, size_t size, void *unused_arg)
{
	struct upnp_GetExternalIPAddress *ret = value;

	(void) unused_arg;

	g_assert(size == sizeof *ret);

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
	}

	return;

rediscover:
	/*
	 * Initiate a re-discovery of UPnP devices on the network.
	 */

	gnet_prop_set_boolean_val(PROP_UPNP_POSSIBLE, FALSE);
	gnet_prop_set_boolean_val(PROP_PORT_MAPPING_POSSIBLE, FALSE);

	upnp_dev_free_null(&igd.dev);
	igd.discover = TRUE;
}

/**
 * Callout queue periodic event to monitor presence of the Internet Gateway
 * Device we are using and detect configuration changes.
 */
static gboolean
upnp_monitor_igd(gpointer unused_obj)
{
	(void) unused_obj;

	/*
	 * When UPnP support is disabled, there is nothing to do.
	 *
	 * We do not remove the periodic monitoring callback since the condition
	 * can change dynamically and this prevents additional bookkeeping.
	 */

	if (!GNET_PROPERTY(enable_upnp))
		return TRUE;		/* Keep calling, nonetheless */

	if (NULL == igd.dev) {
		static unsigned counter;

		/*
		 * We don't have any known Internet Gateway Device, look whether
		 * they plugged one in, but not at every wakeup...
		 *
		 * If we're not firewalled, there's no reason to actively look for an
		 * IGD yet.
		 */

		if (GNET_PROPERTY(is_firewalled) || GNET_PROPERTY(is_udp_firewalled)) {
			gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, TRUE);
		} else {
			if (GNET_PROPERTY(upnp_debug) > 5)
				g_debug("UPNP still no need for port mapping");

			gnet_prop_set_boolean_val(PROP_PORT_MAPPING_REQUIRED, FALSE);
			return TRUE;	/* Keep calling in case we become firewalled */
		}

		/*
		 * When ``igd.discover'' is TRUE, we force the discovery.
		 * This is used to rediscover devices after monitoring of the known
		 * IGD failed at the last period, in case they replaced the IGD with
		 * a new box.
		 */

		if (igd.discover) {
			counter = 0;
			igd.discover = FALSE;
		} else {
			counter++;
		}

		if (0 == counter % 12) {
			if (GNET_PROPERTY(upnp_debug) > 1) {
				g_debug("UPNP initiating discovery");
			}
			upnp_discover(UPNP_DISCOVERY_TIMEOUT, upnp_discovered, NULL);
		}
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

	um->rpc = NULL;		/* RPC completed */

	if (UPNP_ERR_OK == code) {
		if (GNET_PROPERTY(upnp_debug) > 2) {
			g_message("UPNP successfully published mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
		um->published = TRUE;
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not publish mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
		um->published = FALSE;
	}
}

/**
 * Callout queue callback to publish an UPNP mapping to the IGD.
 */
static void
upnp_map_publish(cqueue_t *unused_cq, void *obj)
{
	struct upnp_mapping *um = obj;
	const upnp_service_t *usd;
	static unsigned delayed;

	(void) unused_cq;
	upnp_mapping_check(um);

	/*
	 * Re-install callback for next time.
	 *
	 * At the beginning, we may still be looking for an IGD, so retry
	 * regularily the first few times before waiting for a looong time.
	 */

	um->install_ev = cq_main_insert(
		(NULL == igd.dev && delayed++ < UPNP_PUBLISH_RETRY_CNT) ?
			UPNP_PUBLISH_RETRY_MS : UPNP_MAPPING_LIFE_MS,
		upnp_map_publish, um);

	/*
	 * When UPnP support is disabled, we record port mappings internally
	 * but do not publish them to the IGD.
	 */

	if (!GNET_PROPERTY(enable_upnp)) {
		if (GNET_PROPERTY(upnp_debug) > 10) {
			g_debug("UPNP support is disabled, "
				"not publishing mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
		return;
	}

	/*
	 * Mappings can be recorded at startup before we had a chance to
	 * discover the IGD device, which is why we retry more often at the
	 * beginning (every UPNP_PUBLISH_RETRY_MS for a while).
	 */

	if (NULL == igd.dev) {
		if (GNET_PROPERTY(upnp_debug) > 5) {
			g_message("UPNP no IGD yet to publish mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
		return;
	}

	if (GNET_PROPERTY(upnp_debug) > 2) {
		g_message("UPNP publishing mapping for %s port %u",
			upnp_map_proto_to_string(um->proto), um->port);
	}

	usd = upnp_service_get_wan_connection(igd.dev->services);
	upnp_ctrl_cancel_null(&um->rpc, TRUE);

	um->rpc = upnp_ctrl_AddPortMapping(usd, um->proto, um->port,
		upnp_get_local_addr(), um->port,
		version_string, UPNP_MAPPING_LIFE,
		upnp_map_publish_reply, um);

	if (NULL == um->rpc) {
		um->published = FALSE;
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not launch publishing for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
	}
}

/**
 * Record port mapping addition.
 */
static void
upnp_map_add(enum upnp_map_proto proto, guint16 port)
{
	struct upnp_mapping key;
	struct upnp_mapping *um;

	key.proto = proto;
	key.port = port;

	if (gm_hash_table_contains(upnp_mappings, &key))
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

	g_hash_table_insert(upnp_mappings, um, um);
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
			g_message("UPNP successfully deleted mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not remove mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
	}

	upnp_mapping_free(um, FALSE);
}

/**
 * Remove port mapping.
 */
static void
upnp_map_remove(enum upnp_map_proto proto, guint16 port)
{
	struct upnp_mapping key;
	struct upnp_mapping *um;

	key.proto = proto;
	key.port = port;

	um = g_hash_table_lookup(upnp_mappings, &key);

	if (NULL == um) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP removing unknown mapping for %s port %u",
				upnp_map_proto_to_string(proto), port);
			stacktrace_where_sym_print(stderr);
		}
	} else {
		g_hash_table_remove(upnp_mappings, um);

		if (GNET_PROPERTY(upnp_debug) > 1) {
			g_warning("UPNP removing %spublished mapping for %s port %u",
				um->published ? "" : "un",
				upnp_map_proto_to_string(um->proto), um->port);
		}

		if (um->published) {
			const upnp_service_t *usd;

			if (NULL == igd.dev) {
				g_warning("UPNP cannot remove published mapping for %s port %u "
					"since Internet Gateway Device is not available",
					upnp_map_proto_to_string(um->proto), um->port);
				goto delete;
			}

			usd = upnp_service_get_wan_connection(igd.dev->services);
			upnp_ctrl_cancel_null(&um->rpc, TRUE);

			/* Freeing of ``um'' will happen in upnp_map_delete_reply() */
			um->rpc = upnp_ctrl_DeletePortMapping(usd, um->proto, um->port,
				upnp_map_delete_reply, um);

			if (um->rpc != NULL)
				igd.delete_pending++;
			return;
		}

	delete:
		upnp_mapping_free(um, FALSE);
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
			g_message("UPNP successfully deleted mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
	} else {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP could not remove mapping for %s port %u: "
				"%d => \"%s\"",
				upnp_map_proto_to_string(um->proto), um->port,
				code, upnp_strerror(code));
		}
	}

	/*
	 * We keep the mapping around, in case UPnP is re-enabled.
	 */

	um->published = FALSE;
}

/**
 * Remove published mapping.
 */
static void
upnp_remove_mapping_kv(void *key, void *u_value, void *u_data)
{
	struct upnp_mapping *um = key;
	const upnp_service_t *usd;

	(void) u_value;
	(void) u_data;

	if (!um->published)
		return;

	if (GNET_PROPERTY(upnp_debug) > 1) {
		g_message("UPNP removing mapping for %s port %u",
			upnp_map_proto_to_string(um->proto), um->port);
	}


	usd = upnp_service_get_wan_connection(igd.dev->services);
	upnp_ctrl_cancel_null(&um->rpc, TRUE);

	um->rpc = upnp_ctrl_DeletePortMapping(usd, um->proto, um->port,
		upnp_map_mapping_deleted, um);

	if (NULL == um->rpc) {
		if (GNET_PROPERTY(upnp_debug)) {
			g_warning("UPNP cannot remove mapping for %s port %u",
				upnp_map_proto_to_string(um->proto), um->port);
		}
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
		g_hash_table_foreach(upnp_mappings, upnp_remove_mapping_kv, NULL);
	}
}

/**
 * Request immediate (asynchronous) mapping publishing for all the mappings
 * we may have recorded, regardless of whether they were already published
 * before.
 */
static void
upnp_publish_mapping_kv(void *key, void *u_value, void *u_data)
{
	struct upnp_mapping *um = key;

	(void) u_value;
	(void) u_data;

	/*
	 * Schedule publishing to happen at next callout queue tick.
	 */

	cq_cancel(&um->install_ev);
	um->install_ev = cq_main_insert(1, upnp_map_publish, um);

	if (GNET_PROPERTY(upnp_debug) > 2) {
		g_message("UPNP requested immediate publishing for %s port %u",
			upnp_map_proto_to_string(um->proto), um->port);
	}
}

/**
 * UPnP IDG was discovered.
 *
 * If we have mappings to install, do so immediately.
 */
static void
upnp_idg_discovered(void)
{
	g_assert(igd.dev != NULL);

	if (!GNET_PROPERTY(port_mapping_required))
		return;

	g_hash_table_foreach(upnp_mappings, upnp_publish_mapping_kv, NULL);
}

/**
 * Add TCP port redirection on the IGD device to this machine.
 */
void
upnp_map_tcp(guint16 port)
{
	upnp_map_add(UPNP_MAP_TCP, port);
}

/**
 * Add UDP port redirection on the IGD device to this machine.
 */
void
upnp_map_udp(guint16 port)
{
	upnp_map_add(UPNP_MAP_UDP, port);
}

/**
 * Remove TCP port redirection on the IGD device.
 */
void
upnp_unmap_tcp(guint16 port)
{
	upnp_map_remove(UPNP_MAP_TCP, port);
}

/**
 * Remove UDP port redirection on the IGD device.
 */
void
upnp_unmap_udp(guint16 port)
{
	upnp_map_remove(UPNP_MAP_UDP, port);
}

/**
 * Record local IP address.
 */
void
upnp_set_local_addr(host_addr_t addr)
{
	if (host_addr_equal(addr, upnp_local_addr))
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

	cq_periodic_add(callout_queue, UPNP_MONITOR_DELAY_MS,
		upnp_monitor_igd, NULL);

	upnp_mappings = g_hash_table_new(upnp_mapping_hash, upnp_mapping_eq);
}

/**
 * UPnP post initialization.
 */
void
upnp_post_init(void)
{
	/*
	 * In case UPnP support was disabled, upnp_discover() will do nothing.
	 *
	 * We call it nonethless since at high debugging levels it will log
	 * that support is disabled.
	 */

	upnp_discover(UPNP_DISCOVERY_TIMEOUT, upnp_discovered, NULL);
}

/**
 * Free mappings still present, warning about them since normal cleanup
 * should remove them.
 */
static gboolean
upnp_free_mapping_kv(void *key, void *u_value, void *u_data)
{
	struct upnp_mapping *um = key;

	(void) u_value;
	(void) u_data;

	g_warning("UPNP %spublished mapping for %s port %u still present",
		um->published ? "" : "un",
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
	upnp_ctrl_cancel_null(&igd.monitor, FALSE);
	g_hash_table_foreach_remove(upnp_mappings, upnp_free_mapping_kv, NULL);
	gm_hash_table_destroy_null(&upnp_mappings);
}

/* vi: set ts=4 sw=4 cindent: */
