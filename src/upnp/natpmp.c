/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * NAT Port Mapping Protocol.
 *
 * This is some kind of plug-and-play mechanism for establishing port mappings
 * on the NAT gateway.  It's totally different from the UPnP standard: it
 * only focuses on port mapping and uses small binary UDP messages instead of
 * heavy SOAP XML.
 *
 * However, since it is another mechanism to assure network plug-and-play,
 * it is held within the "upnp" module and is actually the preferred mechanism
 * for establishing mappings when we have the choice.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "natpmp.h"

#include "core/urpc.h"

#include "if/gnet_property_priv.h"

#include "lib/bstr.h"
#include "lib/cq.h"
#include "lib/getgateway.h"
#include "lib/pmsg.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define NATPMP_SRV_PORT		5351			/**< Server port */
#define NATPMP_CLT_PORT		5350			/**< Client port */

#define NATPMP_TIMEOUT		250				/**< 250 ms */
#define NATPMP_ITER_MAX		8				/**< Max number of iterations */
#define NATPMP_REPLY_OFF	128				/**< Opcode offset for replies */

enum natpmp_magic { NATPMP_MAGIC = 0x22c24390 };

struct natpmp {
	enum natpmp_magic magic;
	host_addr_t gateway;		/**< Gateway address */
	host_addr_t wan_ip;			/**< External IP address */
	unsigned sssoe;				/**< Seconds since start of epoch */
	time_t last_update;			/**< When sssoe was last updated */
	unsigned rebooted:1;		/**< Whether gateway reboot was detected */
};

static inline void
natpmp_check(const struct natpmp * const np)
{
	g_assert(np != NULL);
	g_assert(NATPMP_MAGIC == np->magic);
}

/**
 * A NAT-PMP capable gateway.
 */

enum natpmp_rpc_magic	{ NATPMP_RPC_MAGIC = 0x5232e29d };

enum natpmp_op {
	NATPMP_OP_INVALID = -1,		/**< Invalid; for initialization */
	NATPMP_OP_DISCOVERY = 0,	/**< Discovery operation */
	NATPMP_OP_MAP_TCP = 1,		/**< TCP port mapping request */
	NATPMP_OP_MAP_UDP = 2		/**< UDP port mapping request */
};

/**
 * A NAT-PMP RPC descriptor.
 */
struct natpmp_rpc {
	enum natpmp_rpc_magic magic;
	host_addr_t gateway;		/**< Gateway address */
	enum natpmp_op op;			/**< Requested operation */
	union {
		natpmp_discover_cb_t discovery;	/**< Discovery callback */
		natpmp_map_cb_t map;			/**< Mapping callback */
	} cb;
	void *arg;					/**< Additional callback argument */
	pmsg_t *mb;					/**< Message to send */
	natpmp_t *np;				/**< Known NAT-PMP gateway */
	unsigned timeout;			/**< Next timeout, in milliseconds */
	unsigned sssoe;				/**< Seconds since start of epoch */
	unsigned retries;			/**< Max amount of retries */
	unsigned count;				/**< Iteration count */
	uint16 iport;				/**< Internal port (in mapping RPCs) */
};

static inline void
natpmp_rpc_check(const struct natpmp_rpc * const rd)
{
	g_assert(rd != NULL);
	g_assert(NATPMP_RPC_MAGIC == rd->magic);
}

static unsigned natpmp_rpc_pending;

static void natpmp_rpc_iterate(cqueue_t *cq, void *obj);

/**
 * Allocate a new NAT-PMP gateway.
 */
static natpmp_t *
natpmp_alloc(host_addr_t gateway, unsigned sssoe, host_addr_t wan_ip)
{
	natpmp_t *np;

	WALLOC(np);
	np->magic = NATPMP_MAGIC;
	np->gateway = gateway;
	np->wan_ip = wan_ip;
	np->sssoe = sssoe;
	np->last_update = tm_time();

	return np;
}

/**
 * Free a NAT-PMP gateway.
 */
static void
natpmp_free(natpmp_t *np)
{
	natpmp_check(np);

	np->magic = 0;
	WFREE(np);
}

/**
 * Fetch NAT-PMP gateway address.
 */
host_addr_t
natpmp_gateway_addr(const natpmp_t *np)
{
	natpmp_check(np);

	return np->gateway;
}

/**
 * Fetch WAN IP of NAT-PMP gateway.
 */
host_addr_t
natpmp_wan_ip(const natpmp_t *np)
{
	natpmp_check(np);

	return np->wan_ip;
}

/**
 * Check whether NAT-PMP gateway rebooted.
 */
bool
natpmp_has_rebooted(const natpmp_t *np)
{
	natpmp_check(np);

	return np->rebooted;
}

/**
 * Clear "rebooted" flag.
 */
void
natpmp_clear_rebooted(natpmp_t *np)
{
	natpmp_check(np);

	np->rebooted = FALSE;
}

/**
 * Update internal information about the NAT-PMP gateway upon reception
 * of an RPC reply.
 */
static void
natpmp_update(natpmp_t *np, unsigned sssoe)
{
	time_delta_t d;
	unsigned conservative_sssoe;

	natpmp_check(np);

	d = delta_time(tm_time(), np->last_update);
	conservative_sssoe = uint_saturate_add(np->sssoe, 7 * d / 8);

	if (sssoe < conservative_sssoe && conservative_sssoe - sssoe > 1) {
		np->rebooted = TRUE;
		if (GNET_PROPERTY(natpmp_debug) > 1) {
			g_debug("NATPMP new SSSOE=%u < conservative SSSOE=%u, %s rebooted",
				sssoe, conservative_sssoe, host_addr_to_string(np->gateway));
		}
	}

	np->last_update = tm_time();
	np->sssoe = sssoe;
}

/**
 * Free a NAT-PMP gateway and nullify its pointer.
 */
void
natpmp_free_null(natpmp_t **np_ptr)
{
	natpmp_t *np = *np_ptr;

	if (np != NULL) {
		natpmp_free(np);
		*np_ptr = NULL;
	}
}

/**
 * Allocate NAT-PMP RPC descriptor.
 */
static struct natpmp_rpc *
natpmp_rpc_alloc(natpmp_t *np, host_addr_t addr, enum natpmp_op op, pmsg_t *mb)
{
	struct natpmp_rpc *rd;

	WALLOC0(rd);
	rd->magic = NATPMP_RPC_MAGIC;
	rd->gateway = addr;
	rd->op = op;
	rd->np = np;
	rd->mb = mb;
	rd->timeout = NATPMP_TIMEOUT;
	rd->retries = NATPMP_ITER_MAX;
	rd->count = 0;

	natpmp_rpc_pending++;

	return rd;
}

/**
 * Free NAT-PMP RPC descriptor.
 */
static void
natpmp_rpc_free(struct natpmp_rpc *rd)
{
	natpmp_rpc_check(rd);

	g_assert(uint_is_positive(natpmp_rpc_pending));

	natpmp_rpc_pending--;

	pmsg_free_null(&rd->mb);
	rd->magic = 0;
	WFREE(rd);
}

/**
 * How many pending NAT-PMP requests do we have?
 */
unsigned
natpmp_pending(void)
{
	return natpmp_rpc_pending;
}

/**
 * Translates a NAT-PMP error code into a human-readable string.
 */
const char *
natpmp_strerror(int code)
{
	switch (code) {
	case NATPMP_E_OK:			return "OK";
	case NATPMP_E_VERSION:		return "Unsupported Version";
	case NATPMP_E_PERM:			return "Not Authorized / Refused";
	case NATPMP_E_NETWORK:		return "Network Failure";
	case NATPMP_E_RESOURCE:		return "Out of Resources";
	case NATPMP_E_OPCODE:		return "Unsupported Opcode";
	case NATPMP_E_TX:			return "TX Error";
	default:					return "Unknown Error";
	}
}

/**
 * Translates NAT-PMP operation code into a human-readable string.
 */
static const char *
natpmp_op_to_string(enum natpmp_op op)
{
	switch (op) {
	case NATPMP_OP_DISCOVERY:	return "Discovery";
	case NATPMP_OP_MAP_TCP:		return "TCP Mapping";
	case NATPMP_OP_MAP_UDP:		return "UDP Mapping";
	case NATPMP_OP_INVALID:		break;
	}

	return "Unknown NAT-PMP opcode";
}

/**
 * Report a NAT-PMP TX operation error.
 */
static void
natpmp_rpc_error(struct natpmp_rpc *rd)
{
	natpmp_rpc_check(rd);

	switch (rd->op) {
	case NATPMP_OP_DISCOVERY:
		(*rd->cb.discovery)(FALSE, NULL, rd->arg);
		break;
	case NATPMP_OP_MAP_TCP:
	case NATPMP_OP_MAP_UDP:
		if (rd->cb.map != NULL)
			(*rd->cb.map)(NATPMP_E_TX, 0, 0, rd->arg);
		break;
	case NATPMP_OP_INVALID:
		g_assert_not_reached();
	}

	natpmp_rpc_free(rd);
}

/**
 * Handle reply to a discovery request.
 *
 * @param payload		the received reply
 * @param len			length of reply
 * @param rd			the RPC request descriptor
 *
 * @return TRUE if we successfully processed the reply and notified the
 * user code about the outcome of the request, FALSE if we need to resend
 * the request.
 */
static bool
natpmp_handle_discovery_reply(
	const void *payload, size_t len, struct natpmp_rpc *rd)
{
	bstr_t *bs;
	uint8 version;
	uint8 code;
	uint16 result;
	uint32 ip;
	host_addr_t wan_ip;
	natpmp_t *np;
	uint8 expected_code;

	natpmp_rpc_check(rd);

	expected_code = NATPMP_REPLY_OFF + rd->op;

	/**
	 * A NAT gateway will reply with the following message:
	 *
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Vers = 0      | OP = 128 + 0  | Result Code                   |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Seconds Since Start of Epoch                                  |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | External IP Address (a.b.c.d)                                 |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * The first 32-bits are always present, the remaining of the packet
	 * may or may not be there depending on the result code.
	 */

	bs = bstr_open(payload, len,
			GNET_PROPERTY(natpmp_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Make sure we got a valid reply.
	 */

	bstr_read_u8(bs, &version);
	bstr_read_u8(bs, &code);
	bstr_read_be16(bs, &result);

	if (bstr_has_error(bs))
		goto error;

	if (GNET_PROPERTY(natpmp_debug) > 5) {
		g_debug("NATPMP version=%u, code=%u, result_code=%u (%s)",
			version, code, result, natpmp_strerror(result));
	}

	if (version != NATPMP_VERSION || code != expected_code)
		goto inconsistent;

	if (NATPMP_E_OK != result)
		goto failed;

	bstr_read_be32(bs, &rd->sssoe);
	bstr_read_be32(bs, &ip);

	if (bstr_has_error(bs))
		goto error;

	wan_ip = host_addr_get_ipv4(ip);

	if (GNET_PROPERTY(natpmp_debug) > 5) {
		g_debug("NATPMP SSSOE=%u, WAN IP is %s",
			rd->sssoe, host_addr_to_string(wan_ip));
	}

	if (!host_addr_is_routable(wan_ip))
		goto failed;

	/*
	 * Good, we got a valid reply from the gateway, with a routable WAN IP.
	 */

	if (rd->np != NULL) {
		natpmp_check(rd->np);
		np = rd->np;
		natpmp_update(np, rd->sssoe);
		np->wan_ip = wan_ip;
	} else {
		np = natpmp_alloc(rd->gateway, rd->sssoe, wan_ip);
	}

	(*rd->cb.discovery)(TRUE, np, rd->arg);

	bstr_free(&bs);
	return TRUE;		/* OK */

failed:
	if (GNET_PROPERTY(natpmp_debug))
		g_warning("NATPMP did not find any suitable NAT-PMP gateway");

	(*rd->cb.discovery)(FALSE, rd->np, rd->arg);
	return TRUE;		/* We're done for now */

error:
	if (GNET_PROPERTY(natpmp_debug)) {
		g_warning("NATPMP parsing error while processing discovery reply "
			"(%zu byte%s): %s",
			PLURAL(len), bstr_error(bs));
	}
	goto cleanup;

inconsistent:
	if (GNET_PROPERTY(natpmp_debug)) {
		g_warning("NATPMP inconsistent discovery reply (%zu byte%s) from %s: "
			"version=%u %c= %u, code=%u %c= %u, result_code=%u (%s)",
			PLURAL(len), host_addr_to_string(rd->gateway),
			version, NATPMP_VERSION == version ? '=' : '!', NATPMP_VERSION,
			code, code == expected_code ? '=' : '!', expected_code,
			result, natpmp_strerror(result));
	}
	/* FALL THROUGH */

cleanup:
	bstr_free(&bs);
	return FALSE;
}

/**
 * Handle reply to a mapping request.
 *
 * @param payload		the received reply
 * @param len			length of reply
 * @param rd			the RPC request descriptor
 *
 * @return TRUE if we successfully processed the reply and notified the
 * user code about the outcome of the request, FALSE if we need to resend
 * the request.
 */
static bool
natpmp_handle_mapping_reply(
	const void *payload, size_t len, struct natpmp_rpc *rd)
{
	bstr_t *bs;
	uint8 version;
	uint8 code;
	uint16 result = 0;
	uint16 port;
	uint32 lifetime;
	uint8 expected_code;

	natpmp_rpc_check(rd);

	expected_code = NATPMP_REPLY_OFF + rd->op;

	/*
	 * We expect the following reply to a mapping request:
	 *
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Vers = 0      | OP = 128 + x  | Result Code                   |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Seconds Since Start of Epoch                                  |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Internal Port                 | Mapped External Port          |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Port Mapping Lifetime in Seconds                              |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	bs = bstr_open(payload, len,
			GNET_PROPERTY(natpmp_debug) ? BSTR_F_ERROR : 0);

	/*
	 * Make sure we got a valid reply.
	 */

	bstr_read_u8(bs, &version);
	bstr_read_u8(bs, &code);
	bstr_read_be16(bs, &result);

	if (bstr_has_error(bs))
		goto error;

	if (GNET_PROPERTY(natpmp_debug) > 5) {
		g_debug("NATPMP version=%u, code=%u, result_code=%u (%s)",
			version, code, result, natpmp_strerror(result));
	}

	if (version != NATPMP_VERSION || code != expected_code)
		goto inconsistent;

	if (NATPMP_E_OK != result)
		goto failed;

	/*
	 * We're allowed to parse the remaining of the packet.
	 */

	bstr_read_be32(bs, &rd->sssoe);
	bstr_read_be16(bs, &port);			/* Internal port */
	if (port != rd->iport)
		goto error;
	bstr_read_be16(bs, &port);			/* External port */
	bstr_read_be32(bs, &lifetime);		/* Lease time */

	/*
	 * Signal success, if needed.
	 */

	if (GNET_PROPERTY(natpmp_debug) > 1) {
		g_debug("NATPMP %spublished NAT-PMP mapping for %s port %u",
			0 == lifetime ? "un-" : "",
			NATPMP_OP_MAP_TCP == rd->op ? "TCP" : "UDP", rd->iport);
	}

	if (rd->cb.map != NULL)
		(*rd->cb.map)(result, port, lifetime, rd->arg);

	bstr_free(&bs);
	return TRUE;		/* OK */

failed:
	if (GNET_PROPERTY(natpmp_debug))
		g_warning("NATPMP unable to publish NAT-PMP mapping: %s",
			natpmp_strerror(result));

	if (rd->cb.map != NULL)
		(*rd->cb.map)(result, 0, 0, rd->arg);

	return TRUE;		/* We're done for now */

error:
	if (GNET_PROPERTY(natpmp_debug)) {
		if (bstr_has_error(bs)) {
			g_warning("NATPMP parsing error while processing mapping reply "
				"(%zu byte%s): %s",
				PLURAL(len), bstr_error(bs));
		}
	}
	goto cleanup;

inconsistent:
	if (GNET_PROPERTY(natpmp_debug)) {
		g_warning("NATPMP inconsistent mapping reply (%zu byte%s) from %s: "
			"version=%u %c= %u, code=%u %c= %u, result_code=%u (%s)",
			PLURAL(len), host_addr_to_string(rd->gateway),
			version, NATPMP_VERSION == version ? '=' : '!', NATPMP_VERSION,
			code, code == expected_code ? '=' : '!', expected_code,
			result, natpmp_strerror(result));
	}
	/* FALL THROUGH */

cleanup:
	bstr_free(&bs);
	return FALSE;
}

/**
 * UDP RPC reply (or timeout) callback.
 */
static void
natpmp_rpc_reply(enum urpc_ret type, host_addr_t addr, uint16 port,
	const void *payload, size_t len, void *arg)
{
	struct natpmp_rpc *rd = arg;

	natpmp_rpc_check(rd);

	if (GNET_PROPERTY(natpmp_debug) > 4) {
		g_debug("NATPMP %s for \"%s\" #%u (%lu byte%s) from %s",
			URPC_TIMEOUT == type ? "timeout" :
			URPC_ABORT == type ? "aborted" : "got reply",
			natpmp_op_to_string(rd->op), rd->count,
			(unsigned long) PLURAL(len),
			host_addr_port_to_string(addr, port));
	}

	if (URPC_ABORT == type) {
		natpmp_rpc_error(rd);
		return;
	}

	if (URPC_TIMEOUT == type)
		goto iterate;

	/*
	 * Silently discard a reply not coming from the host to whom we
	 * sent the RPC.
	 */

	if (!host_addr_equiv(addr, rd->gateway)) {
		if (GNET_PROPERTY(natpmp_debug)) {
			g_warning("NATPMP discarding reply from %s (sent %s to %s)",
				host_addr_port_to_string(addr, port),
				natpmp_op_to_string(rd->op),
				host_addr_to_string(rd->gateway));
		}
		goto iterate;
	}

	/*
	 * Dispatch reply processing.
	 */

	switch (rd->op) {
	case NATPMP_OP_DISCOVERY:
		if (!natpmp_handle_discovery_reply(payload, len, rd))
			goto iterate;
		break;
	case NATPMP_OP_MAP_TCP:
	case NATPMP_OP_MAP_UDP:
		if (!natpmp_handle_mapping_reply(payload, len, rd))
			goto iterate;
		break;
	case NATPMP_OP_INVALID:
		g_assert_not_reached();
	}

	/*
	 * All done, request was successful.
	 */

	natpmp_rpc_free(rd);
	return;

iterate:
	natpmp_rpc_iterate(NULL, rd);
}

/**
 * Main RPC iteration loop.
 */
static void
natpmp_rpc_iterate(cqueue_t *unused_cq, void *obj)
{
	struct natpmp_rpc *rd = obj;
	int ret;

	natpmp_rpc_check(rd);
	(void) unused_cq;

	if (rd->count++ > rd->retries)
		goto finished;

	ret = urpc_send("NAT-PMP", rd->gateway, NATPMP_SRV_PORT,
			pmsg_phys_base(rd->mb), pmsg_written_size(rd->mb), rd->timeout,
			natpmp_rpc_reply, rd);

	if (0 != ret) {
		if (GNET_PROPERTY(natpmp_debug)) {
			g_warning("NATPMP could not send \"%s\" #%u to %s: %m",
				natpmp_op_to_string(rd->op), rd->count,
				host_addr_port_to_string(rd->gateway, NATPMP_SRV_PORT));
		}
		goto finished;
	} else {
		if (GNET_PROPERTY(natpmp_debug) > 4) {
			g_debug("NATPMP sent \"%s\" #%u to %s, with %u ms timeout",
				natpmp_op_to_string(rd->op), rd->count,
				host_addr_port_to_string(rd->gateway, NATPMP_SRV_PORT),
				rd->timeout);
		}
	}

	rd->timeout = uint_saturate_mult(rd->timeout, 2);	/* For next time */
	return;

finished:
	natpmp_rpc_error(rd);
}

/**
 * Start a "discovery rpc" sequence.
 *
 * @param np		existing NAT-PMP gateway (NULL if unknown yet)
 * @param retries	amount of retries before timeouting
 * @param cb		callback to invoke on completion / timeout
 * @param arg		user-defined callback argument
 */
static void
natpmp_rpc_discover(natpmp_t *np, unsigned retries,
	natpmp_discover_cb_t cb, void *arg)
{
	struct natpmp_rpc *rd;
	host_addr_t addr;
	pmsg_t *mb;

	if (np != NULL) {
		natpmp_check(np);
		addr = np->gateway;
	} else {
		/*
		 * If we can't determine the default gateway, we can't go much further.
		 * We notify of the discovery failure synchronously.
		 */

		if (0 != getgateway(&addr)) {
			if (GNET_PROPERTY(natpmp_debug))
				g_warning("NATPMP cannot find default gateway");
			(*cb)(FALSE, NULL, arg);
			return;
		} else {
			if (GNET_PROPERTY(natpmp_debug)) {
				g_info("NATPMP gateway is %s", host_addr_to_string(addr));
			}
		}
	}

	/*
	 * Build the discovery request:
	 *
     *    0                   1
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Vers = 0      | OP = 0        |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, 2);
	pmsg_write_u8(mb, NATPMP_VERSION);
	pmsg_write_u8(mb, NATPMP_OP_DISCOVERY);

	/*
	 * Initiate asynchronous iteration discovery.
	 */

	rd = natpmp_rpc_alloc(np, addr, NATPMP_OP_DISCOVERY, mb);
	rd->cb.discovery = cb;
	rd->arg = arg;
	if (retries != 0)
		rd->retries = MIN(retries, rd->retries);

	cq_main_insert(1, natpmp_rpc_iterate, rd);
}

/**
 * Initiate discovery of a NAT-PMP gateway.
 * Upon completion, the callback is invoked with the status.
 *
 * @param retries	number of retries before timeout (0 means default)
 * @param cb		callback to invoke on completion / timeout
 * @param arg		user-defined callback argument
 */
void
natpmp_discover(unsigned retries, natpmp_discover_cb_t cb, void *arg)
{
	/*
	 * We discover even if NAT-PMP support is disabled: we won't publish
	 * mappings via NAT-PMP, but we want to know whether we have a NAT-PMP
	 * device available.
	 */

	if (GNET_PROPERTY(natpmp_debug) > 3)
		g_message("NATPMP initiating discovery");

	natpmp_rpc_discover(NULL, retries, cb, arg);
}

/**
 * Initiate monitoring of a NAT-PMP gateway.
 * Upon completion, the callback is invoked with the status.
 *
 * @param np		the NAT-PMP gateway we want to monitor
 * @param cb		callback to invoke on completion / timeout
 * @param arg		user-defined callback argument
 */
void
natpmp_monitor(natpmp_t *np, natpmp_discover_cb_t cb, void *arg)
{
	natpmp_rpc_discover(np, 0, cb, arg);
}

/**
 * Build a mapping message.
 *
 * This is used for mapping and unmapping request: in the latter case, the
 * external port and the lease time are set to 0 in the message.
 *
 * @param op		the NAT-PMP mapping operation
 * @param port		internal port, to be mapped to same external port
 * @param lease		requested lease time (0 for deletions)
 */
static pmsg_t *
natpmp_build_mapping(enum natpmp_op op, uint16 port, time_delta_t lease)
{
	pmsg_t *mb;

	/*
	 * The framing is done thusly:
	 *
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Vers = 0      | OP = x        | Reserved (MUST be zero)       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Internal Port                 | Requested External Port       |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   | Requested Port Mapping Lifetime in Seconds                    |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * x = 1 for TCP, x = 2 for UDP.
	 */

	mb = pmsg_new(PMSG_P_DATA, NULL, 12);
	pmsg_write_u8(mb, NATPMP_VERSION);
	pmsg_write_u8(mb, op & 0xff);
	pmsg_write_be16(mb, 0);
	pmsg_write_be16(mb, port);
	if (lease != 0) {
		pmsg_write_be16(mb, port);		/* Request same port */
	} else {
		pmsg_write_be16(mb, 0);			/* Must be zero on deletions */
	}
	pmsg_write_be32(mb, lease);

	return mb;
}

/**
 * Request port mapping or deletion.
 *
 * @param np		the NAT-PMP gateway to which we publish the mapping
 * @param proto		protocol type (TCP or UDP)
 * @param port		internal port, to be mapped to same external port
 * @param lease		requested lease time (0 for deletion)
 * @param cb		completion callback
 * @param arg		additional callback argument
 */
static void
natpmp_rpc_map(natpmp_t *np, enum upnp_map_proto proto, uint16 port,
	time_delta_t lease, natpmp_map_cb_t cb, void *arg)
{
	pmsg_t *mb;
	enum natpmp_op op = NATPMP_OP_INVALID;
	struct natpmp_rpc *rd;

	natpmp_check(np);

	switch (proto) {
	case UPNP_MAP_TCP: op = NATPMP_OP_MAP_TCP; break;
	case UPNP_MAP_UDP: op = NATPMP_OP_MAP_UDP; break;
	case UPNP_MAP_MAX: g_assert_not_reached();
	}
	g_assert(NATPMP_OP_INVALID != op);

	/*
	 * Creating the mapping message.
	 */

	mb = natpmp_build_mapping(op, port, lease);

	/*
	 * Initiate asynchronous publishing only when there is a user callback.
	 */

	rd = natpmp_rpc_alloc(np, np->gateway, op, mb);
	rd->cb.map = cb;
	rd->arg = arg;
	rd->iport = port;	/* We only accept same internal and external ports */

	if (NULL == cb) {
		natpmp_rpc_iterate(NULL, rd);		/* Synchronous */
	} else {
		cq_main_insert(1, natpmp_rpc_iterate, rd);
	}
}

/**
 * Request port mapping.
 *
 * @param np		the NAT-PMP gateway to which we publish the mapping
 * @param proto		protocol type (TCP or UDP)
 * @param port		internal port, to be mapped to same external port
 * @param lease		requested lease time
 * @param cb		completion callback
 * @param arg		additional callback argument
 */
void
natpmp_map(natpmp_t *np, enum upnp_map_proto proto, uint16 port,
	time_delta_t lease, natpmp_map_cb_t cb, void *arg)
{
	natpmp_check(np);
	g_assert(lease != 0);		/* Since 0 is for deletion */

	natpmp_rpc_map(np, proto, port, lease, cb, arg);
}

/**
 * Unmap specified port.
 *
 * This is an advisory unmapping, there is no callback to the user when done.
 */
void
natpmp_unmap(natpmp_t *np, enum upnp_map_proto proto, uint16 port)
{
	natpmp_check(np);

	natpmp_rpc_map(np, proto, port, 0, NULL, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
