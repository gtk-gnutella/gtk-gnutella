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
 * @ingroup core
 * @file
 *
 * Simple Object Access Protocol (SOAP).
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _core_soap_h_
#define _core_soap_h_

#include "common.h"

#include "xml/xnode.h"
#include "lib/header.h"
#include "lib/host_addr.h"

struct soap_rpc;
typedef struct soap_rpc soap_rpc_t;

/**
 * SOAP error codes.
 */
typedef enum soap_error {
	SOAP_E_OK = 0,					/**< OK */
	SOAP_E_CANCELLED,				/**< Request cancelled by user */
	SOAP_E_CONTACT,					/**< HTTP establishment error */
	SOAP_E_TIMEOUT,					/**< HTTP timeout */
	SOAP_E_TRANSPORT,				/**< HTTP transport error */
	SOAP_E_DATA2BIG,				/**< Data exceeds maximum size */
	SOAP_E_FAILED,					/**< Reported failure, no SOAP fault */
	SOAP_E_FAULT,					/**< SOAP fault reported */
	SOAP_E_PROTOCOL,				/**< SOAP protocol error */
	SOAP_E_PROCESSING,				/**< SOAP reply processing error */
	SOAP_E_MAX
} soap_error_t;

/**
 * Callback used when we get a reply to a SOAP request.
 *
 * @param sr		the SOAP RPC request
 * @param root		XML tree of SOAP reply
 * @param arg		additional user-supplied argument
 */
typedef void (*soap_reply_cb_t)(const soap_rpc_t *sr, xnode_t *root, void *arg);

/**
 * Callback used when we get an error during a SOAP request.
 *
 * @param sr		the SOAP RPC request
 * @param err		error code
 * @param fault		on SOAP faults, the XML tree of the fault
 * @param arg		additional user-supplied argument
 */
typedef void (*soap_error_cb_t)(const soap_rpc_t *sr,
	soap_error_t err, xnode_t *fault, void *arg);

/**
 * Options for soap_rpc().
 */
#define SOAP_RPC_O_MAN_FORCE	(1 << 0)	/**< Force mandatory HTTP */
#define SOAP_RPC_O_MAN_RETRY	(1 << 1)	/**< Allow mandatory HTTP retry */
#define SOAP_RPC_O_LOCAL_ADDR	(1 << 2)	/**< Grab local IP address */
#define SOAP_RPC_O_ALL_CAPS		(1 << 3)	/**< Emit all-caps header names */

/*
 * Public interface.
 */

const char *soap_strerror(soap_error_t errnum);
void soap_rpc_cancel(soap_rpc_t *sr);

soap_rpc_t *soap_rpc(const char *url, const char *action, size_t maxlen,
	uint32 options, xnode_t *xn, const char *soap_ns,
	soap_reply_cb_t reply_cb, soap_error_cb_t error_cb, void *arg);

bool soap_rpc_local_addr(const soap_rpc_t *sr, host_addr_t *addrp);

#endif /* _core_soap_h_ */

/* vi: set ts=4 sw=4 cindent: */
