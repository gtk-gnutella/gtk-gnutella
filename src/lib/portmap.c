/*
 * $Id: portmap.c 17860 2010-11-28 15:51:31Z nonamer $
 *
 * Copyright (c) 2010, Jeroen Asselman
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
 * @ingroup lib
 * @file
 *
 * Portmapping utility routines.
 *
 * @author Jeroen Asselman
 * @date 2010
 */

#include "common.h"

RCSID("$Id: portmap.c 17860 2010-11-28 15:51:31Z nonamer $")

#include "glib-missing.h"

#ifdef MINIUPNPC
#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#endif

#include "override.h"			/* Must be the last header included */

#ifdef MINIUPNPC

static struct UPNPUrls urls;
static struct IGDdatas data;
static char lanaddr[64];	/* UPnP local ip address */

void 
upnp_init(void)
{
	struct UPNPDev * devlist;
	struct UPNPDev * dev;
	char * descXML;
	int descXMLsize = 0;
	g_debug("upnp_init()");
	memset(&urls, 0, sizeof(struct UPNPUrls));
	memset(&data, 0, sizeof(struct IGDdatas));
	devlist = upnpDiscover(2000, NULL, NULL, 0);
	if (devlist) {
		dev = devlist;
		while (dev)
		{
			if (strstr (dev->st, "InternetGatewayDevice"))
				break;
				
			dev = dev->pNext;
		}
		if (!dev)
			dev = devlist; /* defaulting to first device */

		g_info("UPnP device %s\t st: %s",
			   dev->descURL, dev->st);

		descXML = miniwget(dev->descURL, &descXMLsize);
		if (descXML) {
			parserootdesc (descXML, descXMLsize, &data);
			free (descXML); descXML = 0;
			GetUPNPUrls (&urls, &data, dev->descURL);
		}
		
		UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
		g_info("UPnP local LAN ip address : %s", lanaddr);
		
		freeUPNPDevlist(devlist);
	}
}

void
upnp_add_redir (const char *proto, const char * addr, int port)
{
	char port_str[16];
	int r;
	
	if (NULL == addr)
		addr = lanaddr;
		
	g_debug("upnp_add_redir %s %s:%d", proto, addr, port);
	
	if(urls.controlURL[0] == '\0') {
		g_warning("UPnP init was not done!");
		return;
	}
	
	sprintf(port_str, "%d", port);
	r = UPNP_AddPortMapping(urls.controlURL, data.CIF.servicetype,
		port_str, port_str, addr, 
		"gtk-gnutella", proto, NULL);
		
	if(0 != r)
		g_warning("AddPortMapping(%s, %s, %s) failed %d", 
			port_str, port_str, addr, r);
}

void
upnp_add_tcp_redir (const char * addr, int port)
{
	upnp_add_redir("TCP", addr, port);
}

void
upnp_add_udp_redir (const char * addr, int port)
{
	upnp_add_redir("UDP", addr, port);
}
void
upnp_rem_redir (const char * proto, int port)
{
	char port_str[16];

	g_debug("upnp_rem_redir %s :%d", proto, port);

	if(urls.controlURL[0] == '\0') {
		g_warning("UPnP init was not done !");
		return;
	}
	
	sprintf(port_str, "%d", port);
	UPNP_DeletePortMapping(urls.controlURL, data.CIF.servicetype, 
		port_str, proto, NULL);
}

void
upnp_rem_tcp_redir (int port)
{
	upnp_rem_redir("TCP", port);
}

void
upnp_rem_udp_redir (int port)
{
	upnp_rem_redir("UDP", port);
}

#endif


void 
portmap_init(void)
{
#ifdef MINIUPNPC
	upnp_init();
#endif
}

void 
portmap_map_tcp_port(int port)
{
#ifdef MINIUPNPC
	upnp_add_tcp_redir(NULL, port);
#else
	(void) port;
#endif
}

void 
portmap_map_udp_port(int port)
{
#ifdef MINIUPNPC
	upnp_add_udp_redir(NULL, port);
#else
	(void) port;
#endif
}

void
portmap_unmap_tcp_port(int port)
{
#ifdef MINIUPNPC
	upnp_rem_tcp_redir(port);
#else
	(void) port;
#endif
}

void
portmap_unmap_udp_port(int port)
{
#ifdef MINIUPNPC
	upnp_rem_udp_redir(port);
#else
	(void) port;
#endif
}

/* vi: set ts=4 sw=4 cindent: */
