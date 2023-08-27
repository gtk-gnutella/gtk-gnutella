/*
 * Copyright (c) 2009, 2012 Raphael Manfredi
 * Copyright (c) 2006 Christian Biere
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
 * Traffic dumping, for later analysis with barracuda.
 *
 * To use traffic dumping, one needs to create named pipes in the
 * configuration directory (~/.gtk-gnutella, usually).
 *
 * When told to dump data, gtk-gnutella opens the corresponding named
 * pipe for writing, the user needing to open it for reading to get
 * the traffic dumps.
 *
 * Dumping is non-blocking and automatically stops when the pipe becomes
 * full, meaning the reader stopped or cannot extract data fast enough.
 *
 * Two properties (which can be set through a shell command) are governing
 * whether traffic dumping should be done, with explicit names:
 *
 *    dump_received_gnutella_packets
 *    dump_transmitted_gnutella_packets
 *
 * Because indiscriminate traffic dumping can create a lot of output, three
 * additional properties are used (RX = receive, TX = transmit):
 *
 *    dump_rx_addrs
 *    dump_tx_from_addrs
 *    dump_tx_to_addrs
 *
 * These contain a comma-separated list of IP addresses that are used to
 * filter traffic: only traffic sent to or originating from the listed
 * addresses (depending on whether we're filtering for TX or RX) is dumped.
 * An empty set means no filtering is done at all, i.e. everything is logged.
 *
 * When dumping TX traffic, we can filter on both from/to, but RX traffic
 * can only be filtered on its from address.  This is because RX traffic is
 * dumped just after being received and before we know the fate of the packet,
 * whereas TX traffic is dumped when the packet is sent out, at which time we
 * know both its origin and its destination.
 *
 * Dumps are made with a header, hence one must use "barracuda -D" to
 * post-process the logs.
 *
 * Here is a sample traffic dumping session:
 *
 * # create the named pipes
 * mknod ~/.gtk-gnutella/packets_rx.dump p
 * mknod ~/.gtk-gnutella/packets_tx.dump p
 *
 * # prepare TX traffic reading
 * gzip -9 <~/.gtk-gnutella/packets_tx.dump >traffic.gz
 *
 * # request gtk-gnutella dumpping
 * echo set dump_transmitted_gnutella_packets TRUE | gtk-gnutella --shell
 *
 * # when done, hit ^C and post-process with barracuda
 * gzcat traffic.gz | barracuda -D | less
 *
 * # to cleanly stop dumps, use this instead of hitting ^C
 * echo set dump_transmitted_gnutella_packets FALSE | gtk-gnutella --shell
 *
 * @author Raphael Manfredi
 * @date 2009, 2012
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "nodes.h"
#include "settings.h"

#include "lib/fd.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/ipset.h"
#include "lib/path.h"
#include "lib/pmsg.h"
#include "lib/slist.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define DUMP_BUFFER_MAX	(256 * 1024UL)	/* Max amount we keep in memory */

/**
 * Barracuda header flags.
 */
enum dump_header_flags {
	DH_F_UDP  = (1 << 0),
	DH_F_TCP  = (1 << 1),
	DH_F_IPV4 = (1 << 2),
	DH_F_IPV6 = (1 << 3),
	DH_F_TO   = (1 << 4),
	DH_F_CTRL = (1 << 5),

	NUM_DH_F
};

/**
 * Barracuda dump header.
 */
struct dump_header {
/*
 * This is the logic layout:
 *
 *	uint8_t flags;
 *	uint8_t addr[16];
 *	uint8_t port[2];
 */
	uchar data[19];
};

/**
 * Dumping context.
 */
struct dump {
	const char * const filename;
	slist_t *slist;
	const bool *dump_var;
	size_t fill;
	int fd;
	int initialized;
	gnet_property_t dump_property;
};

static struct dump dump_rx = {
	"packets_rx.dump",		/* filename in ~/.gtk-gnutella */
	NULL,					/* slist */
	GNET_PROPERTY_PTR(dump_received_gnutella_packets),	/* dump_var */
	0,						/* fill */
	-1,						/* fd */
	FALSE,					/* initialized */
	PROP_DUMP_RECEIVED_GNUTELLA_PACKETS,	/* dump_property */
};

static struct dump dump_tx = {
	"packets_tx.dump",		/* filename in ~/.gtk-gnutella */
	NULL,					/* slist */
	GNET_PROPERTY_PTR(dump_transmitted_gnutella_packets),	/* dump_var */
	0,						/* fill */
	-1,						/* fd */
	FALSE,					/* initialized */
	PROP_DUMP_TRANSMITTED_GNUTELLA_PACKETS,	/* dump_property */
};

static ipset_t dump_rx_addrs = IPSET_INIT;
static ipset_t dump_tx_from_addrs = IPSET_INIT;
static ipset_t dump_tx_to_addrs = IPSET_INIT;

/**
 * Fill dump header with node address information.
 */
static void
dump_header_set(struct dump_header *dh, const gnutella_node_t *node)
{
	ZERO(dh);

	dh->data[0] = NODE_IS_UDP(node) ? DH_F_UDP : DH_F_TCP;
	switch (host_addr_net(node->addr)) {
	case NET_TYPE_IPV4:
		{
			uint32 ip;

			dh->data[0] |= DH_F_IPV4;
			ip = host_addr_ipv4(node->addr);
			poke_be32(&dh->data[1], ip);
		}
		break;
	case NET_TYPE_IPV6:
		dh->data[0] |= DH_F_IPV6;
		memcpy(&dh->data[1], host_addr_ipv6(&node->addr), 16);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	poke_be16(&dh->data[17], node->port);
}

/**
 * Disable dumps.
 */
static void
dump_disable(struct dump *dump)
{
	pmsg_slist_free(&dump->slist);
	dump->fill = 0;

	if (dump->fd >= 0)
		fd_close(&dump->fd);

	dump->initialized = FALSE;
	if (*dump->dump_var)
		gnet_prop_set_boolean_val(dump->dump_property, FALSE);
}

/**
 * Initialize RX dumping.
 *
 * @return TRUE if initialized.
 */
static bool
dump_initialize(struct dump *dump)
{
	char *pathname;

	if (dump->initialized)
		return TRUE;

	pathname = make_pathname(settings_config_dir(), dump->filename);
	dump->fd = file_open_missing(pathname, O_WRONLY | O_APPEND | O_NONBLOCK);
	HFREE_NULL(pathname);

	/*
	 * If the dump "file" is actually a named pipe, we'd block quickly
	 * if there was no reader.  So set the file as non-blocking and
	 * we'll disable dumping as soon as we can't write all the data
	 * we want.
	 */

	if (dump->fd < 0) {
		g_warning("can't open %s -- disabling dumping", dump->filename);
		dump_disable(dump);
		return FALSE;
	}

	fd_set_nonblocking(dump->fd);

	dump->slist = slist_new();
	dump->fill = 0;
	dump->initialized = TRUE;

	return TRUE;
}

/**
 * Append data to the dump buffer.
 */
static void
dump_append(struct dump *dump, const void *data, size_t size)
{
	g_return_if_fail(dump->slist);

	pmsg_slist_append(dump->slist, data, size);
	dump->fill += size;
}

/**
 * Flush buffered data.
 */
static void
dump_flush(struct dump *dump)
{
	while (dump->fill > 0) {
		ssize_t written;
		iovec_t *iov;
		int iov_cnt;

		iov = pmsg_slist_to_iovec(dump->slist, &iov_cnt, NULL);
		written = writev(dump->fd, iov, iov_cnt);
		HFREE_NULL(iov);

		if ((ssize_t)-1 == written) {
			if (!is_temporary_error(errno)) {
				g_warning("error writing to %s: %m -- disabling dumping",
					dump->filename);
				dump_disable(dump);
			}
			if (dump->fill >= DUMP_BUFFER_MAX) {
				g_warning(
					"queue is full: %s -- disabling dumping", dump->filename);
				dump_disable(dump);
			}
			break;
		} else if (0 == written) {
			g_warning("error writing to %s: hang up -- disabling dumping",
				dump->filename);
			dump_disable(dump);
			break;
		} else {
			g_assert(dump->fill >= (size_t) written);
			dump->fill -= written;
			pmsg_slist_discard(dump->slist, written);
		}
	}
}

/**
 * Dump packet received from node.
 */
static void
dump_packet_from(struct dump *dump, const gnutella_node_t *node)
{
	struct dump_header dh;

	g_assert(node != NULL);

	if (!dump_initialize(dump))
		return;

	if (!ipset_contains_addr(&dump_rx_addrs, node->addr, TRUE))
		return;

	dump_header_set(&dh, node);
	dump_append(dump, ARYLEN(dh.data));
	dump_append(dump, ARYLEN(node->header));
	dump_append(dump, node->data, node->size);
	dump_flush(dump);
}

/**
 * Dump relayed or locally-emitted packet.
 * If ``from'' is NULL, packet was emitted locally.
 */
static void
dump_packet_from_to(struct dump *dump,
	const gnutella_node_t *from, const gnutella_node_t *to,
	const pmsg_t *mb)
{
	struct dump_header dh_to;
	struct dump_header dh_from;

	g_assert(to != NULL);
	g_assert(mb != NULL);
	g_assert(pmsg_is_unread(mb));

	if (!dump_initialize(dump))
		return;

	/*
	 * This is only for Gnutella packets, leave DHT messages out.
	 */

	if (GTA_MSG_DHT == gnutella_header_get_function(pmsg_phys_base(mb)))
		return;

	if (!ipset_contains_addr(&dump_tx_to_addrs, to->addr, TRUE))
		return;

	if (NULL == from) {
		gnutella_node_t local;
		local.peermode = NODE_IS_UDP(to) ? NODE_P_UDP : NODE_P_NORMAL;
		local.addr = listen_addr();
		local.port = GNET_PROPERTY(listen_port);
		if (!ipset_contains_addr(&dump_tx_from_addrs, local.addr, TRUE))
			return;
		dump_header_set(&dh_from, &local);
	} else {
		if (!ipset_contains_addr(&dump_tx_from_addrs, from->addr, TRUE))
			return;
		dump_header_set(&dh_from, from);
	}

	dump_header_set(&dh_to, to);
	dh_to.data[0] |= DH_F_TO;
	if (pmsg_prio(mb) != PMSG_P_DATA)
		dh_to.data[0] |= DH_F_CTRL;

	dump_append(dump, ARYLEN(dh_to.data));
	dump_append(dump, ARYLEN(dh_from.data));
	dump_append(dump, pmsg_start(mb), pmsg_size(mb));
	dump_flush(dump);
}

/**
 * Dump packet received from node.
 */
void
dump_rx_packet(const gnutella_node_t *node)
{
	if (GNET_PROPERTY(dump_received_gnutella_packets)) {
		dump_packet_from(&dump_rx, node);
	} else if (dump_rx.initialized) {
		dump_disable(&dump_rx);
	}
}

/**
 * Dump transmitted message block via TCP.
 * If ``from'' is NULL, packet was emitted locally.
 */
void
dump_tx_tcp_packet(
	const gnutella_node_t *from, const gnutella_node_t *to,
	const pmsg_t *mb)
{
	if (GNET_PROPERTY(dump_transmitted_gnutella_packets)) {
		g_assert(to != NULL);
		g_assert(mb != NULL);
		g_assert(!NODE_IS_UDP(to));

		dump_packet_from_to(&dump_tx, from, to, mb);
	} else if (dump_tx.initialized) {
		dump_disable(&dump_tx);
	}
}

/**
 * Dump locally-emitted message block sent via UDP.
 */
void
dump_tx_udp_packet(const gnet_host_t *to, const pmsg_t *mb)
{
	if (GNET_PROPERTY(dump_transmitted_gnutella_packets)) {
		gnutella_node_t udp;

		g_assert(to != NULL);
		g_assert(mb != NULL);

		/*
		 * Fill only the fields which will be perused by
		 * dump_packet_from_to().
		 */

		udp.peermode = NODE_P_UDP;
		udp.addr = gnet_host_get_addr(to);
		udp.port = gnet_host_get_port(to);

		dump_packet_from_to(&dump_tx, NULL, &udp, mb);
	} else if (dump_tx.initialized) {
		dump_disable(&dump_tx);
	}
}

/**
 * Dump RX traffic coming from listed addresses, all addresses if empty.
 */
void
dump_rx_set_addrs(const char *s)
{
	ipset_set_addrs(&dump_rx_addrs, s);
}

/**
 * Dump TX traffic coming from listed addresses, all addresses if empty.
 */
void dump_tx_set_from_addrs(const char *s)
{
	ipset_set_addrs(&dump_tx_from_addrs, s);
}

/**
 * Dump TX traffic sent to listed addresses, all addresses if empty.
 */
void dump_tx_set_to_addrs(const char *s)
{
	ipset_set_addrs(&dump_tx_to_addrs, s);
}

/**
 * Initialize traffic dumping.
 */
void
dump_init(void)
{
	/* Nothing to do, initialized on the fly */
}

/**
 * Close traffic dumping.
 */
void
dump_close(void)
{
	if (dump_rx.initialized)
		dump_disable(&dump_rx);
	if (dump_tx.initialized)
		dump_disable(&dump_tx);

	ipset_clear(&dump_rx_addrs);
	ipset_clear(&dump_tx_from_addrs);
	ipset_clear(&dump_tx_to_addrs);
}

/* vi: set ts=4 sw=4 cindent: */
