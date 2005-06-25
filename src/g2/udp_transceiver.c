/*
 * Copyright (c) 2004, Jeroen Asselman
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
 * @ingroup undoc
 * @file
 *
 * Needs short description here.
 *
 * @author Jeroen Asselman
 * @date 2004
 */

#include "../common.h"		/* For -DUSE_DMALLOC */

#include <math.h>
#include <glib.h>

int sequencenumber = 0;

static int header_length = 8;
static int MTU = 1500;
int transmit_retransmit_interval = 10;	/**< seconds */
int transmit_packet_timeout = 26;		/**< seconds */
int receive_packet_expiry = 30;			/**< seconds */

GSList *receiving_fragments_list;
GSList *received_fragments_list;

typedef struct fragment_s fragment_t;
struct fragment_s
{
	char *fragment;
	int   fragment_length;

	time_t initial_transmitted;
	time_t last_transmitted;

	guint32 ipaddress;
	guint16 port;
};

void udp_transceiver_timer(time_t now)
{
	/* Fragments waiting for acknowledge > receive_packet_expiry?
	 * Remove acknowledge packets.

	 * Fragments waiting for acknowledge?
	 * Time to retransmit?
	 * Retransmit to be acknowledged packets

	 * Fragments to be send?
	 * Send a few fragments. No more then udp_bandwith_out / MTU
	 */
}

/***
 *** Building and sending
 ***/

/**
 * Wether the udp transceiver might be able to handle this received fragment.
 */
gboolean
udp_transceiver_can_handle_received_fragment(char *buf, int length)
{
	return length > header_length &&
		buf[0] == 'G' && buf[1] == 'N' && buf[2] == 'D';
}

/**
 * Put fragment in the to send list.
 */
static void
udp_transceiver_put_send_fragment(fragment_t *fragment)
{
	/* FIXME: glist_prepend fragment */
}

/**
 * Send the fragment.
 */
static void
udp_transceiver_send_fragment(fragment_t *fragment,
							  gboolean deflate,
							  gboolean acknowledge)
{
	/* FIXME: Send fragment over socket. */

	if (acknowledge)
	{
	    /* FIXME: Add fragment to waiting_for_acknowledge list */
	}
}

/**
 * Free the fragment and all its associated memory.
 */
void
udp_transceiver_free_fragment(fragment_t *fragment)
{
	if (fragment->fragment != NULL)
		free(fragment->fragment);

	free(fragment);
}

/**
 * Build a fragment.
 */
fragment_t *
udp_transceiver_build_fragment(char *buffer, int length,
								int sequencenumber,
								int partnumber,
								int fragments,
								gboolean deflate,
								gboolean acknowledge)
{
	fragment_t *fragment = (fragment_t *) malloc(sizeof(fragment_t));
	fragment->fragment_length = length + header_length;
	fragment->fragment = (char *) malloc(fragment->fragment_length);

	/* Build identifier */
	fragment->fragment[0] = 'G';
	fragment->fragment[1] = 'N';
	fragment->fragment[2] = 'D';

	/* Endian doesn't matter */
	fragment->fragment[4] = (sequencenumber & 0x00FF);
	fragment->fragment[5] = (sequencenumber >> 8);
	fragment->fragment[6] = partnumber;
	fragment->fragment[7] = fragments;

	memcpy(fragment->fragment + header_length, buffer, length);

	return fragment;
}

/**
 * Send a fragment to the specified address.
 */
void
udp_transceiver_send(char *buffer, int length, gboolean deflate,
							gboolean acknowledge,
							guint32 address, guint16 port)
{
	/* Create fragments. */
	int fragments = (int) ceil((double)length / (double) MTU);
	int offset = 0;
	int i;

	sequencenumber++;

	for (i = 0; i < fragments; i++) {
		fragment_t *fragment = udp_transceiver_build_fragment(
			buffer + offset, length - offset > MTU ? MTU : length - offset,
			sequencenumber, i, fragments, deflate, acknowledge);

		fragment->ipaddress = address;
		fragment->port = port;

		udp_transceiver_send_fragment(fragment, deflate, acknowledge);
		offset += MTU;
	}
}

/***
 *** Receiving and parsing
 ***/

/**
 * Get the sequence number from a fragment.
 */
inline int
udp_transceiver_get_sequencenumber(fragment_t *fragment)
{
	return (fragment->fragment[4] << 8) + fragment->fragment[5];
}

/**
 * Get the part number from a fragment.
 */
inline int
udp_transceiver_get_partnumber(fragment_t *fragment)
{
	return fragment->fragment[6];
}

/**
 * Get the number of fragments from a datagram fragment.
 */
inline int
udp_transceiver_get_fragments(fragment_t *fragment)
{
	return fragment->fragment[7];
}

/**
 * Gets previously received fragments from the given source with matching
 * sequencenumber.
 */
static GSList *
udp_transceiver_lookup_fragments_by_sequencenumber_source(
        fragment_t *fragment)
{
	return NULL;
}

/**
 * Puts a received datagram fragment in a to handle list.
 */
static void
udp_transceiver_put_received_fragment(fragment_t *fragment)
{
	int fragments = udp_transceiver_get_fragments(fragment);
	int partnumber = udp_transceiver_get_partnumber(fragment);
	int sequencenumber = udp_transceiver_get_sequencenumber(fragment);

	GSList *fragment_list =
		udp_transceiver_lookup_fragments_by_sequencenumber_source(
			fragment);
	fragment_t *fragment_tmp;

	if (fragment_list == NULL)
	{
		/* FIXME: Create new fragment list (array?) with size fragments */
	}

	/* fragment_tmp = gslist_at(fragment_list, partnumber) */
	if (fragment_tmp == NULL)
	{
		/* FIXME:
		 * gslist_insert_at(fragment_list, partnumber, fragment_received) */
	}
	else
	{
		/* FIXME: udp_transceiver_free_fragment(fragment) */
	}

	/* FIXME: Check if all fragments are received */

	/* All fragments received */
}

/**
 * Parses a datagram and if it is a fragment it will be handed over to
 * udp_transceiver_put_received_fragment.
 */
static gboolean
udp_transceiver_put_received_datagram(char *buf, int length,
                                      guint32 ip, guint16 port)
{
	fragment_t *fragment_received;

	if (!udp_transceiver_can_handle_received_fragment(buf, length))
		return FALSE;

	fragment_received = (fragment_t *) malloc(sizeof(fragment_t));
	fragment_received->fragment = (char *) malloc(length);
	memcpy(fragment_received->fragment, buf, length);
	fragment_received->fragment_length = length;
	fragment_received->ipaddress = ip;
	fragment_received->port = port;

	udp_transceiver_put_received_fragment(fragment_received);
}

/**
 * Handle receiving of data
 */
gboolean
udp_transceiver_receive(char **buffer, int *length)
{
    /* FIXME: for bla in fragments_received */
	/* *length += fragment->fragment_length - header_length */

	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
