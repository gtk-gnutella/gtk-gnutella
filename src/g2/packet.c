/*
 * Copyright (c) 2004, Jeroen Asselman
 *
 * G2 packet parser / constructor
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
 
#include "../common.h"		/* For -DUSE_DMALLOC */

#include <glib.h>

typedef struct G2Packet_s G2Packet_t;
struct G2Packet_s
{
        gboolean     compound;
        gboolean     has_children;
        gboolean     big_endian;

        char     control;
        int              name_length;
        char    *name;
        char    *payload;
        char    *orig_payload;
        int              payload_length;
};

char *g2_packet_pack(G2Packet_t *packet, int *length);
int g2_packet_calc_new_length(G2Packet_t *packet);

/**
 * G2 New Packet. 
 *
 * Creates a new G2 packet.
 */
G2Packet_t * g2_new_packet()
{
        return (G2Packet_t *) malloc(sizeof(G2Packet_t));
}

/**
 * G2 free packet.
 *
 * Frees a g2 packet and any associated memory. This will also 
 * free a payload assigned.
 */
void g2_free_packet(G2Packet_t *packet)
{
        if (packet->name != NULL)
                free(packet->name);

        if (packet->orig_payload != NULL)
                free(packet->orig_payload);

        free(packet);
}

/***
 *** Parse packet functions
 ***/

/**
 * g2 parse header.
 *
 * Parse the packet header to extract length information.
 */
void g2_parse_header(char **buffer, G2Packet_t *packet)
{
        char *source = *buffer;
        char len_length         = ( *source & 0xC0 ) >> 6;
        char flags                      = ( *source & 0x07 );

        packet->name_length     = (( *source & 0x38 ) >> 3) + 1; 

        source++;

        packet->big_endian      = ( flags & 0x02 ) > 0;
        packet->compound                = ( flags & 0x04 ) > 0;

        if (packet->big_endian)
        {
        		int i;
                for (i = 0; i < len_length; i++)
                {
                        packet->payload_length *= 0xFF;
                        packet->payload_length += *source++;
                }
        }
        else
        {
        		int i;
                for (i = len_length; i > 0; i--)
                {
                        packet->payload_length += 0xFF;
                        packet->payload_length += *source++;
                }
        }

        if (packet->payload_length > 0)
        {
                packet->has_children = packet->compound;
        }

        *buffer = source;
}

/**
 * G2 Parse packet
 *
 * Parse the g2 packet to retreive the start of the payload/children
 */
void g2_parse_packet(char **buffer, G2Packet_t *packet)
{
        char *source = *buffer;
        
        g2_parse_header(buffer, packet);

        packet->name = (char *) malloc(packet->name_length + 1);
        memcpy(packet->name, source, packet->name_length);
        *(packet->name + packet->name_length) = '\0';

        printf("[G2] '%s' %s children, payload length %d\n", packet->name,
                packet->has_children ? "has" : "doesn't", packet->payload_length);

        packet->payload = (char *) malloc(packet->payload_length);
        packet->orig_payload = packet->payload;
        memcpy(packet->payload, source, packet->payload_length);
        source += packet->payload_length;
}

char *g2_packet_get_name(G2Packet_t *packet)
{
        return packet->name;
}

G2Packet_t *g2_packet_get_next_child(G2Packet_t *basepacket)
{
        G2Packet_t *packet = NULL;
        char *before = basepacket->payload;

        if (!basepacket->compound) 
                return NULL;
        
        g2_parse_packet(&basepacket->payload, packet);
        basepacket->payload_length -= basepacket->payload - before;

        if (basepacket->payload_length == 0 || 
                (*basepacket->payload == '0' && packet->payload_length != 0))
                basepacket->compound = FALSE;

        return packet;
}

/**
 * Get payload.
 * 
 * After this it isn't possible anymore to retreive any children. As it will
 * fast skip them
 */
char *g2_packet_get_payload(G2Packet_t *packet, int *length)
{
        G2Packet_t *packet_parser = g2_new_packet();

        /* Skip any children */
        while (packet->compound)
        {
                char *before = packet->payload;

                g2_parse_header(&packet->payload, packet_parser);       // This advances after the header
                packet->payload += packet_parser->payload_length;       // This advances after the payload
                
                packet->payload_length -= (int) (packet->payload - before);

                if (packet->payload_length < 0)
                {
                        printf("[G2] Invalid packet\n");

                        g2_free_packet(packet_parser);

                        return NULL;
                }

                if (*packet->payload = '\0' || packet->payload_length == 0)
                        packet->compound = FALSE;
        }

        g2_free_packet(packet_parser);

        if (packet->payload_length == 0)
                return NULL;

        *length = packet->payload_length;

        return packet->payload;
} 

/***
 *** Create packet functions
 ***/

void g2_packet_add_child(G2Packet_t *packet, G2Packet_t *child)
{
        char *buffer = NULL;
        int length;

        buffer = g2_packet_pack(child, &length);

        if (packet->payload == NULL) {
                packet->orig_payload = (char *) malloc(length);
                packet->payload = packet->orig_payload;
        } else {
                int diff = packet->payload - packet->orig_payload;

                packet->orig_payload = (char *) realloc(packet->orig_payload,
                        packet->payload_length + length);

                /* Set payload to the new not used memory space */
                packet->payload = packet->orig_payload + diff + length;
        }

        memcpy(packet->payload, buffer, length);
        packet->has_children = TRUE;
        packet->payload_length += length;

        free(buffer);
        /* Payload points again to the newly added child */
}

/**
 * G2 Packet add payload.
 *
 * Adds a payload to the current packet. After this do _NOT_ add children
 * anymore.
 */
void g2_packet_add_payload(G2Packet_t *packet, char *payload, int length)
{
        if (packet->orig_payload != NULL) {
                int diff = packet->payload - packet->orig_payload;
                int extra = length + packet->has_children ? 1 : 0;

                packet->orig_payload = (char *) realloc(packet->orig_payload,
                        packet->payload_length + extra);

                packet->payload = packet->orig_payload + diff;

                if (packet->has_children)
                {
                        *packet->payload = '0';
                        packet->payload++;
                        packet->payload_length++;
                }
        }

        memcpy(packet->payload, payload, length);
        packet->payload_length += length;

        /* Payload now points to the newly added payload */

//      g_assert(packet->orig_payload - packet->payload == 
//              packet->payload_length - length);
}

/**
 * G2 Packet pack.
 *
 * Construct a buffer from a G2Packet and return the newly allocated
 * buffer.
 *
 * @return a pointer to the buffer containing the packed G2Packet.
 */
char *g2_packet_pack(G2Packet_t *packet, int *length)
{
        *length = g2_packet_calc_new_length(packet);
        char *buffer = (char *) malloc(*length);

        g2_packet2buf(packet, buffer);

        return buffer;
}

int g2_packet_calc_lenlength(int length)
{
	if (length > 0xFFFFFF)
		return 4;
	if (length > 0xFFFF)
		return 3;
	if (length > 0xFF)
		return 2;
	if (length > 0x0)
		return 1;
	return 0;
}

/**
 * G2 Packet calculate length/
 *
 * Calculates the size that will be used by this G2Packet when transformed
 * to a buffer / char pointer.
 *
 * @return the length of the G2Packet when transformed to a buffer.
 */
int g2_packet_calc_new_length(G2Packet_t *packet)
{
        int length = 1; // Control byte;

        // name_length
        length += packet->name_length;

        // len_length
        length += g2_packet_calc_lenlength(packet->payload_length);

        // payload_length
        length += packet->payload_length;

        return length;
}

/**
 * G2 Packet2buf.
 *
 * In the destination pointer a g2 packet is constructed from the given
 * G2Packet.
 * The destination should be at least the size retreived with
 * g2_packet_calc_new_length(packet).
 */
void g2_packet2buf(G2Packet_t *packet, char *destination)
{
        int tmp_length = packet->payload_length;
        char len_length;
        char flags;
		int i;
		
        len_length =  g2_packet_calc_lenlength(packet->payload_length);

        if (packet->payload_length > 0)
        {
                packet->has_children = packet->compound;
        }

        if (len_length > 0)
                packet->compound = packet->has_children;
        else
                packet->compound = TRUE;


        *destination = '0';
        *destination |= (len_length << 6);
        *destination |= ((packet->name_length - 1) << 3);

        if (packet->compound)
                *destination |= 0x04;
        if (packet->big_endian)
                *destination |= 0x02;

        // Advance to next byte, control byte is now finished.
        destination++;

        // Build name.
        for (i = 0; i < packet->name_length; i++)
        {
                *destination = packet->name[i];
                destination++;
        }

        // Insert payload length
        *destination = packet->payload_length;
        if (!packet->big_endian)
                memmove(destination, destination + sizeof(int) - len_length, len_length);

        destination += len_length;

        memcpy(destination, packet->orig_payload, packet->payload_length);
}

