/*
 * Copyright (c) 2004, Jeroen Asselman
 *
 * G2 packet stream parser
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "packetstream.h"

const int MAX_PACKET_SIZE = 1024 * 1024;	/**< Maximum packet size. */

struct g2packetstream_s
{
	gboolean got_control_byte;	/**< Control byte read? */
	gboolean got_len_length;	/**< Length field read? */

	char len_length;			/**< Length field size */
	char name_length;			/**< Name field size */
	gboolean big_endian;		/**< Big endian? */

	int length;					/**< Next packet size */
	int bytes_read;				/**< Number of bytes read */
	char *data;					/**< Data */
	char header[5];				/**< Temp, control byte + max len length */
};

GHashTable *by_connection;

void
g2_packetstream_init()
{
	by_connection = g_hash_table_new(g_direct_hash, g_direct_equal);
}

void
g2_packetstream_close()
{
	/* FIXME: Cleanup all used resources in hashtable! */
	g_hash_table_destroy(by_connection);
}

/**
 * Allocate a new packet stream.
 *
 * Allocates a new packet stream with the given connection as an identifier.
 * Or if the connection allready exists, the existing connection is returned.
 *
 * @param connection will be used as the identifier later for lookup (get)
 * @return a new g2packetstream.
 */
g2packetstream_t *
g2_packetstream_new(gpointer *connection)
{
	g2packetstream_t *packetstream = g2_packetstream_get(connection);

	if (packetstream == NULL)
		packetstream = calloc(1, sizeof(g2packetstream_t));

	g_hash_table_insert(by_connection, connection, packetstream);

	return packetstream;
}

/**
 * Get a packet stream for the given connection.
 *
 * Returns the g2 packet stream associated with the given pointer. If no
 * packetstream could be found, NULL is returned.
 *
 * @param connection the connection to lookup.
 * @return the packetstream associated with the given connection.
 */
g2packetstream_t *
g2_packetstream_get(gpointer *connection)
{
	return g_hash_table_lookup(by_connection, connection);
}

/**
 * Free a packet stream from memory.
 *
 */
void
g2_packetstream_free(gpointer *connection)
{
	g2packetstream_t *stream = g2_packetstream_get(connection);

	if (stream->data != NULL)
		free(stream->data);

	free(stream);

	g_hash_table_remove(by_connection, connection);
}

/**
 * Put data in a given packet stream.
 *
 * Puts received data in the given packet stream.
 *
 * @param stream a pointer to the stream to which the data shall be written.
 * @param data a pointer to the data that shall be written.
 * @param length the amount of data that shall be written.
 * @return the amount of bytes expected to be read additionally, never
 * put more data than was requested or packets might get lost. 0 is returned
 * if a full packet has been read and should be retreived first.
 */
int
g2_packetstream_put_data(g2packetstream_t *stream, char *data, int length)
{
	char *cur_pos = NULL;
	if (stream->data != NULL)
		cur_pos = stream->data + stream->bytes_read;

	g_assert(stream != NULL);
	g_assert((!stream->got_control_byte && length <= 1) ||
			 (length <= stream->length - stream->bytes_read));

	stream->bytes_read += length;

	/* Indicate we want one byte when we want to parse the control byte */
	if (!stream->got_control_byte && length == 0)
		return 1;

	/* Parse control byte */
	if (!stream->got_control_byte) {
		g_assert(stream->got_len_length);
		g_assert(length == 1);
		g_assert(stream->bytes_read == 1);

		stream->len_length = (*data & 0xC0) >> 6;
		stream->name_length = (*data & 0x38) >> 3;
		stream->big_endian = (*data & 0x02) > 0;
		stream->got_control_byte = TRUE;

		/* Write header value */
		stream->header[0] = *data;
		/* Max amount of data to expect in total */
		stream->length = 1 + stream->len_length;

		return stream->len_length;
	}

	/* Parse len length, if all data is received */
	if (!stream->got_len_length) {
		int i;

		g_assert(stream->got_control_byte);
		g_assert(stream->length == stream->len_length + 1);

		/* Write header values */
		for (i = 0; i < length; i++) {
			/* Write header after the control byte ( + 1),
			 * and after the amount of data already written
			 * (bytes_read - length)
			 */
			stream->header[i + 1 + stream->bytes_read - length] = data[i];
		}

		/* got complete header? */
		if (stream->bytes_read == 1 + stream->len_length)
		{
			/* Get packet size */
			if (stream->big_endian)
			{
				/* Start at 1 to skip control byte */
				for (i = 1; i <= stream->len_length; i++)
				{
					stream->length *= 0xFF;
					stream->length += stream->header[i + 1];
				}
			} else {
				for (i = stream->len_length; i > 0; i--)
				{
					stream->length *= 0xFF;
					stream->length += stream->header[i];
				}
			}

			stream->length += stream->len_length + stream->name_length;
			stream->got_len_length = TRUE;

			if (stream->length < MAX_PACKET_SIZE) {
				if (stream->data != NULL)
					stream->data = g_realloc(stream->data, stream->length);
				else
					stream->data = malloc(stream->length);

				/* Copy original header to real packet stream */
				memcpy(stream->data, stream->header, 1 + stream->len_length);

				return stream->length - stream->bytes_read;
			}

			/* Packet was to large, stop reading. */
			return 0;
		}

		/* Not full length has been read yet. */
		return stream->length - stream->bytes_read;
	}

	g_assert(stream->got_control_byte);
	g_assert(stream->got_len_length);
	g_assert(cur_pos != NULL);

	memcpy(cur_pos, data, length);

	return stream->length - stream->bytes_read;
}

/**
 * Get a packet from the packetstream.
 *
 * Gets a packet from the packetstream, if there are no packets available,
 * NULL is returned.
 *
 * @param stream a pointer to the stream to retreive the packet from.
 * @return a pointer to the packet, or NULL if no packets available.
 */
g2packet_t *
g2_packetstream_get_packet(g2packetstream_t *stream)
{
	g2packet_t *packet;

	if (stream->length != stream->bytes_read)
		return NULL;

	stream->got_len_length = FALSE;
	stream->got_control_byte = FALSE;
	stream->length = 0;
	stream->bytes_read = 0;

	return packet;
}

/**
 * Gets an error from the packetstream.
 *
 * Gets an error, if any, from the packetstream. Any error indication
 * could indicate out of sync and as a result the connection should be
 * dropped.
 *
 * @param stream a pointer to the stream from which to retreive the error
 *        message.
 * @param errormessage a pointer where the errormessage string is written.
 * @return 0 on no error.
 */
int
g2_packetstream_get_error(g2packetstream_t *stream, char **errormessage)
{
	/* FIXTHIS */
	if (stream->got_len_length && stream->data == NULL) {
		*errormessage = "Packet was too large";
		return 1;
	}

	return 0;
}
