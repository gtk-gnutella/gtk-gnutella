#include <glib.h>
#include "packet.h"

typedef struct g2packetstream_s g2packetstream_t;


g2packetstream_t *g2_packetstream_new(gpointer *connection);
g2packetstream_t *g2_packetstream_get(gpointer *connection);
void g2_packetstream_free(gpointer *connection);
int g2_packetstream_put_data(g2packetstream_t *stream, char *data, int length);
g2packet_t *g2_packetstream_get_packet(g2packetstream_t *stream);
int g2_packetstream_get_error(g2packetstream_t *stream, char **errormessage);
