/*
 * Copyright (c) 2003, Jeroen Asselman & Raphael Manfredi
 *
 * Passive/Active Remote Queuing.
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

#include "common.h"		/* For -DUSE_DMALLOC */

#include <glib.h>
#include "parq.h"
#include "ioheader.h"
#include "sockets.h"
#include "gnutella.h"
#include "settings.h"


RCSID("$Id$");

#define PARQ_RETRY_SAFETY	40		/* 40 seconds before lifetime */
#define PARQ_TIMER_BY_POS	30		/* 30 seconds for each queue position */

#define PARQ_UL_RETRY_DELAY 300		/* 5 minutes timeout. FIXME: Don't set hard! */

#define PARQ_UL_LARGE_SIZE (300*1024*1024)
									/* 1 ul: 0 < q1
									 * 2 ul: 0 < q1 < 300, 300 < q2 < oo
									 * 3 ul: 0 < q1 < 150, 150 < q2 < 300, 300 < q2 < oo
									 */

guint parq_max_upload_size = 2000;
static gchar *file_parq_file = "parq";

static GList *ul_parqs = NULL;
GHashTable *ul_all_parq_by_IP_and_Name = NULL;
GHashTable *ul_all_parq_by_ID = NULL;
 
/* Holds status of current queue. */
struct parq_ul_queue {
	GList *by_Position;		/* Queued items sorted on position. Newest is 
							   added to the end. */
	
	gint size;				/* Number of entries in current list */
	
	gboolean active;		/* Set to false when the number of upload slots
							   was decreased but the queue still contained
							   queued items. This queue shall be removed when
							   all queued items are finished / removed. */
	gint active_uploads;
};

/* Contains the queued upload */
struct parq_ul_queued {	
	guint position;			/* Current position in the queue */
	guint ETA;				/* Expected time in seconds till an upload slot is
							   reached */

	time_t expire;			/* Max interval before loosing queue position */
	time_t enter;			/* Time upload entered parq */
	time_t updated;			/* Time last upload request was sent */
	 
	gchar ID[PARQ_MAX_ID_LENGTH];	/* PARQ identifier */
	 
	gchar *IP_and_name;
	
	guint32 file_size;		/* Needed to recalculate ETA */
	
	struct parq_ul_queue *queue;	/* In which queue this entry is listed */
};



static void parq_upload_free(struct parq_ul_queued *parq_ul);
static struct parq_ul_queued *parq_upload_create(gnutella_upload_t *u);
static struct parq_ul_queue *parq_upload_which_queue(gnutella_upload_t *u);
static struct parq_ul_queue *parq_upload_new_queue();
static void parq_upload_free_queue(struct parq_ul_queue *queue);
static void parq_upload_update_ETA(struct parq_ul_queue *which_ul_queue);
static struct parq_ul_queued *parq_upload_find(gnutella_upload_t *u);
static gboolean parq_upload_continue(gnutella_upload_t *u, gint free_slots);
static void parq_upload_decrease_all_after(struct parq_ul_queued *cur_parq_ul);
static void parq_store(gpointer data, gpointer x);
static void parq_upload_load_queue();
static void parq_upload_update_IP_and_name(struct parq_ul_queued *parq_ul, 
	gnutella_upload_t *u);
/***
 ***  Generic non PARQ specific functions
 ***/


/*
 * get_header_version
 * 
 * Extract the version from a given header. EG:
 * X-Queue: 1.0
 * major=1 minor=0
 */
static gboolean get_header_version(gchar const *const header, 
								gint *major, gint *minor)
{
	return sscanf(header, "%d.%d", major, minor) == 2;
}

/* 
 * get_header_value
 *
 * Retreives a value from a header line. If possible the length (in gchars)
 * is returned for that value.
 */
static gchar *get_header_value(
	gchar *const s, gchar const *const attribute, gint *length)
{
	gchar *header = s;
	gchar *end;
	gboolean found_right_attribute = FALSE;
	gboolean found_equal_sign = FALSE;
	
	size_t attrlen;
	
	g_assert(s != NULL);
	g_assert(attribute != NULL);

	attrlen = strlen(attribute);

	/*
	 * When we are looking for "foo", make sure we aren't actually
	 * parsing "barfoobar". There should be at least a space, or a
	 * delimiter at the end and at the beginning.
	 */

	do {
		gchar e;
		gchar b;
		gchar es;

		header = strcasestr(header, attribute);
		
		if (header == NULL)
			return NULL;

		e = header[attrlen];		/* End char after attribute */
		
		if (header == s) {
			/*
			 * This is actually the first value of the header. And it
			 * started at position '0'. Which is the same as were
			 * s pointed too. Only check to see if the end is correct
			 */

			found_right_attribute = e == ' ' || e == '=' || e == '\0';
		} else {
			b = *(header - 1);	/* Character before attribute */
			found_right_attribute = (
					b == ';' || b == ',' || b == ':' || b == ' '
				) && (
					e == ' ' || e == '=' || e == '\0'
				);
		}

		/* 
		 * If we weren't looking at the right value. Move on to the next.
		 * If there are no valid values, the while loop will abort with 
		 * lowercase_header == NULL
		 * If we did find a valid position we want to make sure the next
		 * char is an '='. So we need to move ahead anyway.
		 */
		
		header += attrlen;
		
		if (found_right_attribute) {
			
			/*
			 * OK, so we found a possible valid attribute. Now make sure the
			 * first character is an '=', ignoring white spaces.
			 * If we don't, we didn't find a valid attribute.
			 */
			
			es = *header;
			
			do {
				found_right_attribute = es == '=' || es == ' ' || es == '\0';
				found_equal_sign = es == '=';
								
				if (!found_equal_sign)
					es = *(++header);		/* Skip spaces */
				
			} while (!found_equal_sign && found_right_attribute && es != '\0');

			/*
			 * If we did not find the right attribute, it means we did not
			 * encounter an '=' sign before the start of the next attribute
			 * or the end of the string.
			 *
			 * For instance, we stumbled on `var2' in:
			 *
			 *   var1 = foo; var2 ; var3=bar
			 *
			 * Clearly, this is incorrect for our purposes, as all attributes
			 * are expected to have a value.
			 */

			g_assert(!found_equal_sign || found_right_attribute);

			if (!found_right_attribute) {
				g_assert(!found_equal_sign);
				g_warning("attribute '%s' has no value in string: %s",
					attribute, s);
			}
		}		
	} while (!found_right_attribute);	
	
	g_assert(header != NULL);
	g_assert(found_equal_sign);
	g_assert(*header == '=');
	
	header++;			/* Skip the '=' sign */

	/*
	 * If we need to compute the length of the attribute's value, look for
	 * the next trailing delimiter (';' or ',').
	 */
	
	if (length != NULL) {
		*length = 0;

		end = strchr(header, ';');		/* PARQ style */
		if (end == NULL)
			end = strchr(header, ',');	/* Active queuing style */

		/* 
		 * If we couldn't find a delimiter, then this value is the last one.
		 */

		*length = (end == NULL) ?
			strlen(header) : end - header;
	}

	return header;
}


/***
 ***  The following section contains download PARQ functions
 ***/

/*
 * parq_download_retry_active_queued
 *
 * Active queued means we didn't close the http connection on a HTTP 503 busy
 * when the server supports queueing. So prepare the download structure
 * for a 'valid' segment. And re-request the segment.
 */
void parq_download_retry_active_queued(struct download *d)
{
	g_assert(d != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_ACTIVE_QUEUED);
	g_assert(parq_download_is_active_queued(d));
	
	if (download_start_prepare_running(d)) {
		struct gnutella_socket *s = d->socket;
		d->keep_alive = TRUE;			/* was reset in start_prepare_running */
		
 		/* Will be re initialised in download_send_request */
		io_free(d->io_opaque);
		d->io_opaque = NULL;
		getline_free(s->getline);		/* No longer need this */
		s->getline = NULL;

		/* Resend request for download */
		download_send_request(d);
	}
}
	
/*
 * get_integer
 *
 * Convenience wrapper on top of strtoul().
 * Returns parsed integer (base 10), or 0 if none could be found.
 */
static gint get_integer(gchar *buf)
{
	glong val;
	gchar *end;

	/* XXX This needs to get more parameters, so that we can log the
	 * XXX problem if we cannot parse, or if the value does not fit.
	 * XXX We probably need the download structure, and the name of
	 * XXX the field being parsed, with the header line as well.
	 * XXX	--RAM, 02/02/2003.
	 */

	val = strtoul(buf, &end, 10);
	if (end == buf)
		return 0;

	if (val > INT_MAX)
		val = INT_MAX;

	return (gint) val;
}

/*
 * parq_download_parse_queue_status
 *
 * Retrieve and parse queueing information.
 * Returns TRUE if we parsed it OK, FALSE on error.
 */
gboolean parq_download_parse_queue_status(struct download *d, header_t *header)
{	
	gchar *buf;
	gchar *value;
	gint major, minor;
	gint header_value_length;
	gint retry;

	g_assert(d != NULL);
	g_assert(header != NULL);

	buf = header_get(header, "X-Queue");
	
	if (buf == NULL)			/* Remote server does not support queues */
		return FALSE;

	if (!get_header_version(buf, &major, &minor)) {
		/*
	 	* Could not retreive queueing version. It could be 0.1 but there is 
		* no way to tell for certain
	 	*/
		major = 0;
		minor = 1;
	}
	
	d->server->parq_version.major = major;
	d->server->parq_version.minor = minor;
	
	switch (major) {
	case 0:				/* Active queueing */
		g_assert(buf != NULL);		
		d->queue_status.ID[0] = '\0';

		value = get_header_value(buf, "pollMin", NULL);
		d->queue_status.retry_delay  = value == NULL ? 0 : get_integer(value);
		
		value = get_header_value(buf, "pollMax", NULL);
		d->queue_status.lifetime  = value == NULL ? 0 : get_integer(value);
		break;
	case 1:				/* PARQ */
		buf = header_get(header, "X-Queued");

		if (buf == NULL) {
			g_warning("host %s advertised PARQ %d.%d but did not send X-Queued",
				ip_port_to_gchar(download_ip(d), download_port(d)),
				major, minor);
			if (dbg) {
				g_warning("header dump:");
				header_dump(header, stderr);
			}
			return FALSE;
		}
		
		value = get_header_value(buf, "lifetime", NULL);
		d->queue_status.lifetime = value == NULL ? 0 : get_integer(value);

		d->queue_status.retry_delay = extract_retry_after(header);

		value = get_header_value(buf, "ID", &header_value_length);
		header_value_length = MIN(header_value_length, PARQ_MAX_ID_LENGTH);
		strncpy(d->queue_status.ID, value, header_value_length);
		break;
	default:
		g_warning("unhandled queuing version %d.%d from %s <%s>",
			major, minor, ip_port_to_gchar(download_ip(d), download_port(d)),
			download_vendor_str(d));
		return FALSE;
	}

	value = get_header_value(buf, "position", NULL);
	d->queue_status.position = value == NULL ? 0 : get_integer(value);
	
	value = get_header_value(buf, "length", NULL);
	d->queue_status.length   = value == NULL ? 0 : get_integer(value);
				
	value = get_header_value(buf, "ETA", NULL);
	d->queue_status.ETA  = value == NULL ? 0 : get_integer(value);

	/*
	 * If we're not in the first position, lower our retry rate.
	 * We try to retry every 60 seconds when in position 2, every 90 in
	 * position 3, and so on.  If we fall out of range, adjust: we must not
	 * poll before the minimum specified by `retry_delay', and we try to
	 * poll again at least 40 seconds before `lifetime' to avoid being
	 * kicked out.
	 *		--RAM, 22/02/2003
	 */

	retry = d->queue_status.position * PARQ_TIMER_BY_POS;

	if (retry > (d->queue_status.lifetime - PARQ_RETRY_SAFETY))
		retry = d->queue_status.lifetime - PARQ_RETRY_SAFETY;
	if (retry < d->queue_status.retry_delay)
		retry = d->queue_status.retry_delay;

	if (dbg)
		printf("Queue version: %d.%d, position %d out of %d,"
			" retry in %ds within [%d, %d]\n",
			major, minor, d->queue_status.position, d->queue_status.length,
			retry, d->queue_status.retry_delay, d->queue_status.lifetime);
	
	if (parq_download_is_active_queued(d)) {
		/*
		 * Don't keep a chunk busy if we are queued, perhaps another servent
		 * can complete it for us.
		 */

		file_info_clear_download(d, TRUE);
		d->status = GTA_DL_ACTIVE_QUEUED;
	}
	
	d->timeout_delay = retry;

	return TRUE;		/* OK */
}

/*
 * parq_download_is_active_queued
 *
 * Wether the download is queued remotely or not.
 */
gboolean parq_download_is_active_queued(struct download *d)
{
	g_assert(d != NULL);

	return d->queue_status.position > 0 && d->keep_alive;
}

/*
 * parq_download_is_active_queued
 *
 * Wether the download is queued remotely without keeping the connection or not
 */
gboolean parq_download_is_passive_queued(struct download *d)
{
	g_assert(d != NULL);

	return d->queue_status.position > 0 && !d->keep_alive;
}


/*
 * parq_download_add_header
 *
 * Adds an:
 *
 *    X-Queue: 1.0
 *    X-Queued: position=x; ID=xxxxx
 *
 * to the HTTP GET request
 */
void parq_download_add_header(
	gchar *buf, gint len, gint *rw, struct download *d)
{
	*rw += gm_snprintf(&buf[*rw], len - *rw,
		"X-Queue: %d.%d\r\n", PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR);

	/*
	 * Only add X-Queued header if server really supports X-Queue: 1.x. Don't
	 * add X-Queued if there is no ID available. This could be because it is
	 * a first request.
	 */

	if (d->server->parq_version.major == 1 && d->queue_status.ID[0] != '\0')
		*rw += gm_snprintf(&buf[*rw], len - *rw,
			"X-Queued: position=%d; ID=%s\r\n",
			d->queue_status.position, d->queue_status.ID);
}


/***
 ***  The following section contains upload queueing
 ***/

/*
 * TODO:
 * - Caculate better liftime
 * - Active queueing
 * - Send QUEUE when ip changes or host went offline.
 * - Save queue status
 * - 1 active download from the same IP at once.
 */

/*
 * parq_upload_free
 *
 * removes an parq_ul from the parq list and frees all its memory
 */
static void parq_upload_free(struct parq_ul_queued *parq_ul)
{
	g_assert(parq_ul != NULL);
	g_assert(parq_ul->IP_and_name != NULL);
	g_assert(parq_ul->queue != NULL);
	g_assert(parq_ul->queue->size > 0);
	g_assert(parq_ul->queue->by_Position != NULL);
	
	/* Remove the current queued item from all lists */
	parq_ul->queue->by_Position = 
		g_list_remove(parq_ul->queue->by_Position, parq_ul);

	g_hash_table_remove(ul_all_parq_by_IP_and_Name, parq_ul->IP_and_name);
	g_hash_table_remove(ul_all_parq_by_ID, parq_ul->ID);

	/* 
	 * Queued upload is now removed from all lists. So queue size can be
	 * safely decreased and new ETAs can be calculate.
	 */
	parq_ul->queue->size--;

	parq_upload_update_ETA(parq_ul->queue);


	/* Free the memory used by the current queued item */
	G_FREE_NULL(parq_ul->IP_and_name);
	
	wfree(parq_ul, sizeof(*parq_ul));
	parq_ul = NULL;
}

/*
 * parq_upload_create
 *
 * Creates a new upload structure and prefills some values. Returns a pointer to
 * the newly created ul_queued structure.
 */
static struct parq_ul_queued *parq_upload_create(gnutella_upload_t *u)
{
	time_t now = time((time_t *) NULL);
	struct parq_ul_queued *parq_ul = NULL;
	struct parq_ul_queued *parq_ul_prev = NULL;
	struct parq_ul_queue *parq_ul_queue = NULL;

	guint rw = 0;
	guint ETA = 0;
	gchar buf[1024];
	GList *l;
	
	g_assert(u != NULL);
	g_assert(ul_all_parq_by_IP_and_Name	!= NULL);
	g_assert(ul_all_parq_by_ID != NULL);
	
	parq_ul_queue = parq_upload_which_queue(u);
	g_assert(parq_ul_queue != NULL);

	/* Locate the previous queued item so we can calculate the ETA */
    l = g_list_last(parq_ul_queue->by_Position);
    if (l != NULL)
	        parq_ul_prev = (struct parq_ul_queued *) l->data;

	if (parq_ul_prev != NULL) {
		ETA = parq_ul_prev->ETA;
		if (bw_http_out != 0 && bws_out_enabled) {
			ETA += parq_ul_prev->file_size / bw_http_out;
		} else {
			printf("PARQ UL Q %d/%d: Could not calculate ETA\r\n",
				g_list_position(ul_parqs, 
					g_list_find(ul_parqs, parq_ul_prev->queue)),
				g_list_length(ul_parqs) - 1);
			
			/*
			 * According to the PARQ specification the ETA should be calculated
			 * using the maximum upload rate. However the maximum upload rate
			 * is unknown.
			 * Pessimistic: 1 bytes / sec
			 */
			ETA += parq_ul_prev->file_size / max_uploads;
		}
	}
	
	/* Create new parq_upload item */
	parq_ul = walloc(sizeof(*parq_ul));
	g_assert(parq_ul != NULL);

	/* Create identifier to find upload again later. IP + Filename */
	parq_ul->IP_and_name = NULL;
	parq_upload_update_IP_and_name(parq_ul, u);
	
	/* Create an ID. We might want to this better some day. */
	rw = gm_snprintf(buf, sizeof(buf), "%d%d", u->ip, random_value(999999));
	g_strlcpy(parq_ul->ID, buf, sizeof(parq_ul->ID));
	
	g_assert(parq_ul->IP_and_name != NULL);
	g_assert(parq_ul->ID != NULL);
		
	/* Fill parq_ul structure */
	parq_ul->position = ++parq_ul_queue->size;
	parq_ul->ETA = ETA;
	parq_ul->enter = now;
	parq_ul->updated = now;
	parq_ul->expire = now + PARQ_UL_RETRY_DELAY;
	parq_ul->file_size = u->file_size;
	parq_ul->queue = parq_ul_queue;
		
	/* Save into hash table so we can find the current parq ul later */
	g_hash_table_insert(ul_all_parq_by_ID, parq_ul->ID, parq_ul);
	
	parq_ul_queue->by_Position = 
		g_list_append(parq_ul_queue->by_Position, parq_ul);	
	
	g_assert(parq_ul != NULL);
	g_assert(parq_ul->position > 0);
	g_assert(parq_ul->ID != NULL);
	g_assert(parq_ul->IP_and_name != NULL);
	g_assert(parq_ul->queue != NULL);
	g_assert(parq_ul->queue->by_Position != NULL);
	g_assert(parq_ul->queue->by_Position->data != NULL);
	
	return parq_ul;
}

/*
 * parq_upload_which_queue
 * 
 * Looks up in which queue the current upload should be placed and if the queue
 * doesn't exist yet it will be created.
 * Returns a pointer to the queue in which the upload should be queued.
 */
static struct parq_ul_queue *parq_upload_which_queue(gnutella_upload_t *u)
{
	struct parq_ul_queue *queue;
	guint size = 0;
	guint slot = 0;
	
	size = PARQ_UL_LARGE_SIZE;
	
	/* 
	 * Determine in which queue the upload should be placed. Upload queues:
	 * 300 < size < oo
	 * 150 < size < 300
	 *  75 < size < 150
	 *   0 < size < 75
	 * Smallest: PARQ_UL_LARGE_SIZE / 2^(parq_upload_slots-1)
	 */
	
	for(slot = 1 ; slot <= max_uploads; slot++) {
		if (u->file_size > size || slot >= max_uploads)
			break;
		size = size / 2;
	}
	
	while (g_list_length(ul_parqs) < max_uploads) {
		queue = parq_upload_new_queue();
	}
	
	queue = (struct parq_ul_queue *) g_list_nth_data(ul_parqs, slot - 1);
	
	g_assert(queue != NULL);
	g_assert(queue->active == TRUE);
	
	return queue;
}

/*
 * parq_upload_new_queue
 *
 * Creates a new parq_ul_queue structure and places it in the ul_parqs
 * linked list.
 */
static struct parq_ul_queue *parq_upload_new_queue()
{
	struct parq_ul_queue *queue = NULL;

	queue = walloc(sizeof(*queue));
	g_assert(queue != NULL);

	queue->size = 0;
	queue->active = TRUE;
	queue->by_Position = NULL;
	queue->active_uploads = 0;
	
	ul_parqs = g_list_append(ul_parqs, queue);

	if (dbg)
		printf("PARQ UL: Created new queue %d\r\n", 
				g_list_position(ul_parqs, g_list_find(ul_parqs, queue)) + 1);
		
	g_assert(ul_parqs != NULL);
	g_assert(ul_parqs->data != NULL);
	g_assert(queue != NULL);
	
	return queue;
}

/*
 * parq_upload_free_queue
 *
 * Frees the queue from memory and the ul_parqs linked list
 */
static void parq_upload_free_queue(struct parq_ul_queue *queue)
{
	g_assert(queue != NULL);
	g_assert(ul_parqs != NULL);

	/* Never ever remove a queue which is in use and/or marked as active */
	g_assert(queue->size == 0);
	g_assert(queue->active_uploads == 0);
	g_assert(queue->active == FALSE);
	
	if (dbg)
		printf("PARQ UL: Removing inactive queue %d\r\b", 
				g_list_position(ul_parqs, g_list_find(ul_parqs, queue)) + 1);
		
	/* Remove queue from all lists */
	ul_parqs = g_list_remove(ul_parqs, queue);
	
	/* Free memory */
	wfree(queue, sizeof(*queue));
	queue = NULL;
}

/*
 * parq_upload_update_ETA
 *
 * Updates the ETA of all queued items in the given queue
 */
static void parq_upload_update_ETA(struct parq_ul_queue *which_ul_queue)
{
	GList *l;
	guint ETA = 0;
	
	/* Cycle through the current queue linked list */
	for (l = which_ul_queue->by_Position; l; l = g_list_next(l)) {	
		struct parq_ul_queued *parq_ul = (struct parq_ul_queued *) l->data;

		g_assert(parq_ul != NULL);

		parq_ul->ETA = ETA;
		
		/* Recalculate ETA */
		if (bw_http_out != 0 && bws_out_enabled) {
			ETA += parq_ul->file_size / (bw_http_out / max_uploads);
		} else {
			// FIXME, should use average bandwith here
			/* Pessimistic: 1 bytes / sec */
			ETA += parq_ul->file_size;
		}
	}
}

/*
 * parq_upload_find
 *
 * Finds an upload if available in the upload queue.
 * returns NULL if upload could not be found.
 */
static struct parq_ul_queued *parq_upload_find(gnutella_upload_t *u)
{
	guint rw;
	gchar buf[1024];
	
	g_assert(u != NULL);
	g_assert(ul_all_parq_by_IP_and_Name != NULL);
	g_assert(ul_all_parq_by_ID != NULL);
	
	rw = gm_snprintf(buf, sizeof(buf),
		"%d %s", u->ip, u->name);

	return g_hash_table_lookup(ul_all_parq_by_IP_and_Name, buf);
}

/*
 * parq_upload_queue_init
 *
 * Initialises the upload queue for PARQ.
 */
void parq_upload_queue_init()
{
	ul_all_parq_by_IP_and_Name = g_hash_table_new(g_str_hash, g_str_equal);
	ul_all_parq_by_ID = g_hash_table_new(g_str_hash, g_str_equal);
	
	(void) parq_upload_new_queue();
	
	g_assert(ul_all_parq_by_IP_and_Name != NULL);
	g_assert(ul_all_parq_by_ID != NULL);
	
	parq_upload_load_queue();
}

/*
 * parq_upload_timer
 *
 * Removes any PARQ uploads which show no activity.
 */
void parq_upload_timer(time_t now)
{
	GList *queues;
	GList *dl;
	GSList *sl;
	GSList *remove = NULL;
	static guint print_q_size = 0;
	guint	queue_selected = 0;
	
	for (queues = ul_parqs ; queues != NULL; queues = queues->next) {
		struct parq_ul_queue *queue = (struct parq_ul_queue *) queues->data;

		queue_selected++;
		
		for (dl = queue->by_Position; dl != NULL; dl = dl->next) {	
			struct parq_ul_queued *parq_ul = (struct parq_ul_queued *) dl->data;

			if (parq_ul == NULL)
				break;
		
			if (parq_ul->expire < now && parq_ul->position > 0) {
				if (dbg) 
					printf("PARQ UL Q %d/%d (%3d/%3d): Timeout:'%s'\n\r",
						g_list_position(ul_parqs, 
							g_list_find(ul_parqs, parq_ul->queue)) + 1,
						g_list_length(ul_parqs), 
						parq_ul->position, 
						parq_ul->queue->size,
						parq_ul->IP_and_name);
				/*
			 	* Mark for removal. Can't remove now as we are still using the
			 	* ul_parq_by_Position linked list. (prepend is probably the 
				* fastest function
			 	*/
				remove = g_slist_prepend(remove, parq_ul);			
			}
		}

		/*
		 * Mark queue as inactive when there are less uploads slots available.
		 */
		if (queue_selected > max_uploads)
			queue->active = FALSE;
		else
			queue->active = TRUE;
	}
	
	for (sl = remove; sl != NULL; sl = sl->next) {
		struct parq_ul_queued *parq_ul = (struct parq_ul_queued *) sl->data;

		/* Move uploads after the current upload up one slot */
		parq_upload_decrease_all_after(parq_ul);
	
		parq_upload_free(parq_ul);
	}
	
	g_slist_free(remove);

	/* Save queue info every 60 seconds */
	if (print_q_size++ >= 60) {
		print_q_size = 0;
		
		if (dbg) {
			for (queues = ul_parqs ; queues != NULL; queues = queues->next) {
    	    	struct parq_ul_queue *queue = 
					  (struct parq_ul_queue *) queues->data;
			
				printf("PARQ UL: Queue %d/%d contains %d items, "
					  "%d uploading, queue is marked %s \r\n",
					  g_list_position(ul_parqs, g_list_find(ul_parqs, queue))
						  + 1,
					  g_list_length(ul_parqs),
					  queue->size,
					  queue->active_uploads,
					  queue->active ? "active" : "inactive");
			}
		}
			
		parq_upload_save_queue();
	}
	
	/*
	 * If the last queue is not active anymore (ie it should be removed
	 * as soon as the queue is empty) and there are no more queued items
	 * in the queue, remove the queue.
	 */
	queues = g_list_last(ul_parqs);
	
	if (queues != NULL) {
		struct parq_ul_queue *queue = (struct parq_ul_queue *) queues->data;
		if (!queue->active && queue->size == 0) {
			parq_upload_free_queue(queue);
		}
	}
}

/*
 * parq_upload_queue_full
 *
 * Returns true if parq cannot hold any more uploads
 */
gboolean parq_upload_queue_full(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;	
	
	parq_ul = parq_upload_find(u);
	
	if (parq_ul == NULL)
		return FALSE;
	else
		return parq_ul->queue->size >= parq_max_upload_size;
}

/*
 * parq_upload_queued
 *
 * Wether the current upload is already queued.
 */
gboolean parq_upload_queued(gnutella_upload_t *u)
{
	return parq_upload_lookup_position(u) != (guint) -1;
}

/*
 * parq_upload_continue
 * 
 * Returns true if the current upload is allowed to get an upload slot.
 */
static gboolean parq_upload_continue(gnutella_upload_t *u, gint free_slots)
{
	GList *l = NULL;
	guint needed = 0;
	struct parq_ul_queued *parq_ul = NULL;	
		
	/*
	 * If there are no free upload slots the queued upload isn't allowed an 
	 * upload slot anyway. So we might just as well abort here
	 */
	if (free_slots <= 0)
		return FALSE;
	
	parq_ul = parq_upload_find(u);
	g_assert(parq_ul != NULL);
	
	/*
	 * If the current queued position is too large to receive an upload slot
	 * we don't need to continue.
	 */
	if (parq_ul->position > free_slots)
		return FALSE;
	

	/*
	 * XXX: If the number of upload slots have been decreased, an old queue
	 * XXX: may still exist. What to do with those uploads? Should we make
	 * XXX: sure those uploads are served first? Those uploads should take
	 * XXX: less time too upload anyway, as they _must_ be smaller.
	 * XXX
	 * XXX: Something like this?:
	 *
	l = g_list_last(ul_parqs);
	{
		struct parq_ul_queue *queue = (struct parq_ul_queue *) l->data;
		if (!queue->active) {
			if (parq_ul->queue->active)
				return FALSE;
		}
	}
	 */
	
	/*
	 * If the current position = 1 and the current queue hasn't already an item
	 * uploading than the upload is allowed by default.
	 */
	if (parq_ul->position == 1 && parq_ul->queue->active_uploads == 0)
		return TRUE;
	
	/* If position is zero the download is already downloading */
	g_assert(parq_ul->position != 0);
		
	/* See wether the other queues are allowed to get an upload position */
	for (l = ul_parqs; l ; l = l->next) {
		struct parq_ul_queue *queue = (struct parq_ul_queue *) l->data;
		
		printf("PARQ UL: Q %d/%d Active: %d\n\r", 
				g_list_position(ul_parqs, g_list_find(ul_parqs, queue)) + 1,
				g_list_length(ul_parqs),
				queue->active_uploads);
		
		if (queue->size > 1 && queue->active_uploads == 0)
			needed++;
	}
		
	return needed < free_slots;
}

/*
 * parq_upload_update_IP_and_name
 *
 * Updates the IP and name entry in the queued structure and makes sure the hash
 * table remains in sync
 */
static void parq_upload_update_IP_and_name(struct parq_ul_queued *parq_ul, 
	gnutella_upload_t *u)
{
	gint rw;
	gchar buf[1024];
	
	g_assert(parq_ul != NULL);
	
	if (parq_ul->IP_and_name != NULL) {
		g_hash_table_remove(ul_all_parq_by_IP_and_Name, parq_ul->IP_and_name);
		g_free(parq_ul->IP_and_name);
	}
	
	rw = gm_snprintf(buf, sizeof(buf), "%d %s", u->ip, u->name);
	parq_ul->IP_and_name = g_strdup(buf);
	
	g_hash_table_insert(ul_all_parq_by_IP_and_Name, parq_ul->IP_and_name, 
		parq_ul);

}
/*
 * parq_upload_request
 *
 * Looks up an upload in the queue, to see if it is already queued, if it isn't
 * it will be added.
 * If the download may continue, true is returned. False otherwise (which 
 * probably means the upload is queued).
 */
gboolean parq_upload_request(gnutella_upload_t *u, header_t *header, 
	  guint used_slots)
{
	struct parq_ul_queued *parq_ul = NULL;
	time_t now = time((time_t *) NULL);
	gchar *buf;
	
	g_assert(u != NULL);
	g_assert(header != NULL);
	
	/* Try to locate by ID first. If this fails, try to locate by IP and file
	 * name. We want to locate on ID first as a client may reuse an ID.
	 */
	
	buf = header_get(header, "X-Queued");
	
	if (buf != NULL) {
		gint length;
		parq_ul = g_hash_table_lookup(ul_all_parq_by_ID,
			get_header_value(
				buf, "ID", &length));
	
		if (parq_ul == NULL) {
			g_warning("Client send ID with PARQ request, however ID could not"
				"be located\r\n");
			if (dbg) {
				g_warning("header dump:");
				header_dump(header, stderr);
			}
		} else
			g_assert(length > PARQ_MAX_ID_LENGTH);
	}
	
	if (parq_ul == NULL)
		parq_ul = parq_upload_find(u);

	if (parq_ul == NULL) {
		
		/*
		 * Current upload is not queued yet. If the queue isn't full yet, always
		 * add the upload in the queue. 
		 */
		
		if (parq_upload_queue_full(u))
			return FALSE;

		parq_ul = parq_upload_create(u);

		g_assert(parq_ul != NULL);

//		if (dbg)
			printf("PARQ UL Q %d/%d (%3d/%3d) ETA: %s Added:  '%s'\r\n",
				g_list_position(ul_parqs,
					g_list_find(ul_parqs, parq_ul->queue)) + 1,
				g_list_length(ul_parqs),
				parq_ul->position, 
				parq_ul->queue->size,
				short_time(parq_upload_lookup_ETA(u)),
				parq_ul->IP_and_name);
	}
	g_assert(parq_ul != NULL);
	
	parq_ul->updated = now;
	parq_ul->expire = now + PARQ_UL_RETRY_DELAY;
	
	/*
     * It is possible the client reused its ID for another file name, which is
	 * a valid thing to do. So make sure we have still got the IP and name
	 * in sync
	 */
	parq_upload_update_IP_and_name(parq_ul, u);
	
	/*
	 * Client was already downloading a segment, segment was finished and 
	 * just did a follow up request.
	 */
	if (parq_ul->position == 0) {
		return TRUE;
	}
	
	/*
	 * Check wether the current upload is allowed to get an upload slot. If so
	 * move other queued items after the current item up one position in the
	 * queue
	 */
	if (parq_upload_continue(u, max_uploads - used_slots)) {
		return TRUE;
	} else {
		u->parq_status = TRUE;
		return FALSE;
	}
}

/*
 * parq_upload_busy
 *
 * Mark an upload as really being active instead of just being queued.
 */
void parq_upload_busy(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	u->parq_status = 0;
	
	parq_ul = parq_upload_find(u);
	
	g_assert(parq_ul != NULL);
	
	if (parq_ul->position == 0)
		return;
	
	parq_ul->queue->active_uploads++;
	parq_ul->position = 0;	// Mark as uploading
	parq_upload_decrease_all_after(parq_ul);	
}

void parq_upload_add(gnutella_upload_t *u)
{
	/*
	 * Cosmetic. Not used at the moment. gnutella_upload_t structure probably
	 * isn't complete yet at this moment
	 */	
}

/*
 * parq_upload_remove
 *
 * When an upload is removed this function should be called so parq
 * knows the current upload status of an upload.
 */
void parq_upload_remove(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	g_assert(u != NULL);

	/*
	 * Avoid removing an upload which is being removed because we are returning
	 * a busy (503), in which case the upload got queued
	 */
		
	if (u->parq_status) {
		u->parq_status = 0;
		return;
	}
	
	parq_ul = parq_upload_find(u);
	
	/* If parq_ul = NULL, than the upload didn't get a slot in the PARQ. */
	if (parq_ul == NULL)
		return;

	if (parq_ul->position == 0 && u->keep_alive && u->status == GTA_UL_WAITING) {
		printf("**** PARQ UL Q %d/%d: Not removed, waiting for new request\r\n",
			g_list_position(ul_parqs, 
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs));
		return;
	}
	
	if (dbg)
		printf("PARQ UL Q %d/%d: Upload finished or removed from uploads\r\n",
			g_list_position(ul_parqs, 
				g_list_find(ul_parqs, parq_ul->queue)) + 1,
			g_list_length(ul_parqs));
				
	
	if (parq_ul->position == 0)
		parq_ul->queue->active_uploads--;
	else
		parq_upload_decrease_all_after(parq_ul);
	
	g_assert(parq_ul->queue->active_uploads >= 0);
	
	parq_upload_free(parq_ul);
}

/*
 * parq_upload_add_header
 * 
 * Adds X-Queued status to an queud upload in the HTTP header.
 */
void parq_upload_add_header(gchar *buf, gint *retval, gpointer arg)
{	
	gint rw = 0;
	gint length = *retval;
	gchar lbuf[1024];
	struct upload_http_cb *a = (struct upload_http_cb *) arg;

	g_assert(buf != NULL);
	g_assert(retval != NULL);
	g_assert(a->u != NULL);
	
	if (parq_upload_queued(a->u)) {
		guint neededlength = gm_snprintf(lbuf, length,
			"X-Queue: %d.%d\r\n"
			"X-Queued: position=%d; ID=%s; length=%d ETA=%dl lifetime=%d\r\n",
			PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
			parq_upload_lookup_position(a->u),
			parq_upload_lookup_id(a->u),
			parq_upload_lookup_size(a->u),
			parq_upload_lookup_ETA(a->u),
			parq_upload_lookup_lifetime(a->u));

		if (neededlength < length) {
			rw = gm_snprintf(buf, length,
			"X-Queue: %d.%d\r\n"
			"X-Queued: position=%d; ID=%s; length=%d ETA=%dl lifetime=%d\r\n",
			PARQ_VERSION_MAJOR, PARQ_VERSION_MINOR,
			parq_upload_lookup_position(a->u),
			parq_upload_lookup_id(a->u),
			parq_upload_lookup_size(a->u),
			parq_upload_lookup_ETA(a->u),
			parq_upload_lookup_lifetime(a->u));
		}
	}

	g_assert(rw < length);
	
	*retval = rw;
}

/*
 * parq_upload_lookup_position
 *
 * Returns the current queueing position of an upload. Returns a value of 
 * (guint) -1 if not found.
 */
guint parq_upload_lookup_position(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	g_assert(u != NULL);
	
	parq_ul = parq_upload_find(u);

	if (parq_ul != NULL) {
		return parq_ul->position;
	} else {
		return (guint) -1;	
	}
}

/*
 * parq_upload_lookup_id
 * 
 * Returns the current ID of the upload.
 */
gchar* parq_upload_lookup_id(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	g_assert(u != NULL);
	
	parq_ul = parq_upload_find(u);

	if ( parq_ul != NULL)
		return parq_ul->ID;
	else		
		return NULL;
}

/*
 * parq_upload_lookup_ETA
 *
 * Returns the Estimated Time of Arrival for an upload slot for a given upload.
 */
guint parq_upload_lookup_ETA(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul;
	
	parq_ul = parq_upload_find(u);
	
	/* If parq_ul == NULL the current upload isn't queued and ETA is unknown */
	if (parq_ul != NULL)
		return parq_ul->ETA;
	else
		return (guint) -1;
}

/*
 * parq_upload_lookup_size
 *
 * Returns the current upload queue size.
 */
guint parq_upload_lookup_size(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */
	
	parq_ul = parq_upload_find(u);
	
	if (parq_ul != NULL) {
		g_assert(parq_ul->queue != NULL);
		g_assert(parq_max_upload_size > parq_ul->queue->size);
		
		return parq_ul->queue->size;
	} else {
		/* No queue created yet */
		return 0;
	}
}

/*
 * parq_upload_lookup_lifetime
 *
 * Returns the lifetime of a queued upload
 */
guint parq_upload_lookup_lifetime(gnutella_upload_t *u)
{
	struct parq_ul_queued *parq_ul = NULL;
	
	/*
	 * There can be multiple queues. Find the queue in which the upload is
	 * queued.
	 */
	
	parq_ul = parq_upload_find(u);
	
	if (parq_ul != NULL) {
		return PARQ_UL_RETRY_DELAY;
	} else {
		/* No queue created yet */
		return 0;
	}	
}

/* parq_upload_decrease_all_after
 *
 * Decreases the position of all queued items after the given queued item.
 */
static void parq_upload_decrease_all_after(struct parq_ul_queued *cur_parq_ul)
{
	GList *l;

	g_assert(cur_parq_ul != NULL);
	g_assert(cur_parq_ul->queue != NULL);
	g_assert(cur_parq_ul->queue->by_Position != NULL);
	g_assert(cur_parq_ul->queue->size > 0);
	
	l = g_list_find(cur_parq_ul->queue->by_Position, cur_parq_ul);
	l = g_list_next(l);	/* Decrease _after_ current parq */
	
	/*
	 * Cycle through list and decrease all positions by one. Position should
	 * never reach 0 which would mean the queued item is currently uploading
	 */
	for (;	l; l = g_list_next(l)) {
		struct parq_ul_queued *parq_ul = (struct parq_ul_queued *) l->data;

		g_assert(parq_ul != NULL);
		
		/* 
		 * Don't decrease queued position which already have an upload position
		 */
		if (parq_ul->position > 0) {
			parq_ul->position--;
		
			g_assert(parq_ul->position > 0);
		}
	}
}

/*
 * parq_upload_save_queue
 *
 * Saves all the current queues and there items so it can be restored when the
 * client starts up again.
 */
void parq_upload_save_queue()
{
	gchar *file;
	FILE *f;
	time_t now = time((time_t *)NULL);
	GList *queues;

	if (dbg > 3)
		printf("PARQ UL: Trying to save all queue info\r\n");
	
	file = g_strdup_printf("%s/%s", config_dir, file_parq_file);
	f = fopen(file, "w");	

	if (!f) {
		g_warning("parq_upload_save_queue(): "
			  "unable to open file \"%s\" for writing: %s",
			  file, g_strerror(errno));
		g_free(file);
		return;
	}

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n#\n", f);
	fprintf(f, "# Saved on %s\n", ctime(&now));

	for (queues = g_list_last(ul_parqs) ; 
		  queues != NULL; queues = queues->prev) {
		struct parq_ul_queue *queue = (struct parq_ul_queue *) queues->data;

		g_list_foreach(queue->by_Position, parq_store, f);
	}

	fclose(f);
	g_free(file);

	if (dbg > 3)
		printf("PARQ UL: All saved\r\n");

}

/*
 * parq_store
 *
 * Saves an individual queued upload to disc. This is the callback function
 * used by g_list_foreach in function parq_upload_save_queue
 */
static void parq_store(gpointer data, gpointer x)
{
	FILE *f = (FILE *)x;
	guint32 ip;
	guint offset = 0;
	
	struct parq_ul_queued *parq_ul = (struct parq_ul_queued *) data;
	
	if (dbg)
		printf("PARQ UL Q %d/%d (%3d/%3d): Saving ID: '%s' - '%s'\r\n",
			  g_list_position(ul_parqs, 
				  g_list_find(ul_parqs, parq_ul->queue)) + 1,
			  g_list_length(ul_parqs), 
			  parq_ul->position, 
			  parq_ul->queue->size,
			  parq_ul->ID,
			  parq_ul->IP_and_name);
	
	offset = sscanf(parq_ul->IP_and_name, "%d ", &ip),

	fprintf(f, "QUEUE: %d\n"
		  "POS: %d\n"
		  "ENTERED: %d\n"
		  "ID: %s\n"
		  "SIZE: %d\n"
		  "IP: %d\n"
		  "NAME: %s\n\n", 
		  g_list_position(ul_parqs, g_list_find(ul_parqs, parq_ul->queue)) + 1,
		  parq_ul->position,
		  (gint) parq_ul->enter,
		  parq_ul->ID,
		  parq_ul->file_size,
		  ip,
		  strchr(parq_ul->IP_and_name, ' ') + 1);
}

/*
 * parq_upload_load_queue
 *
 * Loads the saved queue status back into memory
 */
static void parq_upload_load_queue()
{
	gchar *file;
	FILE *f;
	gchar line[1024];
	gboolean next = FALSE;
	gnutella_upload_t *u;
	struct parq_ul_queued *parq_ul;
	
	int queue = 0;
	int position = 0;
	int enter = 0;
	int filesize = 0;
	int ip = 0;
	char ID[PARQ_MAX_ID_LENGTH];
	char name[1024];
	
	file = g_strdup_printf("%s/%s", config_dir, file_parq_file);
	f = fopen(file, "r");
	
	if (!f) {
		g_warning("parq_upload_load_queue(): "
			"unable to open file \"%s\" for reading: %s",
			file, g_strerror(errno));
		g_free(file);
		return;
	}
	
	u = walloc(sizeof(gnutella_upload_t));
	
	printf("Loading queue information\r\n");

	line[sizeof(line)-1] = '\0';

	while (fgets(line, sizeof(line), f)) {
		/* Skip comments */
		if (*line == '#') continue;
	
		sscanf(line, "QUEUE: %d", &queue);
		sscanf(line, "POS: %d\n", &position);
		sscanf(line, "ENTERED: %d\n", &enter);
		sscanf(line, "SIZE: %d\n", &filesize);
		sscanf(line, "IP: %d\n", &ip);
		if (!strncmp(line, "ID: ", 4)) {
			gchar *newline;
			g_strlcpy(ID, (line + sizeof("ID:")), sizeof(ID));
			newline = strchr(ID, '\n');
			if (newline)
				*newline = '\0';
		}		
		if (!strncmp(line, "NAME: ", 6)) {
			gchar *newline;
			g_strlcpy(name, (line + sizeof("NAME:")), sizeof(name));
			newline = strchr(name, '\n');
			
			if (newline)
				*newline = '\0';
			
			/* Expect next parq entry */
			next = TRUE;
		}
		
		if (next) {
			next = FALSE;
			
			/* Fill a fake upload structure */
			u->file_size = filesize;
			u->name = name;
			u->ip = ip;
			
			parq_ul = parq_upload_create(u);
			
			g_assert(parq_ul != NULL);
	
			parq_ul->enter = enter;
			
			printf("PARQ UL Q %d/%d (%3d/%3d) ETA: %s Restored: '%s'\r\n",
				g_list_position(ul_parqs,
					g_list_find(ul_parqs, parq_ul->queue)) + 1,
				g_list_length(ul_parqs),
				parq_ul->position, 
				parq_ul->queue->size,
				short_time(parq_upload_lookup_ETA(u)),
				parq_ul->IP_and_name);						
			
		}
	}
	
	wfree(u, sizeof(gnutella_upload_t));
}
/*
# vim:ts=4:sw=4
*/
