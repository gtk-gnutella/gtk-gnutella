
/* Handles upload of our files to others users */

#include "gnutella.h"
#include "interface.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


GSList *uploads          = NULL;
gint running_uploads = 0;

guint32 count_uploads = 0;

/* TODO: Anything :) */
/* Recieve HTTP get information , send headers 200(found) or 404(not found) , look at Range for skip amount
    and do a sanity check on the Range "Range < File Size" and Index, Make Upload structure with socket
    and file desc ,and file name and location , Handle the PUSH request. */

void handle_push_request(struct gnutella_node *n)
{
}

void upload_real_remove(void)
{
}

void upload_remove(struct upload *d, gchar * reason)
{
  gint row;

  if (d->socket->file_desc) close(d->socket->file_desc);
  if (d->file_desc) close(d->file_desc);

  if (d->status != GTA_UL_COMPLETE) /* if UL_COMPLETE, we've already decremented it. */
	running_uploads--;

  if (d->socket->gdk_tag) gdk_input_remove(d->socket->gdk_tag);

  row = gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads), (gpointer) d);
  gtk_clist_remove(GTK_CLIST(clist_uploads), row);

  uploads = g_slist_remove(uploads, (gpointer) d);

  if (d->socket != NULL)
    {
      d->socket = NULL;

      g_free(d->buffer); 
      g_free(d);
    }
  else printf("upload_remove(); upload already free'd %p\n" , d);
}

struct upload* upload_add(struct gnutella_socket *s)
{

  /* TODO: Deal with push request, just setup the upload structure but don't send anything */
  /* Check for duplicate uploads, so no one has two of the same file transfering. */
  struct upload *new_upload = NULL;
  struct shared_file *requested_file = NULL;
  GSList *files = NULL, *t_uploads = NULL;
  guint index = 0, skip = 0, rw = 0, row = 0;
  gchar http_response[1024], *fpath = NULL, sl[] = "/\0";
  gchar *titles[3];

  titles[0] = titles[1] = titles[2] = NULL;

  if(sscanf(s->buffer, "GET /get/%u/", &index)) {
	  if(running_uploads >= max_uploads) {
	    rw = g_snprintf(http_response, sizeof(http_response), 
						"HTTP 503 Too many uploads; try again later\r\nServer: Gnutella\r\n\r\n");
		write(s->file_desc, http_response, rw);

		return NULL;
	  }

      for (files = shared_files; files; files = files->next)
      	if ( (((struct shared_file *)(*files).data)->file_index == index))
	  requested_file = (struct shared_file *)(*files).data;

      for (t_uploads = uploads; t_uploads; t_uploads = t_uploads->next)
      	if ( (((struct upload *)(*t_uploads).data)->index == index) &&
			 (((struct upload *)(*t_uploads).data)->socket->ip == s->ip)) {
		  rw = g_snprintf(http_response, sizeof(http_response),
						  "HTTP 409 Conflict: I think you're already downloading this one from me.\r\n"
						  "Server: Gnutella\r\n\r\n");
		  write(s->file_desc, http_response, rw);
		  return NULL;
		}
 
      
      if (requested_file == NULL)
		goto not_found;

      sscanf(s->buffer, "Range: bytes=%u-\r\n", &skip);
       
      new_upload = (struct upload*)g_malloc0( sizeof(struct upload) );

      /* Set the full path to the file */
      if (requested_file->file_directory[strlen(requested_file->file_directory)-1] == sl[0])
	fpath = g_strconcat(requested_file->file_directory, requested_file->file_name, NULL);
      else
	fpath = g_strconcat(requested_file->file_directory, &sl, requested_file->file_name, NULL);

      /* Open the file for reading , READONLY just in case. */
      if((new_upload->file_desc = open(fpath, O_RDONLY)) < 0)
		goto not_found;

      /* Set all the upload information in our newly created upload struct */
      new_upload->index = index;
      new_upload->name = requested_file->file_name;

      s->type = GTA_TYPE_UPLOAD;

      new_upload->socket = s;
      new_upload->skip = skip;
      new_upload->pos = 0;
      new_upload->status = GTA_UL_SENDING;
      new_upload->push = FALSE;
      new_upload->file_size = requested_file->file_size;
      new_upload->start_date = time((time_t *) NULL);
      new_upload->last_update = 0;

	  new_upload->buf_size = 4096*sizeof(gchar);
      new_upload->buffer = (gchar *)g_malloc(new_upload->buf_size);
      new_upload->bpos = 0;
      new_upload->bsize = 0;

      titles[0] = new_upload->name;
      titles[1] = g_strdup(ip_to_gchar( s->ip ));
      titles[2] = "";


      /* Setup and write the HTTP 200 header , including the file size */
      rw = g_snprintf(http_response, sizeof(http_response), 
		 "HTTP 200 OK\r\nServer: Gnutella\r\nContent-type: application/binary\r\nContent-length: %i\r\n\r\n"
		 , new_upload->file_size); 

      write(new_upload->socket->file_desc, http_response, rw);
       
      /* add the upload structure to the upload slist */
      uploads = g_slist_append(uploads, new_upload);


      /* add upload to the gui */
      row = gtk_clist_append(GTK_CLIST(clist_uploads), titles);
      gtk_clist_set_row_data(GTK_CLIST(clist_uploads), row, (gpointer) new_upload);

      running_uploads++;

      gui_update_c_uploads();

      g_free(fpath);

      return new_upload;
  } 

  not_found:

  /* What? 404 we either don't have it , or have too many uploads already */
  rw = g_snprintf(http_response, sizeof(http_response), 
				  "HTTP 404 Not Found\r\nServer: Gnutella\r\n\r\n");

  write(s->file_desc, http_response, rw);

  printf("upload_add(); request from %s\n%s", ip_to_gchar(s->ip), s->buffer);

  if(new_upload) g_free(new_upload);
  if(fpath) g_free(fpath);

  return NULL;
}      

/* Uplaod Write
 * FIFO type action to deal with low baud rates. If we try to force
 * 4k then the lower speed downloads will be garbled.
 */
void upload_write(gpointer up, gint source, GdkInputCondition cond)
{
  struct upload* current_upload;
  guint32 write_bytes;
  current_upload = (struct upload*)up;
 

  if (!(cond & GDK_INPUT_WRITE)) /* If we can't write then we don't want it, kill the socket */
  {
    printf("upload_write(); Condition %i, Exception = %i\n", cond, GDK_INPUT_EXCEPTION);
   socket_destroy(current_upload->socket);
   return;
  }

  /* If we got a valid skip amount then jump ahead to that position */
  if ((current_upload->pos == 0) && (current_upload->skip > 0) && (current_upload->skip > current_upload->file_size))
    {
      if (lseek(current_upload->file_desc , current_upload->skip, SEEK_SET) == -1)
	{ socket_destroy(current_upload->socket); return; }
    }


  /* if the buffer position is equal to zero then we need to read more data from the file. We read in under or equal to 
     the buffer memory size */

  if (current_upload->bpos == 0)
    if((current_upload->bsize = read(current_upload->file_desc, current_upload->buffer, current_upload->buf_size)) == -1)
    {
      socket_destroy(current_upload->socket);
      return;
    }

  if ((write_bytes = write(current_upload->socket->file_desc, &current_upload->buffer[current_upload->bpos], 
			   (current_upload->bsize - current_upload->bpos))) == -1)
    {
      socket_destroy(current_upload->socket);
      return;
    }


  current_upload->pos += write_bytes;

  if ((current_upload->bpos+write_bytes) < current_upload->bsize)
    current_upload->bpos += write_bytes;
  else
    current_upload->bpos = 0;

	current_upload->last_update = time((time_t *) NULL);


  if (current_upload->pos == current_upload->file_size)
	{
	  count_uploads++;
	  gui_update_upload(current_upload);
	  gui_update_count_uploads();
	  gui_update_c_uploads();
	  if(clear_uploads == TRUE) {
		socket_destroy(current_upload->socket);
		return;
	  } else {
		current_upload->status = GTA_UL_COMPLETE;
		running_uploads--;
		gtk_widget_set_sensitive(button_clear_uploads, 1);
		gdk_input_remove(current_upload->socket->gdk_tag);
		current_upload->socket->gdk_tag = 0;
		gui_update_upload(current_upload);
	  }
	}
}

/* vi: set ts=3: */
