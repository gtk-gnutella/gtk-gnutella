/*
 * functions that should be in gtk-1.2 but are not.
 */

#include "gnutella.h"

#include "gtk-missing.h"

/*
 * gtk_paned_get_position:
 *
 * Get position of divider in a GtkPaned. (in GTK2)
 */
gint gtk_paned_get_position(GtkPaned *paned){
    g_return_if_fail (paned != NULL);
    g_return_if_fail (GTK_IS_PANED (paned));

    return paned->child1_size;
}
