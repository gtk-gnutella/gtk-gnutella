#ifndef __callbacks_h__
#define __callbacks_h__

#include <gtk/gtk.h>
#include "search.h"

gboolean on_clist_monitor_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_clist_nodes_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_clist_uploads_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_entry_max_connections_focus_out_event (GtkWidget *, GdkEventFocus*, gpointer);
gboolean on_entry_max_downloads_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_max_host_downloads_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_max_uploads_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_minimum_speed_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_monitor_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data); 
gboolean on_entry_search_reissue_timeout_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_up_connections_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_main_window_delete_event (GtkWidget *widget, GdkEvent *event, gpointer user_data);
gboolean on_main_window_destroy_event (GtkWidget *widget, GdkEvent *event, gpointer user_data); 
void on_button_extra_config_clicked (GtkButton *button, gpointer user_data); 
void on_button_quit_clicked (GtkButton *button, gpointer user_data);
void on_checkbutton_autodownload_toggled(GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_monitor_enable_toggled (GtkToggleButton *togglebutton, gpointer user_data); 
void on_checkbutton_downloads_never_push_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_clist_nodes_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_nodes_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_clist_nodes_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_ctree_menu_tree_select_row (GtkCTree *clist, GList *node, gint column, gpointer user_data);
void on_entry_host_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_host_changed (GtkEditable *editable, gpointer user_data);
void on_entry_max_connections_activate (GtkEditable *editable, gpointer user_data);
void on_entry_max_downloads_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_max_downloads_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_max_host_downloads_activate (GtkEditable *editable, gpointer user_data);
void on_entry_max_uploads_activate (GtkEditable *editable, gpointer user_data);
void on_entry_minimum_speed_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_monitor_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_monitor_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_up_connections_activate (GtkEditable *editable, gpointer user_data); 



/***
 *** sidebar
 ***/
gboolean on_progressbar_bps_in_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_progressbar_bps_out_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer user_data);


/***
 *** gnutellaNet panel
 ***/
void on_button_host_catcher_clear_clicked (GtkButton *button, gpointer user_data);
void on_button_nodes_add_clicked (GtkButton *button, gpointer user_data); 
void on_button_nodes_remove_clicked (GtkButton *button, gpointer user_data);



/***
 *** uploads panel
 ***/
void on_button_uploads_kill_clicked (GtkButton *button, gpointer user_data);
void on_button_uploads_remove_clicked (GtkButton *button, gpointer user_data); 
void on_checkbutton_uploads_auto_clear_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_clist_uploads_click_column (GtkCList *clist, gint column, gpointer user_data); 
void on_clist_uploads_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_uploads_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data); 
void on_clist_uploads_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_button_uploads_clear_completed_clicked (GtkButton *button, gpointer user_data);


/***
 *** downloads panel
 ***/
/* active downloads */
gboolean on_clist_downloads_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
gboolean on_clist_downloads_queue_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data);
void on_button_downloads_abort_clicked (GtkButton *button, gpointer user_data); 
void on_button_downloads_clear_completed_clicked (GtkButton *button, gpointer user_data);
void on_checkbutton_downloads_auto_clear_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_downloads_delete_aborted_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_clist_downloads_click_column (GtkCList *clist, gint column, gpointer user_data); 
void on_clist_downloads_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_downloads_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_clist_downloads_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_button_downloads_resume_clicked (GtkButton *button, gpointer user_data); 
/* queued downloads */
void on_clist_downloads_queue_click_column (GtkCList *clist, gint column, gpointer user_data);
void on_clist_downloads_queue_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data);
void on_clist_downloads_queue_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_clist_downloads_queue_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data);
void on_button_queue_clear_clicked(GtkButton *button, gpointer user_data);
void on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton, gpointer user_data);



/***
 *** search panel
 ***/
gboolean on_clist_search_results_button_press_event(GtkWidget * widget, GdkEventButton * event, gpointer user_data);
void on_button_search_clear_clicked (GtkButton *button, gpointer user_data);
void on_button_search_clear_clicked(GtkButton * button, gpointer user_data);
void on_button_search_clicked (GtkButton *button, gpointer user_data); 
void on_button_search_close_clicked (GtkButton *button, gpointer user_data);
void on_button_search_download_clicked (GtkButton *button, gpointer user_data); 
void on_button_search_filter_clicked (GtkButton *button, gpointer user_data);
void on_button_search_passive_clicked (GtkButton *button, gpointer user_data);
void on_button_search_stream_clicked (GtkButton *button, gpointer user_data); 
void on_checkbutton_search_jump_downloads_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_search_jump_to_downloads_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_clist_search_results_click_column(GtkCList * clist, gint column, gpointer user_data);
void on_clist_search_results_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);
void on_clist_search_results_select_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_clist_search_results_unselect_row(GtkCList * clist, gint row, gint column, GdkEvent * event, gpointer user_data);
void on_entry_search_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_search_changed (GtkEditable *editable, gpointer user_data);
void on_entry_search_reissue_timeout_activate (GtkEditable *editable, gpointer user_data);
void on_search_notebook_switch(GtkNotebook * notebook, GtkNotebookPage * page, gint page_num, gpointer user_data);
void on_search_popdown_switch(GtkWidget * w, gpointer data);
void on_search_selected(GtkItem * i, gpointer data);
void on_search_switch(struct search *sch);



/***
 *** config panel
 ***/
gboolean on_entry_config_extensions_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_force_ip_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_maxttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data); 
gboolean on_entry_config_myttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_path_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_search_items_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_socks_host_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_socks_password_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_socks_port_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_socks_username_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_speed_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
gboolean on_entry_config_port_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data);
void on_button_config_add_dir_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_move_path_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_rescan_dir_clicked (GtkButton *button, gpointer user_data); 
void on_button_config_save_path_clicked (GtkButton *button, gpointer user_data);
void on_button_config_save_path_clicked (GtkButton *button, gpointer user_data); 
void on_checkbutton_config_force_ip_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_config_proxy_connections_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_checkbutton_config_proxy_auth_toggled(GtkToggleButton *togglebutton, gpointer user_data);
void on_entry_config_extensions_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_extensions_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_force_ip_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_force_ip_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_maxttl_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_maxttl_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_myttl_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_myttl_changed (GtkEditable *editable, gpointer user_data);
void on_entry_config_path_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_port_activate (GtkEditable *editable, gpointer user_data); 
void on_entry_config_search_items_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_socks_host_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_socks_password_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_socks_port_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_socks_username_activate (GtkEditable *editable, gpointer user_data);
void on_entry_config_speed_activate (GtkEditable *editable, gpointer user_data);
void on_radio_config_http_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_radio_config_socksv4_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_radio_config_socksv5_toggled (GtkToggleButton *togglebutton, gpointer user_data);
void on_spinbutton_config_bps_in_changed(GtkSpinButton *spinbutton, gpointer user_data);
void on_spinbutton_config_bps_out_changed(GtkSpinButton *spinbutton, gpointer user_data);

void on_checkbutton_use_netmasks_toggled(GtkToggleButton * togglebutton, gpointer user_data);
void on_entry_config_netmask_activate(GtkEditable * editable, gpointer user_data);
gboolean on_entry_config_netmask_focus_out_event(GtkWidget * widget, GdkEventFocus * event, gpointer user_data);



/***
 *** popup-monitor
 ***/
void on_popup_monitor_add_search_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_monitor_hide(GtkWidget *widget, gpointer user_data);



/***
 *** popup-uploads 
 ***/
void on_popup_uploads_title_activate (GtkMenuItem *menuitem, gpointer user_data);



/***
 *** popup-nodes
 ***/
void on_popup_nodes_remove_activate (GtkMenuItem *menuitem, gpointer user_data); 



/***
 *** popup-search
 ***/
void on_popup_search_clear_results_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_close_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_duplicate_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_filters_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_restart_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_resume_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_stop_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_stop_sorting_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_search_toggle_tabs_activate (GtkMenuItem *menuitem, gpointer user_data);



/***
 *** popup-downloads
 ***/
void on_popup_downloads_push_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_abort_named_activate(GtkMenuItem *menuitem, gpointer user_data); 
void on_popup_downloads_abort_host_activate(GtkMenuItem *menuitem, gpointer user_data); 
void on_popup_downloads_remove_file_activate(GtkMenuItem *menuitem, gpointer user_data); 
void on_popup_downloads_search_again_activate(GtkMenuItem *menuitem, gpointer user_data); 
void on_popup_downloads_queue_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_copy_url_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_popup_downloads_selection_get(GtkWidget * widget, GtkSelectionData * data, 
                                      guint info, guint time, gpointer user_data);
gint on_popup_downloads_selection_clear_event(GtkWidget * widget, GdkEventSelection *event);



/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_queue_freeze_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_queue_search_again_activate (GtkMenuItem *menuitem, gpointer user_data);
void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem, gpointer user_data); 
void on_popup_queue_abort_named_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_popup_queue_abort_activate(GtkMenuItem * menuitem, gpointer user_data);

/***
 *** upload stats
 ***/
void on_button_ul_stats_clear_all_clicked(GtkButton * button, gpointer user_data);
void on_button_ul_stats_clear_deleted_clicked(GtkButton * button, gpointer user_data);
void on_clist_ul_stats_click_column(GtkCList * clist, gint column, gpointer user_data);
void on_clist_ul_stats_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);



/*** 
 *** search stats
 ***/
gboolean on_entry_search_stats_delcoef_focus_out_event(GtkWidget * widget, GdkEventFocus * event, gpointer user_data);
gboolean on_entry_search_stats_update_interval_focus_out_event(GtkWidget * widget, GdkEventFocus * event, gpointer user_data);
void     on_button_search_stats_reset_clicked(GtkButton * button, gpointer user_data);
void     on_checkbutton_search_stats_enable_toggled(GtkToggleButton * togglebutton, gpointer user_data);
void     on_clist_search_stats_resize_column(GtkCList * clist, gint column, gint width, gpointer user_data);
void     on_entry_search_stats_delcoef_activate(GtkEditable * editable, gpointer user_data);
void     on_entry_search_stats_update_interval_activate(GtkEditable * editable, gpointer user_data);



/***
 *** menu bar
 ***/
void on_menu_connections_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_downloads_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_uploads_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_statusbar_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_toolbar_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bps_in_visible_activate(GtkMenuItem * menuitem, gpointer user_data);
void on_menu_bps_out_visible_activate(GtkMenuItem * menuitem, gpointer user_data);

#endif	/* __callbacks_h__ */
