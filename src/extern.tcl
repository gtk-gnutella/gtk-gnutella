#! /usr/bin/tclsh

#
# Glade is wonderful but it can't create 'extern' widgets ...
#
# So this little script...
#
# Of course, you will need tclsh to run it...
#

set w_main_list {
    sw_menu

    menu_toolbar_visible
    menu_statusbar_visible
    menu_uploads_visible
    menu_downloads_visible
    menu_connections_visible
    menu_bws_in_visible
    menu_bws_out_visible
    menu_bws_gin_visible
    menu_bws_gout_visible

    hbox_statusbar
    label_statusbar_uptime

    button_config_move_path
    entry_config_move_path
    button_config_rescan_dir
    button_config_save_path
    entry_config_save_path
    checkbutton_config_force_ip
    checkbutton_config_proxy_connections
    checkbutton_config_proxy_auth
    checkbutton_config_bws_in
    checkbutton_config_bws_out
    checkbutton_config_bws_gin
    checkbutton_config_bws_gout
    checkbutton_config_bw_ul_usage_enabled
    entry_config_extensions
    entry_config_force_ip 
    entry_config_maxttl 
    entry_config_myttl
    entry_config_path 
    spinbutton_config_port 
    entry_config_search_items 
    spinbutton_config_search_min_speed
    entry_config_proxy_ip
    entry_config_socks_password
    entry_config_socks_username 
    entry_config_speed 
    radio_config_http 
    radio_config_socksv4 
    radio_config_socksv5
    checkbutton_config_use_netmasks
    entry_config_netmasks        
    spinbutton_config_proxy_port 
    spinbutton_config_bws_in
    spinbutton_config_bws_out
    spinbutton_config_bws_gin
    spinbutton_config_bws_gout
    spinbutton_config_ul_usage_min_percentage
    spinbutton_config_port
    spinbutton_config_proxy_port
    spinbutton_config_max_high_ttl_radius
    spinbutton_config_max_high_ttl_msg
    spinbutton_config_hard_ttl_limit
    spinbutton_config_download_overlap_range
    spinbutton_config_download_max_retries
    spinbutton_config_download_retry_stopped
    spinbutton_config_download_retry_refused_delay
    spinbutton_config_download_retry_busy_delay
    spinbutton_config_download_retry_timeout_delay
    spinbutton_config_download_retry_timeout_max
    spinbutton_config_download_retry_timeout_min
    spinbutton_config_download_connecting_timeout
    spinbutton_config_download_push_sent_timeout
    spinbutton_config_download_connected_timeout 
    spinbutton_config_node_tx_flowc_timeout
    spinbutton_config_node_connecting_timeout
    spinbutton_config_node_connected_timeout
    spinbutton_config_upload_connecting_timeout
    spinbutton_config_upload_connected_timeout
    vpaned_downloads

    button_nodes_add 
    button_nodes_remove 
    button_host_catcher_clear
    progressbar_hosts_in_catcher

    button_uploads_kill
    button_uploads_clear_completed
    checkbutton_uploads_auto_clear
    spinbutton_uploads_max_ip
    clist_uploads 	

    clist_downloads_queue
    togglebutton_queue_freeze
    entry_queue_regex
    checkbutton_queue_regex_case

    button_downloads_abort
    button_downloads_clear_completed
    button_downloads_resume
    checkbutton_downloads_auto_clear 
    checkbutton_downloads_never_push
    checkbutton_download_delete_aborted
    clist_downloads

    button_search 
    button_search_clear
    button_search_close
    button_search_download 
    button_search_filter
    checkbutton_search_jump_to_downloads
    checkbutton_search_remove_downloaded
    checkbutton_search_pick_all
    entry_search 
    combo_search
    entry_search_reissue_timeout
    entry_search_stats_delcoef 
    entry_search_stats_update_interval 
    clist_search
    optionmenu_search_filter

    clist_monitor
    checkbutton_monitor_enable

    popup_search_clear_results
    popup_search_close
    popup_search_duplicate 
    popup_search_filters 
    popup_search_restart 
    popup_search_resume
    popup_search_stop
    popup_search_toggle_tabs 
    popup_search_config_cols
    popup_search 

    popup_hosts 
    popup_hosts_export
    popup_dl_queued 
    popup_queue_abort
    popup_queue_abort_named
    popup_queue_abort_host
    popup_queue_search_again
    popup_queue_start_now
    popup_queue_search_again
    popup_queue_copy_url
    popup_queue_connect

    popup_dl_active 
    popup_downloads_abort
    popup_downloads_abort_named
    popup_downloads_abort_host
    popup_downloads_resume
    popup_downloads_push 
    popup_downloads_queue
    popup_downloads_remove_file
    popup_downloads_search_again
    popup_downloads_copy_url
    popup_downloads_connect

    popup_monitor 
    popup_monitor_add_search	

    popup_nodes 
    popup_nodes_remove

    popup_uploads 
    popup_uploads_title

    button_ul_stats_clear_all
    button_ul_stats_clear_deleted 
    checkbutton_autodownload
    checkbutton_search_stats_enable
    clist_nodes 
    clist_search_stats 
    clist_ul_stats 
    combo_entry_searches
    combo_searches 
    ctree_menu 
    entry_count_downloads 
    entry_count_uploads
    entry_dropped_messages
    entry_global_messages 
    entry_global_searches 
    entry_host
    entry_max_connections 
    entry_max_downloads 
    entry_max_host_downloads 
    entry_max_uploads
    entry_minimum_speed
    entry_monitor
    entry_routing_errors 
    entry_up_connections
    hb_toolbar
    label_current_port
    label_files_scanned 
    label_items_found 
    label_search_stats_count
    notebook_main 
    notebook_search_results 

    progressbar_downloads
    progressbar_uploads 
    progressbar_bws_in
    progressbar_bws_out
    progressbar_bws_gin
    progressbar_bws_gout

    statusbar 
    sw_connections
    progressbar_connections 
    entry_nodes_guid
    entry_nodes_ip
    pixmap_firewall
    pixmap_no_firewall
    spinbutton_nodes_max_hosts_cached
    frame_bws_inout
    frame_bws_ginout
    hpaned_main
    vpaned_sidebar
    hb_searches
    notebook_sidebar

    label_shutdown_count

    button_filter_add_rule_ip
    button_filter_add_rule_size
    button_filter_add_rule_text
    button_filter_add_rule_jump
    button_filter_clear
    button_filter_remove
    checkbutton_filter_ip_invert_cond
    checkbutton_filter_size_invert_cond
    checkbutton_filter_text_case
    checkbutton_filter_text_invert_cond
    clist_filter_rules
    entry_filter_ip_address
    entry_filter_ip_mask
    entry_filter_new
    entry_filter_text_pattern
    notebook_filter_detail
    optionmenu_filter_ip_target
    optionmenu_filter_filters
    optionmenu_filter_size_target
    optionmenu_filter_text_target
    optionmenu_filter_jump_target
    optionmenu_filter_text_type
    optionmenu_filter_default_policy
    spinbutton_filter_size_max
    spinbutton_filter_size_min
}

# interface.h ----------------------------------------------------------------------------------------

# We add the global widgets declarations

file copy -force -- interface-glade.h interface.h
set h [open "interface.h" "a"]

puts $h "\n/* Global Widgets (added by extern.tcl) */\n"

foreach a $w_main_list { puts $h "extern GtkWidget *$a;" }

puts $h "\n/* End of global widgets */\n";

close $h

# interface.c ----------------------------------------------------------------------------------------

set s [open "interface-glade.c" "r"]
set d [open "interface.c" "w" 0600]

# First, copy the head until the first "GtkWidget *"
# We also replace
#
#	#include "callbacks-glade.h"
#	#include "interface-glade.h"
#
# lines with:.
#
#	#include "callbacks.h"
#	#include "interface.h"
#
# because glade is only for developers, and *-glade files are removed.

while { ! [eof $s] } {
	set l [gets $s]
	if { [regexp -- "^GtkWidget\\*$" $l] == 1 } break
	if { [regexp -- "^#include \"callbacks" $l] == 1 } {
		set l "#include \"callbacks.h\""
	}
	if { [regexp -- "^#include \"interface" $l] == 1 } {
		set l "#include \"interface.h\""
	}
	puts $d $l
}

# Insert the widgets declarations

puts $d "/* Global Widgets (added by extern.tcl) */\n"

foreach a $w_main_list { puts $d "GtkWidget *$a;" }

puts $d "\n/* End of global widgets */\n";

# Put back the "GtkWidget*" line

puts $d "\n$l"

# Then copy all the remaining lines, removing double declarations

set skip 0

while { ! [eof $s] } {

	set l [gets $s]

	if { [regexp -- "^  GtkWidget \\*" $l] == 1 } {

		foreach a $w_main_list {
			if { [regexp -- "^  GtkWidget \\*$a;" $l] == 1 } { set skip 1; break }
		}
	
		if { $skip } {
#			puts -nonewline stdout "."
			puts stdout "$a"
			flush stdout
			set skip 0
			continue
		} 
	}

	puts $d $l
}

# Close the files

close $s
close $d

# Rename the file

puts stdout ""
