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

	hbox_statusbar
	label_statusbar_uptime

	button_config_move_path
	button_config_rescan_dir
	button_config_save_path 
	button_config_update_port 
	checkbutton_config_force_ip 
	checkbutton_config_throttle
	checkbutton_config_proxy_connections
	entry_config_extensions
	entry_config_force_ip 
	entry_config_maxttl 
	entry_config_myttl
	entry_config_path 
	entry_config_port 
	entry_config_search_items 
	entry_config_socks_host
	entry_config_socks_password 
	entry_config_socks_username 
	entry_config_speed 
	radio_config_http 
	radio_config_socksv4 
	radio_config_socksv5
    entry_config_socks_port 

	button_nodes_add 
	button_nodes_remove 
	button_host_catcher_clear
	entry_hosts_in_catcher

	button_uploads_kill
	button_uploads_clear_completed
	checkbutton_uploads_auto_clear
	clist_uploads 	

	button_downloads_abort
	button_downloads_clear_completed
	button_downloads_queue_clear
	button_downloads_resume
	button_downloads_queue_remove
	checkbutton_downloads_auto_clear 
	checkbutton_downloads_never_push
	clist_downloads 
	clist_downloads_queue 

	button_search 
	button_search_clear
	button_search_close
	button_search_download 
	button_search_filter 
	button_search_stream 
	checkbutton_search_jump_to_downloads
	entry_search 
	entry_search_reissue_timeout
	entry_search_stats_delcoef 
	entry_search_stats_update_interval 

	clist_monitor
	checkbutton_monitor_enable

	popup_search_clear_results
	popup_search_close
	popup_search_duplicate 
	popup_search_filters 
	popup_search_restart 
	popup_search_resume
	popup_search_stop 
	popup_search_stop_sorting 
	popup_search_toggle_tabs 
 	popup_search 

	popup_hosts 
	popup_hosts_export

	popup_dl_queued 
	popup_queue_remove
	popup_queue_remove_named
	popup_queue_remove_host
	popup_queue_search_again
	popup_queue_start_now 
	popup_queue_freeze
	popup_queue_search_again

	popup_dl_active 
	popup_downloads_abort
	popup_downloads_resume
	popup_downloads_kill 
	popup_downloads_push 
	popup_downloads_queue
	popup_downloads_remove_file
	popup_downloads_search_again

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
	clist_connections 
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
	statusbar 
	sw_connections
    progressbar_connections 
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
