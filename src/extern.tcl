#! /usr/bin/tclsh

#
# Glade is wonderful but it can't create 'extern' widgets ...
#
# So this little script...
#
# Of course, you will need tclsh to run it...
#

set w_main_list {
	notebook_main
	clist_menu clist_stats clist_connections button_stats_update
	sw_menu sw_stats sw_connections
	clist_nodes button_nodes_add button_nodes_remove entry_host
	entry_up_connections
	entry_global_messages entry_global_searches entry_routing_errors entry_dropped_messages
	entry_count_downloads entry_count_uploads
	entry_hosts_in_catcher
	button_host_catcher_clear
	clist_uploads button_kill_upload button_clear_uploads checkbutton_clear_uploads entry_max_uploads
	clist_downloads button_abort_download button_resume_download button_clear_download
	entry_max_downloads entry_max_host_downloads checkbutton_clear_downloads clist_download_queue button_remove_download
	checkbutton_never_push checkbutton_jump_to_downloads
	checkbutton_autodownload
	entry_search button_search label_items_found entry_minimum_speed
	notebook_search_results button_search_download button_search_stream button_search_clear
	combo_searches combo_entry_searches
	button_search_filter button_search_close
	checkbutton_monitor entry_monitor clist_monitor
	checkbutton_enable_search_stats clist_search_stats entry_search_stats_update_interval entry_search_stats_delcoef label_search_stats_count
	button_config_move_path
	button_config_save_path entry_config_path label_files_scanned entry_config_extensions
	entry_config_port entry_config_force_ip entry_config_speed checkbutton_config_throttle
	label_current_port
	checkbutton_config_force_ip entry_config_search_items entry_config_maxttl entry_config_myttl
	button_config_update_port button_config_rescan_dir
        label_left label_right entry_config radio_http radio_socksv4 radio_socksv5
        checkbutton_proxy_connections config_entry_socks_host
        config_entry_socks_port config_entry_socks_username 
        config_entry_socks_password entry_max_connections entry_search_reissue_timeout
	popup_hosts popup_hosts_title popup_hosts_export
	popup_dl_active popup_dl_active_title download_p_push download_p_queue download_p_kill
	popup_dl_queued popup_dl_queued_title download_start_now
	popup_search popup_search_title popup_search_stop_sorting popup_search_filters popup_search_close
	popup_search_toggle_tabs popup_search_restart popup_search_duplicate popup_search_clear_results
	popup_search_stop popup_search_resume
	popup_monitor popup_monitor_title
	popup_nodes popup_nodes_title
	popup_uploads popup_uploads_title
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
			puts -nonewline stdout "."
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
