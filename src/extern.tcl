#! /usr/bin/tclsh

#
# Glade is wonderful but it can't create 'extern' widgets ...
#
# So this little script...
#
# Of course, you will need tclsh to run it...
#

set w_list {
	notebook_main
	clist_menu clist_stats clist_connections button_stats_update
	clist_nodes button_nodes_add button_nodes_remove entry_host \
	entry_up_connections
	entry_global_messages entry_global_searches entry_routing_errors entry_dropped_messages \
	entry_count_downloads entry_count_uploads
	clist_host_catcher
	button_host_catcher_connect button_host_catcher_get_more
	button_host_catcher_remove button_host_catcher_clear
	clist_uploads button_kill_upload button_clear_uploads checkbutton_clear_uploads
	clist_downloads button_abort_download button_resume_download button_clear_download
	entry_max_downloads checkbutton_clear_downloads clist_download_queue button_remove_download
	entry_search button_search label_items_found entry_minimum_speed
	notebook_search_results button_search_download button_search_stream
	combo_searches combo_entry_searches
	button_search_filter button_search_close
	checkbutton_monitor entry_monitor clist_monitor
	button_config_move_path
	button_config_save_path entry_config_path label_files_scanned entry_config_extensions
	entry_config_port entry_config_force_ip entry_config_speed checkbutton_config_throttle
	label_current_port
	checkbutton_config_force_ip entry_config_search_items entry_config_maxttl entry_config_myttl
	button_config_update_port button_config_rescan_dir
	label_left label_right
	popup_hosts popup_hosts_title popup_hosts_export
	popup_dl_active popup_dl_active_title download_p_push download_p_queue download_p_kill
	popup_dl_queued popup_dl_queued_title download_start_now
	popup_search popup_search_title popup_search_stop_sorting popup_search_filters popup_search_close
	popup_search_toggle_tabs
	popup_monitor popup_monitor_title
	popup_nodes popup_nodes_title
	popup_uploads popup_uploads_title
}

# First we check wether the script hasn't been run already

set h [open "interface.h"]

while { ! [eof $h] } {
	set l [gets $h]
	if { [regexp -- "^/\\* Global Widgets \\(added by extern\\.tcl\\) \\*/$" $l] == 1 } {
		puts stderr "\n\nYou can't run this script more than once !\n\n"
		exit 1
	}
}

# interface.h ----------------------------------------------------------------------------------------

close $h

# Ok, we can add the global widgets declarations

set h [open "interface.h" "a"]

puts $h "\n/* Global Widgets (added by extern.tcl) */\n"

foreach a $w_list { puts $h "extern GtkWidget *$a;" }

puts $h "\n/* End of global widgets */\n";

close $h

# interface.c ----------------------------------------------------------------------------------------

set s [open "interface.c" "r"]
set d [open "interface.c.tmp" "w" 0600]

# First, copy the head until the first "GtkWidget *"

while { ! [eof $s] } {
	set l [gets $s]
	if { [regexp -- "^GtkWidget\\*$" $l] == 1 } break
	puts $d $l
}

# Insert the widgets declarations

puts $d "/* Global Widgets (added by extern.tcl) */\n"

foreach a $w_list { puts $d "GtkWidget *$a;" }

puts $d "\n/* End of global widgets */\n";

# Puts back the "GtkWidget*" line

puts $d "\n$l"

# Then copy all the remaining lines, removing double declarations

set skip 0

while { ! [eof $s] } {

	set l [gets $s]

	if { [regexp -- "^  GtkWidget \\*" $l] == 1 } {
		foreach a $w_list {
			if { [regexp -- "^  GtkWidget \\*$a;" $l] == 1 } { set skip 1; break }
			if { $skip } break
		}
	}
	
	if { $skip } {
		puts -nonewline stdout "."
		flush stdout
		set skip 0
		continue
	}

	puts $d $l
}

# Close the files

close $s
close $d

# Rename the file

file rename -force -- interface.c.tmp interface.c

#

puts stdout ""

