#
# Configuration for the generation of the general statistics constants and the
# derived items such as symbolic translation of enum values and associated
# English descriptions.
#

Prefix: GNR_
Lowercase: yes
I18N: yes
Count: TYPE_COUNT
Enum: gnr_stats_t
Enum-Init: 0
Enum-File: gnr_stats.h
Symbolic: stats_symbols
Description: stats_text
Enum-To-Symbolic: gnet_stats_general_to_string
Enum-To-Description: gnet_stats_general_description
Enum-To-Code: gnr_stats.c
Enum-To-Header: gnr_stats.h
Protection-Prefix: if_gen

