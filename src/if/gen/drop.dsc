#
# Configuration for the generation of the message drop constants and the
# derived items such as symbolic translation of enum values and associated
# English descriptions.
#

Prefix: MSG_DROP_
Lowercase: yes
I18N: yes
Count: REASON_COUNT
Enum: msg_drop_reason_t
Enum-Init: 0
Enum-File: msg_drop.h
Symbolic: msg_drop_reasons
Description: msg_drop_reason_text
Enum-To-Symbolic: gnet_stats_drop_reason_name
Enum-To-Description: gnet_stats_drop_reason_to_string
Enum-To-Code: msg_drop.c
Enum-To-Header: msg_drop.h
Protection-Prefix: if_gen

