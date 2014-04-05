#
# Configuration for the generation of the message type constants and the
# derived items such as symbolic translation of enum values and associated
# English descriptions.
#

Prefix: MSG_
Lowercase: no
I18N: yes
Count: TYPE_COUNT
Enum: msg_type_t
Enum-Init: 0
Enum-File: msg.h
#Symbolic:
Description: msg_type_description
#Enum-To-Symbolic:
Enum-To-Description: gnet_msg_type_description
Enum-To-Code: msg.c
Enum-To-Header: msg.h
Protection-Prefix: if_gen

