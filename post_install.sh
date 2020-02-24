#!/bin/sh

setcap cap_setuid,cap_setgid,cap_dac_override,cap_sys_admin+ep /usr/bin/bst
