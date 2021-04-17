#!/usr/bin/env cram.sh

Dummy interface

	$ bst --nic dummy,type=dummy,address=fe:ed:de:ad:be:ef -- ip link show dummy
	2: dummy: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	    link/ether fe:ed:de:ad:be:ef brd ff:ff:ff:ff:ff:ff

MACVLANs

	$ bst --nic invalid,type=macvlan,link=invalid,address=fe:ed:de:ad:be:ef -- false
	bst: if_nametoindex invalid: No such device
	[1]

	$ bst --nic parent,dummy bst --nic macvlan0,type=macvlan,link=parent,mode=bridge,address=fe:ed:de:ad:be:ef -- ip link show macvlan0
	2: macvlan0@if2: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
	    link/ether fe:ed:de:ad:be:ef brd ff:ff:ff:ff:ff:ff link-netnsid 0

IPVLANs

	$ bst --nic parent,dummy,address=fe:ed:de:ad:be:ef bst --nic ipvlan,type=ipvlan,link=parent -- ip link show ipvlan
	2: ipvlan@if2: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
	    link/ether fe:ed:de:ad:be:ef brd ff:ff:ff:ff:ff:ff link-netnsid 0
