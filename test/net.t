#!/usr/bin/env cram.sh

Dummy interface

	$ bst --nic dummy,type=dummy ip -d -j link show dummy | sed -e 's/"address":"[^"]*",//'
	[{"ifindex":2,"ifname":"dummy","flags":["BROADCAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"ether","broadcast":"ff:ff:ff:ff:ff:ff","promiscuity":0,"min_mtu":0,"max_mtu":0,"linkinfo":{"info_kind":"dummy"},"inet6_addr_gen_mode":"eui64","num_tx_queues":1,"num_rx_queues":1,"gso_max_size":65536,"gso_max_segs":65535}]

MACVLANs

	$ bst --nic invalid,type=macvlan,link=invalid false
	bst: if_nametoindex invalid: No such device
	[1]

	$ bst --nic parent,dummy bst --nic macvlan0,type=macvlan,link=parent,mode=bridge ip -d -j link show macvlan0 | sed -e 's/"address":"[^"]*",//'
	[{"ifindex":2,"link_index":2,"ifname":"macvlan0","flags":["BROADCAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"ether","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":0,"promiscuity":0,"min_mtu":68,"max_mtu":0,"linkinfo":{"info_kind":"macvlan","info_data":{"mode":"bridge"}},"inet6_addr_gen_mode":"eui64","num_tx_queues":1,"num_rx_queues":1,"gso_max_size":65536,"gso_max_segs":65535}]

IPVLANs

	$ bst --nic parent,dummy bst --nic ipvlan,type=ipvlan,link=parent ip -d -j link show ipvlan | sed -e 's/"address":"[^"]*",//'
	[{"ifindex":2,"ifname":"ipvlan","flags":["BROADCAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"ether","broadcast":"ff:ff:ff:ff:ff:ff","promiscuity":0,"min_mtu":68,"max_mtu":65535,"linkinfo":{"info_kind":"ipvlan","info_data":{"mode":"l2","bridge":true}},"inet6_addr_gen_mode":"eui64","num_tx_queues":1,"num_rx_queues":1,"gso_max_size":65536,"gso_max_segs":65535}]
