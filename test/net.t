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

Adding addresses

	$ bst --nic dummy,type=dummy,address=fe:ed:de:ad:be:ef --ip 172.20.0.1,dev=dummy -- ip -j addr show dummy | jq '.[0]  | "\(.ifname) \(.address) \(.addr_info[0].local) \(.addr_info[0].prefixlen) \(.addr_info[1].local) \(.addr_info[1].prefixlen)"'
	"dummy fe:ed:de:ad:be:ef 172.20.0.1 32 fe80::fced:deff:fead:beef 64"

	$ bst --nic dummy,type=dummy,address=fe:ed:de:ad:be:ef --ip 172.20.0.1/16,dev=dummy -- ip -j addr show dummy | jq '.[0]  | "\(.ifname) \(.address) \(.addr_info[0].local) \(.addr_info[0].prefixlen) \(.addr_info[1].local) \(.addr_info[1].prefixlen)"'
	"dummy fe:ed:de:ad:be:ef 172.20.0.1 16 fe80::fced:deff:fead:beef 64"

Adding routes

	$ (bst --route gateway=1.1.1.1 -- ip route show 2>&1 || echo [$?]) | sed 's/Network unreachable/Network is unreachable/'
	bst: route_add 0.0.0.0/0 via 1.1.1.1/32 src 0.0.0.0/0 dev  metric 0: Network is unreachable
	[1]

	$ bst --ip 172.20.0.2/16,lo --route src=172.20.0.2,dst=10.0.0.0/8,gateway=172.20.0.1 -- ip route show
	10.0.0.0/8 via 172.20.0.1 dev lo 

	$ bst --ip 172.20.0.2/16,lo --route src=172.20.0.2,gateway=172.20.0.1 -- ip route show
	default via 172.20.0.1 dev lo 

	$ bst --ip 172.20.0.2/16,lo --route dst=10.0.0.0/8,gateway=172.20.0.1 -- ip route show
	10.0.0.0/8 via 172.20.0.1 dev lo 

	$ bst --ip 172.20.0.2/16,lo --route gateway=172.20.0.1 -- ip route show
	default via 172.20.0.1 dev lo 

	$ exp=$(bst --no-loopback-setup sh -c 'ip link set lo up && ip route add default dev lo scope link && ip route show' 2>&1)
	> act=$(bst --route dev=lo,scope=link -- ip route show 2>&1)
	> [ "$exp" = "$act" ] || echo -e "-$exp\n+$act"
