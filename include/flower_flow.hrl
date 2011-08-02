-define(ETH_ADDR_LEN, 6).

-define(ARP_OP_REQUEST,          1).       %% request to resolve ha given pa
-define(ARP_OP_REPLY,            2).       %% response giving hardware address
-define(ARP_OP_REVREQUEST,       3).       %% request to resolve pa given ha
-define(ARP_OP_REVREPLY,         4).       %% response giving protocol address

-define(IP_DSCP_MASK, 16#fc).

-define(IP_DONT_FRAGMENT,  16#4000).
-define(IP_MORE_FRAGMENTS, 16#2000).
-define(IP_FRAG_OFF_MASK,  16#1fff).

-define(LLC_DSAP_SNAP, 16#aa).
-define(LLC_SSAP_SNAP, 16#aa).
-define(LLC_CNTL_SNAP, 3).
-define(SNAP_ORG_ETHERNET, 0,0,0).

%% The match fields for ICMP type and code use the transport source and
%% destination port fields, respectively. */
-define(ICMP_TYPE, tp_src).
-define(ICMP_CODE, tp_dst).

-record(flow, {
		  tun_id,
		  nw_src,
		  nw_dst,
		  in_port,
		  vlan_tci,
		  dl_type,
		  tp_src,
		  tp_dst,
		  dl_src,
		  dl_dst,
		  nw_proto,
		  nw_tos,
		  arp_sha,
		  arp_tha,
		  l2,
		  l3,
		  l4,
		  l7
		 }).
