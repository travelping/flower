%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------

-type ofp_flags() :: list(atom()).
-type ofp_port() :: 'in_port' | 'table' | 'normal' | 'flood' | 'all' | 'controller' | 'local' | 'none' | non_neg_integer().
-type ofp_command() :: 'hello' | 'error' | 'echo_request' | 'echo_reply' | 'vendor' | 'features_request' | 'features_reply' |
					   'get_config_request' | 'get_config_reply' | 'set_config' | 'packet_in' | 'flow_removed' | 'port_status' |
					   'packet_out' | 'flow_mod' | 'port_mod' | 'stats_request' | 'stats_reply' | 'barrier_request' |
					   'barrier_reply' | 'queue_get_config_request' | 'queue_get_config_reply'.
-type ofp_addr_type() :: 'src' | 'dst'.
-type ofp_reason() :: atom() | non_neg_integer().
-type ofp_duration() :: {non_neg_integer(),non_neg_integer()}.

-type nxm_reg() :: {'nxm_nx_reg' | 'nxm_nx_regw' , non_neg_integer()}.
-type nxm_header() :: 'nxm_of_in_port' | 'nxm_of_eth_dst' | 'nxm_of_eth_dst_w' |
					  'nxm_of_eth_src' | 'nxm_of_eth_type' | 'nxm_of_vlan_tci' |
					  'nxm_of_vlan_tci_w' | 'nxm_of_ip_tos' | 'nxm_of_ip_proto' |
					  'nxm_of_ip_src' | 'nxm_of_ip_src_w' | 'nxm_of_ip_dst' |
					  'nxm_of_ip_dst_w' | 'nxm_of_tcp_src' | 'nxm_of_tcp_dst' |
					  'nxm_of_udp_src' | 'nxm_of_udp_dst' | 'nxm_of_icmp_type' |
					  'nxm_of_icmp_code' | 'nxm_of_arp_op' | 'nxm_of_arp_spa' |
					  'nxm_of_arp_spa_w' | 'nxm_of_arp_tpa' | 'nxm_of_arp_tpa_w' |
					  'nxm_nx_tun_id' | 'nxm_nx_tun_id_w' | 'nxm_nx_arp_sha' |
					  'nxm_nx_arp_tha' | 'nxm_nx_ipv6_src' | 'nxm_nx_ipv6_src_w' |
					  'nxm_nx_ipv6_dst' | 'nxm_nx_ipv6_dst_w' | 'nxm_nx_icmpv6_type' |
					  'nxm_nx_icmpv6_code' | 'nxm_nx_nd_target' | 'nxm_nx_nd_sll' |
					  'nxm_nx_nd_tll' | nxm_reg().
-type nxt_action() :: 'nxast_snat__obsolete' | 'nxast_resubmit' | 'nxast_set_tunnel' |
					  'nxast_drop_spoofed_arp__obsolete' | 'nxast_set_queue' |
					  'nxast_pop_queue' | 'nxast_reg_move' | 'nxast_reg_load' |
					  'nxast_note' | 'nxast_set_tunnel64' | 'nxast_multipath' |
					  'nxast_autopath'.
-type of_vendor_ext() :: 'nxt_role_request' | 'nxt_role_reply' | 'nxt_set_flow_format' | 'nxt_flow_mod' | 'nxt_flow_removed' | 'nxt_flow_mod_table_id'.

-define(ETH_TYPE_NONE,   16#5ff).
-define(ETH_TYPE_MIN,    16#600).
-define(ETH_TYPE_IP,    16#0800).
-define(ETH_TYPE_ARP,   16#0806).
-define(ETH_TYPE_MOPRC, 16#6002).
-define(ETH_TYPE_VLAN,  16#8100).
-define(ETH_TYPE_IPV6,  16#86dd).
-define(ETH_TYPE_LACP,  16#8809).
-define(ETH_TYPE_LOOP,  16#9000).

-define(ETH_BROADCAST, <<255,255,255,255,255,255>>).

-record(ovs_msg, {
		  version = 1        :: non_neg_integer(),
		  type               :: atom() | non_neg_integer(),
		  xid                :: non_neg_integer(),
		  msg                :: term()
		 }).

-record(ofp_error, {
		  error,
		  data
		 }).

-record(ofp_switch_features, {
		  datapath_id,
		  n_buffers,
		  n_tables,
		  capabilities,
		  actions,
		  ports
		 }).

-record(ofp_phy_port, {
		  port_no,
		  hw_addr,
		  name,
		  config,
		  state,
		  curr,
		  advertised,
		  supported,
		  peer
		 }).

-record(ofp_packet_in, {
		  buffer_id,
		  total_len,
		  in_port,
		  reason,
		  data
		 }).

-record(ofp_switch_config, {
		  flags,
		  miss_send_len
		 }).

-record(ofp_match, {
		  wildcards = 0              :: non_neg_integer(),
		  in_port = none             :: ofp_port(),
		  dl_src = <<0,0,0,0,0,0>>   :: <<_:48>>,
		  dl_dst = <<0,0,0,0,0,0>>   :: <<_:48>>,
		  dl_vlan = 0                :: non_neg_integer(),
		  dl_vlan_pcp = 0            :: non_neg_integer(),
		  dl_type = 0                :: non_neg_integer(),
		  nw_tos = 0                 :: non_neg_integer(),
		  nw_proto = 0               :: atom() | non_neg_integer(),
		  nw_src = <<0,0,0,0>>       :: <<_:32>>,
		  nw_dst = <<0,0,0,0>>       :: <<_:32>>,
		  tp_src = 0                 :: non_neg_integer(),
		  tp_dst = 0                 :: non_neg_integer()
		 }).

-record(ofp_action_output, {
		  port = none                :: ofp_port(),
		  max_len                    :: non_neg_integer()
		 }).

-record(ofp_action_enqueue, {
		  port = none                :: ofp_port(),
		  queue_id = 0               :: non_neg_integer()
		 }).

-record(ofp_action_vlan_vid, {
		  vlan_vid = 0               :: non_neg_integer()
		 }).

-record(ofp_action_vlan_pcp, {
		  vlan_pcp = 0               :: non_neg_integer()
		 }).

-record(ofp_action_strip_vlan, {}).

-record(ofp_action_dl_addr, {
		  type = src                 :: ofp_addr_type(),
		  dl_addr = <<0,0,0,0,0,0>>  :: <<_:48>>
		 }).

-record(ofp_action_nw_addr, {
		  type = src                 :: ofp_addr_type(),
		  nw_addr = <<0,0,0,0>>      :: <<_:32>>
		 }).

-record(ofp_action_nw_tos, {
		  nw_tos = 0                 :: non_neg_integer()
		 }).

-record(ofp_action_tp_port, {
		  type = src                 :: ofp_addr_type(),
		  tp_port = 0                :: non_neg_integer()
		 }).

-record(ofp_action_vendor_header, {
		  vendor,
		  msg
}).

-type ofp_action() :: #ofp_action_output{} | #ofp_action_enqueue{} | #ofp_action_vlan_vid{} | #ofp_action_vlan_pcp{} |
					  #ofp_action_strip_vlan{} | #ofp_action_dl_addr{} | #ofp_action_nw_addr{} | #ofp_action_nw_tos{} |
					  #ofp_action_tp_port{} | #ofp_action_vendor_header{}.
-type ofp_actions() :: list(ofp_action() | binary()) | ofp_action() | binary().

-record(ofp_flow_mod, {
		  match                      :: binary() | #ofp_match{},
		  cookie                     :: non_neg_integer(),
		  command                    :: ofp_command(),
		  idle_timeout               :: non_neg_integer(),
		  hard_timeout               :: non_neg_integer(),
		  priority                   :: non_neg_integer(),
		  buffer_id                  :: non_neg_integer(),
		  out_port                   :: ofp_port(),
		  flags                      :: ofp_flags(),
		  actions                    :: ofp_actions()
		 }).

-record(ofp_packet_out, {
		  buffer_id                  :: non_neg_integer(),
		  in_port                    :: ofp_port(),
		  actions                    :: ofp_actions(),
		  data
}).

-record(ofp_flow_removed, {
		  match                      :: binary() | #ofp_match{},
		  cookie                     :: non_neg_integer(),
		  priority                   :: non_neg_integer(),
		  reason                     :: ofp_reason(),
		  duration,
		  idle_timeout               :: non_neg_integer(),
		  packet_count               :: non_neg_integer(),
		  byte_count                 :: non_neg_integer()
}).

-record(ofp_port_status, {
		  reason                     :: ofp_reason(),
		  port                       :: #ofp_phy_port{}
}).


%% Nicira extensions

-record(nxt_flow_mod_table_id, {
		  set
}).

-record(nxt_role_request, {
		  role
}).


-record(nx_flow_mod, {
		  cookie,
		  command,
		  idle_timeout,
		  hard_timeout,
		  priority,
		  buffer_id,
		  out_port,
		  flags,
		  nx_match,
		  actions
}).

-record(nx_action_resubmit, {
		  in_port
}).

-record(nx_action_set_tunnel, {
		  tun_id
}).

-record(nx_action_set_tunnel64, {
		  tun_id
}).

-record(nx_action_set_queue, {
		  queue_id
}).

-record(nx_action_pop_queue, {
}).

-record(nx_action_reg_move, {
		  n_bits,
		  src_ofs,
		  dst_ofs,
		  src,
		  dst
}).

%% -record(nx_action_reg_load, {
%% 		  value = 0               :: binary(),
%% 		  nbits = 0               :: non_neg_integer(),
%% 		  dst = nxm_of_in_port    :: nxm_header(),
%% 		  ofs = 0                 :: non_neg_integer()
%% }).
-record(nx_action_reg_load, {
		  value   :: binary(),
		  nbits   :: non_neg_integer(),
		  dst     :: nxm_header(),
		  ofs     :: non_neg_integer()
}).

-record(nx_action_note, {
		  note    :: list() | binary()
}).

-record(nx_action_multipath, {
		  fields,
		  basis,
		  algorithm,
		  max_link,
		  arg,
		  ofs,
		  nbits,
		  dst
}).

-record(nx_action_autopath, {
		  ofs,
		  nbits,
		  dst,
		  id
}).

%% Read State Messages

-record(ofp_desc_stats_request, {}).

-record(ofp_desc_stats, {
		  mfr_desc		:: binary(),					%% Manufacturer description.
		  hw_desc		:: binary(),					%% Hardware description.
		  sw_desc		:: binary(),					%% Software description.
		  serial_num	:: binary(),					%% Serial number.
		  dp_desc		:: binary()						%% Human readable description of datapath.
}).

-record(ofp_flow_stats_request, {
		  match		:: binary() | #ofp_match{},			%% Fields to match.
		  table_id	:: non_neg_integer() | 'all' | 'emergency',
														%% ID of table to read (from ofp_table_stats),
														%% 0xff for all tables or 0xfe for emergency.
		  out_port	:: non_neg_integer() | 'none'		%% Require matching entries to include this
														%% as an output port. A value of OFPP_NONE
														%% indicates no restriction.
}).

-record(ofp_flow_stats, {
		  table_id		:: non_neg_integer(),			%% ID of table flow came from.
		  match			:: binary() | #ofp_match{},		%% Description of fields.
		  duration		:: ofp_duration(),				%% Time flow has been alive in {seconds, nanoseconds}
		  priority		:: non_neg_integer(),			%% Priority of the entry. Only meaningful
														%% when this is not an exact-match entry.
		  idle_timeout	:: non_neg_integer(),			%% Number of seconds idle before expiration.
		  hard_timeout	:: non_neg_integer(),			%% Number of seconds before expiration.
		  cookie		:: non_neg_integer(),			%% Opaque controller-issued identifier.
		  packet_count	:: non_neg_integer(),			%% Number of packets in flow.
		  byte_count	:: non_neg_integer(),			%% Number of bytes in flow.
		  actions		:: ofp_actions()				%% Actions.
}).

-record(ofp_aggregate_stats_request, {
		  match		:: binary() | #ofp_match{},			%% Fields to match.
		  table_id	:: non_neg_integer() | 'all' | 'emergency',
														%% ID of table to read (from ofp_table_stats)
														%% 0xff for all tables or 0xfe for emergency.
		  out_port	:: non_neg_integer() | 'none'		%% Require matching entries to include this
														%% as an output port. A value of OFPP_NONE
														%% indicates no restriction.
}).

-record(ofp_aggregate_stats_reply, {
		  packet_count	:: non_neg_integer(),			%% Number of packets in flows.
		  byte_count	:: non_neg_integer(),			%% Number of bytes in flows.
		  flow_count	:: non_neg_integer()			%% Number of flows.
}).

-record(ofp_table_stats_request, {}).
-record(ofp_table_stats, {
		  table_id		:: non_neg_integer(),			%% Identifier of table. Lower numbered tables
														%% are consulted first.
		  name			:: binary(),
		  wildcards		:: non_neg_integer(),			%% Bitmap of OFPFW_* wildcards that are
														%% supported by the table.
		  max_entries	:: non_neg_integer(),			%% Max number of entries supported. */
		  active_count	:: non_neg_integer(),			%% Number of active entries. */
		  lookup_count	:: non_neg_integer(),			%% Number of packets looked up in table. */
		  matched_count	:: non_neg_integer()			%% Number of packets that hit table. */
}).

-record(ofp_port_stats_request, {
		  port_no	:: non_neg_integer() | 'none'		%% OFPST_PORT message must request statistics
														%% either for a single port (specified in
														%% port_no) or for all ports (if port_no ==
														%% OFPP_NONE).
}).

-record(ofp_port_stats, {
		  port_no		:: non_neg_integer(),
		  rx_packets	:: non_neg_integer(),			%% Number of received packets.
		  tx_packets	:: non_neg_integer(),			%% Number of transmitted packets.
		  rx_bytes		:: non_neg_integer(),			%% Number of received bytes.
		  tx_bytes		:: non_neg_integer(),			%% Number of transmitted bytes.
		  rx_dropped	:: non_neg_integer(),			%% Number of packets dropped by RX.
		  tx_dropped	:: non_neg_integer(),			%% Number of packets dropped by TX.
		  rx_errors		:: non_neg_integer(),			%% Number of receive errors. This is a super-set
														%% of more specific receive errors and should be
														%% greater than or equal to the sum of all
														%% rx_*_err values.
		  tx_errors		:: non_neg_integer(),			%% Number of transmit errors. This is a super-set
														%% of more specific transmit errors and should be
														%% greater than or equal to the sum of all
														%% tx_*_err values (none currently defined.)
		  rx_frame_err	:: non_neg_integer(),			%% Number of frame alignment errors.
		  rx_over_err	:: non_neg_integer(),			%% Number of packets with RX overrun.
		  rx_crc_err	:: non_neg_integer(),			%% Number of CRC errors.
		  collisions	:: non_neg_integer()			%% Number of collisions.
}).

-record(ofp_queue_stats_request, {
		  port_no	:: non_neg_integer() | 'all',		%% All ports if OFPT_ALL.
		  queue_id	:: non_neg_integer() | 'all'		%% All queues if OFPQ_ALL.
}).

-record(ofp_queue_stats, {
		  port_no		:: non_neg_integer(),
		  queue_id		:: non_neg_integer(),			%% Queue i.d
		  tx_bytes		:: non_neg_integer(),			%% Number of transmitted bytes.
		  tx_packets	:: non_neg_integer(),			%% Number of transmitted packets.
		  tx_errors		:: non_neg_integer()			%% Number of packets dropped due to overrun.
}).
