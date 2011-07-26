%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------

-define(ETH_TYPE_MIN,   16#600).
-define(ETH_TYPE_IP,   16#0800).
-define(ETH_TYPE_ARP,  16#0806).
-define(ETH_TYPE_VLAN, 16#8100).
-define(ETH_TYPE_IPV6, 16#86dd).
-define(ETH_TYPE_LACP, 16#8809).

-define(ETH_BROADCAST, <<255,255,255,255,255,255>>).

-record(ovs_msg, {
		  version = 1        :: integer(),
		  type               :: atom(),
		  xid                :: integer(),
		  msg                :: atom()
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
		  wildcards = 0              :: integer(),
		  in_port = 0                :: integer(),
		  dl_src = <<0,0,0,0,0,0>>   :: <<_:48>>,
		  dl_dst = <<0,0,0,0,0,0>>   :: <<_:48>>,
		  dl_vlan = 0                :: integer(),
		  dl_vlan_pcp = 0            :: integer(),
		  dl_type = 0                :: integer(),
		  nw_tos = 0                 :: integer(),
		  nw_proto = 0               :: atom()|integer(),
		  nw_src = <<0,0,0,0>>       :: <<_:32>>,
		  nw_dst = <<0,0,0,0>>       :: <<_:32>>,
		  tp_src = 0                 :: integer(),
		  tp_dst = 0                 :: integer()
		 }).

-record(ofp_flow_mod, {
		  match,
		  cookie,
		  command,
		  idle_timeout,
		  hard_timeout,
		  priority,
		  buffer_id,
		  out_port,
		  flags,
		  actions
		 }).

-record(ofp_action_output, {
		  port,
		  max_len
		 }).

-record(ofp_action_enqueue, {
		  port,
		  queue_id
		 }).

-record(ofp_action_vlan_vid, {
		  vlan_vid
		 }).

-record(ofp_action_vlan_pcp, {
		  vlan_pcp
		 }).

-record(ofp_action_strip_vlan, {}).

-record(ofp_action_dl_addr, {
		  type,
		  dl_addr
		 }).

-record(ofp_action_nw_addr, {
		  type,
		  nw_addr
		 }).

-record(ofp_action_nw_tos, {
		  nw_tos
		 }).

-record(ofp_action_tp_port, {
		  type,
		  tp_port
		 }).

-record(ofp_action_vendor_header, {
		  vendor,
		  msg
}).

-record(ofp_packet_out, {
		  buffer_id,
		  in_port,
		  actions,
		  data
}).

-record(ofp_flow_removed, {
		  match,
		  cookie,
		  priority,
		  reason,
		  duration,
		  idle_timeout,
		  packet_count,
		  byte_count
}).

-record(ofp_port_status, {
		  reason,
		  port
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

-record(nx_action_reg_load, {
		  value,
		  nbits,
		  dst,
		  ofs
}).

-record(nx_action_note, {
		  note
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
