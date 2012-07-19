%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------

-type uint8() :: 0..16#ff.
-type uint16() :: 0..16#ffff.
-type uint32() :: 0..16#ffffffff.
-type uint64() :: 0..16#ffffffffffffffff.

-type ofp_flags() :: 'send_flow_rem' | 'check_overlap' | 'emerg'.
-type ofp_error_type() :: 'hello_failed' | 'bad_request' | 'bad_action' | 'flow_mod_failed' |
			  'port_mod_failed' | 'queue_op_failed'.
-type ofp_error_hello_failed_types() :: 'incompatible' | 'eperm'.
-type ofp_error_bad_request_types() :: 'bad_version' | 'bad_type' | 'bad_stat' |
				       'bad_vendor' | 'bad_subtype' | 'eperm' |
				       'bad_len' | 'buffer_empty' | 'buffer_unknown'.
-type ofp_error_bad_action_types() :: 'bad_type' | 'bad_len' | 'bad_vendor' |
				      'bad_vendor_type' | 'bad_out_port' |
				      'bad_argument' | 'eperm' | 'too_many' |
				      'bad_queue'.
-type ofp_error_flow_mod_failed_types() :: 'all_tables_full' | 'overlap' | 'eperm' |
					   'bad_emerg_timeout ' | 'bad_command' |
					   'unsupported'.
-type ofp_error_port_mod_failed_types() :: 'bad_port' | 'bad_hw_addr'.
-type ofp_error_queue_op_failed_types() :: 'bad_port' | 'bad_queue' | 'eperm'.
-type ofp_error() :: {'hello_failed', ofp_error_hello_failed_types()} |
		     {'bad_request', ofp_error_bad_request_types()} |
		     {'bad_action', ofp_error_bad_action_types()} |
		     {'flow_mod_failed', ofp_error_flow_mod_failed_types()} |
		     {'port_mod_failed', ofp_error_port_mod_failed_types()} |
		     {'queue_op_failed', ofp_error_queue_op_failed_types()}.

-type ofp_port_number() :: 0..16#ffffff00.
-type ofp_port_name() :: 'in_port' | 'table' | 'normal' | 'flood' | 'all' | 'controller' | 'local' | 'none'.
-type ofp_port() :: ofp_port_name() | ofp_port_number().
-type ofp_group() :: 0..16#ffffffff.
-type ofp_command() :: 'hello' | 'error' | 'echo_request' | 'echo_reply' | 'vendor' | 'features_request' | 'features_reply' |
		       'get_config_request' | 'get_config_reply' | 'set_config' | 'packet_in' | 'flow_removed' | 'port_status' |
		       'packet_out' | 'flow_mod' | 'port_mod' | 'stats_request' | 'stats_reply' | 'barrier_request' |
		       'barrier_reply' | 'queue_get_config_request' | 'queue_get_config_reply'.
-type ofp_addr_type() :: 'src' | 'dst'.
-type ofp_reason() :: atom() | non_neg_integer().
-type ofp_duration() :: {non_neg_integer(),non_neg_integer()}.

-type ofp_capabilities() :: 'flow_stats' | 'table_stats' | 'port_stats' | 'stp' | 'reserved' | 'ip_reasm' | 'queue_stats' | 'arp_match_ip'.
-type ofp_action_type() :: 'output' | 'set_vlan_vid' | 'set_vlan_pcp' | 'strip_vlan' | 'set_dl_src' | 'set_dl_dst' |
			   'set_nw_src' | 'set_nw_dst' | 'set_nw_tos' | 'set_tp_src' | 'set_tp_dst' | 'enqueue'.
-type ofp_port_config() :: 'port_down' | 'no_stp' | 'no_recv' | 'no_recv_stp' | 'no_flood' | 'no_fwd' | 'no_packet_in'.
-type ofp_port_state() :: 'link_down' | 'stp_listen' | 'stp_learn' | 'stp_forward' | 'stp_block'.
-type ofp_port_features() :: '10mb_hd' | '10mb_fd' | '100mb_hd' | '100mb_fd' | '1gb_hd' | '1gb_fd' | '10gb_fd'
			   | 'copper' | 'fiber' | 'autoneg' | 'pause' | 'pause_asym'.
-type ofp_config_flags() :: 'frag_normal' | 'frag_drop' | 'frag_reasm' | 'frag_mask'.
-type ofp_packet_in_reason() ::'no_match' | 'action'.
-type ofp_match_type() :: 'standard'.
-type ofp_instruction_type() :: 'goto_table' | 'write_metadata' | 'write_actions' | 'apply_actions' | 'clear_actions' | 'experimenter'.
-type ofp_table_id() :: non_neg_integer().
-type ofp_table_config() :: 'miss_controller' | 'miss_continue' | 'miss_drop'.
-type ofp_group_mod_command() :: 'add' | 'modify' | 'delete'.
-type ofp_group_type() :: 'all' | 'select' | 'indirect' | 'ff'.

-type nxm_reg() :: {'nxm_nx_reg' | 'nxm_nx_reg_w' , non_neg_integer()}.
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
-type nx_match() :: [{nxm_header(), term()}].
-type of_vendor_ext() :: 'nxt_role_request' | 'nxt_role_reply' | 'nxt_set_flow_format' | 'nxt_flow_mod' | 'nxt_flow_removed' | 'nxt_flow_mod_table_id'.

-define(ETH_TYPE_NONE,   16#5ff).
-define(ETH_TYPE_MIN,    16#600).
-define(ETH_TYPE_IP,    16#0800).
-define(ETH_TYPE_ARP,   16#0806).
-define(ETH_TYPE_MOPRC, 16#6002).
-define(ETH_TYPE_RARP,  16#8035).
-define(ETH_TYPE_VLAN,  16#8100).
-define(ETH_TYPE_IPV6,  16#86dd).
-define(ETH_TYPE_LACP,  16#8809).
-define(ETH_TYPE_LOOP,  16#9000).

-define(ETH_BROADCAST, <<255,255,255,255,255,255>>).

-record(ovs_msg, {
	  version = 1	:: non_neg_integer(),
	  type		:: atom() | non_neg_integer(),
	  xid		:: non_neg_integer(),
	  msg		:: term()
}).

%% OFPT_ERROR: Error message (datapath -> controller).
-record(ofp_error, {
	  error		:: ofp_error(),				%% Error Type and Code.
	  data		:: binary()				%% Variable-length data. Interpreted based
								%% on the type and code.
}).

%% Description of a physical port
-record(ofp_phy_port, {
	  port_no = none	:: ofp_port(),			%% A value the datapath associates with a physical port.
	  hw_addr = <<0:48>>	:: <<_:48>>,			%% Typically The MAC address for the port
	  name = <<>>		:: binary(),			%% Human-readable name for the interface.
	  config = []		:: [ofp_port_config()],		%% Flags to indicate behavior of the physical port.
	  state = []		:: [ofp_port_state()],		%% Current state of the physical port.
	  curr = []		:: [ofp_port_features()],	%% Current features.
	  advertised = []	:: [ofp_port_features()],	%% Features being advertised by the port.
	  supported = []	:: [ofp_port_features()],	%% Features supported by the port.
	  peer = []		:: [ofp_port_features()],	%% Features advertised by peer.
	  curr_speed = 0	:: integer(),			%% Current port bitrate in kbps. (OF 1.1)
	  max_speed = 0		:: integer()			%% Max port bitrate in kbps. (OF 1.1)
}).

%% Switch features
-record(ofp_switch_features, {
	  datapath_id = 0	:: non_neg_integer(),		%% Datapath unique ID. The lower 48-bits are for
								%% a MAC address, while the upper 16-bits are
								%% implementer-defined.

	  n_buffers = 0		:: non_neg_integer(),		%% Max packets buffered at once.
	  n_tables = 0		:: non_neg_integer(),		%% Number of tables supported by datapath.

								%% Features:
	  capabilities = []	:: [ofp_capabilities()],	%%   List of supported "ofp_capabilities".
	  actions = []		:: [ofp_action_type()],		%%   List of supported "ofp_action_type"s.

								%% Port info:
	  ports = []		:: [#ofp_phy_port{}]		%%   List of Port definitions. 
}).

%% Packet received on port (datapath -> controller).
-record(ofp_packet_in, {
	  buffer_id = 0		:: non_neg_integer(),		%% ID assigned by datapath.
	  total_len = 0		:: non_neg_integer(),		%% Full length of frame.
	  in_port = none	:: ofp_port(),			%% Port on which frame was received.
	  reason		:: ofp_packet_in_reason(),	%% Reason packet is being sent
	  data = <<>>		:: binary()			%% Ethernet frame, halfway through 32-bit word,
								%% so the IP header is 32-bit aligned.
}).

%% Packet received on port (datapath -> controller).
-record(ofp_packet_in_v11, {
	  buffer_id = 0		:: non_neg_integer(),		%% ID assigned by datapath.
	  in_port = none	:: ofp_port(),			%% Port on which frame was received.
	  in_phy_port = none	:: ofp_port(),			%% Physical Port on which frame was received.
	  total_len = 0		:: non_neg_integer(),		%% Full length of frame.
	  reason		:: ofp_packet_in_reason(),	%% Reason packet is being sent
	  table_id = 0		:: non_neg_integer(),		%% ID of the table that was looked up
	  data = <<>>		:: binary()			%% Ethernet frame, halfway through 32-bit word,
								%% so the IP header is 32-bit aligned.
}).

%% Switch configuration.
-record(ofp_switch_config, {
	  flags = frag_normal		:: ofp_config_flags(),		%% The configuration flags
	  miss_send_len = 0		:: non_neg_integer()		%% Max bytes of new flow that datapath should
									%% send to the controller.
}).

%% Fields to match against flows
-record(ofp_match, {
	  wildcards = 0				:: non_neg_integer(),		%% Wildcard fields.
	  in_port = none			:: ofp_port(),			%% Input switch port.
	  dl_src = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet source address.
	  dl_dst = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet destination address.
	  dl_vlan = 0				:: non_neg_integer(),		%% Input VLAN id.
	  dl_vlan_pcp = 0			:: non_neg_integer(),		%% Input VLAN priority.
	  dl_type = 0				:: non_neg_integer(),		%% Ethernet frame type.
	  nw_tos = 0				:: non_neg_integer(),		%% IP ToS (actually DSCP field, 6 bits).
	  nw_proto = 0				:: atom() | non_neg_integer(),	%% IP protocol or lower 8 bits of ARP opcode.
	  nw_src = <<0,0,0,0>>			:: <<_:32>>,			%% IP source address.
	  nw_dst = <<0,0,0,0>>			:: <<_:32>>,			%% IP destination address.
	  tp_src = 0				:: non_neg_integer(),		%% TCP/UDP source port.
	  tp_dst = 0				:: non_neg_integer()		%% TCP/UDP destination port.
}).

%% OF 1.1 Fields to match against flows
-record(ofp_match_standard, {
	  in_port = none			:: ofp_port(),			%% Input switch port.
	  wildcards = 0				:: non_neg_integer(),		%% Wildcard fields.
	  dl_src = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet source address.
	  dl_src_mask = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet source address mask. (OF 1.1)
	  dl_dst = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet destination address.
	  dl_dst_mask = <<0,0,0,0,0,0>>		:: <<_:48>>,			%% Ethernet destination address mask. (OF 1.1)
	  dl_vlan = 0				:: non_neg_integer(),		%% Input VLAN id.
	  dl_vlan_pcp = 0			:: non_neg_integer(),		%% Input VLAN priority.
	  dl_type = 0				:: non_neg_integer(),		%% Ethernet frame type.
	  nw_tos = 0				:: non_neg_integer(),		%% IP ToS (actually DSCP field, 6 bits).
	  nw_proto = 0				:: atom() | non_neg_integer(),	%% IP protocol or lower 8 bits of ARP opcode.
	  nw_src = <<0,0,0,0>>			:: <<_:32>>,			%% IP source address.
	  nw_src_mask = <<0,0,0,0>>		:: <<_:32>>,			%% IP source address mask. (OF 1.1)
	  nw_dst = <<0,0,0,0>>			:: <<_:32>>,			%% IP destination address.
	  nw_dst_mask = <<0,0,0,0>>		:: <<_:32>>,			%% IP destination address mask. (OF 1.1)
	  tp_src = 0				:: non_neg_integer(),		%% TCP/UDP source port.
	  tp_dst = 0				:: non_neg_integer(),		%% TCP/UDP destination port.
	  mpls_label = 0			:: non_neg_integer(),		%% MPLS label. (OF 1.1)
	  mpls_tc = 0				:: non_neg_integer(),		%% MPLS TC. (OF 1.1)
	  metadata = <<0,0,0,0,0,0,0,0>>	:: <<_:64>>,			%% Metadata passed between tables. (OF 1.1)
	  metadata_mask = <<0,0,0,0,0,0,0,0>>	:: <<_:64>>			%% Mask for metadata. (OF 1.1)
}).

%% Output to switch port.
-record(ofp_action_output, {
	  port = none		:: ofp_port(),			%% Output port.
	  max_len = 0		:: non_neg_integer()		%% Max length to send to controller.
}).

%% Output to queue.
-record(ofp_action_enqueue, {
	  port = none		:: ofp_port(),			%% Port that queue belongs. Should refer to a valid physical port
	  queue_id = 0		:: non_neg_integer()		%% Where to enqueue the packets.
}).

%% Set the 802.1q VLAN id.
-record(ofp_action_vlan_vid, {
	  vlan_vid = 0		:: non_neg_integer()		%% VLAN id.
}).

%% Set the 802.1q priority.
-record(ofp_action_vlan_pcp, {
	  vlan_pcp = 0		:: non_neg_integer()		%% VLAN priority.
}).

%% Strip the 802.1q header.
-record(ofp_action_strip_vlan, {}).

%% Set the Ethernet source or destination address.
-record(ofp_action_dl_addr, {
	  type = src			:: ofp_addr_type(),	%% Source or destination.
	  dl_addr = <<0,0,0,0,0,0>>	:: <<_:48>>		%% Ethernet address.
}).

%% Set the IP source or destination address.
-record(ofp_action_nw_addr, {
	  type = src			:: ofp_addr_type(),	%% Source or destination.
	  nw_addr = <<0,0,0,0>>		:: <<_:32>>		%% IP address.
}).

%% Set the IP ToS (DSCP field, 6 bits).
-record(ofp_action_nw_tos, {
	  nw_tos = 0		:: non_neg_integer()		%% Source or destination
}).

%% Set the TCP/UDP source or destination port.
-record(ofp_action_tp_port, {
	  type = src		:: ofp_addr_type(),		%% Source or destination.
	  tp_port = 0		:: non_neg_integer()		%% TCP/UDP port
}).

%% IP ECN (2 bits).
-record(ofp_action_set_nw_ecn, {
	  ecn = 0		:: non_neg_integer()		%% IP ECN (2 bits).
}).

%% Copy TTL "outwards" -- from next-to-outermost to outermost
-record(ofp_action_copy_ttl_out, {}).

%% Copy TTL "inwards" -- from outermost to next-to-outermost
-record(ofp_action_copy_ttl_in, {}).

%% set MPLS label
-record(ofp_action_set_mpls_label, {
	  label = 0			:: non_neg_integer()	%% MPLS Label
 }).

%% set MPLS TC
-record(ofp_action_set_mpls_tc, {
	  tc = 0			:: non_neg_integer()	%% MPLS TC
 }).

%% set MPLS TTL
-record(ofp_action_set_mpls_ttl, {
	  ttl = 0			:: non_neg_integer()	%% MPLS TTL
 }).

%% Decrement MPLS TTL
-record(ofp_action_dec_mpls_ttl, {}).

%% Push a new VLAN tag
-record(ofp_action_push_vlan, {
	  ethertype = 0			:: non_neg_integer()	%% Ethertype
 }).

%% Pop the outer VLAN tag
-record(ofp_action_pop_vlan, {}).

%% Push a new MPLS tag
-record(ofp_action_push_mpls, {
	  ethertype = 0			:: non_neg_integer()	%% Ethertype
 }).

%% Pop the outer MPLS tag
-record(ofp_action_pop_mpls, {
	  ethertype = 0			:: non_neg_integer()	%% Ethertype
 }).

%% Set queue id when outputting to a port
-record(ofp_action_set_queue, {
	  queue_id = 0			:: non_neg_integer()	%% QueueID
 }).

%% Apply group.
-record(ofp_action_group, {
	  group_id = 0			:: non_neg_integer()	%% GroupID
 }).

%% IP TTL.
-record(ofp_action_set_nw_ttl, {
	  ttl = 0			:: non_neg_integer()	%% NW TTL
 }).

%% Decrement IP TTL.
-record(ofp_action_dec_nw_ttl, {}).

%% Vendor action
-record(ofp_action_vendor, {
	  vendor,						%% Vendor ID
	  msg							%% Vendor message
}).

%% Experimenter action
-record(ofp_action_experimenter, {
	  experimenter,						%% Experimenter ID
	  msg							%% Experimenter message
}).

-type ofp_action() :: #ofp_action_output{} | #ofp_action_enqueue{} | #ofp_action_vlan_vid{} | #ofp_action_vlan_pcp{} |
		      #ofp_action_strip_vlan{} | #ofp_action_dl_addr{} | #ofp_action_nw_addr{} | #ofp_action_nw_tos{} |
		      #ofp_action_tp_port{} | #ofp_action_vendor{}.
-type ofp_actions() :: [ofp_action() | binary()] | ofp_action() | binary().
-type ofp_action_v11() :: #ofp_action_output{} | #ofp_action_vlan_vid{} | #ofp_action_vlan_pcp{} | #ofp_action_strip_vlan{} |
			  #ofp_action_dl_addr{} | #ofp_action_nw_addr{} | #ofp_action_nw_tos{} | #ofp_action_set_nw_ecn{} |
			  #ofp_action_tp_port{} | #ofp_action_copy_ttl_out{} | #ofp_action_copy_ttl_in{} |
			  #ofp_action_set_mpls_label{} | #ofp_action_set_mpls_tc{} | #ofp_action_set_mpls_ttl{} |
			  #ofp_action_dec_mpls_ttl{} | #ofp_action_push_vlan{} | #ofp_action_pop_vlan{} |
			  #ofp_action_push_mpls{} | #ofp_action_pop_mpls{} | #ofp_action_set_queue{} |
			  #ofp_action_group{} | #ofp_action_set_nw_ttl{} | #ofp_action_dec_nw_ttl{} |
			  #ofp_action_experimenter{}.
-type ofp_actions_v11() :: [ofp_action_v11() | binary()] | ofp_action_v11() | binary().

%% Setup the next table in the lookup pipeline
-record(ofp_instruction_goto_table, {
	  table_id = 0		:: ofp_table_id()		%% Set next table in the lookup pipeline
}).

%% Setup the metadata field for use later in pipeline
-record(ofp_instruction_write_metadata, {
	  metadata = <<0,0,0,0,0,0,0,0>>	:: <<_:64>>,			%% Metadata value to write
	  metadata_mask = <<0,0,0,0,0,0,0,0>>	:: <<_:64>>			%% Metadata write bitmask
}).

%% Instruction structure for OFPIT_WRITE/APPLY/CLEAR_ACTIONS
-record(ofp_instruction_actions, {
	  type :: 'write_actions' | 'apply_actions' | 'clear_actions',		%% One of OFPIT_*_ACTIONS
	  actions = [] :: ofp_actions_v11()					%% Actions associated with
										%% OFPIT_WRITE_ACTIONS and
										%% OFPIT_APPLY_ACTIONS
}).

-type ofp_instruction() :: #ofp_instruction_goto_table{} | #ofp_instruction_write_metadata{} | #ofp_instruction_actions{}.
-type ofp_instructions() :: [ofp_instruction() | binary()] | ofp_instruction() | binary().

%% Flow setup and teardown (controller -> datapath).
-record(ofp_flow_mod, {
          match                 :: binary() | #ofp_match{},     %% Fields to match
          cookie = 0            :: non_neg_integer(),           %% Opaque controller-issued identifier.
          command               :: ofp_command(),               %% Flow actions.
          idle_timeout = 0      :: non_neg_integer(),           %% Idle time before discarding (seconds).
          hard_timeout = 0      :: non_neg_integer(),           %% Max time before discarding (seconds).
          priority = 0          :: non_neg_integer(),           %% Priority level of flow entry.
          buffer_id = -1        :: integer(),                   %% Buffered packet to apply to (or -1).
                                                                %% Not meaningful for OFPFC_DELETE*.
          out_port = none       :: ofp_port(),                  %% For OFPFC_DELETE* commands, require
                                                                %% matching entries to include this as an
                                                                %% output port. A value of OFPP_NONE
                                                                %% indicates no restriction.
          flags = []            :: [ofp_flags()],               %% Flags
          actions = []          :: ofp_actions()                %% List of actions
}).

-record(ofp_flow_mod_v11, {
	  cookie = 0		:: non_neg_integer(),		%% Opaque controller-issued identifier.
	  cookie_mask = 0	:: non_neg_integer(),		%% Mask used to restrict the cookie bits
								%% that must match when the command is
								%% OFPFC_MODIFY* or OFPFC_DELETE*. A value
								%% of 0 indicates no restriction.
	  table_id		:: ofp_table_id(),		%% ID of the table to put the flow in
	  command		:: ofp_command(),		%% Flow actions.
	  idle_timeout = 0	:: non_neg_integer(),		%% Idle time before discarding (seconds).
	  hard_timeout = 0	:: non_neg_integer(),		%% Max time before discarding (seconds).
	  priority = 0		:: non_neg_integer(),		%% Priority level of flow entry.
	  buffer_id = -1	:: integer(),			%% Buffered packet to apply to (or -1).
								%% Not meaningful for OFPFC_DELETE*.
	  out_port = none	:: ofp_port(),			%% For OFPFC_DELETE* commands, require
								%% matching entries to include this as an
								%% output port. A value of OFPP_ANY
								%% indicates no restriction.
	  out_group = 0		:: ofp_group(),			%% For OFPFC_DELETE* commands, require
								%% matching entries to include this as an
								%% output group. A value of OFPG_ANY
								%% indicates no restriction.
	  flags	= []		:: [ofp_flags()],		%% Flags
	  match			:: binary() | #ofp_match{},	%% Fields to match
	  instructions = []	:: ofp_instructions()		%% List of instructions
}).

%% Bucket for use in groups.
-record(ofp_bucket, {
	weight = 0		:: uint16(),			%% Relative weight of bucket. Only
								%% defined for select groups.
	watch_port = none	:: ofp_port(),			%% Port whose state affects whether this
								%% bucket is live. Only required for fast
								%% failover groups.
	watch_group = 0		:: uint32(),			%% Group whose state affects whether this
								%% bucket is live. Only required for fast
								%% failover groups.
	actions = []		:: ofp_actions()		%% The action length is inferred
								%% from the length field in the
								%% header.
}).

-type ofp_buckets() :: [#ofp_bucket{}].

%% Group setup and teardown (controller -> datapath).
-record(ofp_group_mod, {
	command			:: ofp_group_mod_command(),	%% One of OFPGC_*.
	type			:: ofp_group_type(),		%% One of OFPGT_*.
	group_id = 0		:: uint32(),			%% Group identifier.
	buckets = []		:: ofp_buckets()		%% The bucket length is inferred from the
								%% length field in the header.
}).

%% Modify behavior of the physical port
-record(ofp_port_mod, {
	  port_no = none	:: ofp_port(),			%% A value the datapath associates with a physical port.
	  hw_addr = <<0:48>>	:: <<_:48>>,			%% The hardware address is not
								%% configurable. This is used to
								%% sanity-check the request, so it must
								%% be the same as returned in an
								%% ofp_phy_port record.
	  config = []		:: [ofp_port_config()],		%% List of "ofp_port_config" to set.
	  mask = []		:: [ofp_port_config()],		%% List of "ofp_port_config" flags to be changed.
	  advertise = []	:: [ofp_port_features()]	%% List of "ofp_port_features"s. Leave empty
								%% to prevent any action taking place.
}).

%% Configure/Modify behavior of a flow table
-record(ofp_table_mod, {
	  table_id :: integer(),				%% ID of the table, 0xFF indicates all tables
	  config = [] :: [ofp_table_config()]			%% Bitmap of OFPTC_* flags
}).

%% Min-Rate queue property description.
-record(ofp_queue_prop_min_rate, {
	  rate = 0		:: non_neg_integer()		%% In 1/10 of a percent; >1000 -> disabled.
}).

%% Full description for a queue.
-record(ofp_packet_queue, {
	  queue_id = 0		:: non_neg_integer(),		%% Id for the specific queue.
	  properties = []	:: [ofp_queue_prop()]		%% List of properties.
}).

-type ofp_queue_prop() :: #ofp_queue_prop_min_rate{}.

%% Query for port queue configuration
-record(ofp_queue_get_config_request, {
	  port = none	:: ofp_port()				%% Port to be queried. Should refer
								%% to a valid physical port (i.e. < OFPP_MAX)
}).

%% Queue configuration for a given port.
-record(ofp_queue_get_config_reply, {
	  port = none	:: ofp_port(),				%% Port that had be queried.
	  queues = []	:: [#ofp_packet_queue{}]		%% List of configured queues.
}).

%% Send packet (controller -> datapath).
-record(ofp_packet_out, {
	  buffer_id = -1	:: non_neg_integer(),		%% ID assigned by datapath (-1 if none).
	  in_port = none	:: ofp_port(),			%% Packet's input port
	  actions = []		:: ofp_actions(),		%% Actions.
	  data = <<>>		:: binary()			%% Packet data.
}).

%% Flow removed (datapath -> controller).
-record(ofp_flow_removed, {
	  match			:: binary() | #ofp_match{},	%% Description of fields.
	  cookie = 0		:: non_neg_integer(),		%% Opaque controller-issued identifier.
	  priority = 0		:: non_neg_integer(),		%% Priority level of flow entry.
	  reason		:: ofp_reason(),		%% Reason
	  duration		:: ofp_duration(),		%% Time flow was alive in seconds,nanoseconds.
	  idle_timeout		:: non_neg_integer(),		%% Idle timeout from original flow mod.
	  packet_count		:: non_neg_integer(),
	  byte_count		:: non_neg_integer()
}).

%% Flow removed (datapath -> controller).
-record(ofp_flow_removed_v11, {
	  cookie = 0		:: non_neg_integer(),		%% Opaque controller-issued identifier.
	  priority = 0		:: non_neg_integer(),		%% Priority level of flow entry.
	  reason		:: ofp_reason(),		%% Reason
	  table_id		:: uint8(),			%% ID of the table
	  duration		:: ofp_duration(),		%% Time flow was alive in seconds,nanoseconds.
	  idle_timeout		:: non_neg_integer(),		%% Idle timeout from original flow mod.
	  packet_count		:: non_neg_integer(),
	  byte_count		:: non_neg_integer(),
	  match			:: binary() | #ofp_match{}	%% Description of fields.
}).

%% A physical port has changed in the datapath
-record(ofp_port_status, {
	  reason		:: ofp_reason(),		%% Reason
	  port			:: #ofp_phy_port{}		%% Description of a physical port
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
	  nx_match	:: nx_match(),
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
%% 		  value = 0		:: binary(),
%% 		  nbits = 0		:: non_neg_integer(),
%% 		  dst = nxm_of_in_port	:: nxm_header(),
%% 		  ofs = 0			:: non_neg_integer()
%% }).
-record(nx_action_reg_load, {
	  value		:: binary(),
	  nbits		:: non_neg_integer(),
	  dst		:: nxm_header() | binary(),
	  ofs		:: non_neg_integer()
}).

-record(nx_action_note, {
	  note	:: list() | binary()
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

%% Request description of this OpenFlow switch.
-record(ofp_desc_stats_request, {}).

%% Description of this OpenFlow switch.
-record(ofp_desc_stats, {
	  mfr_desc	:: binary(),				%% Manufacturer description.
	  hw_desc	:: binary(),				%% Hardware description.
	  sw_desc	:: binary(),				%% Software description.
	  serial_num	:: binary(),				%% Serial number.
	  dp_desc	:: binary()				%% Human readable description of datapath.
	 }).

%% Request individual flow statistics.
-record(ofp_flow_stats_request, {
	  match		:: binary() | #ofp_match{},		%% Fields to match.
	  table_id	:: non_neg_integer() | 'all' | 'emergency',
								%% ID of table to read (from ofp_table_stats),
								%% 0xff for all tables or 0xfe for emergency.
	  out_port	:: ofp_port()				%% Require matching entries to include this
								%% as an output port. A value of OFPP_NONE
								%% indicates no restriction.
}).

%% Request individual flow statistics.
-record(ofp_flow_stats_request_v11, {
	  table_id	:: non_neg_integer() | 'all' | 'emergency',
								%% ID of table to read (from ofp_table_stats),
								%% 0xff for all tables or 0xfe for emergency.
	  out_port	:: ofp_port(),				%% Require matching entries to include this
								%% as an output port. A value of OFPP_ANY
								%% indicates no restriction.
	  out_group	:: uint32(),				%% Require matching entries to include this
								%% as an output group. A value of OFPG_ANY
								%% indicates no restriction. */
	  cookie	:: uint64(),				%% Require matching entries to contain this
								%% cookie value */
	  cookie_mask	:: uint64(),				%% Mask used to restrict the cookie bits that
								%% must match. A value of 0
								%% indicates no restriction.

	  match		:: binary() | #ofp_match{}		%% Fields to match.
}).

%% Individual flow statistics.
-record(ofp_flow_stats, {
	  table_id	:: non_neg_integer(),			%% ID of table flow came from.
	  match		:: binary() | #ofp_match{},		%% Description of fields.
	  duration	:: ofp_duration(),			%% Time flow has been alive in {seconds, nanoseconds}
	  priority	:: non_neg_integer(),			%% Priority of the entry. Only meaningful
														%% when this is not an exact-match entry.
	  idle_timeout	:: non_neg_integer(),			%% Number of seconds idle before expiration.
	  hard_timeout	:: non_neg_integer(),			%% Number of seconds before expiration.
	  cookie	:: non_neg_integer(),			%% Opaque controller-issued identifier.
	  packet_count	:: non_neg_integer(),			%% Number of packets in flow.
	  byte_count	:: non_neg_integer(),			%% Number of bytes in flow.
	  actions	:: ofp_actions()			%% Actions.
}).

%% Individual flow statistics.
-record(ofp_flow_stats_v11, {
	  table_id	:: non_neg_integer(),			%% ID of table flow came from.
	  duration	:: ofp_duration(),			%% Time flow has been alive in {seconds, nanoseconds}
	  priority	:: non_neg_integer(),			%% Priority of the entry. Only meaningful
														%% when this is not an exact-match entry.
	  idle_timeout	:: non_neg_integer(),			%% Number of seconds idle before expiration.
	  hard_timeout	:: non_neg_integer(),			%% Number of seconds before expiration.
	  cookie	:: non_neg_integer(),			%% Opaque controller-issued identifier.
	  packet_count	:: non_neg_integer(),			%% Number of packets in flow.
	  byte_count	:: non_neg_integer(),			%% Number of bytes in flow.
	  match		:: binary() | #ofp_match{},		%% Description of fields.
	  instructions	:: ofp_instructions()			%% Instructions
}).

%% Request aggregate flow statistics.
-record(ofp_aggregate_stats_request, {
	  match		:: binary() | #ofp_match{},		%% Fields to match.
	  table_id	:: non_neg_integer() | 'all' | 'emergency',
								%% ID of table to read (from ofp_table_stats)
								%% 0xff for all tables or 0xfe for emergency.
	  out_port	:: ofp_port()				%% Require matching entries to include this
								%% as an output port. A value of OFPP_NONE
								%% indicates no restriction.
}).

%% Request aggregate flow statistics.
-record(ofp_aggregate_stats_request_v11, {
	  table_id	:: non_neg_integer() | 'all',		%% ID of table to read (from ofp_table_stats)
								%% 0xff for all tables
	  out_port	:: ofp_port(),				%% Require matching entries to include this
								%% as an output port. A value of OFPP_ANY
								%% indicates no restriction.
	  out_group	:: uint32(),				%% Require matching entries to include this
								%% as an output group. A value of OFPG_ANY
								%% indicates no restriction. */
	  cookie	:: uint64(),				%% Require matching entries to contain this
								%% cookie value */
	  cookie_mask	:: uint64(),				%% Mask used to restrict the cookie bits that
								%% must match. A value of 0
								%% indicates no restriction.
	  match		:: binary() | #ofp_match{}		%% Fields to match.
}).

%% Aggregate flow statistics.
-record(ofp_aggregate_stats, {
	  packet_count	:: non_neg_integer(),			%% Number of packets in flows.
	  byte_count	:: non_neg_integer(),			%% Number of bytes in flows.
	  flow_count	:: non_neg_integer()			%% Number of flows.
}).

%% Request flow table statistics.
-record(ofp_table_stats_request, {}).

%% Flow table statistics.
-record(ofp_table_stats, {
	  table_id	:: non_neg_integer(),			%% Identifier of table. Lower numbered tables
								%% are consulted first.
	  name		:: binary(),
	  wildcards	:: non_neg_integer(),			%% Bitmap of OFPFW_* wildcards that are
								%% supported by the table.
	  max_entries	:: non_neg_integer(),			%% Max number of entries supported. */
	  active_count	:: non_neg_integer(),			%% Number of active entries. */
	  lookup_count	:: non_neg_integer(),			%% Number of packets looked up in table. */
	  matched_count	:: non_neg_integer()			%% Number of packets that hit table. */
	 }).

%% Flow table statistics.
-record(ofp_table_stats_v11, {
	  table_id	:: uint8(),			%% Identifier of table. Lower numbered tables
							%% are consulted first.
	  name		:: binary(),
	  wildcards	:: uint32(),			%% Bitmap of OFPFMF_* wildcards that are
							%% supported by the table.
	  match		:: uint32(),			%% Bitmap of OFPFMF_* that indicate the fields
							%% the table can match on.
	  instructions	:: uint32(),			%% Bitmap of OFPIT_* values supported.
	  write_actions	:: uint32(),			%% Bitmap of OFPAT_* that are supported
							%% by the table with OFPIT_WRITE_ACTIONS.
	  apply_actions	:: uint32(),			%% Bitmap of OFPAT_* that are supported
	  config	:: uint32(),			%% Bitmap of OFPTC_* values
	  max_entries	:: uint32(),			%% Max number of entries supported.
	  active_count	:: uint32(),			%% Number of active entries.
	  lookup_count	:: uint64(),			%% Number of packets looked up in table.
	  matched_count	:: uint64()			%% Number of packets that hit table.
}).

%% Request physical port statistics.
-record(ofp_port_stats_request, {
	  port_no	:: ofp_port()				%% OFPST_PORT message must request statistics
								%% either for a single port (specified in
								%% port_no) or for all ports (if port_no ==
								%% OFPP_NONE).
}).

%% Physical port statistics.
-record(ofp_port_stats, {
	  port_no	:: ofp_port(),				%% All ports if OFPT_ALL.
	  rx_packets	:: non_neg_integer(),			%% Number of received packets.
	  tx_packets	:: non_neg_integer(),			%% Number of transmitted packets.
	  rx_bytes	:: non_neg_integer(),			%% Number of received bytes.
	  tx_bytes	:: non_neg_integer(),			%% Number of transmitted bytes.
	  rx_dropped	:: non_neg_integer(),			%% Number of packets dropped by RX.
	  tx_dropped	:: non_neg_integer(),			%% Number of packets dropped by TX.
	  rx_errors	:: non_neg_integer(),			%% Number of receive errors. This is a super-set
								%% of more specific receive errors and should be
								%% greater than or equal to the sum of all
								%% rx_*_err values.
	  tx_errors	:: non_neg_integer(),			%% Number of transmit errors. This is a super-set
								%% of more specific transmit errors and should be
								%% greater than or equal to the sum of all
								%% tx_*_err values (none currently defined.)
	  rx_frame_err	:: non_neg_integer(),			%% Number of frame alignment errors.
	  rx_over_err	:: non_neg_integer(),			%% Number of packets with RX overrun.
	  rx_crc_err	:: non_neg_integer(),			%% Number of CRC errors.
	  collisions	:: non_neg_integer()			%% Number of collisions.
}).

%% Request queue statistics for a port
-record(ofp_queue_stats_request, {
	  port_no	:: ofp_port(),				%% All ports if OFPT_ALL.
	  queue_id	:: non_neg_integer() | 'all'		%% All queues if OFPQ_ALL.
}).

%% Queue statistics for a port
-record(ofp_queue_stats, {
	  port_no	:: ofp_port(),				%% All ports if OFPT_ALL.
	  queue_id	:: non_neg_integer(),			%% Queue i.d
	  tx_bytes	:: non_neg_integer(),			%% Number of transmitted bytes.
	  tx_packets	:: non_neg_integer(),			%% Number of transmitted packets.
	  tx_errors	:: non_neg_integer()			%% Number of packets dropped due to overrun.
}).

%% Used in group stats replies.
-record(ofp_bucket_counter, {
	  packet_count	:: uint64(),				%% Number of packets processed by bucket.
	  byte_count	:: uint64()				%% Number of bytes processed by bucket.
}).

%% Request group statistics.
-record(ofp_group_stats_request, {
	  group_id	:: uint32()				%% All groups if OFPG_ALL.
}).

%% Body of reply to OFPST_GROUP request.
-record(ofp_group_stats, {
	  group_id	:: uint32(),				%% Group identifier.
	  ref_count	:: uint32(),				%% Number of flows or groups that directly forward
								%% to this group.
	  packet_count	:: uint64(),				%% Number of packets processed by group.
	  byte_count	:: uint64(),				%% Number of bytes processed by group.
	  bucket_stats	:: [#ofp_bucket_counter{}]
}).

%% Request group description statistics
-record(ofp_group_desc_stats_request, {}).

%% Body of reply to OFPST_GROUP_DESC request.
-record(ofp_group_desc_stats, {
	  type		:: uint8(),				%% One of OFPGT_*.
	  group_id	:: uint32(),				%% Group identifier.
	  buckets	:: [#ofp_bucket{}]
}).


%% nicira extensions

-record(ofp_nxst_flow_stats_request, {
	  out_port	:: ofp_port(),				%% Require matching entries to include this
								%% as an output port. A value of OFPP_NONE
								%% indicates no restriction.
	  table_id	:: non_neg_integer() | 'all' | 'emergency',
								%% ID of table to read (from ofp_table_stats),
								%% 0xff for all tables or 0xfe for emergency.
	  nx_match	:: nx_match()				%% Fields to match.
}).

-record(ofp_nxst_flow_stats, {
	  table_id	:: non_neg_integer(),			%% ID of table flow came from.
	  duration	:: ofp_duration(),			%% Time flow has been alive in {seconds, nanoseconds}
	  priority	:: non_neg_integer(),			%% Priority of the entry. Only meaningful
								%% when this is not an exact-match entry.
	  idle_timeout	:: non_neg_integer(),			%% Number of seconds idle before expiration.
	  hard_timeout	:: non_neg_integer(),			%% Number of seconds before expiration.
	  cookie	:: non_neg_integer(),			%% Opaque controller-issued identifier.
	  packet_count	:: non_neg_integer(),			%% Number of packets in flow.
	  byte_count	:: non_neg_integer(),			%% Number of bytes in flow.
	  nx_match	:: nx_match(),				%% Description of fields.
	  actions	:: ofp_actions()			%% Actions.
}).

-record(ofp_nxst_aggregate_stats_request, {
	  out_port	:: ofp_port(),				%% Require matching entries to include this
								%% as an output port. A value of OFPP_NONE
								%% indicates no restriction.
	  table_id	:: non_neg_integer() | 'all' | 'emergency',
								%% ID of table to read (from ofp_table_stats)
								%% 0xff for all tables or 0xfe for emergency.
	  nx_match	:: nx_match()				%% Fields to match.
}).

-record(ofp_nxst_aggregate_stats, {
	  packet_count	:: non_neg_integer(),			%% Number of packets in flows.
	  byte_count	:: non_neg_integer(),			%% Number of bytes in flows.
	  flow_count	:: non_neg_integer()			%% Number of flows.
}).
