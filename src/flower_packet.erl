-module(flower_packet).

%% API
-export([encode/1, encode_msg/1, encode_match/1, decode/1]).
%% constant mappers
-export([ofpt/1, ofp_packet_in_reason/1, ofp_config_flags/1,
	 ofp_flow_mod_command/1, ofp_port/1, eth_type/1]).
%% part encoders
-export([encode_ofs_action_output/2, encode_ofs_action_vlan_vid/1,
	 encode_ofs_action_vlan_pcp/1, encode_ofs_action_strip_vlan/0,
	 encode_ofs_action_dl_addr/2, encode_ofs_action_nw_addr/2,
	 encode_ofs_action_nw_tos/1, encode_ofs_action_tp_addr/2,
	 encode_ofs_action_enqueue/2, encode_ofs_action_vendor/2,
	 encode_nx_action_resubmit/1, encode_nx_action_set_tunnel/1,
	 encode_nx_action_set_tunnel64/1, encode_nx_action_set_queue/1,
	 encode_nx_action_pop_queue/0, encode_nx_action_reg_move/5,
	 encode_nx_action_reg_load/4, encode_nx_action_note/1,
	 encode_nx_action_multipath/8, encode_nx_action_autopath/4,
	 nxm_header/1, encode_nx_action/2,
	 encode_actions/1,
	 encode_action/1,
	 encode_ofp_match/13,
	 encode_ofp_flow_mod/10,
	 encode_ofp_flow_removed/8,
	 encode_ofp_packet_out/4]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_packet.hrl").

%% --------------------------------------------------------------------
-type int8() :: 0..16#ff.
-type int16() :: 0..16#ffff.
-type int32() :: 0..16#ffffffff.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

decode(Msg) ->
    decode(Msg, []).

decode(<<Version:8/integer, Type:8/integer, Length:16/integer, Xid:32/integer,
	 _/binary>> = Data, Acc)
  when size(Data) >= Length ->
    MsgLen = Length - 8,
    <<_Hdr:8/bytes, Msg:MsgLen/bytes, Rest/binary>> = Data,
    MType = ofpt(Type),
    M = decode_msg(MType, Msg),
    lager:debug("decode got: ~p", [M]),
    decode(Rest, [#ovs_msg{version = Version, type = MType, xid = Xid, msg = M}|Acc]);

decode(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.

encode(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg}) ->
    Mtype = ofpt(Type),
    Data = encode_msg(Msg),
    Length = size(Data) + 8,
    lager:debug("~p ~p ~p ~p ~p", [Version, Mtype, Length, Xid, Msg]),
    R = <<Version:8, Mtype:8, Length:16, Xid:32, Data/binary>>,
    lager:debug("Send: ~p", [R]),
    R;

encode(Msg) when is_list(Msg) ->
    encode(Msg, []).

encode([], Acc) ->
    list_to_binary(lists:reverse(Acc));
encode([Msg|Rest], Acc) ->
    encode(Rest, [encode(Msg)|Acc]).

%%%===================================================================
%%% constant, flags and enum translators
%%%===================================================================

-define(VENDOR_NICIRA, 16#2320).
vendor(?VENDOR_NICIRA) -> nicira;
vendor(X) when is_integer(X) -> X;
vendor(nicira) -> ?VENDOR_NICIRA.

eth_type(?ETH_TYPE_IP)    -> ip;
eth_type(?ETH_TYPE_ARP)   -> arp;
eth_type(?ETH_TYPE_RARP)  -> rarp;
eth_type(?ETH_TYPE_MOPRC) -> moprc;
eth_type(?ETH_TYPE_VLAN)  -> vlan;
eth_type(?ETH_TYPE_IPV6)  -> ipv6;
eth_type(?ETH_TYPE_LACP)  -> lacp;
eth_type(?ETH_TYPE_LOOP)  -> loop;
eth_type(X) when is_integer(X) -> X;

eth_type(none)  -> ?ETH_TYPE_NONE;
eth_type(ip)    -> ?ETH_TYPE_IP;
eth_type(arp)   -> ?ETH_TYPE_ARP;
eth_type(rarp)  -> ?ETH_TYPE_RARP;
eth_type(moprc) -> ?ETH_TYPE_MOPRC;
eth_type(vlan)  -> ?ETH_TYPE_VLAN;
eth_type(ipv6)  -> ?ETH_TYPE_IPV6;
eth_type(lacp)  -> ?ETH_TYPE_LACP;
eth_type(loop)  -> ?ETH_TYPE_LOOP;
eth_type(undefined) -> 0.

ofpt(0)		-> hello;
ofpt(1)		-> error;
ofpt(2)		-> echo_request;
ofpt(3)		-> echo_reply;
ofpt(4)		-> vendor;
ofpt(5)		-> features_request;
ofpt(6)		-> features_reply;
ofpt(7)		-> get_config_request;
ofpt(8)		-> get_config_reply;
ofpt(9)		-> set_config;
ofpt(10)	-> packet_in;
ofpt(11)	-> flow_removed;
ofpt(12)	-> port_status;
ofpt(13)	-> packet_out;
ofpt(14)	-> flow_mod;
ofpt(15)	-> port_mod;
ofpt(16)	-> stats_request;
ofpt(17)	-> stats_reply;
ofpt(18)	-> barrier_request;
ofpt(19)	-> barrier_reply;
ofpt(20)	-> queue_get_config_request;
ofpt(21)	-> queue_get_config_reply;

ofpt(hello)			-> 0;
ofpt(error)			-> 1;
ofpt(echo_request)		-> 2;
ofpt(echo_reply)		-> 3;
ofpt(vendor)			-> 4;
ofpt(features_request)		-> 5;
ofpt(features_reply)		-> 6;
ofpt(get_config_request)	-> 7;
ofpt(get_config_reply)		-> 8;
ofpt(set_config)		-> 9;
ofpt(packet_in)			-> 10;
ofpt(flow_removed)		-> 11;
ofpt(port_status)		-> 12;
ofpt(packet_out)		-> 13;
ofpt(flow_mod)			-> 14;
ofpt(port_mod)			-> 15;
ofpt(stats_request)		-> 16;
ofpt(stats_reply)		-> 17;
ofpt(barrier_request)		-> 18;
ofpt(barrier_reply)		-> 19;
ofpt(queue_get_config_request)	-> 20;
ofpt(queue_get_config_reply)	-> 21;

ofpt(_)		-> error.

-spec ofp_error_type(non_neg_integer()) -> ofp_error_type() | non_neg_integer();
		    (ofp_error_type()) -> non_neg_integer().
ofp_error_type(hello_failed)    -> 0;
ofp_error_type(bad_request)     -> 1;
ofp_error_type(bad_action)      -> 2;
ofp_error_type(flow_mod_failed) -> 3;
ofp_error_type(port_mod_failed) -> 4;
ofp_error_type(queue_op_failed) -> 5;

ofp_error_type(0) -> hello_failed;
ofp_error_type(1) -> bad_request;
ofp_error_type(2) -> bad_action;
ofp_error_type(3) -> flow_mod_failed;
ofp_error_type(4) -> port_mod_failed;
ofp_error_type(5) -> queue_op_failed;

ofp_error_type(X) when is_integer(X) -> X.

-spec ofp_error_code_type(ofp_error_type(), non_neg_integer()) -> atom() | 'error';
			 (ofp_error_type(), atom()) -> non_neg_integer() | 'error'.
ofp_error_code_type(hello_failed, 0) -> incompatible;
ofp_error_code_type(hello_failed, 1) -> eperm;

ofp_error_code_type(bad_request, 0) -> bad_version;
ofp_error_code_type(bad_request, 1) -> bad_type;
ofp_error_code_type(bad_request, 2) -> bad_stat;
ofp_error_code_type(bad_request, 3) -> bad_vendor;
ofp_error_code_type(bad_request, 4) -> bad_subtype;
ofp_error_code_type(bad_request, 5) -> eperm;
ofp_error_code_type(bad_request, 6) -> bad_len;
ofp_error_code_type(bad_request, 7) -> buffer_empty;
ofp_error_code_type(bad_request, 8) -> buffer_unknown;

ofp_error_code_type(bad_action, 0) -> bad_type;
ofp_error_code_type(bad_action, 1) -> bad_len;
ofp_error_code_type(bad_action, 2) -> bad_vendor;
ofp_error_code_type(bad_action, 3) -> bad_vendor_type;
ofp_error_code_type(bad_action, 4) -> bad_out_port;
ofp_error_code_type(bad_action, 5) -> bad_argument;
ofp_error_code_type(bad_action, 6) -> eperm;
ofp_error_code_type(bad_action, 7) -> too_many;
ofp_error_code_type(bad_action, 8) -> bad_queue;

ofp_error_code_type(flow_mod_failed, 0) -> all_tables_full;
ofp_error_code_type(flow_mod_failed, 1) -> overlap;
ofp_error_code_type(flow_mod_failed, 2) -> eperm;
ofp_error_code_type(flow_mod_failed, 3) -> bad_emerg_timeout ;
ofp_error_code_type(flow_mod_failed, 4) -> bad_command;
ofp_error_code_type(flow_mod_failed, 5) -> unsupported;

ofp_error_code_type(port_mod_failed, 0) -> bad_port;
ofp_error_code_type(port_mod_failed, 1) -> bad_hw_addr;

ofp_error_code_type(queue_op_failed, 0) -> bad_port;
ofp_error_code_type(queue_op_failed, 1) -> bad_queue;
ofp_error_code_type(queue_op_failed, 2) -> eperm;

ofp_error_code_type(hello_failed, incompatible)		-> 0;
ofp_error_code_type(hello_failed, eperm)		-> 1;

ofp_error_code_type(bad_request, bad_version)		-> 0;
ofp_error_code_type(bad_request, bad_type)		-> 1;
ofp_error_code_type(bad_request, bad_stat)		-> 2;
ofp_error_code_type(bad_request, bad_vendor)		-> 3;
ofp_error_code_type(bad_request, bad_subtype)		-> 4;
ofp_error_code_type(bad_request, eperm)			-> 5;
ofp_error_code_type(bad_request, bad_len)		-> 6;
ofp_error_code_type(bad_request, buffer_empty)		-> 7;
ofp_error_code_type(bad_request, buffer_unknown)	-> 8;

ofp_error_code_type(bad_action, bad_type)		-> 0;
ofp_error_code_type(bad_action, bad_len)		-> 1;
ofp_error_code_type(bad_action, bad_vendor)		-> 2;
ofp_error_code_type(bad_action, bad_vendor_type)	-> 3;
ofp_error_code_type(bad_action, bad_out_port)		-> 4;
ofp_error_code_type(bad_action, bad_argument)		-> 5;
ofp_error_code_type(bad_action, eperm)			-> 6;
ofp_error_code_type(bad_action, too_many)		-> 7;
ofp_error_code_type(bad_action, bad_queue)		-> 8;

ofp_error_code_type(flow_mod_failed, all_tables_full)	-> 0;
ofp_error_code_type(flow_mod_failed, overlap)		-> 1;
ofp_error_code_type(flow_mod_failed, eperm)		-> 2;
ofp_error_code_type(flow_mod_failed, bad_emerg_timeout )-> 3;
ofp_error_code_type(flow_mod_failed, bad_command)	-> 4;
ofp_error_code_type(flow_mod_failed, unsupported)	-> 5;

ofp_error_code_type(port_mod_failed, bad_port)		-> 0;
ofp_error_code_type(port_mod_failed, bad_hw_addr)	-> 1;

ofp_error_code_type(queue_op_failed, bad_port)		-> 0;
ofp_error_code_type(queue_op_failed, bad_queue)		-> 1;
ofp_error_code_type(queue_op_failed, eperm)		-> 2;

ofp_error_code_type(_, _) -> error.

ofp_capabilities() ->
    [flow_stats, table_stats, port_stats, stp, reserved, ip_reasm, queue_stats, arp_match_ip].

ofp_action_type() ->
    [output, set_vlan_vid, set_vlan_pcp, strip_vlan, set_dl_src, set_dl_dst, 
     set_nw_src, set_nw_dst, set_nw_tos, set_tp_src, set_tp_dst, enqueue].

ofp_port_config() ->
    [port_down, no_stp, no_recv, no_recv_stp, no_flood, no_fwd, no_packet_in].

ofp_port_state() ->
    [link_down, stp_listen, stp_learn, stp_forward, stp_block].

ofp_port_features() ->
    ['10mb_hd', '10mb_fd', '100mb_hd', '100mb_fd', '1gb_hd', '1gb_fd', '10gb_fd', copper, fiber, autoneg, pause, pause_asym].

ofp_packet_in_reason(0)	-> no_match;
ofp_packet_in_reason(1)	-> action;

ofp_packet_in_reason(no_match)	-> 0;
ofp_packet_in_reason(action)	-> 1;

ofp_packet_in_reason(_) -> error.

ofp_config_flags(0)	-> frag_normal;
ofp_config_flags(1)	-> frag_drop;
ofp_config_flags(2)	-> frag_reasm;
ofp_config_flags(3)	-> frag_mask;

ofp_config_flags(frag_normal)	-> 0;
ofp_config_flags(frag_drop)	-> 1;
ofp_config_flags(frag_reasm)	-> 2;
ofp_config_flags(frag_mask)	-> 3;

ofp_config_flags(_) -> error.

ofp_flow_mod_command(0)	-> add;
ofp_flow_mod_command(1)	-> modify;
ofp_flow_mod_command(2)	-> modify_strict;
ofp_flow_mod_command(3)	-> delete;
ofp_flow_mod_command(4)	-> delete_strict;

ofp_flow_mod_command(add)		-> 0;
ofp_flow_mod_command(modify)		-> 1;
ofp_flow_mod_command(modify_strict)	-> 2;
ofp_flow_mod_command(delete)		-> 3;
ofp_flow_mod_command(delete_strict)	-> 4;

ofp_flow_mod_command(X) when is_integer(X)	-> X;
ofp_flow_mod_command(_)	-> error.

ofp_flow_mod_flags() ->
    [send_flow_rem, check_overlap, emerg].

-spec ofp_port(non_neg_integer()) -> ofp_port_name() | non_neg_integer();
	      (ofp_port_name()) -> non_neg_integer().
%% Port numbering.  Physical ports are numbered starting from 1.
ofp_port(16#fff8) -> in_port;
ofp_port(16#fff9) -> table;
ofp_port(16#fffa) -> normal;
ofp_port(16#fffb) -> flood;
ofp_port(16#fffc) -> all;
ofp_port(16#fffd) -> controller;
ofp_port(16#fffe) -> local;
ofp_port(16#ffff) -> none;
ofp_port(X) when is_integer(X) -> X;

ofp_port(in_port)    -> 16#fff8;
ofp_port(table)      -> 16#fff9;
ofp_port(normal)     -> 16#fffa;
ofp_port(flood)      -> 16#fffb;
ofp_port(all)        -> 16#fffc;
ofp_port(controller) -> 16#fffd;
ofp_port(local)      -> 16#fffe;
ofp_port(none)       -> 16#ffff.

ofp_table(16#fe) -> emergency; 
ofp_table(16#ff) -> all;
ofp_table(X) when is_integer(X) -> X;
ofp_table(emergency) -> 16#fe;
ofp_table(all)       -> 16#ff.

ofp_queue(16#ffff) -> all;
ofp_queue(X) when is_integer(X) -> X;
ofp_queue(all)      -> 16#ffff.

ofp_flow_removed_reason(0) -> idle_timeout;
ofp_flow_removed_reason(1) -> hard_timeout;
ofp_flow_removed_reason(2) -> delete;
ofp_flow_removed_reason(X) when is_integer(X) -> X;

ofp_flow_removed_reason(idle_timeout) -> 0;
ofp_flow_removed_reason(hard_timeout) -> 1;
ofp_flow_removed_reason(delete)       -> 2.

ofp_port_reason(0) -> add;
ofp_port_reason(1) -> delete;
ofp_port_reason(2) -> modify;
ofp_port_reason(X) when is_integer(X) -> X;
ofp_port_reason(add)    -> 0;
ofp_port_reason(delete) -> 1;
ofp_port_reason(modify) -> 2.

ofp_stats_type(0)		-> desc;
ofp_stats_type(1)		-> flow;
ofp_stats_type(2)		-> aggregate;
ofp_stats_type(3)		-> table;
ofp_stats_type(4)		-> port;
ofp_stats_type(5)		-> queue;
ofp_stats_type(16#ffff)	-> vendor;
ofp_stats_type(X) when is_integer(X) -> X;
ofp_stats_type(desc)		-> 0;
ofp_stats_type(flow)		-> 1;
ofp_stats_type(aggregate)	-> 2;
ofp_stats_type(table)		-> 3;
ofp_stats_type(port)		-> 4;
ofp_stats_type(queue)		-> 5;
ofp_stats_type(vendor)		-> 16#ffff.

ofp_queue_properties(0)        -> none;
ofp_queue_properties(1)        -> min_rate;
ofp_queue_properties(none)     -> 0;
ofp_queue_properties(min_rate) -> 1.
     
ofp_vendor_stats_type({nicira, 0})	-> nxst_flow;
ofp_vendor_stats_type({nicira, 1})	-> nxst_aggregate;
ofp_vendor_stats_type(nxst_flow)	-> {nicira, 0};
ofp_vendor_stats_type(nxst_aggregate)	-> {nicira, 1}.

-spec of_vendor_ext(of_vendor_ext()) -> {atom(), non_neg_integer()};
		   ({atom(), non_neg_integer()}) -> of_vendor_ext().
of_vendor_ext({nicira, 10}) ->	nxt_role_request;
of_vendor_ext({nicira, 11}) ->	nxt_role_reply;
of_vendor_ext({nicira, 12}) ->	nxt_set_flow_format;
of_vendor_ext({nicira, 13}) ->	nxt_flow_mod;
of_vendor_ext({nicira, 14}) ->	nxt_flow_removed;
of_vendor_ext({nicira, 15}) ->	nxt_flow_mod_table_id;

of_vendor_ext(nxt_role_request)      ->	{nicira, 10};
of_vendor_ext(nxt_role_reply)        ->	{nicira, 11};
of_vendor_ext(nxt_set_flow_format)   ->	{nicira, 12};
of_vendor_ext(nxt_flow_mod)          ->	{nicira, 13};
of_vendor_ext(nxt_flow_removed)      ->	{nicira, 14};
of_vendor_ext(nxt_flow_mod_table_id) ->	{nicira, 15}.

nxt_role(0) -> other;
nxt_role(1) -> master;
nxt_role(2) -> slave;
nxt_role(X) when is_integer(X) -> X;

nxt_role(other)  -> 0;
nxt_role(master) -> 1;
nxt_role(slave)  -> 2.

nxt_action(0)  -> nxast_snat__obsolete;
nxt_action(1)  -> nxast_resubmit;
nxt_action(2)  -> nxast_set_tunnel;
nxt_action(3)  -> nxast_drop_spoofed_arp__obsolete;
nxt_action(4)  -> nxast_set_queue;
nxt_action(5)  -> nxast_pop_queue;
nxt_action(6)  -> nxast_reg_move;
nxt_action(7)  -> nxast_reg_load;
nxt_action(8)  -> nxast_note;
nxt_action(9)  -> nxast_set_tunnel64;
nxt_action(10) -> nxast_multipath;
nxt_action(11) -> nxast_autopath;
nxt_action(X) when is_integer(X) -> X;

nxt_action(nxast_snat__obsolete) -> 0;            %% No longer used.
nxt_action(nxast_resubmit)       -> 1;            %% struct nx_action_resubmit
nxt_action(nxast_set_tunnel)     -> 2;            %% struct nx_action_set_tunnel
nxt_action(nxast_drop_spoofed_arp__obsolete) -> 3;
nxt_action(nxast_set_queue)      -> 4;            %% struct nx_action_set_queue
nxt_action(nxast_pop_queue)      -> 5;            %% struct nx_action_pop_queue
nxt_action(nxast_reg_move)       -> 6;            %% struct nx_action_reg_move
nxt_action(nxast_reg_load)       -> 7;            %% struct nx_action_reg_load
nxt_action(nxast_note)           -> 8;            %% struct nx_action_note
nxt_action(nxast_set_tunnel64)   -> 9;            %% struct nx_action_set_tunnel64
nxt_action(nxast_multipath)      -> 10;           %% struct nx_action_multipath
nxt_action(nxast_autopath)       -> 11.           %% struct nx_action_autopath

protocol(NwProto)
  when is_atom(NwProto) ->
    gen_socket:protocol(NwProto);
protocol(NwProto) ->
    NwProto.

-spec not_impl() -> no_return().
not_impl() ->
    throw(not_implemented_yet).

%%%===================================================================
%%% Decode
%%%===================================================================
decode_nx_matches(<< Header:4/binary, Rest/binary>>, Acc) ->
    H = nxm_header(Header),
    <<_Vendor:16, _Field:7, Mult:1, Length:8>> = Header,
    case Mult of
	0 ->
	    <<Value:Length/binary, Next/binary>> = Rest,
	    decode_nx_matches(Next, [{H, Value}|Acc]);
	1 ->
	    L = Length div 2,
	    <<Value:L/binary, Mask:L/binary, Next/binary>> = Rest,
	    decode_nx_matches(Next, [{H, {Value, Mask}}|Acc])
    end;
decode_nx_matches(_, Acc) ->
    lists:reverse(Acc).
decode_nx_matches(NxMatch) ->
    decode_nx_matches(NxMatch, []).

decode_msg(error, << Type:16/integer, Code:16/integer, Data/binary >>) ->
    Type1 = ofp_error_type(Type),
    Code1 = ofp_error_code_type(Type1, Code),
    Error = {Type1, Code1},
    #ofp_error{error = Error, data = Data};

decode_msg(vendor, << Vendor:32/integer, Cmd:32/integer, Data/binary >>) ->
    decode_msg(of_vendor_ext({vendor(Vendor), Cmd}), Data);

decode_msg(features_reply, <<DataPathId:64/integer, NBuffers:32/integer, NTables:8/integer, Pad:3/bytes,
			     Capabilities:32/integer, Actions:32/integer, Ports/binary>>) ->
    lager:debug("DataPathId: ~p, NBuffers: ~p, NTables: ~p, Pad: ~p, Capabilities: ~p, Actions: ~p, Ports: ~p",
	   [DataPathId, NBuffers, NTables, Pad, Capabilities, Actions, Ports]),
    #ofp_switch_features{datapath_id = DataPathId,
			 n_buffers = NBuffers,
			 n_tables = NTables,
			 capabilities = dec_flags(ofp_capabilities(), Capabilities),
			 actions = dec_flags(ofp_action_type(), Actions),
			 ports = decode_phy_ports(Ports)};

decode_msg(get_config_reply, <<Flags:16/integer, MissSendLen:16/integer>>) ->
    #ofp_switch_config{flags = ofp_config_flags(Flags), miss_send_len = MissSendLen};

decode_msg(set_config, <<Flags:16/integer, MissSendLen:16/integer>>) ->
    #ofp_switch_config{flags = ofp_config_flags(Flags), miss_send_len = MissSendLen};

decode_msg(packet_in, <<BufferId:32/integer, TotalLen:16/integer, InPort:16/integer, Reason:8/integer, _Pad:1/binary, Data/binary>>) ->
    #ofp_packet_in{buffer_id = BufferId, total_len = TotalLen, in_port = ofp_port(InPort), reason = ofp_packet_in_reason(Reason), data = Data};

decode_msg(flow_removed, <<Match:40/bytes, Cookie:64/integer, Priority:16/integer, Reason:8/integer, _Pad1:1/bytes,
			   DurationSec:32/integer, DurationNSec:32/integer, IdleTimeout:16/integer, _Pad2:2/bytes,
			   PacketCount:64/integer, ByteCount:64/integer>>) ->
    #ofp_flow_removed{match = decode_ofp_match(Match), cookie = Cookie, priority = Priority, reason = ofp_flow_removed_reason(Reason),
		      duration = {DurationSec, DurationNSec}, idle_timeout = IdleTimeout, packet_count = PacketCount, byte_count = ByteCount};

decode_msg(port_status, <<Reason:8/integer, _Pad:7/bytes, PhyPort/binary>>) ->
    #ofp_port_status{reason = ofp_port_reason(Reason),
		     port = decode_phy_port(PhyPort)};

decode_msg(packet_out, <<BufferId:32/integer, InPort:16/integer, ActionsLen:16/integer, Actions:ActionsLen/bytes, Data/binary>>) ->
    #ofp_packet_out{buffer_id = BufferId, in_port = ofp_port(InPort), actions = decode_actions(Actions), data = Data};

decode_msg(flow_mod, <<Match:40/bytes, Cookie:64/integer, Command:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer,
		       Priority:16/integer, BufferId:32/integer, OutPort:16/integer, Flags:16/integer, Actions/binary>>) ->
    #ofp_flow_mod{match = decode_ofp_match(Match), cookie = Cookie, command = ofp_flow_mod_command(Command),
		  idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
		  priority = Priority, buffer_id = BufferId,
		  out_port = ofp_port(OutPort), flags = dec_flags(ofp_flow_mod_flags(), Flags), actions = decode_actions(Actions)};

decode_msg(port_mod, <<PortNo:16/integer, HwAddr:6/bytes, Config:32/integer, Mask:32/integer, Advertise:32/integer, _Pad:4/bytes>>) ->
    #ofp_port_mod{port_no = PortNo, hw_addr = HwAddr,
		  config = dec_flags(ofp_port_config(), Config),
		  mask = dec_flags(ofp_port_config(), Mask),
		  advertise = dec_flags(ofp_port_features(), Advertise)};

decode_msg(stats_request, <<Type:16/integer, _Flags:16/integer, Msg/binary>>) ->
    decode_stats_request(ofp_stats_type(Type), Msg);

decode_msg(stats_reply, <<Type:16/integer, _Flags:16/integer, Msg/binary>>) ->
    decode_stats_reply(ofp_stats_type(Type), [], Msg);

decode_msg(queue_get_config_request, <<Port:16/integer, _Pad:2/bytes>>) ->
    #ofp_queue_get_config_request{port = ofp_port(Port)};

decode_msg(ofp_queue_get_config_reply, <<Port:16/integer, _Pad:6/bytes, Queues/binary>>) ->
    #ofp_queue_get_config_reply{port = ofp_port(Port), queues = decode_queues(Queues)};

%% Nicira Extensions

decode_msg(nxt_flow_mod_table_id, <<Set:8/integer>>) ->
    #nxt_flow_mod_table_id{set = bool(Set)};

decode_msg(nxt_role_request, <<Role:32/integer>>) ->
    #nxt_role_request{role = nxt_role(Role)};

decode_msg(nxt_flow_mod, <<Cookie:64/integer, Command:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer,
			   Priority:16/integer, BufferId:32/integer, OutPort:16/integer, Flags:16/integer,
			   NxMatchLen:16/integer, 0:48, NxPayload/binary>>) ->
    PadLen = pad_length(8, NxMatchLen),
    <<NxMatch:NxMatchLen/bytes, _Pad:PadLen/bytes, Actions/binary>> = NxPayload,
    #nx_flow_mod{cookie = Cookie, command = ofp_flow_mod_command(Command),
		 idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
		 priority = Priority, buffer_id = BufferId,
		 out_port = ofp_port(OutPort), flags = dec_flags(ofp_flow_mod_flags(), Flags), nx_match = decode_nx_matches(NxMatch), actions = decode_actions(Actions)};

decode_msg(_, Msg) ->
    Msg.

-spec decode_ofp_match(Match :: binary()) -> #ofp_match{}.
decode_ofp_match(<<Wildcards:32/integer, InPort:16/integer,
		   DlSrc:6/binary, DlDst:6/binary, DlVlan:16/integer, DlVlanPcp:8/integer,
		   _Pad1:1/bytes, 
		   DlType:16/integer, NwTos:8/integer, NwProto:8/integer, _Pad2:2/bytes,
		   NwSrc:4/bytes, NwDst:4/bytes, TpSrc:16/integer, TpDst:16/integer>>) ->
    lager:debug("DlType: ~w, NwTos: ~w", [DlType, NwTos]),
    #ofp_match{wildcards = Wildcards, in_port = ofp_port(InPort),
	       dl_src = DlSrc, dl_dst = DlDst, dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = eth_type(DlType),
	       nw_tos = NwTos, nw_proto = protocol(NwProto), nw_src = NwSrc, nw_dst = NwDst,
	       tp_src = TpSrc, tp_dst = TpDst}.

decode_nx_action(nxast_resubmit, << InPort:16, _/binary >>) ->
    #nx_action_resubmit{in_port = ofp_port(InPort)};
decode_nx_action(nxast_set_tunnel, << 0:16, TunId:32 >>) ->
    #nx_action_set_tunnel{tun_id = TunId};
decode_nx_action(nxast_set_queue, << 0:16, QueueId:32 >>) ->
    #nx_action_set_queue{queue_id = QueueId};
decode_nx_action(nxast_pop_queue, << 0:48 >>) ->
    #nx_action_pop_queue{};
decode_nx_action(nxast_reg_move, << Nbits:16, SrcOfs:16, DstOfs:16, Src:4/binary, Dst:4/binary>>) ->
    #nx_action_reg_move{n_bits = Nbits, src_ofs = SrcOfs, dst_ofs = DstOfs, src = nxm_header(Src), dst = nxm_header(Dst)};
decode_nx_action(nxast_reg_load, << Ofs:10, Nbits:6, Dst:4/binary, RawValue/binary >>) ->
    <<_:16, _:7, _:1, ValLen:8, _/binary>> = Dst,
    <<Value:ValLen/binary, _/binary>> = RawValue,
    #nx_action_reg_load{ofs = Ofs, nbits = Nbits, dst = nxm_header(Dst), value = Value};
decode_nx_action(nxast_note, << Note/binary >>) ->
    #nx_action_note{note = Note};
decode_nx_action(nxast_set_tunnel64, << 0:48, TunId:64 >>) ->
    #nx_action_set_tunnel64{tun_id = TunId}.
%%#decode_nx_action(nxast_multipath) ->
%%decode_nx_action(nxast_autopath) ->

decode_vendor_action(nicira, <<Action:16, Msg/binary>>) ->
    decode_nx_action(nxt_action(Action), Msg);
decode_vendor_action(Vendor, Msg) ->
    #ofp_action_vendor{vendor = Vendor, msg = Msg}.

-spec decode_action(Type :: non_neg_integer(), Length :: non_neg_integer(), binary()) -> ofp_action().
decode_action(0, 4, <<Port:16/integer, MaxLen:16/integer>>) ->
    #ofp_action_output{port = ofp_port(Port), max_len = MaxLen};
decode_action(1, 4, <<VlanVid:16/integer, _:16>>) ->
    #ofp_action_vlan_vid{vlan_vid = VlanVid};
decode_action(2, 4, <<VlanPcp:8/integer, 0:24>>) ->
    #ofp_action_vlan_pcp{vlan_pcp = VlanPcp};
decode_action(3, 4, <<_:32>>) ->
    #ofp_action_strip_vlan{};
decode_action(4, 12, <<Addr:6/binary, _:48>>) ->
    #ofp_action_dl_addr{type = src, dl_addr = Addr};
decode_action(5, 12, <<Addr:6/binary, _:48>>) ->
    #ofp_action_dl_addr{type = dst, dl_addr = Addr};
decode_action(6, 4, <<Addr:4/binary>>) ->
    #ofp_action_nw_addr{type = src, nw_addr = Addr};
decode_action(7, 4, <<Addr:4/binary>>) ->
    #ofp_action_nw_addr{type = dst, nw_addr = Addr};
decode_action(8, 4, <<NwTos:8/integer, _:24>>) ->
    #ofp_action_nw_tos{nw_tos = NwTos};
decode_action(9, 4, <<TpPort:16/integer, _:16>>) ->
    #ofp_action_tp_port{type = src, tp_port = TpPort};
decode_action(10, 4, <<TpPort:16/integer, _:16>>) ->
    #ofp_action_tp_port{type = dst, tp_port = TpPort};
decode_action(11, 12, <<Port:16/integer, _:48, QueueId:32/integer>>) ->
    #ofp_action_enqueue{port = ofp_port(Port), queue_id = QueueId};
decode_action(16#FFFF, Length, <<Vendor:32, Msg/binary>> = PayLoad)
  when Length == size(PayLoad) ->
    decode_vendor_action(vendor(Vendor), Msg);
decode_action(Type, Length, Msg)
  when Length == size(Msg) ->
    {Type, Msg}.

decode_actions(<<>>, Acc) ->
    lists:reverse(Acc);
decode_actions(<<Type:16/integer, Length:16/integer, Rest/binary>>, Acc) ->
    Len = Length - 4,
    <<Msg:Len/bytes, Next/binary>> = Rest,
    decode_actions(Next, [decode_action(Type, Len, Msg)|Acc]).

decode_actions(Msg) ->
    decode_actions(Msg, []).

decode_phy_port(<<PortNo:16/integer, HwAddr:6/binary, Name:16/binary,
		  Config:32/integer, State:32/integer,
		  Curr:32/integer, Advertised:32/integer,
		  Supported:32/integer, Peer:32/integer>>) ->
    #ofp_phy_port{port_no = ofp_port(PortNo),
		  hw_addr = HwAddr,
		  name = decode_binstring(Name),
		  config = dec_flags(ofp_port_config(), Config),
		  state = dec_flags(ofp_port_state(), State),
		  curr = dec_flags(ofp_port_features(), Curr),
		  advertised = dec_flags(ofp_port_features(), Advertised),
		  supported = dec_flags(ofp_port_features(), Supported),
		  peer = dec_flags(ofp_port_features(), Peer)}.

decode_phy_ports(<<>>, Acc) ->
    lists:reverse(Acc);
decode_phy_ports(<<Port:48/binary, Rest/binary>>, Acc) ->
    decode_phy_ports(Rest, [decode_phy_port(Port)|Acc]).

decode_phy_ports(Msg) ->
    decode_phy_ports(Msg, []).

decode_queue_prop(none, <<>>) ->
    none;
decode_queue_prop(min_rate, <<Rate:16/integer, _Pad:6/bytes>>) ->
    #ofp_queue_prop_min_rate{rate = Rate}.

decode_queue_props(<<>>, Acc) ->
    lists:reverse(Acc);
decode_queue_props(<<Property:16/integer, Len:16/integer, _Pad:4/bytes, Data>>, Acc) ->
    PropLen = Len - 8,
    <<Prop:PropLen/bytes, Rest/binary>> = Data,
    decode_queue_props(Rest, [decode_queue_prop(ofp_queue_properties(Property), Prop)|Acc]).

decode_queues(<<>>, Acc) ->
    lists:reverse(Acc);
decode_queues(<<QueueId:32/integer, Len:16/integer, _Pad:2/bytes, Data/binary>>, Acc) ->
    DescLen = Len - 8,
    <<Desc:DescLen/bytes, Rest/binary>> = Data,
    Properties = decode_queues(Rest, [decode_queue_props(Desc, [])|Acc]),
    #ofp_packet_queue{queue_id = QueueId, properties = Properties}.

decode_queues(Queues) ->
    decode_queues(Queues, []).

decode_binstring(Str) ->
    [Name|_Rest] = binary:split(Str, <<0>>),
    Name.

%% Stats Reques/Reply

decode_stats_request(desc, <<>>) ->
    #ofp_desc_stats_request{};

decode_stats_request(flow, <<Match:40/bytes, TableId:8/integer, _Pad:1/binary, OutPort:16/integer>>) ->
    #ofp_flow_stats_request{match = decode_ofp_match(Match), table_id = ofp_table(TableId), out_port = ofp_port(OutPort)};

decode_stats_request(aggregate, <<Match:40/bytes, TableId:8/integer, _Pad:1/binary, OutPort:16/integer>>) ->
    #ofp_aggregate_stats_request{match = decode_ofp_match(Match), table_id = ofp_table(TableId), out_port = ofp_port(OutPort)};

decode_stats_request(table, <<>>) ->
    #ofp_table_stats_request{};

decode_stats_request(port, <<Port:16/integer, _Pad:6/bytes>>) ->
    #ofp_port_stats_request{port_no = ofp_port(Port)};

decode_stats_request(queue, <<Port:16/integer, _Pad:2/bytes, Queue:32/integer>>) ->
    #ofp_queue_stats_request{port_no = ofp_port(Port), queue_id = ofp_queue(Queue)};

decode_stats_request(nxst_flow, <<OutPort:16/integer, NxMatchLen:16/integer, TableId:8/integer, _Pad1:3/bytes, More/binary>>) ->
    PadLen = pad_length(8, NxMatchLen),
    <<NxMatch:NxMatchLen/bytes, _Pad2:PadLen/bytes>> = More,
    #ofp_nxst_flow_stats_request{out_port = ofp_port(OutPort), table_id = ofp_table(TableId), nx_match = decode_nx_matches(NxMatch)};

decode_stats_request(nxst_aggregate, <<OutPort:16/integer, NxMatchLen:16/integer, TableId:8/integer, _Pad1:3/bytes, More/binary>>) ->
    PadLen = pad_length(8, NxMatchLen),
    <<NxMatch:NxMatchLen/bytes, _Pad2:PadLen/bytes>> = More,
    #ofp_nxst_aggregate_stats_request{out_port = ofp_port(OutPort), table_id = ofp_table(TableId), nx_match = decode_nx_matches(NxMatch)};

decode_stats_request(vendor, <<Vendor:32/integer, Msg/binary>>) ->
    decode_vendor_stats_request(vendor(Vendor), Msg).

decode_vendor_stats_request(nicira, <<SubType:32/integer, _Pad:4/bytes, Msg/binary>>) ->
    decode_stats_request(ofp_vendor_stats_type({nicira, SubType}), Msg).

decode_stats_reply(_, Acc, <<>>) ->
    lists:reverse(Acc);

decode_stats_reply(desc, Acc, <<MfrDesc:256/bytes, HwDesc:256/bytes, SwDesc:256/bytes,
				SerialNum:32/bytes, DpDesc:256/bytes, Rest/binary>>) ->
    R = #ofp_desc_stats{mfr_desc = decode_binstring(MfrDesc), hw_desc = decode_binstring(HwDesc),
			sw_desc = decode_binstring(SwDesc),	serial_num = decode_binstring(SerialNum),
			dp_desc = decode_binstring(DpDesc)},
    decode_stats_reply(desc, [R|Acc], Rest);

decode_stats_reply(flow, Acc, <<Length:16/integer, TableId:8/integer, _Pad1:1/binary, Match:40/bytes, Sec:32/integer, NSec:32/integer,
				Priority:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer, _Pad2:6/bytes,
				Cookie:64/integer, PacketCount:64/integer, ByteCount:64/integer, More/binary>>) ->
    ActionLength = Length - 88,
    <<Actions:ActionLength/bytes, Rest/binary>> = More,
    R = #ofp_flow_stats{table_id = ofp_table(TableId), match = decode_ofp_match(Match),
			duration = {Sec, NSec}, priority = Priority,
			idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
			packet_count = PacketCount, byte_count = ByteCount, actions = decode_actions(Actions)},
    decode_stats_reply(flow, [R|Acc], Rest);

decode_stats_reply(aggregate, Acc, <<PacketCount:64/integer, ByteCount:64/integer, FlowCount:32/integer, _Pad:4/bytes, Rest/binary>>) ->
    R = #ofp_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount,
			     flow_count = FlowCount},
    decode_stats_reply(aggregate, [R|Acc], Rest);

decode_stats_reply(table, Acc, <<TableId:8/integer, _Pad:3/bytes, Name:32/bytes, Wildcards:32/integer, MaxEntries:32/integer,
				 ActiveCount:32/integer, LookupCount:64/integer, MatchedCount:64/integer, Rest/binary>>) ->
    R = #ofp_table_stats{table_id = ofp_table(TableId), name = decode_binstring(Name), wildcards = Wildcards, max_entries = MaxEntries,
			 active_count = ActiveCount, lookup_count = LookupCount, matched_count = MatchedCount},
    decode_stats_reply(table, [R|Acc], Rest);

decode_stats_reply(port, Acc, <<Port:16/integer, _Pad:6/bytes, RxPackets:64/integer, TxPackets:64/integer,
				RxBytes:64/integer, TxBytes:64/integer, RxDropped:64/integer, TxDropped:64/integer,
				RxErrors:64/integer, TxErrors:64/integer, RxFrameErr:64/integer, RxOverErr:64/integer,
				RxCrcErr:64/integer, Collisions:64/integer, Rest/binary>>) ->
    R = #ofp_port_stats{port_no = ofp_port(Port), rx_packets = RxPackets, tx_packets = TxPackets,
			rx_bytes = RxBytes, tx_bytes = TxBytes, rx_dropped = RxDropped,
			tx_dropped = TxDropped,	rx_errors = RxErrors, tx_errors = TxErrors,
			rx_frame_err = RxFrameErr, rx_over_err = RxOverErr,
			rx_crc_err = RxCrcErr, collisions = Collisions},
    decode_stats_reply(port, [R|Acc], Rest);

decode_stats_reply(queue, Acc, <<Port:16/integer, _Pad:2/bytes, Queue:32/integer, TxBytes:64/integer,
				 TxPackets:64/integer, TxErrors:64/integer, Rest/binary>>) ->
    R = #ofp_queue_stats{port_no = ofp_port(Port), queue_id = ofp_queue(Queue),
			 tx_bytes = TxBytes, tx_packets = TxPackets, tx_errors = TxErrors},
    decode_stats_reply(queue, [R|Acc], Rest);

decode_stats_reply(nxst_flow, Acc, <<Length:16/integer, TableId:8/integer, _Pad1:1/binary, Sec:32/integer, NSec:32/integer,
				     Priority:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer, NxMatchLen:16/integer,
				     _Pad2:4/bytes, Cookie:64/integer, PacketCount:64/integer, ByteCount:64/integer, More/binary>>) ->
    PadLen = pad_length(8, NxMatchLen),
    ActionLength = Length - 48 - NxMatchLen - PadLen,
    <<NxMatch:NxMatchLen/bytes, _Pad3:PadLen/bytes, Actions:ActionLength/bytes, Rest/binary>> = More,
    R = #ofp_nxst_flow_stats{table_id = ofp_table(TableId),
			     duration = {Sec, NSec}, priority = Priority,
			     idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
			     packet_count = PacketCount, byte_count = ByteCount,
			     nx_match = decode_nx_matches(NxMatch),
			     actions = decode_actions(Actions)},
    decode_stats_reply(nxst_flow, [R|Acc], Rest);

decode_stats_reply(nxst_aggregate, Acc, <<PacketCount:64/integer, ByteCount:64/integer, FlowCount:32/integer, _Pad:4/bytes, Rest/binary>>) ->
    R = #ofp_nxst_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount,
				  flow_count = FlowCount},
    decode_stats_reply(nxst_aggregate, [R|Acc], Rest);

decode_stats_reply(vendor, Acc, <<Vendor:32/integer, Msg/binary>>) ->
    decode_vendor_stats(vendor(Vendor), Acc, Msg).

decode_vendor_stats(nicira, Acc, <<SubType:32/integer, _Pad:4/bytes, Msg/binary>>) ->
    decode_stats_reply(ofp_vendor_stats_type({nicira, SubType}), Acc, Msg).

%%%===================================================================
%%% Encode
%%%===================================================================
-spec encode_ovs_vendor({Vendor :: atom(), Cmd :: non_neg_integer()}, binary()) -> binary();
		       ({Vendor :: non_neg_integer(), Cmd :: non_neg_integer()}, binary()) -> binary();
		       (Cmd :: of_vendor_ext(), binary()) -> binary().
encode_ovs_vendor({Vendor, Cmd}, Data)
  when is_atom(Vendor) ->
    encode_ovs_vendor({vendor(Vendor), Cmd}, Data);
encode_ovs_vendor({Vendor, Cmd}, Data) ->
    << Vendor:32, Cmd:32, Data/binary >>;
encode_ovs_vendor(Cmd, Data) ->
    encode_ovs_vendor(of_vendor_ext(Cmd), Data).

-spec encode_ofp_switch_features(integer(), integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_switch_features(DataPathId, NBuffers, NTables, Capabilities, Actions, Ports) ->
    <<DataPathId:64, NBuffers:32, NTables:8, 0:24, Capabilities:32, Actions:32, Ports/binary>>.

-spec encode_ofp_error(non_neg_integer(), non_neg_integer(), binary()) -> binary().
encode_ofp_error(Type, Code, Data) ->
    <<Type:16/integer, Code:16/integer, Data/binary>>.

-spec encode_phy_port(integer(), binary(), binary(), integer(), integer(), integer(), integer(), integer(), integer()) -> binary().
encode_phy_port(PortNo, HwAddr, Name, Config, State,Curr, Advertised, Supported, Peer) ->
    Name0 = pad_to(16, Name),
    <<PortNo:16, HwAddr:6/bytes, Name0:16/bytes, Config:32, State:32, Curr:32, Advertised:32, Supported:32, Peer:32>>.

encode_phy_port(#ofp_phy_port{port_no = PortNo,
			      hw_addr = HwAddr,
			      name = Name,
			      config = Config,
			      state = State,
			      curr = Curr,
			      advertised = Advertised,
			      supported = Supported,
			      peer = Peer}) ->
    encode_phy_port(ofp_port(PortNo), HwAddr, Name, 
		    enc_flags(ofp_port_config(), Config),
		    enc_flags(ofp_port_state(), State),
		    enc_flags(ofp_port_features(), Curr),
		    enc_flags(ofp_port_features(), Advertised),
		    enc_flags(ofp_port_features(), Supported),
		    enc_flags(ofp_port_features(), Peer)).

encode_phy_ports(Ports) ->
    << << (encode_phy_port(P))/binary >> || P <- Ports >>.

encode_ofp_port_status(Reason, Port) ->
    Reason0 = ofp_port_reason(Reason),
    <<Reason0:8, 0:56, Port/binary>>.

-spec encode_queue_get_config_request(integer()) -> binary().
encode_queue_get_config_request(Port) ->
    <<Port:16>>.

encode_ofp_queue_prop(none) ->
    <<>>;
encode_ofp_queue_prop(#ofp_queue_prop_min_rate{rate = Rate}) ->
    <<Rate:16>>.

encode_ofp_packet_queue(#ofp_packet_queue{queue_id = QueueId, properties = Properties}) ->
    Props = << << (pad_to(8, encode_ofp_queue_prop(P)))/binary >> || P <- Properties >>,
    Len = size(Props) + 8,
    <<QueueId:32, Len:16, 0:16, Props/binary>>.

-spec encode_ofp_packet_queues([#ofp_packet_queue{}]) -> binary().
encode_ofp_packet_queues(Queues) ->
    << << (encode_ofp_packet_queue(Q))/binary >> || Q <- Queues >>.

-spec encode_ofp_queue_get_config_reply(integer(), binary()) -> binary().
encode_ofp_queue_get_config_reply(Port, Queues) ->
    <<Port:16, 0:48, Queues/binary>>.

-spec encode_ofp_switch_config(integer(), integer()) -> binary().
encode_ofp_switch_config(Flags, MissSendLen) ->
    <<Flags:16, MissSendLen:16>>.

-spec bool(boolean()) -> 0 | 1;
	  (non_neg_integer()) -> boolean().
bool(true) -> 1;
bool(false) -> 0;
bool(0) -> false;
bool(_) -> true.

int_maybe_undefined(X) when is_integer(X) -> X;
int_maybe_undefined(undefined) -> 0.

bin_maybe_undefined(X, Len) when is_binary(X) -> pad_to(Len, X);
bin_maybe_undefined(undefined, Len) -> pad_to(Len, <<0>>).

bin_fixed_length(X, Len) when size(X) > Len -> binary_part(X, {0, Len});
bin_fixed_length(X, Len) -> bin_maybe_undefined(X, Len).

-spec encode_ofp_match(integer(), ofp_port(), binary(), binary(), integer(),
		       integer(), integer()|atom(), integer(), integer()|atom(),
		       binary(), binary(), integer(), integer()) -> binary().
encode_ofp_match(Wildcards, InPort, DlSrc, DlDst, DlVlan, DlVlanPcp, DlType,
		 NwTos, NwProto, NwSrc, NwDst, TpSrc, TpDst) when DlType == arp ->
    InPort0 = ofp_port(InPort),
    DlType0 = eth_type(DlType),
    NwProto0 = int_maybe_undefined(flower_arp:op(NwProto)),
    NwSrc0 = bin_maybe_undefined(NwSrc, 4),
    NwDst0 = bin_maybe_undefined(NwDst, 4),
    TpSrc0 = int_maybe_undefined(TpSrc),
    TpDst0 = int_maybe_undefined(TpDst),
    <<Wildcards:32, InPort0:16, DlSrc:6/binary, DlDst:6/binary, DlVlan:16, DlVlanPcp:8,
      0:8, DlType0:16, NwTos:8, NwProto0:8, 0:16, NwSrc0:4/binary, NwDst0:4/binary, TpSrc0:16, TpDst0:16>>;

encode_ofp_match(Wildcards, InPort, DlSrc, DlDst, DlVlan, DlVlanPcp, DlType,
		 NwTos, NwProto, NwSrc, NwDst, TpSrc, TpDst) ->
    InPort0 = ofp_port(InPort),
    DlType0 = eth_type(DlType),
    NwProto0 = int_maybe_undefined(protocol(NwProto)),
    NwSrc0 = bin_maybe_undefined(NwSrc, 4),
    NwDst0 = bin_maybe_undefined(NwDst, 4),
    TpSrc0 = int_maybe_undefined(TpSrc),
    TpDst0 = int_maybe_undefined(TpDst),
    <<Wildcards:32, InPort0:16, DlSrc:6/binary, DlDst:6/binary, DlVlan:16, DlVlanPcp:8,
      0:8, DlType0:16, NwTos:8, NwProto0:8, 0:16, NwSrc0:4/binary, NwDst0:4/binary, TpSrc0:16, TpDst0:16>>.

-spec encode_ofs_action(int16(), binary()) -> binary().
encode_ofs_action(Type, Data) ->
    Len = 4 + size(Data),
    <<Type:16, Len:16, Data/binary>>.

-spec encode_ofs_action_output(ofp_port(), int16()) -> binary().
encode_ofs_action_output(Port, MaxLen) ->
    Port0 = ofp_port(Port),
    encode_ofs_action(0, <<Port0:16, MaxLen:16>>).

-spec encode_ofs_action_vlan_vid(int16()) -> binary().
encode_ofs_action_vlan_vid(VlanVid) ->
    encode_ofs_action(1, <<VlanVid:16, 0:16>>).

-spec encode_ofs_action_vlan_pcp(int8()) -> binary().
encode_ofs_action_vlan_pcp(VlanPcp) ->
    encode_ofs_action(2, <<VlanPcp:8, 0:24>>).

-spec encode_ofs_action_strip_vlan() -> binary().
encode_ofs_action_strip_vlan() ->
    encode_ofs_action(3, <<0:32>>).

-spec encode_ofs_action_dl_addr(ofp_addr_type(), binary()) -> binary().
encode_ofs_action_dl_addr(src, Addr) ->
    encode_ofs_action(4, <<Addr:6/bytes, 0:48>>);
encode_ofs_action_dl_addr(dst, Addr) ->
    encode_ofs_action(5, <<Addr:6/bytes, 0:48>>).

-spec encode_ofs_action_nw_addr(ofp_addr_type(), binary()) -> binary().
encode_ofs_action_nw_addr(src, Addr) ->
    encode_ofs_action(6, <<Addr:4/bytes>>);
encode_ofs_action_nw_addr(dst, Addr) ->
    encode_ofs_action(7, <<Addr:4/bytes>>).

-spec encode_ofs_action_nw_tos(int8()) -> binary().
encode_ofs_action_nw_tos(NwTos) ->
    encode_ofs_action(8, <<NwTos:8, 0:24>>).

-spec encode_ofs_action_tp_addr(ofp_addr_type(), int16()) -> binary().
encode_ofs_action_tp_addr(src, TpPort) ->
    encode_ofs_action(9, <<TpPort:16, 0:16>>);
encode_ofs_action_tp_addr(dst, TpPort) ->
    encode_ofs_action(10, <<TpPort:16, 0:16>>).

-spec encode_ofs_action_enqueue(ofp_port(), int32()) -> binary().
encode_ofs_action_enqueue(Port, QueueId) ->
    Port0 = ofp_port(Port),
    encode_ofs_action(11, <<Port0:16, 0:48, QueueId:32>>).

-spec encode_ofs_action_vendor(int32(), binary()) -> binary().
encode_ofs_action_vendor(Vendor, Msg) ->
    Data = pad_to(8, Msg),
    encode_ofs_action(16#FFFF, <<Vendor:32, Data/binary>>).

-spec encode_ofp_flow_mod(Match :: binary(), Cookie :: integer(), Command :: ofp_command() | non_neg_integer(),
			  IdleTimeout :: integer(), HardTimeout:: integer(),
			  Priority :: integer(), BufferId :: integer(), OutPort :: ofp_port(),
			  Flags :: integer(), Actions :: binary()|list(binary)) -> binary().
encode_ofp_flow_mod(Match, Cookie, Command, IdleTimeout, HardTimeout, Priority,
		    BufferId, OutPort, Flags, Actions) when is_list(Actions) ->
    encode_ofp_flow_mod(Match, Cookie, Command, IdleTimeout, HardTimeout, Priority,
			BufferId, OutPort, Flags, list_to_binary(Actions));
encode_ofp_flow_mod(Match, Cookie, Command, IdleTimeout, HardTimeout, Priority,
		    BufferId, OutPort, Flags, Actions) ->
    OutPort0 = ofp_port(OutPort),
    Cmd = ofp_flow_mod_command(Command),
    <<Match/binary, Cookie:64, Cmd:16, IdleTimeout:16, HardTimeout:16,
      Priority:16, BufferId:32, OutPort0:16, Flags:16, Actions/binary>>.

-spec encode_ofp_flow_removed(binary(), integer(), integer(), integer()|atom(), tuple(integer(), integer()), integer(), integer(), integer()) -> binary().
encode_ofp_flow_removed(Match, Cookie, Priority, Reason, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount) when is_atom(Reason) ->
    Reason0 = ofp_flow_removed_reason(Reason),
    encode_ofp_flow_removed(Match, Cookie, Priority, Reason0, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount);
encode_ofp_flow_removed(Match, Cookie, Priority, Reason, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount) ->
    <<Match/binary, Cookie:64, Priority:16, Reason:8, 0:8, DurationSec:32, DurationNSec:32, IdleTimeout:16, 0:16,
      PacketCount:64, ByteCount:64>>.

-spec encode_ofp_packet_in(integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_packet_in(BufferId, TotalLen, InPort, Reason, Data) ->
    <<BufferId:32, TotalLen:16, InPort:16, Reason:8, 0:8, Data/binary>>.

-spec encode_ofp_packet_out(integer(), integer()|atom(), binary(), list(binary())|binary()) -> binary().
encode_ofp_packet_out(BufferId, InPort, Actions, Data) when is_list(Actions) ->
    encode_ofp_packet_out(BufferId, InPort, list_to_binary(Actions), Data);
encode_ofp_packet_out(BufferId, InPort, Actions, Data) ->
    InPort0 = ofp_port(InPort),
    <<BufferId:32, InPort0:16, (size(Actions)):16, Actions/binary, Data/binary>>.

-spec encode_ofp_port_mod(integer(), binary(), integer(), integer(), integer()) -> binary().
encode_ofp_port_mod(PortNo, HwAddr, Config, Mask, Advertise) ->
    <<PortNo:16, HwAddr/binary, Config:32, Mask:32, Advertise:32>>.

encode_ofp_desc_stats(MfrDesc, HwDesc, SwDesc, SerialNum, DpDesc) ->
    MfrDesc0 = bin_fixed_length(MfrDesc, 256),
    HwDesc0 = bin_fixed_length(HwDesc, 256),
    SwDesc0 = bin_fixed_length(SwDesc, 256),
    SerialNum0 = bin_fixed_length(SerialNum, 32),
    DpDesc0 = bin_fixed_length(DpDesc, 256),
    <<MfrDesc0:256/bytes, HwDesc0:256/bytes, SwDesc0:256/bytes, SerialNum0:32/bytes, DpDesc0:256/bytes>>.

encode_ofp_flow_stats_request(Match, TableId, OutPort) ->
    TableId0 = ofp_table(TableId),
    OutPort0 = ofp_port(OutPort),
    <<Match/binary, TableId0:8, 0:8, OutPort0:16>>.

encode_ofp_flow_stats(TableId, Match, {Sec, NSec} = _Duration, Priority, IdleTimeout, HardTimeout, Cookie, PacketCount, ByteCount, Actions) ->
    Length = 88 + size(Actions),
    <<Length:16, TableId:8, 0:8, Match/binary, Sec:32, NSec:32, Priority:16, IdleTimeout:16, HardTimeout:16, 0:48,
      Cookie:64, PacketCount:64, ByteCount:64, Actions/binary>>.

encode_ofp_aggregate_stats_request(Match, TableId, OutPort) ->
    TableId0 = ofp_table(TableId),
    OutPort0 = ofp_port(OutPort),
    <<Match/binary, TableId0:8, 0:8, OutPort0:16>>.

encode_ofp_aggregate_stats(PacketCount, ByteCount, FlowCount) ->
    <<PacketCount:64, ByteCount:64, FlowCount:32, 0:32>>.

encode_ofp_table_stats(TableId, Name, Wildcards, MaxEntries, ActiveCount, LookupCount, MatchedCount) ->
    Name0 = bin_fixed_length(Name, 32),
    <<TableId:8, 0:24, Name0/binary, Wildcards:32, MaxEntries:32, ActiveCount:32, LookupCount:64, MatchedCount:64>>.

encode_ofp_port_stats_request(Port) ->
    Port0 = ofp_port(Port),
    <<Port0:16, 0:48>>.

encode_ofp_port_stats(Port, RxPackets, TxPackets, RxBytes, TxBytes, RxDropped, TxDropped,
		      RxErrors, TxErrors, RxFrameErr, RxOverErr, RxCrcErr, Collisions) ->
    <<Port:16, 0:48, RxPackets:64, TxPackets:64, RxBytes:64, TxBytes:64, RxDropped:64, TxDropped:64,
      RxErrors:64, TxErrors:64, RxFrameErr:64, RxOverErr:64, RxCrcErr:64, Collisions:64>>.

encode_ofp_queue_stats_request(Port, Queue) ->
    Port0 = ofp_port(Port),
    Queue0 = ofp_queue(Queue),
    <<Port0:16, 0:16, Queue0:32>>.

encode_ofp_queue_stats(Port, Queue, TxBytes, TxPackets, TxErrors) ->
    <<Port:16, 0:16, Queue:32, TxBytes:64, TxPackets:64, TxErrors:64>>.

encode_ofp_nxst_flow_stats_request(OutPort, TableId, NxMatch) ->
    OutPort0 = ofp_port(OutPort),
    TableId0 = ofp_table(TableId),
    <<OutPort0:16, (size(NxMatch)):16, TableId0:8, 0:24, (pad_to(8, NxMatch))/binary>>.

encode_ofp_nxst_flow_stats(TableId, {Sec, NSec} = _Duration, Priority, IdleTimeout, HardTimeout, Cookie, PacketCount, ByteCount, NxMatch, Actions) ->
    Length = 48 + size(NxMatch) + pad_length(8, size(NxMatch)) + size(Actions),
    <<Length:16, TableId:8, 0:8, Sec:32, NSec:32, Priority:16, IdleTimeout:16, HardTimeout:16, (size(NxMatch)):16, 0:32,
      Cookie:64, PacketCount:64, ByteCount:64, (pad_to(8, NxMatch))/binary, Actions/binary>>.

encode_ofp_nxst_aggregate_stats_request(OutPort, TableId, NxMatch) ->
    OutPort0 = ofp_port(OutPort),
    TableId0 = ofp_table(TableId),
    <<OutPort0:16, (size(NxMatch)):16, TableId0:8, 0:24, (pad_to(8, NxMatch))/binary>>.

encode_ofp_nxst_aggregate_stats(PacketCount, ByteCount, FlowCount) ->
    <<PacketCount:64, ByteCount:64, FlowCount:32, 0:32>>.

encode_ofp_stats_request(Type, Body) when is_atom(Type) ->
    encode_ofp_stats_request(ofp_stats_type(Type), Body);
encode_ofp_stats_request(Type, Body) when is_integer(Type) ->
    <<Type:16, 0:16, Body/binary>>.

encode_ofp_vendor_stats_request(Type, Body) when is_atom(Type) ->
    encode_ofp_vendor_stats_request(ofp_vendor_stats_type(Type), Body);
encode_ofp_vendor_stats_request({nicira, SubType}, Body) ->
    encode_ofp_stats_request(vendor, <<(vendor(nicira)):32, SubType:32, 0:32, Body/binary>>).

%% TODO: we don't support flags in stats replies...
encode_ofp_stats({vendor, Type}, Body) ->
    encode_ofp_vendor_stats(Type, Body);
encode_ofp_stats(Type, Body) when is_atom(Type) ->
    encode_ofp_stats(ofp_stats_type(Type), Body);
encode_ofp_stats(Type, Body) when is_integer(Type) ->
    <<Type:16, 0:16, Body/binary>>.

encode_ofp_vendor_stats(Type, Body) when is_atom(Type) ->
    encode_ofp_vendor_stats(ofp_vendor_stats_type(Type), Body);
encode_ofp_vendor_stats({nicira, SubType}, Body) ->
    encode_ofp_stats(vendor, <<(vendor(nicira)):32, SubType:32, 0:32, Body/binary>>).

-spec encode_nxt_flow_mod_table_id(integer()|boolean()) -> binary().
encode_nxt_flow_mod_table_id(Set)
  when is_boolean(Set)->
    encode_nxt_flow_mod_table_id(bool(Set));
encode_nxt_flow_mod_table_id(Set) ->
    encode_ovs_vendor(nxt_flow_mod_table_id, <<Set:8>>).

-spec encode_nxt_role_request(integer()|atom()) -> binary().
encode_nxt_role_request(Role)
  when is_atom(Role) ->
    encode_nxt_role_request(nxt_role(Role));
encode_nxt_role_request(Role) ->
    encode_ovs_vendor(nxt_role_request, <<Role:32>>).

-spec enc_nxm_match(Header :: binary(), {Value :: binary(), Mask :: binary()}) -> binary();
		   (Header :: binary(), Value :: binary()) -> binary().
enc_nxm_match(<<_Vendor:16, _Field:7, 1:1, Length:8>> = Header, {Value, Mask})
  when is_binary(Value), is_binary(Mask) ->
    Len = Length div 2,
    <<Header/binary, Value:Len/bytes, Mask:Len/bytes>>;
enc_nxm_match(<<_Vendor:16, _Field:7, 0:1, Length:8>> = Header, Value)
  when is_binary(Value) ->
    <<Header/binary, Value:Length/bytes>>.

-spec encode_nx_matches([{nxm_header(), term()}], [binary()]) -> binary().
encode_nx_matches([], Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_nx_matches([{Header, Value}|Rest], Acc) ->
    encode_nx_matches(Rest, [enc_nxm_match(nxm_header(Header), Value)|Acc]).

-spec encode_nx_matches([{nxm_header(), term()}]) -> binary().
encode_nx_matches(NxMatch) ->
    encode_nx_matches(NxMatch, []).

-spec encode_nx_flow_mod(Cookie :: non_neg_integer(),
			 Command :: term(),
			 IdleTimeout :: non_neg_integer(),
			 HardTimeout :: non_neg_integer(),
			 Priority :: non_neg_integer(),
			 BufferId :: non_neg_integer(),
			 OutPort :: ofp_port(),
			 Flags :: non_neg_integer(),
			 NxMatch :: binary(),
			 Actions :: binary()) -> binary().
encode_nx_flow_mod(Cookie, Command, IdleTimeout, HardTimeout, Priority,
		   BufferId, OutPort, Flags, NxMatch, Actions) ->
    OutPort0 = ofp_port(OutPort),
    Cmd = ofp_flow_mod_command(Command),
    encode_ovs_vendor(nxt_flow_mod,
		      <<Cookie:64, Cmd:16, IdleTimeout:16, HardTimeout:16,
			Priority:16, BufferId:32, OutPort0:16, Flags:16,
			(size(NxMatch)):16, 0:48, (pad_to(8, NxMatch))/binary,
			Actions/binary>>).


-define(NXM_HEADER(Vendor, Field, HasMask, Length),	<<Vendor:16, Field:7, HasMask:1, Length:8>>).
-define(NXM_HEADER(Vendor, Field, Length), ?NXM_HEADER(Vendor, Field, 0, Length)).
-define(NXM_HEADER_W(Vendor, Field, Length), ?NXM_HEADER(Vendor, Field, 1, ((Length) * 2))).

-define(NXM_OF_IN_PORT,    ?NXM_HEADER  (16#0000,  0, 2)).
-define(NXM_OF_ETH_DST,    ?NXM_HEADER  (16#0000,  1, 6)).
-define(NXM_OF_ETH_DST_W,  ?NXM_HEADER_W(16#0000,  1, 6)).
-define(NXM_OF_ETH_SRC,    ?NXM_HEADER  (16#0000,  2, 6)).
-define(NXM_OF_ETH_TYPE,   ?NXM_HEADER  (16#0000,  3, 2)).
-define(NXM_OF_VLAN_TCI,   ?NXM_HEADER  (16#0000,  4, 2)).
-define(NXM_OF_VLAN_TCI_W, ?NXM_HEADER_W(16#0000,  4, 2)).
-define(NXM_OF_IP_TOS,     ?NXM_HEADER  (16#0000,  5, 1)).
-define(NXM_OF_IP_PROTO,   ?NXM_HEADER  (16#0000,  6, 1)).
-define(NXM_OF_IP_SRC,     ?NXM_HEADER  (16#0000,  7, 4)).
-define(NXM_OF_IP_SRC_W,   ?NXM_HEADER_W(16#0000,  7, 4)).
-define(NXM_OF_IP_DST,     ?NXM_HEADER  (16#0000,  8, 4)).
-define(NXM_OF_IP_DST_W,   ?NXM_HEADER_W(16#0000,  8, 4)).
-define(NXM_OF_TCP_SRC,    ?NXM_HEADER  (16#0000,  9, 2)).
-define(NXM_OF_TCP_DST,    ?NXM_HEADER  (16#0000, 10, 2)).
-define(NXM_OF_UDP_SRC,    ?NXM_HEADER  (16#0000, 11, 2)).
-define(NXM_OF_UDP_DST,    ?NXM_HEADER  (16#0000, 12, 2)).
-define(NXM_OF_ICMP_TYPE,  ?NXM_HEADER  (16#0000, 13, 1)).
-define(NXM_OF_ICMP_CODE,  ?NXM_HEADER  (16#0000, 14, 1)).
-define(NXM_OF_ARP_OP,     ?NXM_HEADER  (16#0000, 15, 2)).
-define(NXM_OF_ARP_SPA,    ?NXM_HEADER  (16#0000, 16, 4)).
-define(NXM_OF_ARP_SPA_W,  ?NXM_HEADER_W(16#0000, 16, 4)).
-define(NXM_OF_ARP_TPA,    ?NXM_HEADER  (16#0000, 17, 4)).
-define(NXM_OF_ARP_TPA_W,  ?NXM_HEADER_W(16#0000, 17, 4)).

-define(NXM_NX_TUN_ID,     ?NXM_HEADER  (16#0001, 16, 8)).
-define(NXM_NX_TUN_ID_W,   ?NXM_HEADER_W(16#0001, 16, 8)).
-define(NXM_NX_ARP_SHA,    ?NXM_HEADER  (16#0001, 17, 6)).
-define(NXM_NX_ARP_THA,    ?NXM_HEADER  (16#0001, 18, 6)).

-define(NXM_NX_IPV6_SRC,    ?NXM_HEADER  (16#0001, 19, 16)).
-define(NXM_NX_IPV6_SRC_W,  ?NXM_HEADER_W(16#0001, 19, 16)).
-define(NXM_NX_IPV6_DST,    ?NXM_HEADER  (16#0001, 20, 16)).
-define(NXM_NX_IPV6_DST_W,  ?NXM_HEADER_W(16#0001, 20, 16)).
-define(NXM_NX_ICMPV6_TYPE, ?NXM_HEADER  (16#0001, 21, 1)).
-define(NXM_NX_ICMPV6_CODE, ?NXM_HEADER  (16#0001, 22, 1)).
-define(NXM_NX_ND_TARGET,   ?NXM_HEADER  (16#0001, 23, 16)).
-define(NXM_NX_ND_SLL,      ?NXM_HEADER  (16#0001, 24, 6)).
-define(NXM_NX_ND_TLL,      ?NXM_HEADER  (16#0001, 25, 6)).

-spec nxm_header(Header :: nxm_header()) -> binary();
		(Header :: binary()) -> nxm_header() | binary().
nxm_header(nxm_of_in_port)	-> ?NXM_OF_IN_PORT;
nxm_header(nxm_of_eth_dst)	-> ?NXM_OF_ETH_DST;
nxm_header(nxm_of_eth_dst_w)	-> ?NXM_OF_ETH_DST_W;
nxm_header(nxm_of_eth_src)	-> ?NXM_OF_ETH_SRC;
nxm_header(nxm_of_eth_type)	-> ?NXM_OF_ETH_TYPE;
nxm_header(nxm_of_vlan_tci)	-> ?NXM_OF_VLAN_TCI;
nxm_header(nxm_of_vlan_tci_w)	-> ?NXM_OF_VLAN_TCI_W;
nxm_header(nxm_of_ip_tos)	-> ?NXM_OF_IP_TOS;
nxm_header(nxm_of_ip_proto)	-> ?NXM_OF_IP_PROTO;
nxm_header(nxm_of_ip_src)	-> ?NXM_OF_IP_SRC;
nxm_header(nxm_of_ip_src_w)	-> ?NXM_OF_IP_SRC_W;
nxm_header(nxm_of_ip_dst)	-> ?NXM_OF_IP_DST;
nxm_header(nxm_of_ip_dst_w)	-> ?NXM_OF_IP_DST_W;
nxm_header(nxm_of_tcp_src)	-> ?NXM_OF_TCP_SRC;
nxm_header(nxm_of_tcp_dst)	-> ?NXM_OF_TCP_DST;
nxm_header(nxm_of_udp_src)	-> ?NXM_OF_UDP_SRC;
nxm_header(nxm_of_udp_dst)	-> ?NXM_OF_UDP_DST;
nxm_header(nxm_of_icmp_type)	-> ?NXM_OF_ICMP_TYPE;
nxm_header(nxm_of_icmp_code)	-> ?NXM_OF_ICMP_CODE;
nxm_header(nxm_of_arp_op)	-> ?NXM_OF_ARP_OP;
nxm_header(nxm_of_arp_spa)	-> ?NXM_OF_ARP_SPA;
nxm_header(nxm_of_arp_spa_w)	-> ?NXM_OF_ARP_SPA_W;
nxm_header(nxm_of_arp_tpa)	-> ?NXM_OF_ARP_TPA;
nxm_header(nxm_of_arp_tpa_w)	-> ?NXM_OF_ARP_TPA_W;

nxm_header(nxm_nx_tun_id)	-> ?NXM_NX_TUN_ID;
nxm_header(nxm_nx_tun_id_w)	-> ?NXM_NX_TUN_ID_W;
nxm_header(nxm_nx_arp_sha)	-> ?NXM_NX_ARP_SHA;
nxm_header(nxm_nx_arp_tha)	-> ?NXM_NX_ARP_THA;

nxm_header(nxm_nx_ipv6_src)	-> ?NXM_NX_IPV6_SRC;
nxm_header(nxm_nx_ipv6_src_w)	-> ?NXM_NX_IPV6_SRC_W;
nxm_header(nxm_nx_ipv6_dst)	-> ?NXM_NX_IPV6_DST;
nxm_header(nxm_nx_ipv6_dst_w)	-> ?NXM_NX_IPV6_DST_W;
nxm_header(nxm_nx_icmpv6_type)	-> ?NXM_NX_ICMPV6_TYPE;
nxm_header(nxm_nx_icmpv6_code)	-> ?NXM_NX_ICMPV6_CODE;
nxm_header(nxm_nx_nd_target)	-> ?NXM_NX_ND_TARGET;
nxm_header(nxm_nx_nd_sll)	-> ?NXM_NX_ND_SLL;
nxm_header(nxm_nx_nd_tll)	-> ?NXM_NX_ND_TLL;

nxm_header({nxm_nx_reg, X})	-> ?NXM_HEADER  (16#0001, X, 4);
nxm_header({nxm_nx_reg_w, X})	-> ?NXM_HEADER_W(16#0001, X, 4);

nxm_header(?NXM_OF_IN_PORT)     -> nxm_of_in_port;
nxm_header(?NXM_OF_ETH_DST)     -> nxm_of_eth_dst;
nxm_header(?NXM_OF_ETH_DST_W)   -> nxm_of_eth_dst_w;
nxm_header(?NXM_OF_ETH_SRC)     -> nxm_of_eth_src;
nxm_header(?NXM_OF_ETH_TYPE)    -> nxm_of_eth_type;
nxm_header(?NXM_OF_VLAN_TCI)    -> nxm_of_vlan_tci;
nxm_header(?NXM_OF_VLAN_TCI_W)  -> nxm_of_vlan_tci_w;
nxm_header(?NXM_OF_IP_TOS)      -> nxm_of_ip_tos;
nxm_header(?NXM_OF_IP_PROTO)    -> nxm_of_ip_proto;
nxm_header(?NXM_OF_IP_SRC)      -> nxm_of_ip_src;
nxm_header(?NXM_OF_IP_SRC_W)    -> nxm_of_ip_src_w;
nxm_header(?NXM_OF_IP_DST    )  -> nxm_of_ip_dst;
nxm_header(?NXM_OF_IP_DST_W)    -> nxm_of_ip_dst_w;
nxm_header(?NXM_OF_TCP_SRC    ) -> nxm_of_tcp_src;
nxm_header(?NXM_OF_TCP_DST)     -> nxm_of_tcp_dst;
nxm_header(?NXM_OF_UDP_SRC)     -> nxm_of_udp_src;
nxm_header(?NXM_OF_UDP_DST)     -> nxm_of_udp_dst;
nxm_header(?NXM_OF_ICMP_TYPE)   -> nxm_of_icmp_type;
nxm_header(?NXM_OF_ICMP_CODE)   -> nxm_of_icmp_code;
nxm_header(?NXM_OF_ARP_OP)      -> nxm_of_arp_op;
nxm_header(?NXM_OF_ARP_SPA)     -> nxm_of_arp_spa;
nxm_header(?NXM_OF_ARP_SPA_W)   -> nxm_of_arp_spa_w;
nxm_header(?NXM_OF_ARP_TPA)     -> nxm_of_arp_tpa;
nxm_header(?NXM_OF_ARP_TPA_W)   -> nxm_of_arp_tpa_w;

nxm_header(?NXM_NX_TUN_ID)      -> nxm_nx_tun_id;
nxm_header(?NXM_NX_TUN_ID_W)    -> nxm_nx_tun_id_w;
nxm_header(?NXM_NX_ARP_SHA)     -> nxm_nx_arp_sha;
nxm_header(?NXM_NX_ARP_THA)     -> nxm_nx_arp_tha;

nxm_header(?NXM_NX_IPV6_SRC)    -> nxm_nx_ipv6_src;
nxm_header(?NXM_NX_IPV6_SRC_W)  -> nxm_nx_ipv6_src_w;
nxm_header(?NXM_NX_IPV6_DST)    -> nxm_nx_ipv6_dst;
nxm_header(?NXM_NX_IPV6_DST_W)  -> nxm_nx_ipv6_dst_w;
nxm_header(?NXM_NX_ICMPV6_TYPE) -> nxm_nx_icmpv6_type;
nxm_header(?NXM_NX_ICMPV6_CODE) -> nxm_nx_icmpv6_code;
nxm_header(?NXM_NX_ND_TARGET)   -> nxm_nx_nd_target;
nxm_header(?NXM_NX_ND_SLL)      -> nxm_nx_nd_sll;
nxm_header(?NXM_NX_ND_TLL)      -> nxm_nx_nd_tll;

nxm_header(?NXM_HEADER  (16#0001, X, 4)) -> {nxm_nx_reg, X};
nxm_header(?NXM_HEADER_W(16#0001, X, 4)) -> {nxm_nx_reg_w, X};

nxm_header(X) when is_binary(X) -> X.

-spec encode_nx_action(Action :: nxt_action(), Data :: binary()) -> binary().
encode_nx_action(Action, Data) ->
    Act = nxt_action(Action),
    encode_ofs_action_vendor(vendor(nicira), <<Act:16, Data/binary>>).

-spec encode_nx_action_resubmit(InPort :: non_neg_integer()) -> binary().
encode_nx_action_resubmit(InPort) ->
    InPort0 = ofp_port(InPort),
    encode_nx_action(nxast_resubmit, << InPort0:16 >>).

-spec encode_nx_action_set_tunnel(TunId :: non_neg_integer()) -> binary().
encode_nx_action_set_tunnel(TunId) ->
    encode_nx_action(nxast_set_tunnel, << 0:16, TunId:32 >>).

-spec encode_nx_action_set_tunnel64(TunId :: non_neg_integer()) -> binary().
encode_nx_action_set_tunnel64(TunId) ->
    encode_nx_action(nxast_set_tunnel64, << 0:48, TunId:64 >>).

-spec encode_nx_action_set_queue(QueueId :: non_neg_integer()) -> binary().
encode_nx_action_set_queue(QueueId) ->
    encode_nx_action(nxast_set_queue, << 0:16, QueueId:32 >>).

-spec encode_nx_action_pop_queue() -> binary().
encode_nx_action_pop_queue() ->
    encode_nx_action(nxast_pop_queue, << 0:48 >>).

-spec encode_nx_action_reg_move(Nbits :: non_neg_integer(),
				SrcOfs :: non_neg_integer(),
				DstOfs :: non_neg_integer(),
				Src :: binary() | nxm_header(),
				Dst :: binary() | nxm_header()) -> binary().
encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, Src, Dst)
  when is_atom(Src); is_atom(Dst); is_tuple(Dst) ->
    encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, nxm_header(Src), nxm_header(Dst));
encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, Src, Dst) ->
    encode_nx_action(nxast_reg_move, << Nbits:16, SrcOfs:16, DstOfs:16, Src/binary, Dst/binary>>).

-spec encode_nx_action_reg_load(Ofs :: non_neg_integer(),
				Nbits :: non_neg_integer(),
				Dst :: binary() | nxm_header(),
				Value :: binary()) -> binary().
encode_nx_action_reg_load(Ofs, Nbits, Dst, Value)
  when is_atom(Dst); is_tuple(Dst) ->
    encode_nx_action_reg_load(Ofs, Nbits, nxm_header(Dst), Value);
encode_nx_action_reg_load(Ofs, Nbits, Dst, Value) ->
    encode_nx_action(nxast_reg_load, << Ofs:10, Nbits:6, Dst/binary, (pad_to(8, Value))/binary >>).

-spec encode_nx_action_note(list() | binary()) -> binary().
encode_nx_action_note(Note)
  when is_list(Note) ->
    encode_nx_action(nxast_note, list_to_binary(Note));
encode_nx_action_note(Note)
  when is_binary(Note) ->
    encode_nx_action(nxast_note, Note).

-spec encode_nx_action_multipath(term(),term(),term(),term(),term(),term(),term(),term()) -> no_return().
encode_nx_action_multipath(_Fields, _Basis, _Algo, _MaxLink, _Arg, _Ofs, _Nbits, _Dst) -> not_impl().

-spec encode_nx_action_autopath(term(),term(),term(),term()) -> no_return().
encode_nx_action_autopath(_Ofs, _Nbits, _Dst, _Id) -> not_impl().

encode_action(#ofp_action_output{port = Port, max_len = MaxLen}) ->
    encode_ofs_action_output(Port, MaxLen);

encode_action(#ofp_action_vlan_vid{vlan_vid = VlanVid}) ->
    encode_ofs_action_vlan_vid(VlanVid);

encode_action(#ofp_action_vlan_pcp{vlan_pcp = VlanPcp}) ->
    encode_ofs_action_vlan_pcp(VlanPcp);

encode_action(#ofp_action_strip_vlan{}) ->
    encode_ofs_action_strip_vlan();

encode_action(#ofp_action_dl_addr{type = Type, dl_addr = DlAddr}) ->
    encode_ofs_action_dl_addr(Type, DlAddr);

encode_action(#ofp_action_nw_addr{type = Type, nw_addr = NwAddr}) ->
    encode_ofs_action_nw_addr(Type, NwAddr);

encode_action(#ofp_action_nw_tos{nw_tos = NwTos}) ->
    encode_ofs_action_nw_tos(NwTos);

encode_action(#ofp_action_tp_port{type = Type, tp_port = TpPort}) ->
    encode_ofs_action_tp_addr(Type, TpPort);

encode_action(#ofp_action_enqueue{port = Port, queue_id = QueueId}) ->
    encode_ofs_action_enqueue(Port, QueueId);

encode_action(#ofp_action_vendor{vendor = Vendor, msg = Msg}) ->
    encode_ofs_action_vendor(Vendor, Msg);

encode_action(#nx_action_resubmit{in_port = InPort}) ->
    encode_nx_action_resubmit(InPort);
encode_action(#nx_action_set_tunnel{tun_id = TunId}) ->
    encode_nx_action_set_tunnel(TunId);
encode_action(#nx_action_set_tunnel64{tun_id = TunId}) ->
    encode_nx_action_set_tunnel64(TunId);
encode_action(#nx_action_set_queue{queue_id = QueueId}) ->
    encode_nx_action_set_queue(QueueId);
encode_action(#nx_action_pop_queue{}) ->
    encode_nx_action_pop_queue();
encode_action(#nx_action_reg_move{n_bits = Nbits, src_ofs = SrcOfs, dst_ofs = DstOfs, src = Src, dst = Dst}) ->
    encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, Src, Dst);
encode_action(#nx_action_reg_load{ofs = Ofs, nbits = Nbits, dst = Dst, value = Value}) ->
    encode_nx_action_reg_load(Ofs, Nbits, Dst, Value);
encode_action(#nx_action_note{note = Note}) ->
    encode_nx_action_note(Note);
encode_action(#nx_action_multipath{fields = Fields, basis = Basis, algorithm = Algo, max_link = MaxLink, arg = Arg, ofs = Ofs, nbits = Nbits, dst = Dst}) ->
    encode_nx_action_multipath(Fields, Basis, Algo, MaxLink, Arg, Ofs, Nbits, Dst);
encode_action(#nx_action_autopath{ofs = Ofs, nbits = Nbits, dst = Dst, id = Id}) ->
    encode_nx_action_autopath(Ofs, Nbits, Dst, Id);

encode_action(Action) when is_binary(Action) ->
    pad_to(8, Action).

encode_actions([], Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_actions([Head|Rest], Acc) ->
    encode_actions(Rest, [encode_action(Head)|Acc]).

encode_actions(List) when is_list(List) ->
    encode_actions(List, []);
encode_actions(Action) when is_tuple(Action) ->
    encode_action(Action).

%% Stats Reques/Reply

encode_stats_reply_entry(#ofp_desc_stats{mfr_desc = MfrDesc, hw_desc = HwDesc, sw_desc = SwDesc,
					 serial_num = SerialNum, dp_desc = DpDesc}) ->
    encode_ofp_desc_stats(MfrDesc, HwDesc, SwDesc, SerialNum, DpDesc);

encode_stats_reply_entry(#ofp_flow_stats{table_id = TableId, match = Match, duration = Duration, priority = Priority,
					 idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
					 packet_count = PacketCount, byte_count = ByteCount, actions = Actions}) ->
    encode_ofp_flow_stats(TableId, encode_match(Match), Duration, Priority, IdleTimeout, HardTimeout,
			  Cookie, PacketCount, ByteCount, encode_actions(Actions));

encode_stats_reply_entry(#ofp_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount, flow_count = FlowCount}) ->
    encode_ofp_aggregate_stats(PacketCount, ByteCount, FlowCount);

encode_stats_reply_entry(#ofp_table_stats{table_id = TableId, name = Name, wildcards = Wildcards, max_entries = MaxEntries,
					  active_count = ActiveCount, lookup_count = LookupCount, matched_count = MatchedCount}) ->
    encode_ofp_table_stats(TableId, Name, Wildcards, MaxEntries, ActiveCount, LookupCount, MatchedCount);

encode_stats_reply_entry(#ofp_port_stats{port_no = Port, rx_packets = RxPackets, tx_packets = TxPackets, rx_bytes = RxBytes, tx_bytes = TxBytes,
					 rx_dropped = RxDropped, tx_dropped = TxDropped, rx_errors = RxErrors, tx_errors = TxErrors,
					 rx_frame_err = RxFrameErr, rx_over_err = RxOverErr, rx_crc_err = RxCrcErr, collisions = Collisions}) ->
    encode_ofp_port_stats(Port, RxPackets, TxPackets, RxBytes, TxBytes, RxDropped, TxDropped,
			  RxErrors, TxErrors, RxFrameErr, RxOverErr, RxCrcErr, Collisions);

encode_stats_reply_entry(#ofp_queue_stats{port_no = Port, queue_id = Queue, tx_bytes = TxBytes, tx_packets = TxPackets, tx_errors = TxErrors}) ->
    encode_ofp_queue_stats(Port, Queue, TxBytes, TxPackets, TxErrors);

encode_stats_reply_entry(#ofp_nxst_flow_stats{table_id = TableId, duration = Duration, priority = Priority,
					      idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
					      packet_count = PacketCount, byte_count = ByteCount, nx_match = NxMatch, actions = Actions}) ->
    encode_ofp_nxst_flow_stats(TableId, Duration, Priority, IdleTimeout, HardTimeout,
			       Cookie, PacketCount, ByteCount, encode_nx_matches(NxMatch), encode_actions(Actions));

encode_stats_reply_entry(#ofp_nxst_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount, flow_count = FlowCount}) ->
    encode_ofp_nxst_aggregate_stats(PacketCount, ByteCount, FlowCount).

stats_reply_record_type(ofp_desc_stats)			-> desc;
stats_reply_record_type(ofp_flow_stats)			-> flow;
stats_reply_record_type(ofp_aggregate_stats)		-> aggregate;
stats_reply_record_type(ofp_table_stats)		-> table;
stats_reply_record_type(ofp_port_stats)			-> port;
stats_reply_record_type(ofp_queue_stats)		-> queue;
stats_reply_record_type(ofp_nxst_flow_stats)		-> {vendor, nxst_flow};
stats_reply_record_type(ofp_nxst_aggregate_stats)	-> {vendor, nxst_aggregate}.

encode_stats_reply([], _RecType, Acc) ->
    list_to_binary(lists:reverse(Acc));
encode_stats_reply([Head|Rest], RecType, Acc) ->
    case is_record(Head, RecType) of
	true ->
	    encode_stats_reply(Rest, RecType, [encode_stats_reply_entry(Head)|Acc]);
	_ ->
	    error(badarg, [Head])
    end.

encode_stats_reply(Reply, RecType) ->
    Body = encode_stats_reply(Reply, RecType, []),
    Type = stats_reply_record_type(RecType),
    encode_ofp_stats(Type, Body).

encode_match(#ofp_match{wildcards = Wildcards, in_port = InPort,
			dl_src = DlSrc, dl_dst = DlDst, dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = DlType,
			nw_tos = NwTos, nw_proto = NwProto, nw_src = NwSrc, nw_dst = NwDst,
			tp_src = TpSrc, tp_dst = TpDst}) ->
    encode_ofp_match(Wildcards,
		     InPort, DlSrc, DlDst, DlVlan, DlVlanPcp, DlType,
		     NwTos, NwProto, NwSrc, NwDst, TpSrc, TpDst);
encode_match(Match)
  when is_binary(Match) ->
    Match.

encode_msg(#ofp_error{error = {Type, Code}, data = Data}) ->
    encode_ofp_error(ofp_error_type(Type),
		     ofp_error_code_type(Type, Code),
		     Data);

encode_msg(#ofp_switch_features{datapath_id = DataPathId,
				n_buffers = NBuffers,
				n_tables = NTables,
				capabilities = Capabilities,
				actions = Actions,
				ports = Ports}) ->
    encode_ofp_switch_features(DataPathId, NBuffers, NTables,
			       enc_flags(ofp_capabilities(), Capabilities),
			       enc_flags(ofp_action_type(), Actions),
			       encode_phy_ports(Ports));

encode_msg(#ofp_switch_config{flags = Flags, miss_send_len = MissSendLen}) ->
    encode_ofp_switch_config(ofp_config_flags(Flags), MissSendLen);

encode_msg(#ofp_packet_in{buffer_id = BufferId, total_len = TotalLen,
			  in_port = InPort, reason = Reason, data = Data}) ->
    encode_ofp_packet_in(BufferId, TotalLen, ofp_port(InPort), ofp_packet_in_reason(Reason), Data);

encode_msg(#ofp_flow_removed{match = Match, cookie = Cookie, priority = Priority,
			     reason = Reason, duration = Duration, idle_timeout = IdleTimeout,
			     packet_count = PacketCount, byte_count = ByteCount}) ->
    encode_ofp_flow_removed(encode_match(Match), Cookie, Priority, Reason, Duration,
			    IdleTimeout, PacketCount, ByteCount);

encode_msg(#ofp_port_status{reason = Reason, port = Port}) ->
    encode_ofp_port_status(Reason, encode_phy_port(Port));

encode_msg(#ofp_packet_out{buffer_id = BufferId, in_port = InPort, actions = Actions, data = Data}) ->
    encode_ofp_packet_out(BufferId, InPort, encode_actions(Actions), Data);

encode_msg(#ofp_flow_mod{match = Match, cookie = Cookie, command = Command,
			 idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
			 priority = Priority, buffer_id = BufferId,
			 out_port = OutPort, flags = Flags, actions = Actions}) ->
    encode_ofp_flow_mod(encode_match(Match), Cookie, Command, 
			IdleTimeout, HardTimeout, Priority, BufferId, OutPort,
			enc_flags(ofp_flow_mod_flags(), Flags), encode_actions(Actions));

encode_msg(#ofp_port_mod{port_no = PortNo, hw_addr = HwAddr,
			 config = Config, mask = Mask, advertise = Advertise}) ->
    encode_ofp_port_mod(PortNo, HwAddr, enc_flags(ofp_port_config(), Config),
			enc_flags(ofp_port_config(), Mask), enc_flags(ofp_port_features(), Advertise));

encode_msg(#ofp_queue_get_config_request{port = Port}) ->
    encode_queue_get_config_request(ofp_port(Port));

encode_msg(#ofp_queue_get_config_reply{port = Port, queues = Queues}) ->
    encode_ofp_queue_get_config_reply(port = ofp_port(Port), encode_ofp_packet_queues(Queues));

encode_msg([Head|_] = Msg)
  when is_record(Head, ofp_desc_stats); is_record(Head, ofp_flow_stats); is_record(Head, ofp_aggregate_stats);
       is_record(Head, ofp_table_stats); is_record(Head, ofp_port_stats); is_record(Head, ofp_queue_stats);
       is_record(Head, ofp_nxst_flow_stats); is_record(Head, ofp_nxst_aggregate_stats) ->
    encode_stats_reply(Msg, element(1, Head));

encode_msg(#ofp_desc_stats_request{}) ->
    encode_ofp_stats_request(desc, <<>>);

encode_msg(#ofp_flow_stats_request{match = Match, table_id = TableId, out_port = OutPort}) ->
    encode_ofp_stats_request(flow, encode_ofp_flow_stats_request(encode_match(Match), TableId, OutPort));

encode_msg(#ofp_aggregate_stats_request{match = Match, table_id = TableId, out_port = OutPort}) ->
    encode_ofp_stats_request(aggregate, encode_ofp_aggregate_stats_request(encode_match(Match), TableId, OutPort));

encode_msg(#ofp_table_stats_request{}) ->
    encode_ofp_stats_request(table, <<>>);

encode_msg(#ofp_port_stats_request{port_no = Port}) ->
    encode_ofp_stats_request(port, encode_ofp_port_stats_request(Port));

encode_msg(#ofp_queue_stats_request{port_no = Port, queue_id = Queue}) ->
    encode_ofp_stats_request(queue, encode_ofp_queue_stats_request(Port, Queue));

encode_msg(#ofp_nxst_flow_stats_request{out_port = OutPort, table_id = TableId, nx_match = NxMatch}) ->
    encode_ofp_vendor_stats_request(nxst_flow, encode_ofp_nxst_flow_stats_request(OutPort, TableId, encode_nx_matches(NxMatch)));

encode_msg(#ofp_nxst_aggregate_stats_request{out_port = OutPort, table_id = TableId, nx_match = NxMatch}) ->
    encode_ofp_vendor_stats_request(nxst_aggregate, encode_ofp_nxst_aggregate_stats_request(OutPort, TableId, encode_nx_matches(NxMatch)));

%% Nicira Extensions

encode_msg(#nxt_flow_mod_table_id{set = Set}) ->
    encode_nxt_flow_mod_table_id(Set);

encode_msg(#nxt_role_request{role = Role}) ->
    encode_nxt_role_request(Role);

encode_msg(#nx_flow_mod{cookie = Cookie, command = Command,
			idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
			priority = Priority, buffer_id = BufferId,
			out_port = OutPort, flags = Flags, nx_match = NxMatch, actions = Actions}) ->
    encode_nx_flow_mod(Cookie, Command, IdleTimeout, HardTimeout, Priority,
		       BufferId, OutPort, enc_flags(ofp_flow_mod_flags(), Flags), 
		       encode_nx_matches(NxMatch), encode_actions(Actions));

encode_msg(Msg)
  when is_binary(Msg) ->
    Msg.

%%%===================================================================
%%% Internal functions
%%%===================================================================

pad_length(Width, Length) ->
    (Width - Length rem Width) rem Width.

%%
%% pad binary to specific length
%%   -> http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html
%%
pad_to(Width, Binary) ->
    case pad_length(Width, size(Binary)) of
	0 -> Binary;
	N -> <<Binary/binary, 0:(N*8)>>
    end.

%%FIXME: bitstring comprehension could be (much) simpler....
dec_flag([], _, Acc) ->
    Acc;
dec_flag([Flag|Rest], F, Acc) ->
    case F rem 2 of
        1 -> dec_flag(Rest, F bsr 1, [Flag | Acc]);
        _ -> dec_flag(Rest, F bsr 1, Acc)
    end.

-spec dec_flags(Flags, non_neg_integer()) -> Flags.
dec_flags(Map, Flag) ->
    dec_flag(Map, Flag, []).

enc_flag([], _, _, Acc) ->
    Acc;
enc_flag([Flag|Rest], F, Pos, Acc) ->
    case proplists:get_bool(Flag, F) of
	true -> enc_flag(Rest, F, Pos bsl 1, Acc bor Pos);
	_    -> enc_flag(Rest, F, Pos bsl 1, Acc)
    end.

-spec enc_flags([Flags :: atom()], [Flags :: atom()]) -> non_neg_integer().
enc_flags(Map, Flag) ->
    enc_flag(Map, Flag, 1, 0).
