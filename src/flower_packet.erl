%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_packet).

%% API
-export([encode/1, encode_msg/1, decode/1]).
%% constant mappers
-export([ofpt/1, ofp_packet_in_reason/1, ofp_config_flags/1,
		 ofp_flow_mod_command/1, ofp_port/1]).
%% part encoders
-export([encode_ofs_action_output/2, encode_ofs_action_vlan_vid/1,
		 encode_ofs_action_vlan_pcp/1, encode_ofs_action_strip_vlan/0,
		 encode_ofs_action_dl_addr/2, encode_ofs_action_nw_addr/2,
		 encode_ofs_action_nw_tos/1, encode_ofs_action_tp_addr/2,
		 encode_ofs_action_enqueue/2, encode_ofs_action_vendor/2,
		 encode_ofp_match/13,
		 encode_ofp_flow_mod/10,
		 encode_ofp_packet_out/4]).
		 
%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include("flower_packet.hrl").

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

decode(<<>>, Acc) ->
	lists:reverse(Acc);
decode(<<Version:8/integer, Type:8/integer, Length:16/integer, Xid:32/integer,
		 _/binary>> = Data, Acc) ->
	if 
		size(Data) < Length ->
			{error, invalid_length};
		true ->
			MsgLen = Length - 8,
			<<_Hdr:8/bytes, Msg:MsgLen/bytes, Rest/binary>> = Data,
			MType = ofpt(Type),
			M = decode_msg(MType, Msg),
			?DEBUG("deode got: ~p~n", [M]),
			decode(Rest, [#ovs_msg{version = Version, type = MType, xid = Xid, msg = M}|Acc])
	end.

encode(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg}) ->
	Mtype = ofpt(Type),
	Data = encode_msg(Msg),
	Length = size(Data) + 8,
	?DEBUG("~p ~p ~p ~p ~p~n", [Version, Mtype, Length, Xid, Msg]),
	R = <<Version:8, Mtype:8, Length:16, Xid:32, Data/binary>>,
	?DEBUG("Send: ~p~n", [R]),
	R.

%%%===================================================================
%%% constant, flags and enum translators
%%%===================================================================


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

ofpt(hello)						-> 0;
ofpt(error)						-> 1;
ofpt(echo_request)				-> 2;
ofpt(echo_reply)				-> 3;
ofpt(vendor)					-> 4;
ofpt(features_request)			-> 5;
ofpt(features_reply)			-> 6;
ofpt(get_config_request)		-> 7;
ofpt(get_config_reply)			-> 8;
ofpt(set_config)				-> 9;
ofpt(packet_in)					-> 10;
ofpt(flow_removed)				-> 11;
ofpt(port_status)				-> 12;
ofpt(packet_out)				-> 13;
ofpt(flow_mod)					-> 14;
ofpt(port_mod)					-> 15;
ofpt(stats_request)				-> 16;
ofpt(stats_reply)				-> 17;
ofpt(barrier_request)			-> 18;
ofpt(barrier_reply)				-> 19;
ofpt(queue_get_config_request)	-> 20;
ofpt(queue_get_config_reply)	-> 21;

ofpt(_)		-> error.

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
ofp_config_flags(frag_drop)		-> 1;
ofp_config_flags(frag_reasm)	-> 2;
ofp_config_flags(frag_mask)		-> 3;

ofp_config_flags(_) -> error.

ofp_flow_mod_command(0)	-> add;
ofp_flow_mod_command(1)	-> modify;
ofp_flow_mod_command(2)	-> modify_strict;
ofp_flow_mod_command(3)	-> delete;
ofp_flow_mod_command(4)	-> delete_strict;

ofp_flow_mod_command(add)			-> 0;
ofp_flow_mod_command(modify)		-> 1;
ofp_flow_mod_command(modify_strict)	-> 2;
ofp_flow_mod_command(delete)		-> 3;
ofp_flow_mod_command(delete_strict)	-> 4;

ofp_flow_mod_command(X) when is_integer(X)	-> X;
ofp_flow_mod_command(_)	-> error.

ofp_flow_mod_flags() ->
	[send_flow_rem, check_overlap, emerg].

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

ofp_flow_removed_reason(0) -> idle_timeout;
ofp_flow_removed_reason(1) -> hard_timeout;
ofp_flow_removed_reason(2) -> delete;
ofp_flow_removed_reason(X) when is_integer(X) -> X;

ofp_flow_removed_reason(idle_timeout) -> 0;
ofp_flow_removed_reason(hard_timeout) -> 1;
ofp_flow_removed_reason(delete)       -> 2.
	

protocol(NwProto)
  when is_atom(NwProto) ->
	gen_socket:protocol(NwProto);
protocol(NwProto) ->
	NwProto.

%%%===================================================================
%%% Decode
%%%===================================================================

decode_msg(features_reply, <<DataPathId:64/integer, NBuffers:32/integer, NTables:8/integer, _Pad:3/bytes,
							 Capabilities:32/integer, Actions:32/integer, Ports/binary>>) ->
	?DEBUG("DataPathId: ~p, NBuffers: ~p, NTables: ~p, Pad: ~p, Capabilities: ~p, Actions: ~p, Ports: ~p~n",
		   [DataPathId, NBuffers, NTables, Pad, Capabilities, Actions, Ports]),
	#ofp_switch_features{datapath_id = DataPathId,
						 n_buffers = NBuffers,
						 n_tables = NTables,
						 capabilities = dec_flags(ofp_capabilities(), Capabilities),
						 actions = dec_flags(ofp_action_type(), Actions),
						 ports = decode_phy_ports(Ports)};

decode_msg(packet_in, <<BufferId:32/integer, TotalLen:16/integer, InPort:16/integer, Reason:8/integer, _Pad:1/binary, Data/binary>>) ->
	#ofp_packet_in{buffer_id = BufferId, total_len = TotalLen, in_port = ofp_port(InPort), reason = ofp_packet_in_reason(Reason), data = Data};

decode_msg(packet_out, <<BufferId:32/integer, InPort:16/integer, ActionsLen:16/integer, Actions:ActionsLen/bytes, Data/binary>>) ->
	#ofp_packet_out{buffer_id = BufferId, in_port = ofp_port(InPort), actions = decode_actions(Actions), data = Data};

decode_msg(set_config, <<Flags:16/integer, MissSendLen:16/integer>>) ->
	#ofp_switch_config{flags = ofp_config_flags(Flags), miss_send_len = MissSendLen};

decode_msg(flow_mod, <<Match:40/bytes, Cookie:64/integer, Command:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer,
					   Priority:16/integer, BufferId:32/integer, OutPort:16/integer, Flags:16/integer, Actions/binary>>) ->
	#ofp_flow_mod{match = decode_ofp_match(Match), cookie = Cookie, command = Command,
				  idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
				  priority = Priority, buffer_id = BufferId,
				  out_port = ofp_port(OutPort), flags = dec_flags(ofp_flow_mod_flags(), Flags), actions = decode_actions(Actions)};

decode_msg(flow_removed, <<Match:40/bytes, Cookie:64/integer, Priority:16/integer, Reason:8/integer, _Pad1:1/bytes,
						   DurationSec:32/integer, DurationNSec:32/integer, IdleTimeout:16/integer, _Pad2:2/bytes,
						   PacketCount:64/integer, ByteCount:64/integer>>) ->
	#ofp_flow_removed{match = decode_ofp_match(Match), cookie = Cookie, priority = Priority, reason = ofp_flow_removed_reason(Reason),
					  duration_sec = DurationSec, duration_nsec = DurationNSec, idle_timeout = IdleTimeout,
					  packet_count = PacketCount, byte_count = ByteCount};

decode_msg(_, Msg) ->
	Msg.

decode_ofp_match(<<Wildcards:32/integer, InPort:16/integer,
				   DlSrc:6/binary, DlDst:6/binary, DlVlan:16/integer, DlVlanPcp:8/integer,
				   _Pad1:1/bytes, 
				   DlType:16/integer, NwTos:8/integer, NwProto:8/integer, _Pad2:2/bytes,
				   NwSrc:4/bytes, NwDst:4/bytes, TpSrc:16/integer, TpDst:16/integer>>) ->
	#ofp_match{wildcards = Wildcards, in_port = ofp_port(InPort),
			   dl_src = DlSrc, dl_dst = DlDst, dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = DlType,
			   nw_tos = NwTos, nw_proto = protocol(NwProto), nw_src = NwSrc, nw_dst = NwDst,
			   tp_src = TpSrc, tp_dst = TpDst}.

decode_action(<<0:16, 8:16, Port:16/integer, MaxLen:16/integer>>) ->
	#ofp_action_output{port = ofp_port(Port), max_len = MaxLen};
decode_action(<<1:16, 8:16, VlanVid:16/integer, _:16>>) ->
	#ofp_action_vlan_vid{vlan_vid = VlanVid};
decode_action(<<2:16, 8:16, VlanPcp:8/integer, 0:24>>) ->
	#ofp_action_vlan_pcp{vlan_pcp = VlanPcp};
decode_action(<<3:16, 8:16, _:32>>) ->
	#ofp_action_strip_vlan{};
decode_action(<<4:16, 16:16, Addr:6/binary, _:48>>) ->
	#ofp_action_dl_addr{type = src, dl_addr = Addr};
decode_action(<<5:16, 16:16, Addr:6/binary, _:48>>) ->
	#ofp_action_dl_addr{type = dst, dl_addr = Addr};
decode_action(<<6:16, 8:8, Addr:4/binary>>) ->
	#ofp_action_nw_addr{type = src, nw_addr = Addr};
decode_action(<<7:16, 8:8, Addr:4/binary>>) ->
	#ofp_action_nw_addr{type = dst, nw_addr = Addr};
decode_action(<<9:16, 8:8, NwTos:8/integer, _:24>>) ->
	#ofp_action_nw_tos{nw_tos = NwTos};
decode_action(<<9:16, 8:8, TpPort:16/integer, _:16>>) ->
	#ofp_action_tp_port{type = src, tp_port = TpPort};
decode_action(<<10:16, 8:8, TpPort:16/integer, _:16>>) ->
	#ofp_action_tp_port{type = dst, tp_port = TpPort};
decode_action(<<11:16, 16:16, Port:16/integer, _:48, QueueId:32/integer>>) ->
	#ofp_action_enqueue{port = ofp_port(Port), queue_id = QueueId};
decode_action(<<16#FFFF:16, _Length:16, Vendor:32, Msg>>) ->
	#ofp_action_vendor_header{vendor = Vendor, msg = Msg};
decode_action(Msg) when is_binary(Msg) ->
	Msg.

decode_actions(<<>>, Acc) ->
	lists:reverse(Acc);
decode_actions(<<_Type:16/integer, Length:16/integer, _Rest/binary>> = Data, Acc) ->
	<<Msg:Length/bytes, Rest/binary>> = Data,
	decode_actions(Rest, [decode_action(Msg)|Acc]).

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

decode_binstring(Str) ->
	case binary:split(Str, <<0>>) of
		[Name|_Rest] ->
			Name;
		Name when is_binary(Name) ->
			Name;
		_ ->
			<<>>
	end.

%%%===================================================================
%%% Encode
%%%===================================================================

-spec encode_ofp_switch_features(integer(), integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_switch_features(DataPathId, NBuffers, NTables, Capabilities, Actions, Ports) ->
	<<DataPathId:64, NBuffers:32, NTables:8, 0:24, Capabilities:32, Actions:32, Ports/binary>>.

-spec encode_phy_port(integer(), binary(), binary(), integer(), integer(), integer(), integer(), integer(), integer()) -> binary().
encode_phy_port(PortNo, HwAddr, Name, Config, State,Curr, Advertised, Supported, Peer) ->
	PortNo0 = ofp_port(PortNo),
	Name0 = pad_to(16, Name),
	<<PortNo0:16, HwAddr:6/bytes, Name0:16/bytes, Config:32, State:32, Curr:32, Advertised:32, Supported:32, Peer:32>>.

encode_phy_port(#ofp_phy_port{port_no = PortNo,
							  hw_addr = HwAddr,
							  name = Name,
							  config = Config,
							  state = State,
							  curr = Curr,
							  advertised = Advertised,
							  supported = Supported,
							  peer = Peer}) ->
	encode_phy_port(PortNo, HwAddr, Name, 
					enc_flags(ofp_port_config(), Config),
					enc_flags(ofp_port_state(), State),
					enc_flags(ofp_port_features(), Curr),
					enc_flags(ofp_port_features(), Advertised),
					enc_flags(ofp_port_features(), Supported),
					enc_flags(ofp_port_features(), Peer)).

encode_phy_ports([], Acc) ->
	list_to_binary(lists:reverse(Acc));
encode_phy_ports([Port|Rest], Acc) ->
	encode_phy_ports(Rest, [encode_phy_port(Port)|Acc]).

encode_phy_ports(Msg) ->
	encode_phy_ports(Msg, []).

-spec encode_ofp_switch_config(integer(), integer()) -> binary().
encode_ofp_switch_config(Flags, MissSendLen) ->
	<<Flags:16, MissSendLen:16>>.

-spec encode_ofp_match(integer(), integer()|atom(), binary(), binary(), integer(),
					   integer(), integer(), integer(), integer()|atom(),
					   binary(), binary(), integer(), integer()) -> binary().
encode_ofp_match(Wildcards, InPort, DlSrc, DlDst, DlVlan, DlVlanPcp, DlType,
				 NwTos, NwProto, NwSrc, NwDst, TpSrc, TpDst) ->
	InPort0 = ofp_port(InPort),
	NwProto0 = protocol(NwProto),
	<<Wildcards:32, InPort0:16, DlSrc:6/binary, DlDst:6/binary, DlVlan:16, DlVlanPcp:8,
	  0:8, DlType:16, NwTos:8, NwProto0:8, 0:16, NwSrc:4/binary, NwDst:4/binary, TpSrc:16, TpDst:16>>.

encode_ofs_action_output(Port, MaxLen) ->
	Port0 = ofp_port(Port),
	<<0:16, 8:16, Port0:16, MaxLen:16>>.

encode_ofs_action_vlan_vid(VlanVid) ->
	<<1:16, 8:16, VlanVid:16, 0:16>>.

encode_ofs_action_vlan_pcp(VlanPcp) ->
	<<2:16, 8:16, VlanPcp:8, 0:24>>.

encode_ofs_action_strip_vlan() ->
	<<3:16, 8:16, 0:32>>.

encode_ofs_action_dl_addr(src, Addr) ->
	<<4:16, 16:16, Addr:6/binary, 0:48>>;
encode_ofs_action_dl_addr(dst, Addr) ->
	<<5:16, 16:16, Addr:6/binary, 0:48>>.

encode_ofs_action_nw_addr(src, Addr) ->
	<<6:16, 8:8, Addr:4/binary>>;
encode_ofs_action_nw_addr(dst, Addr) ->
	<<7:16, 8:8, Addr:4/binary>>.

encode_ofs_action_nw_tos(NwTos) ->
	<<9:16, 8:8, NwTos:8, 0:24>>.

encode_ofs_action_tp_addr(src, TpPort) ->
	<<9:16, 8:8, TpPort:16, 0:16>>;
encode_ofs_action_tp_addr(dst, TpPort) ->
	<<10:16, 8:8, TpPort:16, 0:16>>.

encode_ofs_action_enqueue(Port, QueueId) ->
	Port0 = ofp_port(Port),
	<<11:16, 16:16, Port0:16, 0:48, QueueId:32>>.

encode_ofs_action_vendor(Vendor, Msg) ->
	Length = pad_length(8, size(Msg) + 8),
	pad_to(8, <<16#FFFF:16, Length:16, Vendor:32, Msg>>).

-spec encode_ofp_flow_mod(binary(), integer(), integer(), integer(), integer(), integer(), integer(), integer()|atom(), integer(), binary()|list(binary)) -> binary().
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

-spec encode_ofp_packet_out(integer(), integer()|atom(), binary(), list(binary())|binary()) -> binary().
encode_ofp_packet_out(BufferId, InPort, Actions, Data) when is_list(Actions) ->
	encode_ofp_packet_out(BufferId, InPort, list_to_binary(Actions), Data);
encode_ofp_packet_out(BufferId, InPort, Actions, Data) ->
	InPort0 = ofp_port(InPort),
	<<BufferId:32, InPort0:16, (size(Actions)):16, Actions/binary, Data/binary>>.

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

encode_action(#ofp_action_vendor_header{vendor = Vendor, msg = Msg}) ->
	encode_ofs_action_vendor(Vendor, Msg);

encode_action(Action) when is_binary(Action) ->
	pad_to(8, Action).

encode_actions([], Acc) ->
	list_to_binary(lists:reverse(Acc));
encode_actions([Head|Rest], Acc) ->
	encode_actions(Rest, [encode_action(Head)|Acc]).
encode_actions(List) ->
	encode_actions(List, []).

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

encode_msg(#ofp_match{wildcards = Wildcards, in_port = InPort,
					  dl_src = DlSrc, dl_dst = DlDst, dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = DlType,
					  nw_tos = NwTos, nw_proto = NwProto, nw_src = NwSrc, nw_dst = NwDst,
					  tp_src = TpSrc, tp_dst = TpDst}) ->
	encode_ofp_match(Wildcards,
					 InPort, DlSrc, DlDst, DlVlan, DlVlanPcp, DlType,
					 NwTos, NwProto, NwSrc, NwDst, TpSrc, TpDst);

encode_msg(#ofp_flow_mod{match = Match, cookie = Cookie, command = Command,
						 idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
						 priority = Priority, buffer_id = BufferId,
						 out_port = OutPort, flags = Flags, actions = Actions}) ->
	encode_ofp_flow_mod(encode_msg(Match), Cookie, ofp_flow_mod_command(Command), 
						IdleTimeout, HardTimeout, Priority,	BufferId, OutPort,
						enc_flags(ofp_flow_mod_flags(), Flags), encode_actions(Actions));

encode_msg(#ofp_packet_out{buffer_id = BufferId, in_port = InPort, actions = Actions, data = Data}) ->
		   encode_ofp_packet_out(BufferId, InPort, encode_actions(Actions), Data);

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

dec_flags(Map, Flag) ->
     dec_flag(Map, Flag, []).

enc_flag([], _, _, Acc) ->
    Acc;
enc_flag([Flag|Rest], F, Pos, Acc) ->
	case proplists:get_bool(Flag, F) of
		true -> enc_flag(Rest, F, Pos bsl 1, Acc bor Pos);
		_    -> enc_flag(Rest, F, Pos bsl 1, Acc)
    end.

enc_flags(Map, Flag) ->
     enc_flag(Map, Flag, 1, 0).
