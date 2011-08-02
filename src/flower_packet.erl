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
eth_type(?ETH_TYPE_MOPRC) -> moprc;
eth_type(?ETH_TYPE_VLAN)  -> vlan;
eth_type(?ETH_TYPE_IPV6)  -> ipv6;
eth_type(?ETH_TYPE_LACP)  -> lacp;
eth_type(?ETH_TYPE_LOOP)  -> loop;
eth_type(X) when is_integer(X), X =< ?ETH_TYPE_MIN -> none;
eth_type(X) when is_integer(X) -> X;
													   
eth_type(none)  -> ?ETH_TYPE_NONE;
eth_type(ip)    -> ?ETH_TYPE_IP;
eth_type(arp)   -> ?ETH_TYPE_ARP;
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

ofp_port_reason(0) -> add;
ofp_port_reason(1) -> delete;
ofp_port_reason(2) -> modify;
ofp_port_reason(X) when is_integer(X) -> X;
ofp_port_reason(add)    -> 0;
ofp_port_reason(delete) -> 1;
ofp_port_reason(modify) -> 2.

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

not_impl() ->
	throw(not_implemented_yet).

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
					  duration = {DurationSec, DurationNSec}, idle_timeout = IdleTimeout, packet_count = PacketCount, byte_count = ByteCount};

decode_msg(port_status, <<Reason:8/integer, _Pad:7/bytes, PhyPort/binary>>) ->
				  #ofp_port_status{reason = ofp_port_reason(Reason),
								   port = decode_phy_port(PhyPort)};

decode_msg(_, Msg) ->
	Msg.

decode_ofp_match(<<Wildcards:32/integer, InPort:16/integer,
				   DlSrc:6/binary, DlDst:6/binary, DlVlan:16/integer, DlVlanPcp:8/integer,
				   _Pad1:1/bytes, 
				   DlType:16/integer, NwTos:8/integer, NwProto:8/integer, _Pad2:2/bytes,
				   NwSrc:4/bytes, NwDst:4/bytes, TpSrc:16/integer, TpDst:16/integer>>) ->
	#ofp_match{wildcards = Wildcards, in_port = ofp_port(InPort),
			   dl_src = DlSrc, dl_dst = DlDst, dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = eth_type(DlType),
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
encode_ovs_vendor({Vendor, Cmd}, Data)
  when is_atom(Vendor) ->
	encode_ovs_vendor({Vendor, Cmd}, Data);
encode_ovs_vendor({Vendor, Cmd}, Data) ->
	<< Vendor:8, Cmd:8, Data/binary >>;
encode_ovs_vendor(Cmd, Data) ->
	encode_ovs_vendor(of_vendor_ext(Cmd), Data).

-spec encode_ofp_switch_features(integer(), integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_switch_features(DataPathId, NBuffers, NTables, Capabilities, Actions, Ports) ->
	<<DataPathId:64, NBuffers:32, NTables:8, 0:24, Capabilities:32, Actions:32, Ports/binary>>.

-spec encode_phy_port(integer(), binary(), binary(), integer(), integer(), integer(), integer(), integer(), integer()) -> binary().
encode_phy_port(PortNo, HwAddr, Name, Config, State,Curr, Advertised, Supported, Peer) ->
	PortNo0 = ofp_port(PortNo),
	Name0 = pad_to(16, Name),
	<<PortNo0:16, HwAddr:6/bytes, Name0:16/bytes, Config:32, State:32, Curr:32, Advertised:32, Supported:32, Peer:32>>.

encode_phy_port(Port) when is_binary(Port) ->
	Port;
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

encode_phy_ports(Ports) when is_binary(Ports) ->
	Ports;
encode_phy_ports(Ports) ->
	encode_phy_ports(Ports, []).

encode_ofp_port_status(Reason, Port) ->
	Reason0 = ofp_port_reason(Reason),
	<<Reason0:8, 0:56, Port/binary>>.

-spec encode_ofp_switch_config(integer(), integer()) -> binary().
encode_ofp_switch_config(Flags, MissSendLen) ->
	<<Flags:16, MissSendLen:16>>.

bool(true) -> 1;
bool(false) -> 0;
bool(0) -> false;
bool(_) -> true.
	
int_maybe_undefined(X) when is_integer(X) -> X;
int_maybe_undefined(undefined) -> 0.

bin_maybe_undefined(X, Len) when is_binary(X) -> pad_to(Len, X);
bin_maybe_undefined(undefined, Len) -> pad_to(Len, <<0>>).
	
-spec encode_ofp_match(integer(), integer()|atom(), binary(), binary(), integer(),
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
	Data = pad_to(8, Msg),
	pad_to(8, <<16#FFFF:16, (size(Data) + 8):16, Vendor:32, Data/binary>>).

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

-spec encode_ofp_flow_removed(binary(), integer(), integer(), integer()|atom(), tuple(integer(), integer()), integer(), integer(), integer()) -> binary().
encode_ofp_flow_removed(Match, Cookie, Priority, Reason, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount) when is_atom(Reason) ->
	Reason0 = ofp_flow_removed_reason(Reason),
	encode_ofp_flow_removed(Match, Cookie, Priority, Reason0, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount);
encode_ofp_flow_removed(Match, Cookie, Priority, Reason, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount) ->
	<<Match/binary, Cookie:64, Priority:16, Reason:8, 0:8, DurationSec:32, DurationNSec:32, IdleTimeout:16, 0:16,
	  PacketCount:64, ByteCount:64>>.

-spec encode_ofp_packet_out(integer(), integer()|atom(), binary(), list(binary())|binary()) -> binary().
encode_ofp_packet_out(BufferId, InPort, Actions, Data) when is_list(Actions) ->
	encode_ofp_packet_out(BufferId, InPort, list_to_binary(Actions), Data);
encode_ofp_packet_out(BufferId, InPort, Actions, Data) ->
	InPort0 = ofp_port(InPort),
	<<BufferId:32, InPort0:16, (size(Actions)):16, Actions/binary, Data/binary>>.

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

enc_nxm_match(<<_Vendor:16, _Field:7, 1:1, Length:8>> = Header, {Value, Mask})
  when is_binary(Value), is_binary(Mask) ->
	BitLen = Length * 4,
	<<Header/binary, Value:BitLen, Mask:BitLen>>;
enc_nxm_match(<<_Vendor:16, _Field:7, 1:0, Length:8>> = Header, Value)
  when is_binary(Value) ->
	BitLen = Length * 8,
	<<Header/binary, Value:BitLen>>.
	
encode_nx_matches([], Acc) ->
	list_to_binary(lists:reverse(Acc));
encode_nx_matches([{Header, Value}|Rest], Acc) ->
	encode_nx_matches(Rest, [enc_nxm_match(nxm_header(Header), Value)|Acc]).
encode_nx_matches(NxMatch) ->
	 encode_nx_matches(NxMatch, []).

encode_nx_flow_mod(Cookie, Command, IdleTimeout, HardTimeout, Priority,
				   BufferId, OutPort, Flags, NxMatch, Actions) when is_list(Actions) ->
	encode_nx_flow_mod(Cookie, Command, IdleTimeout, HardTimeout, Priority,
					   BufferId, OutPort, Flags, NxMatch, list_to_binary(Actions));
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

nxm_header(nxm_of_in_port)		-> ?NXM_OF_IN_PORT;
nxm_header(nxm_of_eth_dst)		-> ?NXM_OF_ETH_DST;
nxm_header(nxm_of_eth_dst_w)	-> ?NXM_OF_ETH_DST_W;
nxm_header(nxm_of_eth_src)		-> ?NXM_OF_ETH_SRC;
nxm_header(nxm_of_eth_type)		-> ?NXM_OF_ETH_TYPE;
nxm_header(nxm_of_vlan_tci)		-> ?NXM_OF_VLAN_TCI;
nxm_header(nxm_of_vlan_tci_w)	-> ?NXM_OF_VLAN_TCI_W;
nxm_header(nxm_of_ip_tos)		-> ?NXM_OF_IP_TOS;
nxm_header(nxm_of_ip_proto)		-> ?NXM_OF_IP_PROTO;
nxm_header(nxm_of_ip_src)		-> ?NXM_OF_IP_SRC;
nxm_header(nxm_of_ip_src_w)		-> ?NXM_OF_IP_SRC_W;
nxm_header(nxm_of_ip_dst)		-> ?NXM_OF_IP_DST;
nxm_header(nxm_of_ip_dst_w)		-> ?NXM_OF_IP_DST_W;
nxm_header(nxm_of_tcp_src)		-> ?NXM_OF_TCP_SRC;
nxm_header(nxm_of_tcp_dst)		-> ?NXM_OF_TCP_DST;
nxm_header(nxm_of_udp_src)		-> ?NXM_OF_UDP_SRC;
nxm_header(nxm_of_udp_dst)		-> ?NXM_OF_UDP_DST;
nxm_header(nxm_of_icmp_type)	-> ?NXM_OF_ICMP_TYPE;
nxm_header(nxm_of_icmp_code)	-> ?NXM_OF_ICMP_CODE;
nxm_header(nxm_of_arp_op)		-> ?NXM_OF_ARP_OP;
nxm_header(nxm_of_arp_spa)		-> ?NXM_OF_ARP_SPA;
nxm_header(nxm_of_arp_spa_w)	-> ?NXM_OF_ARP_SPA_W;
nxm_header(nxm_of_arp_tpa)		-> ?NXM_OF_ARP_TPA;
nxm_header(nxm_of_arp_tpa_w)	-> ?NXM_OF_ARP_TPA_W;

nxm_header(nxm_nx_tun_id)		-> ?NXM_NX_TUN_ID;
nxm_header(nxm_nx_tun_id_w)		-> ?NXM_NX_TUN_ID_W;
nxm_header(nxm_nx_arp_sha)		-> ?NXM_NX_ARP_SHA;
nxm_header(nxm_nx_arp_tha)		-> ?NXM_NX_ARP_THA;

nxm_header(nxm_nx_ipv6_src)		-> ?NXM_NX_IPV6_SRC;
nxm_header(nxm_nx_ipv6_src_w)	-> ?NXM_NX_IPV6_SRC_W;
nxm_header(nxm_nx_ipv6_dst)		-> ?NXM_NX_IPV6_DST;
nxm_header(nxm_nx_ipv6_dst_w)	-> ?NXM_NX_IPV6_DST_W;
nxm_header(nxm_nx_icmpv6_type)	-> ?NXM_NX_ICMPV6_TYPE;
nxm_header(nxm_nx_icmpv6_code)	-> ?NXM_NX_ICMPV6_CODE;
nxm_header(nxm_nx_nd_target)	-> ?NXM_NX_ND_TARGET;
nxm_header(nxm_nx_nd_sll)		-> ?NXM_NX_ND_SLL;
nxm_header(nxm_nx_nd_tll)		-> ?NXM_NX_ND_TLL;

nxm_header({nxm_nx_reg, X})		-> ?NXM_HEADER  (16#0001, X, 4);
nxm_header({nxm_nx_reg_w, X})	-> ?NXM_HEADER_W(16#0001, X, 4);

nxm_header(X) when is_binary(X) -> X.

encode_nx_action(Action, Data) ->
	Act = nxt_action(Action),
	encode_ofs_action_vendor(vendor(nicira), <<Act:16, Data/binary>>).

encode_nx_action_resubmit(InPort) ->
	encode_nx_action(nxast_resubmit, << InPort:16 >>).

encode_nx_action_set_tunnel(TunId) ->
	encode_nx_action(nxast_set_tunnel, << 0:16, TunId:32 >>).

encode_nx_action_set_tunnel64(TunId) ->
	encode_nx_action(nxast_set_tunnel64, << 0:48, TunId:64 >>).

encode_nx_action_set_queue(QueueId) ->
 	encode_nx_action(nxast_set_queue, << 0:16, QueueId:32 >>).

encode_nx_action_pop_queue() ->
 	encode_nx_action(nxast_pop_queue, << >>).

encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, Src, Dst)
  when is_atom(Src); is_atom(Dst); is_tuple(Dst) ->
	encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, nxm_header(Src), nxm_header(Dst));
encode_nx_action_reg_move(Nbits, SrcOfs, DstOfs, Src, Dst) ->
	encode_nx_action(nxast_reg_move, << Nbits:16, SrcOfs:16, DstOfs:16, Src/binary, Dst/binary>>).

encode_nx_action_reg_load(Ofs, Nbits, Dst, Value)
  when is_atom(Dst); is_tuple(Dst) ->
	encode_nx_action_reg_load(Ofs, Nbits, nxm_header(Dst), Value);
encode_nx_action_reg_load(Ofs, Nbits, Dst, Value) ->
	encode_nx_action(nxast_reg_load, << Ofs:10, Nbits:6, Dst/binary, (pad_to(8, Value))/binary >>).

encode_nx_action_note(Note)
  when is_list(Note) ->
	encode_nx_action(nxast_action_note, list_to_binary(Note));
encode_nx_action_note(Note)
  when is_binary(Note) ->
	encode_nx_action(nxast_action_note, Note).

encode_nx_action_multipath(_Fields, _Basis, _Algo, _MaxLink, _Arg, _Ofs, _Nbits, _Dst) -> not_impl().
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

encode_action(#ofp_action_vendor_header{vendor = Vendor, msg = Msg}) ->
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

encode_msg(#ofp_port_status{reason = Reason, port = Port}) ->
	encode_ofp_port_status(Reason, encode_phy_port(Port));

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

encode_msg(#ofp_flow_removed{match = Match, cookie = Cookie, priority = Priority,
							 reason = Reason, duration = Duration, idle_timeout = IdleTimeout,
							 packet_count = PacketCount, byte_count = ByteCount}) ->
	encode_ofp_flow_removed(encode_msg(Match), Cookie, Priority, Reason, Duration,
							IdleTimeout, PacketCount, ByteCount);

encode_msg(#ofp_packet_out{buffer_id = BufferId, in_port = InPort, actions = Actions, data = Data}) ->
	encode_ofp_packet_out(BufferId, InPort, encode_actions(Actions), Data);

encode_msg(#nxt_flow_mod_table_id{set = Set}) ->
	encode_nxt_flow_mod_table_id(Set);

encode_msg(#nxt_role_request{role = Role}) ->
	encode_nxt_role_request(Role);

encode_msg(#nx_flow_mod{cookie = Cookie, command = Command,
						idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
						priority = Priority, buffer_id = BufferId,
						out_port = OutPort, flags = Flags, nx_match = NxMatch, actions = Actions}) ->
	encode_nx_flow_mod(Cookie, ofp_flow_mod_command(Command), IdleTimeout, HardTimeout, Priority,
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
