%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>

%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:

%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.

%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(flower_packet_v11).

%% API
-export([encode/1, encode_msg/1, encode_match/1, decode/1]).
%% constant mappers
-export([ofpt/1, ofp_packet_in_reason/1, ofp_config_flags/1,
	 ofp_flow_mod_command/1, ofp_port/1, eth_type/1]).
%% part encoders
-export([encode_actions/1,
	 encode_action/1,
	 encode_ofp_packet_out/4]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
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
    ?DEBUG("decode got: ~p~n", [M]),
    decode(Rest, [#ovs_msg{version = Version, type = MType, xid = Xid, msg = M}|Acc]);

decode(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.

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

vendor(X) when is_integer(X) -> X.
experimenter(X) when is_integer(X) -> X.

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
ofpt(experimenter)		-> 4;
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
ofpt(group_mod)			-> 15;
ofpt(port_mod)			-> 16;
ofpt(table_mod)			-> 17;
ofpt(stats_request)		-> 18;
ofpt(stats_reply)		-> 19;
ofpt(barrier_request)		-> 20;
ofpt(barrier_reply)		-> 21;
ofpt(queue_get_config_request)	-> 22;
ofpt(queue_get_config_reply)	-> 23;

ofpt(_)		-> error.

-spec ofp_error_type(non_neg_integer()) -> ofp_error_type() | non_neg_integer();
		    (ofp_error_type()) -> non_neg_integer().
ofp_error_type(hello_failed)		-> 0;			%% Hello protocol failed. */
ofp_error_type(bad_request)		-> 1;			%% Request was not understood. */
ofp_error_type(bad_action)		-> 2;			%% Error in action description. */
ofp_error_type(bad_instruction)		-> 3;			%% Error in instruction list. */
ofp_error_type(bad_match)		-> 4;			%% Error in match. */
ofp_error_type(flow_mod_failed)		-> 5;			%% Problem modifying flow entry. */
ofp_error_type(group_mod_failed)	-> 6;			%% Problem modifying group entry. */
ofp_error_type(port_mod_failed)		-> 7;			%% Port mod request failed. */
ofp_error_type(table_mod_failed)	-> 8;			%% Table mod request failed. */
ofp_error_type(queue_op_failed)		-> 9;			%% Queue operation failed. */
ofp_error_type(switch_config_failed)	-> 10;			%% Switch config request failed. */

ofp_error_type(0)	-> hello_failed;
ofp_error_type(1)	-> bad_request;
ofp_error_type(2)	-> bad_action;
ofp_error_type(3)	-> bad_instruction;
ofp_error_type(4)	-> bad_match;
ofp_error_type(5)	-> flow_mod_failed;
ofp_error_type(6)	-> group_mod_failed;
ofp_error_type(7)	-> port_mod_failed;
ofp_error_type(8)	-> table_mod_failed;
ofp_error_type(9)	-> queue_op_failed;
ofp_error_type(10)	-> switch_config_failed;

ofp_error_type(X) when is_integer(X) -> X.

-spec ofp_error_code_type(ofp_error_type(), non_neg_integer()) -> atom() | 'error';
			 (ofp_error_type(), atom()) -> non_neg_integer() | 'error'.
ofp_error_code_type(hello_failed, 0) -> incompatible;
ofp_error_code_type(hello_failed, 1) -> eperm;

ofp_error_code_type(bad_request, 0) -> bad_version;
ofp_error_code_type(bad_request, 1) -> bad_type;
ofp_error_code_type(bad_request, 2) -> bad_stat;
ofp_error_code_type(bad_request, 3) -> bad_experimenter;
ofp_error_code_type(bad_request, 4) -> bad_subtype;
ofp_error_code_type(bad_request, 5) -> eperm;
ofp_error_code_type(bad_request, 6) -> bad_len;
ofp_error_code_type(bad_request, 7) -> buffer_empty;
ofp_error_code_type(bad_request, 8) -> buffer_unknown;
ofp_error_code_type(bad_request, 9) -> bad_table_id;

ofp_error_code_type(bad_action, 0) -> bad_type;
ofp_error_code_type(bad_action, 1) -> bad_len;
ofp_error_code_type(bad_action, 2) -> bad_experimenter;
ofp_error_code_type(bad_action, 3) -> bad_experimenter_type;
ofp_error_code_type(bad_action, 4) -> bad_out_port;
ofp_error_code_type(bad_action, 5) -> bad_argument;
ofp_error_code_type(bad_action, 6) -> eperm;
ofp_error_code_type(bad_action, 7) -> too_many;
ofp_error_code_type(bad_action, 8) -> bad_queue;
ofp_error_code_type(bad_action, 9) -> bad_out_group;
ofp_error_code_type(bad_action, 10) -> match_inconsistent;
ofp_error_code_type(bad_action, 11) -> unsupported_order;
ofp_error_code_type(bad_action, 12) -> bad_bad_tag;

ofp_error_code_type(bad_instruction_code, 0)	-> unknown_inst;				%% Unknown instruction.
ofp_error_code_type(bad_instruction_code, 1)	-> unsup_inst;					%% Switch or table does not support the instruction.
ofp_error_code_type(bad_instruction_code, 2)	-> bad_table_id;				%% Invalid Table-ID specified.
ofp_error_code_type(bad_instruction_code, 3)	-> unsup_metadata;				%% Metadata value unsupported by datapath.
ofp_error_code_type(bad_instruction_code, 4)	-> unsup_metadata_mask;				%% Metadata mask value unsupported by datapath.
ofp_error_code_type(bad_instruction_code, 5)	-> unsup_exp_inst;				%% Specific experimenter instruction unsupported

ofp_error_code_type(bad_match_code, 0)		-> bad_type;					%% Unsupported match type specified by the
												%% match
ofp_error_code_type(bad_match_code, 1)		-> bad_len;					%% Length problem in match.
ofp_error_code_type(bad_match_code, 2)		-> bad_tag;					%% Match uses an unsupported tag/encap.
ofp_error_code_type(bad_match_code, 3)		-> bad_dl_addr_mask;				%% Unsupported datalink addr mask - switch does
												%% not support arbitrary datalink address
												%% mask.
ofp_error_code_type(bad_match_code, 4)		-> bad_nw_addr_mask;				%% Unsupported network addr mask - switch does
												%% not support arbitrary network address
												%% mask.
ofp_error_code_type(bad_match_code, 5)		-> bad_wildcards;				%% Unsupported wildcard specified in the
												%% match.
ofp_error_code_type(bad_match_code, 6)		-> bad_field;					%% Unsupported field in the match.
ofp_error_code_type(bad_match_code, 7)		-> bad_value;					%% Unsupported value in a match field.

ofp_error_code_type(flow_mod_failed, 0)		-> unknown;
ofp_error_code_type(flow_mod_failed, 1)		-> tables_full;
ofp_error_code_type(flow_mod_failed, 2)		-> bad_table_id;
ofp_error_code_type(flow_mod_failed, 3)		-> overlap;
ofp_error_code_type(flow_mod_failed, 4)		-> eperm;
ofp_error_code_type(flow_mod_failed, 5)		-> bad_timeout;
ofp_error_code_type(flow_mod_failed, 6)		-> bad_command;

ofp_error_code_type(group_mod_failed, 0)	-> group_exists;				%% Group not added because a group ADD
												%% attempted to replace an
												%% already-present group.
ofp_error_code_type(group_mod_failed, 1)	-> invalid_group;				%% Group not added because Group specified
												%% is invalid.
ofp_error_code_type(group_mod_failed, 2)	-> weight_unsupported;				%% Switch does not support unequal load
												%% sharing with select groups.
ofp_error_code_type(group_mod_failed, 3)	-> out_of_groups;				%% The group table is full.
ofp_error_code_type(group_mod_failed, 4)	-> out_of_buckets;				%% The maximum number of action buckets
												%% for a group has been exceeded.
ofp_error_code_type(group_mod_failed, 5)	-> chaining_unsupported;			%% Switch does not support groups that
												%% forward to groups.
ofp_error_code_type(group_mod_failed, 6)	-> watch_unsupported;				%% This group cannot watch the
												%% watch_port or watch_group specified.
ofp_error_code_type(group_mod_failed, 7)	-> loop;					%% Group entry would cause a loop.
ofp_error_code_type(group_mod_failed, 8)	-> unknown_group;				%% Group not modified because a group
												%% MODIFY attempted to modify a
												%% non-existent group.
ofp_error_code_type(port_mod_failed, 0)		-> bad_port;
ofp_error_code_type(port_mod_failed, 1)		-> bad_hw_addr;
ofp_error_code_type(port_mod_failed, 2)		-> bad_config;
ofp_error_code_type(port_mod_failed, 3)		-> bad_advertise;

ofp_error_code_type(table_mod_failed, 0)	-> bad_table;
ofp_error_code_type(table_mod_failed, 1)	-> bad_config;

ofp_error_code_type(queue_op_failed, 0)		-> bad_port;
ofp_error_code_type(queue_op_failed, 1)		-> bad_queue;
ofp_error_code_type(queue_op_failed, 2)		-> eperm;

ofp_error_code_type(switch_config_failed, 0)	-> bad_flags;
ofp_error_code_type(switch_config_failed, 1)	-> bad_len;


ofp_error_code_type(hello_failed, incompatible)		-> 0;
ofp_error_code_type(hello_failed, eperm)		-> 1;

ofp_error_code_type(bad_request, bad_version)		-> 0;
ofp_error_code_type(bad_request, bad_type)		-> 1;
ofp_error_code_type(bad_request, bad_stat)		-> 2;
ofp_error_code_type(bad_request, bad_experimenter)	-> 3;
ofp_error_code_type(bad_request, bad_subtype)		-> 4;
ofp_error_code_type(bad_request, eperm)			-> 5;
ofp_error_code_type(bad_request, bad_len)		-> 6;
ofp_error_code_type(bad_request, buffer_empty)		-> 7;
ofp_error_code_type(bad_request, buffer_unknown)	-> 8;
ofp_error_code_type(bad_request, bad_table_id)		-> 9;

ofp_error_code_type(bad_action, bad_type)		-> 0;
ofp_error_code_type(bad_action, bad_len)		-> 1;
ofp_error_code_type(bad_action, bad_experimenter)	-> 2;
ofp_error_code_type(bad_action, bad_experimenter_type)	-> 3;
ofp_error_code_type(bad_action, bad_out_port)		-> 4;
ofp_error_code_type(bad_action, bad_argument)		-> 5;
ofp_error_code_type(bad_action, eperm)			-> 6;
ofp_error_code_type(bad_action, too_many)		-> 7;
ofp_error_code_type(bad_action, bad_queue)		-> 8;
ofp_error_code_type(bad_action, bad_out_group)		-> 9;
ofp_error_code_type(bad_action, match_inconsistent)	-> 10;
ofp_error_code_type(bad_action, unsupported_order)	-> 11;
ofp_error_code_type(bad_action, bad_bad_tag)		-> 12;

ofp_error_code_type(bad_instruction_code, unknown_inst)		-> 0;
ofp_error_code_type(bad_instruction_code, unsup_inst)		-> 1;
ofp_error_code_type(bad_instruction_code, bad_table_id)		-> 2;
ofp_error_code_type(bad_instruction_code, unsup_metadata)	-> 3;
ofp_error_code_type(bad_instruction_code, unsup_metadata_mask)	-> 4;
ofp_error_code_type(bad_instruction_code, unsup_exp_inst)	-> 5;

ofp_error_code_type(bad_match_code, bad_type)		-> 0;
ofp_error_code_type(bad_match_code, bad_len)		-> 1;
ofp_error_code_type(bad_match_code, bad_tag)		-> 2;
ofp_error_code_type(bad_match_code, bad_dl_addr_mask)	-> 3;
ofp_error_code_type(bad_match_code, bad_nw_addr_mask)	-> 4;
ofp_error_code_type(bad_match_code, bad_wildcards)	-> 5;
ofp_error_code_type(bad_match_code, bad_field)		-> 6;
ofp_error_code_type(bad_match_code, bad_value)		-> 7;

ofp_error_code_type(flow_mod_failed, all_tables_full)	-> 0;
ofp_error_code_type(flow_mod_failed, overlap)		-> 1;
ofp_error_code_type(flow_mod_failed, eperm)		-> 2;
ofp_error_code_type(flow_mod_failed, bad_emerg_timeout )-> 3;
ofp_error_code_type(flow_mod_failed, bad_command)	-> 4;
ofp_error_code_type(flow_mod_failed, unsupported)	-> 5;

ofp_error_code_type(group_mod_failed, group_exists)		-> 0;
ofp_error_code_type(group_mod_failed, invalid_group)		-> 1;
ofp_error_code_type(group_mod_failed, weight_unsupported)	-> 2;
ofp_error_code_type(group_mod_failed, out_of_groups)		-> 3;
ofp_error_code_type(group_mod_failed, out_of_buckets)		-> 4;
ofp_error_code_type(group_mod_failed, chaining_unsupported)	-> 5;
ofp_error_code_type(group_mod_failed, watch_unsupported)	-> 6;
ofp_error_code_type(group_mod_failed, loop)			-> 7;
ofp_error_code_type(group_mod_failed, unknown_group)		-> 8;

ofp_error_code_type(port_mod_failed, bad_port)		-> 0;
ofp_error_code_type(port_mod_failed, bad_hw_addr)	-> 1;
ofp_error_code_type(port_mod_failed, bad_config)	-> 2;
ofp_error_code_type(port_mod_failed, bad_advertise)	-> 3;

ofp_error_code_type(queue_op_failed, bad_port)		-> 0;
ofp_error_code_type(queue_op_failed, bad_queue)		-> 1;
ofp_error_code_type(queue_op_failed, eperm)		-> 2;

ofp_error_code_type(switch_config_failed, bad_flags)	-> 0;
ofp_error_code_type(switch_config_failed, bad_len)	-> 1;

ofp_error_code_type(_, _) -> error.

ofp_capabilities() ->
    [flow_stats, table_stats, port_stats, group_stats, reserved, ip_reasm, queue_stats, arp_match_ip].

ofp_action_type() ->
    [output,		%% Output to switch port.
     set_vlan_vid,	%% Set the 802.1q VLAN id.
     set_vlan_pcp,	%% Set the 802.1q priority.
     set_dl_src,	%% Ethernet source address.
     set_dl_dst,	%% Ethernet destination address.
     set_nw_src,	%% IP source address.
     set_nw_dst,	%% IP destination address.
     set_nw_tos,	%% IP ToS (DSCP field, 6 bits).
     set_nw_ecn,	%% IP ECN (2 bits).
     set_tp_src,	%% TCP/UDP/SCTP source port.
     set_tp_dst,	%% TCP/UDP/SCTP destination port.
     copy_ttl_out,	%% Copy TTL "outwards" -- from next-to-outermost to outermost
     copy_ttl_in,	%% Copy TTL "inwards" -- from outermost to next-to-outermost
     set_mpls_label,	%% MPLS label
     set_mpls_tc,	%% MPLS TC
     set_mpls_ttl,	%% MPLS TTL
     dec_mpls_ttl,	%% Decrement MPLS TTL
     push_vlan,		%% Push a new VLAN tag
     pop_vlan,		%% Pop the outer VLAN tag
     push_mpls,		%% Push a new MPLS tag
     pop_mpls,		%% Pop the outer MPLS tag
     set_queue,		%% Set queue id when outputting to a port
     group,		%% Apply group.
     set_nw_ttl,	%% IP TTL.
     dec_nw_ttl,	%% Decrement IP TTL.
     experimenter].

ofp_port_config() ->
    [port_down, undefined, no_recv, undefined, undefined, no_fwd, no_packet_in].

ofp_port_state() ->
    [link_down, blocked, live].

ofp_port_features() ->
    ['10mb_hd', '10mb_fd', '100mb_hd', '100mb_fd', '1gb_hd', '1gb_fd', '10gb_fd', '40gb_fd', '100gb_fd', '1tb_fd', other, copper, fiber, autoneg, pause, pause_asym].

ofp_packet_in_reason(0)	-> no_match;
ofp_packet_in_reason(1)	-> action;

ofp_packet_in_reason(no_match)	-> 0;
ofp_packet_in_reason(action)	-> 1;

ofp_packet_in_reason(_) -> error.

ofp_config_flags(0)	-> frag_normal;
ofp_config_flags(1)	-> frag_drop;
ofp_config_flags(2)	-> frag_reasm;
ofp_config_flags(4)	-> invalid_ttl_to_controller;

ofp_config_flags(frag_normal)			-> 0;
ofp_config_flags(frag_drop)			-> 1;
ofp_config_flags(frag_reasm)			-> 2;
ofp_config_flags(invalid_ttl_to_controller)	-> 4;

ofp_config_flags(_) -> error.

ofp_match_type(0)        -> standard;
ofp_match_type(standard) -> 0.

ofp_instruction_types() ->
    [goto_table, write_metadata, write_actions, apply_actions, clear_actions].

ofp_instruction_type(1)              -> goto_table;
ofp_instruction_type(2)              -> write_metadata;
ofp_instruction_type(3)              -> write_actions;
ofp_instruction_type(4)              -> apply_actions;
ofp_instruction_type(5)              -> clear_actions;
ofp_instruction_type(16#ffff)        -> experimenter;
ofp_instruction_type(goto_table)     -> 1;
ofp_instruction_type(write_metadata) -> 2;
ofp_instruction_type(apply_actions)  -> 3;
ofp_instruction_type(clear_actions)  -> 4;
ofp_instruction_type(experimenter)   -> 16#ffff.

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

ofp_table_config() ->
    [miss_controller, miss_continue, miss_drop].

ofp_group_mod_command(0)	-> add;
ofp_group_mod_command(1)	-> modify;
ofp_group_mod_command(2)	-> delete;
ofp_group_mod_command(add)	-> 0;
ofp_group_mod_command(modify)	-> 1;
ofp_group_mod_command(delete)	-> 2.

ofp_group_type(0)		-> all;
ofp_group_type(1)		-> select;
ofp_group_type(2)		-> indirect;
ofp_group_type(3)		-> ff;
ofp_group_type(all)		-> 0;
ofp_group_type(select)		-> 1;
ofp_group_type(indirect)	-> 2;
ofp_group_type(ff)		-> 3.

-spec ofp_port(non_neg_integer()) -> ofp_port_name() | non_neg_integer();
	      (ofp_port_name()) -> non_neg_integer().
%% Port numbering.  Physical ports are numbered starting from 1.
ofp_port(16#fffffff8) -> in_port;
ofp_port(16#fffffff9) -> table;
ofp_port(16#fffffffa) -> normal;
ofp_port(16#fffffffb) -> flood;
ofp_port(16#fffffffc) -> all;
ofp_port(16#fffffffd) -> controller;
ofp_port(16#fffffffe) -> local;
ofp_port(16#ffffffff) -> any;
ofp_port(X) when is_integer(X) -> X;

ofp_port(in_port)    -> 16#fffffff8;
ofp_port(table)      -> 16#fffffff9;
ofp_port(normal)     -> 16#fffffffa;
ofp_port(flood)      -> 16#fffffffb;
ofp_port(all)        -> 16#fffffffc;
ofp_port(controller) -> 16#fffffffd;
ofp_port(local)      -> 16#fffffffe;
ofp_port(any)        -> 16#ffffffff.

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
ofp_flow_removed_reason(3) -> group_delete;
ofp_flow_removed_reason(X) when is_integer(X) -> X;

ofp_flow_removed_reason(idle_timeout) -> 0;
ofp_flow_removed_reason(hard_timeout) -> 1;
ofp_flow_removed_reason(delete)       -> 2;
ofp_flow_removed_reason(group_delete) -> 3.

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

ofp_vendor_stats_type(VendorStatsType)	-> VendorStatsType.

-spec of_vendor_ext(of_vendor_ext()) -> {atom(), non_neg_integer()};
		   ({atom(), non_neg_integer()}) -> of_vendor_ext().
of_vendor_ext(VendorExt) ->	VendorExt.

protocol(NwProto)
  when is_atom(NwProto) ->
    gen_socket:protocol(NwProto);
protocol(NwProto) ->
    NwProto.

%%%===================================================================
%%% Decode
%%%===================================================================
decode_msg(error, << Type:16/integer, Code:16/integer, Data/binary >>) ->
    Type1 = ofp_error_type(Type),
    Code1 = ofp_error_code_type(Type1, Code),
    Error = {Type1, Code1},
    #ofp_error{error = Error, data = Data};

decode_msg(vendor, << Vendor:32/integer, Cmd:32/integer, Data/binary >>) ->
    decode_msg(of_vendor_ext({vendor(Vendor), Cmd}), Data);

decode_msg(features_reply, <<DataPathId:64/integer, NBuffers:32/integer, NTables:8/integer, Pad:3/bytes,
			     Capabilities:32/integer, _Reserved:32/integer, Ports/binary>>) ->
    ?DEBUG("DataPathId: ~p, NBuffers: ~p, NTables: ~p, Pad: ~p, Capabilities: ~p, Ports: ~p~n",
	   [DataPathId, NBuffers, NTables, Pad, Capabilities, Ports]),
    #ofp_switch_features{datapath_id = DataPathId,
			 n_buffers = NBuffers,
			 n_tables = NTables,
			 capabilities = dec_flags(ofp_capabilities(), Capabilities),
			 actions = [],
			 ports = decode_phy_ports(Ports)};

decode_msg(get_config_reply, <<Flags:16/integer, MissSendLen:16/integer>>) ->
    #ofp_switch_config{flags = ofp_config_flags(Flags), miss_send_len = MissSendLen};

decode_msg(set_config, <<Flags:16/integer, MissSendLen:16/integer>>) ->
    #ofp_switch_config{flags = ofp_config_flags(Flags), miss_send_len = MissSendLen};

decode_msg(packet_in, <<BufferId:32/integer, InPort:32/integer, InPhyPort:32/integer,
			TotalLen:16/integer, Reason:8/integer, TableId:8/integer, _Pad:2/bytes, Data/binary>>) ->
    #ofp_packet_in_v11{buffer_id = BufferId, in_port = ofp_port(InPort), in_phy_port = ofp_port(InPhyPort), 
		       total_len = TotalLen, reason = ofp_packet_in_reason(Reason), table_id = TableId, data = Data};

decode_msg(flow_removed, <<Cookie:64/integer, Priority:16/integer, Reason:8/integer, TableId:8/integer,
			   DurationSec:32/integer, DurationNSec:32/integer, IdleTimeout:16/integer, _Pad2:2/bytes,
			   PacketCount:64/integer, ByteCount:64/integer, Match/binary>>) ->
    #ofp_flow_removed_v11{cookie = Cookie, priority = Priority, reason = ofp_flow_removed_reason(Reason), table_id = TableId,
			  duration = {DurationSec, DurationNSec}, idle_timeout = IdleTimeout, packet_count = PacketCount,
			  byte_count = ByteCount, match = decode_ofp_match(Match)};

decode_msg(port_status, <<Reason:8/integer, _Pad:7/bytes, PhyPort/binary>>) ->
    #ofp_port_status{reason = ofp_port_reason(Reason),
		     port = decode_phy_port(PhyPort)};

decode_msg(packet_out, <<BufferId:32/integer, InPort:32/integer, ActionsLen:16/integer, _Pad:6/bytes, Actions:ActionsLen/bytes, Data/binary>>) ->
    #ofp_packet_out{buffer_id = BufferId, in_port = ofp_port(InPort), actions = decode_actions(Actions), data = Data};

decode_msg(flow_mod, <<Cookie:64/integer, CookieMask:64/integer, TableId:8/integer,
		       Command:8/integer, IdleTimeout:16/integer, HardTimeout:16/integer,
		       Priority:16/integer, BufferId:32/integer, OutPort:32/integer,
		       OutGroup:32/integer, Flags:16/integer, _Pad1:2/bytes,
		       Rest/binary>>) ->
    <<_MatchType:16/integer, MatchLength:16/integer, _/binary>> = Rest,
    <<Match:MatchLength/bytes, Instructions/binary>> = Rest,
    #ofp_flow_mod_v11{cookie = Cookie, cookie_mask = CookieMask, table_id = TableId,
		      command = ofp_flow_mod_command(Command),
		      idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
		      priority = Priority, buffer_id = BufferId,
		      out_port = ofp_port(OutPort), out_group = OutGroup,
		      flags = dec_flags(ofp_flow_mod_flags(), Flags),
		      match = decode_ofp_match(Match),
		      instructions = decode_ofp_instructions(Instructions)};

decode_msg(group_mod, <<Command:16/integer, Type:8/integer, _Pad:1/bytes,
			GroupId:32/integer, Buckets/binary>>) ->
    #ofp_group_mod{command = ofp_group_mod_command(Command),
		   type = ofp_group_type(Type),
		   group_id = GroupId,
		   buckets = decode_ofp_buckets(Buckets)};

decode_msg(port_mod, <<PortNo:32/integer, _Pad0:4/bytes, HwAddr:6/bytes, _Pad1:2/bytes,
		       Config:32/integer, Mask:32/integer, Advertise:32/integer, _Pad2:4/bytes>>) ->
    #ofp_port_mod{port_no = PortNo, hw_addr = HwAddr,
		  config = dec_flags(ofp_port_config(), Config),
		  mask = dec_flags(ofp_port_config(), Mask),
		  advertise = dec_flags(ofp_port_features(), Advertise)};

decode_msg(stats_request, <<Type:16/integer, _Flags:16/integer, _Pad:4/bytes, Msg/binary>>) ->
    decode_stats_request(ofp_stats_type(Type), Msg);

decode_msg(stats_reply, <<Type:16/integer, _Flags:16/integer, Msg/binary>>) ->
    decode_stats_reply(ofp_stats_type(Type), [], Msg);

decode_msg(queue_get_config_request, <<Port:32/integer, _Pad:4/bytes>>) ->
    #ofp_queue_get_config_request{port = ofp_port(Port)};

decode_msg(ofp_queue_get_config_reply, <<Port:32/integer, _Pad:4/bytes, Queues/binary>>) ->
    #ofp_queue_get_config_reply{port = ofp_port(Port), queues = decode_queues(Queues)};

decode_msg(_, Msg) ->
    Msg.

-spec decode_ofp_match(Match :: binary()) -> #ofp_match_standard{}.
decode_ofp_match(<<0:16, 88:16, InPort:32/integer, Wildcards:32/integer,
		   DlSrc:6/binary, DlSrcMask:6/binary, DlDst:6/binary, DlDstMask:6/binary,
		   DlVlan:16/integer, DlVlanPcp:8/integer,
		   _Pad1:1/bytes, 
		   DlType:16/integer, NwTos:8/integer, NwProto:8/integer,
		   NwSrc:4/bytes, NwSrcMask:4/bytes, NwDst:4/bytes, NwDstMask:4/bytes,
		   TpSrc:16/integer, TpDst:16/integer,
		   MplsLabel:32/integer, MplsTc:8/integer, _Pad2:3/bytes,
		   MetaData:8/bytes, MetaDataMask:8/bytes>>) ->

    ?DEBUG("DlType: ~w, NwTos: ~w", [DlType, NwTos]),
    #ofp_match_standard{in_port = ofp_port(InPort), wildcards = Wildcards,
			dl_src = DlSrc, dl_src_mask = DlSrcMask, dl_dst = DlDst, dl_dst_mask = DlDstMask,
			dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = eth_type(DlType),
			nw_tos = NwTos, nw_proto = protocol(NwProto),
			nw_src = NwSrc, nw_src_mask = NwSrcMask, nw_dst = NwDst, nw_dst_mask = NwDstMask,
			tp_src = TpSrc, tp_dst = TpDst,
			mpls_label = MplsLabel, mpls_tc = MplsTc,
			metadata = MetaData, metadata_mask = MetaDataMask}.

-spec decode_ofp_instructions(Instructions :: binary()) -> [ofp_instructions()].
decode_ofp_instructions(Instructions) ->
    decode_ofp_instructions(Instructions, []).

decode_ofp_instructions(<<>>, Acc) ->
    lists:reverse(Acc);
decode_ofp_instructions(<<Type:16/integer, Len:16/integer, Rest/binary>>, Acc) ->
    PayLoadLen = Len - 4,
    <<PayLoad:PayLoadLen/bytes, Next>> = Rest,
    decode_ofp_instructions(Next, [decode_ofp_instruction(ofp_instruction_type(Type), PayLoad)|Acc]).
decode_ofp_instruction(goto_table, <<TableId:8/integer, _Pad:3/bytes>>) ->
    #ofp_instruction_goto_table{table_id = TableId};
decode_ofp_instruction(write_metadata, <<_Pad:32, MetaData:64/integer, MetaDataMask:64/integer>>) ->
    #ofp_instruction_write_metadata{metadata = MetaData, metadata_mask = MetaDataMask};
decode_ofp_instruction(Type, <<_Pad:4/bytes, Actions/binary>>) ->
    #ofp_instruction_actions{type = Type, actions = decode_actions(Actions)}.

decode_ofp_buckets(Buckets) ->
    decode_ofp_buckets(Buckets, []).

decode_ofp_buckets(<<>>, Acc) ->
    lists:reverse(Acc);
decode_ofp_buckets(<<Len:16/integer, Weight:16/integer, WatchPort:32/integer,
		     WatchGroup:32/integer, _Pad:4/bytes, Rest/binary>>, Acc) ->
    ActionsLen = Len - 16,
    <<Actions:ActionsLen/bytes, Next>> = Rest,
    Bucket = #ofp_bucket{weight = Weight, watch_port = ofp_port(WatchPort),
			 watch_group = WatchGroup, actions = decode_actions(Actions)},
    decode_ofp_buckets(Next, [Bucket|Acc]).

decode_experimenter_action(Experimenter, Msg) ->
    #ofp_action_experimenter{experimenter = Experimenter, msg = Msg}.

-spec decode_action(Type :: non_neg_integer(), Length :: non_neg_integer(), binary()) -> ofp_action().
decode_action(0, 4, <<Port:32/integer, MaxLen:16/integer, _:48>>) ->
    #ofp_action_output{port = ofp_port(Port), max_len = MaxLen};
decode_action(1, 4, <<VlanVid:16/integer, _:16>>) ->
    #ofp_action_vlan_vid{vlan_vid = VlanVid};
decode_action(2, 4, <<VlanPcp:8/integer, _:24>>) ->
    #ofp_action_vlan_pcp{vlan_pcp = VlanPcp};
decode_action(3, 12, <<Addr:6/binary, _:48>>) ->
    #ofp_action_dl_addr{type = src, dl_addr = Addr};
decode_action(4, 12, <<Addr:6/binary, _:48>>) ->
    #ofp_action_dl_addr{type = dst, dl_addr = Addr};
decode_action(5, 4, <<Addr:4/binary>>) ->
    #ofp_action_nw_addr{type = src, nw_addr = Addr};
decode_action(6, 4, <<Addr:4/binary>>) ->
    #ofp_action_nw_addr{type = dst, nw_addr = Addr};
decode_action(7, 4, <<NwTos:8/integer, _:24>>) ->
    #ofp_action_nw_tos{nw_tos = NwTos};
decode_action(8, 4, <<ECN:8/integer, _:24>>) ->
    #ofp_action_set_nw_ecn{ecn = ECN};
decode_action(9, 4, <<TpPort:16/integer, _:16>>) ->
    #ofp_action_tp_port{type = src, tp_port = TpPort};
decode_action(10, 4, <<TpPort:16/integer, _:16>>) ->
    #ofp_action_tp_port{type = dst, tp_port = TpPort};
decode_action(11, 0, <<>>) ->
    #ofp_action_copy_ttl_out{};
decode_action(12, 0, <<>>) ->
    #ofp_action_copy_ttl_in{};
decode_action(13, 4, <<MplsLabel:32/integer>>) ->
    #ofp_action_set_mpls_label{label = MplsLabel};
decode_action(14, 4, <<MplsTc:8/integer, _:24>>) ->
    #ofp_action_set_mpls_tc{tc = MplsTc};
decode_action(15, 4, <<MplsTtl:8/integer, _:24>>) ->
    #ofp_action_set_mpls_ttl{ttl = MplsTtl};
decode_action(16, 0, <<>>) ->
    #ofp_action_dec_mpls_ttl{};
decode_action(17, 4, <<EtherType:16/integer, _:16>>) ->
    #ofp_action_push_vlan{ethertype = EtherType};
decode_action(18, 0, <<>>) ->
    #ofp_action_pop_vlan{};
decode_action(19, 4, <<EtherType:16/integer, _:16>>) ->
    #ofp_action_push_mpls{ethertype = EtherType};
decode_action(20, 4, <<EtherType:16/integer, _:16>>) ->
    #ofp_action_pop_mpls{ethertype = EtherType};
decode_action(21, 4, <<QueueId:32/integer>>) ->
    #ofp_action_set_queue{queue_id = QueueId};
decode_action(22, 4, <<GroupId:32/integer>>) ->
    #ofp_action_group{group_id = GroupId};
decode_action(23, 4, <<NwTtl:8/integer, _:24>>) ->
    #ofp_action_set_nw_ttl{ttl = NwTtl};
decode_action(24, 0, <<>>) ->
    #ofp_action_dec_nw_ttl{};

decode_action(16#FFFF, Length, <<Experimenter:32, Msg/binary>> = PayLoad)
  when Length == size(PayLoad) ->
    decode_experimenter_action(experimenter(Experimenter), Msg);
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

decode_phy_port(<<PortNo:32/integer, _Pad1:4/bytes,
		  HwAddr:6/binary, _Pad2:2/bytes, Name:16/binary,
		  Config:32/integer, State:32/integer,
		  Curr:32/integer, Advertised:32/integer,
		  Supported:32/integer, Peer:32/integer,
		  CurrSpeed:32/integer, MaxSpeed:32/integer>>) ->
    #ofp_phy_port{port_no = ofp_port(PortNo),
		  hw_addr = HwAddr,
		  name = decode_binstring(Name),
		  config = dec_flags(ofp_port_config(), Config),
		  state = dec_flags(ofp_port_state(), State),
		  curr = dec_flags(ofp_port_features(), Curr),
		  advertised = dec_flags(ofp_port_features(), Advertised),
		  supported = dec_flags(ofp_port_features(), Supported),
		  peer = dec_flags(ofp_port_features(), Peer),
		  curr_speed = CurrSpeed, max_speed = MaxSpeed}.

decode_phy_ports(Msg) ->
    [ decode_phy_port(Port) || <<Port:64/binary>> <= Msg].

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

decode_stats_request(flow, <<TableId:8/integer, _Pad0:3/bytes, OutPort:32/integer, OutGroup:32/integer,
			     _Pad1:4/bytes, Cookie:64/integer, CookieMask:64/integer, Match/binary>>) ->
    #ofp_flow_stats_request_v11{table_id = ofp_table(TableId), out_port = ofp_port(OutPort),
				out_group = OutGroup, cookie = Cookie, cookie_mask = CookieMask,
				match = decode_ofp_match(Match)};

decode_stats_request(aggregate, <<TableId:8/integer, _Pad0:3/bytes, OutPort:32/integer, OutGroup:32/integer,
			     _Pad1:4/bytes, Cookie:64/integer, CookieMask:64/integer, Match/binary>>) ->
    #ofp_aggregate_stats_request_v11{table_id = ofp_table(TableId), out_port = ofp_port(OutPort),
				     out_group = OutGroup, cookie = Cookie, cookie_mask = CookieMask,
				     match = decode_ofp_match(Match)};

decode_stats_request(table, <<>>) ->
    #ofp_table_stats_request{};

decode_stats_request(port, <<Port:32/integer, _Pad:4/bytes>>) ->
    #ofp_port_stats_request{port_no = ofp_port(Port)};

decode_stats_request(queue, <<Port:32/integer, Queue:32/integer>>) ->
    #ofp_queue_stats_request{port_no = ofp_port(Port), queue_id = ofp_queue(Queue)};

decode_stats_request(group, <<GroupId:32/integer, _Pad:4/bytes>>) ->
    #ofp_group_stats_request{group_id = GroupId};

decode_stats_request(group_desc, <<>>) ->
    #ofp_group_desc_stats_request{};

decode_stats_request(vendor, <<Vendor:32/integer, Msg/binary>>) ->
    decode_vendor_stats_request(vendor(Vendor), Msg).

decode_vendor_stats_request(Vendor, <<SubType:32/integer, _Pad:4/bytes, Msg/binary>>) ->
    decode_stats_request(ofp_vendor_stats_type({Vendor, SubType}), Msg).

decode_stats_reply(_, Acc, <<>>) ->
    lists:reverse(Acc);

decode_stats_reply(desc, Acc, <<MfrDesc:256/bytes, HwDesc:256/bytes, SwDesc:256/bytes,
				SerialNum:32/bytes, DpDesc:256/bytes, Rest/binary>>) ->
    R = #ofp_desc_stats{mfr_desc = decode_binstring(MfrDesc), hw_desc = decode_binstring(HwDesc),
			sw_desc = decode_binstring(SwDesc), serial_num = decode_binstring(SerialNum),
			dp_desc = decode_binstring(DpDesc)},
    decode_stats_reply(desc, [R|Acc], Rest);

decode_stats_reply(flow, Acc, <<Length:16/integer, TableId:8/integer, _Pad0:1/bytes, Sec:32/integer, NSec:32/integer,
				Priority:16/integer, IdleTimeout:16/integer, HardTimeout:16/integer, _Pad2:6/bytes,
				Cookie:64/integer, PacketCount:64/integer, ByteCount:64/integer, More/binary>>) ->

    RestLength = Length - 48,
    <<Rest:RestLength/bytes, Next/binary>> = More,
    <<_MatchType:16/integer, MatchLength:16/integer, _/binary>> = Rest,
    <<Match:MatchLength/bytes, Instructions/binary>> = Rest,

    R = #ofp_flow_stats_v11{table_id = ofp_table(TableId), duration = {Sec, NSec},
			    priority = Priority,
			    idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
			    packet_count = PacketCount, byte_count = ByteCount,
			    match = decode_ofp_match(Match), instructions = decode_ofp_instructions(Instructions)},
    decode_stats_reply(flow, [R|Acc], Next);

decode_stats_reply(aggregate, Acc, <<PacketCount:64/integer, ByteCount:64/integer, FlowCount:32/integer, _Pad:4/bytes, Rest/binary>>) ->
    R = #ofp_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount,
			     flow_count = FlowCount},
    decode_stats_reply(aggregate, [R|Acc], Rest);

decode_stats_reply(table, Acc, <<TableId:8/integer, _Pad:7/bytes, Name:32/bytes, Wildcards:32/integer,
				 Match:32/integer, Instructions:32/integer, WriteActions:32/integer,
				 ApplyActions:32/integer, Config:32/integer, MaxEntries:32/integer,
				 ActiveCount:32/integer, LookupCount:64/integer, MatchedCount:64/integer,
				 Rest/binary>>) ->
    R = #ofp_table_stats_v11{table_id = ofp_table(TableId), name = decode_binstring(Name),
			     wildcards = Wildcards, match = Match, 
			     instructions = dec_flags(ofp_instruction_types(), Instructions),
			     write_actions = dec_flags(ofp_action_type(), WriteActions),
			     apply_actions = dec_flags(ofp_action_type(), ApplyActions),
			     config = Config, max_entries = MaxEntries,
			     active_count = ActiveCount, lookup_count = LookupCount, matched_count = MatchedCount},
    decode_stats_reply(table, [R|Acc], Rest);

decode_stats_reply(port, Acc, <<Port:32/integer, _Pad:4/bytes, RxPackets:64/integer, TxPackets:64/integer,
				RxBytes:64/integer, TxBytes:64/integer, RxDropped:64/integer, TxDropped:64/integer,
				RxErrors:64/integer, TxErrors:64/integer, RxFrameErr:64/integer, RxOverErr:64/integer,
				RxCrcErr:64/integer, Collisions:64/integer, Rest/binary>>) ->
    R = #ofp_port_stats{port_no = ofp_port(Port), rx_packets = RxPackets, tx_packets = TxPackets,
			rx_bytes = RxBytes, tx_bytes = TxBytes, rx_dropped = RxDropped,
			tx_dropped = TxDropped,	rx_errors = RxErrors, tx_errors = TxErrors,
			rx_frame_err = RxFrameErr, rx_over_err = RxOverErr,
			rx_crc_err = RxCrcErr, collisions = Collisions},
    decode_stats_reply(port, [R|Acc], Rest);

decode_stats_reply(queue, Acc, <<Port:32/integer, Queue:32/integer, TxBytes:64/integer,
				 TxPackets:64/integer, TxErrors:64/integer, Rest/binary>>) ->
    R = #ofp_queue_stats{port_no = ofp_port(Port), queue_id = ofp_queue(Queue),
			 tx_bytes = TxBytes, tx_packets = TxPackets, tx_errors = TxErrors},
    decode_stats_reply(queue, [R|Acc], Rest);

decode_stats_reply(group, Acc, <<Len:16/integer, _Pad0:2/bytes, GroupId:32/integer, RefCount:32/integer,
				 _Pad1:4/bytes, PacketCount:64/integer, ByteCount:64/integer, More/binary>>) ->
    BucketStatsLen = Len - 32,
    <<BucketStats:BucketStatsLen/bytes, Rest/binary>> = More,
    R = #ofp_group_stats{group_id = GroupId, ref_count = RefCount,
			 packet_count = PacketCount, byte_count = ByteCount,
			 bucket_stats = decode_ofp_bucket_stats(BucketStats)},
    decode_stats_reply(group, [R|Acc], Rest);

decode_stats_reply(group_desc, Acc, <<Len:16, Type:8, _Pad:1/bytes, GroupId:32, More/binary>>) ->
    BucketsLen = Len - 8,
    <<Buckets:BucketsLen/bytes, Rest/binary>> = More,
    R = #ofp_group_desc_stats{type = ofp_group_type(Type), group_id = GroupId, buckets = decode_ofp_buckets(Buckets)},
    decode_stats_reply(group_desc, [R|Acc], Rest);

decode_stats_reply(vendor, Acc, <<Vendor:32/integer, Msg/binary>>) ->
    decode_vendor_stats(vendor(Vendor), Acc, Msg).

decode_vendor_stats(Vendor, Acc, <<SubType:32/integer, _Pad:4/bytes, Msg/binary>>) ->
    decode_stats_reply(ofp_vendor_stats_type({Vendor, SubType}), Acc, Msg).

decode_ofp_bucket_stats(BucketStats) ->
    [#ofp_bucket_counter{packet_count = PacketCount, byte_count = ByteCount} || <<PacketCount: 64/integer, ByteCount:64/integer>> <= BucketStats].

%%%===================================================================
%%% Encode
%%%===================================================================
%% -spec encode_ovs_vendor({Vendor :: atom(), Cmd :: non_neg_integer()}, binary()) -> binary();
%% 		       ({Vendor :: non_neg_integer(), Cmd :: non_neg_integer()}, binary()) -> binary();
%% 		       (Cmd :: of_vendor_ext(), binary()) -> binary().
%% encode_ovs_vendor({Vendor, Cmd}, Data)
%%   when is_atom(Vendor) ->
%%     encode_ovs_vendor({vendor(Vendor), Cmd}, Data);
%% encode_ovs_vendor({Vendor, Cmd}, Data) ->
%%     << Vendor:32, Cmd:32, Data/binary >>;
%% encode_ovs_vendor(Cmd, Data) ->
%%     encode_ovs_vendor(of_vendor_ext(Cmd), Data).

-spec encode_ofp_switch_features(integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_switch_features(DataPathId, NBuffers, NTables, Capabilities, Ports) ->
    <<DataPathId:64, NBuffers:32, NTables:8, 0:24, Capabilities:32, 0:32, Ports/binary>>.

-spec encode_ofp_error(non_neg_integer(), non_neg_integer(), binary()) -> binary().
encode_ofp_error(Type, Code, Data) ->
    <<Type:16/integer, Code:16/integer, Data/binary>>.

-spec encode_phy_port(integer(), binary(), binary(), integer(), integer(), integer(), integer(), integer(), integer(), integer(), integer()) -> binary().
encode_phy_port(PortNo, HwAddr, Name, Config, State,Curr, Advertised, Supported, Peer, CurrSpeed, MaxSpeed) ->
    Name0 = pad_to(16, Name),
    <<PortNo:32, 0:32, HwAddr:6/bytes, 0:16, Name0:16/bytes, Config:32, State:32, Curr:32, Advertised:32, Supported:32, Peer:32, CurrSpeed:32, MaxSpeed:32>>.

encode_phy_port(#ofp_phy_port{port_no = PortNo,
			      hw_addr = HwAddr,
			      name = Name,
			      config = Config,
			      state = State,
			      curr = Curr,
			      advertised = Advertised,
			      supported = Supported,
			      peer = Peer,
			      curr_speed = CurrSpeed,
			      max_speed = MaxSpeed}) ->
    encode_phy_port(ofp_port(PortNo), HwAddr, Name, 
		    enc_flags(ofp_port_config(), Config),
		    enc_flags(ofp_port_state(), State),
		    enc_flags(ofp_port_features(), Curr),
		    enc_flags(ofp_port_features(), Advertised),
		    enc_flags(ofp_port_features(), Supported),
		    enc_flags(ofp_port_features(), Peer),
		    MaxSpeed, CurrSpeed).

encode_phy_ports(Ports) ->
    << << (encode_phy_port(P))/binary >> || P <- Ports >>.

encode_ofp_port_status(Reason, Port) ->
    Reason0 = ofp_port_reason(Reason),
    <<Reason0:8, 0:56, Port/binary>>.

-spec encode_queue_get_config_request(integer()) -> binary().
encode_queue_get_config_request(Port) ->
    <<Port:32>>.

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
    <<Port:32, 0:32, Queues/binary>>.

-spec encode_ofp_switch_config(integer(), integer()) -> binary().
encode_ofp_switch_config(Flags, MissSendLen) ->
    <<Flags:16, MissSendLen:16>>.

%% -spec bool(boolean()) -> 0 | 1;
%% 	  (non_neg_integer()) -> boolean().
%% bool(true) -> 1;
%% bool(false) -> 0;
%% bool(0) -> false;
%% bool(_) -> true.

int_maybe_undefined(X) when is_integer(X) -> X;
int_maybe_undefined(undefined) -> 0.

bin_maybe_undefined(X, Len) when is_binary(X) -> pad_to(Len, X);
bin_maybe_undefined(undefined, Len) -> pad_to(Len, <<0>>).

bin_fixed_length(X, Len) when size(X) > Len -> binary_part(X, {0, Len});
bin_fixed_length(X, Len) -> bin_maybe_undefined(X, Len).

-spec encode_ofp_match_standard(ofp_port(), integer(), binary(), binary(), binary(),
				binary(),  integer(),  integer(), integer()|atom(),
				integer(), integer()|atom(), binary(), binary(), binary(),
				binary(), integer(), integer(), integer(), integer(),
				binary(), binary()) -> binary().
encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			  DlVlan, DlVlanPcp, DlType, NwTos, NwProto,
			  NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			  MplsLabel, MplsTc, MetaData, MetaDataMask)
  when is_atom(NwProto), DlType == arp ->
    NwProto0 = int_maybe_undefined(flower_arp:op(NwProto)),
    encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			      DlVlan, DlVlanPcp, DlType, NwTos, NwProto0,
			      NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			      MplsLabel, MplsTc, MetaData, MetaDataMask);

encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			  DlVlan, DlVlanPcp, DlType, NwTos, NwProto,
			  NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			  MplsLabel, MplsTc, MetaData, MetaDataMask)
  when is_atom(NwProto) ->
    NwProto0 = int_maybe_undefined(protocol(NwProto)),
    encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			      DlVlan, DlVlanPcp, DlType, NwTos, NwProto0,
			      NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			      MplsLabel, MplsTc, MetaData, MetaDataMask);

encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			  DlVlan, DlVlanPcp, DlType, NwTos, NwProto,
			  NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			  MplsLabel, MplsTc, MetaData, MetaDataMask) ->
    InPort0 = ofp_port(InPort),
    DlType0 = eth_type(DlType),
    DlSrc0 = bin_maybe_undefined(DlSrc, 6),
    DlSrcMask0 = bin_maybe_undefined(DlSrcMask, 6),
    DlDst0 = bin_maybe_undefined(DlDst, 6),
    DlDstMask0 = bin_maybe_undefined(DlDstMask, 6),
    NwSrc0 = bin_maybe_undefined(NwSrc, 4),
    NwSrcMask0 = bin_maybe_undefined(NwSrcMask, 4),
    NwDst0 = bin_maybe_undefined(NwDst, 4),
    NwDstMask0 = bin_maybe_undefined(NwDstMask, 4),
    TpSrc0 = int_maybe_undefined(TpSrc),
    TpDst0 = int_maybe_undefined(TpDst),
    <<(ofp_match_type(standard)):16, 88:16, InPort0:32, Wildcards:32,
      DlSrc0:6/binary, DlSrcMask0:6/binary, DlDst0:6/binary, DlDstMask0:6/binary, DlVlan:16, DlVlanPcp:8, 0:8, DlType0:16,
      NwTos:8, NwProto:8, NwSrc0:4/binary, NwSrcMask0:4/binary, NwDst0:4/binary, NwDstMask0:4/binary,
      TpSrc0:16, TpDst0:16,
      MplsLabel:32, MplsTc:8, 0:24,
      MetaData/binary, MetaDataMask/binary>>.

-spec encode_ofs_action(int16(), binary()) -> binary().
encode_ofs_action(Type, Data) ->
    Len = 4 + size(Data),
    <<Type:16, Len:16, Data/binary>>.

-spec encode_ofs_action_output(ofp_port(), int16()) -> binary().
encode_ofs_action_output(Port, MaxLen) ->
    Port0 = ofp_port(Port),
    encode_ofs_action(0, <<Port0:32, MaxLen:16, 0:48>>).

-spec encode_ofs_action_vlan_vid(int16()) -> binary().
encode_ofs_action_vlan_vid(VlanVid) ->
    encode_ofs_action(1, <<VlanVid:16, 0:16>>).

-spec encode_ofs_action_vlan_pcp(int8()) -> binary().
encode_ofs_action_vlan_pcp(VlanPcp) ->
    encode_ofs_action(2, <<VlanPcp:8, 0:24>>).

-spec encode_ofs_action_dl_addr(ofp_addr_type(), binary()) -> binary().
encode_ofs_action_dl_addr(src, Addr) ->
    encode_ofs_action(3, <<Addr:6/bytes, 0:48>>);
encode_ofs_action_dl_addr(dst, Addr) ->
    encode_ofs_action(4, <<Addr:6/bytes, 0:48>>).

-spec encode_ofs_action_nw_addr(ofp_addr_type(), binary()) -> binary().
encode_ofs_action_nw_addr(src, Addr) ->
    encode_ofs_action(5, <<Addr:4/bytes>>);
encode_ofs_action_nw_addr(dst, Addr) ->
    encode_ofs_action(6, <<Addr:4/bytes>>).

-spec encode_ofs_action_nw_tos(int8()) -> binary().
encode_ofs_action_nw_tos(NwTos) ->
    encode_ofs_action(7, <<NwTos:8, 0:24>>).

-spec encode_ofs_action_set_nw_ecn(int8()) -> binary().
encode_ofs_action_set_nw_ecn(NwECN) ->
    encode_ofs_action(8, <<NwECN:8, 0:24>>).

-spec encode_ofs_action_tp_addr(ofp_addr_type(), int16()) -> binary().
encode_ofs_action_tp_addr(src, TpPort) ->
    encode_ofs_action(9, <<TpPort:16, 0:16>>);
encode_ofs_action_tp_addr(dst, TpPort) ->
    encode_ofs_action(10, <<TpPort:16, 0:16>>).

-spec encode_ofs_action_copy_ttl_out() -> binary().
encode_ofs_action_copy_ttl_out() ->
    encode_ofs_action(11, <<>>).

-spec encode_ofs_action_copy_ttl_in() -> binary().
encode_ofs_action_copy_ttl_in() ->
    encode_ofs_action(12, <<>>).

-spec encode_ofs_action_set_mpls_label(int32()) -> binary().
encode_ofs_action_set_mpls_label(MplsLabel) ->
    encode_ofs_action(13, <<MplsLabel:32>>).

-spec encode_ofs_action_set_mpls_tc(int8()) -> binary().
encode_ofs_action_set_mpls_tc(MplsTc) ->
    encode_ofs_action(14, <<MplsTc:8, 0:24>>).

-spec encode_ofs_action_set_mpls_ttl(int8()) -> binary().
encode_ofs_action_set_mpls_ttl(MplsTTL) ->
    encode_ofs_action(15, <<MplsTTL:8, 0:24>>).

-spec encode_ofs_action_dec_mpls_ttl() -> binary().
encode_ofs_action_dec_mpls_ttl() ->
    encode_ofs_action(16, <<>>).

-spec encode_ofs_action_push_vlan(int16()) -> binary().
encode_ofs_action_push_vlan(EtherType) ->
    encode_ofs_action(17, <<EtherType:16, 0:16>>).

-spec encode_ofs_action_pop_vlan() -> binary().
encode_ofs_action_pop_vlan() ->
    encode_ofs_action(18, <<>>).

-spec encode_ofs_action_push_mpls(int16()) -> binary().
encode_ofs_action_push_mpls(EtherType) ->
    encode_ofs_action(19, <<EtherType:16, 0:16>>).

-spec encode_ofs_action_pop_mpls(int16()) -> binary().
encode_ofs_action_pop_mpls(EtherType) ->
    encode_ofs_action(20, <<EtherType:16, 0:16>>).

-spec encode_ofs_action_set_queue(int32()) -> binary().
encode_ofs_action_set_queue(QueueId) ->
    encode_ofs_action(21, <<QueueId:32>>).

-spec encode_ofs_action_group(int32()) -> binary().
encode_ofs_action_group(GroupId) ->
    encode_ofs_action(22, <<GroupId:32>>).

-spec encode_ofs_action_set_nw_ttl(int8()) -> binary().
encode_ofs_action_set_nw_ttl(NwTTL) ->
    encode_ofs_action(23, <<NwTTL:8, 0:24>>).

-spec encode_ofs_action_dec_nw_ttl() -> binary().
encode_ofs_action_dec_nw_ttl() ->
    encode_ofs_action(24, <<>>).

-spec encode_ofs_action_experimenter(int32(), binary()) -> binary().
encode_ofs_action_experimenter(Experimenter, Msg) ->
    encode_ofs_action(16#FFFF, <<Experimenter:32, (pad_to(8, Msg))/binary>>).

-spec encode_ofp_flow_mod(Cookie :: integer(), CookieMask :: integer(), TableId :: integer(), 
			  Command :: ofp_command() | non_neg_integer(),
			  IdleTimeout :: integer(), HardTimeout:: integer(),
			  Priority :: integer(), BufferId :: integer(),
			  OutPort :: ofp_port(), OutGroup :: ofp_group(),
			  Flags :: integer(), Match :: binary(), Instructions :: binary()|list(binary)) -> binary().
encode_ofp_flow_mod(Cookie, CookieMask, TableId, Command, IdleTimeout, HardTimeout, Priority,
		    BufferId, OutPort, OutGroup, Flags, Match, Instructions) when is_list(Instructions) ->
    encode_ofp_flow_mod(Cookie, CookieMask, TableId, Command, IdleTimeout, HardTimeout, Priority,
			BufferId, OutPort, OutGroup, Flags, Match, list_to_binary(Instructions));
encode_ofp_flow_mod(Cookie, CookieMask, TableId, Command, IdleTimeout, HardTimeout, Priority,
		    BufferId, OutPort, OutGroup, Flags, Match, Instructions) ->
    OutPort0 = ofp_port(OutPort),
    Cmd = ofp_flow_mod_command(Command),
    <<Cookie:64, CookieMask:64, TableId:8, Cmd:8, IdleTimeout:16, HardTimeout:16,
      Priority:16, BufferId:32, OutPort0:32, OutGroup:32, Flags:16, 0:16, Match/binary, Instructions/binary>>.

-spec encode_ofp_group_mod(Command :: ofp_group_mod_command(), Type :: ofp_group_type(),
			   GroupId :: integer(), Buckets :: binary()|list(binary)) -> binary().
encode_ofp_group_mod(Command, Type, GroupId, Buckets) when is_list(Buckets) ->
    encode_ofp_group_mod(Command, Type, GroupId, list_to_binary(Buckets));
encode_ofp_group_mod(Command, Type, GroupId, Buckets) ->
    Cmd = ofp_group_mod_command(Command),
    Type0 = ofp_group_type(Type),
    <<Cmd:16, Type0:8, 0:8, GroupId:32, Buckets/binary>>.

-spec encode_ofp_flow_removed(integer(), integer(), integer()|atom(), integer(), tuple(integer(), integer()), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_flow_removed(Cookie, Priority, Reason, TableId, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount, Match) when is_atom(Reason) ->
    Reason0 = ofp_flow_removed_reason(Reason),
    encode_ofp_flow_removed(Cookie, Priority, Reason0, TableId, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount, Match);
encode_ofp_flow_removed(Cookie, Priority, Reason, TableId, {DurationSec, DurationNSec}, IdleTimeout, PacketCount, ByteCount, Match) ->
    <<Cookie:64, Priority:16, Reason:8, TableId:8, DurationSec:32, DurationNSec:32, IdleTimeout:16, 0:16,
      PacketCount:64, ByteCount:64, Match/binary>>.

-spec encode_ofp_packet_in(integer(), integer(), integer(), integer(), integer(), integer(), binary()) -> binary().
encode_ofp_packet_in(BufferId, InPort, InPhyPort, TotalLen, Reason, TableId, Data) ->
    <<BufferId:32, InPort:32, InPhyPort:32, TotalLen:16, Reason:8, TableId:8, 0:16, Data/binary>>.

-spec encode_ofp_packet_out(integer(), integer()|atom(), binary(), list(binary())|binary()) -> binary().
encode_ofp_packet_out(BufferId, InPort, Actions, Data) when is_list(Actions) ->
    encode_ofp_packet_out(BufferId, InPort, list_to_binary(Actions), Data);
encode_ofp_packet_out(BufferId, InPort, Actions, Data) ->
    InPort0 = ofp_port(InPort),
    <<BufferId:32, InPort0:32, (size(Actions)):16, 0:48, Actions/binary, Data/binary>>.

-spec encode_ofp_port_mod(integer(), binary(), integer(), integer(), integer()) -> binary().
encode_ofp_port_mod(PortNo, HwAddr, Config, Mask, Advertise) ->
    <<PortNo:32, 0:32, HwAddr/binary, 0:2, Config:32, Mask:32, Advertise:32>>.

-spec encode_ofp_table_mod(integer(), binary()) -> binary().
encode_ofp_table_mod(TableId, Config) ->
    <<TableId:8, 0:24, Config:32>>.

encode_ofp_desc_stats(MfrDesc, HwDesc, SwDesc, SerialNum, DpDesc) ->
    MfrDesc0 = bin_fixed_length(MfrDesc, 256),
    HwDesc0 = bin_fixed_length(HwDesc, 256),
    SwDesc0 = bin_fixed_length(SwDesc, 256),
    SerialNum0 = bin_fixed_length(SerialNum, 32),
    DpDesc0 = bin_fixed_length(DpDesc, 256),
    <<MfrDesc0:256/bytes, HwDesc0:256/bytes, SwDesc0:256/bytes, SerialNum0:32/bytes, DpDesc0:256/bytes>>.

encode_ofp_flow_stats_request(TableId, OutPort, OutGroup, Cookie, CookieMask, Match) ->
    TableId0 = ofp_table(TableId),
    OutPort0 = ofp_port(OutPort),
    <<TableId0:8, 0:24, OutPort0:32, OutGroup:32, 0:32, Cookie:64, CookieMask:64, Match/binary>>.

encode_ofp_flow_stats(TableId, {Sec, NSec} = _Duration, Priority, IdleTimeout, HardTimeout,
		      Cookie, PacketCount, ByteCount, Match, Instructions) ->
    Length = 48 + size(Match) + size(Instructions),
    <<Length:16, TableId:8, 0:8, Sec:32, NSec:32, Priority:16, IdleTimeout:16, HardTimeout:16, 0:48,
      Cookie:64, PacketCount:64, ByteCount:64, Match/binary, Instructions/binary>>.

encode_ofp_aggregate_stats_request(TableId, OutPort, OutGroup, Cookie, CookieMask, Match) ->
    TableId0 = ofp_table(TableId),
    OutPort0 = ofp_port(OutPort),
    <<TableId0:8, 0:24, OutPort0:32, OutGroup:32, 0:32, Cookie:64, CookieMask:64, Match/binary>>.

encode_ofp_aggregate_stats(PacketCount, ByteCount, FlowCount) ->
    <<PacketCount:64, ByteCount:64, FlowCount:32, 0:32>>.

encode_ofp_table_stats(TableId, Name, Wildcards, Match, Instructions, WriteActions,
		       ApplyActions, Config, MaxEntries, ActiveCount, LookupCount, MatchedCount) ->
    Name0 = bin_fixed_length(Name, 32),
    <<TableId:8, 0:56, Name0/binary, Wildcards:32, Match:32, Instructions:32, WriteActions:32,
      ApplyActions:32, Config:32, MaxEntries:32, ActiveCount:32, LookupCount:64, MatchedCount:64>>.

encode_ofp_port_stats_request(Port) ->
    Port0 = ofp_port(Port),
    <<Port0:32, 0:32>>.

encode_ofp_port_stats(Port, RxPackets, TxPackets, RxBytes, TxBytes, RxDropped, TxDropped,
		      RxErrors, TxErrors, RxFrameErr, RxOverErr, RxCrcErr, Collisions) ->
    <<Port:32, 0:32, RxPackets:64, TxPackets:64, RxBytes:64, TxBytes:64, RxDropped:64, TxDropped:64,
      RxErrors:64, TxErrors:64, RxFrameErr:64, RxOverErr:64, RxCrcErr:64, Collisions:64>>.

encode_ofp_queue_stats_request(Port, Queue) ->
    Port0 = ofp_port(Port),
    Queue0 = ofp_queue(Queue),
    <<Port0:32, Queue0:32>>.

encode_ofp_queue_stats(Port, Queue, TxBytes, TxPackets, TxErrors) ->
    <<Port:32, Queue:32, TxBytes:64, TxPackets:64, TxErrors:64>>.

encode_ofp_group_stats_request(GroupId) ->
    <<GroupId:32, 0:32>>.

encode_ofp_group_stats(GroupId, RefCount, PacketCount, ByteCount, BucketStats) ->
    Len = 32 + size(BucketStats),
    <<Len:16, 0:16, GroupId:32, RefCount:32, 0:32, PacketCount: 64, ByteCount:64, BucketStats/binary>>.

encode_ofp_bucket_stats(PacketCount, ByteCount) ->
    <<PacketCount: 64, ByteCount:64>>.

encode_ofp_group_desc_stats(Type, GroupId, Buckets) ->
    Len = 8 + size(Buckets),
    Type0 = ofp_group_type(Type),
    <<Len:16, Type0:8, 0:8, GroupId:32, Buckets/binary>>.

encode_ofp_stats_request(Type, Flags, Body) when is_atom(Type) ->
    encode_ofp_stats_request(ofp_stats_type(Type), Flags, Body);
encode_ofp_stats_request(Type, Flags, Body) when is_integer(Type) ->
    <<Type:16, Flags:16, 0:32, Body/binary>>.

%% TODO: we don't support flags in stats replies...
encode_ofp_stats({vendor, Type}, Body) ->
    encode_ofp_vendor_stats(Type, Body);
encode_ofp_stats(Type, Body) when is_atom(Type) ->
    encode_ofp_stats(ofp_stats_type(Type), Body);
encode_ofp_stats(Type, Body) when is_integer(Type) ->
    <<Type:16, 0:16, Body/binary>>.

encode_ofp_vendor_stats(Type, Body) when is_atom(Type) ->
    encode_ofp_vendor_stats(ofp_vendor_stats_type(Type), Body).

encode_action(#ofp_action_output{port = Port, max_len = MaxLen}) ->
    encode_ofs_action_output(Port, MaxLen);

encode_action(#ofp_action_vlan_vid{vlan_vid = VlanVid}) ->
    encode_ofs_action_vlan_vid(VlanVid);

encode_action(#ofp_action_vlan_pcp{vlan_pcp = VlanPcp}) ->
    encode_ofs_action_vlan_pcp(VlanPcp);

encode_action(#ofp_action_dl_addr{type = Type, dl_addr = DlAddr}) ->
    encode_ofs_action_dl_addr(Type, DlAddr);

encode_action(#ofp_action_nw_addr{type = Type, nw_addr = NwAddr}) ->
    encode_ofs_action_nw_addr(Type, NwAddr);

encode_action(#ofp_action_nw_tos{nw_tos = NwTos}) ->
    encode_ofs_action_nw_tos(NwTos);

encode_action(#ofp_action_set_nw_ecn{ecn = ECN}) ->
    encode_ofs_action_set_nw_ecn(ECN);

encode_action(#ofp_action_tp_port{type = Type, tp_port = TpPort}) ->
    encode_ofs_action_tp_addr(Type, TpPort);

encode_action(#ofp_action_copy_ttl_out{}) ->
    encode_ofs_action_copy_ttl_out();

encode_action(#ofp_action_copy_ttl_in{}) ->
    encode_ofs_action_copy_ttl_in();

encode_action(#ofp_action_set_mpls_label{label = MplsLabel}) ->
    encode_ofs_action_set_mpls_label(MplsLabel);

encode_action(#ofp_action_set_mpls_tc{tc = MplsTc}) ->
    encode_ofs_action_set_mpls_tc(MplsTc);

encode_action(#ofp_action_set_mpls_ttl{ttl = MplsTtl}) ->
    encode_ofs_action_set_mpls_ttl(MplsTtl);

encode_action(#ofp_action_dec_mpls_ttl{}) ->
    encode_ofs_action_dec_mpls_ttl();

encode_action(#ofp_action_push_vlan{ethertype = EtherType}) ->
    encode_ofs_action_push_vlan(EtherType);

encode_action(#ofp_action_pop_vlan{}) ->
    encode_ofs_action_pop_vlan();

encode_action(#ofp_action_push_mpls{ethertype = EtherType}) ->
    encode_ofs_action_push_mpls(EtherType);

encode_action(#ofp_action_pop_mpls{ethertype = EtherType}) ->
    encode_ofs_action_pop_mpls(EtherType);

encode_action(#ofp_action_set_queue{queue_id = QueueId}) ->
    encode_ofs_action_set_queue(QueueId);

encode_action(#ofp_action_group{group_id = GroupId}) ->
    encode_ofs_action_group(GroupId);

encode_action(#ofp_action_set_nw_ttl{ttl = TTL}) ->
    encode_ofs_action_set_nw_ttl(TTL);

encode_action(#ofp_action_dec_nw_ttl{}) ->
    encode_ofs_action_dec_nw_ttl();

encode_action(#ofp_action_experimenter{experimenter = Experimenter, msg = Msg}) ->
    encode_ofs_action_experimenter(Experimenter, Msg);

encode_action(Action) when is_binary(Action) ->
    pad_to(8, Action).

encode_actions(List) when is_list(List) ->
    iolist_to_binary([encode_action(A) || A <- List]);
encode_actions(Action) when is_tuple(Action) ->
    encode_action(Action).

%% Instructions
encode_instruction(Type, Instruction) ->
    <<(ofp_instruction_type(Type)):16, (size(Instruction) + 4):16, Instruction/binary>>.

encode_instruction_goto_table(TableId) ->
    encode_instruction(goto_table, <<TableId:8, 0:24>>).
encode_instruction_write_metadata(MetaData, MetaDataMask) ->
    encode_instruction(write_metadata, <<0:32, MetaData:64, MetaDataMask:64>>).
encode_instruction_actions(Type, Actions) ->
    encode_instruction(Type, <<0:32, (encode_actions(Actions))/binary>>).
    

encode_instruction(#ofp_instruction_goto_table{table_id = TableId}) ->
    encode_instruction_goto_table(TableId);
encode_instruction(#ofp_instruction_write_metadata{metadata = MetaData, metadata_mask = MetaDataMask}) ->
    encode_instruction_write_metadata(MetaData, MetaDataMask);
encode_instruction(#ofp_instruction_actions{type = Type, actions = Actions}) ->
    encode_instruction_actions(Type, Actions);

encode_instruction(Instruction) when is_binary(Instruction) ->
    pad_to(8, Instruction).

encode_instructions(List) when is_list(List) ->
    iolist_to_binary([encode_instruction(A) || A <- List]);
encode_instructions(Instruction) when is_tuple(Instruction) ->
    encode_instruction(Instruction).

%% Buckets
encode_bucket(#ofp_bucket{weight = Weight, watch_port = WatchPort,
			  watch_group = WatchGroup, actions = Actions}) ->
    Actions0 = encode_actions(Actions),
    Len = 16 + size(Actions0),
    <<Len:16, Weight:16, (ofp_port(WatchPort)):32, WatchGroup:32, 0:32, Actions0/binary>>.

encode_buckets(List) when is_list(List) ->
    iolist_to_binary([encode_bucket(A) || A <- List]);
encode_buckets(Bucket) when is_tuple(Bucket) ->
    encode_bucket(Bucket).

%% Stats Reques/Reply

encode_stats_reply_entry(#ofp_desc_stats{mfr_desc = MfrDesc, hw_desc = HwDesc, sw_desc = SwDesc,
					 serial_num = SerialNum, dp_desc = DpDesc}) ->
    encode_ofp_desc_stats(MfrDesc, HwDesc, SwDesc, SerialNum, DpDesc);

encode_stats_reply_entry(#ofp_flow_stats_v11{table_id = TableId, duration = Duration, priority = Priority,
					     idle_timeout = IdleTimeout, hard_timeout = HardTimeout, cookie = Cookie,
					     packet_count = PacketCount, byte_count = ByteCount, match = Match, instructions = Instructions}) ->
    encode_ofp_flow_stats(TableId, Duration, Priority, IdleTimeout, HardTimeout,
			  Cookie, PacketCount, ByteCount, encode_match(Match), encode_instructions(Instructions));

encode_stats_reply_entry(#ofp_aggregate_stats{packet_count = PacketCount, byte_count = ByteCount, flow_count = FlowCount}) ->
    encode_ofp_aggregate_stats(PacketCount, ByteCount, FlowCount);

encode_stats_reply_entry(#ofp_table_stats_v11{table_id = TableId, name = Name, wildcards = Wildcards,
					      match = Match, instructions = Instructions,
					      write_actions = WriteActions, apply_actions = ApplyActions,
					      config = Config, max_entries = MaxEntries, active_count = ActiveCount,
					      lookup_count = LookupCount, matched_count = MatchedCount}) ->
    encode_ofp_table_stats(TableId, Name, Wildcards, Match, 
			   enc_flags(ofp_instruction_types(), Instructions),
			   enc_flags(ofp_action_type(), WriteActions),
			   enc_flags(ofp_action_type(), ApplyActions),
			   Config, MaxEntries, ActiveCount, LookupCount, MatchedCount);

encode_stats_reply_entry(#ofp_port_stats{port_no = Port, rx_packets = RxPackets, tx_packets = TxPackets, rx_bytes = RxBytes, tx_bytes = TxBytes,
					 rx_dropped = RxDropped, tx_dropped = TxDropped, rx_errors = RxErrors, tx_errors = TxErrors,
					 rx_frame_err = RxFrameErr, rx_over_err = RxOverErr, rx_crc_err = RxCrcErr, collisions = Collisions}) ->
    encode_ofp_port_stats(Port, RxPackets, TxPackets, RxBytes, TxBytes, RxDropped, TxDropped,
			  RxErrors, TxErrors, RxFrameErr, RxOverErr, RxCrcErr, Collisions);

encode_stats_reply_entry(#ofp_queue_stats{port_no = Port, queue_id = Queue, tx_bytes = TxBytes, tx_packets = TxPackets, tx_errors = TxErrors}) ->
    encode_ofp_queue_stats(Port, Queue, TxBytes, TxPackets, TxErrors);

encode_stats_reply_entry(#ofp_group_stats{group_id = GroupId, ref_count = RefCount,
					  packet_count = PacketCount, byte_count = ByteCount,
					  bucket_stats = BucketStats}) ->
        encode_ofp_group_stats(GroupId, RefCount, PacketCount, ByteCount, encode_bucket_stats(BucketStats));

encode_stats_reply_entry(#ofp_group_desc_stats{type = Type, group_id = GroupId, buckets = Buckets}) ->
        encode_ofp_group_desc_stats(Type, GroupId, encode_bucket(Buckets)).

encode_bucket_counter(#ofp_bucket_counter{packet_count = PacketCount,
					  byte_count = ByteCount}) ->
    encode_ofp_bucket_stats(PacketCount, ByteCount).

encode_bucket_stats(BucketStats) when is_binary(BucketStats) ->
    BucketStats;
encode_bucket_stats(BucketStats) when is_tuple(BucketStats) ->
    encode_bucket_counter(BucketStats);
encode_bucket_stats(BucketStats) when is_list(BucketStats) ->
    << <<(encode_bucket_counter(B))/binary>> || B <- BucketStats>>.

stats_reply_record_type(ofp_desc_stats)			-> desc;
stats_reply_record_type(ofp_flow_stats)			-> flow;
stats_reply_record_type(ofp_aggregate_stats)		-> aggregate;
stats_reply_record_type(ofp_table_stats)		-> table;
stats_reply_record_type(ofp_port_stats)			-> port;
stats_reply_record_type(ofp_queue_stats)		-> queue.

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

encode_match(#ofp_match_standard{in_port = InPort, wildcards = Wildcards,
				 dl_src = DlSrc, dl_src_mask = DlSrcMask, dl_dst = DlDst, dl_dst_mask = DlDstMask,
				 dl_vlan = DlVlan, dl_vlan_pcp = DlVlanPcp, dl_type = DlType,
				 nw_tos = NwTos, nw_proto = NwProto,
				 nw_src = NwSrc, nw_src_mask = NwSrcMask, nw_dst = NwDst, nw_dst_mask = NwDstMask,
				 tp_src = TpSrc, tp_dst = TpDst,
				 mpls_label = MplsLabel, mpls_tc = MplsTc, metadata = MetaData, metadata_mask = MetaDataMask}) ->
    encode_ofp_match_standard(InPort, Wildcards, DlSrc, DlSrcMask, DlDst, DlDstMask,
			      DlVlan, DlVlanPcp, DlType, NwTos, NwProto,
			      NwSrc, NwSrcMask, NwDst, NwDstMask, TpSrc, TpDst,
			      MplsLabel, MplsTc, MetaData, MetaDataMask);

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
				ports = Ports}) ->
    encode_ofp_switch_features(DataPathId, NBuffers, NTables,
			       enc_flags(ofp_capabilities(), Capabilities),
			       encode_phy_ports(Ports));

encode_msg(#ofp_switch_config{flags = Flags, miss_send_len = MissSendLen}) ->
    encode_ofp_switch_config(ofp_config_flags(Flags), MissSendLen);

encode_msg(#ofp_packet_in_v11{buffer_id = BufferId, in_port = InPort,in_phy_port = InPhyPort, 
			      total_len = TotalLen, reason = Reason, table_id = TableId, data = Data}) ->
    encode_ofp_packet_in(BufferId, ofp_port(InPort), ofp_port(InPhyPort),
			 TotalLen, ofp_packet_in_reason(Reason), TableId, Data);

encode_msg(#ofp_flow_removed_v11{cookie = Cookie, priority = Priority, reason = Reason,
				 table_id = TableId, duration = Duration, idle_timeout = IdleTimeout,
				 packet_count = PacketCount, byte_count = ByteCount, match = Match}) ->
    encode_ofp_flow_removed(Cookie, Priority, Reason, TableId, Duration,
			    IdleTimeout, PacketCount, ByteCount, encode_match(Match));

encode_msg(#ofp_port_status{reason = Reason, port = Port}) ->
    encode_ofp_port_status(Reason, encode_phy_port(Port));

encode_msg(#ofp_packet_out{buffer_id = BufferId, in_port = InPort, actions = Actions, data = Data}) ->
    encode_ofp_packet_out(BufferId, InPort, encode_actions(Actions), Data);

encode_msg(#ofp_flow_mod_v11{cookie = Cookie, cookie_mask = CookieMask, table_id = TableId,
			     command = Command, idle_timeout = IdleTimeout, hard_timeout = HardTimeout,
			     priority = Priority, buffer_id = BufferId,
			     out_port = OutPort, out_group = OutGroup,
			     flags = Flags, match = Match, instructions = Instructions}) ->
    encode_ofp_flow_mod(Cookie, CookieMask, TableId, Command, IdleTimeout, HardTimeout, Priority,
			BufferId, OutPort, OutGroup, enc_flags(ofp_flow_mod_flags(), Flags),
			encode_match(Match), encode_instructions(Instructions));

encode_msg(#ofp_group_mod{command = Command, type = Type,
			  group_id = GroupId, buckets = Buckets}) ->
    encode_ofp_group_mod(Command, Type, GroupId, encode_buckets(Buckets));

encode_msg(#ofp_port_mod{port_no = PortNo, hw_addr = HwAddr,
			 config = Config, mask = Mask, advertise = Advertise}) ->
    encode_ofp_port_mod(PortNo, HwAddr, enc_flags(ofp_port_config(), Config),
			enc_flags(ofp_port_config(), Mask), enc_flags(ofp_port_features(), Advertise));

encode_msg(#ofp_table_mod{table_id = TableId, config = Config}) ->
    encode_ofp_table_mod(TableId, enc_flags(ofp_table_config(), Config));

encode_msg(#ofp_queue_get_config_request{port = Port}) ->
    encode_queue_get_config_request(ofp_port(Port));

encode_msg(#ofp_queue_get_config_reply{port = Port, queues = Queues}) ->
    encode_ofp_queue_get_config_reply(port = ofp_port(Port), encode_ofp_packet_queues(Queues));

encode_msg([Head|_] = Msg)
  when is_record(Head, ofp_desc_stats); is_record(Head, ofp_flow_stats_v11); is_record(Head, ofp_aggregate_stats);
       is_record(Head, ofp_table_stats_v11); is_record(Head, ofp_port_stats); is_record(Head, ofp_queue_stats);
       is_record(Head, ofp_group_stats); is_record(Head, ofp_group_desc_stats) ->
    encode_stats_reply(Msg, element(1, Head));

encode_msg(#ofp_desc_stats_request{}) ->
    encode_ofp_stats_request(desc, 0, <<>>);

encode_msg(#ofp_flow_stats_request_v11{table_id = TableId, out_port = OutPort, out_group = OutGroup,
				       cookie = Cookie, cookie_mask = CookieMask, match = Match}) ->
    encode_ofp_stats_request(flow, 0, encode_ofp_flow_stats_request(TableId, OutPort, OutGroup,
								    Cookie, CookieMask, encode_match(Match)));

encode_msg(#ofp_aggregate_stats_request_v11{table_id = TableId, out_port = OutPort, out_group = OutGroup,
					    cookie = Cookie, cookie_mask = CookieMask, match = Match}) ->
    encode_ofp_stats_request(aggregate, 0, encode_ofp_aggregate_stats_request(TableId, OutPort, OutGroup,
									      Cookie, CookieMask, encode_match(Match)));
encode_msg(#ofp_table_stats_request{}) ->
    encode_ofp_stats_request(table, 0, <<>>);

encode_msg(#ofp_port_stats_request{port_no = Port}) ->
    encode_ofp_stats_request(port, 0, encode_ofp_port_stats_request(Port));

encode_msg(#ofp_queue_stats_request{port_no = Port, queue_id = Queue}) ->
    encode_ofp_stats_request(queue, 0, encode_ofp_queue_stats_request(Port, Queue));

encode_msg(#ofp_group_stats_request{group_id = GroupId}) ->
    encode_ofp_stats_request(group, 0, encode_ofp_group_stats_request(GroupId));

encode_msg(#ofp_group_desc_stats_request{}) ->
    encode_ofp_stats_request(group_desc, 0, <<>>);

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
