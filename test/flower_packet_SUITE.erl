%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 29 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_packet_SUITE).

-compile(export_all).

-include("../include/flower_packet.hrl").
-include("../include/flower_flow.hrl").
-include_lib("common_test/include/ct.hrl").

ofp_switch_features_reply() ->
	<<1,6,0,176,0,0,0,3,0,0,0,35,32,245,84,249,0,0,1,0,2,
	  0,0,0,0,0,0,135,0,0,15,255,0,2,0,80,86,174,0,20,
	  101,116,104,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,1,0,0,2,128,0,0,2,175,0,0,2,175,0,0,0,0,255,254,
	  0,35,32,131,73,116,100,112,48,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,1,0,80,86,174,0,19,101,116,104,49,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,160,0,0,2,175,
	  0,0,2,175,0,0,0,0>>.

ofp_packet_in() ->
	<<1,10,0,76,0,0,0,0,255,255,255,0,0,58,255,254,0,0,255,255,255,
	  255,255,255,0,35,32,192,4,32,0,44,170,170,3,0,35,32,160,51,79,
	  112,101,110,32,118,83,119,105,116,99,104,32,67,111,110,116,114,
	  111,108,108,101,114,32,80,114,111,98,101,0,0,35,32,192,4,32>>.

ofp_packet_out() ->
	<<1,13,0,82,0,0,0,0,255,255,255,0,255,254,0,8,0,0,0,8,255,251,0,0,255,
        255,255,255,255,255,0,35,32,250,101,249,0,44,170,170,3,0,35,32,160,51,
        79,112,101,110,32,118,83,119,105,116,99,104,32,67,111,110,116,114,111,
        108,108,101,114,32,80,114,111,98,101,0,0,35,32,250,101,249>>.

ofp_flow_mod_add() ->
	<<1,14,0,80,0,0,0,0,0,8,32,240,255,254,0,35,32,131,73,116,0,25,185,71,250,19,
	  255,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,60,0,0,
	  0,0,0,0,1,107,0,0,0,0,0,0,0,8,0,1,0,0>>.

ofp_flow_removed() ->
	<<1,11,0,88,0,0,0,0,0,48,0,15,255,254,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,8,0,0,1,0,0,10,48,0,1,10,48,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,61,7,8,137,128,0,60,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,1,
	  38,1,11,0,88,0,0,0,0,0,48,0,15,255,254,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,8,0,0,17,0,0,10,48,0,3,10,48,127,255,2,119,2,119,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,60,21,71,99,64,0,60,0,0,0,0,0,0,0,0,0,2,
	  0,0,0,0,0,0,1,196>>.

ofp_set_config() ->
	<<1,9,0,12,0,0,0,6,0,0,0,128>>.

ofp_port_status_cfg_down() ->
	<<1,12,0,64,0,0,0,0,2,0,0,0,0,0,0,0,0,1,0,80,86,174,0,19,101,116,
	  104,49,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,2,160,0,0,2,
	  175,0,0,2,175,0,0,0,0>>.

ofp_port_status_lnk_down() ->
	<<1,12,0,64,0,0,0,0,2,0,0,0,0,0,0,0,0,1,0,80,86,174,0,19,101,116,
	  104,49,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,2,160,0,0,2,
	  175,0,0,2,175,0,0,0,0>>.

ofp_port_status_lnk_up() ->
	<<1,12,0,64,0,0,0,0,2,0,0,0,0,0,0,0,0,1,0,80,86,174,0,19,101,116,
	  104,49,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,160,0,0,2,
	  175,0,0,2,175,0,0,0,0>>.

ofp_stats_reply_desc() ->
	<<1,17,4,44,0,0,0,4,0,0,0,0,78,105,99,105,114,97,32,78,101,116,
	  119,111,114,107,115,44,32,73,110,99,46,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  79,112,101,110,32,118,83,119,105,116,99,104,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,49,46,49,46,49,43,98,117,105,108,100,48,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,78,111,110,101,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,78,111,110,101,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

ofp_stats_reply_table() ->
	<<1,17,0,76,0,0,0,4,0,3,0,0,0,0,0,0,99,108,97,115,115,105,102,105,
	  101,114,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,63,255,
	  255,0,16,0,0,0,0,0,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

ofp_stats_reply_port() ->
	<<1,17,0,220,0,0,0,4,0,4,0,0,255,254,0,0,0,0,0,0,0,0,0,0,0,0,26,
	  187,0,0,0,0,0,1,9,12,0,0,0,0,0,14,90,28,0,0,0,0,0,116,51,35,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
	  0,0,0,0,0,0,0,0,0,0,0,5,97,140,0,0,0,0,0,1,44,58,0,0,0,0,1,187,
	  65,233,0,0,0,0,0,88,188,102,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

ofp_nxst_flow_stats() ->
	<<1,17,0,216,0,0,0,16,255,255,0,0,0,0,35,32,0,0,0,0,0,0,0,0,0,96,
	  0,0,0,0,0,1,14,1,208,192,0,0,0,60,0,0,0,37,0,0,0,0,0,0,0,0,0,0,
	  0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,98,0,0,6,2,8,0,0,0,14,4,10,48,
	  0,2,0,0,16,4,10,48,0,3,0,0,12,1,1,0,0,26,1,0,0,0,28,1,0,0,0,0,0,
	  0,0,8,0,1,0,0,0,96,0,0,0,0,0,0,13,242,142,128,0,0,0,60,0,0,0,37,
	  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,98,0,0,6,
	  2,8,0,0,0,14,4,10,48,0,3,0,0,16,4,10,48,0,2,0,0,12,1,1,0,0,26,1,
	  8,0,0,28,1,0,0,0,0,0,0,0,8,255,254,0,0>>.

v12_ofp_hello() ->
    hexstr2bin("03000008e9ad0355").

v12_ofp_features_request() ->
    hexstr2bin("030500083a528eed").

v12_ofp_features_reply() ->
    hexstr2bin("030600203a528eed692c8bf65add495c0000040001000000000000c700000000").

v12_ofp_get_config_request() ->
    hexstr2bin("030700083a528eed").

v12_ofp_get_config_reply() ->
    hexstr2bin("0308000c3a528eed00000080").

v12_ofp_table_stats_request() ->
    hexstr2bin("031200103a528eed0003000000000000").

v12_ofp_table_stats_reply() ->
    hexstr2bin("0313009000000008000300000000000000000000000000005445535400000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "00000000000000000000000000000000").

v12_rofl_broken_table_stats_request() ->
    hexstr2bin("0312041030cdd336000300000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "00000000000000000000000000000000").


v12_rofl_broken_table_stats_reply() ->
    hexstr2bin("0313006830cdd336000300000000000000000000000000007461626c65303030"
	       "300000000000000000000000000000000000000000000000ffff0000ffff0000"
	       "3e0000000198ff3f0198ff3f0000000000040000000000000000000000000000"
	       "0000000000000000").

% hexstr2bin
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

test_hello_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = hello, xid = 8, msg = <<>>},
	{[Sw],_} = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_echo_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = echo_request, xid = 8, msg = <<>>},
	{[Sw],_} = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_echo_reply(_Config) ->
	Sw = #ovs_msg{version = 1, type = echo_reply, xid = 8, msg = <<>>},
	{[Sw],_} = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_switch_features_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = features_request, xid = 2, msg = <<>>},
	{[Sw],_} = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_switch_features_reply(_Config) ->
	Sw = ofp_switch_features_reply(),
	{[Msg = #ovs_msg{msg = #ofp_switch_features{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_packet_out(_Config) ->
	Sw = ofp_packet_out(),
	{[Msg = #ovs_msg{msg = #ofp_packet_out{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_packet_in(_Config) ->
	Sw = ofp_packet_in(),
	{[Msg = #ovs_msg{msg = #ofp_packet_in{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.
	
test_flow_mod_add(_Config) ->
	Sw = ofp_flow_mod_add(),
	{[Msg = #ovs_msg{msg = #ofp_flow_mod{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_flow_removed(_Config) ->
	Sw = ofp_flow_removed(),
	{Msg = [#ovs_msg{msg = #ofp_flow_removed{}}|[#ovs_msg{msg = #ofp_flow_removed{}}]],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_port_status_cfg_down(_Config) ->
	Sw = ofp_port_status_cfg_down(),
	{[Msg = #ovs_msg{msg = #ofp_port_status{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_port_status_lnk_down(_Config) ->
	Sw = ofp_port_status_lnk_down(),
	{[Msg = #ovs_msg{msg = #ofp_port_status{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_port_status_lnk_up(_Config) ->
	Sw = ofp_port_status_lnk_up(),
	{[Msg = #ovs_msg{msg = #ofp_port_status{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_set_config(_Config) ->
	Sw = ofp_set_config(),
	{[Msg = #ovs_msg{msg = #ofp_switch_config{}}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_flow_mod(_Config) ->
	IP = <<127,0,0,1>>,
	Flow = #flow{dl_type = ip, nw_src = IP, nw_dst = IP},
	ActionsBin = <<>>,
	MatchSrc = flower_packet:encode_match(flower_match:encode_ofp_matchflow([{nw_src_mask,32}, dl_type], Flow)),
	PktSrc = flower_packet:encode_ofp_flow_mod(MatchSrc, 0, delete, 0, 0, 0, -1, none, 1, ActionsBin),
	OutSrc = flower_packet:encode(#ovs_msg{version = 1, type = flow_mod, xid = 20, msg = PktSrc}),
	flower_packet:decode(OutSrc),

	MatchDst = flower_packet:encode_match(flower_match:encode_ofp_matchflow([{nw_dst_mask,32}, dl_type], Flow)),
	PktDst = flower_packet:encode_ofp_flow_mod(MatchDst, 0, delete, 0, 0, 0, -1, none, 1, ActionsBin),
	OutDst = flower_packet:encode(#ovs_msg{version = 1, type = flow_mod, xid = 20, msg = PktDst}),
	flower_packet:decode(OutDst).


test_nx_flow_mod(_Config) ->
	NxMatches = [
				  {nxm_of_in_port, << 0:16 >>},
				  {nxm_of_eth_dst, << 0,1,2,3,4,5 >>},
				  {nxm_of_eth_dst_w, {<< 0,1,2,3,4,5 >>, << 255,255,255,255,255,255 >>}},
				  {nxm_of_eth_src, << 0,1,2,3,4,5 >>},
				  {nxm_of_eth_type, << 0:16 >>},
				  {nxm_of_vlan_tci, << 0:16 >>},
				  {nxm_of_vlan_tci_w, {<< 0:16 >>, << 0:16 >>}},
				  {nxm_of_ip_tos, << 0 >>},
				  {nxm_of_ip_proto, << 0 >>},
				  {nxm_of_ip_src, << 1,2,3,4 >>},
				  {nxm_of_ip_src_w, {<< 1,2,3,4 >>, << 255,255,255,255 >>}},
				  {nxm_of_ip_dst, << 5,6,7,8 >>},
				  {nxm_of_ip_dst_w, {<<  5,6,7,8 >>, << 255,255,255,255 >>}},
				  {nxm_of_tcp_src, << 0:16 >>},
				  {nxm_of_tcp_dst, << 0:16 >>},
				  {nxm_of_udp_src, << 0:16 >>},
				  {nxm_of_udp_dst, << 0:16 >>},
				  {nxm_of_icmp_type, << 0 >>},
				  {nxm_of_icmp_code, << 0 >>},
				  {nxm_of_arp_op, << 0:16 >>},
				  {nxm_of_arp_spa, << 0:32 >>},
				  {nxm_of_arp_spa_w, {<< 0:32 >>, << 255,255,255,255 >>}},
				  {nxm_of_arp_tpa, << 0:32 >>},
				  {nxm_of_arp_tpa_w, {<< 0:32 >>, << 255,255,255,255 >>}},
				  {nxm_nx_tun_id, << 0,1,2,3,4,5,6,7 >>},
				  {nxm_nx_tun_id_w, {<< 0,1,2,3,4,5,6,7 >>, << 255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_arp_sha, << 0,1,2,3,4,5 >>},
				  {nxm_nx_arp_tha, << 0,1,2,3,4,5 >>},
				  {nxm_nx_ipv6_src, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_ipv6_src_w, {<< 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>, << 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_ipv6_dst, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_ipv6_dst_w, {<< 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>, << 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_icmpv6_type, << 0 >>},
				  {nxm_nx_icmpv6_code, << 0 >>},
				  {nxm_nx_nd_target, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_nd_sll, << 0,1,2,3,4,5 >>},
				  {nxm_nx_nd_tll, << 0,1,2,3,4,5 >>}],
	Actions = [
				#ofp_action_output{port = local, max_len = 123},
				#ofp_action_vlan_vid{vlan_vid = 1},
				#ofp_action_vlan_pcp{vlan_pcp = 2},
				#ofp_action_strip_vlan{},
				#ofp_action_dl_addr{type = src, dl_addr = <<0,1,2,3,4,5>>},
				#ofp_action_dl_addr{type = dst, dl_addr = <<0,1,2,3,4,5>>},
				#ofp_action_nw_addr{type = src, nw_addr = <<0,1,2,3>>},
				#ofp_action_nw_addr{type = dst, nw_addr = <<0,1,2,3>>},
				#ofp_action_nw_tos{nw_tos = 1},
				#ofp_action_tp_port{type = src, tp_port = 22},
				#ofp_action_tp_port{type = dst, tp_port = 22},
				#ofp_action_enqueue{port = local, queue_id = 123},
				#nx_action_resubmit{in_port = local},
				#nx_action_set_tunnel{tun_id = 123},
				#nx_action_set_tunnel64{tun_id = 456},
				#nx_action_set_queue{queue_id = 789},
				#nx_action_pop_queue{},
				#nx_action_reg_move{n_bits = 32, src_ofs = 0, dst_ofs = 0, src = nxm_of_eth_dst, dst = nxm_of_eth_src},
				#nx_action_reg_load{ofs = 0, nbits = 32, dst = nxm_of_eth_dst, value = << 0,1,2,3,4,5 >>},
				#nx_action_note{note = <<"Note12">>}
			   ],
%%#nx_action_multipath{fields = Fields, basis = Basis, algorithm = Algo, max_link = MaxLink, arg = Arg, ofs = Ofs, nbits = Nbits, dst = Dst},
%%#nx_action_autopath{ofs = Ofs, nbits = Nbits, dst = Dst, id = Id}

	FlowMod = #nx_flow_mod{cookie = 123, command = add, idle_timeout = 60, hard_timeout = 300,
						   priority = 1, buffer_id = 0, out_port = local, flags = [], nx_match = NxMatches, actions = Actions},
	MOut = #ovs_msg{version = 1, type = vendor, xid = 1, msg = FlowMod},
	Pkt = flower_packet:encode(MOut),
	{[MIn],_} = flower_packet:decode(Pkt),
	MOut = MIn,
	ok.

test_nxst_flow_stats_request(_Config) ->
	NxMatches = [
				  {nxm_of_in_port, << 0:16 >>},
				  {nxm_of_eth_dst, << 0,1,2,3,4,5 >>},
				  {nxm_of_eth_dst_w, {<< 0,1,2,3,4,5 >>, << 255,255,255,255,255,255 >>}},
				  {nxm_of_eth_src, << 0,1,2,3,4,5 >>},
				  {nxm_of_eth_type, << 0:16 >>},
				  {nxm_of_vlan_tci, << 0:16 >>},
				  {nxm_of_vlan_tci_w, {<< 0:16 >>, << 0:16 >>}},
				  {nxm_of_ip_tos, << 0 >>},
				  {nxm_of_ip_proto, << 0 >>},
				  {nxm_of_ip_src, << 1,2,3,4 >>},
				  {nxm_of_ip_src_w, {<< 1,2,3,4 >>, << 255,255,255,255 >>}},
				  {nxm_of_ip_dst, << 5,6,7,8 >>},
				  {nxm_of_ip_dst_w, {<<  5,6,7,8 >>, << 255,255,255,255 >>}},
				  {nxm_of_tcp_src, << 0:16 >>},
				  {nxm_of_tcp_dst, << 0:16 >>},
				  {nxm_of_udp_src, << 0:16 >>},
				  {nxm_of_udp_dst, << 0:16 >>},
				  {nxm_of_icmp_type, << 0 >>},
				  {nxm_of_icmp_code, << 0 >>},
				  {nxm_of_arp_op, << 0:16 >>},
				  {nxm_of_arp_spa, << 0:32 >>},
				  {nxm_of_arp_spa_w, {<< 0:32 >>, << 255,255,255,255 >>}},
				  {nxm_of_arp_tpa, << 0:32 >>},
				  {nxm_of_arp_tpa_w, {<< 0:32 >>, << 255,255,255,255 >>}},
				  {nxm_nx_tun_id, << 0,1,2,3,4,5,6,7 >>},
				  {nxm_nx_tun_id_w, {<< 0,1,2,3,4,5,6,7 >>, << 255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_arp_sha, << 0,1,2,3,4,5 >>},
				  {nxm_nx_arp_tha, << 0,1,2,3,4,5 >>},
				  {nxm_nx_ipv6_src, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_ipv6_src_w, {<< 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>, << 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_ipv6_dst, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_ipv6_dst_w, {<< 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>, << 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255 >>}},
				  {nxm_nx_icmpv6_type, << 0 >>},
				  {nxm_nx_icmpv6_code, << 0 >>},
				  {nxm_nx_nd_target, << 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 >>},
				  {nxm_nx_nd_sll, << 0,1,2,3,4,5 >>},
				  {nxm_nx_nd_tll, << 0,1,2,3,4,5 >>}],

	FlowStats = #ofp_nxst_flow_stats_request{out_port = none, table_id = all, nx_match = NxMatches},
	MOut = #ovs_msg{version = 1, type = stats_request, xid = 1, msg = FlowStats},
	Pkt = flower_packet:encode(MOut),
	{[MIn],_} = flower_packet:decode(Pkt),
	MOut = MIn,
	ok.

test_nxst_flow_stats(_Config) ->
	Sw = ofp_nxst_flow_stats(),
	{[Msg = #ovs_msg{msg = [#ofp_nxst_flow_stats{}|_R]}],_} = flower_packet:decode(Sw),
	Sw = flower_packet:encode(Msg),
	ok.

test_stats_req(_Config) ->
	flower_packet:encode_msg(#ofp_desc_stats_request{}),
	flower_packet:encode_msg(#ofp_flow_stats_request{match = <<>>, table_id = all, out_port = none}),
	flower_packet:encode_msg(#ofp_aggregate_stats_request{match = <<>>, table_id = all, out_port = none}),
	flower_packet:encode_msg(#ofp_table_stats_request{}),
	flower_packet:encode_msg(#ofp_port_stats_request{port_no = none}),
	flower_packet:encode_msg(#ofp_queue_stats_request{port_no = none, queue_id = all}).

test_v12(_Config) ->
    io:format("P0: ~p~n", [flower_packet_v12:decode(v12_ofp_hello())]),
    io:format("P1: ~p~n", [flower_packet_v12:decode(v12_ofp_features_request())]),
    io:format("P2: ~p~n", [flower_packet_v12:decode(v12_ofp_features_reply())]),
    io:format("P3: ~p~n", [flower_packet_v12:decode(v12_ofp_get_config_request())]),
    io:format("P4: ~p~n", [flower_packet_v12:decode(v12_ofp_get_config_reply())]),
    io:format("P5: ~p~n", [flower_packet_v12:decode(v12_ofp_table_stats_request())]),
    io:format("P6: ~p~n", [flower_packet_v12:decode(v12_ofp_table_stats_reply())]),
    io:format("P7: ~p~n", [flower_packet_v12:decode(v12_rofl_broken_table_stats_request())]),
    io:format("P8: ~p~n", [flower_packet_v12:decode(v12_rofl_broken_table_stats_reply())]),
    ok.

all() -> 
	[test_hello_request, test_echo_request, test_echo_reply,
	 test_switch_features_request, test_switch_features_reply,
	 test_set_config, test_flow_mod_add, test_flow_removed,
	 test_packet_in, test_packet_out,
	 test_port_status_cfg_down, test_port_status_lnk_down,
	 test_port_status_lnk_up,
	 test_flow_mod,
	 test_nx_flow_mod, test_nxst_flow_stats_request, test_nxst_flow_stats,
	 test_stats_req, test_v12].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

