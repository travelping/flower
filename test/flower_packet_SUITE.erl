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

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

test_hello_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = hello, xid = 8, msg = <<>>},
	[Sw] = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_echo_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = echo_request, xid = 8, msg = <<>>},
	[Sw] = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_echo_reply(_Config) ->
	Sw = #ovs_msg{version = 1, type = echo_reply, xid = 8, msg = <<>>},
	[Sw] = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_switch_features_request(_Config) ->
	Sw = #ovs_msg{version = 1, type = features_request, xid = 2, msg = <<>>},
	[Sw] = flower_packet:decode(flower_packet:encode(Sw)),
	ok.

test_switch_features_reply(_Config) ->
	Sw = ofp_switch_features_reply(),
	[#ovs_msg{msg = #ofp_switch_features{}}] = flower_packet:decode(Sw),
	Sw = flower_packet:encode(flower_packet:decode(Sw)),
	ok.

test_packet_out(_Config) ->
	Sw = ofp_packet_out(),
	[#ovs_msg{msg = #ofp_packet_out{}}] = flower_packet:decode(Sw),
	Sw = flower_packet:encode(flower_packet:decode(Sw)),
	ok.

test_packet_in(_Config) ->
	Sw = ofp_packet_in(),
	[#ovs_msg{msg = #ofp_packet_in{}}] = flower_packet:decode(Sw),
	ok.
	
test_flow_mod_add(_Config) ->
	Sw = ofp_flow_mod_add(),
	[#ovs_msg{msg = #ofp_flow_mod{}}] = flower_packet:decode(Sw),
	Sw = flower_packet:encode(flower_packet:decode(Sw)),
	ok.

test_flow_removed(_Config) ->
	Sw = ofp_flow_removed(),
	[#ovs_msg{msg = #ofp_flow_removed{}}|[#ovs_msg{msg = #ofp_flow_removed{}}]] = flower_packet:decode(Sw),
	Sw = flower_packet:encode(flower_packet:decode(Sw)),
	ok.
	
test_set_config(_Config) ->
	Sw = ofp_set_config(),
	[#ovs_msg{msg = #ofp_switch_config{}}] = flower_packet:decode(Sw),
	Sw = flower_packet:encode(flower_packet:decode(Sw)),
	ok.

all() -> 
	[test_hello_request, test_echo_request, test_echo_reply,
	 test_switch_features_request, test_switch_features_reply,
	 test_set_config, test_flow_mod_add, test_flow_removed,
	 test_packet_in].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

