%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created :  5 Jul 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_simple_switch).

-behaviour(gen_server).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include("flower_packet.hrl").
-include("flower_flow.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
		 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
	flower_dispatcher:join({packet, in}),
	{ok, #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
	Reply = ok,
	{reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({{packet, in}, Sw, Msg}, State) ->
	case Flow = (catch flower_flow:flow_extract(0, Msg#ofp_packet_in.in_port, Msg#ofp_packet_in.data)) of
		#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst, in_port = InPort, vlan_tci = VlanTci,
			  dl_type = DlType, tp_src = TpSrc, tp_dst = TpDst, dl_src = DlSrc, dl_dst = DlDst,
			  nw_proto = NwProto, nw_tos = NwTos, arp_sha = ArpSha, arp_tha = ArpTha} ->
			%% choose destination...
			Port = choose_destination(Flow),
			Actions = case Port of
						 none -> [];
%%						 X when is_integer(X) ->
%%							 [#ofp_action_enqueue{port = X, queue_id = 0}];
						 X ->
							 [#ofp_action_output{port = X, max_len = 0}]
					 end,
			
			if
				Port =:= flood ->
					%% We don't know that MAC, or we don't set up flows.  Send along the
					%% packet without setting up a flow.
					flower_datapath:send_packet(Sw, Msg#ofp_packet_in.buffer_id, Msg#ofp_packet_in.data, Actions, Msg#ofp_packet_in.in_port);
				true ->
					%% The output port is known, so add a new flow.
					Match = flower_match:encode_ofp_matchflow([{nw_src_mask,32}, {nw_dst_mask,32}, tp_dst, tp_src, nw_proto, dl_type], Flow),
					?DEBUG("Match: ~p~n", [Match]),

					flower_datapath:install_flow(Sw, Match, 0, 60, 0, Actions, Msg#ofp_packet_in.buffer_id, 0, Msg#ofp_packet_in.in_port, Msg#ofp_packet_in.data)
			end;
		_ ->
			?DEBUG("no match: ~p~n", [Flow])
	end,
	{noreply, State};

handle_cast(_Msg, State) ->
	{noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
	{noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
	ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

format_mac(<<A:8,B:8,C:8,D:8,E:8,F>>) ->
	lists:flatten(io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B", [A,B,C,D,E,F])).

format_ip(<<A:8,B:8,C:8,D:8>>) ->
	lists:flatten(io_lib:format("~B.~B.~B.~B", [A,B,C,D])).

choose_destination(#flow{in_port = Port, dl_src = DlSrc, dl_dst = DlDst} = _Flow) ->
	OutPort = case flower_mac_learning:eth_addr_is_reserved(DlSrc) of
				  false -> learn_mac(DlSrc, 0, Port),
						   find_out_port(DlDst, 0, Port);
				  true -> none
			  end,
	?DEBUG("Verdict: ~p", [OutPort]),
	OutPort.

learn_mac(DlSrc, VLan, Port) ->		 
	R = case flower_mac_learning:may_learn(DlSrc, VLan) of
			true -> flower_mac_learning:insert(DlSrc, VLan, Port);
			false ->
				not_learned
		end,
	if
		R =:= new; R =:= updated ->
            ?DEBUG("~p: learned that ~s is on port ~w", [self(), format_mac(DlSrc), Port]),
			ok;
		true ->
			ok
	end.

find_out_port(DlDst, _VLan, Port) ->
	OutPort = case flower_mac_learning:lookup(DlDst, 0) of
				  none -> flood;
				  {ok, OutPort1} -> 
					  if
						  %% Don't send a packet back out its input port.
						  OutPort1 =:= Port -> none;
						  true -> OutPort1
					  end
			  end,
	OutPort.
