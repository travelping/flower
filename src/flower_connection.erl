%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_connection).

-behaviour(gen_fsm).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include("flower_packet.hrl").
-include("flower_flow.hrl").

%% API
-export([start_link/0, start/0]).
-export([accept/2]).

%% gen_fsm callbacks
-export([init/1, handle_event/3,
		 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
-export([setup/2, open/2, connected/2]).

-define(SERVER, ?MODULE).

-record(state, {
		  xid = 1,
		  socket,
		  features
		 }).

-define(STARTUP_TIMEOUT, 10000).     %% wait 10sec for someone to tell us what to do
-define(CONNECT_TIMEOUT, 30000).     %% wait 30sec for the first packet to arrive
-define(REQUEST_TIMEOUT, 10000).     %% wait 10sec for answer
-define(TCP_OPTS, [binary, inet6,
                   {active,       false},
                                   {send_timeout, 5000},
                   {backlog,      10},
                   {nodelay,      true},
                   {packet,       raw},
                   {reuseaddr,    true}]).

-ifdef(debug).
-define(FSM_OPTS,{debug,[trace]}).
-else.
-define(FSM_OPTS,).
-endif.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
	gen_fsm:start_link(?MODULE, [], [?FSM_OPTS]).

start() ->
	gen_fsm:start(?MODULE, [], [?FSM_OPTS]).

accept(Server, Socket) ->
    gen_tcp:controlling_process(Socket, Server),
	gen_fsm:send_event(Server, {accept, Socket}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    {ok, setup, #state{}, ?STARTUP_TIMEOUT}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
setup({accept, Socket}, State) ->
	?DEBUG("got setup~n"),
	NewState = State#state{socket = Socket},
	?DEBUG("NewState: ~p~n", [NewState]),
	send_request(hello, <<>>, {next_state, open, NewState, ?CONNECT_TIMEOUT}).

open({hello, _Xid, _Msg}, State) ->
	?DEBUG("got hello in open"),
	send_request(features_request, <<>>, {next_state, connected, State, ?REQUEST_TIMEOUT}).

connected({features_reply, _Xid, Msg}, State) ->
	?DEBUG("got features_reply in connected"),
	{next_state, connected, State#state{features = Msg}};

connected({echo_request, Xid, _Msg}, State) ->
	send_pkt(echo_reply, Xid, <<>>, {next_state, connected, State});

connected({packet_in, Xid, Msg}, State) ->
	case Flow = (catch flower_flow:flow_extract(0, Msg#ofp_packet_in.in_port, Msg#ofp_packet_in.data)) of
		#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst, in_port = InPort, vlan_tci = VlanTci,
			  dl_type = DlType, tp_src = TpSrc, tp_dst = TpDst, dl_src = DlSrc, dl_dst = DlDst,
			  nw_proto = NwProto, nw_tos = NwTos, arp_sha = ArpSha, arp_tha = ArpTha} ->
			%% choose destination...
			Port = choose_destination(Flow),
			Action = case Port of
						 none -> <<>>;
%%						 X when is_integer(X) ->
%%							 flower_packet:encode_ofs_action_enqueue(X, 0);
						 X ->
							 flower_packet:encode_ofs_action_output(X, 0)
					 end,
			
			if
				Port =:= flood ->
					%% We don't know that MAC, or we don't set up flows.  Send along the
					%% packet without setting up a flow.
					PktOut = flower_packet:encode_ofp_packet_out(Msg#ofp_packet_in.buffer_id, Msg#ofp_packet_in.in_port, Action, Msg#ofp_packet_in.data),
					?DEBUG("Send: ~p~n", [PktOut]),
					send_pkt(packet_out, Xid, PktOut, {next_state, connected, State});
				true ->
					%% The output port is known, so add a new flow.
					Match = flower_match:encode_ofp_matchflow([{nw_src_mask,32}, {nw_dst_mask,32}, tp_dst, tp_src, nw_proto, dl_type], Flow),
					?DEBUG("Match: ~p~n", [Match]),
					MatchBin = flower_packet:encode_msg(Match),
					PktOut = flower_packet:encode_ofp_flow_mod(MatchBin, 0, add, 60, 0, 0, Msg#ofp_packet_in.buffer_id, 0, 1, Action),
					?DEBUG("Send: ~p~n", [PktOut]),
					send_pkt(flow_mod, Xid, PktOut, {next_state, connected, State})

					%% if
					%% 	%% If the switch didn't buffer the packet, we need to send a copy.
					%% 	Msg#ofp_packet_in.buffer_id =:= 16#FFFFFFFF ->
					%% 		PktOut = flower_packet:encode_ofp_packet_out(Msg#ofp_packet_in.buffer_id, Msg#ofp_packet_in.in_port, Action, Msg#ofp_packet_in.data),
					%% 		io:format("Send: ~p~n", [PktOut]),
					%% 		send_pkt(packet_out, Xid, PktOut, {next_state, connected, State});
					%% 	true ->
					%% 		ok
					%% end,
					%% ok
			end;
		_ ->
			?DEBUG("no match: ~p~n", [Flow]),
			{next_state, connected, State}
	end;

connected({flow_removed, Xid, Msg}, State) ->
	io:format("flow removed, ~w~n", [Xid]),
	{next_state, connected, State}.
	
format_mac(<<A:8,B:8,C:8,D:8,E:8,F>>) ->
	io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B", [A,B,C,D,E,F]).

format_ip(<<A:8,B:8,C:8,D:8>>) ->
	io_lib:format("~B.~B.~B.~B", [A,B,C,D]).

choose_destination(#flow{in_port = Port, dl_src = DlSrc, dl_dst = DlDst} = _Flow) ->
	OutPort = case flower_mac_learning:eth_addr_is_reserved(DlSrc) of
				  false -> learn_mac(DlSrc, 0, Port),
						   find_out_port(DlDst, 0, Port);
				  true -> none
			  end,
	io:format("Verdict: ~p~n", [OutPort]),
	OutPort.

learn_mac(DlSrc, VLan, Port) ->		 
	R = case flower_mac_learning:may_learn(DlSrc, VLan) of
			true -> flower_mac_learning:insert(DlSrc, VLan, Port);
			false ->
				not_learned
		end,
	if
		R =:= new; R =:= updated ->
            io:format("~p: learned that ~s is on port ~w~n", [self(), format_mac(DlSrc), Port]),
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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------

%% state_name(_Event, _From, State) ->
%% 	Reply = ok,
%% 	{reply, Reply, state_name, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
	{next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, State) ->
	Reply = ok,
	{reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_info({tcp, Socket, Data}, StateName, #state{socket = Socket} = State) ->
	?DEBUG("handle_info: ~p~n", [Data]),
	[Msg|Rest] = flower_packet:decode(Data),

	%% exec first Msg directly....
	Reply = ?MODULE:StateName({Msg#ovs_msg.type, Msg#ovs_msg.xid, Msg#ovs_msg.msg}, State),
	case Reply of
		{next_state, _, _} ->
			ok = inet:setopts(Socket, [{active, once}]);
		{next_state, _, _, _} -> 
			ok = inet:setopts(Socket, [{active, once}]);
		_ ->
			ok
	end,

	%% push any other message into our MailBox....
	lists:foldl(fun(Msg, _) -> gen_fsm:send_event(self(), {Msg#ovs_msg.type, Msg#ovs_msg.xid, Msg#ovs_msg.msg}) end, ok, Rest),

	Reply;

handle_info({tcp_closed, Socket}, _StateName, #state{socket = Socket} = State) ->
	error_logger:info_msg("Client Disconnected."),
	{stop, normal, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, State) ->
	?DEBUG("terminate"),
	gen_tcp:close(State#state.socket),
	ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
	{ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

inc_xid(State) ->
	State#state{xid = State#state.xid + 1}.
	
send_hello(State) ->
	NewState = inc_xid(State),
	Packet = flower_packet:encode(#ovs_msg{version = 1, type = hello, xid = NewState#state.xid, msg = <<>>}),

	case gen_tcp:send(State#state.socket, Packet) of
		ok ->
			{ok, NewState};
		{error, Reason} ->
			{error, Reason, NewState}
	end.


send_request(Type, Msg, NextStateInfo) ->
	State = element(3, NextStateInfo),
	NewState = inc_xid(State),
	NewNextStateInfo = setelement(3, NextStateInfo, NewState),
	send_pkt(Type, NewState#state.xid, Msg, NewNextStateInfo).

send_pkt(Type, Xid, Msg, NextStateInfo) ->
	State = element(3, NextStateInfo),
	Socket = State#state.socket,

	Packet = flower_packet:encode(#ovs_msg{version = 1, type = Type, xid = Xid, msg = Msg}),

	case gen_tcp:send(Socket, Packet) of
		ok ->
			ok = inet:setopts(Socket, [{active, once}]),
			NextStateInfo;
		{error, Reason} ->
			?DEBUG("error - Reason: ~p~n", [Reason]),
			{stop, Reason, State}
	end.
