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

%% API
-export([start_link/0]).
-export([start_connection/0, accept/2, send/3, send/4]).

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

start_connection() ->
	flower_connection_sup:start_connection(?MODULE).

accept(Server, Socket) ->
    gen_tcp:controlling_process(Socket, Server),
	gen_fsm:send_event(Server, {accept, Socket}).

send(Sw, Type, Msg) ->
	gen_fsm:send_event(Sw, {send, Type, Msg}).

send(Sw, Type, Xid, Msg) ->
	gen_fsm:send_event(Sw, {send, Type, Xid, Msg}).

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
	flower_dispatcher:dispatch({packet, in}, self(), Xid, Msg),
	{next_state, connected, State};

connected({flow_removed, Xid, Msg}, State) ->
	flower_dispatcher:dispatch({flow, removed}, self(), Xid, Msg),
	{next_state, connected, State};

connected({send, Type, Msg}, State) ->
	send_request(Type, Msg, {next_state, connected, State});

connected({send, Type, Xid, Msg}, State) ->
	send_pkt(Type, Xid, Msg, {next_state, connected, State});

connected(Msg, State) ->
	io:format("unhandled message: ~w~n", [Msg]),
	{next_state, connected, State}.
	
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
	lists:foldl(fun(M, _) -> gen_fsm:send_event(self(), {M#ovs_msg.type, M#ovs_msg.xid, M#ovs_msg.msg}) end, ok, Rest),

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
