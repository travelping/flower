%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 28 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_datapath).

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
-export([setup/2, open/2, connecting/2, connected/2, connected/3]).
-export([install_flow/10, send_packet/4, send_buffer/4, send_packet/5, portinfo/2]).

-define(SERVER, ?MODULE).

-record(state, {
		  xid = 1,
		  socket,
		  pending = <<>>,
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
	flower_datapath_sup:start_connection().

accept(Server, Socket) ->
    gen_tcp:controlling_process(Socket, Server),
	gen_fsm:send_event(Server, {accept, Socket}).

send(Sw, Type, Msg) ->
	gen_fsm:send_event(Sw, {send, Type, Msg}).

send(Sw, Type, Xid, Msg) ->
	gen_fsm:send_event(Sw, {send, Type, Xid, Msg}).

%%--------------------------------------------------------------------
%% @doc
%% Send a Port_Stats_Request
%% @end
%%--------------------------------------------------------------------
%%send_port_stats_request(Sw, Port) ->
%%	send(Sw, Type, flower_packet:encode_ofp_stats_request()).

%%--------------------------------------------------------------------
%% @doc
%% Add a flow entry to datapath
%% @end
%%--------------------------------------------------------------------
install_flow(Sw, Match, Cookie, IdleTimeout, HardTimeout,
			 Actions, BufferId, Priority, InPort, Packet) ->
	MatchBin = flower_packet:encode_match(Match),
	ActionsBin = flower_packet:encode_actions(Actions),
	PktOut = flower_packet:encode_ofp_flow_mod(MatchBin, Cookie, add, IdleTimeout, HardTimeout, Priority, BufferId, none, 1, ActionsBin),

	% applies Actions automatically for buffered packets (BufferId /= 16#FFFFFFFF)
	send(Sw, flow_mod, PktOut),
	if
	    BufferId == 16#FFFFFFFF,
		Packet /= none ->
		    % only explicitly send unbuffered packets
			send_packet(Sw, Packet, Actions, InPort);
		true ->
			ok
	end,
	flower_dispatcher:dispatch({flow, mod}, Sw, Match),
	ok.

%%--------------------------------------------------------------------
%% @doc
%% sends an openflow packet to a datapath
%% @end
%%--------------------------------------------------------------------
send_packet(Sw, Packet, Actions, InPort) when is_list(Actions) ->
    case lists:keymember(ofp_action_output, 1, Actions) of
        true ->
            ActionsBin = flower_packet:encode_actions(Actions),
            PktOut = flower_packet:encode_ofp_packet_out(16#FFFFFFFF, InPort, ActionsBin, Packet),
            send(Sw, packet_out, PktOut);
        false ->
            % packet is unbuffered and not forwarded -> no need to send it to
            % the datapath
            ok
    end;
send_packet(Sw, Packet, Action, InPort) ->
    send_packet(Sw, Packet, [Action], InPort).

%%--------------------------------------------------------------------
%% @doc
%% Tells a datapath to send out a buffer
%% @end
%%--------------------------------------------------------------------
send_buffer(Sw, BufferId, Actions, InPort) ->
	ActionsBin = flower_packet:encode_actions(Actions),
	PktOut = flower_packet:encode_ofp_packet_out(BufferId, InPort, ActionsBin, <<>>),
	send(Sw, packet_out, PktOut).

%%--------------------------------------------------------------------
%% @doc
%% Sends an openflow packet to a datapath.
%%
%% This function is a convenient wrapper for send_packet and 
%% send_buffer for situations where it is unknown in advance
%% whether the packet to be sent is buffered. If
%% 'buffer_id' is -1, it sends 'packet'; otherwise, it sends the
%% buffer represented by 'buffer_id'.
%% @end
%%--------------------------------------------------------------------
send_packet(Sw, BufferId, Packet, Actions, InPort) ->
	if
		BufferId == 16#FFFFFFFF;
		BufferId == none ->
			send_packet(Sw, Packet, Actions, InPort);
		true ->
			send_buffer(Sw, BufferId, Actions, InPort)
	end.

portinfo(Sw, Port) ->
	gen_fsm:sync_send_event(Sw, {portinfo, Port}, 1000).

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
	send_request(features_request, <<>>, {next_state, connecting, State, ?REQUEST_TIMEOUT}).

connecting({features_reply, Xid, Msg}, State) ->
	?DEBUG("got features_reply in connected"),
	flower_dispatcher:dispatch({datapath, join}, self(), Msg),
	{next_state, connected, State#state{features = Msg}};

connecting({echo_request, Xid, _Msg}, State) ->
	send_pkt(echo_reply, Xid, <<>>, {next_state, connected, State}).

connected({features_reply, _Xid, Msg}, State) ->
	?DEBUG("got features_reply in connected"),
	{next_state, connected, State#state{features = Msg}};

connected({echo_request, Xid, _Msg}, State) ->
	send_pkt(echo_reply, Xid, <<>>, {next_state, connected, State});

connected({packet_in, Xid, Msg}, State) ->
	flower_dispatcher:dispatch({packet, in}, self(), Msg),
	{next_state, connected, State};

connected({flow_removed, Xid, Msg}, State) ->
	flower_dispatcher:dispatch({flow, removed}, self(), Msg),
	{next_state, connected, State};

connected({port_status, Xid, Msg}, State) ->
	flower_dispatcher:dispatch({port, status}, self(), Msg),
	{next_state, connected, State};

connected({stats_reply, Xid, Msg}, State) ->
	flower_dispatcher:dispatch({port, stats}, self(), Msg),
	{next_state, connected, State};

connected({send, Type, Msg}, State) ->
	send_request(Type, Msg, {next_state, connected, State});

connected({send, Type, Xid, Msg}, State) ->
	send_pkt(Type, Xid, Msg, {next_state, connected, State});

connected(Msg, State) ->
	?DEBUG("unhandled message: ~w", [Msg]),
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

connected({portinfo, Port}, _From, #state{features = Features} = State) ->
	Reply = lists:keyfind(Port, #ofp_phy_port.port_no, Features#ofp_switch_features.ports),
	{reply, Reply, connected, State}.

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
	{Msg, DataRest} = flower_packet:decode(<<(State#state.pending)/binary, Data/binary>>),
	State1 = State#state{pending = DataRest},
	?DEBUG("handle_info: decoded: ~p~nrest: ~p~n", [Msg, DataRest]),

	case Msg of
		[] -> 
			ok = inet:setopts(Socket, [{active, once}]),
			{next_state, StateName, State1};

		[First|Next] ->
			%% exec first Msg directly....
			Reply = ?MODULE:StateName({First#ovs_msg.type, First#ovs_msg.xid, First#ovs_msg.msg}, State1),
			case Reply of
				{next_state, _, _} ->
					ok = inet:setopts(Socket, [{active, once}]);
				{next_state, _, _, _} -> 
					ok = inet:setopts(Socket, [{active, once}]);
				_ ->
					ok
			end,

			%% push any other message into our MailBox....
			lists:foldl(fun(M, _) -> gen_fsm:send_event(self(), {M#ovs_msg.type, M#ovs_msg.xid, M#ovs_msg.msg}) end, ok, Next),

			Reply
	end;

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
terminate(_Reason, StateName, State) ->
	?DEBUG("terminate"),
	case StateName of
		connected ->
			flower_dispatcher:dispatch({datapath, leave}, self(), undefined);
		_ ->
			ok
	end,
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
