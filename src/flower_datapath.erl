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

-module(flower_datapath).

-behaviour(gen_fsm).

%%-define(debug, true).
%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include("flower_packet.hrl").
-include("flower_datapath.hrl").

%% internal API
-export([start_link/1]).
-export([start_connection/1, accept/2, connect/2, send/3, send/4, stats_request/4]).

%% gen_fsm callbacks
-export([init/1, handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
-export([setup/2, setup/3, open/2, open/3, connecting/2, connecting/3, connected/2, connected/3]).
-export([install_flow/10, send_packet/4, send_buffer/4, send_packet/5, portinfo/2,
         remove_flow/10, remove_all_flows/1, modify_flow/10, modify_flow/11]).
-export([install_flow_v12/10,
         remove_flow_v12/10, remove_all_flows_v12/1, modify_flow_v12/10, modify_flow_v12/11]).
-export([counters/0, counters/1, features/1, features_all/0]).

-define(SERVER, ?MODULE).
-define(VERSION, 3).

-record(state, {
	  transport,
	  role = server,
	  arguments,
	  version = ?VERSION,

	  xid = 1,
	  socket,
	  pending = <<>>,
	  features,
	  counters = #flower_datapath_counters{} :: #flower_datapath_counters{},
	  timeouts
	 }).


-define(STARTUP_TIMEOUT, 10000).        %% wait 10sec for someone to tell us what to do
-define(CONNECT_SETUP_TIMEOUT, 1000).   %% wait  1sec for the transport connection to establish
-define(RECONNECT_TIMEOUT, 10000).      %% retry after 10sec when a transport connect failed
-define(CONNECT_TIMEOUT, 30000).        %% wait 30sec for the first packet to arrive
-define(REQUEST_TIMEOUT, 10000).        %% wait 10sec for answer

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
start_link(TransportMod) ->
    gen_fsm:start_link(?MODULE, TransportMod, [?FSM_OPTS]).

connect(TransportMod, Arguments) ->
    case flower_datapath:start_connection(TransportMod) of
	{ok, Pid} ->
	    gen_fsm:send_event(Pid, {connect, Arguments}),
	    {ok, Pid};
	Error ->
	    Error
    end.

start_connection(TransportMod) ->
    flower_datapath_sup:start_connection(TransportMod).


accept(Server, Socket) ->
    gen_fsm:send_event(Server, {accept, Socket}).

send(Sw, Type, Msg) ->
    gen_fsm:send_event(Sw, {send, Type, Msg}).

send(Sw, Type, Xid, Msg) ->
    gen_fsm:send_event(Sw, {send, Type, Xid, Msg}).

stats_request(Sw, Type, Msg, Timeout) ->
    gen_fsm:sync_send_event(Sw, {stats_request, Type, Msg, Timeout}).

counters() ->
    lists:map(fun(Sw) -> counters(Sw) end, flower_datapath_sup:datapaths()).

counters(Sw) ->
    gen_fsm:sync_send_all_state_event(Sw, counters).

features(Sw) ->
    gen_fsm:sync_send_event(Sw, features, 2000).

features_all() ->
    lists:map(
      fun(Sw) ->
              flower_datapath:features(Sw)
      end, flower_datapath_sup:datapaths()).


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
    modify_flow(Sw, Match, Cookie, add, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

install_flow_v12(Sw, Match, Cookie, IdleTimeout, HardTimeout,
	     Actions, BufferId, Priority, InPort, Packet) ->
    modify_flow_v12(Sw, Match, Cookie, add, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

remove_all_flows(Sw) ->
    remove_flow(Sw, flower_match:encode_ofp_match([]),
                0, 0, 0, [], ?OFP_NO_BUFFER, 0, 0, <<>>).

remove_all_flows_v12(Sw) ->
    remove_flow_v12(Sw, flower_match:encode_ofp_match([]),
                0, 0, 0, [], ?OFP_NO_BUFFER, 0, 0, <<>>).

remove_flow(Sw, Match, Cookie, IdleTimeout, HardTimeout,
	     Actions, BufferId, Priority, InPort, Packet) ->
    modify_flow(Sw, Match, Cookie, delete, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

remove_flow_v12(Sw, Match, Cookie, IdleTimeout, HardTimeout,
	     Actions, BufferId, Priority, InPort, Packet) ->
    modify_flow_v12(Sw, Match, Cookie, delete, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

modify_flow(Sw, Match, Cookie, IdleTimeout, HardTimeout,
	     Actions, BufferId, Priority, InPort, Packet) ->
    modify_flow(Sw, Match, Cookie, modify, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

modify_flow_v12(Sw, Match, Cookie, IdleTimeout, HardTimeout,
	     Actions, BufferId, Priority, InPort, Packet) ->
    modify_flow_v12(Sw, Match, Cookie, modify, IdleTimeout, HardTimeout,
                Actions, BufferId, Priority, InPort, Packet).

modify_flow(Sw, Match, Cookie, ModCmd, IdleTimeout, HardTimeout,
            Actions, BufferId, Priority, InPort, Packet) ->
    MatchBin = flower_packet:encode_match(Match),
    ActionsBin = flower_packet:encode_actions(Actions),
    PktOut = flower_packet:encode_ofp_flow_mod(MatchBin, Cookie, ModCmd,
                                               IdleTimeout, HardTimeout,
                                               Priority, BufferId,
                                               none, 1, ActionsBin),
    %% apply Actions automatically for buffered packets
    %% (BufferId /= ?OFP_NO_BUFFER)
    send(Sw, flow_mod, PktOut),
    if
	BufferId == ?OFP_NO_BUFFER,
	Packet /= none ->
            %% only explicitly send unbuffered packets
	    send_packet(Sw, Packet, Actions, InPort);
	true ->
	    ok
    end,
    flower_dispatcher:dispatch({flow, mod}, Sw, Match),
    ok.

modify_flow_v12(Sw, Match, Cookie, ModCmd, IdleTimeout, HardTimeout,
            Actions, BufferId, Priority, InPort, Packet) ->
    FlowMod = #ofp_flow_mod_v12{
        match=Match,
        cookie=Cookie,
        command=ModCmd,
        out_port=any,
        out_group=any,
        idle_timeout=IdleTimeout,
        hard_timeout=HardTimeout,
        buffer_id=BufferId,
        priority=Priority,
        table_id=0,
        instructions=#ofp_instruction_actions{type=apply_actions,
                actions=Actions}},
    PktOut = flower_packet_v12:encode_msg(FlowMod),
    %% apply Actions automatically for buffered packets
    %% (BufferId /= ?OFP_NO_BUFFER)
    send(Sw, flow_mod, PktOut),
    if
	BufferId == ?OFP_NO_BUFFER,
	Packet /= none ->
            %% only explicitly send unbuffered packets
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
	    PktOut = #ofp_packet_out{buffer_id = ?OFP_NO_BUFFER,
				     in_port = InPort,
				     actions = Actions,
				     data = Packet},
            send(Sw, packet_out, PktOut);
        false ->
	    %% packet is unbuffered and not forwarded -> no need to send it to
	    %% the datapath
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
    PktOut = #ofp_packet_out{buffer_id = BufferId,
			     in_port = InPort,
			     actions = Actions,
			     data = <<>>},
    send(Sw, packet_out, PktOut).

%%--------------------------------------------------------------------
%% @doc
%% Sends an openflow packet to a datapath.
%%
%% This function is a convenient wrapper for send_packet and
%% send_buffer for situations where it is unknown in advance
%% whether the packet to be sent is buffered. If
%% 'buffer_id' is 0xffffffff, it sends 'packet'; otherwise, it sends the
%% buffer represented by 'buffer_id'.
%% @end
%%--------------------------------------------------------------------
send_packet(Sw, BufferId, Packet, Actions, InPort) ->
    if
	BufferId == ?OFP_NO_BUFFER;
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
init(TransportMod) ->
    process_flag(trap_exit, true),
    {ok, setup, #state{transport = TransportMod, timeouts = orddict:new()}, ?STARTUP_TIMEOUT}.

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
    NewState = State#state{role = server, socket = Socket},
    ?DEBUG("NewState: ~p~n", [NewState]),
    ok = inet:setopts(Socket, [{active, once}]),
    send_request(hello, <<>>, {next_state, open, NewState, ?CONNECT_TIMEOUT});

setup(timeout, State = #state{role = client, arguments = Arguments}) ->
    ?DEBUG("connect timeout in state setup"),
    setup({connect, Arguments}, State);

setup({connect, Arguments}, State = #state{transport = TransportMod}) ->
    NewState0 = State#state{role = client, arguments = Arguments},
    case TransportMod:connect(Arguments, ?CONNECT_SETUP_TIMEOUT) of
	{ok, Socket} ->
	    NewState1 = NewState0#state{socket = Socket},
	    ?DEBUG("NewState: ~p~n", [NewState1]),
	    ok = inet:setopts(Socket, [{active, once}]),
	    send_request(hello, <<>>, {next_state, open, NewState1, ?CONNECT_TIMEOUT});
	_ ->
	   {next_state, setup, NewState0, ?RECONNECT_TIMEOUT}
    end;

setup(Msg, State)
  when element(1, Msg) =:= send ->
    ?DEBUG("ignoring send in state setup, Msg was: ~p~n", [Msg]),
    {next_state, setup, State}.

setup(_Msg, _From, State) ->
    Reply = {error, not_connected},
    {reply, Reply, setup, State, ?RECONNECT_TIMEOUT}.

open({hello, Version, Xid, _Msg}, State)
  when Version > ?VERSION ->
    ?DEBUG("got hello in open"),
    Reply = #ofp_error{error = hello_failed, data = incompatible},
    send_pkt(error, Xid, Reply, {stop, normal, State});

open({hello, Version, _Xid, _Msg}, State) ->
    ?DEBUG("got hello in open"),
    %% Accept their Idea of version if we support it
    NewState = State#state{version = Version},
    send_request(features_request, <<>>, {next_state, connecting, NewState, ?REQUEST_TIMEOUT});

open(Msg, State)
  when element(1, Msg) =:= send ->
    ?DEBUG("ignoring send in state open, Msg was: ~p~n", [Msg]),
    {next_state, open, State}.

open(_Msg, _From, State) ->
    Reply = {error, not_connected},
    {reply, Reply, open, State, ?CONNECT_TIMEOUT}.

connecting({features_reply, _Version, _Xid, Msg}, State) ->
    ?DEBUG("got features_reply in connected"),
    flower_dispatcher:dispatch({datapath, join}, self(), Msg),
    {next_state, connected, State#state{features = Msg}};

connecting({echo_request, _Version, Xid, _Msg}, State) ->
    send_pkt(echo_reply, Xid, <<>>, {next_state, connecting, State});

connecting(Msg, State)
  when element(1, Msg) =:= send ->
    ?DEBUG("ignoring send in state connecting, Msg was: ~p~n", [Msg]),
    {next_state, connecting, State}.

connecting(_Msg, _From, State) ->
    Reply = {error, not_connected},
    {reply, Reply, connecting, State, ?REQUEST_TIMEOUT}.

connected({timeout, _Ref, Xid}, State) ->
    case stop_timeout(Xid, State) of
	{ok, From, NewState} ->
	    gen_fsm:reply(From, {error, timeout}),
	    {next_state, connected, NewState};
	_ ->
	    {next_state, connected, State}
    end;

connected({features_reply, _Version, _Xid, Msg}, State) ->
    ?DEBUG("got features_reply in connected"),
    {next_state, connected, State#state{features = Msg}};

connected({echo_request, _Version, Xid, _Msg}, State) ->
    send_pkt(echo_reply, Xid, <<>>, {next_state, connected, State});

connected({packet_in, _Version, _Xid, Msg}, State) ->
    flower_dispatcher:dispatch({packet, in}, self(), Msg),
    {next_state, connected, State};

connected({flow_removed, _Version, _Xid, Msg}, State) ->
    flower_dispatcher:dispatch({flow, removed}, self(), Msg),
    {next_state, connected, State};

connected({port_status,_Version,  _Xid, Msg}, State) ->
    flower_dispatcher:dispatch({port, status}, self(), Msg),
    {next_state, connected, State};

connected({stats_reply, _Version, Xid, Msg}, State) ->
    case stop_timeout(Xid, State) of
	{ok, From, NewState} ->
	    gen_fsm:reply(From, {ok, Msg}),
	    {next_state, connected, NewState};
	_ ->
	    flower_dispatcher:dispatch({port, stats}, self(), Msg),
	    {next_state, connected, State}
    end;

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

connected(features, _From, #state{features = Features} = State) ->
    Reply = Features,
    {reply, Reply, connected, State};

connected({portinfo, Port}, _From, #state{features = Features} = State) ->
    Reply = lists:keyfind(Port, #ofp_phy_port.port_no, Features#ofp_switch_features.ports),
    {reply, Reply, connected, State};

connected({stats_request, Type, Msg, Timeout}, From, State) ->
    #state{xid = Xid} = NewState0 = inc_xid(State),
    NewState1 = start_timeout(Xid, Timeout, From, NewState0),
    send_pkt(Type, Xid, Msg, {next_state, connected, NewState1}).

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
handle_event(activate_socket, StateName, State = #state{socket = Socket}) ->
    ok = inet:setopts(Socket, [{active, once}]),
    {next_state, StateName, State};

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
handle_sync_event(counters, _From, StateName, State = #state{counters = Counters}) ->
    {reply, Counters, StateName, State};

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
    ?DEBUG(flower_tools:hexdump(Data)),
    {Msg, DataRest} = decode_of_pkt(<<(State#state.pending)/binary, Data/binary>>, State),
    State0 = inc_counter(State, recv, raw_packets),
    State1 = State0#state{pending = DataRest},
    ?DEBUG("handle_info: decoded: ~p~nrest: ~p~n", [Msg, DataRest]),

    case Msg of
	[] ->
	    ok = inet:setopts(Socket, [{active, once}]),
	    {next_state, StateName, State1};

	[First|Next] ->
	    %% exec first Msg directly....
	    Reply = exec_sync(First, StateName, State1),

	    case element(1, Reply) of
		%% don't process more message if we got a stop
		next_state ->
		    case Next of
			[] ->
			    ok = inet:setopts(Socket, [{active, once}]),
			    Reply;

			_ ->
			    %% push any other message into our MailBox....
			    %%  - extract Reply's NextState directly...
			    NextState = lists:foldl(fun(M, StateX) -> exec_async(M, StateX) end, element(3, Reply), Next),

			    %% accept new packets only after we finished processing
			    gen_fsm:send_all_state_event(self(), activate_socket),
			    setelement(3, Reply, NextState)
		    end;
		_ ->
		    Reply
	    end
    end;

handle_info({tcp_closed, Socket}, _StateName, State) ->
    handle_socket_error(Socket, State).

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
    socket_close(State),
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
start_timeout(_Xid, 0, _From, State) ->
    State;
start_timeout(Xid, Timeout, From, State = #state{timeouts = TimeOuts}) ->
    Ref = gen_fsm:start_timer(Timeout, Xid),
    State#state{timeouts = orddict:store(Xid, {Ref, From}, TimeOuts)}.

stop_timeout(Xid, State = #state{timeouts = TimeOuts}) ->
    case orddict:find(Xid, TimeOuts) of
	{ok, {Ref, From}} ->
	    gen_fsm:cancel_timer(Ref),
	    NewState = State#state{timeouts = orddict:erase(Xid, TimeOuts)},
	    {ok, From, NewState};
	_ ->
	    {not_found, State}
    end.

cancel_timeouts(State = #state{timeouts = TimeOuts}) ->
    orddict:fold(fun(_, {Ref, From}, _) ->
			 gen_fsm:cancel_timer(Ref),
			 gen_fsm:reply(From, {error, connection})
		 end, ok, TimeOuts),
    State#state{timeouts = orddict:new()}.

exec_sync(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg}, StateName, State) ->
    State0 = inc_counter(State, recv, Type),
    ?MODULE:StateName({Type, Version, Xid, Msg}, State0).

exec_async(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg}, State) ->
    State0 = inc_counter(State, recv, Type),
    gen_fsm:send_event(self(), {Type, Version, Xid, Msg}),
    State0.

inc_xid(State) ->
    State#state{xid = State#state.xid + 1}.

socket_close(State = #state{socket = undefined}) ->
    State;
socket_close(State = #state{transport = TransportMod, socket = Socket}) ->
    TransportMod:close(Socket),
    State#state{socket = undefined}.

handle_socket_error(_Socket,
		    State = #state{role = client, socket = undefined}) ->
    {next_state, setup, State, ?RECONNECT_TIMEOUT};
handle_socket_error(Socket,
		    State = #state{role = client, socket = Socket}) ->
    error_logger:info_msg("Server Disconnected."),
    flower_dispatcher:dispatch({datapath, leave}, self(), undefined),
    NewState0 = State#state{pending = <<>>, features = undefined},
    NewState1 = socket_close(NewState0),
    NewState2 = cancel_timeouts(NewState1),
    {next_state, setup, NewState2, ?RECONNECT_TIMEOUT};

handle_socket_error(Socket,
		    State = #state{role = server, socket = Socket}) ->
    error_logger:info_msg("Client Disconnected."),
    {stop, normal, State}.

send_request(Type, Msg, NextStateInfo) ->
    State = element(3, NextStateInfo),
    NewState = inc_xid(State),
    NewNextStateInfo = setelement(3, NextStateInfo, NewState),
    send_pkt(Type, NewState#state.xid, Msg, NewNextStateInfo).

send_pkt(Type, Xid, Msg, NextStateInfo) ->
    State0 = element(3, NextStateInfo),
    State1 = inc_counter(State0, send, raw_packets),
    NewState = inc_counter(State1, send, Type),
    TransportMod = NewState#state.transport,
    Socket = NewState#state.socket,

    Packet = build_of_pkt(Type, Xid, Msg, NewState),

    case TransportMod:send(Socket, Packet) of
	ok ->
	    setelement(3, NextStateInfo, NewState);
	{error, Reason} ->
	    ?DEBUG("error - Reason: ~p~n", [Reason]),
	    handle_socket_error(Socket, NewState)
    end.

%%
%% counter wrapper
%%

-define(INC_COUNTER(Field), do_inc_counter(Counter, Field) -> Counter#flower_datapath_counter{Field = Counter#flower_datapath_counter.Field + 1}).
?INC_COUNTER(raw_packets);
?INC_COUNTER(hello);
?INC_COUNTER(error);
?INC_COUNTER(echo_request);
?INC_COUNTER(echo_reply);
?INC_COUNTER(vendor);
?INC_COUNTER(features_request);
?INC_COUNTER(features_reply);
?INC_COUNTER(get_config_request);
?INC_COUNTER(get_config_reply);
?INC_COUNTER(set_config);
?INC_COUNTER(packet_in);
?INC_COUNTER(flow_removed);
?INC_COUNTER(port_status);
?INC_COUNTER(packet_out);
?INC_COUNTER(flow_mod);
?INC_COUNTER(port_mod);
?INC_COUNTER(stats_request);
?INC_COUNTER(stats_reply);
?INC_COUNTER(barrier_request);
?INC_COUNTER(barrier_reply);
?INC_COUNTER(queue_get_config_request);
?INC_COUNTER(queue_get_config_reply);
?INC_COUNTER(role_request);
?INC_COUNTER(role_reply);
do_inc_counter(Counter, _) -> Counter#flower_datapath_counter{unknown = Counter#flower_datapath_counter.unknown + 1}.

inc_counter(State = #state{counters = Counters}, send, Field) ->
    State#state{counters = Counters#flower_datapath_counters{send = do_inc_counter(Counters#flower_datapath_counters.send, Field)}};
inc_counter(State = #state{counters = Counters}, recv, Field) ->
    State#state{counters = Counters#flower_datapath_counters{recv = do_inc_counter(Counters#flower_datapath_counters.recv, Field)}}.

build_of_pkt(Type, Xid, Msg, #state{version = Version})
  when Version == 1 ->
    flower_packet:encode(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg});

build_of_pkt(Type, Xid, Msg, #state{version = Version})
  when Version == 2 ->
    flower_packet_v11:encode(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg});

build_of_pkt(Type, Xid, Msg, #state{version = Version})
  when Version == 3 ->
    flower_packet_v12:encode(#ovs_msg{version = Version, type = Type, xid = Xid, msg = Msg}).

decode_of_pkt(Data, #state{version = Version})
  when Version == 1 ->
    flower_packet:decode(Data);

decode_of_pkt(Data, #state{version = Version})
  when Version == 2 ->
    flower_packet_v11:decode(Data);

decode_of_pkt(Data, #state{version = Version})
  when Version == 3 ->
    flower_packet_v12:decode(Data);

decode_of_pkt(Data, _State) ->
    %% best effort try even when the version it to high,
    %% really for hello only....
    flower_packet_v12:decode(Data).
