%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created :  5 Jul 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_event).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([is_registered/1, register/1, unregister/1, terminate/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
		 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {
		  events
		 }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

is_registered(Event) ->
	gen_server:call(?SERVER, {is_registered, Event}).

register(Event) ->
	gen_server:call(?SERVER, {register, Event}).

unregister(Event) ->
	gen_server:call(?SERVER, {unregister, Event}).
	
terminate(Event) ->
	gen_server:cast(?SERVER, {terminate, Event}).

%%%===================================================================
%%% gen_server functions
%%%===================================================================

default_events() ->
	[{datapath, join}, {datapath, leave}, {packet, in}, {flow, mod}, {flow, removed}, {port, status}, {port, stats}].

init([]) ->
    process_flag(trap_exit, true),
	Events = lists:foldl(fun(Event, Events) -> orddict:store(Event, self(), Events) end, orddict:new(), default_events()),
	{ok, #state{events = Events}}.

handle_call({register, Event}, {Pid, _Ref} = _From, #state{events = Events} = State) ->
	case orddict:is_key(Event, Events) of
		true ->
			link(Pid),
			Events1 = orddict:store(Event, Pid, Events),
			{reply, ok, State#state{events = Events1}};
		false ->
			{reply, {error, duplicate}, State}
	end;

handle_call({unregister, Event}, _From, #state{events = Events} = State) ->
	Events1 = orddict:erase(Event, Events),
	{reply, ok, State#state{events = Events1}};

handle_call({is_registered, Event}, _From, #state{events = Events} = State) ->
	Reply = orddict:is_key(Event, Events),
	{reply, Reply, State}.

handle_cast({terminate, Event}, #state{events = Events} = State) ->
	case orddict:find(Event, Events) of
		{ok, Pid} ->
			gen_server:cast(Pid, {terminate, Event});
		_ ->
			ok
	end,
	{noreply, State};

handle_cast(terminate, State) ->
	{stop, request, State}.

handle_info({'EXIT', Pid, _Reason}, #state{events = Events} = State) ->
	Events1 = orddict:filter(fun(Key, Value) when Value == Pid -> flower_dispatcher:delete(Key), false;
								(_Key, _Value) -> true end,
					 Events),
	{noreply, State#state{events = Events1}}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
