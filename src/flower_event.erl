%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created :  5 Jul 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_event).

-behaviour(regine_server).


%% API
-export([start_link/0]).
-export([is_registered/1, register/1, unregister/1, terminate/1]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).
-export([handle_call/3, handle_cast/2]).

-define(SERVER, ?MODULE). 

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    regine_server:start_link({local, ?SERVER}, ?MODULE, []).

register(Event) ->
    regine_server:register(?SERVER, self(), Event, undefined).

unregister(Event) ->
    regine_server:unregister(?SERVER, Event, undefined).

is_registered(Event) ->
	regine_server:call(?SERVER, {is_registered, Event}).

terminate(Event) ->
	regine_server:cast(?SERVER, {terminate, Event}).

%%%===================================================================
%%% gen_server functions
%%%===================================================================

default_events() ->
	[{datapath, join}, {datapath, leave}, {packet, in}, {flow, mod}, {flow, removed}, {port, status}, {port, stats}].

init([]) ->
	Events = lists:foldl(fun(Event, Events) -> orddict:store(Event, self(), Events) end, orddict:new(), default_events()),
	{ok, Events}.

handle_register(Pid, Event, _Args, Events) ->
	case orddict:is_key(Event, Events) of
		false ->
			Events1 = orddict:store(Event, Pid, Events),
			{ok, [Pid], Events1};
		true ->
			{error, duplicate}
	end.

handle_unregister(Event, Events, _Args) ->
	Pids = case orddict:find(Event, Events) of
			   {ok, Pid} ->
				   [Pid];
					   _ ->
				   []
		   end,
	Events1 = orddict:erase(Event, Events),
	{Pids, Events1}.

handle_pid_remove(Pid, _Event, Events) ->
	Events1 = orddict:filter(fun(Key, Value) when Value == Pid -> flower_dispatcher:delete(Key), false;
								(_Key, _Value) -> true end,
							 Events),
	Events1.

handle_death(_Pid, _Reason, Events) ->
	Events.

handle_call({is_registered, Event}, _From, Events) ->
	Reply = orddict:is_key(Event, Events),
	{reply, Reply, Events}.

handle_cast({terminate, Event}, Events) ->
	case orddict:find(Event, Events) of
		{ok, Pid} ->
			gen_server:cast(Pid, {terminate, Event});
		_ ->
			ok
	end,
	{noreply, Events}.

terminate(_Reason, _State) ->
	ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
