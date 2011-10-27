%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created :  5 Jul 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(flower_dispatcher).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([delete/1, join/1, leave/1, dispatch/3]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

-define(SERVER, ?MODULE). 

-record(state, {
		 }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
	regine_server:start_link({local, ?SERVER}, ?MODULE, []).

join(Event) ->
	regine_server:register(?SERVER, self(), Event, self()).

leave(Event) ->
	regine_server:unregister(?SERVER, Event, self()).

delete(Event) ->
	regine_server:unregister(?SERVER, Event, all).

dispatch(Event, Sw, Msg) ->
	Handlers = ets:lookup(?SERVER, Event),
	lists:foreach(fun({_Ev, Pid}) ->
						  gen_server:cast(Pid, {Event, Sw, Msg})
				  end, Handlers).

%%%===================================================================
%%% regine_server functions
%%%===================================================================

init([]) ->
    process_flag(trap_exit, true),
	ets:new(?SERVER, [bag, protected, named_table, {keypos, 1}]),
	{ok, #state{}}.

handle_register(Pid, Event, Pid, State) ->
	Reply = do_join(Event, Pid),
	{ok, Reply, State}.

handle_unregister(Event, all, State) ->
	Pids = ets:lookup_element(?SERVER, Event, 2),
	ets:delete(?SERVER, Event),
	{Pids, State};

handle_unregister(Event, Pid, State) ->
	do_leave(Event, Pid),
	{[Pid], State}.

handle_death(_Pid, _Reason, State) ->
	State.

handle_pid_remove(Pid, Events, State) ->
	lists:foreach(fun(Event) -> do_leave(Event, Pid) end, Events),
	State.
						   
terminate(_Reason, _State) ->
	ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

do_join(Event, Pid) ->
	case flower_event:is_registered(Event) of
		true ->
			ets:insert(?SERVER, {Event, Pid}),
			[Pid];
		false ->
			{error, invalid}
	end.

do_leave(Event, Pid) ->
	ets:match_delete(?SERVER, {Event, Pid}).
