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

do_join(Events, Pid) when is_list(Events) ->
    [do_join(Event, Pid) || Event <- Events];
do_join(Event, Pid) ->
    case flower_event:is_registered(Event) of
	true ->
	    ets:insert(?SERVER, {Event, Pid}),
	    [Pid];
	false ->
	    {error, invalid}
    end.

do_leave(Events, Pid) when is_list(Events) ->
    [do_leave(Event, Pid) || Event <- Events];
do_leave(Event, Pid) ->
    ets:match_delete(?SERVER, {Event, Pid}).
