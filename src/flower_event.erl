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

handle_unregister(Event, _Args, Events) ->
    Pids = case orddict:find(Event, Events) of
	       {ok, Pid} ->
		   [Pid];
	       _ ->
		   []
	   end,
    Events1 = orddict:erase(Event, Events),
    {Pids, Events1}.

handle_pid_remove(Pid, _Event, Events) ->
    {Events1, Keys} = orddict:fold(fun(Key, Value, {Ev, K}) when Value == Pid -> {Ev, [Key|K]};
				      (Key, Value, {Ev, K}) -> {orddict:append(Key, Value, Ev), K}
				   end, {orddict:new(), []}, Events),
    %% avoid dead-lock
    spawn(fun() -> lists:foreach(fun(Key) -> flower_dispatcher:delete(Key) end, Keys) end),
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
