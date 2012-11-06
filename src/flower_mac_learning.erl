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

-module(flower_mac_learning).

-behaviour(gen_server).

%% API
-export([start_link/0
         , insert/2
         , insert/3
         , lookup/1
         , lookup/2
         , expire/0
         , may_learn/1
         , may_learn/2
         , eth_addr_is_reserved/1
         , dump/0
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 
-define(MAC_ENTRY_IDLE_TIME, 60).

-record(state, {
	  timer,
	  lru
	 }).

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

insert(MAC, Port) ->
    insert(MAC, 0, Port).

insert(MAC, VLan, Port) ->
    gen_server:call(?SERVER, {insert, MAC, VLan, Port}).

lookup(MAC) ->
    lookup(MAC, 0).

lookup(MAC, VLan) ->
    gen_server:call(?SERVER, {lookup, MAC, VLan}).

dump() ->
    gen_server:call(?SERVER, {dump}).

expire() ->
    gen_server:cast(?SERVER, expire).

may_learn(<<_:7, BCast:1, _/binary>> = _MAC) ->
    (BCast =/= 1).

may_learn(<<_:7, BCast:1, _/binary>> = _MAC, _VLan) ->
    (BCast =/= 1).

%% Returns true if it is a reserved multicast address, that a bridge must
%% never forward, false otherwise.
eth_addr_is_reserved(<<16#01, 16#80, 16#C2, 16#00, 16#00, 0:4, _:4>>) ->
    true;
eth_addr_is_reserved(_Addr) ->
    false.


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
    process_flag(trap_exit, true),
    LRU = lrulist:new(),
    {ok, Timer} = timer:apply_interval(1000, ?MODULE, expire, []),
    {ok, #state{timer = Timer, lru = LRU}}.

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
handle_call({insert, MAC, VLan, Port}, _From, #state{lru = LRU} = State) ->
    {Result, LRU0} =  lrulist:get({MAC, VLan}, LRU),
    {Reply, LRU1} = case Result of
			none ->
			    {ok, NewLRU} = lrulist:insert({MAC, VLan}, Port, LRU0, [{slidingexpire, ?MAC_ENTRY_IDLE_TIME}]),
			    {new, NewLRU};
			{ok, Data} ->
			    if (Data =/= Port) ->
				    {ok, NewLRU} = lrulist:insert({MAC, VLan}, Port, LRU0, [{slidingexpire, ?MAC_ENTRY_IDLE_TIME}]),
				    {updated, NewLRU};
			       true ->
				    {ok, LRU0}
			    end
		    end,
    {reply, Reply, State#state{lru = LRU1}};

handle_call({lookup, MAC, VLan}, _From, #state{lru = LRU} = State) ->
    {Result, LRU0} =  lrulist:peek({MAC, VLan}, LRU),
    {reply, Result, State#state{lru = LRU0}};

handle_call({dump}, _From, #state{lru = LRU} = State) ->
    Result =  [{Mac,Val} || {{Mac,_VLan},Val} <- lrulist:dump(LRU)],
    {reply, {ok, Result}, State}.

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
handle_cast(expire, #state{lru = LRU} = State) ->
    LRU0 = lrulist:purge(LRU),
    {noreply, State#state{lru = LRU0}}.

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
