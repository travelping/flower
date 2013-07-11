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

-module(flower_mac_learning2).

-behaviour(gen_server).

%% API
-export([start_link/1, start_link/2, insert/3, insert/4, lookup/2, lookup/3,
	 expire/1, may_learn/1, may_learn/2, eth_addr_is_reserved/1,
	 is_broadcast/1,
	 dump/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

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
start_link(Options) when is_list(Options) ->
    gen_server:start_link(?MODULE, [], Options);
start_link(ServerName) ->
    gen_server:start_link(ServerName, ?MODULE, [], []).

start_link(ServerName, Options) ->
    gen_server:start_link(ServerName, ?MODULE, [], Options).

insert(Server, MAC, Port) ->
    insert(Server, MAC, 0, Port).

insert(Server, MAC, VLan, Port) ->
    gen_server:call(Server, {insert, MAC, VLan, Port}).

lookup(Server, MAC) ->
    lookup(Server, MAC, 0).

lookup(Server, MAC, VLan) ->
    gen_server:call(Server, {lookup, MAC, VLan}).

dump(Server) ->
    gen_server:call(Server, {dump}).

expire(Server) ->
    gen_server:cast(Server, expire).

may_learn(<<_:7, BCast:1, _/binary>> = _MAC) ->
    (BCast =/= 1).

may_learn(<<_:7, BCast:1, _/binary>> = _MAC, _VLan) ->
    (BCast =/= 1).

is_broadcast(<<_:7, 1:1, _/binary>> = _MAC) ->
    true;
is_broadcast(_) ->
    false.

%%
%% Some well known Ethernet multicast addresses[11]
%% Ethernet multicast addressType FieldUsage
%% 01-00-0C-CC-CC-CC  0x0802      CDP (Cisco Discovery Protocol),
%%                                VTP (VLAN Trunking Protocol)
%% 01-00-0C-CC-CC-CD  0x0802      Cisco Shared Spanning Tree Protocol Address
%% 01-80-C2-00-00-00  0x0802      Spanning Tree Protocol (for bridges) IEEE 802.1D
%% 01-80-C2-00-00-08  0x0802      Spanning Tree Protocol (for provider bridges) IEEE 802.1AD
%% 01-80-C2-00-00-02  0x8809      Ethernet OAM Protocol IEEE 802.3ah (A.K.A. "slow protocols")
%% 01-00-5E-xx-xx-xx  0x0800      IPv4 Multicast (RFC 1112)
%% 33-33-xx-xx-xx-xx  0x86DD      IPv6 Multicast (RFC 2464)
%%
%% Returns true if it is a reserved multicast address, that a bridge must
%% never forward, false otherwise.
%%
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
