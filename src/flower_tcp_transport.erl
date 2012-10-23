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

-module(flower_tcp_transport).
-behaviour(gen_listener_tcp).

-include("flower_debug.hrl").

%% API
-export([listen/2, connect/3]).

%% Transport Modules Callbacks
-export([listener_spec/1, connect/2, close/1, send/2]).

%% Listener exports
-export([start_link/2]).

%% gen_listener_tcp callbacks
-export([init/1, handle_accept/2, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TCP_CLIENT_OPTS, [binary, inet,
			  {active,       false},
			  {send_timeout, 5000},
			  {nodelay,      true},
			  {packet,       raw},
			  {reuseaddr,    true}]).

-define(TCP_SERVER_OPTS, [binary, inet,
			  {ip,           {0,0,0,0}},
			  {active,       false},
			  {send_timeout, 5000},
			  {backlog,      10},
			  {nodelay,      true},
			  {packet,       raw},
			  {reuseaddr,    true}]).

%%%===================================================================
%%% API
%%%===================================================================

%% start a TCP listener process on the given Port with Options
listen(Port, Options) ->
    flower_sup:start_listener(?MODULE, {Port, Options}).

connect(Host, Port, Options) ->
    flower_datapath:connect(?MODULE, {Host, Port, Options}).

%%%===================================================================
%%% Transport Module Callbacks
%%%===================================================================

%% return a supervisor spec to start a listener
listener_spec({Port, Options}) ->
    {{?MODULE, Port},
     {?MODULE, start_link, [Port, Options]},
     permanent, 5000, worker, [?MODULE]}.

connect({Host, Port, Options}, Timeout) ->
    gen_tcp:connect(Host, Port, Options ++ ?TCP_CLIENT_OPTS, Timeout).

close(Socket) ->
    gen_tcp:close(Socket).

send(Socket, Packet) ->
    case gen_tcp:send(Socket, Packet) of
	ok ->
	    inet:setopts(Socket, [{active, once}]);
	Reply ->
	    Reply
    end.

%%%===================================================================
%%% Listener Callbacks
%%%===================================================================

start_link(Port, Options) ->
    gen_listener_tcp:start_link({local, ?MODULE}, ?MODULE, {Port, Options}, [{debug,[trace]}]).

init({Port, Options}) ->
    {ok, {Port, lists:merge(lists:sort(Options), lists:sort(?TCP_SERVER_OPTS))}, nil}.

handle_accept(Sock, State) ->
    case flower_datapath:start_connection(?MODULE) of
	{ok, Pid} ->
	    ok = gen_tcp:controlling_process(Sock, Pid),
	    flower_datapath:accept(Pid, Sock);
	_ ->
	    error_logger:error_report([{event, accept_failed}]),
	    gen_tcp:close(Sock)
    end,
    {noreply, State}.

handle_call(Request, _From, State) ->
    {reply, {illegal_request, Request}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(Reason, _State) ->
    ?DEBUG("flower_tcp_listener terminate on ~p", [Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
