-module(flower_tcp_socket).
-behaviour(gen_listener_tcp).

-define(TCP_PORT, 6633).
-define(TCP_OPTS, [binary, inet6,
                   {active,       false},
				   {send_timeout, 5000},
                   {backlog,      10},
                   {nodelay,      true},
                   {packet,       raw},
                   {reuseaddr,    true}]).

%% --------------------------------------------------------------------
%% External exports
-export([start/0, start_link/0]).

%% gen_listener_tcp callbacks
-export([init/1, handle_accept/2, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%%-record(state, {}).

%% ====================================================================
%% External functions
%% ====================================================================

%% @doc Start the server.
start() ->
    gen_listener_tcp:start({local, ?MODULE}, ?MODULE, [], [{debug,[trace]}]).

start_link() ->
    gen_listener_tcp:start_link({local, ?MODULE}, ?MODULE, [], [{debug,[trace]}]).

init([]) ->
    {ok, {?TCP_PORT, ?TCP_OPTS}, nil}.

handle_accept(Sock, State) ->
	case flower_connection:start() of
		{ok, Pid} ->
			flower_connection:accept(Pid, Sock);
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
	io:format("flower_tcp_socket terminate on ~p~n", [Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
