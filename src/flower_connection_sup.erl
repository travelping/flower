-module(flower_connection_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([start_connection/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Restart), {I, {I, start_link, []}, Restart, 5000, worker, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_connection(I) ->
	supervisor:start_child(?MODULE, ?CHILD(I, temporary)).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 5, 10}, [?CHILD(flower_tcp_socket, permanent)]}}.

