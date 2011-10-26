-module(flower_datapath_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).
-export([start_connection/0, datapaths/0]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_connection() ->
	supervisor:start_child(?MODULE, []).

datapaths() ->
	lists:map(fun({_, Child, _, _}) -> Child end, supervisor:which_children(?MODULE)).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
	{ok, {{simple_one_for_one, 0, 1},
          [{flower_datapath, {flower_datapath, start_link, []},
            temporary, brutal_kill, worker, [flower_datapath]}]}}.
