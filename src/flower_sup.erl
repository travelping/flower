
-module(flower_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, { {one_for_one, 5, 10}, [
                                  {flower_tcp_socket, {flower_tcp_socket, start_link, []}, permanent, brutal_kill, worker, [flower_tcp_socket]},
                                  {flower_mac_learning, {flower_mac_learning, start_link, []}, permanent, brutal_kill, worker, [flower_mac_learning]},
                                  {flower_event, {flower_event, start_link, []}, permanent, brutal_kill, worker, [flower_event]},
                                  {flower_dispatcher, {flower_dispatcher, start_link, []}, permanent, brutal_kill, worker, [flower_dispatcher]}
                                 ]} }.

