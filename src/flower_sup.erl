-module(flower_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_listener/2, stop_listener/2]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% start a listener process for the given transport module with arguments
start_listener(TransportMod, Arguments) ->
    Spec = TransportMod:listener_spec(Arguments),
    supervisor:start_child(?MODULE, Spec).

stop_listener(TransportMod, Arguments) ->
    {Id,_,_,_,_,_} = TransportMod:listener_spec(Arguments),
    ok = supervisor:terminate_child(?MODULE, Id),
    ok = supervisor:delete_child(?MODULE, Id).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 5, 10}, [
				 ?CHILD(flower_event, worker),
				 ?CHILD(flower_dispatcher, worker),
				 ?CHILD(flower_mac_learning, worker),
				 ?CHILD(flower_component_sup, supervisor),
				 ?CHILD(flower_datapath_sup, supervisor)
				]} }.

