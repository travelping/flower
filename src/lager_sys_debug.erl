-module(lager_sys_debug).

-export([lager_gen_fsm_trace/3, lager_gen_server_trace/3]).

%%-----------------------------------------------------------------
%% Format debug messages. Print them as the call-back module sees
%% them, not as the real erlang messages.
%%
%% This a copy of gen_event:print_event/3 modified for lager debug
%%-----------------------------------------------------------------
lager_gen_fsm_trace(FuncState, {in, Msg}, {Name, StateName}) ->
    case Msg of
        {'$gen_fsm', Event} ->
            lager:debug("~p:~p got event ~p in state ~w", [FuncState, Name, Event, StateName]);
        {'$gen_all_state_event', Event} ->
            lager:debug("~p:~p got all_state_event ~p in state ~w", [FuncState, Name, Event, StateName]);
        {timeout, Ref, {'$gen_timer', Message}} ->
            lager:debug("~p:~p got timer ~p in state ~w", [FuncState, Name, {timeout, Ref, Message}, StateName]);
        {timeout, _Ref, {'$gen_fsm', Event}} ->
            lager:debug("~p:~p got timer ~p in state ~w", [FuncState, Name, Event, StateName]);
        _ ->
            lager:debug("~p:~p got ~p in state ~w~n", [FuncState, Name, Msg, StateName])
    end,
    FuncState;
lager_gen_fsm_trace(FuncState, {out, Msg, To, StateName}, Name) ->
    lager:debug("~p:~p sent ~p to ~w and switched to state ~w", [FuncState, Name, Msg, To, StateName]),
    FuncState;
lager_gen_fsm_trace(FuncState, return, {Name, StateName}) ->
    lager:debug("~p:~p switched to state ~w", [FuncState, Name, StateName]),
    FuncState.

%%-----------------------------------------------------------------
%% Format debug messages. Print them as the call-back module sees
%% them, not as the real erlang messages.
%%
%% This a copy of gen_server:print_event/3 modified for lager debug
%%-----------------------------------------------------------------
lager_gen_server_trace(FuncState, {in, Msg}, Name) ->
    case Msg of
        {'$gen_call', {From, _Tag}, Call} ->
            lager:debug("~p:~p got call ~p from ~w", [FuncState, Name, Call, From]);
        {'$gen_cast', Cast} ->
	    lager:debug("~p:~p got cast ~p", [FuncState, Name, Cast]);
        _ ->
            lager:debug("~p:~p got ~p", [FuncState, Name, Msg])
    end,
    FuncState;
lager_gen_server_trace(FuncState, {out, Msg, To, State}, Name) ->
    lager:debug("~p:~p sent ~p to ~w, new state ~w", [FuncState, Name, Msg, To, State]),
    FuncState;
lager_gen_server_trace(FuncState, {noreply, State}, Name) ->
    lager:debug("~p:~p new state ~w", [FuncState, Name, State]),
    FuncState;
lager_gen_server_trace(FuncState, Event, Name) ->
    lager:debug("~p:~p dbg ~p", [FuncState, Name, Event]),
    FuncState.
