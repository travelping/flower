%% @doc A small LRU list container.
%% @todo Add better documentation.
%% @todo Find edge case bugs in purging.
-module(lrulist).
-author("Nick Gerakines <nick@gerakines.net>").

-export([new/0, new/1, get/2, peek/2, insert/3, insert/4, remove/2, purge/1, keys/1]).

-define(EXPIRE_RULES, [expire, slidingexpire]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include_lib("eunit/include/eunit.hrl").

%% ---
%% Public functions

%% @doc Create a new LRU container with the default size (100).
new() ->
    new(100).

%% @doc Create a new LRU container with a max size.
new(Max) when Max > 0 -> {Max, gb_trees:empty()}.

%% @doc Fetch data from a LRU list based on a key.
get(Key, LRUL = {Max, Tree}) ->
    case gb_trees:lookup(Key, Tree) of
        none -> {none, LRUL};
        {value, Data} ->
            case expire_rules(?EXPIRE_RULES, Key, Data) of
                true ->
                    NewLRUL = remove(Key, LRUL),
                    {none, NewLRUL};
                false ->
                    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
                    UpdatedTree = gb_trees:enter(Key, lists:keystore(lastAccess, 1, Data, {lastAccess, Now}), Tree),
                    {{ok, proplists:get_value(value, Data)}, {Max, UpdatedTree}}
            end
    end.

%% @doc Fetch data from a LRU list based on a key, don't update lastAccess
peek(Key, LRUL = {Max, Tree}) ->
    case gb_trees:lookup(Key, Tree) of
        none -> {none, LRUL};
        {value, Data} ->
            case expire_rules(?EXPIRE_RULES, Key, Data) of
                true ->
                    NewLRUL = remove(Key, LRUL),
                    {none, NewLRUL};
                false ->
                    {{ok, proplists:get_value(value, Data)}, {Max, Tree}}
            end
    end.

%% This is the same as insert(Key, Value, LRUContainer, []).
insert(Key, Value, {Max, Tree}) ->
    insert(Key, Value, {Max, Tree}, []).

%% @doc Insert a new value into the container.
%% @todo document options.
insert(Key, Value, {Max, Tree}, Options) ->
	Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
    PropList = lists:flatten([{lastAccess, Now},{value, Value}|Options]),
    NewTree = gb_trees:enter(Key, PropList, Tree),
    {Max, NewTree2} = case [Max > 0, gb_trees:size(Tree) > Max] of
        [true, true] -> purge({Max, NewTree});
        _ -> {Max, NewTree}
    end,
    {ok, {Max, NewTree2}}.

%% @doc Remove an item from the container.
%% @todo Check for edge cases.
remove(Key, {Max, Tree}) ->
    NewTree = gb_trees:delete_any(Key, Tree),
    {Max, NewTree}.

%% @doc Attempt to purge expired and bloating items from the LRU container.
%% @todo Add Max vs Max * .75 checks
%% @todo Document the Max * .75 rule
purge({Max, Tree}) ->
    NewTree = purge_rules(expire, Tree, Max),
    BalancedTree = gb_trees:balance(NewTree),
    {Max, BalancedTree}.

keys({_Max, Tree}) ->
    gb_trees:keys(Tree).

%% ---
%% Private functions

expire_rules([], _Key, _LRU) -> false;
%% Rule 'expire' -- If an 'absoluteExpire' key/value tuple is set as an
%% option when creating the item via insert/4, this rule will remove items
%% that have a hard expiration time.
expire_rules([expire | Rules], Key, Data ) ->
    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
    case proplists:get_value(absoluteExpire, Data, Now) < Now of
        true -> true;
        false -> expire_rules(Rules, Key, Data)
    end;
%% Rule 'slidingexpire' -- If a 'slidingExpire' key/value tuple is set as an
%% option when creating the item via insert/4, this rule will remove keys
%% based on a relative lifespan set by that tuple based on when it was last
%% accessed. In other words this expiration rule is used to expire items
%% based on when they are read from the first time.
expire_rules([slidingexpire | Rules], Key, Data) ->
    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
    case [proplists:get_value(lastAccess, Data), proplists:get_value(slidingexpire, Data)] of
        [undefined, _] -> expire_rules(Rules, Key, Data);
        [_, undefined] -> expire_rules(Rules, Key, Data);
        [LastAccess, SlidingExpire] ->
            case LastAccess + SlidingExpire < Now of
                true -> true;
                false -> expire_rules(Rules, Key, Data)
            end
    end.

%% Purge rule 'expire' -- This is the purge_* equiv of the 'expire' expire
%% rule above.
purge_rules(expire, Tree, _Max) ->
    Iter = gb_trees:iterator(Tree),
    Keys = expire_iter(gb_trees:next(Iter), []),
    lists:foldl(
        fun(Key, TmpTree) ->
            gb_trees:delete_any(Key, TmpTree)
        end,
        Tree,
        Keys
    ).

%% This funciton takes advantage of the gb_trees:iterator/1 and
%% gb_trees:next/1 functions to quickly iterate through a tree without
%% having to do heavy break-down and build-up operations on the internal
%% tree.
expire_iter(none, Acc) -> Acc;
expire_iter({Key, Value, Iter}, Acc) ->
	?DEBUG("Key: ~p, Value: ~p~n", [Key, Value]),
    NewAcc = case expire_rules(?EXPIRE_RULES, Key, Value) of
        true -> [Key | Acc];
        false -> Acc
    end,
    expire_iter(gb_trees:next(Iter), NewAcc).

%% ---
%% Test Functions
%% call with `lrulist:test().`

%% basic_test_ -- Do some basic writes and reads
basic_test_() ->
    {
        "Basic setting and getting.",
        fun() ->
            L1 = lrulist:new(),
            {ok, L2} = lrulist:insert("starbucks", 4, L1),
            {ok, L3} = lrulist:insert("petes", 2, L2),
            {ok, L4} = lrulist:insert("distel", none, L3),
            {{ok, 4}, L5} = lrulist:get("starbucks", L4),
            {{ok, 2}, L6} = lrulist:get("petes", L5),
            {{ok, none}, _L7} = lrulist:get("distel", L6)
        end
    }.

%% purge_test_ -- Do some writes and reads while tripping the Max of a lru
%% container.
purge_test_() ->
    fun() ->
        LRUList = lists:foldl(
            fun(User, Tmplru) ->
                {ok, Tmplru2} = lrulist:insert(User, User, Tmplru),
                {{ok, User}, Tmplru3} = lrulist:get(User, Tmplru2),
                Tmplru3
            end,
            lrulist:new(15),
            [lists:concat(["user", X]) || X <- lists:seq(1, 20)]
        ),
        [lists:concat(["user", X]) || X <- lists:seq(1, 15)] == lrulist:keys(LRUList)
    end.
