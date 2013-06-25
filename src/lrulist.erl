%%From:
%%   git://gist.github.com/14833.git

%% @doc A small LRU list container.
%% @todo Add better documentation.
%% @todo Find edge case bugs in purging.

-module(lrulist).
-author("Nick Gerakines <nick@gerakines.net>").

-export([dump/1, new/0, get/2, peek/2, insert/3, insert/4, remove/2, purge/1, keys/1]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include_lib("eunit/include/eunit.hrl").

-record(data, {expire, lastAccess, rules, data}).

%% ---
%% Public functions

%% @doc Create a new LRU container
new() ->
    {gb_trees:empty(), gb_trees:empty()}.

%% @doc Fetch data from a LRU list based on a key.
get(Key, LRUL = {Tree, LRUTree}) ->
    case gb_trees:lookup(Key, Tree) of
	none -> {none, LRUL};
	{value, #data{} = Data} ->
	    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
	    if
		Data#data.expire < Now ->
		    NewLRUL = remove(Key, LRUL),
		    {none, NewLRUL};
		true ->
		    NewData = update_lastAccess(Data, Now),
		    UpdatedTree = gb_trees:enter(Key, NewData, Tree),
		    UpdateLRUTree = update_lru(Key, Data#data.expire, NewData#data.expire, LRUTree),
		    {{ok, Data#data.data}, {UpdatedTree, UpdateLRUTree}}
	    end
    end.

%% @doc Dump the data as a key-value list
dump(Tree) ->
    {Res,_} =
        lists:foldl(fun(Key,{Vals,Tree0}) ->
                            case peek(Key, Tree0) of
                                {none, Tree1}     -> {Vals,Tree1};
                                {{ok,Val}, Tree1} -> {[{Key,Val}|Vals],Tree1}
                            end
                    end, {[],Tree}, keys(Tree)),
    Res.


%% @doc Fetch data from a LRU list based on a key, don't update lastAccess
peek(Key, LRUL = {Tree, _}) ->
    case gb_trees:lookup(Key, Tree) of
	none -> {none, LRUL};
	{value, #data{} = Data} ->
	    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
	    if
		Data#data.expire < Now ->
		    NewLRUL = remove(Key, LRUL),
		    {none, NewLRUL};
		true ->
		    {{ok, Data#data.data}, LRUL}
	    end
    end.

%% This is the same as insert(Key, Value, LRUContainer, []).
insert(Key, Value, LRUL) ->
    insert(Key, Value, LRUL, []).

%% @doc Insert a new value into the container.
%% @todo document options.
insert(Key, Value, {Tree, LRUTree}, Options) ->
    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
    Data0 = init_data(Options, Now),
    Data1 = Data0#data{data = Value},
    NewTree = gb_trees:enter(Key, Data1, Tree),
    NewLRUTree = enter_lru(Key, Data1#data.expire, LRUTree),
    {ok, {NewTree, NewLRUTree}}.

%% @doc Remove an item from the container.
%% @todo Check for edge cases.
remove(Key, {Tree, LRUTree}) ->
    {NewTree, NewLRUTree} = case gb_trees:lookup(Key, Tree) of
				none ->
				    {Tree, LRUTree};
				{value, #data{} = Data} ->
				    NewTree1 = gb_trees:delete(Key, Tree),
				    NewLRUTree1 = delete_lru(Key, Data#data.expire, LRUTree),
				    {NewTree1, NewLRUTree1}
			    end,
    {NewTree, NewLRUTree}.

%% @doc Attempt to purge expired and bloating items from the LRU container.
purge(LRUL = {_, LRUTree}) ->
    Now = calendar:datetime_to_gregorian_seconds({date(), time()}),
    {NewTree, NewLRUTree} = purge_run(Now, purge_next(LRUTree), LRUL),
    BalancedTree = gb_trees:balance(NewTree),
    BalancedLRUTree = gb_trees:balance(NewLRUTree),
    {BalancedTree, BalancedLRUTree}.

keys({Tree, _LRUTree}) ->
    gb_trees:keys(Tree).

%% ---
%% Private functions

%% get next exntry to expire
purge_next(LRUTree) ->
    case gb_trees:is_empty(LRUTree) of
	true ->
	    none;
	_ ->
	    gb_trees:smallest(LRUTree)
    end.

%% go over the LRUTree until the 1st non expired entry
%%
%%@REMARK:
%% we could use a iterator here, but a iterator is basicly
%% a linerized form of the full tree, someone needs to
%% convince me that this is actually faster than doing
%% a few lookups...
%% or in other works, for n > 100000 and x < 20 is
%% amortized x * O(log n) worse than O(n)
purge_run(_, none, LRUL) ->
    LRUL;
purge_run(Now, {Expire, _}, LRUL)
  when Expire >= Now ->
    LRUL;
purge_run(Now, {Expire, Keys}, {Tree, LRUTree}) ->
    Empty = gb_trees:empty(),
    NewTree = lists:foldl(fun(_Key, ATree) when ATree =:= Empty -> ATree;
                             (Key, ATree) ->
                                  gb_trees:delete(Key, ATree)
                          end, Tree, Keys),
    NewLRUTree = gb_trees:delete(Expire, LRUTree),
    purge_run(Now, purge_next(NewLRUTree), {NewTree, NewLRUTree}).

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

%% purge_test_ -- Do some writes and reads on a
%% container.
purge_test_() ->
    {timeout, 20,
     fun() ->
	     LRUList = lists:foldl(
			 fun(User, Tmplru) ->
				 {ok, Tmplru2} = lrulist:insert(User, User, Tmplru, [{slidingexpire, 5}]),
				 {{ok, User}, Tmplru3} = lrulist:get(User, Tmplru2),
				 Tmplru3
			 end,
			 lrulist:new(),
			 [lists:concat(["user", X]) || X <- lists:seq(1, 20)]
			),

	     %% wait 10 sec
	     timer:sleep(10000),
	     LRUList1 = purge(LRUList),
	     [] == lrulist:keys(LRUList1)
     end}.

dump_test_() ->
    {
      "Get all values.",
      fun() ->
              L1 = lrulist:new(),
              {ok, L2} = lrulist:insert("s", 4, L1),
              {ok, L3} = lrulist:insert("p", 2, L2),
              {ok, L4} = lrulist:insert("d", 4, L3),
              [{"d",4},{"p",2},{"s",4}] = lists:keysort(1, dump(L4))
      end
           }.

-spec gb_trees_update_fun(Key, Fun, Tree1) -> Tree2 when
      Key :: term(),
      Fun :: fun(),
      Tree1 :: gb_tree(),
      Tree2 :: gb_tree().

%% derived from stdlib/gb_trees.erl

gb_trees_update_fun(Key, Fun, {S, T}) ->
    T1 = gb_trees_update_1(Key, Fun, T),
    {S, T1}.
gb_trees_update_1(Key, Fun, {Key1, V, Smaller, Bigger}) when Key < Key1 -> 
    {Key1, V, gb_trees_update_1(Key, Fun, Smaller), Bigger};
gb_trees_update_1(Key, Fun, {Key1, V, Smaller, Bigger}) when Key > Key1 ->
    {Key1, V, Smaller, gb_trees_update_1(Key, Fun, Bigger)};
gb_trees_update_1(Key, Fun, {_, V, Smaller, Bigger}) ->
    {Key, Fun(V), Smaller, Bigger}.

calc_expire({Absolute, Sliding}, Now)
  when Absolute /= undefined,
       Sliding /= undefined ->
    if
	Absolute < Now + Sliding ->
	    Absolute;
	true -> Now + Sliding
    end;
calc_expire({_Absolute, Sliding}, Now)
  when Sliding /= undefined ->
    Now + Sliding;
calc_expire({Absolute, _Sliding}, _)
  when Absolute /= undefined ->
    Absolute;
calc_expire({_Absolute, _Sliding}, _) ->
    never.

init_data(Options, Now) ->
    Sliding = proplists:get_value(slidingexpire, Options),
    Absolute = proplists:get_value(absoluteExpire, Options),
    Rules = {Absolute, Sliding},
    #data{expire = calc_expire(Rules, Now), lastAccess = Now, rules = Rules}.

update_lastAccess(Data = #data{rules = Rules}, Now) ->
    Data#data{expire = calc_expire(Rules, Now), lastAccess = Now}.

update_lru(_, ATime, ATime, LRUTree) ->
    LRUTree;
update_lru(Key, OldATime, NewATime, LRUTree) ->
    LRUTree1 = delete_lru(Key, OldATime, LRUTree),
    enter_lru(Key, NewATime, LRUTree1).

delete_lru(Key, ATime, LRUTree) ->
    gb_trees_update_fun(ATime, fun(List) -> lists:delete(Key, List) end, LRUTree).

enter_lru(Key, ATime, LRUTree) ->
    case gb_trees:is_defined(ATime, LRUTree) of
	true ->
	    gb_trees_update_fun(ATime, fun(List) -> lists:merge(List, [Key]) end, LRUTree);
	false ->
	    gb_trees:insert(ATime, [Key], LRUTree)
    end.
