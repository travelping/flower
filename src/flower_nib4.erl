%%----------------------------------------------------------------------
%% Purpose: Network Information Base for IPv4
%%----------------------------------------------------------------------
%%
%% The nib4 module stores IPv4 network ranges in Network/Mask notation
%% and provides a way to match single IP's against those ranges
%%
%%----------------------------------------------------------------------

-module(flower_nib4).

-export([new/0, add/3, del/2, lookup/2, to_list/1]).

-record(nib4, {
	  nib4 :: array:array()
	 }).

%%%===================================================================
%%% API
%%%===================================================================

-type nib4() :: #nib4{}.

-spec new() -> nib4().
new() ->
    #nib4{nib4 = array:new(33, {default, gb_trees:empty()})}.

-spec add({Network :: binary(), Mask :: non_neg_integer()}, Value :: term(), Nib :: nib4()) -> nib4().
add({<<Network:32/integer>>, Mask}, Value, #nib4{nib4 = Nib4} = Nib)
  when Mask >= 0, Mask =< 32, is_record(Nib, nib4) ->
    N = Network band (16#FFFFFFFF bsl (32 - Mask)),
    Nib#nib4{nib4 = array:set(Mask, gb_trees:enter(N, Value, array:get(Mask, Nib4)), Nib4)}.

-spec del({Network :: binary(), Mask :: non_neg_integer()}, Nib :: nib4()) -> nib4().
del({<<Network:32/integer>>, Mask}, #nib4{nib4 = Nib4} = Nib)
  when Mask >= 0, Mask =< 32, is_record(Nib, nib4) ->
    N = Network band (16#FFFFFFFF bsl (32 - Mask)),
    Nib#nib4{nib4 = array:set(Mask, gb_trees:delete_any(N, array:get(Mask, Nib4)), Nib4)}.

-spec lookup(IP :: binary(), Nib :: nib4()) -> term();
	    ({Network :: binary(), Mask :: non_neg_integer()}, Nib :: nib4()) -> term().
lookup(<<IP:32/integer>>, #nib4{nib4 = Nib4} = Nib)
  when is_record(Nib, nib4) ->
    array:sparse_foldr(fun(Index, Tree, none) ->
			       N = IP band (16#FFFFFFFF bsl (32 - Index)),
			       gb_trees:lookup(N, Tree);
			  (_Index, _Tree, A) ->
			       A
		       end, none, Nib4);

lookup({<<Network:32/integer>>, Mask}, #nib4{nib4 = Nib4} = Nib)
  when Mask >= 0, Mask =< 32, is_record(Nib, nib4) ->
    N = Network band (16#FFFFFFFF bsl (32 - Mask)),
    gb_trees:lookup(N, array:get(Mask, Nib4)).

to_list(#nib4{nib4 = Nib4} = Nib)
  when is_record(Nib, nib4) ->
    array:sparse_foldr(fun(Index, Tree, Acc) -> Acc ++ [{{<<Network:32>>, Index}, Value, Owner} || {Network, {Owner, Value}} <- gb_trees:to_list(Tree)] end, [], Nib4).
