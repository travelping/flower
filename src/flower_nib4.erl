%%----------------------------------------------------------------------
%% Purpose: Network Information Base for IPv4
%%----------------------------------------------------------------------
%%
%% The nib4 module stores IPv4 network ranges in Network/Mask notation
%% and provides a way to match single IP's against those ranges
%%
%%----------------------------------------------------------------------

-module(flower_nib4).

-export([new/0, add/3, del/2, lookup/2]).

-record(nib4, {
		  nib4 :: gb_tree()
		 }).

%%%===================================================================
%%% API
%%%===================================================================

new() ->
	#nib4{nib4 = array:new(31, {default, gb_trees:empty()})}.

add({<<Network:32/integer>>, Mask}, Value, #nib4{nib4 = Nib4} = Nib)
  when Mask > 0, Mask =< 32, is_record(Nib, nib4) ->
	N = Network band (16#FFFFFFFF bsl (32 - Mask)),
	Nib#nib4{nib4 = array:set(Mask - 1, gb_trees:enter(N, Value, array:get(Mask - 1, Nib4)), Nib4)}.

del({<<Network:32/integer>>, Mask}, #nib4{nib4 = Nib4} = Nib)
  when Mask > 0, Mask =< 32, is_record(Nib, nib4) ->
	N = Network band (16#FFFFFFFF bsl (32 - Mask)),
	Nib#nib4{nib4 = array:set(Mask - 1, gb_trees:delete_any(N, array:get(Mask - 1, Nib4)), Nib4)}.

lookup(<<IP:32/integer>>, #nib4{nib4 = Nib4} = Nib)
  when is_record(Nib, nib4) ->
	array:sparse_foldr(fun(Index, Tree, none) ->
							   N = IP band (16#FFFFFFFF bsl (32 - (Index + 1))),
							   gb_trees:lookup(N, Tree);
						  (_Index, _Tree, A) ->
							   A
					   end, none, Nib4).
