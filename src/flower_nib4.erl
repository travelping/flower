%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>

%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:

%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.

%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

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
	  nib4 :: array()
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
