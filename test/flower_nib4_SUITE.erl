-module(flower_nib4_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

suite() ->
        [{timetrap,{seconds,30}}].

test_nib4(Config) ->
	Nib = ?config(nib, Config),
	{value, priv1} = flower_nib4:lookup(<<10,10,10,10>>, Nib),
	{value, priv2} = flower_nib4:lookup(<<172,20,10,10>>, Nib),
	{value, priv3} = flower_nib4:lookup(<<192,168,10,10>>, Nib),
	none = flower_nib4:lookup(<<193,168,10,10>>, Nib),
	flower_nib4:del({<<10,0,0,0>>, 8}, Nib),
	flower_nib4:del({<<11,0,0,0>>, 8}, Nib),
	ok.

all() -> 
        [test_nib4].

init_per_suite(Config) ->
	Nib = flower_nib4:new(),
	Nib1 = flower_nib4:add({<<10,0,0,0>>, 8}, priv1, Nib),
	Nib2 = flower_nib4:add({<<172,20,0,0>>, 12}, priv2, Nib1),
	Nib3 = flower_nib4:add({<<192,168,0,0>>, 16}, priv3, Nib2),
	[{nib, Nib3}|Config].

end_per_suite(_Config) ->
        ok.
