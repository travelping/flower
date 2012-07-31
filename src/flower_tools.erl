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

-module(flower_tools).

-include("flower_flow.hrl").

-export([ip_to_tuple/1, tuple_to_ip/1]).
-export([format_ip/1, format_mac/1]).
-export([format_flow/1]).
-export([hexdump/1]).

flat_format(Format, Data) ->
    lists:flatten(io_lib:format(Format, Data)).

ip_to_tuple(<<A:8, B:8, C:8, D:8>>) ->
    {A, B, C, D};
ip_to_tuple(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

format_mac(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    flat_format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B", [A, B, C, D, E, F]);
format_mac(MAC) ->
    flat_format("~w", MAC).

format_ip(undefined) ->
    "undefined";
format_ip(<<A:8, B:8, C:8, D:8>>) ->
    flat_format("~B.~B.~B.~B", [A, B, C, D]);
format_ip(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    flat_format("~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B", [A, B, C, D, E, F, G, H]);
format_ip(IP) ->
    flat_format("~w", IP).


format_flow(#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst, in_port = InPort, vlan_tci = VlanTci,
		  dl_type = DlType, dl_src = DlSrc, dl_dst = DlDst,
		  nw_proto = NwProto, arp_sha = ArpSha, arp_tha = ArpTha})
  when DlType == arp ->
    flat_format("ARP Flow: tun_id = ~w, in_port = ~w, vlan_tci = ~w, dl_src = ~s, dl_dst = ~s, dl_type = ~w, nw_proto (arp op) = ~w, nw_src (sha) = ~s, nw_dst (tpa) = ~s, arp_sha = ~s, arp_tha = ~s",
		[TunId,  InPort, VlanTci, format_mac(DlSrc), format_mac(DlDst), DlType, NwProto, format_ip(NwSrc), format_ip(NwDst),format_mac(ArpSha), format_mac(ArpTha)]);

format_flow(#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst, in_port = InPort, vlan_tci = VlanTci,
		  dl_type = DlType, tp_src = TpSrc, tp_dst = TpDst, dl_src = DlSrc, dl_dst = DlDst,
		  nw_proto = NwProto, nw_tos = NwTos}) ->
    flat_format("Flow: tun_id = ~w, nw_src = ~s, nw_dst = ~s, in_port = ~w, vlan_tci = ~w, dl_type = ~w, tp_src = ~w, tp_dst = ~w, dl_src = ~s, dl_dst = ~s, nw_proto = ~w, nw_tos = ~w",
		[TunId, format_ip(NwSrc), format_ip(NwDst), InPort, VlanTci, DlType, TpSrc, TpDst, format_mac(DlSrc), format_mac(DlDst), NwProto, NwTos]).


hexdump(Line, Part) ->
       L0 = [io_lib:format(" ~2.16.0B", [X]) || <<X:8>> <= Part],
       L1 = lists:flatten(L0),
       io_lib:format("~4.16.0B:~s~n", [Line * 16, L0]).
       
hexdump(Line, <<>>, Out) ->
       lists:flatten(lists:reverse(Out));
hexdump(Line, <<Part:16/bytes, Rest/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, Rest, [L1|Out]);
hexdump(Line, <<Part/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, <<>>, [L1|Out]).

hexdump(List) when is_list(List) ->
       hexdump(0, list_to_binary(List), []);
hexdump(Bin) when is_binary(Bin)->
       hexdump(0, Bin, []).
