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

-module(flower_udp).

%% API
-export([make_udp/8]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_packet.hrl").
-include("flower_flow.hrl").

%%--------------------------------------------------------------------
%% @doc
%% Make an ethernet UDP packet
%%
%% @end
%%--------------------------------------------------------------------

make_udp(TCI, DlDst, DlSrc, NwSrc, NwDst, TpSrc, TpDst, PayLoad) ->
    Ether = flower_tools:ether_hdr(DlDst, DlSrc, TCI, flower_packet:eth_type(ip)),
    Id = 0,
    Proto = gen_socket:protocol(udp),

    UDPLength = 8 + size(PayLoad),
    UDPCSum = flower_tools:ip_csum(<<NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8,
				     0:8, Proto:8, UDPLength:16,
				     TpSrc:16, TpDst:16, UDPLength:16, 0:16,
				     PayLoad/binary>>),
    UDP = <<TpSrc:16, TpDst:16, UDPLength:16, UDPCSum:16, PayLoad/binary>>,

    TotLen = 20 + size(UDP),
    HdrCSum = flower_tools:ip_csum(<<4:4, 5:4, 0:8, TotLen:16,
				     Id:16, 0:16, 64:8, Proto:8,
				     0:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>),
    IP = <<4:4, 5:4, 0:8, TotLen:16,
	   Id:16, 0:16, 64:8, Proto:8,
	   HdrCSum:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>,
    list_to_binary([Ether, IP, UDP]).
