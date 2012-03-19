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

-module(flower_arp).

%% API
-export([make_arp/8, make_arp/6, op/1]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_packet.hrl").
-include("flower_flow.hrl").

%%--------------------------------------------------------------------
%% @doc
%% Make an ethernet ARP packet
%%
%% @end
%%--------------------------------------------------------------------

op(?ARP_OP_REQUEST)      -> request;
op(?ARP_OP_REPLY)        -> reply;
op(?ARP_OP_REVREQUEST)   -> revrequest;
op(?ARP_OP_REVREPLY)     -> revreply;
op(X) when is_integer(X) -> X;

op(request)    -> ?ARP_OP_REQUEST;
op(reply)      -> ?ARP_OP_REPLY;
op(revrequest) -> ?ARP_OP_REVREQUEST;
op(revreply)   -> ?ARP_OP_REVREPLY.

-spec ether_hdr(binary(), binary(), vlan_tci(), integer()) -> binary().
ether_hdr(DlDst, DlSrc, undefined, EthType) ->
    <<DlDst:?ETH_ADDR_LEN/bytes-unit:8, DlSrc:?ETH_ADDR_LEN/bytes-unit:8, EthType:16>>;
ether_hdr(DlDst, DlSrc, {PCP, VID}, EthType) ->
    <<DlDst:?ETH_ADDR_LEN/bytes-unit:8, DlSrc:?ETH_ADDR_LEN/bytes-unit:8, 16#8100:16, PCP:3, 0:1, VID:12, EthType:16>>.

-spec make_arp(integer(), vlan_tci(), binary(), binary(), binary(), binary(), binary(), binary()) -> binary().
make_arp(Op, TCI, DlDst, DlSrc, Sha, Spa, Tha, Tpa) ->
    Ether = ether_hdr(DlDst, DlSrc, TCI, flower_packet:eth_type(arp)),
    Arp = <<1:16, ?ETH_TYPE_IP:16, ?ETH_ADDR_LEN:8, 4:8,
	    Op:16, Sha:?ETH_ADDR_LEN/bytes-unit:8, Spa:4/bytes-unit:8, Tha:?ETH_ADDR_LEN/bytes-unit:8, Tpa:4/bytes-unit:8>>,
    list_to_binary([Ether, Arp]).

-spec make_arp(integer(), vlan_tci(), binary(), binary(), binary(), binary()) -> binary().
make_arp(Op, TCI, Sha, Spa, Tha, Tpa) ->
    make_arp(Op, TCI, Tha, Sha, Sha, Spa, Tha, Tpa).
