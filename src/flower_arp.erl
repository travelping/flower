-module(flower_arp).

%% API
-export([make_arp/7, make_arp/5, op/1]).

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

-spec make_arp(integer(), binary(), binary(), binary(), binary(), binary(), binary()) -> binary().
make_arp(Op, NwDst, NwSrc, Sha, Spa, Tha, Tpa) ->
	Ether = <<NwDst:?ETH_ADDR_LEN/bytes-unit:8, NwSrc:?ETH_ADDR_LEN/bytes-unit:8, (flower_packet:eth_type(arp)):16>>,
	Arp = <<1:16, ?ETH_TYPE_IP:16, ?ETH_ADDR_LEN:8, 4:8,
			Op:16, Sha:?ETH_ADDR_LEN/bytes-unit:8, Spa:4/bytes-unit:8, Tha:?ETH_ADDR_LEN/bytes-unit:8, Tpa:4/bytes-unit:8>>,
	list_to_binary([Ether, Arp]).

-spec make_arp(integer(), binary(), binary(), binary(), binary()) -> binary().
make_arp(Op, Sha, Spa, Tha, Tpa) ->
	make_arp(Op, Tha, Sha, Sha, Spa, Tha, Tpa).
