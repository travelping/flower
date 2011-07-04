-module(flower_flow).

%% API
-export([flow_extract/3]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_flow.hrl").

%%%===================================================================
%%% API
%%%===================================================================

-define(ETH_ADDR_LEN, 6).

-define(ARP_OP_REQUEST, 1).
-define(ARP_OP_REPLY, 2).

-define(FLOW_DL_TYPE_NONE, 16#5ff).
-define(ETH_TYPE_MIN,   16#600).
-define(ETH_TYPE_IP,   16#0800).
-define(ETH_TYPE_ARP,  16#0806).
-define(ETH_TYPE_VLAN, 16#8100).
-define(ETH_TYPE_IPV6, 16#86dd).
-define(ETH_TYPE_LACP, 16#8809).

-define(IP_DSCP_MASK, 16#fc).

-define(IP_DONT_FRAGMENT,  16#4000).
-define(IP_MORE_FRAGMENTS, 16#2000).
-define(IP_FRAG_OFF_MASK,  16#1fff).

-define(LLC_DSAP_SNAP, 16#aa).
-define(LLC_SSAP_SNAP, 16#aa).
-define(LLC_CNTL_SNAP, 3).
-define(SNAP_ORG_ETHERNET, 0,0,0).

%% The match fields for ICMP type and code use the transport source and
%% destination port fields, respectively. */
-define(ICMP_TYPE, tp_src).
-define(ICMP_CODE, tp_dst).

flow_extract(TunId, InPort, Packet) ->
	Flow = #flow{tun_id = TunId, in_port = InPort, l2 = Packet},
	decode_packet(Packet, Flow).

decode_packet(<<DlSrc:?ETH_ADDR_LEN/bytes, DlDst:?ETH_ADDR_LEN/bytes, 16#8100:16/integer, PCP:3/integer, _CFI:1/integer, VID:12/integer, EtherType:16/integer, PayLoad/binary>>,
			  Flow) ->
	decode_ethertype(EtherType, PayLoad, Flow#flow{vlan_tci = {PCP, VID}, dl_src = DlSrc, dl_dst = DlDst});

decode_packet(<<DlSrc:?ETH_ADDR_LEN/bytes, DlDst:?ETH_ADDR_LEN/bytes, EtherType:16/integer, PayLoad/binary>>,
			  Flow) ->
	io:format("Ethertype: ~p~n", [EtherType]),
	decode_ethertype(EtherType, PayLoad, Flow#flow{dl_src = DlSrc, dl_dst = DlDst}).

decode_ethertype(EtherType, PayLoad, Flow) when EtherType >= ?ETH_TYPE_MIN ->
	decode_payload(EtherType, PayLoad, Flow#flow{dl_type = EtherType, l3 = PayLoad});

%% llc_dsap == LLC_DSAP_SNAP
%% llc.llc_ssap == LLC_SSAP_SNAP
%% llc.llc_cntl == LLC_CNTL_SNAP
%% snap.snap_org ==  SNAP_ORG_ETHERNET,
decode_ethertype(_EtherType, <<?LLC_DSAP_SNAP:8/integer, ?LLC_SSAP_SNAP:8/integer, ?LLC_CNTL_SNAP:8/integer, ?SNAP_ORG_ETHERNET, SnapType:16/integer, PayLoad/binary>>, Flow) ->
	decode_payload(SnapType, PayLoad, Flow#flow{dl_type = SnapType, l3 = PayLoad});

decode_ethertype(_EtherType, PayLoad, Flow) ->
	decode_payload(?FLOW_DL_TYPE_NONE, PayLoad, Flow#flow{dl_type = ?FLOW_DL_TYPE_NONE, l3 = PayLoad}).

decode_payload(?ETH_TYPE_IP, <<_IhlVer:8/integer, Tos:8/integer, _TotLen:16/integer,
							  _Id:16/integer, FragOff:16/integer, _Ttl:8/integer, Proto:8/integer,
							  _Csum:16/integer, Src:4/bytes, Dst:4/bytes, PayLoad/binary>>, Flow0) ->

	NwProto = gen_socket:protocol(Proto),
	Flow1 = Flow0#flow{nw_src = Src, nw_dst = Dst,
					   nw_tos = Tos band ?IP_DSCP_MASK,
					   nw_proto = NwProto,
					   l4 = PayLoad},
	if
		(FragOff band (?IP_MORE_FRAGMENTS bor ?IP_FRAG_OFF_MASK)) =:= 0 ->
			decode_ip(NwProto, PayLoad, Flow1);
		true ->
			Flow1
	end;

%% ar_hrd == htons(1)
%% ar_pro == htons(ETH_TYPE_IP)
%% ar_hln == ETH_ADDR_LEN
%% ar_pln == 4
decode_payload(?ETH_TYPE_ARP, <<1:16/integer, ?ETH_TYPE_IP:16/integer, ?ETH_ADDR_LEN:8/integer, 4:8/integer,
								Op:16/integer, Sha:?ETH_ADDR_LEN/bytes, Spa:32/integer, Tha:?ETH_ADDR_LEN/bytes, Tpa:32/integer>>, Flow) ->
	Flow1 = if
				Op =< 16#FF -> Flow#flow{nw_proto = Op};
				true -> Flow
			end,
	if
		Op =:= ?ARP_OP_REQUEST;
		Op =:= ?ARP_OP_REPLY ->
			Flow1#flow{nw_src = Spa, nw_dst = Tpa, arp_sha = Sha, arp_tha = Tha};
		true -> Flow1
	end;

decode_payload(_, _, Flow) ->
	Flow.

decode_ip(tcp, <<Src:16/integer, Dst:16/integer, _Seq:32/integer, _Ack:32/integer,
						  _Ctl:16/integer, _WinSz:16/integer, _Csum:16/integer, _Urg:16/integer,
						  PayLoad/binary>>, Flow) ->
	Flow#flow{tp_src = Src, tp_dst = Dst, l7 = PayLoad};

decode_ip(udp, <<Src:16/integer, Dst:16/integer, _Len:16/integer, _Csum:16/integer, PayLoad/binary>>, Flow) ->
	Flow#flow{tp_src = Src, tp_dst = Dst, l7 = PayLoad};
decode_ip(icmp, <<Type:8/integer, Code:8/integer, _Csum:16/integer, PayLoad/binary>>, Flow) ->
	Flow#flow{?ICMP_TYPE = Type, ?ICMP_CODE = Code, l7 = PayLoad};
decode_ip(_, _, Flow) ->
	Flow.
