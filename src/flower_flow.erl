-module(flower_flow).

%% API
-export([flow_extract/3]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_debug.hrl").
-include("flower_packet.hrl").
-include("flower_flow.hrl").

%%%===================================================================
%%% API
%%%===================================================================

flow_extract(TunId, InPort, Packet) ->
    Flow = #flow{tun_id = TunId, in_port = InPort, l2 = Packet},
    decode_packet(Packet, Flow).

decode_packet(<<DlDst:?ETH_ADDR_LEN/bytes, DlSrc:?ETH_ADDR_LEN/bytes, 16#8100:16/integer, PCP:3/integer, _CFI:1/integer, VID:12/integer, EtherType:16/integer, PayLoad/binary>>,
	      Flow) ->
    decode_ethertype(EtherType, PayLoad, Flow#flow{vlan_tci = {PCP, VID}, dl_src = DlSrc, dl_dst = DlDst});

decode_packet(<<DlDst:?ETH_ADDR_LEN/bytes, DlSrc:?ETH_ADDR_LEN/bytes, EtherType:16/integer, PayLoad/binary>>,
	      Flow) ->
    decode_ethertype(flower_packet:eth_type(EtherType), PayLoad, Flow#flow{dl_src = DlSrc, dl_dst = DlDst}).

decode_ethertype(EtherType, <<PCP:3/integer, _CFI:1/integer, VID:12/integer, InnerEtherType:16/integer, PayLoad/binary>>,
		 Flow = #flow{tags = Tags})
  when EtherType == 16#8100;
       EtherType == 16#88a8 ->
    decode_ethertype(InnerEtherType, PayLoad, Flow#flow{tags = Tags ++ [{EtherType, PCP, VID}]});
decode_ethertype(EtherType, PayLoad, Flow) when EtherType >= ?ETH_TYPE_MIN ->
    decode_payload(EtherType, PayLoad, Flow#flow{dl_type = EtherType, l3 = PayLoad});

%% llc_dsap == LLC_DSAP_SNAP
%% llc.llc_ssap == LLC_SSAP_SNAP
%% llc.llc_cntl == LLC_CNTL_SNAP
%% snap.snap_org ==  SNAP_ORG_ETHERNET,
decode_ethertype(_EtherType, <<?LLC_DSAP_SNAP:8/integer, ?LLC_SSAP_SNAP:8/integer, ?LLC_CNTL_SNAP:8/integer, ?SNAP_ORG_ETHERNET, SnapType:16/integer, PayLoad/binary>>, Flow) ->
    decode_payload(flower_packet:eth_type(SnapType), PayLoad, Flow#flow{dl_type = flower_packet:eth_type(SnapType), l3 = PayLoad});

decode_ethertype(_EtherType, PayLoad, Flow) ->
    decode_payload(none, PayLoad, Flow#flow{dl_type = none, l3 = PayLoad}).

decode_payload(ip, <<_IhlVer:8/integer, Tos:8/integer, _TotLen:16/integer,
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
decode_payload(arp, <<1:16/integer, ?ETH_TYPE_IP:16/integer, ?ETH_ADDR_LEN:8/integer, 4:8/integer,
		      Op:16/integer, Sha:?ETH_ADDR_LEN/bytes, Spa:4/bytes, Tha:?ETH_ADDR_LEN/bytes, Tpa:4/bytes, _Pad/binary>> = PayLoad, Flow) ->
    Flow1 = if
		Op =< 16#FF -> Flow#flow{nw_proto = flower_arp:op(Op), l4 = PayLoad};
		true -> Flow#flow{l4 = PayLoad}
	    end,
    if
	Op =:= ?ARP_OP_REQUEST;
	Op =:= ?ARP_OP_REPLY ->
	    Flow1#flow{nw_src = Spa, nw_dst = Tpa, arp_sha = Sha, arp_tha = Tha};
	true -> Flow1
    end;

decode_payload(Type, Pkt, Flow)
  when Type == loop; Type == moprc ->
    Flow#flow{l4 = Pkt};

decode_payload(Type, Pkt, Flow) ->
    ?DEBUG("decode_payload: ~p, ~p, ~p", [Type, Pkt, Flow]),
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
