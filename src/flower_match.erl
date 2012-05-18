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

-module(flower_match).

-export([encode_ofp_matchflow/2, encode_ofp_match/1, decode_ofp_match/1]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include("flower_packet.hrl").
-include("flower_flow.hrl").

-define(OFPFW_IN_PORT,     16#00000001).
-define(OFPFW_DL_VLAN,     16#00000002).
-define(OFPFW_DL_SRC,      16#00000004).
-define(OFPFW_DL_DST,      16#00000008).
-define(OFPFW_DL_TYPE,     16#00000010).
-define(OFPFW_NW_PROTO,    16#00000020).
-define(OFPFW_TP_SRC,      16#00000040).
-define(OFPFW_TP_DST,      16#00000080).
-define(OFPFW_NW_SRC_MASK, 16#00003F00).
-define(OFPFW_NW_DST_MASK, 16#000FC000).
-define(OFPFW_DL_VLAN_PCP, 16#00100000).
-define(OFPFW_NW_TOS,      16#00200000).
-define(OFPFW_ALL,         16#003FFFFF).

-define(OFPFW_VLAN_TCI,    16#00010002).

-define(OFP_VLAN_NONE, 16#ffff).

-type ofp_match() :: #ofp_match{}.
-type flow() :: #flow{}.

-spec ofp_matchflow(atom(), ofp_match(), flow()) -> ofp_match().
ofp_matchflow(in_port, Match, Flow) ->
    ofp_match({in_port, Flow#flow.in_port}, Match);
ofp_matchflow({vlan_tci, none}, Match, #flow{vlan_tci = VLanTag} = _Flow) 
  when VLanTag == undefined ->
    ofp_match({vlan_tci, none}, Match);
ofp_matchflow({vlan_tci, VLanMatch}, Match, #flow{vlan_tci = TCI} = _Flow) ->
    ofp_match({vlan_tci, VLanMatch, TCI}, Match);
ofp_matchflow(dl_src, Match, Flow) ->
    ofp_match({dl_src, Flow#flow.dl_src}, Match);
ofp_matchflow(dl_dst, Match, Flow) ->
    ofp_match({dl_dst, Flow#flow.dl_dst}, Match);
ofp_matchflow(dl_type, Match, Flow) ->
    ofp_match({dl_type, Flow#flow.dl_type}, Match);
ofp_matchflow(nw_proto, Match, Flow) ->
    ofp_match({nw_proto, Flow#flow.nw_proto}, Match);
ofp_matchflow(tp_src, Match, Flow) ->
    ofp_match({tp_src, Flow#flow.tp_src}, Match);
ofp_matchflow(tp_dst, Match, Flow) ->
    ofp_match({tp_dst, Flow#flow.tp_dst}, Match);
ofp_matchflow(nw_tos, Match, Flow) ->
    ofp_match({nw_tos, Flow#flow.nw_tos}, Match);
ofp_matchflow({nw_src_mask, Mask}, Match, Flow) ->
    ofp_match({nw_src_mask, Flow#flow.nw_src, Mask}, Match);
ofp_matchflow({nw_dst_mask, Mask}, Match, Flow) ->
    ofp_match({nw_dst_mask, Flow#flow.nw_dst, Mask}, Match).

-spec encode_ofp_matchflow(list(term()), flow()) -> ofp_match().
encode_ofp_matchflow(MatchSpec, Flow) ->
    lists:foldl(fun(MatchRule, Match) -> ofp_matchflow(MatchRule, Match, Flow) end, #ofp_match{wildcards = ?OFPFW_ALL}, MatchSpec).

ofp_vlan_match(#ofp_match{wildcards = Wildcards} = Match, vid, DlVID)  ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_DL_VLAN), dl_vlan = DlVID};
ofp_vlan_match(#ofp_match{wildcards = Wildcards} = Match, pcp, DlPCP) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_DL_VLAN_PCP), dl_vlan_pcp = DlPCP};
ofp_vlan_match(#ofp_match{wildcards = Wildcards} = Match, both, {DlPCP, DlVID}) ->
    Match#ofp_match{wildcards = Wildcards band (bnot (?OFPFW_DL_VLAN bor ?OFPFW_DL_VLAN_PCP)), dl_vlan = DlVID, dl_vlan_pcp = DlPCP}.

-spec ofp_match(term(), ofp_match()) -> ofp_match().
ofp_match({_, undefined}, Match) ->
    Match;
ofp_match({in_port, InPort}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_IN_PORT), in_port = InPort};
ofp_match({vlan_tci, none}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot (?OFPFW_DL_VLAN bor ?OFPFW_DL_VLAN_PCP)), dl_vlan = ?OFP_VLAN_NONE};
ofp_match({vlan_tci, VLanMatch, TCI}, #ofp_match{} = Match) ->
    ofp_vlan_match(Match, VLanMatch, TCI);
ofp_match({dl_src, DlSrc}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_DL_SRC), dl_src = DlSrc};
ofp_match({dl_dst, DlDst}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_DL_DST), dl_dst = DlDst};
ofp_match({dl_type, DlType}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_DL_TYPE), dl_type = DlType};
ofp_match({nw_proto, NwProto}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_NW_PROTO), nw_proto = NwProto};
ofp_match({tp_src, TpSrc}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_TP_SRC), tp_src = TpSrc};
ofp_match({tp_dst, TpDst}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_TP_DST), tp_dst = TpDst};
ofp_match({nw_tos, NwTos}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = Wildcards band (bnot ?OFPFW_NW_TOS), nw_tos = NwTos};
ofp_match({nw_src_mask, NwSrc, Mask}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = (Wildcards band bnot ?OFPFW_NW_SRC_MASK) bor (((32 - Mask) band 16#3F) bsl 8), nw_src = NwSrc};
ofp_match({nw_dst_mask, NwDst, Mask}, #ofp_match{wildcards = Wildcards} = Match) ->
    Match#ofp_match{wildcards = (Wildcards band bnot ?OFPFW_NW_DST_MASK) bor (((32 - Mask) band 16#3F) bsl 14), nw_dst = NwDst}.

-spec encode_ofp_match(list(term())) -> ofp_match().
encode_ofp_match(MatchSpec) ->
    lists:foldl(fun(MatchRule, Match) -> ofp_match(MatchRule, Match) end, #ofp_match{wildcards = ?OFPFW_ALL}, MatchSpec).

dec_ofp_match(in_port, Match, MatchSpec) ->
    [{in_port, Match#ofp_match.in_port}|MatchSpec];
dec_ofp_match(vlan_tci, #ofp_match{wildcards = Wildcards} = Match, MatchSpec) ->
    Spec = case (Wildcards band ?OFPFW_VLAN_TCI) of
	       ?OFPFW_VLAN_TCI ->
		   {both, {Match#ofp_match.dl_vlan_pcp, Match#ofp_match.dl_vlan}};
	       ?OFPFW_DL_VLAN_PCP ->
		   {pcp, Match#ofp_match.dl_vlan_pcp};
	       ?OFPFW_DL_VLAN ->
		   {vid, Match#ofp_match.dl_vlan};
	       _ ->
		   none
	   end,
    [{vlan_tci, Spec}|MatchSpec];
dec_ofp_match(dl_src, Match, MatchSpec) ->
    [{dl_src, Match#ofp_match.dl_src}|MatchSpec];
dec_ofp_match(dl_dst, Match, MatchSpec) ->
    [{dl_dst, Match#ofp_match.dl_dst}|MatchSpec];
dec_ofp_match(dl_type, Match, MatchSpec) ->
    [{dl_type, Match#ofp_match.dl_type}|MatchSpec];
dec_ofp_match(nw_proto, Match, MatchSpec) ->
    [{nw_proto, Match#ofp_match.nw_proto}|MatchSpec];
dec_ofp_match(tp_src, Match, MatchSpec) ->
    [{tp_src, Match#ofp_match.tp_src}|MatchSpec];
dec_ofp_match(tp_dst, Match, MatchSpec) ->
    [{tp_dst, Match#ofp_match.tp_dst}|MatchSpec];
dec_ofp_match(nw_tos, Match, MatchSpec) ->
    [{nw_tos, Match#ofp_match.nw_tos}|MatchSpec];
dec_ofp_match(nw_src_mask, Match, MatchSpec) ->
    [{nw_src_mask, Match#ofp_match.nw_src}, 32 - (Match#ofp_match.wildcards bsr  8) band 16#3F|MatchSpec];
dec_ofp_match(nw_dst_mask, Match, MatchSpec) ->
    [{nw_dst_mask, Match#ofp_match.nw_dst, 32 - (Match#ofp_match.wildcards bsr 14) band 16#3F}|MatchSpec].

dec_ofp_match_fun({Prop, Bits}, #ofp_match{wildcards = Wildcards} = Match, MatchSpec) ->
    if
	(Wildcards band Bits) =/= Bits ->
	    dec_ofp_match(Prop, Match, MatchSpec);
	true ->
	    MatchSpec
    end.

ofp_match_matches() ->
    [{in_port, ?OFPFW_IN_PORT},
     {vlan_tci, ?OFPFW_VLAN_TCI},
     {dl_src, ?OFPFW_DL_SRC},
     {dl_dst, ?OFPFW_DL_DST},
     {dl_type, ?OFPFW_DL_TYPE},
     {nw_proto, ?OFPFW_NW_PROTO},
     {tp_src, ?OFPFW_TP_SRC},
     {tp_dst, ?OFPFW_TP_DST},
     {nw_src_mask, ?OFPFW_NW_SRC_MASK},
     {nw_dst_mask, ?OFPFW_NW_DST_MASK},
     {nw_tos, ?OFPFW_NW_TOS}].

decode_ofp_match(#ofp_match{} = Match) ->
    lists:foldl(fun(Field, MatchSpec) -> dec_ofp_match_fun(Field, Match, MatchSpec) end, [], ofp_match_matches()).
