_init_comp_wordbreaks()
{
    if [[ $PROMPT_COMMAND == *";COMP_WORDBREAKS="* ]]; then
        [[ $PROMPT_COMMAND =~ ^:\ ([^;]+)\; ]]
        [[ ${BASH_REMATCH[1]} != "${COMP_WORDS[0]}" ]] && eval "${PROMPT_COMMAND%%$'\n'*}"
    fi
    if [[ $PROMPT_COMMAND != *";COMP_WORDBREAKS="* ]]; then
        PROMPT_COMMAND=": ${COMP_WORDS[0]};COMP_WORDBREAKS=${COMP_WORDBREAKS@Q};\
        "$'PROMPT_COMMAND=${PROMPT_COMMAND#*$\'\\n\'}\n'$PROMPT_COMMAND
    fi
}
_ip_data()
{
    if [[ $1 == interface ]]; then
        if [[ -n $nsname ]]; then
            sudo ip -n $nsname link show $2 | sed -En 's/^[0-9]+:[ ]+([^@:]+).*/\1/p'
        else
            ip link show $2 | sed -En 's/^[0-9]+:[ ]+([^@:]+).*/\1/p'
        fi
    elif [[ $1 == iproute2_etc ]]; then
        gawk '!/^#/{ print $2 }' /etc/iproute2/$2
    elif [[ $1 == netns ]]; then
        ip netns list | gawk '{ print $1 }'
    fi
}
_ip_cmd3()
{
    if [[ -z ${sub_line%$cur_o} ]]; then
        words=${cmd3_list//|/$'\n'}
        return
    fi
    if [[ $sub_line =~ ^(($cmd3_list)[ ]+) ]]; then
        cmd3=${BASH_REMATCH[2]}
        sub_line=${sub_line/#${BASH_REMATCH[1]}/}
    fi
}
_ip_route_encap()
{
    local etype encap_type='mpls|ip\ id|ip6|rpl|seg6|seg6local\ action|ioam6\ trace\ prealloc\ type'
    sub_line=${sub_line/#!(*mode )encap+( )/} 
    if [[ -z ${sub_line%"$cur_o"} ]]; then
        words=${encap_type//|/$'\n'}
        return
    fi
    [[ $sub_line =~ ^(($encap_type)[ ]+)(.*) ]] 
    sub_line=${BASH_REMATCH[3]}
    etype=${BASH_REMATCH[2]}
    if [[ $etype == mpls ]]; then
        words2=$'LABEL\nttl'
    elif [[ $etype == "ip id" ]]; then
        case $prev in
            id) words="TUNNEL_ID" ;;
            dst) words="REMOTE_IP" ;;
            *) words2=$'src\ntos\nttl' ;;
        esac
        [[ $prev2 == id ]] && words=dst
    elif [[ $etype == "seg6" ]]; then
        case $prev in
            seg6) words=$'mode\nsegs' ;;
            mode) words=$'encap\ninline' ;;
            encap|inline) words="segs" ;;
            segs) words="SEGMENTS" ;;
            *) words2=$'hmac\ncleanup' ;;
        esac
    elif [[ $etype == "seg6local action" ]]; then 
        case $prev in
            action) words=$'End\nEnd.X\nEnd.T\nEnd.DX2\nEnd.DX6\nEnd.DX4\nEnd.DT6
End.DT4\nEnd.DT46\nEnd.B6\nEnd.B6.Encaps\nEnd.BM\nEnd.S\nEnd.AS\nEnd.AM\nEnd.BPF' ;;
            srh) words=$'mode\nsegs' ;;
            mode) words=$'encap\ninline' ;;
            encap|inline) words="segs" ;;
            segs) words="SEGMENTS"; words2=$'hmac\ncleanup' ;;
            *) words2=$'srh\nnh4\nnh6\niif\noif\ntable\nvrftable\nendpoint\ncount\nhmac\ncleanup' ;;
        esac
    elif [[ $etype == "ioam6 trace prealloc type" ]]; then
        case $prev in
            type) words="IOAM6_TRACE_TYPE" ;;
            ns) words="IOAM6_NAMESPACE" ;;
            size) words="IOAM6_TRACE_SIZE" ;;
        esac
        case $prev2 in
            type) words="ns" ;;
            ns) words="size" ;;
        esac
    fi
}
_ip_route_info_spec()
{
    opts=$'mtu\nadvmss\nas to\nrtt\nrttvar\nreordering\nwindow\ncwnd\ninitcwnd
ssthresh\nrealms\nsrc\nrto_min\nhoplimit\ninitrwnd\nfeatures\nquickack\ncongctl\npref
expires\nfastopen_no_cookie'
    local family='inet|inet6|mpls|bridge|link'
    local address=$( ip route | sed -En 's/.* via ([0-9.]*).*/\1/p' )
    case $prev in
        via) words=${family//|/$'\n'}$'\n'$address ;;
        dev) words=$( _ip_data interface up ) ;;
        weight) words="NUMBER" ;;
        nhid) words="ID" ;;
        pref) words=$'low\nmedium\nhigh' ;;
        *) _ip_route_encap
            if [[ -z $words ]]; then
                words=$'encap\nvia\ndev\nweight\nonlink\npervasive\nnhid\nnexthop'
                words+=$'\n'$opts
                words+=$'\n'$words2
            fi
    esac
    [[ $prev2 == via && $prev == @($family) ]] && words=$address
}
_ip_route() 
{
    cmd3_list='list|flush|save|restore|showdump|get|add|del|change|append|replace|help'
    _ip_cmd3; [[ -n $words ]] && return
    local type="unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat"
    local rtproto=$'kernel\nboot\nstatic\n'$( _ip_data iproute2_etc rt_protos )
    local scope=$'host\nlink\nglobal\nNUMBER'
    [[ $prev == proto ]] && { words=$rtproto; return ;}
    [[ $prev == scope ]] && { words=$scope; return ;}
    [[ $prev == @(table|vrftable) ]] && { words=$'local\nmain\ndefault\nall\nNUMBER'; return ;}
    case $cmd3 in
        list | flush | save) 
            case $prev in
                root | match | exact) words="PREFIX" ;;
                vrf) words="NAME" ;;
                type) words=${type//|/$'\n'} ;;
                *) local selector=$'root\nmatch\nexact\ntable\nvrf\nproto\ntype\nscope' 
                    words=$selector ;;
            esac
            ;;
        get)
            if [[ -z ${sub_line%$cur_o} ]]; then
                words=$'fibmatch\nADDRESS'
                return
            elif [[ ${sub_line/%+( )/} == fibmatch ]]; then
                words="ADDRESS"
                return
            fi
            opts='from ADDRESS iif STRING|oif|mark|tos|vrf|ipproto|sport|dport'
            case $prev in
                from) words="ADDRESS" ;;
                oif | iif) words="STRING" ;;
                mark) words="MARK" ;;
                tos) words="TOS" ;;
                vrf) words="NAME" ;;
                ipproto) words="PROTOCOL" ;;
                sport | dport) words="NUMBER" ;;
                *) words=${opts//|/$'\n'} ;;
            esac
            ;;
        add | del | change | append | replace)
            local prefix=$( ip route | gawk '{ print $1 }' )
            if [[ -z ${sub_line%$cur_o} ]]; then
                words=${type//|/$'\n'}$'\n'$prefix
                return
            elif [[ ${sub_line/%+( )$cur_o/} == @($type) ]]; then
                words=$prefix
                return
            fi
            [[ $sub_line =~ ^((($type)[ ]+$colon|$colon)[ ]+)(.*) ]]
            sub_line=${BASH_REMATCH[6]}
            local node_spec='tos|table|proto|scope|metric|ttl-propagate'
            [[ $sub_line =~ ^((($node_spec)[ ]+$colon)[ ]+)*(.*) ]]
            sub_line=${BASH_REMATCH[5]}
            if [[ -z ${sub_line%$cur_o} ]]; then
                words=${node_spec//|/$'\n'}$'\nencap\nvia\ndev\nweight\nonlink\npervasive\nnhid'
                return
            fi
            case ${sub_line/%+( )/} in
                tos) [[ $prev == tos ]] && words=TOS ;;
                metric) [[ $prev == metric ]] && words=METRIC ;;
                ttl-propagate+( )*([[:alnum:]])) [[ $prev == ttl-propagate ]] && words=$'enabled\ndisabled' ;;
                *) _ip_route_info_spec ;;
            esac
    esac
}
_ip_link_type()
{
    if ! $type_exist; then
        words=$opts
    elif [[ $prev == "type" ]]; then
        words=$type
    else
        words=$( ip link help $type_value |
            sed -En '1,/^$/{ 1{s/^.*'"$type_value"'//}; s/[{<][^}>]*[}>]//g; s/([][a-z|_-]{2,})|./\1\n/g; p}' |
            sed -E 's/(.*)\[no](.*)/\1\2\n\1no\2/' |
            sed -E 's/(.*)\[i\|o](.*)/\1\2\n\1i\2\n\1o\2/; s/[][|]/\n/g' )
        case $type_value in
            bareudp) [[ $prev == ethertype ]] && words=$'ipv4\nipv6\nmpls_uc' ;;
            bond)
                case $prev in
                    mode) words=$'balance-rr\nactive-backup\nbalance-xor\nbroadcast\n802.3ad\nbalance-tlb\nbalance-alb' ;;
                    arp_validate) words=$'none\nactive\nbackup\nall\nfilter\nfilter_active\nfilter_backup' ;;
                    arp_all_targets) words=$'any\nall' ;;
                    primary_reselect) words=$'always\nbetter\nfailure' ;;
                    fail_over_mac) words=$'none\nactive\nfollow' ;;
                    xmit_hash_policy) words=$'layer2\nlayer2+3\nlayer3+4\nencap2+3\nencap3+4\nvlan+srcmac' ;;
                    lacp_active) words=$'on\noff' ;;
                    lacp_rate) words=$'slow\nfast' ;;
                    ad_select) words=$'stable\nbandwidth\ncount' ;;
                esac ;;
            bridge) [[ $prev == vlan_protocol ]] && words=$'802.1Q\n802.1ad' ;;
            bridge_slave) [[ $prev == @(guard|hairpin|fastleave|root_block|learning|\
flood|proxy_arp|proxy_arp_wifi|mcast_fast_leave|mcast_flood|mcast_to_unicast|\
neigh_suppress|vlan_tunnel isolated) ]] && words=$'on\noff' ;;
            erspan|gre|gretap|ip6erspan|ip6gre|ip6gretap)
                case $prev in
                    encap) words=$'fou\ngue\nnone' ;;
                    erspan_dir) words=$'ingress\negress' ;;
                esac
                if [[ $type_value == ip6gretap ]]; then
                    words=${words//$'\ninherit\n'/$'\n'}
                    words=${words//$'\nversion\n'/$'\n'}
                    words=${words//$'\nhwid'/$'\n'}
                fi ;;
            ip6tnl|ipip|sit)
                case $prev in
                    encap) words=$'fou\ngue\nnone' ;;
                    mode) 
                        case $type_value in
                            ip6tnl) words=$'ip6ip6\nipip6\nany' ;;
                            ipip) words=$'ipip\nmplsip\nany' ;;
                            sit) words=$'ip6ip\nipip\nmplsip\nany' ;;
                        esac
                esac ;;
            geneve) [[ $prev == df ]] && words=$'unset\nset\ninherit' ;;
            ipoib) [[ $prev == mode ]] && words=$'datagram\nconnected' ;;
            ipvlan|ipvtab) 
                [[ $prev == mode ]] && words=$'l3\nl3s\nl2' 
                [[ $prev2 == mode ]] && words=$'bridge\nprivate\nvepa' ;;
            macsec)
                case $prev in
                    cipher) words=$'default\ngcm-aes-128\ngcm-aes-256' ;;
                    encrypt|send_sci|end_station|scb|protect|replay) words=$'on\noff' ;;
                    validate) words=$'strict\ncheck\ndisabled' ;;
                    offload) words=$'mac\nphy\noff' ;;
                esac ;;
            macvlan|macvtap)
                [[ $prev == $type_value ]] && words="mode"
                [[ $prev == mode ]] && words=$'private\nvepa\nbridge\npassthru\nsource'
                [[ $prev == flag ]] &&  words=$'null\nnopromisc\nnodst'
                [[ ${COMP_WORDS[type_index + 2]} == source ]] && words+=$'\nmacaddr'
                [[ $sub_line == *macaddr* ]] && words=$'add\ndel\nset\nflush\nbcqueuelen' ;;
            rmnet) words="mux_id" ;;
            veth | vxcan) words="peer name" ;;
            vlan)
                case $prev in
                    protocol) words=$'802.1Q\n802.1ad' ;;
                    reorder_hdr|gvrp|mvrp|loose_binding|bridge_binding) words=$'on\noff' ;;
                esac ;;
            vrf) words="table" ;;
            vxlan) 
                words+=$'\ngroup\nremote'
                [[ $prev == df ]] && words=$'unset\nset\ninherit' ;;
        esac
    fi
}
_ip_link_add()
{
    case $prev in
        add) words=$'link\nparentdev\nname\nNAME' ;;
        link) words="DEV" ;;
        parentdev) words="NAME" ;;
    esac
    [[ ${sub_line/%+( )/} == @(link|parentdev)+( )+([^ ]) ]] && words="name"
    [[ -n $words ]] && return
    opts=$'txqueuelen\naddress\nbroadcast\nmtu\nindex\nnumtxqueues\nnumrxqueues\ntype'
    _ip_link_type
}
_ip_link_set()
{
    case $prev in
        set) words=$( _ip_data interface )$'\ndev\ngroup' ;;
        dev) words=$( _ip_data interface ) ;;
        group) words="DEVGROUP" ;;
    esac
    [[ -n $words ]] && return
    opts=$'up\ndown\ntype\narp\ndynamic\nmulticast\nallmulticast\npromisc\ntrailers
carrier\ntxqueuelen\nname\naddress\nbroadcast\nmtu\nnetns\nlink-netns\nlink-netnsid
alias\nvf\nxdp\nxdpgeneric\nxdpdrv\nxdpoffload\nmaster\nvrf\nnomaster\naddrgenmode
protodown\nprotodown_reason\ngso_max_size\ngso_max_segs'
    if [[ $prev == @(arp|dynamic|multicast|allmulticast|promisc|trailers|carrier\
spoofchk|query_rss|trust|protodown) || $prev2 == protodown_reason ]]; then
        words=$'on\noff'
    elif [[ $prev == netns ]]; then
        words=$( _ip_data netns )$'\nPID'
    elif [[ $prev == @(xdp|xdpgeneric|xdpdrv|xdpoffload) ]]; then
        words=$'off\nobject\npinned'
    elif [[ $prev == object ]]; then
        words=$'FILE\nsection\nverbose'
    elif [[ $sub_line == *" object "* ]] && ! $type_exist; then
        words=$'section\nverbose\n'$opts
    elif [[ $prev == pinned ]]; then
        words="FILE"
    elif [[ $prev == addrgenmode ]]; then
        words=$'eui64\nnone\nstable_secret\nrandom'
    elif [[ $prev == vf ]]; then
        words="NUM"
    elif [[ $prev2 == vf ]]; then
        words=$'mac\nvlan\nrate\nmax_tx_rate\nmin_tx_rate\nspoofchk\nquery_rss\nstate\ntrust\nnode_guid\nport_guid'
    elif [[ $prev == proto ]]; then
        words=$'802.1Q\n802.1ad'
    elif [[ $sub_line == *" vf "*" vlan "* ]] && ! $type_exist; then
        words=$'qos\nproto\n'$opts
    elif [[ $sub_line == *" vf "*" state "$cur ]]; then
        words=$'auto\nenable\ndisable'
    fi
    [[ -n $words ]] && return
    _ip_link_type
}
_ip_link()
{
    cmd3_list='add|delete|set|show|xstats|afstats|property|help'
    _ip_cmd3; [[ -n $words ]] && return
    local type_exist=false type_value="" type_index
    for (( i = COMP_CWORD; i > 2; i-- )); do
        if [[ ${COMP_WORDS[i]} == "type" ]]; then
            type_exist=true
            type_value=${COMP_WORDS[i+1]}
            type_index=$(( i + 1 ))
        fi
    done
    case $cmd3 in
        add)
            _ip_link_add ;;
        set)
            _ip_link_set ;;
        delete)
            case $prev in
                $cmd3) words=$( _ip_data interface )$'\ndev\ngroup' ;;
                dev) words=$( _ip_data interface ) ;;
                group) words="DEVGROUP" ;;
                type) words=$type ;;
                *) opts="type"
                    _ip_link_type
            esac ;;
        show)
            case $prev in
                group) words=$( _ip_data iproute2_etc group ) ;;
                master) words=$( _ip_data interface ) ;;
                type) words=$type ;;
                *) 
                    words=$( _ip_data interface )$'\ngroup'
                    words+=$'\nup\nmaster\nvrf\ntype' ;;
            esac ;;
        xstats) 
            opts="type"
            _ip_link_type ;;
        afstats)
            case $prev in
                $cmd3) words="dev" ;;
                dev) words=$( _ip_data interface ) ;;
            esac ;;
        property) 
            case $prev in
                $cmd3) words=$'add\ndel' ;;
                @(add|del)) words="dev" ;;
                dev) words=$( _ip_data interface ) ;;
                *) [[ $prev2 == dev ]] && words="altname" ;;
            esac ;;
        help) [[ $prev == $cmd3 ]] && words=$type ;;
    esac
}
_ip_address()
{
    cmd3_list='add|change|replace|del|save|flush|show|showdump|restore|help'
    _ip_cmd3; [[ -n $words ]] && return
    local scope=$'host\nlink\nglobal\n'$( _ip_data iproute2_etc rt_scopes )
    case $cmd3 in
        add|change|replace|del)
            [[ $sub_line != *" dev "* ]] &&
                words=$'PREFIX\nADDR peer PREFIX\nbroadcast\nanycast\nlabel\nscope\ndev'
            [[ $prev == scope ]] && words=$scope
            [[ $prev == dev ]] && words=$( _ip_data interface )
            [[ $prev == @(valid_lft|preferred_lft) ]] && words=$'forever\nSECONDS'
            if [[ -z $words ]]; then
                if [[ $cmd3 == del ]]; then
                    words="mngtmpaddr"
                else
                    words=$'valid_lft\npreferred_lft\nhome\nnodad\nmngtmpaddr\nnoprefixroute\nautojoin'
                fi
            fi ;;
        save|flush|show) 
            [[ $prev == dev ]] && words=$( _ip_data interface )
            [[ $prev == scope ]] && words=$scope
            [[ $prev == type ]] && words=$type
            if [[ -z $words ]]; then 
                if [[ $cmd3 == show ]]; then
                    words=$'dev\nscope\nmaster\ntype\nto\nlabel\nup\nvrf'
                else
                    words=$'dev\nscope\nto\nlabel\nup'
                fi
                words+=$'\npermanent\ndynamic\nsecondary\nprimary\ntentative
deprecated\ndadfailed\ntemporary\n-tentative\n-deprecated\n-dadfailed\nhome\nnodad
mngtmpaddr\nnoprefixroute\nautojoin'
            fi ;;
    esac
}
_ip_addrlabel()
{
    cmd3_list='add|del|list|flush|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $prev == @(add|del) ]] && words="prefix"
    [[ $sub_line == "prefix "* ]] && words=$'dev\nlabel'
    [[ $prev == dev ]] && words=$( _ip_data interface )
}
_ip_fou()
{
    cmd3_list='add|del|show|help'
    _ip_cmd3; [[ -n $words ]] && return
    if [[ $prev == @(add|del) ]]; then
        words="port"
    elif [[ $prev == port ]]; then
        words="PORT"
    elif [[ $cmd3 == @(add|del) ]]; then
        if [[ $cmd3 == add && $prev2 == port ]]; then
            words=$'ipproto\ngue'
        else
            words=$'local\npeer\npeer_port\ndev'
        fi
    fi
}
_ip_ioam()
{
    cmd3_list='namespace|schema|help'
    _ip_cmd3; [[ -n $words ]] && return
    case $prev in
        namespace) words=$'show\nadd\ndel\nset' ;;
        schema) words=$'show\nadd\ndel' ;;
    esac
    [[ $cmd3 == namespace && $sub_line == "add "* ]] && words=$'data\nwide'
    [[ $prev2 == set ]] && words="schema"
    [[ $cmd3 == namespace && $prev == schema ]] && words=$'ID\nnone'
}
_ip_ila()
{
    cmd3_list='add|del|list|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $prev == @(add|del) ]] && words="loc_match"
    if [[ $cmd3 == add ]]; then
        [[ $prev2 == loc_match ]] && words="loc"
        [[ $sub_line == *" loc "* ]] && words=$'dev\ncsum-mode\nident-type'
        case $prev in
            csum-mode) words=$'adj-transport\nneutral-map\nneutral-map-auto\nno-action' ;;
            ident-type) words=$'luid\nuse-format' ;;
        esac
    fi
    [[ $cmd3 == del && $sub_line == "loc_match "* ]] && words=$'loc\ndev'
}
_ip_l2tp()
{
    cmd3_list='add|del|show|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $prev == @(add|del|show) ]] && words=$'tunnel\nsession'
    if [[ $cmd3 == add && ${sub_line%% *} == tunnel ]]; then
        case $prev in
            remote|local) words="ADDR" ;;
            encap) words=$'ip\nudp' ;;
            udp_csum|udp6_csum_tx|udp6_csum_rx) words=$'on\noff' ;;
        esac
        [[ -z $words ]] && words=$'remote\nlocal\ntunnel_id\npeer_tunnel_id\nencap
udp_sport\nudp_dport\nudp_csum\nudp6_csum_tx\nudp6_csum_rx'
    elif [[ $cmd3 == add && ${sub_line%% *} == session ]]; then
        case $prev in
            cookie|peer_cookie) words="HEXSTR" ;;
            seq) words=$'none\nsend\nrecv\nboth' ;;
            l2spec_type) words=$'none\ndefault' ;;
        esac
        [[ -z $words ]] && words=$'name\ntunnel_id\nsession_id\npeer_session_id
cookie\npeer_cookie\nseq\nl2spec_type'
    elif [[ $cmd3 == @(del|show) && ${sub_line%% *} == tunnel ]]; then
        words="tunnel_id"
    elif [[ $cmd3 == @(del|show) && ${sub_line%% *} == session ]]; then
        words=$'tunnel_id\nsession_id'
    fi
}
_ip_macsec()
{
    cmd3_list='add|set|del|show|offload|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $prev == @(${cmd3_list/help/}) ]] && words="DEV"
    if [[ $cmd3 == @(add|set|del) ]]; then
        [[ $prev2 == @(add|set|del) ]] && words=$'tx\nrx'
        [[ $prev == tx ]] && words="sa"
        [[ $sub_line == *" tx sa "* ]] && words=$'pn\non\noff\nkey'
        if [[ $sub_line == *" rx "* ]]; then
            words=$'sci\nport\nsa\npn\non\noff\nkey'
            [[ $prev2 == port ]] && words="address"
        fi
    else
        [[ $prev2 == offload ]] && words=$'off\nphy\nmac'
    fi
}
_ip_maddress()
{
    words=$'add\ndel\nshow\nhelp\nMULTIADDR'
    [[ $prev == show || $prev2 == @(maddress|maddr|add|del) ]] && words="dev"
    [[ $prev == @(add|del) ]] && words="MULTIADDR"
    [[ $prev == dev ]] && words=$( _ip_data interface )
}
_ip_monitor()
{
    words=$'all\naddress\nlink\nmroute\nneigh\nnetconf\nnexthop\nnsid\nprefix\nroute
rule\nfile\nlabel\nall-nsid\ndev\nhelp'
    [[ $prev == dev ]] && words=$( _ip_data interface up )
}
_ip_mptcp()
{
    cmd3_list='endpoint|limits|monitor|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $cmd3 == endpoint && $sub_line == "add "* ]] &&
        words=$'dev\nid\nport\nsignal\nsubflow\nbackup'
    [[ $prev == endpoint ]] && words=$'add\ndelete\nshow\nflush'
    [[ $prev == limits ]] && words=$'set\nshow'
    [[ $prev == add ]] && words="ADDRESS"
    [[ $cmd3 == endpoint && $prev == @(delete|show) ]] && words="id"
    [[ $cmd3 == limits && $sub_line == "set "* ]] && words=$'subflows\nadd_addr_accepted'
}
_ip_mroute()
{
    words=$'to\nfrom\niif\ntable\nPREFIX'
    [[ $prev == $cmd2 ]] && words=$'show\nhelp'
    [[ $prev == table ]] && words=$'local\nmain\ndefault\nall\nNUMBER'
}
_ip_mrule()
{
    [[ $prev != @(flush|save|restore) ]] &&
        words=$'add\ndel\nflush\nsave\nrestore\nlist\nhelp'
    [[ $comp_line2 == *" "@(add|del|list)" "* ]] &&
        words=$'not\nfrom\nto\ntos\nfwmark\niif\noif\npref\nl3mdev\nuidrange\nipproto\nsport\ndport'
    [[ $comp_line2 == *" "@(add|del)" "* ]] &&
        words+=$'\ntable\nprotocol\nnat\nrealms\ngoto\nsuppress_prefixlength\nsuppress_ifgroup'
    [[ $prev == table ]] && words=$'local\nmain\ndefault\nNUMBER'
    [[ $prev == @(iif|oif) ]] && words=$( _ip_data interface up )

}
_ip_neighbor()
{
    cmd3_list='add|del|change|replace|show|flush|get|help'
    _ip_cmd3; [[ -n $words ]] && return
    case $cmd3 in
        add | del | change | replace)
            if [[ $sub_line == *" proxy "* ]]; then
                words=$'dev\nrouter\nextern_learn\nprotocol'
            else
                words=$'lladdr\nnud\nproxy' 
            fi 
            [[ $prev == $cmd3 ]] && words="ADDR" ;;
        show | flush)
            words=$'proxy\nto\ndev\nnud\nvrf' ;;
        get) 
            [[ $prev == get ]] && words=$'ADDR\nproxy' || words="dev" ;;
    esac
    [[ $prev == nud ]] && words=$'delay\nfailed\nincomplete\nnoarp\nnone\npermanent\nprobe\nreachable\nstale'
    [[ $prev == dev ]] && words=$( _ip_data interface )
    [[ $cmd3 == @(add|del|change|replace|get) && $prev == proxy ]] && words="ADDR"
}
_ip_netconf()
{
    [[ $prev == netconf ]] && words=$'show\nhelp'
    [[ $prev == show ]] && words="dev"
    [[ $prev == dev ]] && words=$( _ip_data interface )
}
_ip_netns()
{
    cmd3_list=$'list|add|attach|set|delete|identify|pids|exec|monitor|list-id|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $prev == @(set|delete|pids|exec) ]] && words=$( _ip_data netns )
    [[ $prev == @(add|attach) ]] && words="NAME"
    [[ $prev == identify || $prev2 == attach ]] && words="PID"
    [[ $prev2 == set ]] && words=$'auto\nPOSITIVE-INT'
    [[ $cmd3 == list-id ]] && words=$'target-nsid\nnsid'
}
_ip_nexthop()
{
    cmd3_list='list|flush|add|replace|get|del|bucket|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $cmd3 == @(list|flush) ]] &&
        words=$'protocol\nid\ndev\nvrf\nmaster\ngroups\nfdb'
    [[ $prev == @(add|replace|get|del) ]] && words="id"
    [[ $cmd3 == @(add|replace) && $sub_line == "id "* ]] &&
        words=$'blackhole\nvia\ndev\nonlink\nencap\ngroup\nprotocol'
    [[ $cmd3 == @(add|replace) && $sub_line == *" group "* ]] && 
        words=$'fdb\ntype\nprotocol'
    [[ $prev == type ]] && words=$'mpath\nresilient'
    [[ $prev2 == type && $prev == resilient ]] &&
        words=$'buckets\nidle_timer\nunbalanced_timer'
    [[ $prev == bucket ]] && words=$'list\nget'
    [[ $prev2 == bucket && $prev == list ]] && 
        words=$'id\ndev\nvrf\nmaster\ngroups\nfdb\nnhid'
    [[ $prev2 == bucket && $prev == get ]] && words="id"
    [[ $cmd3 == bucket && $prev2 == id ]] && words="index"
    [[ $prev == encap ]] && words="mpls"
    [[ $prev2 == encap ]] && words="MPLSLABEL"
    [[ $prev == @(dev|master) ]] && words=$( _ip_data interface )
}
_ip_ntable()
{
    cmd3_list=$'change|show|help'
    _ip_cmd3; [[ -n $words ]] && return
    [[ $cmd3 == show ]] && words=$'dev\nname'
    [[ $cmd3 == change ]] && words=$'dev\nthresh1\nthresh2\nthresh3\ngc_int
base_reachable\nretrans\ngc_stale\ndelay_probe\nqueue\napp_probes\nucast_probes
mcast_probes\nanycast_delay\nproxy_delay\nproxy_queue\nlocktime'
    [[ $prev == change ]] && words="name"
    [[ $prev == dev ]] && words=$( _ip_data interface )
}
_ip_sr()
{
    [[ $prev == sr ]] && words=$'hmac\ntunsrc\nhelp'
    [[ $prev == @(hmac|tunsrc) ]] && words=$'show\nset'
    [[ $prev2 == hmac && $prev == set ]] && words="KEYID"
    [[ $prev2 == tunsrc && $prev == set ]] && words="ADDRESS"
    [[ ${COMP_WORDS[COMP_CWORD - 3]} == hmac && $prev2 == set ]] && words=$'sha1\nsha256'
}
_ip_tap()
{
    if [[ -z ${sub_line%$cur_o} ]]; then
        words=$'add\ndel\nshow\nlist\nlst\nhelp'
    else
        words=$'dev\nmode\nuser\ngroup\none_queue\npi\nvnet_hdr\nmulti_queue\nname'
    fi
    [[ $prev == mode ]] && words=$'tun\ntap'
    [[ $prev == dev ]] && words="PHYS_DEV"
}
_ip_tcpmetrics()
{
    if [[ -z ${sub_line%$cur_o} ]]; then
        words=$'show\nflush\ndelete\nhelp'
    else
        words=$'address\nall'
    fi
}
_ip_token()
{
    words=$'list\nset\ndel\nget\nTOKEN\ndev\nhelp'
    [[ $prev == dev ]] && words=$( _ip_data interface )
}
_ip_tunnel()
{
    if [[ -z ${sub_line%$cur_o} ]]; then
        words=$'add\nchange\ndel\nshow\nprl\n6rd\nhelp'
    else
        words=$'NAME\nmode\nremote\nlocal\nseq\niseq\noseq\nkey\nikey\nokey\ncsum
icsum\nocsum\nprl-default\nprl-nodefault\nprl-delete\n6rd-prefix\n6rd-relay_prefix
6rd-reset\nttl\ntos\npmtudisc\nnopmtudisc\ndev'  
    fi
    case $prev in
        mode) words=$'gre\nipip\nisatap\nsit\nvti' ;;
        remote|local|prl-default|prl-nodefault|prl-delete|6rd-prefix|6rd-relay_prefix)
            words=$'IP_ADDRESS\nany' ;;
        key|ikey|okey) words=$'DOTTED_QUAD\nNUMBER' ;;
        tos) words=$'STRING\n00..ff\ninherit\ninherit/STRING\ninherit/00..ff' ;;
        ttl) words=$'1..255\ninherit' ;;
        dev) words="PHYS_DEV" ;;
    esac
}
_ip_vrf()
{
    [[ -z ${sub_line%$cur_o} ]] && words=$'show\nexec\nidentify\npids\nhelp'
    [[ $prev == @(show|exec|pids) ]] && words="NAME"
    [[ $prev == identify ]] && words="PID"
}
_ip_xfrm()
{
    cmd3_list=$'state|policy|monitor|help'
    _ip_cmd3; [[ -n $words ]] && return

    if [[ $cmd3 == state ]]; then
        if [[ $prev == $cmd3 ]]; then
            words=$'add\nupdate\nallocspi\ndelete\nget\ndeleteall\nlist\nflush\ncount'
        else
            local cmd4=${sub_line%% *} ID=$'src\ndst\nproto\nspi'
            case $cmd4 in
                add | update) words=$ID$'\nenc\nauth\nauth-trunc\naead\ncomp\nmode\mark
mask\nreqid\nseq\nreplay-window\nreplay-seq\nreplay-oseq\nreplay-seq-hi\nreplay-oseq-hi
flag\nsel\nlimit\nencap\ncoa\nctx\nextra-flag\noffload\noutput-mark\nif_id\ntfcpad
src\ndst\ndev\nproto\nsport\ndport\ntype\ncode\nkey' ;;
                allocspi) words=$ID$'\nmode\nmark\nmask\nreqid\nseq\nmin SPI max SPI' ;;
                delete | get) words=$ID$'\nmark\nmask' ;;
                deleteall) words=$ID$'\nmode\nreqid\nflag' ;;
                list) words=$ID$'nokeys\nmode\nreqid\nflag' ;;
                flush) words="proto" ;;
            esac
            case $prev in
                mode) words=$'transport\ntunnel\nbeet\nro\nin_trigger' ;;
                flag) words=$'noecn\ndecap-dscp\nnopmtudisc\nwildrecv\nicmp\naf-unspec\nalign4\nesn' ;;
                limit) words=$'time-soft\ntime-hard\ntime-use-soft\ntime-use-hard
byte-soft\nbyte-hard\npacket-soft\npacket-hard' ;;
                encap) words=$'espinudp\nespinudp-nonike\nespintcp' ;;
                extra-flag) words=$'dont-encap-dscp\noseq-may-wrap' ;;
                proto) words=$'esp\nah\ncomp\nroute2\nhao' ;;
                offload) words=$'dev\ndir' ;;
                dir) words=$'in\nout' ;;
            esac
            [[ $prev2 == dev && ${COMP_WORDS[COMP_CWORD - 3]} == offload ]] && words="dir"
            [[ $cmd4 == @(add|update) && $sub_line == *" sel "* && $prev == proto ]] &&
                words=$'tcp\nudp\nsctp\ndccp\nicmp\nipv6-icmp\nmobility-header\ngre'
        fi
    elif [[ $cmd3 == policy ]]; then
        if [[ $prev == $cmd3 ]]; then
            words=$'add\nupdate\ndelete\nget\ndeleteall\nlist\nflush\ncount\nset'
        else
            local cmd4=${sub_line%% *} ID=$'src\ndst\nproto\nspi'
            case $cmd4 in
                add | update) words=$'src\ndst\ndev\nproto\nsport\ndport\ntype\ncode\nkey
dir\nctx\nmark\nmask\nindex\nptype\naction\npriority\nflag\nif_id\nlimit\ntmpl\nspi
mode\nreqid\nlevel' ;;
                delete | get) words=$'src\ndst\ndev\nproto\nsport\ndport\ntype\ncode\nkey
index\ndir\nctx\nmark\nmask\nptype\nif_id' ;;
                deleteall | list) words=$'nosock\nsrc\ndst\ndev\nproto\nsport\ndport\ntype
code\nkey\ndir\nindex\nptype\naction\npriority\nflag' ;;
                flush) words="ptype" ;;
                set) words=$'hthresh4\nhthresh6' ;;
            esac
            case $prev in
                mode) words=$'transport\ntunnel\nbeet\nro\nin_trigger' ;;
                level) words=$'required\nuse' ;;
                ptype) words=$'main\nsub' ;;
                action) words=$'allow\nblock' ;;
                flag) words=$'localok\nicmp' ;;
                limit) words=$'time-soft\ntime-hard\ntime-use-soft\ntime-use-hard
byte-soft\nbyte-hard\npacket-soft\npacket-hard' ;;
                proto) words=$'tcp\nudp\nsctp\ndccp\nicmp\nipv6-icmp\nmobility-header\ngre' ;;
                dir) words=$'in\nout\nfwd' ;;
            esac
            [[ $cmd4 == @(add|update) && $sub_line == *" tmpl "* && $prev == proto ]] &&
                words=$'esp\nah\ncomp\nroute2\nhao'
        fi
    elif [[ $cmd3 == monitor ]]; then
        words=$'nokeys\nall-nsid\nall\nacquire\nexpire\naevent\npolicy\nreport\nhelp'
    fi
}
_ip()
{
    _init_comp_wordbreaks
    COMP_WORDBREAKS=${COMP_WORDBREAKS//:/}

    local extglob_reset=$(shopt -p extglob)
    trap "$extglob_reset" RETURN
    shopt -s extglob

    local nsname=$( _ip_data netns ) nsname_all IFS=$' \t\n' i

    if [[ $COMP_LINE =~ ^(ip[ ]+(-n|-netns)[ ]+([[:alnum:]_-]+)[ ]+)(.*) ]]; then
        nsname=${BASH_REMATCH[3]}
        COMP_LINE=${BASH_REMATCH[4]}
        let COMP_POINT-="COMP_POINT - ${#COMP_LINE}"
        COMP_LINE="ip $COMP_LINE"
        let COMP_POINT+=3
        for (( i = 0; i < ${#COMP_WORDS[@]}; i++ )); do
            if [[ ${COMP_WORDS[i]} == @(-n|-netns) ]]; then
                unset -v 'COMP_WORDS[i]' 'COMP_WORDS[i+1]'
                COMP_WORDS=( "ip" "${COMP_WORDS[@]}" )
                let COMP_CWORD-=i+1
                break
            fi
            unset -v 'COMP_WORDS[i]'
        done
        _ip_main "$@"

    elif [[ $COMP_LINE =~ ^(ip[ ]+((-a|-all)[ ]+)?netns[ ]+exec[ ]+)(.*) ]]; then
        [[ -n ${BASH_REMATCH[3]} ]] && nsname_all=true || nsname_all=false
        local cmd func arr tmp_line=${BASH_REMATCH[4]} 
        if $nsname_all; then nsname=""
        else
            ! [[ $tmp_line =~ ^(([[:alnum:]_-]+)[ ]+)(.*) ]] && { _ip_main "$@"; return ;}
            nsname=${BASH_REMATCH[2]}
            tmp_line=${BASH_REMATCH[3]}
        fi
        if [[ -z ${tmp_line%${COMP_WORDS[COMP_CWORD]}} ]]; then
            local words=$(compgen -c)
            COMPREPLY=($(compgen -W "$words" -- "${COMP_WORDS[COMP_CWORD]}"))
            return
        fi
        cmd=${tmp_line%% *}
        if ! complete -p "$cmd" &> /dev/null; then
            _completion_loader "$cmd" &> /dev/null
        fi
        if arr=($(complete -p "$cmd" 2> /dev/null)); then
            for (( i = 1; i < ${#arr[@]}; i++ )); do 
                [[ ${arr[i]} == -F ]] && { func=${arr[i + 1]}; break ;}
            done
            if [[ -n $func ]]; then 
                COMP_LINE=$tmp_line
                let COMP_POINT-="COMP_POINT - ${#COMP_LINE}"
                for (( i = 0; i < $COMP_CWORD; i++ )); do
                    if [[ $i -ne 0 && ${COMP_WORDS[i]} == $cmd ]]; then
                        COMP_WORDS=( "${COMP_WORDS[@]}" )
                        let COMP_CWORD-=i
                        break
                    fi
                    unset -v 'COMP_WORDS[i]'
                done
                if [[ $cmd == ip ]]; then
                    _ip_main "$@"
                else
                    "$func" "$cmd" "$2" "$3"
                fi
            fi
        fi
    else
        _ip_main "$@"
    fi
}
_ip_main()
{
    local IFS=$' \t\n' cur cur_o prev prev_o prev2 comp_line2 words help args i v
    local cmd=$1 cmd2 cmd3 cmd3_list objs options opts sub_line words2

    cur=${COMP_WORDS[COMP_CWORD]} cur_o=$cur
    comp_line2=${COMP_LINE:0:$COMP_POINT}
    [[ ${comp_line2: -1} = " " || $COMP_WORDBREAKS == *$cur* ]] && cur=""
    prev=${COMP_WORDS[COMP_CWORD-1]} prev_o=$prev
    [[ $prev == [,=] ]] && prev=${COMP_WORDS[COMP_CWORD-2]}
    prev2=${COMP_WORDS[COMP_CWORD-2]}

    objs=$( $cmd -h |& sed -Ez 's/.*OBJECT := \{([^}]+)}.*/\1/; s/[ \t\n]+//g;' )
    options="-V|-Version|-h|-human|-human-readable|-b:|-batch:|-s|-stats|-statistics|\
-d|-details|-l:|-loops:|-f:|-family:|-4|-6|-B|-M|-0|-o|-oneline|-r|-resolve|\
-n:|-netns:|-N|-Numeric|-a|-all|-t|-timestamp|-ts|-tshort|-rc:|-rcvbuf:|-iec|\
-br|-brief|-j|-json|-p|-pretty|-force|(-c|-color)(=(always|auto|never))?"

    local colon="(\\\\\ |[^ ]|[\"'][^\"']*[\"'])+"
    local regex="^$cmd[ ]+((${options//:/[ ]+$colon})[ ]+)*(${objs})[ ]+(.*)"
    if [[ $cur == -* && $comp_line2 != *" address"+( )@(save|flush|show)" "* ]]; then
        options=${options/%\(-c|-color)(=(always|auto|never))?/-c=|-color=}
        words=${options//?(:)|/$'\n'}
    elif [[ $prev == @(-b|-batch) ]]; then
        :
    elif [[ $prev == @(-l|-loops) ]]; then
        words="COUNT"
    elif [[ $prev == @(-f|-family) ]]; then
        words=$'inet\ninet6\nbridge\nmpls\nlink'
    elif [[ $prev == @(-n|-netns) ]]; then
        words=$( _ip_data netns )
        [[ -z $words ]] && words="NETNS"
    elif [[ $prev == @(-rc|-rcvbuf) ]]; then
        words="SIZE"
    elif [[ $prev == @(-c|-color) ]]; then
        words=$'always\nauto\nnever'
    elif ! [[ $comp_line2 =~ $regex ]]; then
        words=${objs//|/$'\n'}
    else
        cmd2=${BASH_REMATCH[ ${#BASH_REMATCH[@]} - 2 ]}
        sub_line=${BASH_REMATCH[ ${#BASH_REMATCH[@]} - 1 ]}
        local type=$'bareudp\nbond\nbond_slave\nbridge\nbridge_slave\ndummy\nerspan
geneve\ngre\ngretap\nifb\nip6erspan\nip6gre\nip6gretap\nip6tnl\nipip\nipoib\nipvlan
ipvtap\nmacsec\nmacvlan\nmacvtap\nnetdevsim\nnlmon\nrmnet\nsit\nteam\nteam_slave\nvcan
veth\nvlan\nvrf\nvti\nvxcan\nvxlan\nwwan\nxfrm'
        case $cmd2 in
            address | addr) _ip_address ;;
            addrlabel) _ip_addrlabel ;;
            fou) _ip_fou ;;
            ila) _ip_ila ;;
            ioam) _ip_ioam ;;
            l2tp) _ip_l2tp ;;
            link) _ip_link ;;
            macsec) _ip_macsec ;;
            maddress | maddr) _ip_maddress ;;
            monitor) _ip_monitor ;;
            mptcp) _ip_mptcp ;;
            mroute) _ip_mroute ;;
            mrule | rule) _ip_mrule ;;
            neighbor | neighbour) _ip_neighbor ;;
            netconf) _ip_netconf ;;
            netns) _ip_netns ;;
            nexthop) _ip_nexthop ;;
            ntable | ntbl) _ip_ntable ;;
            route) _ip_route ;;
            sr) _ip_sr ;;
            tap | tuntap) _ip_tap ;;
            tcpmetrics | tcp_metrics) _ip_tcpmetrics ;;
            token) _ip_token ;;
            tunnel) _ip_tunnel ;;
            vrf) _ip_vrf ;;
            xfrm) _ip_xfrm ;;
        esac
    fi

    if ! declare -p COMPREPLY &> /dev/null; then
        words=$( <<< $words sed -E 's/^[[:blank:]]+|[[:blank:]]+$//g' )
        IFS=$'\n' COMPREPLY=($(compgen -W "$words" -- "$cur"))
    fi
    [[ ${COMPREPLY: -1} == "=" ]] && compopt -o nospace
}

complete -o default -o bashdefault -F _ip ip

