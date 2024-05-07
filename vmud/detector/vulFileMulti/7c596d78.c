















void mss_fixup_ipv4(struct buffer *buf, int maxmss)
{
    const struct openvpn_iphdr *pip;
    int hlen;

    if (BLEN(buf) < (int) sizeof(struct openvpn_iphdr))
    {
        return;
    }

    verify_align_4(buf);
    pip = (struct openvpn_iphdr *) BPTR(buf);

    hlen = OPENVPN_IPH_GET_LEN(pip->version_len);

    if (pip->protocol == OPENVPN_IPPROTO_TCP && ntohs(pip->tot_len) == BLEN(buf)
        && (ntohs(pip->frag_off) & OPENVPN_IP_OFFMASK) == 0 && hlen <= BLEN(buf)
        && BLEN(buf) - hlen >= (int) sizeof(struct openvpn_tcphdr))
    {
        struct buffer newbuf = *buf;
        if (buf_advance(&newbuf, hlen))
        {
            struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *) BPTR(&newbuf);
            if (tc->flags & OPENVPN_TCPH_SYN_MASK)
            {
                mss_fixup_dowork(&newbuf, (uint16_t) maxmss);
            }
        }
    }
}


void mss_fixup_ipv6(struct buffer *buf, int maxmss)
{
    const struct openvpn_ipv6hdr *pip6;
    struct buffer newbuf;

    if (BLEN(buf) < (int) sizeof(struct openvpn_ipv6hdr))
    {
        return;
    }

    verify_align_4(buf);
    pip6 = (struct openvpn_ipv6hdr *) BPTR(buf);

    
    if (BLEN(buf) != (int) ntohs(pip6->payload_len)+40)
    {
        return;
    }

    
    if (pip6->nexthdr != OPENVPN_IPPROTO_TCP)
    {
        return;
    }

    newbuf = *buf;
    if (buf_advance( &newbuf, 40 ) )
    {
        struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *) BPTR(&newbuf);
        if (tc->flags & OPENVPN_TCPH_SYN_MASK)
        {
            mss_fixup_dowork(&newbuf, (uint16_t) maxmss-20);
        }
    }
}



void mss_fixup_dowork(struct buffer *buf, uint16_t maxmss)
{
    int hlen, olen, optlen;
    uint8_t *opt;
    uint16_t mssval;
    int accumulate;
    struct openvpn_tcphdr *tc;

    ASSERT(BLEN(buf) >= (int) sizeof(struct openvpn_tcphdr));

    verify_align_4(buf);
    tc = (struct openvpn_tcphdr *) BPTR(buf);
    hlen = OPENVPN_TCPH_GET_DOFF(tc->doff_res);

    
    if (hlen <= (int) sizeof(struct openvpn_tcphdr)
        || hlen > BLEN(buf))
    {
        return;
    }

    for (olen = hlen - sizeof(struct openvpn_tcphdr), opt = (uint8_t *)(tc + 1);
         olen > 1;
         olen -= optlen, opt += optlen)
    {
        if (*opt == OPENVPN_TCPOPT_EOL)
        {
            break;
        }
        else if (*opt == OPENVPN_TCPOPT_NOP)
        {
            optlen = 1;
        }
        else {
            optlen = *(opt + 1);
            if (optlen <= 0 || optlen > olen)
            {
                break;
            }
            if (*opt == OPENVPN_TCPOPT_MAXSEG)
            {
                if (optlen != OPENVPN_TCPOLEN_MAXSEG)
                {
                    continue;
                }
                mssval = (opt[2]<<8)+opt[3];
                if (mssval > maxmss)
                {
                    dmsg(D_MSS, "MSS: %d -> %d", (int) mssval, (int) maxmss);
                    accumulate = htons(mssval);
                    opt[2] = (maxmss>>8)&0xff;
                    opt[3] = maxmss&0xff;
                    accumulate -= htons(maxmss);
                    ADJUST_CHECKSUM(accumulate, tc->check);
                }
            }
        }
    }
}
