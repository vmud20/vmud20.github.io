














static const char tstr[] = " [|VXLAN-GPE]";
static const struct tok vxlan_gpe_flags [] = {
    { 0x08, "I" }, { 0x04, "P" }, { 0x01, "O" }, { 0, NULL }


};





void vxlan_gpe_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags;
    uint8_t next_protocol;
    uint32_t vni;

    if (len < VXLAN_GPE_HDR_LEN)
        goto trunc;

    ND_TCHECK2(*bp, VXLAN_GPE_HDR_LEN);

    flags = *bp;
    bp += 3;

    next_protocol = *bp;
    bp += 1;

    vni = EXTRACT_24BITS(bp);
    bp += 4;

    ND_PRINT((ndo, "VXLAN-GPE, "));
    ND_PRINT((ndo, "flags [%s], ", bittok2str_nosep(vxlan_gpe_flags, "none", flags)));
    ND_PRINT((ndo, "vni %u", vni));
    ND_PRINT((ndo, ndo->ndo_vflag ? "\n    " : ": "));

    switch (next_protocol) {
    case 0x1:
        ip_print(ndo, bp, len - 8);
        break;
    case 0x2:
        ip6_print(ndo, bp, len - 8);
        break;
    case 0x3:
        ether_print(ndo, bp, len - 8, len - 8, NULL, NULL);
        break;
    case 0x4:
        nsh_print(ndo, bp, len - 8);
        break;
    case 0x5:
        mpls_print(ndo, bp, len - 8);
        break;
    default:
        ND_PRINT((ndo, "ERROR: unknown-next-protocol"));
        return;
    }

	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}

