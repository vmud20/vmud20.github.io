














static const char tstr[] = " [|VXLAN]";





void vxlan_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags;
    uint32_t vni;

    if (len < VXLAN_HDR_LEN)
        goto trunc;

    ND_TCHECK2(*bp, VXLAN_HDR_LEN);

    flags = *bp;
    bp += 4;

    vni = EXTRACT_24BITS(bp);
    bp += 4;

    ND_PRINT((ndo, "VXLAN, "));
    ND_PRINT((ndo, "flags [%s] (0x%02x), ", flags & 0x08 ? "I" : ".", flags));
    ND_PRINT((ndo, "vni %u\n", vni));

    ether_print(ndo, bp, len - VXLAN_HDR_LEN, len - VXLAN_HDR_LEN, NULL, NULL);

    return;

trunc:
    ND_PRINT((ndo, "%s", tstr));
}
