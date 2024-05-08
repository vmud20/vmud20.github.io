















static const char *op_code_str[] = {
	"hello", "coup", "resign" };




static const struct tok states[] = {
	{  0, "initial" }, {  1, "learn" }, {  2, "listen" }, {  4, "speak" }, {  8, "standby" }, { 16, "active" }, {  0, NULL }





};






struct hsrp {
	uint8_t		hsrp_version;
	uint8_t		hsrp_op_code;
	uint8_t		hsrp_state;
	uint8_t		hsrp_hellotime;
	uint8_t		hsrp_holdtime;
	uint8_t		hsrp_priority;
	uint8_t		hsrp_group;
	uint8_t		hsrp_reserved;
	uint8_t		hsrp_authdata[HSRP_AUTH_SIZE];
	struct in_addr	hsrp_virtaddr;
};

void hsrp_print(netdissect_options *ndo, register const uint8_t *bp, register u_int len)
{
	const struct hsrp *hp = (const struct hsrp *) bp;

	ND_TCHECK(hp->hsrp_version);
	ND_PRINT((ndo, "HSRPv%d", hp->hsrp_version));
	if (hp->hsrp_version != 0)
		return;
	ND_TCHECK(hp->hsrp_op_code);
	ND_PRINT((ndo, "-"));
	ND_PRINT((ndo, "%s ", tok2strary(op_code_str, "unknown (%d)", hp->hsrp_op_code)));
	ND_PRINT((ndo, "%d: ", len));
	ND_TCHECK(hp->hsrp_state);
	ND_PRINT((ndo, "state=%s ", tok2str(states, "Unknown (%d)", hp->hsrp_state)));
	ND_TCHECK(hp->hsrp_group);
	ND_PRINT((ndo, "group=%d ", hp->hsrp_group));
	ND_TCHECK(hp->hsrp_reserved);
	if (hp->hsrp_reserved != 0) {
		ND_PRINT((ndo, "[reserved=%d!] ", hp->hsrp_reserved));
	}
	ND_TCHECK(hp->hsrp_virtaddr);
	ND_PRINT((ndo, "addr=%s", ipaddr_string(ndo, &hp->hsrp_virtaddr)));
	if (ndo->ndo_vflag) {
		ND_PRINT((ndo, " hellotime="));
		relts_print(ndo, hp->hsrp_hellotime);
		ND_PRINT((ndo, " holdtime="));
		relts_print(ndo, hp->hsrp_holdtime);
		ND_PRINT((ndo, " priority=%d", hp->hsrp_priority));
		ND_PRINT((ndo, " auth=\""));
		if (fn_printn(ndo, hp->hsrp_authdata, sizeof(hp->hsrp_authdata), ndo->ndo_snapend)) {
			ND_PRINT((ndo, "\""));
			goto trunc;
		}
		ND_PRINT((ndo, "\""));
	}
	return;
trunc:
	ND_PRINT((ndo, "[|hsrp]"));
}
