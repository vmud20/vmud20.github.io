














static ERR_STRING_DATA DSA_str_functs[]= {
{ERR_FUNC(DSA_F_D2I_DSA_SIG),	"d2i_DSA_SIG", {ERR_FUNC(DSA_F_DO_DSA_PRINT),	"DO_DSA_PRINT", {ERR_FUNC(DSA_F_DSAPARAMS_PRINT),	"DSAparams_print", {ERR_FUNC(DSA_F_DSAPARAMS_PRINT_FP),	"DSAparams_print_fp", {ERR_FUNC(DSA_F_DSA_DO_SIGN),	"DSA_do_sign", {ERR_FUNC(DSA_F_DSA_DO_VERIFY),	"DSA_do_verify", {ERR_FUNC(DSA_F_DSA_NEW_METHOD),	"DSA_new_method", {ERR_FUNC(DSA_F_DSA_PARAM_DECODE),	"DSA_PARAM_DECODE", {ERR_FUNC(DSA_F_DSA_PRINT_FP),	"DSA_print_fp", {ERR_FUNC(DSA_F_DSA_PRIV_DECODE),	"DSA_PRIV_DECODE", {ERR_FUNC(DSA_F_DSA_PRIV_ENCODE),	"DSA_PRIV_ENCODE", {ERR_FUNC(DSA_F_DSA_PUB_DECODE),	"DSA_PUB_DECODE", {ERR_FUNC(DSA_F_DSA_PUB_ENCODE),	"DSA_PUB_ENCODE", {ERR_FUNC(DSA_F_DSA_SIGN),	"DSA_sign", {ERR_FUNC(DSA_F_DSA_SIGN_SETUP),	"DSA_sign_setup", {ERR_FUNC(DSA_F_DSA_SIG_NEW),	"DSA_SIG_new", {ERR_FUNC(DSA_F_DSA_VERIFY),	"DSA_verify", {ERR_FUNC(DSA_F_I2D_DSA_SIG),	"i2d_DSA_SIG", {ERR_FUNC(DSA_F_OLD_DSA_PRIV_DECODE),	"OLD_DSA_PRIV_DECODE", {ERR_FUNC(DSA_F_PKEY_DSA_CTRL),	"PKEY_DSA_CTRL", {ERR_FUNC(DSA_F_PKEY_DSA_KEYGEN),	"PKEY_DSA_KEYGEN", {ERR_FUNC(DSA_F_SIG_CB),	"SIG_CB", {0,NULL}





















	};

static ERR_STRING_DATA DSA_str_reasons[]= {
{ERR_REASON(DSA_R_BN_DECODE_ERROR)       ,"bn decode error", {ERR_REASON(DSA_R_BN_ERROR)              ,"bn error", {ERR_REASON(DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE),"data too large for key size", {ERR_REASON(DSA_R_DECODE_ERROR)          ,"decode error", {ERR_REASON(DSA_R_INVALID_DIGEST_TYPE)   ,"invalid digest type", {ERR_REASON(DSA_R_MISSING_PARAMETERS)    ,"missing parameters", {ERR_REASON(DSA_R_NO_PARAMETERS_SET)     ,"no parameters set", {ERR_REASON(DSA_R_PARAMETER_ENCODING_ERROR),"parameter encoding error", {0,NULL}







	};



void ERR_load_DSA_strings(void)
	{
	static int init=1;

	if (init)
		{
		init=0;

		ERR_load_strings(0,DSA_str_functs);
		ERR_load_strings(0,DSA_str_reasons);


		}
	}
