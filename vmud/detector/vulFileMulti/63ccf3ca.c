





















extern Buffer loginmsg;
extern ServerOptions options;


extern login_cap_t *lc;






void disable_forwarding(void)
{
	no_port_forwarding_flag = 1;
	no_agent_forwarding_flag = 1;
	no_x11_forwarding_flag = 1;
}


int auth_password(Authctxt *authctxt, const char *password)
{
	struct passwd * pw = authctxt->pw;
	int result, ok = authctxt->valid;

	static int expire_checked = 0;



	if (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;

	if (*password == '\0' && options.permit_empty_passwd == 0)
		return 0;


	if (options.kerberos_authentication == 1) {
		int ret = auth_krb5_password(authctxt, password);
		if (ret == 1 || ret == 0)
			return ret && ok;
		
	}


	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		if (hToken == INVALID_HANDLE_VALUE)
			return 0;
		cygwin_set_impersonation_token(hToken);
		return ok;
	}


	if (options.use_pam)
		return (sshpam_auth_passwd(authctxt, password) && ok);


	if (!expire_checked) {
		expire_checked = 1;
		if (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}

	result = sys_auth_passwd(authctxt, password);
	if (authctxt->force_pwchange)
		disable_forwarding();
	return (result && ok);
}


static void warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	char buf[256];
	quad_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);

	if (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS, TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS, TWO_WEEKS);
	}

	if (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		snprintf(buf, sizeof(buf), "Your password will expire in %lld day%s.\n", daysleft, daysleft == 1 ? "" : "s");

		buffer_append(&loginmsg, buf, strlen(buf));
	}
	if (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		snprintf(buf, sizeof(buf), "Your account will expire in %lld day%s.\n", daysleft, daysleft == 1 ? "" : "s");

		buffer_append(&loginmsg, buf, strlen(buf));
	}
}

int sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	auth_session_t *as;
	static int expire_checked = 0;

	as = auth_usercheck(pw->pw_name, authctxt->style, "auth-ssh", (char *)password);
	if (as == NULL)
		return (0);
	if (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		disable_forwarding();
		authctxt->force_pwchange = 1;
		return (1);
	} else {
		if (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		return (auth_close(as));
	}
}

int sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	char *encrypted_password;

	
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	
	if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		return (1);

	
	encrypted_password = xcrypt(password, (pw_password[0] && pw_password[1]) ? pw_password : "xx");

	
	return encrypted_password != NULL && strcmp(encrypted_password, pw_password) == 0;
}

