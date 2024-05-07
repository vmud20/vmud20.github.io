









































char * xcrypt(const char *password, const char *salt)
{
	char *crypted;


        if (is_md5_salt(salt))
                crypted = md5_crypt(password, salt);
        else crypted = crypt(password, salt);

	if (iscomsec())
                crypted = bigcrypt(password, salt);
        else crypted = crypt(password, salt);

        crypted = bigcrypt(password, salt);

        crypted = crypt(password, salt);


	return crypted;
}



char * shadow_pw(struct passwd *pw)
{
	char *pw_password = pw->pw_passwd;


	struct spwd *spw = getspnam(pw->pw_name);

	if (spw != NULL)
		pw_password = spw->sp_pwdp;



	return(get_iaf_password(pw));



	struct passwd_adjunct *spw;
	if (issecure() && (spw = getpwanam(pw->pw_name)) != NULL)
		pw_password = spw->pwa_passwd;

	struct pr_passwd *spw = getprpwnam(pw->pw_name);

	if (spw != NULL)
		pw_password = spw->ufld.fd_encrypt;


	return pw_password;
}
