








































FILE_RCSID("@(#)$Id: magic.c,v 1.2 2004/05/19 02:36:26 tedu Exp $")



private char *apptypeName = NULL;
protected int file_os2_apptype(struct magic_set *ms, const char *fn, const void *buf, size_t nb);


private void free_mlist(struct mlist *);
private void close_and_restore(const struct magic_set *, const char *, int, const struct stat *);

public struct magic_set * magic_open(int flags)
{
	struct magic_set *ms;

	if ((ms = malloc(sizeof(struct magic_set))) == NULL)
		return NULL;

	if (magic_setflags(ms, flags) == -1) {
		free(ms);
		errno = EINVAL;
		return NULL;
	}

	ms->o.ptr = ms->o.buf = malloc(ms->o.size = 1024);
	ms->o.len = 0;
	if (ms->o.buf == NULL) {
		free(ms);
		return NULL;
	}
	ms->o.pbuf = malloc(ms->o.psize = 1024);
	if (ms->o.pbuf == NULL) {
		free(ms->o.buf);
		free(ms);
		return NULL;
	}
	ms->c.off = malloc((ms->c.len = 10) * sizeof(*ms->c.off));
	if (ms->c.off == NULL) {
		free(ms->o.pbuf);
		free(ms->o.buf);
		free(ms);
		return NULL;
	}
	ms->haderr = 0;
	ms->error = -1;
	ms->mlist = NULL;
	return ms;
}

private void free_mlist(struct mlist *mlist)
{
	struct mlist *ml;

	if (mlist == NULL)
		return;

	for (ml = mlist->next; ml != mlist;) {
		struct mlist *next = ml->next;
		struct magic *mg = ml->magic;
		file_delmagic(mg, ml->mapped, ml->nmagic);
		free(ml);
		ml = next;
	}
	free(ml);
}

public void magic_close(ms)
    struct magic_set *ms;
{
	free_mlist(ms->mlist);
	free(ms->o.buf);
	free(ms->c.off);
	free(ms);
}


public int magic_load(struct magic_set *ms, const char *magicfile)
{
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_LOAD);
	if (ml) {
		free_mlist(ms->mlist);
		ms->mlist = ml;
		return 0;
	}
	return -1;
}

public int magic_compile(struct magic_set *ms, const char *magicfile)
{
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_COMPILE);
	free_mlist(ml);
	return ml ? 0 : -1;
}

public int magic_check(struct magic_set *ms, const char *magicfile)
{
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_CHECK);
	free_mlist(ml);
	return ml ? 0 : -1;
}

private void close_and_restore(const struct magic_set *ms, const char *name, int fd, const struct stat *sb)

{
	(void) close(fd);
	if (fd != STDIN_FILENO && (ms->flags & MAGIC_PRESERVE_ATIME) != 0) {
		

		struct timeval  utsbuf[2];
		utsbuf[0].tv_sec = sb->st_atime;
		utsbuf[1].tv_sec = sb->st_mtime;

		(void) utimes(name, utsbuf); 

		struct utimbuf  utbuf;

		utbuf.actime = sb->st_atime;
		utbuf.modtime = sb->st_mtime;
		(void) utime(name, &utbuf); 

	}
}


public const char * magic_file(struct magic_set *ms, const char *inname)
{
	int	fd = 0;
	unsigned char buf[HOWMANY+1];	
	struct stat	sb;
	ssize_t nbytes = 0;	

	if (file_reset(ms) == -1)
		return NULL;

	switch (file_fsmagic(ms, inname, &sb)) {
	case -1:
		return NULL;
	case 0:
		break;
	default:
		return file_getbuffer(ms);
	}




	if (inname == NULL)
		fd = STDIN_FILENO;
	else if ((fd = open(inname, O_RDONLY)) < 0) {
		
		if (sb.st_mode & 0222)
			if (file_printf(ms, "writable, ") == -1)
				return NULL;
		if (sb.st_mode & 0111)
			if (file_printf(ms, "executable, ") == -1)
				return NULL;
		if (S_ISREG(sb.st_mode))
			if (file_printf(ms, "regular file, ") == -1)
				return NULL;
		if (file_printf(ms, "no read permission") == -1)
			return NULL;
		return file_getbuffer(ms);
	}

	
	if ((nbytes = read(fd, (char *)buf, HOWMANY)) == -1) {
		file_error(ms, errno, "cannot read `%s'", inname);
		goto done;
	}

	if (nbytes == 0) {
		if (file_printf(ms, (ms->flags & MAGIC_MIME) ? "application/x-empty" : "empty") == -1)
			goto done;
		goto gotit;
	} else if (nbytes == 1) {
		if (file_printf(ms, "very short file (no magic)") == -1)
			goto done;
		goto gotit;
	} else {
		buf[nbytes] = '\0';	

		switch (file_os2_apptype(ms, inname, buf, nbytes)) {
		case -1:
			goto done;
		case 0:
			break;
		default:
			goto gotit;
		}

		if (file_buffer(ms, buf, (size_t)nbytes) == -1)
			goto done;

		if (nbytes > 5) {
			
			file_tryelf(ms, fd, buf, (size_t)nbytes);
		}

	}
gotit:
	close_and_restore(ms, inname, fd, &sb);
	return file_getbuffer(ms);
done:
	close_and_restore(ms, inname, fd, &sb);
	return NULL;
}


public const char * magic_buffer(struct magic_set *ms, const void *buf, size_t nb)
{
	if (file_reset(ms) == -1)
		return NULL;
	
	if (file_buffer(ms, buf, nb) == -1) {
		return NULL;
	}
	return file_getbuffer(ms);
}

public const char * magic_error(struct magic_set *ms)
{
	return ms->haderr ? ms->o.buf : NULL;
}

public int magic_errno(struct magic_set *ms)
{
	return ms->haderr ? ms->error : 0;
}

public int magic_setflags(struct magic_set *ms, int flags)
{

	if (flags & MAGIC_PRESERVE_ATIME)
		return -1;

	ms->flags = flags;
	return 0;
}
