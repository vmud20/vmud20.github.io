




























static int o_directory_works;

static void tryopen_o_directory (void)
{
  int serrno = errno;
  int x = open_not_cancel_2 ("/dev/null", O_RDONLY|O_NDELAY|O_DIRECTORY);

  if (x >= 0)
    {
      close_not_cancel_no_status (x);
      o_directory_works = -1;
    }
  else if (errno != ENOTDIR)
    o_directory_works = -1;
  else o_directory_works = 1;

  __set_errno (serrno);
}







DIR * internal_function __opendirat (int dfd, const char *name)

{
  struct stat64 statbuf;
  struct stat64 *statp = NULL;

  if (__builtin_expect (name[0], '\1') == '\0')
    {
      
      __set_errno (ENOENT);
      return NULL;
    }


  
  if (o_directory_works == 0)
    tryopen_o_directory ();

  
  if (o_directory_works < 0)

    {
      
      if (__builtin_expect (__xstat64 (_STAT_VER, name, &statbuf), 0) < 0)
	return NULL;
      if (__builtin_expect (! S_ISDIR (statbuf.st_mode), 0))
	{
	  __set_errno (ENOTDIR);
	  return NULL;
	 }
    }

  int flags = O_RDONLY|O_NDELAY|EXTRA_FLAGS|O_LARGEFILE;

  flags |= O_CLOEXEC;

  int fd;

  assert (dfd == AT_FDCWD);
  fd = open_not_cancel_2 (name, flags);

  fd = openat_not_cancel_3 (dfd, name, flags);

  if (__builtin_expect (fd, 0) < 0)
    return NULL;


  if (o_directory_works <= 0)

    {
      
      if (__builtin_expect (__fxstat64 (_STAT_VER, fd, &statbuf), 0) < 0)
	goto lose;
      if (__builtin_expect (! S_ISDIR (statbuf.st_mode), 0))
	{
	  __set_errno (ENOTDIR);
	lose:
	  close_not_cancel_no_status (fd);
	  return NULL;
	}
      statp = &statbuf;
    }

  return __alloc_dir (fd, true, 0, statp);
}



DIR * __opendir (const char *name)
{
  return __opendirat (AT_FDCWD, name);
}
weak_alias (__opendir, opendir)





static int check_have_o_cloexec (int fd)
{
  if (__have_o_cloexec == 0)
    __have_o_cloexec = (__fcntl (fd, F_GETFD, 0) & FD_CLOEXEC) == 0 ? -1 : 1;
  return __have_o_cloexec > 0;
}



DIR * internal_function __alloc_dir (int fd, bool close_fd, int flags, const struct stat64 *statp)

{
  

  if ((! close_fd && (flags & O_CLOEXEC) == 0)
      || ! check_have_o_cloexec (fd))

    {
      if (__builtin_expect (__fcntl (fd, F_SETFD, FD_CLOEXEC), 0) < 0)
	goto lose;
    }

  const size_t default_allocation = (4 * BUFSIZ < sizeof (struct dirent64)
				     ? sizeof (struct dirent64) : 4 * BUFSIZ);
  const size_t small_allocation = (BUFSIZ < sizeof (struct dirent64)
				   ? sizeof (struct dirent64) : BUFSIZ);
  size_t allocation = default_allocation;

  
  if (statp != NULL)
    allocation = MIN (MAX ((size_t) statp->st_blksize, default_allocation), MAX_DIR_BUFFER_SIZE);


  DIR *dirp = (DIR *) malloc (sizeof (DIR) + allocation);
  if (dirp == NULL)
    {
      allocation = small_allocation;
      dirp = (DIR *) malloc (sizeof (DIR) + allocation);

      if (dirp == NULL)
      lose:
	{
	  if (close_fd)
	    {
	      int save_errno = errno;
	      close_not_cancel_no_status (fd);
	      __set_errno (save_errno);
	    }
	  return NULL;
	}
    }

  dirp->fd = fd;

  __libc_lock_init (dirp->lock);

  dirp->allocation = allocation;
  dirp->size = 0;
  dirp->offset = 0;
  dirp->filepos = 0;

  return dirp;
}
