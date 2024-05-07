




















int __READDIR_R (DIR *dirp, DIRENT_TYPE *entry, DIRENT_TYPE **result)
{
  DIRENT_TYPE *dp;
  size_t reclen;
  const int saved_errno = errno;

  __libc_lock_lock (dirp->lock);

  do {
      if (dirp->offset >= dirp->size)
	{
	  

	  size_t maxread;
	  ssize_t bytes;


	  
	  maxread = sizeof *dp;

	  maxread = dirp->allocation;


	  bytes = __GETDENTS (dirp->fd, dirp->data, maxread);
	  if (bytes <= 0)
	    {
	      
	      if (bytes < 0 && errno == ENOENT)
		{
		  bytes = 0;
		  __set_errno (saved_errno);
		}

	      dp = NULL;
	      
	      reclen = bytes != 0;
	      break;
	    }
	  dirp->size = (size_t) bytes;

	  
	  dirp->offset = 0;
	}

      dp = (DIRENT_TYPE *) &dirp->data[dirp->offset];


      reclen = dp->d_reclen;

      
      assert (sizeof dp->d_name > 1);
      reclen = sizeof *dp;
      
      dp->d_name[sizeof dp->d_name] = '\0';


      dirp->offset += reclen;


      dirp->filepos = dp->d_off;

      dirp->filepos += reclen;


      
    }
  while (dp->d_ino == 0);

  if (dp != NULL)
    {

      
      reclen = MIN (reclen, offsetof (DIRENT_TYPE, d_name) + sizeof (dp->d_name));

      *result = memcpy (entry, dp, reclen);

      entry->d_reclen = reclen;

    }
  else *result = NULL;

  __libc_lock_unlock (dirp->lock);

  return dp != NULL ? 0 : reclen ? errno : 0;
}


weak_alias (__readdir_r, readdir_r)

