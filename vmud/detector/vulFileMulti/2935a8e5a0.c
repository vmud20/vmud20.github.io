








void rewinddir (dirp)
     DIR *dirp;
{

  __libc_lock_lock (dirp->lock);

  (void) __lseek (dirp->fd, (off_t) 0, SEEK_SET);
  dirp->filepos = 0;
  dirp->offset = 0;
  dirp->size = 0;

  __libc_lock_unlock (dirp->lock);

}
libc_hidden_def (rewinddir)
