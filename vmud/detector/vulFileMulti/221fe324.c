























































int main (int argc, char **argv)
{
  int errsv = 0;
  int i;

  for (i = 1; i < argc; i++)
    {
      const char *arg = argv[i];

      if (strcmp (arg, "print-errno-values") == 0)
        {
          printf ("EBADF=%d\n", EBADF);
          printf ("EFAULT=%d\n", EFAULT);
          printf ("ENOENT=%d\n", ENOENT);
          printf ("ENOSYS=%d\n", ENOSYS);
          printf ("EPERM=%d\n", EPERM);
        }
      else if (strcmp (arg, "chmod") == 0)
        {
          
          if (chmod (WRONG_POINTER, 0700) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
      else if (strcmp (arg, "chroot") == 0)
        {
          
          if (chroot (WRONG_POINTER) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
      else if (strcmp (arg, "clone3") == 0)
        {
          
          if (syscall (__NR_clone3, WRONG_POINTER, SIZEOF_STRUCT_CLONE_ARGS) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
      else if (strcmp (arg, "ioctl TIOCNOTTY") == 0)
        {
          
          if (ioctl (-1, TIOCNOTTY) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
      else if (strcmp (arg, "ioctl TIOCSTI") == 0)
        {
          
          if (ioctl (-1, TIOCSTI, WRONG_POINTER) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }

      else if (strcmp (arg, "ioctl TIOCSTI CVE-2019-10063") == 0)
        {
          unsigned long not_TIOCSTI = (0x123UL << 32) | (unsigned long) TIOCSTI;

          
          if (syscall (__NR_ioctl, -1, not_TIOCSTI, WRONG_POINTER) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }

     else if (strcmp (arg, "listen") == 0)
        {
          
          if (listen (-1, 42) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
     else if (strcmp (arg, "prctl") == 0)
        {
          
          if (prctl (PR_GET_CHILD_SUBREAPER, WRONG_POINTER, 0, 0, 0) != 0)
            {
              errsv = errno;
              perror (arg);
            }
        }
      else {
          fprintf (stderr, "Unsupported syscall \"%s\"\n", arg);
          errsv = ENOENT;
        }
   }

  return errsv;
}
