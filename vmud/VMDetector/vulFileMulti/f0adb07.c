




























static uid_t real_uid;
static gid_t real_gid;
static uid_t overflow_uid;
static gid_t overflow_gid;
static bool is_privileged;
static const char *argv0;
static const char *host_tty_dev;
static int proc_fd = -1;
static char *opt_exec_label = NULL;
static char *opt_file_label = NULL;

char *opt_chdir_path = NULL;
bool opt_unshare_user = FALSE;
bool opt_unshare_user_try = FALSE;
bool opt_unshare_pid = FALSE;
bool opt_unshare_ipc = FALSE;
bool opt_unshare_net = FALSE;
bool opt_unshare_uts = FALSE;
bool opt_unshare_cgroup = FALSE;
bool opt_unshare_cgroup_try = FALSE;
bool opt_needs_devpts = FALSE;
uid_t opt_sandbox_uid = -1;
gid_t opt_sandbox_gid = -1;
int opt_sync_fd = -1;
int opt_block_fd = -1;
int opt_info_fd = -1;
int opt_seccomp_fd = -1;
char *opt_sandbox_hostname = NULL;

typedef enum {
  SETUP_BIND_MOUNT, SETUP_RO_BIND_MOUNT, SETUP_DEV_BIND_MOUNT, SETUP_MOUNT_PROC, SETUP_MOUNT_DEV, SETUP_MOUNT_TMPFS, SETUP_MOUNT_MQUEUE, SETUP_MAKE_DIR, SETUP_MAKE_FILE, SETUP_MAKE_BIND_FILE, SETUP_MAKE_RO_BIND_FILE, SETUP_MAKE_SYMLINK, SETUP_REMOUNT_RO_NO_RECURSIVE, SETUP_SET_HOSTNAME, } SetupOpType;














typedef enum {
  NO_CREATE_DEST = (1 << 0), } SetupOpFlag;

typedef struct _SetupOp SetupOp;

struct _SetupOp {
  SetupOpType type;
  const char *source;
  const char *dest;
  int         fd;
  SetupOpFlag flags;
  SetupOp    *next;
};

typedef struct _LockFile LockFile;

struct _LockFile {
  const char *path;
  LockFile   *next;
};

static SetupOp *ops = NULL;
static SetupOp *last_op = NULL;
static LockFile *lock_files = NULL;
static LockFile *last_lock_file = NULL;

enum {
  PRIV_SEP_OP_DONE, PRIV_SEP_OP_BIND_MOUNT, PRIV_SEP_OP_PROC_MOUNT, PRIV_SEP_OP_TMPFS_MOUNT, PRIV_SEP_OP_DEVPTS_MOUNT, PRIV_SEP_OP_MQUEUE_MOUNT, PRIV_SEP_OP_REMOUNT_RO_NO_RECURSIVE, PRIV_SEP_OP_SET_HOSTNAME, };








typedef struct {
  uint32_t op;
  uint32_t flags;
  uint32_t arg1_offset;
  uint32_t arg2_offset;
} PrivSepOp;

static SetupOp * setup_op_new (SetupOpType type)
{
  SetupOp *op = xcalloc (sizeof (SetupOp));

  op->type = type;
  op->fd = -1;
  op->flags = 0;
  if (last_op != NULL)
    last_op->next = op;
  else ops = op;

  last_op = op;
  return op;
}

static LockFile * lock_file_new (const char *path)
{
  LockFile *lock = xcalloc (sizeof (LockFile));

  lock->path = path;
  if (last_lock_file != NULL)
    last_lock_file->next = lock;
  else lock_files = lock;

  last_lock_file = lock;
  return lock;
}


static void usage (int ecode, FILE *out)
{
  fprintf (out, "usage: %s [OPTIONS...] COMMAND [ARGS...]\n\n", argv0);

  fprintf (out, "    --help                       Print this help\n" "    --version                    Print version\n" "    --args FD                    Parse nul-separated args from FD\n" "    --unshare-user               Create new user namespace (may be automatically implied if not setuid)\n" "    --unshare-user-try           Create new user namespace if possible else continue by skipping it\n" "    --unshare-ipc                Create new ipc namespace\n" "    --unshare-pid                Create new pid namespace\n" "    --unshare-net                Create new network namespace\n" "    --unshare-uts                Create new uts namespace\n" "    --unshare-cgroup             Create new cgroup namespace\n" "    --unshare-cgroup-try         Create new cgroup namespace if possible else continue by skipping it\n" "    --uid UID                    Custom uid in the sandbox (requires --unshare-user)\n" "    --gid GID                    Custon gid in the sandbox (requires --unshare-user)\n" "    --hostname NAME              Custom hostname in the sandbox (requires --unshare-uts)\n" "    --chdir DIR                  Change directory to DIR\n" "    --setenv VAR VALUE           Set an environment variable\n" "    --unsetenv VAR               Unset an environment variable\n" "    --lock-file DEST             Take a lock on DEST while sandbox is running\n" "    --sync-fd FD                 Keep this fd open while sandbox is running\n" "    --bind SRC DEST              Bind mount the host path SRC on DEST\n" "    --dev-bind SRC DEST          Bind mount the host path SRC on DEST, allowing device access\n" "    --ro-bind SRC DEST           Bind mount the host path SRC readonly on DEST\n" "    --remount-ro DEST            Remount DEST as readonly, it doesn't recursively remount\n" "    --exec-label LABEL           Exec Label for the sandbox\n" "    --file-label LABEL           File label for temporary sandbox content\n" "    --proc DEST                  Mount procfs on DEST\n" "    --dev DEST                   Mount new dev on DEST\n" "    --tmpfs DEST                 Mount new tmpfs on DEST\n" "    --mqueue DEST                Mount new mqueue on DEST\n" "    --dir DEST                   Create dir at DEST\n" "    --file FD DEST               Copy from FD to dest DEST\n" "    --bind-data FD DEST          Copy from FD to file which is bind-mounted on DEST\n" "    --ro-bind-data FD DEST       Copy from FD to file which is readonly bind-mounted on DEST\n" "    --symlink SRC DEST           Create symlink at DEST with target SRC\n" "    --seccomp FD                 Load and use seccomp rules from FD\n" "    --block-fd FD                Block on FD until some data to read is available\n" "    --info-fd FD                 Write information about the running container to FD\n" );





































  exit (ecode);
}

static void block_sigchild (void)
{
  sigset_t mask;
  int status;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_BLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");

  
  while (waitpid (-1, &status, WNOHANG) > 0)
    ;
}

static void unblock_sigchild (void)
{
  sigset_t mask;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_UNBLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");
}


static int close_extra_fds (void *data, int fd)
{
  int *extra_fds = (int *) data;
  int i;

  for (i = 0; extra_fds[i] != -1; i++)
    if (fd == extra_fds[i])
      return 0;

  if (fd <= 2)
    return 0;

  close (fd);
  return 0;
}

static int propagate_exit_status (int status)
{
  if (WIFEXITED (status))
    return WEXITSTATUS (status);

  
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);

  
  return 255;
}


static void monitor_child (int event_fd, pid_t child_pid)
{
  int res;
  uint64_t val;
  ssize_t s;
  int signal_fd;
  sigset_t mask;
  struct pollfd fds[2];
  int num_fds;
  struct signalfd_siginfo fdsi;
  int dont_close[] = { event_fd, -1 };
  pid_t died_pid;
  int died_status;

  
  fdwalk (proc_fd, close_extra_fds, dont_close);

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  signal_fd = signalfd (-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd == -1)
    die_with_error ("Can't create signalfd");

  num_fds = 1;
  fds[0].fd = signal_fd;
  fds[0].events = POLLIN;
  if (event_fd != -1)
    {
      fds[1].fd = event_fd;
      fds[1].events = POLLIN;
      num_fds++;
    }

  while (1)
    {
      fds[0].revents = fds[1].revents = 0;
      res = poll (fds, num_fds, -1);
      if (res == -1 && errno != EINTR)
        die_with_error ("poll");

      
      if (event_fd != -1)
        {
          s = read (event_fd, &val, 8);
          if (s == -1 && errno != EINTR && errno != EAGAIN)
            die_with_error ("read eventfd");
          else if (s == 8)
            exit ((int) val - 1);
        }

      
      s = read (signal_fd, &fdsi, sizeof (struct signalfd_siginfo));
      if (s == -1 && errno != EINTR && errno != EAGAIN)
        die_with_error ("read signalfd");

      
      while ((died_pid = waitpid (-1, &died_status, WNOHANG)) > 0)
        {
          
          if (died_pid == child_pid)
            exit (propagate_exit_status (died_status));
        }
    }
}


static int do_init (int event_fd, pid_t initial_pid)
{
  int initial_exit_status = 1;
  LockFile *lock;

  for (lock = lock_files; lock != NULL; lock = lock->next)
    {
      int fd = open (lock->path, O_RDONLY | O_CLOEXEC);
      if (fd == -1)
        die_with_error ("Unable to open lock file %s", lock->path);

      struct flock l = {
        .l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0 };




      if (fcntl (fd, F_SETLK, &l) < 0)
        die_with_error ("Unable to lock file %s", lock->path);

      
    }

  while (TRUE)
    {
      pid_t child;
      int status;

      child = wait (&status);
      if (child == initial_pid && event_fd != -1)
        {
          uint64_t val;
          int res UNUSED;

          initial_exit_status = propagate_exit_status (status);

          val = initial_exit_status + 1;
          res = write (event_fd, &val, 8);
          
        }

      if (child == -1 && errno != EINTR)
        {
          if (errno != ECHILD)
            die_with_error ("init wait()");
          break;
        }
    }

  return initial_exit_status;
}






static void set_required_caps (void)
{
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  
  data[0].effective = REQUIRED_CAPS_0;
  data[0].permitted = REQUIRED_CAPS_0;
  data[0].inheritable = 0;
  data[1].effective = REQUIRED_CAPS_1;
  data[1].permitted = REQUIRED_CAPS_1;
  data[1].inheritable = 0;
  if (capset (&hdr, data) < 0)
    die_with_error ("capset failed");
}

static void drop_all_caps (void)
{
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  if (capset (&hdr, data) < 0)
    die_with_error ("capset failed");
}

static bool has_caps (void)
{
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  if (capget (&hdr, data)  < 0)
    die_with_error ("capget failed");

  return data[0].permitted != 0 || data[1].permitted != 0;
}

static void drop_cap_bounding_set (void)
{
  unsigned long cap;

  for (cap = 0; cap <= 63; cap++)
    {
      int res = prctl (PR_CAPBSET_DROP, cap, 0, 0, 0);
      if (res == -1 && errno != EINVAL)
        die_with_error ("Dropping capability %ld from bounds", cap);
    }
}


static void acquire_privs (void)
{
  uid_t euid, new_fsuid;

  euid = geteuid ();

  
  if (real_uid != euid)
    {
      if (euid == 0)
        is_privileged = TRUE;
      else die ("Unexpected setuid user %d, should be 0", euid);

      
      if (setfsuid (real_uid) < 0)
        die_with_error ("Unable to set fsuid");

      
      new_fsuid = setfsuid (-1);
      if (new_fsuid != real_uid)
        die ("Unable to set fsuid (was %d)", (int)new_fsuid);

      
      drop_cap_bounding_set ();

      
      set_required_caps ();
    }
  else if (real_uid != 0 && has_caps ())
    {
      
      die ("Unexpected capabilities but not setuid, old file caps config?");
    }

  
}


static void switch_to_user_with_privs (void)
{
  
  if (opt_unshare_user)
    drop_cap_bounding_set ();

  if (!is_privileged)
    return;

  
  if (prctl (PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_KEEPCAPS) failed");

  if (setuid (opt_sandbox_uid) < 0)
    die_with_error ("unable to drop root uid");

  
  set_required_caps ();
}

static void drop_privs (void)
{
  if (!is_privileged)
    return;

  
  if (setuid (opt_sandbox_uid) < 0)
    die_with_error ("unable to drop root uid");

  drop_all_caps ();
}

static char * get_newroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/newroot/", path);
}

static char * get_oldroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/oldroot/", path);
}

static void write_uid_gid_map (uid_t sandbox_uid, uid_t parent_uid, uid_t sandbox_gid, uid_t parent_gid, pid_t pid, bool  deny_groups, bool  map_root)






{
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;
  cleanup_free char *dir = NULL;
  cleanup_fd int dir_fd = -1;
  uid_t old_fsuid = -1;

  if (pid == -1)
    dir = xstrdup ("self");
  else dir = xasprintf ("%d", pid);

  dir_fd = openat (proc_fd, dir, O_RDONLY | O_PATH);
  if (dir_fd < 0)
    die_with_error ("open /proc/%s failed", dir);

  if (map_root && parent_uid != 0 && sandbox_uid != 0)
    uid_map = xasprintf ("0 %d 1\n" "%d %d 1\n", overflow_uid, sandbox_uid, parent_uid);
  else uid_map = xasprintf ("%d %d 1\n", sandbox_uid, parent_uid);

  if (map_root && parent_gid != 0 && sandbox_gid != 0)
    gid_map = xasprintf ("0 %d 1\n" "%d %d 1\n", overflow_gid, sandbox_gid, parent_gid);
  else gid_map = xasprintf ("%d %d 1\n", sandbox_gid, parent_gid);

  
  if (is_privileged)
    old_fsuid = setfsuid (0);

  if (write_file_at (dir_fd, "uid_map", uid_map) != 0)
    die_with_error ("setting up uid map");

  if (deny_groups && write_file_at (dir_fd, "setgroups", "deny\n") != 0)
    {
      
      if (errno != ENOENT)
        die_with_error ("error writing to setgroups");
    }

  if (write_file_at (dir_fd, "gid_map", gid_map) != 0)
    die_with_error ("setting up gid map");

  if (is_privileged)
    {
      setfsuid (old_fsuid);
      if (setfsuid (-1) != real_uid)
        die ("Unable to re-set fsuid");
    }
}

static void privileged_op (int         privileged_op_socket, uint32_t    op, uint32_t    flags, const char *arg1, const char *arg2)




{
  if (privileged_op_socket != -1)
    {
      uint32_t buffer[2048];  
      PrivSepOp *op_buffer = (PrivSepOp *) buffer;
      size_t buffer_size = sizeof (PrivSepOp);
      uint32_t arg1_offset = 0, arg2_offset = 0;

      

      if (arg1 != NULL)
        {
          arg1_offset = buffer_size;
          buffer_size += strlen (arg1) + 1;
        }
      if (arg2 != NULL)
        {
          arg2_offset = buffer_size;
          buffer_size += strlen (arg2) + 1;
        }

      if (buffer_size >= sizeof (buffer))
        die ("privilege separation operation to large");

      op_buffer->op = op;
      op_buffer->flags = flags;
      op_buffer->arg1_offset = arg1_offset;
      op_buffer->arg2_offset = arg2_offset;
      if (arg1 != NULL)
        strcpy ((char *) buffer + arg1_offset, arg1);
      if (arg2 != NULL)
        strcpy ((char *) buffer + arg2_offset, arg2);

      if (write (privileged_op_socket, buffer, buffer_size) != buffer_size)
        die ("Can't write to privileged_op_socket");

      if (read (privileged_op_socket, buffer, 1) != 1)
        die ("Can't read from privileged_op_socket");

      return;
    }

  
  switch (op)
    {
    case PRIV_SEP_OP_DONE:
      break;

    case PRIV_SEP_OP_REMOUNT_RO_NO_RECURSIVE:
      if (bind_mount (proc_fd, NULL, arg2, BIND_READONLY) != 0)
        die_with_error ("Can't remount readonly on %s", arg2);
      break;

    case PRIV_SEP_OP_BIND_MOUNT:
      
      if (bind_mount (proc_fd, arg1, arg2, BIND_RECURSIVE | flags) != 0)
        die_with_error ("Can't bind mount %s on %s", arg1, arg2);
      break;

    case PRIV_SEP_OP_PROC_MOUNT:
      if (mount ("proc", arg1, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
        die_with_error ("Can't mount proc on %s", arg1);
      break;

    case PRIV_SEP_OP_TMPFS_MOUNT:
      {
        cleanup_free char *opt = label_mount ("mode=0755", opt_file_label);
        if (mount ("tmpfs", arg1, "tmpfs", MS_MGC_VAL | MS_NOSUID | MS_NODEV, opt) != 0)
          die_with_error ("Can't mount tmpfs on %s", arg1);
        break;
      }

    case PRIV_SEP_OP_DEVPTS_MOUNT:
      if (mount ("devpts", arg1, "devpts", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620") != 0)
        die_with_error ("Can't mount devpts on %s", arg1);
      break;

    case PRIV_SEP_OP_MQUEUE_MOUNT:
      if (mount ("mqueue", arg1, "mqueue", 0, NULL) != 0)
        die_with_error ("Can't mount mqueue on %s", arg1);
      break;

    case PRIV_SEP_OP_SET_HOSTNAME:
      
      if (!opt_unshare_uts)
        die ("Refusing to set hostname in original namespace");
      if (sethostname (arg1, strlen(arg1)) != 0)
        die_with_error ("Can't set hostname to %s", arg1);
      break;

    default:
      die ("Unexpected privileged op %d", op);
    }
}


static void setup_newroot (bool unshare_pid, int  privileged_op_socket)

{
  SetupOp *op;

  for (op = ops; op != NULL; op = op->next)
    {
      cleanup_free char *source = NULL;
      cleanup_free char *dest = NULL;
      int source_mode = 0;
      int i;

      if (op->source && op->type != SETUP_MAKE_SYMLINK)
        {
          source = get_oldroot_path (op->source);
          source_mode = get_file_mode (source);
          if (source_mode < 0)
            die_with_error ("Can't get type of source %s", op->source);
        }

      if (op->dest && (op->flags & NO_CREATE_DEST) == 0)
        {
          dest = get_newroot_path (op->dest);
          if (mkdir_with_parents (dest, 0755, FALSE) != 0)
            die_with_error ("Can't mkdir parents for %s", op->dest);
        }

      switch (op->type)
        {
        case SETUP_RO_BIND_MOUNT:
        case SETUP_DEV_BIND_MOUNT:
        case SETUP_BIND_MOUNT:
          if (source_mode == S_IFDIR)
            {
              if (mkdir (dest, 0755) != 0 && errno != EEXIST)
                die_with_error ("Can't mkdir %s", op->dest);
            }
          else if (ensure_file (dest, 0666) != 0)
            die_with_error ("Can't create file at %s", op->dest);

          privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, (op->type == SETUP_RO_BIND_MOUNT ? BIND_READONLY : 0) | (op->type == SETUP_DEV_BIND_MOUNT ? BIND_DEVICES : 0), source, dest);



          break;

        case SETUP_REMOUNT_RO_NO_RECURSIVE:
          privileged_op (privileged_op_socket, PRIV_SEP_OP_REMOUNT_RO_NO_RECURSIVE, BIND_READONLY, NULL, dest);
          break;

        case SETUP_MOUNT_PROC:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          if (unshare_pid)
            {
              
              privileged_op (privileged_op_socket, PRIV_SEP_OP_PROC_MOUNT, 0, dest, NULL);

            }
          else {
              
              privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, 0, "oldroot/proc", dest);

            }

          
          const char *cover_proc_dirs[] = { "sys", "sysrq-trigger", "irq", "bus" };
          for (i = 0; i < N_ELEMENTS (cover_proc_dirs); i++)
            {
              cleanup_free char *subdir = strconcat3 (dest, "/", cover_proc_dirs[i]);
              privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, BIND_READONLY, subdir, subdir);

            }

          break;

        case SETUP_MOUNT_DEV:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          privileged_op (privileged_op_socket, PRIV_SEP_OP_TMPFS_MOUNT, 0, dest, NULL);


          static const char *const devnodes[] = { "null", "zero", "full", "random", "urandom", "tty" };
          for (i = 0; i < N_ELEMENTS (devnodes); i++)
            {
              cleanup_free char *node_dest = strconcat3 (dest, "/", devnodes[i]);
              cleanup_free char *node_src = strconcat ("/oldroot/dev/", devnodes[i]);
              if (create_file (node_dest, 0666, NULL) != 0)
                die_with_error ("Can't create file %s/%s", op->dest, devnodes[i]);
              privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, BIND_DEVICES, node_src, node_dest);

            }

          static const char *const stdionodes[] = { "stdin", "stdout", "stderr" };
          for (i = 0; i < N_ELEMENTS (stdionodes); i++)
            {
              cleanup_free char *target = xasprintf ("/proc/self/fd/%d", i);
              cleanup_free char *node_dest = strconcat3 (dest, "/", stdionodes[i]);
              if (symlink (target, node_dest) < 0)
                die_with_error ("Can't create symlink %s/%s", op->dest, stdionodes[i]);
            }

          {
            cleanup_free char *pts = strconcat (dest, "/pts");
            cleanup_free char *ptmx = strconcat (dest, "/ptmx");
            cleanup_free char *shm = strconcat (dest, "/shm");

            if (mkdir (shm, 0755) == -1)
              die_with_error ("Can't create %s/shm", op->dest);

            if (mkdir (pts, 0755) == -1)
              die_with_error ("Can't create %s/devpts", op->dest);
            privileged_op (privileged_op_socket, PRIV_SEP_OP_DEVPTS_MOUNT, BIND_DEVICES, pts, NULL);


            if (symlink ("pts/ptmx", ptmx) != 0)
              die_with_error ("Can't make symlink at %s/ptmx", op->dest);
          }

          
          if (host_tty_dev != NULL && *host_tty_dev != 0)
            {
              cleanup_free char *src_tty_dev = strconcat ("/oldroot", host_tty_dev);
              cleanup_free char *dest_console = strconcat (dest, "/console");

              if (create_file (dest_console, 0666, NULL) != 0)
                die_with_error ("creating %s/console", op->dest);

              privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, BIND_DEVICES, src_tty_dev, dest_console);

            }

          break;

        case SETUP_MOUNT_TMPFS:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          privileged_op (privileged_op_socket, PRIV_SEP_OP_TMPFS_MOUNT, 0, dest, NULL);

          break;

        case SETUP_MOUNT_MQUEUE:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          privileged_op (privileged_op_socket, PRIV_SEP_OP_MQUEUE_MOUNT, 0, dest, NULL);

          break;

        case SETUP_MAKE_DIR:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          break;

        case SETUP_MAKE_FILE:
          {
            cleanup_fd int dest_fd = -1;

            dest_fd = creat (dest, 0666);
            if (dest_fd == -1)
              die_with_error ("Can't create file %s", op->dest);

            if (copy_file_data (op->fd, dest_fd) != 0)
              die_with_error ("Can't write data to file %s", op->dest);

            close (op->fd);
          }
          break;

        case SETUP_MAKE_BIND_FILE:
        case SETUP_MAKE_RO_BIND_FILE:
          {
            cleanup_fd int dest_fd = -1;
            char tempfile[] = "/bindfileXXXXXX";

            dest_fd = mkstemp (tempfile);
            if (dest_fd == -1)
              die_with_error ("Can't create tmpfile for %s", op->dest);

            if (copy_file_data (op->fd, dest_fd) != 0)
              die_with_error ("Can't write data to file %s", op->dest);

            close (op->fd);

            if (ensure_file (dest, 0666) != 0)
              die_with_error ("Can't create file at %s", op->dest);

            privileged_op (privileged_op_socket, PRIV_SEP_OP_BIND_MOUNT, (op->type == SETUP_MAKE_RO_BIND_FILE ? BIND_READONLY : 0), tempfile, dest);



            
            unlink (tempfile);
          }
          break;

        case SETUP_MAKE_SYMLINK:
          if (symlink (op->source, dest) != 0)
            die_with_error ("Can't make symlink at %s", op->dest);
          break;

        case SETUP_SET_HOSTNAME:
          privileged_op (privileged_op_socket, PRIV_SEP_OP_SET_HOSTNAME, 0, op->dest, NULL);

          break;

        default:
          die ("Unexpected type %d", op->type);
        }
    }
  privileged_op (privileged_op_socket, PRIV_SEP_OP_DONE, 0, NULL, NULL);
}


static void resolve_symlinks_in_ops (void)
{
  SetupOp *op;

  for (op = ops; op != NULL; op = op->next)
    {
      const char *old_source;

      switch (op->type)
        {
        case SETUP_RO_BIND_MOUNT:
        case SETUP_DEV_BIND_MOUNT:
        case SETUP_BIND_MOUNT:
          old_source = op->source;
          op->source = realpath (old_source, NULL);
          if (op->source == NULL)
            die_with_error ("Can't find source path %s", old_source);
          break;
        default:
          break;
        }
    }
}


static const char * resolve_string_offset (void    *buffer, size_t   buffer_size, uint32_t offset)


{
  if (offset == 0)
    return NULL;

  if (offset > buffer_size)
    die ("Invalid string offset %d (buffer size %zd)", offset, buffer_size);

  return (const char *) buffer + offset;
}

static uint32_t read_priv_sec_op (int          read_socket, void        *buffer, size_t       buffer_size, uint32_t    *flags, const char **arg1, const char **arg2)





{
  const PrivSepOp *op = (const PrivSepOp *) buffer;
  ssize_t rec_len;

  do rec_len = read (read_socket, buffer, buffer_size - 1);
  while (rec_len == -1 && errno == EINTR);

  if (rec_len < 0)
    die_with_error ("Can't read from unprivileged helper");

  if (rec_len == 0)
    exit (1); 

  if (rec_len < sizeof (PrivSepOp))
    die ("Invalid size %zd from unprivileged helper", rec_len);

  
  ((char *) buffer)[rec_len] = 0;

  *flags = op->flags;
  *arg1 = resolve_string_offset (buffer, rec_len, op->arg1_offset);
  *arg2 = resolve_string_offset (buffer, rec_len, op->arg2_offset);

  return op->op;
}

static void parse_args_recurse (int    *argcp, char ***argvp, bool    in_file, int    *total_parsed_argc_p)



{
  SetupOp *op;
  int argc = *argcp;
  char **argv = *argvp;
  
  static const uint32_t MAX_ARGS = 9000;

  if (*total_parsed_argc_p > MAX_ARGS)
    die ("Exceeded maximum number of arguments %u", MAX_ARGS);

  while (argc > 0)
    {
      const char *arg = argv[0];

      if (strcmp (arg, "--help") == 0)
        {
          usage (EXIT_SUCCESS, stdout);
        }
      else if (strcmp (arg, "--version") == 0)
        {
          printf ("%s\n", PACKAGE_STRING);
          exit (0);
        }
      else if (strcmp (arg, "--args") == 0)
        {
          int the_fd;
          char *endptr;
          char *data, *p;
          char *data_end;
          size_t data_len;
          cleanup_free char **data_argv = NULL;
          char **data_argv_copy;
          int data_argc;
          int i;

          if (in_file)
            die ("--args not supported in arguments file");

          if (argc < 2)
            die ("--args takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          data = load_file_data (the_fd, &data_len);
          if (data == NULL)
            die_with_error ("Can't read --args data");

          data_end = data + data_len;
          data_argc = 0;

          p = data;
          while (p != NULL && p < data_end)
            {
              data_argc++;
              (*total_parsed_argc_p)++;
              if (*total_parsed_argc_p > MAX_ARGS)
                die ("Exceeded maximum number of arguments %u", MAX_ARGS);
              p = memchr (p, 0, data_end - p);
              if (p != NULL)
                p++;
            }

          data_argv = xcalloc (sizeof (char *) * (data_argc + 1));

          i = 0;
          p = data;
          while (p != NULL && p < data_end)
            {
              
              data_argv[i++] = p;
              p = memchr (p, 0, data_end - p);
              if (p != NULL)
                p++;
            }

          data_argv_copy = data_argv; 
          parse_args_recurse (&data_argc, &data_argv_copy, TRUE, total_parsed_argc_p);

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--unshare-user") == 0)
        {
          opt_unshare_user = TRUE;
        }
      else if (strcmp (arg, "--unshare-user-try") == 0)
        {
          opt_unshare_user_try = TRUE;
        }
      else if (strcmp (arg, "--unshare-ipc") == 0)
        {
          opt_unshare_ipc = TRUE;
        }
      else if (strcmp (arg, "--unshare-pid") == 0)
        {
          opt_unshare_pid = TRUE;
        }
      else if (strcmp (arg, "--unshare-net") == 0)
        {
          opt_unshare_net = TRUE;
        }
      else if (strcmp (arg, "--unshare-uts") == 0)
        {
          opt_unshare_uts = TRUE;
        }
      else if (strcmp (arg, "--unshare-cgroup") == 0)
        {
          opt_unshare_cgroup = TRUE;
        }
      else if (strcmp (arg, "--unshare-cgroup-try") == 0)
        {
          opt_unshare_cgroup_try = TRUE;
        }
      else if (strcmp (arg, "--chdir") == 0)
        {
          if (argc < 2)
            die ("--chdir takes one argument");

          opt_chdir_path = argv[1];
          argv++;
          argc--;
        }
      else if (strcmp (arg, "--remount-ro") == 0)
        {
          SetupOp *op = setup_op_new (SETUP_REMOUNT_RO_NO_RECURSIVE);
          op->dest = argv[1];

          argv++;
          argc--;
        }
      else if (strcmp (arg, "--bind") == 0)
        {
          if (argc < 3)
            die ("--bind takes two arguments");

          op = setup_op_new (SETUP_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--ro-bind") == 0)
        {
          if (argc < 3)
            die ("--ro-bind takes two arguments");

          op = setup_op_new (SETUP_RO_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--dev-bind") == 0)
        {
          if (argc < 3)
            die ("--dev-bind takes two arguments");

          op = setup_op_new (SETUP_DEV_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--proc") == 0)
        {
          if (argc < 2)
            die ("--proc takes an argument");

          op = setup_op_new (SETUP_MOUNT_PROC);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--exec-label") == 0)
        {
          if (argc < 2)
            die ("--exec-label takes an argument");
          opt_exec_label = argv[1];
          die_unless_label_valid (opt_exec_label);

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--file-label") == 0)
        {
          if (argc < 2)
            die ("--file-label takes an argument");
          opt_file_label = argv[1];
          die_unless_label_valid (opt_file_label);
          if (label_create_file (opt_file_label))
            die_with_error ("--file-label setup failed");

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--dev") == 0)
        {
          if (argc < 2)
            die ("--dev takes an argument");

          op = setup_op_new (SETUP_MOUNT_DEV);
          op->dest = argv[1];
          opt_needs_devpts = TRUE;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--tmpfs") == 0)
        {
          if (argc < 2)
            die ("--tmpfs takes an argument");

          op = setup_op_new (SETUP_MOUNT_TMPFS);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--mqueue") == 0)
        {
          if (argc < 2)
            die ("--mqueue takes an argument");

          op = setup_op_new (SETUP_MOUNT_MQUEUE);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--dir") == 0)
        {
          if (argc < 2)
            die ("--dir takes an argument");

          op = setup_op_new (SETUP_MAKE_DIR);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--file") == 0)
        {
          int file_fd;
          char *endptr;

          if (argc < 3)
            die ("--file takes two arguments");

          file_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || file_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          op = setup_op_new (SETUP_MAKE_FILE);
          op->fd = file_fd;
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--bind-data") == 0)
        {
          int file_fd;
          char *endptr;

          if (argc < 3)
            die ("--bind-data takes two arguments");

          file_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || file_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          op = setup_op_new (SETUP_MAKE_BIND_FILE);
          op->fd = file_fd;
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--ro-bind-data") == 0)
        {
          int file_fd;
          char *endptr;

          if (argc < 3)
            die ("--ro-bind-data takes two arguments");

          file_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || file_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          op = setup_op_new (SETUP_MAKE_RO_BIND_FILE);
          op->fd = file_fd;
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--symlink") == 0)
        {
          if (argc < 3)
            die ("--symlink takes two arguments");

          op = setup_op_new (SETUP_MAKE_SYMLINK);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--lock-file") == 0)
        {
          if (argc < 2)
            die ("--lock-file takes an argument");

          (void) lock_file_new (argv[1]);

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--sync-fd") == 0)
        {
          int the_fd;
          char *endptr;

          if (argc < 2)
            die ("--sync-fd takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          opt_sync_fd = the_fd;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--block-fd") == 0)
        {
          int the_fd;
          char *endptr;

          if (argc < 2)
            die ("--block-fd takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          opt_block_fd = the_fd;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--info-fd") == 0)
        {
          int the_fd;
          char *endptr;

          if (argc < 2)
            die ("--info-fd takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          opt_info_fd = the_fd;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--seccomp") == 0)
        {
          int the_fd;
          char *endptr;

          if (argc < 2)
            die ("--seccomp takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          opt_seccomp_fd = the_fd;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--setenv") == 0)
        {
          if (argc < 3)
            die ("--setenv takes two arguments");

          xsetenv (argv[1], argv[2], 1);

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--unsetenv") == 0)
        {
          if (argc < 2)
            die ("--unsetenv takes an argument");

          xunsetenv (argv[1]);

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--uid") == 0)
        {
          int the_uid;
          char *endptr;

          if (argc < 2)
            die ("--uid takes an argument");

          the_uid = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_uid < 0)
            die ("Invalid uid: %s", argv[1]);

          opt_sandbox_uid = the_uid;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--gid") == 0)
        {
          int the_gid;
          char *endptr;

          if (argc < 2)
            die ("--gid takes an argument");

          the_gid = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_gid < 0)
            die ("Invalid gid: %s", argv[1]);

          opt_sandbox_gid = the_gid;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--hostname") == 0)
        {
          if (argc < 2)
            die ("--hostname takes an argument");

          op = setup_op_new (SETUP_SET_HOSTNAME);
          op->dest = argv[1];
          op->flags = NO_CREATE_DEST;

          opt_sandbox_hostname = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (*arg == '-')
        {
          die ("Unknown option %s", arg);
        }
      else {
          break;
        }

      argv++;
      argc--;
    }

  *argcp = argc;
  *argvp = argv;
}

static void parse_args (int    *argcp, char ***argvp)

{
  int total_parsed_argc = *argcp;

  parse_args_recurse (argcp, argvp, FALSE, &total_parsed_argc);
}

static void read_overflowids (void)
{
  cleanup_free char *uid_data = NULL;
  cleanup_free char *gid_data = NULL;

  uid_data = load_file_at (AT_FDCWD, "/proc/sys/kernel/overflowuid");
  if (uid_data == NULL)
    die_with_error ("Can't read /proc/sys/kernel/overflowuid");

  overflow_uid = strtol (uid_data, NULL, 10);
  if (overflow_uid == 0)
    die ("Can't parse /proc/sys/kernel/overflowuid");

  gid_data = load_file_at (AT_FDCWD, "/proc/sys/kernel/overflowgid");
  if (gid_data == NULL)
    die_with_error ("Can't read /proc/sys/kernel/overflowgid");

  overflow_gid = strtol (gid_data, NULL, 10);
  if (overflow_gid == 0)
    die ("Can't parse /proc/sys/kernel/overflowgid");
}

int main (int    argc, char **argv)

{
  mode_t old_umask;
  cleanup_free char *base_path = NULL;
  int clone_flags;
  char *old_cwd = NULL;
  pid_t pid;
  int event_fd = -1;
  int child_wait_fd = -1;
  const char *new_cwd;
  uid_t ns_uid;
  gid_t ns_gid;
  struct stat sbuf;
  uint64_t val;
  int res UNUSED;

  real_uid = getuid ();
  real_gid = getgid ();

  
  acquire_privs ();

  
  if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_NO_NEW_CAPS) failed");

  

  read_overflowids ();

  argv0 = argv[0];

  if (isatty (1))
    host_tty_dev = ttyname (1);

  argv++;
  argc--;

  if (argc == 0)
    usage (EXIT_FAILURE, stderr);

  parse_args (&argc, &argv);

  
  if (!is_privileged && getuid () != 0)
    opt_unshare_user = TRUE;

  if (opt_unshare_user_try && stat ("/proc/self/ns/user", &sbuf) == 0)
    {
      bool disabled = FALSE;

      
      if (stat ("/sys/module/user_namespace/parameters/enable", &sbuf) == 0)
        {
          cleanup_free char *enable = NULL;
          enable = load_file_at (AT_FDCWD, "/sys/module/user_namespace/parameters/enable");
          if (enable != NULL && enable[0] == 'N')
            disabled = TRUE;
        }

      

      if (!disabled)
        opt_unshare_user = TRUE;
    }

  if (argc == 0)
    usage (EXIT_FAILURE, stderr);

  __debug__ (("Creating root mount point\n"));

  if (opt_sandbox_uid == -1)
    opt_sandbox_uid = real_uid;
  if (opt_sandbox_gid == -1)
    opt_sandbox_gid = real_gid;

  if (!opt_unshare_user && opt_sandbox_uid != real_uid)
    die ("Specifying --uid requires --unshare-user");

  if (!opt_unshare_user && opt_sandbox_gid != real_gid)
    die ("Specifying --gid requires --unshare-user");

  if (!opt_unshare_uts && opt_sandbox_hostname != NULL)
    die ("Specifying --hostname requires --unshare-uts");

  
  proc_fd = open ("/proc", O_RDONLY | O_PATH);
  if (proc_fd == -1)
    die_with_error ("Can't open /proc");

  
  base_path = xasprintf ("/run/user/%d/.bubblewrap", real_uid);
  if (mkdir (base_path, 0755) && errno != EEXIST)
    {
      free (base_path);
      base_path = xasprintf ("/tmp/.bubblewrap-%d", real_uid);
      if (mkdir (base_path, 0755) && errno != EEXIST)
        die_with_error ("Creating root mountpoint failed");
    }

  __debug__ (("creating new namespace\n"));

  if (opt_unshare_pid)
    {
      event_fd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
      if (event_fd == -1)
        die_with_error ("eventfd()");
    }

  
  block_sigchild ();

  clone_flags = SIGCHLD | CLONE_NEWNS;
  if (opt_unshare_user)
    clone_flags |= CLONE_NEWUSER;
  if (opt_unshare_pid)
    clone_flags |= CLONE_NEWPID;
  if (opt_unshare_net)
    clone_flags |= CLONE_NEWNET;
  if (opt_unshare_ipc)
    clone_flags |= CLONE_NEWIPC;
  if (opt_unshare_uts)
    clone_flags |= CLONE_NEWUTS;
  if (opt_unshare_cgroup)
    {
      if (stat ("/proc/self/ns/cgroup", &sbuf))
        {
          if (errno == ENOENT)
            die ("Cannot create new cgroup namespace because the kernel does not support it");
          else die_with_error ("stat on /proc/self/ns/cgroup failed");
        }
      clone_flags |= CLONE_NEWCGROUP;
    }
  if (opt_unshare_cgroup_try)
    if (!stat ("/proc/self/ns/cgroup", &sbuf))
      clone_flags |= CLONE_NEWCGROUP;

  child_wait_fd = eventfd (0, EFD_CLOEXEC);
  if (child_wait_fd == -1)
    die_with_error ("eventfd()");

  pid = raw_clone (clone_flags, NULL);
  if (pid == -1)
    {
      if (opt_unshare_user)
        {
          if (errno == EINVAL)
            die ("Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems.");
          else if (errno == EPERM && !is_privileged)
            die ("No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.");
        }

      die_with_error ("Creating new namespace failed");
    }

  ns_uid = opt_sandbox_uid;
  ns_gid = opt_sandbox_gid;

  if (pid != 0)
    {
      

      if (is_privileged && opt_unshare_user)
        {
          
          write_uid_gid_map (ns_uid, real_uid, ns_gid, real_gid, pid, TRUE, opt_needs_devpts);

        }

      

      
      drop_privs ();

      
      val = 1;
      res = write (child_wait_fd, &val, 8);
      
      close (child_wait_fd);

      if (opt_info_fd != -1)
        {
          cleanup_free char *output = xasprintf ("{\n    \"child-pid\": %i\n}\n", pid);
          size_t len = strlen (output);
          if (write (opt_info_fd, output, len) != len)
            die_with_error ("Write to info_fd");
          close (opt_info_fd);
        }

      monitor_child (event_fd, pid);
      exit (0); 
    }

  

  if (opt_info_fd != -1)
    close (opt_info_fd);

  
  res = read (child_wait_fd, &val, 8);
  close (child_wait_fd);

  
  switch_to_user_with_privs ();

  if (opt_unshare_net && loopback_setup () != 0)
    die ("Can't create loopback device");

  ns_uid = opt_sandbox_uid;
  ns_gid = opt_sandbox_gid;
  if (!is_privileged && opt_unshare_user)
    {
      

      if (opt_needs_devpts)
        {
          
          ns_uid = 0;
          ns_gid = 0;
        }

      write_uid_gid_map (ns_uid, real_uid, ns_gid, real_gid, -1, TRUE, FALSE);

    }

  old_umask = umask (0);

  
  resolve_symlinks_in_ops ();

  
  if (mount (NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
    die_with_error ("Failed to make / slave");

  
  if (mount ("", base_path, "tmpfs", MS_NODEV | MS_NOSUID, NULL) != 0)
    die_with_error ("Failed to mount tmpfs");

  old_cwd = get_current_dir_name ();

  
  if (chdir (base_path) != 0)
    die_with_error ("chdir base_path");

  

  if (mkdir ("newroot", 0755))
    die_with_error ("Creating newroot failed");

  if (mkdir ("oldroot", 0755))
    die_with_error ("Creating oldroot failed");

  if (pivot_root (base_path, "oldroot"))
    die_with_error ("pivot_root");

  if (chdir ("/") != 0)
    die_with_error ("chdir / (base path)");

  if (is_privileged)
    {
      pid_t child;
      int privsep_sockets[2];

      if (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, privsep_sockets) != 0)
        die_with_error ("Can't create privsep socket");

      child = fork ();
      if (child == -1)
        die_with_error ("Can't fork unprivileged helper");

      if (child == 0)
        {
          
          drop_privs ();
          close (privsep_sockets[0]);
          setup_newroot (opt_unshare_pid, privsep_sockets[1]);
          exit (0);
        }
      else {
          int status;
          uint32_t buffer[2048];  
          uint32_t op, flags;
          const char *arg1, *arg2;
          cleanup_fd int unpriv_socket = -1;

          unpriv_socket = privsep_sockets[0];
          close (privsep_sockets[1]);

          do {
              op = read_priv_sec_op (unpriv_socket, buffer, sizeof (buffer), &flags, &arg1, &arg2);
              privileged_op (-1, op, flags, arg1, arg2);
              if (write (unpriv_socket, buffer, 1) != 1)
                die ("Can't write to op_socket");
            }
          while (op != PRIV_SEP_OP_DONE);

          waitpid (child, &status, 0);
          
        }
    }
  else {
      setup_newroot (opt_unshare_pid, -1);
    }

  
  if (mount ("oldroot", "oldroot", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    die_with_error ("Failed to make old root rprivate");

  if (umount2 ("oldroot", MNT_DETACH))
    die_with_error ("unmount old root");

  if (opt_unshare_user && (ns_uid != opt_sandbox_uid || ns_gid != opt_sandbox_gid))
    {
      

      if (unshare (CLONE_NEWUSER))
        die_with_error ("unshare user ns");

      write_uid_gid_map (opt_sandbox_uid, ns_uid, opt_sandbox_gid, ns_gid, -1, FALSE, FALSE);

    }

  
  if (chdir ("/newroot") != 0)
    die_with_error ("chdir newroot");
  if (chroot ("/newroot") != 0)
    die_with_error ("chroot /newroot");
  if (chdir ("/") != 0)
    die_with_error ("chdir /");

  
  drop_privs ();

  if (opt_block_fd != -1)
    {
      char b[1];
      read (opt_block_fd, b, 1);
      close (opt_block_fd);
    }

  if (opt_seccomp_fd != -1)
    {
      cleanup_free char *seccomp_data = NULL;
      size_t seccomp_len;
      struct sock_fprog prog;

      seccomp_data = load_file_data (opt_seccomp_fd, &seccomp_len);
      if (seccomp_data == NULL)
        die_with_error ("Can't read seccomp data");

      if (seccomp_len % 8 != 0)
        die ("Invalid seccomp data, must be multiple of 8");

      prog.len = seccomp_len / 8;
      prog.filter = (struct sock_filter *) seccomp_data;

      close (opt_seccomp_fd);

      if (prctl (PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        die_with_error ("prctl(PR_SET_SECCOMP)");
    }

  umask (old_umask);

  new_cwd = "/";
  if (opt_chdir_path)
    {
      if (chdir (opt_chdir_path))
        die_with_error ("Can't chdir to %s", opt_chdir_path);
      new_cwd = opt_chdir_path;
    }
  else if (chdir (old_cwd) == 0)
    {
      
      new_cwd = old_cwd;
    }
  else {
      
      const char *home = getenv ("HOME");
      if (home != NULL && chdir (home) == 0)
        new_cwd = home;
    }
  xsetenv ("PWD", new_cwd, 1);
  free (old_cwd);

  __debug__ (("forking for child\n"));

  if (opt_unshare_pid || lock_files != NULL || opt_sync_fd != -1)
    {
      

      pid = fork ();
      if (pid == -1)
        die_with_error ("Can't fork for pid 1");

      if (pid != 0)
        {
          
          {
            int dont_close[3];
            int j = 0;
            if (event_fd != -1)
              dont_close[j++] = event_fd;
            if (opt_sync_fd != -1)
              dont_close[j++] = opt_sync_fd;
            dont_close[j++] = -1;
            fdwalk (proc_fd, close_extra_fds, dont_close);
          }

          return do_init (event_fd, pid);
        }
    }

  __debug__ (("launch executable %s\n", argv[0]));

  if (proc_fd != -1)
    close (proc_fd);

  if (opt_sync_fd != -1)
    close (opt_sync_fd);

  
  unblock_sigchild ();

  if (setsid () == (pid_t) -1)
    die_with_error ("setsid");

  if (label_exec (opt_exec_label) == -1)
    die_with_error ("label_exec %s", argv[0]);

  if (execvp (argv[0], argv) == -1)
    die_with_error ("execvp %s", argv[0]);

  return 0;
}
