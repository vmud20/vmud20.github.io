






























typedef struct _mapping {
    
    int fd;

    
    struct oe_epoll_event event;
} mapping_t;


typedef struct _device {
    struct _oe_device base;

    
    uint32_t magic;
} device_t;

typedef struct _epoll {
    oe_fd_t base;

    
    uint32_t magic;

    
    oe_host_fd_t host_fd;

    
    mapping_t* map;
    size_t map_size;
    size_t map_capacity;

    
    oe_mutex_t lock;
} epoll_t;

static oe_epoll_ops_t _get_epoll_ops(void);

static device_t* _cast_device(const oe_device_t* device_)
{
    device_t* device = (device_t*)device_;

    if (device == NULL || device->magic != DEVICE_MAGIC)
        return NULL;

    return device;
}

static epoll_t* _cast_epoll(const oe_fd_t* epoll_)
{
    epoll_t* epoll = (epoll_t*)epoll_;

    if (epoll == NULL || epoll->magic != EPOLL_MAGIC)
        return NULL;

    return epoll;
}


static int _map_reserve(epoll_t* epoll, size_t new_capacity)
{
    int ret = -1;

    new_capacity = oe_round_up_to_multiple(new_capacity, MAP_CHUNK_SIZE);

    if (new_capacity > epoll->map_capacity)
    {
        mapping_t* p;
        const size_t n = new_capacity;

        
        if (!(p = oe_realloc(epoll->map, n * sizeof(mapping_t))))
            goto done;

        
        {
            const size_t num_bytes = (n - epoll->map_size) * sizeof(mapping_t);
            void* ptr = p + epoll->map_size;

            if (oe_memset_s(ptr, num_bytes, 0, num_bytes) != OE_OK)
                goto done;
        }

        epoll->map = p;
        epoll->map_capacity = n;
    }

    ret = 0;

done:
    return ret;
}


static mapping_t* _map_find(epoll_t* epoll, int fd)
{
    size_t i;

    for (i = 0; i < epoll->map_size; i++)
    {
        mapping_t* mapping = &epoll->map[i];

        if (mapping->fd == fd)
            return mapping;
    }

    
    return NULL;
}


static oe_fd_t* _epoll_create1(oe_device_t* device_, int32_t flags)
{
    oe_fd_t* ret = NULL;
    epoll_t* epoll = NULL;
    device_t* device = _cast_device(device_);
    oe_host_fd_t retval;

    oe_errno = 0;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(epoll = oe_calloc(1, sizeof(epoll_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (oe_syscall_epoll_create1_ocall(&retval, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (retval < 0)
        goto done;

    epoll->base.type = OE_FD_TYPE_EPOLL;
    epoll->base.ops.epoll = _get_epoll_ops();
    epoll->magic = EPOLL_MAGIC;
    epoll->host_fd = retval;

    ret = &epoll->base;
    epoll = NULL;

done:

    if (epoll)
        oe_free(epoll);

    return ret;
}


static oe_fd_t* _epoll_create(oe_device_t* device_, int size)
{
    
    OE_UNUSED(size);

    
    return _epoll_create1(device_, 0);
}

static int _epoll_ctl_add(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;
    bool locked = false;

    oe_errno = 0;

    
    if (!epoll || !event)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    
    host_epfd = epoll->host_fd;

    
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    
    {
        const size_t num_bytes = sizeof(host_event);

        if (oe_memset_s(&host_event, num_bytes, 0, num_bytes) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    
    locked = true;
    oe_mutex_lock(&epoll->lock);

    if (oe_syscall_epoll_ctl_ocall( &retval, host_epfd, OE_EPOLL_CTL_ADD, host_fd, &host_event) != OE_OK)

    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (retval == 0)
    {
        if (_map_reserve(epoll, epoll->map_size + 1) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);

        epoll->map[epoll->map_size].fd = fd;
        epoll->map[epoll->map_size].event = *event;
        epoll->map_size++;
    }

    ret = retval;

done:

    if (locked)
        oe_mutex_unlock(&epoll->lock);

    return ret;
}

static int _epoll_ctl_mod(epoll_t* epoll, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    struct oe_epoll_event host_event;
    int retval;
    bool locked = false;

    oe_errno = 0;

    
    if (!epoll || !event)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    
    host_epfd = epoll->host_fd;

    
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    
    {
        const size_t num_bytes = sizeof(host_event);

        if (oe_memset_s(&host_event, num_bytes, 0, num_bytes) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        host_event.events = event->events;
        host_event.data.fd = fd;
    }

    
    locked = true;
    oe_mutex_lock(&epoll->lock);

    if (oe_syscall_epoll_ctl_ocall( &retval, host_epfd, OE_EPOLL_CTL_MOD, host_fd, &host_event) != OE_OK)

    {
        OE_RAISE_ERRNO(oe_errno);
    }

    
    if (retval == 0)
    {
        mapping_t* const mapping = _map_find(epoll, fd);
        if (!mapping)
            OE_RAISE_ERRNO(OE_ENOENT);

        mapping->event = *event;
    }

    ret = 0;

done:
    if (locked)
        oe_mutex_unlock(&epoll->lock);

    return ret;
}

static int _epoll_ctl_del(epoll_t* epoll, int fd)
{
    int ret = -1;
    oe_fd_t* desc;
    oe_host_fd_t host_epfd;
    oe_host_fd_t host_fd;
    int retval;
    bool locked = false;

    oe_errno = 0;

    
    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    
    host_epfd = epoll->host_fd;

    
    if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    
    locked = true;
    oe_mutex_lock(&epoll->lock);

    if (oe_syscall_epoll_ctl_ocall( &retval, host_epfd, OE_EPOLL_CTL_DEL, host_fd, NULL) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    
    if (retval == 0)
    {
        bool found = false;

        for (size_t i = 0; i < epoll->map_size; i++)
        {
            if (epoll->map[i].fd == fd)
            {
                
                epoll->map[i] = epoll->map[--epoll->map_size];
                found = true;
                break;
            }
        }

        if (!found)
            OE_RAISE_ERRNO(OE_ENOENT);
    }

    ret = 0;

done:
    if (locked)
        oe_mutex_unlock(&epoll->lock);

    return ret;
}


static int _epoll_ctl( oe_fd_t* epoll_, int op, int fd, struct oe_epoll_event* event)



{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
        {
            ret = _epoll_ctl_add(epoll, fd, event);
            goto done;
        }

        case OE_EPOLL_CTL_MOD:
        {
            ret = _epoll_ctl_mod(epoll, fd, event);
            goto done;
        }

        case OE_EPOLL_CTL_DEL:
        {
            ret = _epoll_ctl_del(epoll, fd);
            goto done;
        }

        default:
        {
            OE_RAISE_ERRNO(OE_EINVAL);
            return -1;
        }
    }

    ret = 0;

done:
    return ret;
}


static int _epoll_wait( oe_fd_t* epoll_, struct oe_epoll_event* events, int maxevents, int timeout)



{
    int ret = -1;
    int retval;
    bool locked = false;
    epoll_t* epoll = _cast_epoll(epoll_);
    oe_host_fd_t host_epfd = -1;

    if (!epoll || !events || maxevents <= 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_errno = 0;

    if ((host_epfd = epoll_->ops.fd.get_host_fd(epoll_)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_epoll_wait_ocall( &retval, host_epfd, events, (unsigned int)maxevents, timeout) != OE_OK)

    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (retval > 0)
    {
        if (retval > maxevents)
            OE_RAISE_ERRNO(OE_EINVAL);

        locked = true;
        oe_mutex_lock(&epoll->lock);

        for (int i = 0; i < retval; i++)
        {
            struct oe_epoll_event* const event = &events[i];
            const mapping_t* const mapping = _map_find(epoll, event->data.fd);

            if (mapping)
                event->data.u64 = mapping->event.data.u64;
            else {
                
                
                --retval;
                *event = events[retval];
                --i;
            }
        }
    }

    ret = (int)retval;

done:
    if (locked)
        oe_mutex_unlock(&epoll->lock);

    return ret;
}


static int _epoll_close(oe_fd_t* epoll_)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);
    int retval = -1;

    oe_errno = 0;

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    if (oe_syscall_epoll_close_ocall(&retval, epoll->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (retval == -1)
        OE_RAISE_ERRNO(oe_errno);

    if (epoll->map)
        oe_free(epoll->map);

    oe_free(epoll);

    ret = 0;

done:
    return ret;
}

static int _epoll_release(oe_device_t* device_)
{
    int ret = -1;
    device_t* device = _cast_device(device_);

    oe_errno = 0;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_free(device);

    ret = 0;

done:
    return ret;
}

static oe_host_fd_t _epoll_get_host_fd(oe_fd_t* epoll_)
{
    epoll_t* epoll = _cast_epoll(epoll_);
    return epoll->host_fd;
}

static int _epoll_ioctl(oe_fd_t* desc, unsigned long request, uint64_t arg)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(desc);
    uint64_t argsize = 0;
    void* argout = NULL;

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    switch (request)
    {
        default:
            OE_RAISE_ERRNO(OE_ENOTTY);
    }

    
    if (oe_syscall_ioctl_ocall( &ret, epoll->host_fd, request, arg, argsize, argout) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static int _epoll_fcntl(oe_fd_t* desc, int cmd, uint64_t arg)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(desc);
    void* argout = NULL;
    uint64_t argsize = 0;

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (cmd)
    {
        case OE_F_GETFD:
        case OE_F_SETFD:
        case OE_F_GETFL:
        case OE_F_SETFL:
            break;

        case OE_F_GETLK64:
        case OE_F_OFD_GETLK:
            argsize = sizeof(struct oe_flock);
            argout = (void*)arg;
            break;

        case OE_F_SETLKW64:
        case OE_F_SETLK64:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        case OE_F_OFD_SETLK:
        case OE_F_OFD_SETLKW:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        
        default:
        case OE_F_DUPFD: 
        case OE_F_SETOWN:
        case OE_F_GETOWN:
        case OE_F_SETSIG:
        case OE_F_GETSIG:
        case OE_F_SETOWN_EX:
        case OE_F_GETOWN_EX:
        case OE_F_GETOWNER_UIDS:
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_syscall_fcntl_ocall( &ret, epoll->host_fd, cmd, arg, argsize, argout) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_read(oe_fd_t* epoll_, void* buf, size_t count)
{
    ssize_t ret = -1;
    epoll_t* file = _cast_epoll(epoll_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    if (oe_syscall_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_write(oe_fd_t* epoll_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);

    oe_errno = 0;

    
    if (oe_syscall_write_ocall(&ret, epoll->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _epoll_readv( oe_fd_t* desc, const struct oe_iovec* iov, int iovcnt)


{
    ssize_t ret = -1;
    epoll_t* file = _cast_epoll(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || (iovcnt && !iov) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    
    if (oe_syscall_readv_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    
    if (oe_iov_sync(iov, iovcnt, buf, buf_size) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _epoll_writev( oe_fd_t* desc, const struct oe_iovec* iov, int iovcnt)


{
    ssize_t ret = -1;
    epoll_t* file = _cast_epoll(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || (iovcnt && !iov) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    
    if (oe_syscall_writev_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static int _epoll_dup(oe_fd_t* epoll_, oe_fd_t** new_epoll_out)
{
    int ret = -1;
    epoll_t* epoll = _cast_epoll(epoll_);
    epoll_t* new_epoll = NULL;
    oe_host_fd_t retval;

    oe_errno = 0;

    
    if (!new_epoll_out)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!epoll)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    {
        if (oe_syscall_dup_ocall(&retval, epoll->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    
    {
        if (!(new_epoll = oe_calloc(1, sizeof(epoll_t))))
            OE_RAISE_ERRNO(oe_errno);

        new_epoll->base.type = OE_FD_TYPE_EPOLL;
        new_epoll->base.ops.epoll = _get_epoll_ops();
        new_epoll->magic = EPOLL_MAGIC;
        new_epoll->host_fd = retval;

        if (epoll->map && epoll->map_size)
        {
            mapping_t* map;

            if (!(map = oe_calloc(epoll->map_size, sizeof(mapping_t))))
                OE_RAISE_ERRNO(OE_ENOMEM);

            memcpy(map, epoll->map, epoll->map_size * sizeof(mapping_t));
            new_epoll->map = map;
            new_epoll->map_size = epoll->map_size;
        }

        *new_epoll_out = &new_epoll->base;
        new_epoll = NULL;
    }

    ret = 0;

done:

    if (new_epoll)
        oe_free(new_epoll);

    return ret;
}

static void _epoll_on_close(oe_fd_t* epoll_, int fd)
{
    epoll_t* const epoll = _cast_epoll(epoll_);
    oe_assert(epoll);

    oe_assert(fd >= 0);

    oe_mutex_lock(&epoll->lock);

    
    for (size_t i = 0; i < epoll->map_size; i++)
    {
        if (epoll->map[i].fd == fd)
        {
            
            epoll->map[i] = epoll->map[--epoll->map_size];
            break;
        }
    }

    oe_mutex_unlock(&epoll->lock);
}

static oe_epoll_ops_t _epoll_ops = {
    .fd.read = _epoll_read, .fd.write = _epoll_write, .fd.readv = _epoll_readv, .fd.writev = _epoll_writev, .fd.dup = _epoll_dup, .fd.ioctl = _epoll_ioctl, .fd.fcntl = _epoll_fcntl, .fd.close = _epoll_close, .fd.get_host_fd = _epoll_get_host_fd, .epoll_ctl = _epoll_ctl, .epoll_wait = _epoll_wait, .on_close = _epoll_on_close, };












static oe_epoll_ops_t _get_epoll_ops(void)
{
    return _epoll_ops;
}


static device_t _device = {
    .base.type = OE_DEVICE_TYPE_EPOLL, .base.name = OE_DEVICE_NAME_HOST_EPOLL, .base.ops.epoll = {


        .base.release = _epoll_release, .epoll_create = _epoll_create, .epoll_create1 = _epoll_create1, }, .magic = DEVICE_MAGIC, };






oe_result_t oe_load_module_host_epoll(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static bool _loaded = false;

    oe_spin_lock(&_lock);

    if (!_loaded)
    {
        if (oe_device_table_set(OE_DEVID_HOST_EPOLL, &_device.base) != 0)
        {
            
            oe_errno = 0;
            OE_RAISE(OE_FAILURE);
        }

        _loaded = true;
    }

    result = OE_OK;

done:
    oe_spin_unlock(&_lock);

    return result;
}
