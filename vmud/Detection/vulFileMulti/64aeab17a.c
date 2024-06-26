


























typedef struct _resolver {
    struct _oe_resolver base;
    uint32_t magic;
} resolver_t;

static resolver_t* _cast_resolver(const oe_resolver_t* device)
{
    resolver_t* resolver = (resolver_t*)device;

    if (resolver == NULL || resolver->magic != RESOLV_MAGIC)
        return NULL;

    return resolver;
}

static resolver_t _hostresolver;

static int _hostresolver_getnameinfo( oe_resolver_t* dev, const struct oe_sockaddr* sa, oe_socklen_t salen, char* host, oe_socklen_t hostlen, char* serv, oe_socklen_t servlen, int flags)







{
    int ret = OE_EAI_FAIL;

    OE_UNUSED(dev);

    oe_errno = 0;

    if (oe_syscall_getnameinfo_ocall( &ret, sa, salen, host, hostlen, serv, servlen, flags) != OE_OK)
    {
        goto done;
    }

done:

    return ret;
}

static int _hostresolver_getaddrinfo( oe_resolver_t* resolver, const char* node, const char* service, const struct oe_addrinfo* hints, struct oe_addrinfo** res)




{
    int ret = OE_EAI_FAIL;
    uint64_t handle = 0;
    struct oe_addrinfo* head = NULL;
    struct oe_addrinfo* tail = NULL;
    struct oe_addrinfo* p = NULL;

    OE_UNUSED(resolver);

    if (res)
        *res = NULL;

    if (!res)
    {
        ret = OE_EAI_SYSTEM;
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    
    {
        int retval = OE_EAI_FAIL;

        if (oe_syscall_getaddrinfo_open_ocall( &retval, node, service, hints, &handle) != OE_OK)
        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        if (!handle)
        {
            ret = retval;
            goto done;
        }
    }

    
    for (;;)
    {
        int retval = 0;
        size_t canonnamelen = 0;

        if (!(p = oe_calloc(1, sizeof(struct oe_addrinfo))))
        {
            ret = OE_EAI_MEMORY;
            goto done;
        }

        
        if (oe_syscall_getaddrinfo_read_ocall( &retval, handle, &p->ai_flags, &p->ai_family, &p->ai_socktype, &p->ai_protocol, p->ai_addrlen, &p->ai_addrlen, NULL, canonnamelen, &canonnamelen, NULL) != OE_OK)











        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        
        if (retval == 1)
            break;

        
        if (retval != -1 || oe_errno != OE_ENAMETOOLONG)
        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(oe_errno);
        }

        if (p->ai_addrlen && !(p->ai_addr = oe_calloc(1, p->ai_addrlen)))
        {
            ret = OE_EAI_MEMORY;
            goto done;
        }

        if (canonnamelen && !(p->ai_canonname = oe_calloc(1, canonnamelen)))
        {
            ret = OE_EAI_MEMORY;
            goto done;
        }

        if (oe_syscall_getaddrinfo_read_ocall( &retval, handle, &p->ai_flags, &p->ai_family, &p->ai_socktype, &p->ai_protocol, p->ai_addrlen, &p->ai_addrlen, p->ai_addr, canonnamelen, &canonnamelen, p->ai_canonname) != OE_OK)











        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        
        if (tail)
        {
            tail->ai_next = p;
            tail = p;
        }
        else {
            head = p;
            tail = p;
        }

        p = NULL;
    }

    
    if (handle)
    {
        int retval = -1;

        if (oe_syscall_getaddrinfo_close_ocall(&retval, handle) != OE_OK)
        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        handle = 0;

        if (retval != 0)
        {
            ret = OE_EAI_SYSTEM;
            OE_RAISE_ERRNO(oe_errno);
        }
    }

    
    if (!head)
    {
        ret = OE_EAI_SYSTEM;
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    *res = head;
    head = NULL;
    tail = NULL;
    ret = 0;

done:

    if (handle)
    {
        int retval;
        oe_syscall_getaddrinfo_close_ocall(&retval, handle);
    }

    if (head)
        oe_freeaddrinfo(head);

    if (p)
        oe_freeaddrinfo(p);

    return ret;
}

static int _hostresolver_release(oe_resolver_t* resolv_)
{
    int ret = -1;
    resolver_t* resolver = _cast_resolver(resolv_);

    oe_errno = 0;

    if (!resolver)
        OE_RAISE_ERRNO(OE_EINVAL);

    
    ret = 0;

done:
    return ret;
}


static oe_resolver_ops_t _ops = {
    .getaddrinfo = _hostresolver_getaddrinfo, .getnameinfo = _hostresolver_getnameinfo, .release = _hostresolver_release };





static resolver_t _hostresolver = {
    .base.type = OE_RESOLVER_TYPE_HOST, .base.ops = &_ops, .magic = RESOLV_MAGIC };




oe_result_t oe_load_module_host_resolver(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static bool _loaded = false;

    oe_spin_lock(&_lock);

    if (!_loaded)
    {
        if (oe_register_resolver(&_hostresolver.base) != 0)
            OE_RAISE_ERRNO(oe_errno);

        _loaded = true;
    }

    result = OE_OK;

done:
    oe_spin_unlock(&_lock);

    return result;
}
