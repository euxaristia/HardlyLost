# cython: language_level=3

cdef extern from "stddef.h":
    ctypedef unsigned long size_t

cdef extern from "sys/types.h":
    ctypedef long off_t
    ctypedef long ssize_t

cdef extern from "unistd.h":
    int getpid()
    int close(int fd)
    int ftruncate(int fd, off_t length)
    int unlink(const char *pathname)
    int mkstemp(char *template)
    int fork()
    int execl(const char *path, const char *arg, ...)
    void _exit(int status)
    long lseek(int fd, long offset, int whence)
    ssize_t read(int fd, void *buf, size_t count)
    ssize_t write(int fd, const void *buf, size_t count)

cdef extern from "time.h":
    ctypedef long time_t

    cdef struct timespec:
        time_t tv_sec
        long tv_nsec

    int clock_gettime(int clk_id, timespec *tp)

    cdef enum:
        CLOCK_MONOTONIC

cdef extern from "sys/wait.h":
    int waitpid(int pid, int *status, int options)

cdef extern from "sys/mman.h":
    void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    int munmap(void *addr, size_t length)
    cdef enum:
        PROT_READ
        PROT_WRITE
        MAP_SHARED

cdef extern from "fcntl.h":
    cdef enum:
        O_RDONLY

cdef extern from "string.h":
    void *memset(void *s, int c, size_t n)
    void *memcpy(void *dest, const void *src, size_t n)
    size_t strlen(const char *s)

cdef extern from "sys/stat.h":
    cdef struct stat_t "stat":
        pass
    int c_stat "stat"(const char *pathname, stat_t *buf)

cdef extern from "stdlib.h":
    void *malloc(size_t size)
    void free(void *ptr)

cdef extern from "errno.h":
    int errno

cdef int SEEK_SET = 0


cdef inline double _now():
    cdef timespec ts
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return ts.tv_sec + ts.tv_nsec / 1e9


def syscall_loop(int n):
    cdef int i
    cdef double t0 = _now()
    for i in range(n):
        getpid()
    return _now() - t0


def stat_loop(bytes path, int n):
    cdef int i
    cdef const char *cpath = path
    cdef stat_t st
    cdef double t0 = _now()
    for i in range(n):
        c_stat(cpath, &st)
    return _now() - t0


def fork_exec(int n):
    cdef int i
    cdef int status = 0
    cdef int pid
    cdef double t0 = _now()
    for i in range(n):
        pid = fork()
        if pid == 0:
            execl(b"/bin/true", b"true", NULL)
            _exit(1)
        elif pid < 0:
            return -1.0
        if waitpid(pid, &status, 0) < 0:
            return -1.0
    return _now() - t0


def mmap_touch(int mb):
    cdef size_t size = <size_t>mb * 1024 * 1024
    cdef int fd
    cdef void *addr
    cdef size_t i
    cdef double t0
    cdef char templ[32]
    cdef const char *tpl = b"/tmp/bench_mmapXXXXXX"
    memset(templ, 0, 32)
    memcpy(templ, tpl, strlen(tpl) + 1)
    fd = mkstemp(templ)
    if fd < 0:
        return -1.0
    if ftruncate(fd, <off_t>size) != 0:
        close(fd)
        unlink(templ)
        return -1.0
    addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
    if <long>addr == -1:
        close(fd)
        unlink(templ)
        return -1.0
    t0 = _now()
    i = 0
    while i < size:
        (<char *>addr)[i] = 1
        i += 4096
    t0 = _now() - t0
    munmap(addr, size)
    close(fd)
    unlink(templ)
    return t0


def file_io(int mb):
    cdef size_t size = <size_t>mb * 1024 * 1024
    cdef size_t chunk = 1024 * 1024
    cdef int fd
    cdef size_t remaining
    cdef ssize_t w
    cdef ssize_t r
    cdef char *buf
    cdef double t0
    cdef char templ[32]
    cdef const char *tpl = b"/tmp/bench_ioXXXXXX"
    memset(templ, 0, 32)
    memcpy(templ, tpl, strlen(tpl) + 1)
    fd = mkstemp(templ)
    if fd < 0:
        return -1.0
    buf = <char *>malloc(chunk)
    if buf == NULL:
        close(fd)
        unlink(templ)
        return -1.0
    memset(buf, 0xA5, chunk)
    t0 = _now()
    remaining = size
    while remaining > 0:
        w = write(fd, buf, chunk if remaining >= chunk else remaining)
        if w <= 0:
            free(buf)
            close(fd)
            unlink(templ)
            return -1.0
        remaining -= <size_t>w
    lseek(fd, 0, SEEK_SET)
    remaining = size
    while remaining > 0:
        r = read(fd, buf, chunk if remaining >= chunk else remaining)
        if r <= 0:
            free(buf)
            close(fd)
            unlink(templ)
            return -1.0
        remaining -= <size_t>r
    t0 = _now() - t0
    free(buf)
    close(fd)
    unlink(templ)
    return t0
