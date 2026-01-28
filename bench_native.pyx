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

cdef extern from "time.h" nogil:
    ctypedef long time_t

    cdef struct timespec:
        time_t tv_sec
        long tv_nsec

    int clock_gettime(int clk_id, timespec *tp)

    cdef enum:
        CLOCK_MONOTONIC

cdef extern from "sys/wait.h":
    int waitpid(int pid, int *status, int options)

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_t:
        pass
    ctypedef struct pthread_mutex_t:
        pass
    ctypedef struct pthread_cond_t:
        pass
    int pthread_create(pthread_t *thread, void *attr, void *(*start_routine)(void *) noexcept, void *arg)
    int pthread_join(pthread_t thread, void **retval)
    int pthread_mutex_init(pthread_mutex_t *mutex, void *attr)
    int pthread_mutex_destroy(pthread_mutex_t *mutex)
    int pthread_mutex_lock(pthread_mutex_t *mutex)
    int pthread_mutex_unlock(pthread_mutex_t *mutex)
    int pthread_cond_init(pthread_cond_t *cond, void *attr)
    int pthread_cond_destroy(pthread_cond_t *cond)
    int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
    int pthread_cond_signal(pthread_cond_t *cond)

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


cdef inline double _now() nogil:
    cdef timespec ts
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return ts.tv_sec + ts.tv_nsec / 1e9


def syscall_loop(int n):
    cdef int i
    cdef double t0 = _now()
    for i in range(n):
        getpid()
    return _now() - t0


def pure_loop(int n):
    cdef int i
    cdef long acc = 0
    cdef double t0 = _now()
    for i in range(n):
        acc += i
    if acc == -1:
        return -1.0
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


cdef struct pingpong_state:
    pthread_mutex_t mutex
    pthread_cond_t cond_main
    pthread_cond_t cond_worker
    int turn
    int stop


cdef void* _pingpong_worker(void *arg) noexcept nogil:
    cdef pingpong_state *st = <pingpong_state *>arg
    while True:
        pthread_mutex_lock(&st.mutex)
        while st.turn == 0 and st.stop == 0:
            pthread_cond_wait(&st.cond_worker, &st.mutex)
        if st.stop != 0:
            pthread_mutex_unlock(&st.mutex)
            break
        st.turn = 0
        pthread_cond_signal(&st.cond_main)
        pthread_mutex_unlock(&st.mutex)
    return NULL


cdef double _thread_pingpong_nogil(int n) nogil:
    cdef pingpong_state st
    cdef pthread_t thr
    cdef int i
    cdef double t0
    st.turn = 0
    st.stop = 0
    if pthread_mutex_init(&st.mutex, <void *>0) != 0:
        return -1.0
    if pthread_cond_init(&st.cond_main, <void *>0) != 0:
        pthread_mutex_destroy(&st.mutex)
        return -1.0
    if pthread_cond_init(&st.cond_worker, <void *>0) != 0:
        pthread_cond_destroy(&st.cond_main)
        pthread_mutex_destroy(&st.mutex)
        return -1.0
    if pthread_create(&thr, <void *>0, _pingpong_worker, <void *>&st) != 0:
        pthread_cond_destroy(&st.cond_worker)
        pthread_cond_destroy(&st.cond_main)
        pthread_mutex_destroy(&st.mutex)
        return -1.0

    t0 = _now()
    for i in range(n):
        pthread_mutex_lock(&st.mutex)
        st.turn = 1
        pthread_cond_signal(&st.cond_worker)
        while st.turn == 1:
            pthread_cond_wait(&st.cond_main, &st.mutex)
        pthread_mutex_unlock(&st.mutex)
    t0 = _now() - t0

    pthread_mutex_lock(&st.mutex)
    st.stop = 1
    pthread_cond_signal(&st.cond_worker)
    pthread_mutex_unlock(&st.mutex)
    pthread_join(thr, <void **>0)
    pthread_cond_destroy(&st.cond_worker)
    pthread_cond_destroy(&st.cond_main)
    pthread_mutex_destroy(&st.mutex)
    return t0


def thread_pingpong(int n):
    cdef double t0
    with nogil:
        t0 = _thread_pingpong_nogil(n)
    return t0
