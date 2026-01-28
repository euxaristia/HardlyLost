# cython: language_level=3

cdef extern from "unistd.h":
    int getpid()

cdef extern from "time.h":
    ctypedef long time_t

    cdef struct timespec:
        time_t tv_sec
        long tv_nsec

    int clock_gettime(int clk_id, timespec *tp)

    cdef enum:
        CLOCK_MONOTONIC

cdef extern from "sys/stat.h":
    cdef struct stat_t "stat":
        pass
    int c_stat "stat"(const char *pathname, stat_t *buf)


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
