import Foundation
#if canImport(Glibc)
import Glibc
#endif

enum Benchmarks {
    static func now() -> Double {
        var ts = timespec()
        clock_gettime(CLOCK_MONOTONIC, &ts)
        return Double(ts.tv_sec) + Double(ts.tv_nsec) / 1e9
    }

    static func timeit(_ label: String, iters: Int, fn: () -> Double) -> BenchmarkResult {
        var samples: [Double] = []
        for i in 1...iters {
            print("[\(label)] sample \(i)/\(iters)...", terminator: "\r")
            // fflush(stdout) can be tricky with Swift 6 strict concurrency.
            // Using fflush(nil) flushes all open output streams.
            fflush(nil)
            let result = fn()
            samples.append(result)
        }
        print("[\(label)] done                          ")
        
        let sorted = samples.sorted()
        let median = sorted[iters / 2]
        let mean = samples.reduce(0, +) / Double(iters)
        
        return BenchmarkResult(
            min_s: sorted.first ?? 0,
            p50_s: median,
            mean_s: mean,
            max_s: sorted.last ?? 0,
            samples: samples
        )
    }

    static func syscallLoop(n: Int) -> Double {
        let t0 = now()
        for _ in 0..<n {
            getpid()
        }
        return now() - t0
    }

    static func pureLoop(n: Int) -> Double {
        var acc: Int64 = 0
        let t0 = now()
        for i in 0..<n {
            acc += Int64(i)
        }
        if acc == -1 { return -1.0 }
        return now() - t0
    }

    static func statLoop(path: String, n: Int) -> Double {
        var st = stat()
        let t0 = now()
        path.withCString { cPath in
            for _ in 0..<n {
                stat(cPath, &st)
            }
        }
        return now() - t0
    }

    static func forkExec(n: Int) -> Double {
        let t0 = now()
        for _ in 0..<n {
            let pid = fork()
            if pid == 0 {
                let args: [UnsafeMutablePointer<CChar>?] = [
                    strdup("/bin/true"),
                    nil
                ]
                execv("/bin/true", args)
                _exit(1)
            } else if pid < 0 {
                return -1.0
            }
            var status: Int32 = 0
            waitpid(pid, &status, 0)
        }
        return now() - t0
    }

    static func mmapTouch(mb: Int) -> Double {
        let size = mb * 1024 * 1024
        var template = "/tmp/bench_mmapXXXXXX".utf8CString
        let fd = mkstemp(&template[0])
        if fd < 0 { return -1.0 }
        
        ftruncate(fd, off_t(size))
        let addr = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
        if addr == MAP_FAILED {
            close(fd)
            unlink(&template[0])
            return -1.0
        }
        
        let ptr = addr!.bindMemory(to: UInt8.self, capacity: size)
        let t0 = now()
        var i = 0
        while i < size {
            ptr[i] = 1
            i += 4096
        }
        let elapsed = now() - t0
        
        munmap(addr, size)
        close(fd)
        unlink(&template[0])
        return elapsed
    }

    static func fileIO(mb: Int) -> Double {
        let size = mb * 1024 * 1024
        let chunk = 1024 * 1024
        var template = "/tmp/bench_ioXXXXXX".utf8CString
        let fd = mkstemp(&template[0])
        if fd < 0 { return -1.0 }
        
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        memset(buf, 0xA5, chunk)
        
        let t0 = now()
        var remaining = size
        while remaining > 0 {
            let toWrite = min(remaining, chunk)
            let w = write(fd, buf, toWrite)
            if w <= 0 { break }
            remaining -= w
        }
        
        lseek(fd, 0, SEEK_SET)
        remaining = size
        while remaining > 0 {
            let toRead = min(remaining, chunk)
            let r = read(fd, buf, toRead)
            if r <= 0 { break }
            remaining -= r
        }
        let elapsed = now() - t0
        
        buf.deallocate()
        close(fd)
        unlink(&template[0])
        return elapsed
    }

    static func threadPingpong(n: Int) -> Double {
        class State {
            var mutex = pthread_mutex_t()
            var condMain = pthread_cond_t()
            var condWorker = pthread_cond_t()
            var turn = 0
            var stop = false
            
            init() {
                pthread_mutex_init(&mutex, nil)
                pthread_cond_init(&condMain, nil)
                pthread_cond_init(&condWorker, nil)
            }
            
            deinit {
                pthread_mutex_destroy(&mutex)
                pthread_cond_destroy(&condMain)
                pthread_cond_destroy(&condWorker)
            }
        }
        
        let state = State()
        
        let worker: @convention(c) (UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? = { arg in
            guard let arg = arg else { return nil }
            let st = Unmanaged<State>.fromOpaque(arg).takeUnretainedValue()
            while true {
                pthread_mutex_lock(&st.mutex)
                while st.turn == 0 && !st.stop {
                    pthread_cond_wait(&st.condWorker, &st.mutex)
                }
                if st.stop {
                    pthread_mutex_unlock(&st.mutex)
                    break
                }
                st.turn = 0
                pthread_cond_signal(&st.condMain)
                pthread_mutex_unlock(&st.mutex)
            }
            return nil
        }
        
        var threadId = pthread_t()
        let unmanaged = Unmanaged.passUnretained(state)
        pthread_create(&threadId, nil, worker, unmanaged.toOpaque())
        
        let t0 = now()
        for _ in 0..<n {
            pthread_mutex_lock(&state.mutex)
            state.turn = 1
            pthread_cond_signal(&state.condWorker)
            while state.turn == 1 {
                pthread_cond_wait(&state.condMain, &state.mutex)
            }
            pthread_mutex_unlock(&state.mutex)
        }
        let elapsed = now() - t0
        
        pthread_mutex_lock(&state.mutex)
        state.stop = true
        pthread_cond_signal(&state.condWorker)
        pthread_mutex_unlock(&state.mutex)
        pthread_join(threadId, nil)
        
        return elapsed
    }
}
