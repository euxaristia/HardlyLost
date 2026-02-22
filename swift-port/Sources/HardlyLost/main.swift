import Foundation

struct HardlyLostApp {
    static func run() {
        let args = CommandLine.arguments
        let command = args.count > 1 ? args[1] : "run"
        
        switch command {
        case "run":
            runBenchmarks()
        case "list":
            listRuns()
        case "compare":
            if args.count < 4 {
                print("Usage: HardlyLost compare <run_a> <run_b>")
                return
            }
            compareRuns(a: args[2], b: args[3])
        default:
            print("Unknown command: \(command)")
        }
    }

    static func runBenchmarks() {
        print("Starting HardlyLost Swift benchmarks...")
        let config = BenchConfig(
            syscall_iters: 3_000_000,
            stat_iters: 800_000,
            fork_iters: 800,
            pingpong_iters: 500_000,
            mmap_mb: 128,
            io_mb: 128,
            gpu_frames: 1200,
            gpu_width: 640,
            gpu_height: 360
        )

        let kernel = KernelInfoCollector.collect()
        var results: [String: BenchmarkResult] = [:]

        results["syscall_loop"] = Benchmarks.timeit("syscall_loop", iters: 5) { Benchmarks.syscallLoop(n: config.syscall_iters) }
        results["pure_loop"] = Benchmarks.timeit("pure_loop", iters: 5) { Benchmarks.pureLoop(n: config.syscall_iters) }
        results["stat_loop"] = Benchmarks.timeit("stat_loop", iters: 5) { Benchmarks.statLoop(path: "/tmp", n: config.stat_iters) }
        results["fork_exec"] = Benchmarks.timeit("fork_exec", iters: 5) { Benchmarks.forkExec(n: config.fork_iters) }
        results["thread_pingpong"] = Benchmarks.timeit("thread_pingpong", iters: 5) { Benchmarks.threadPingpong(n: config.pingpong_iters) }
        results["mmap_touch"] = Benchmarks.timeit("mmap_touch", iters: 3) { Benchmarks.mmapTouch(mb: config.mmap_mb) }
        results["file_io"] = Benchmarks.timeit("file_io", iters: 3) { Benchmarks.fileIO(mb: config.io_mb) }

        let runId = "\(Int(Date().timeIntervalSince1970))-\(Int.random(in: 1000...9999))"
        let data = RunData(
            run_id: runId,
            timestamp_utc: ISO8601DateFormatter().string(from: Date()),
            bench_impl: "swift",
            kernel: kernel,
            benchmarks: results,
            bench_repeat: 1,
            bench_config: config
        )

        saveRun(data)
        printRunTable(results)
    }

    static func saveRun(_ data: RunData) {
        let logDir = "bench_logs"
        try? FileManager.default.createDirectory(atPath: logDir, withIntermediateDirectories: true)
        let path = "\(logDir)/\(data.run_id).json"
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        if let encoded = try? encoder.encode(data) {
            try? encoded.write(to: URL(fileURLWithPath: path))
            print("Saved: \(path)")
        }
    }

    static func printRunTable(_ benchmarks: [String: BenchmarkResult]) {
        print("\nbenchmark            p50        min        max")
        print("----------------------------------------------")
        for (name, res) in benchmarks.sorted(by: { $0.key < $1.key }) {
            let p50 = formatSeconds(res.p50_s)
            let min = formatSeconds(res.min_s)
            let max = formatSeconds(res.max_s)
            
            let namePad = name.padding(toLength: 18, withPad: " ", startingAt: 0)
            let p50Pad = p50.leftPadding(toLength: 10, withPad: " ")
            let minPad = min.leftPadding(toLength: 10, withPad: " ")
            let maxPad = max.leftPadding(toLength: 10, withPad: " ")
            
            print("\(namePad) \(p50Pad) \(minPad) \(maxPad)")
        }
    }

    static func formatSeconds(_ s: Double) -> String {
        if s >= 1.0 { return String(format: "%.3fs", s) }
        if s >= 1e-3 { return String(format: "%.2fms", s * 1e3) }
        if s >= 1e-6 { return String(format: "%.1fus", s * 1e6) }
        return String(format: "%.1fns", s * 1e9)
    }

    static func listRuns() {
        let logDir = "bench_logs"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: logDir) else { return }
        for item in items where item.hasSuffix(".json") {
            print(item)
        }
    }

    static func compareRuns(a: String, b: String) {
        print("Comparing \(a) and \(b)... (Comparison logic placeholder)")
    }
}

extension String {
    func leftPadding(toLength: Int, withPad: String) -> String {
        let stringLength = self.count
        if stringLength < toLength {
            return String(repeating: withPad, count: toLength - stringLength) + self
        } else {
            let start = self.index(self.endIndex, offsetBy: -toLength)
            return String(self[start..<self.endIndex])
        }
    }
}

HardlyLostApp.run()
