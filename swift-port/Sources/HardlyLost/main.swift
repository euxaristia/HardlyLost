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
            compareCmd(a: args[2], b: args[3])
        default:
            // Check if user omitted 'run' and passed flags
            if command.hasPrefix("-") {
                runBenchmarks()
            } else {
                print("Unknown command: \(command)")
            }
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
        results["syscall_minus_loop"] = Benchmarks.timeit("syscall_minus_loop", iters: 5) { Benchmarks.syscallMinusLoop(n: config.syscall_iters) }
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
        autoCompare(current: data)
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

    static func loadRun(idOrPath: String) -> RunData? {
        let path = idOrPath.hasSuffix(".json") ? idOrPath : "bench_logs/\(idOrPath).json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(RunData.self, from: data)
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

    static func formatDelta(_ d: Double?) -> String {
        guard let d = d else { return "n/a" }
        return String(format: "%+.1f%%", d)
    }

    static func listRuns() {
        let logDir = "bench_logs"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: logDir) else { return }
        var entries: [(String, String, String)] = []
        for item in items where item.hasSuffix(".json") {
            if let run = loadRun(idOrPath: "bench_logs/\(item)") {
                let kind = classifyRun(run) ?? "-"
                entries.append((run.timestamp_utc, run.run_id, kind))
            }
        }
        for (ts, id, kind) in entries.sorted(by: { $0.0 < $1.0 }) {
            print("\(ts)  \(id)  \(kind)")
        }
    }

    static func classifyKernel(_ info: KernelInfo) -> String? {
        let tokens = (info.kernel_release + " " + info.kernel_version).lowercased()
        let hardenedTokens = ["harden", "hardening", "lockdown", "grsec", "pax"]
        if hardenedTokens.contains(where: { tokens.contains($0) }) { return "hardened" }
        return "normal"
    }

    static func classifyRun(_ data: RunData) -> String? {
        let kind = classifyKernel(data.kernel)
        if kind == "hardened" { return "hardened" }
        
        let indicators = data.kernel.hardening_indicators
        if indicators.indicators.contains("lockdown") || indicators.score >= 10 {
            return "hardened"
        }
        if indicators.score <= 4 {
            return "normal"
        }
        return kind
    }

    static func compareCmd(a: String, b: String) {
        guard let runA = loadRun(idOrPath: a), let runB = loadRun(idOrPath: b) else {
            print("Could not load runs for comparison")
            return
        }
        printReport(generateReport(baseline: runA, comparison: runB))
    }

    static func autoCompare(current: RunData) {
        let logDir = "bench_logs"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: logDir) else { return }
        
        let currentKind = classifyRun(current)
        var others: [RunData] = []
        
        for item in items where item.hasSuffix(".json") {
            if let run = loadRun(idOrPath: "bench_logs/\(item)"), run.run_id != current.run_id {
                others.append(run)
            }
        }

        let targetKind = currentKind == "hardened" ? "normal" : "hardened"
        let candidates = others.filter { classifyRun($0) == targetKind }
        
        guard let bestMatch = candidates.sorted(by: { $0.timestamp_utc > $1.timestamp_utc }).first else {
            print("\nauto-compare: need both normal and hardened runs to compare.")
            return
        }

        print("\nauto-compare: comparing against latest \(targetKind) run (\(bestMatch.run_id))")
        let baseline = currentKind == "hardened" ? bestMatch : current
        let comparison = currentKind == "hardened" ? current : bestMatch
        printReport(generateReport(baseline: baseline, comparison: comparison))
    }

    struct Report {
        var baselineId: String
        var comparisonId: String
        var baselineKind: String
        var comparisonKind: String
        var results: [String: (base: Double, comp: Double, delta: Double?)]
    }

    static func generateReport(baseline: RunData, comparison: RunData) -> Report {
        var results: [String: (base: Double, comp: Double, delta: Double?)] = [:]
        let allKeys = Set(baseline.benchmarks.keys).union(comparison.benchmarks.keys)
        
        for key in allKeys {
            guard let baseRes = baseline.benchmarks[key], let compRes = comparison.benchmarks[key] else { continue }
            let base = baseRes.p50_s
            let comp = compRes.p50_s
            let delta = base > 0 ? ((comp - base) / base) * 100.0 : nil
            results[key] = (base, comp, delta)
        }
        
        return Report(
            baselineId: baseline.run_id,
            comparisonId: comparison.run_id,
            baselineKind: classifyRun(baseline) ?? "base",
            comparisonKind: classifyRun(comparison) ?? "comp",
            results: results
        )
    }

    static func printReport(_ report: Report) {
        let baseLabel = report.baselineKind
        let compLabel = report.comparisonKind
        
        print("\nbenchmark            \(baseLabel.padding(toLength: 10, withPad: " ", startingAt: 0)) \(compLabel.padding(toLength: 10, withPad: " ", startingAt: 0)) delta")
        print("------------------------------------------------------------")
        
        for (name, vals) in report.results.sorted(by: { $0.key < $1.key }) {
            let namePad = name.padding(toLength: 18, withPad: " ", startingAt: 0)
            let basePad = formatSeconds(vals.base).leftPadding(toLength: 10, withPad: " ")
            let compPad = formatSeconds(vals.comp).leftPadding(toLength: 10, withPad: " ")
            let deltaPad = formatDelta(vals.delta).leftPadding(toLength: 10, withPad: " ")
            print("\(namePad) \(basePad) \(compPad) \(deltaPad)")
        }
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
