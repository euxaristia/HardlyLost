import Foundation

struct BenchmarkResult: Codable {
    var min_s: Double
    var p50_s: Double
    var mean_s: Double
    var max_s: Double
    var samples: [Double]
    var unit: String? = nil
    var skipped: String? = nil
}

struct KernelInfo: Codable {
    var kernel_release: String
    var kernel_version: String
    var machine: String
    var node: String
    var os: String
    var arch: String
    var sysctl: [String: String?]
    var lockdown: String?
    var vulnerabilities: [String: String?]
    var config: [String: Bool?]
    var hardening_indicators: HardeningScore
}

struct HardeningScore: Codable {
    var score: Int
    var indicators: [String]
}

struct BenchConfig: Codable {
    var syscall_iters: Int
    var stat_iters: Int
    var fork_iters: Int
    var pingpong_iters: Int
    var mmap_mb: Int
    var io_mb: Int
    var gpu_frames: Int
    var gpu_width: Int
    var gpu_height: Int
}

struct RunData: Codable {
    var run_id: String
    var timestamp_utc: String
    var bench_impl: String
    var kernel: KernelInfo
    var benchmarks: [String: BenchmarkResult]
    var bench_repeat: Int
    var bench_config: BenchConfig
}
