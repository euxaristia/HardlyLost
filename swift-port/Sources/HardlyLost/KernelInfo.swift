import Foundation
#if canImport(Glibc)
import Glibc
#endif

// We need a small wrapper for zlib to decompress /proc/config.gz
// We'll declare the C functions directly to avoid a complicated package structure.
@_silgen_name("gzopen") func gzopen(_ path: UnsafePointer<CChar>, _ mode: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?
@_silgen_name("gzread") func gzread(_ file: UnsafeMutableRawPointer, _ buf: UnsafeMutableRawPointer, _ len: UInt32) -> Int32
@_silgen_name("gzclose") func gzclose(_ file: UnsafeMutableRawPointer) -> Int32

enum KernelInfoCollector {
    static func collect() -> KernelInfo {
        var uts = utsname()
        uname(&uts)

        let info = KernelInfo(
            kernel_release: withUnsafePointer(to: uts.release) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            kernel_version: withUnsafePointer(to: uts.version) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            machine: withUnsafePointer(to: uts.machine) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            node: withUnsafePointer(to: uts.nodename) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            os: withUnsafePointer(to: uts.sysname) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            arch: withUnsafePointer(to: uts.machine) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } },
            sysctl: collectSysctls(),
            lockdown: readFile("/sys/kernel/security/lockdown"),
            vulnerabilities: collectVulnerabilities(),
            config: collectConfig(),
            hardening_indicators: .init(score: 0, indicators: [])
        )
        
        var finalInfo = info
        finalInfo.hardening_indicators = scoreHardening(info)
        return finalInfo
    }

    private static func readFile(_ path: String) -> String? {
        try? String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func readGzipFile(_ path: String) -> String? {
        guard let file = gzopen(path, "rb") else { return nil }
        defer { gzclose(file) }
        
        var data = Data()
        let bufferSize = 1024 * 16
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        
        while true {
            let read = gzread(file, buffer, UInt32(bufferSize))
            if read <= 0 { break }
            data.append(buffer, count: Int(read))
        }
        
        return String(data: data, encoding: .utf8)
    }

    private static func collectSysctls() -> [String: String?] {
        let paths = [
            "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
            "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
            "ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
            "randomize_va_space": "/proc/sys/kernel/randomize_va_space"
        ]
        return paths.mapValues { readFile($0) }
    }

    private static func collectVulnerabilities() -> [String: String?] {
        let vulnsDir = "/sys/devices/system/cpu/vulnerabilities"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: vulnsDir) else { return [:] }
        var result: [String: String?] = [:]
        for item in items {
            result[item] = readFile("\(vulnsDir)/\(item)")
        }
        return result
    }

    private static func collectConfig() -> [String: Bool?] {
        if let content = readGzipFile("/proc/config.gz") {
            return parseConfig(content)
        }
        
        let kernelRelease = withUnsafePointer(to: utsname().release) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } }
        let bootConfigPath = "/boot/config-\(kernelRelease)"
        if let content = readFile(bootConfigPath) {
            return parseConfig(content)
        }
        
        return [:]
    }

    private static func parseConfig(_ content: String) -> [String: Bool?] {
        let keys = [
            "CONFIG_HARDENED_USERCOPY", "CONFIG_HARDENED_USERCOPY_FALLBACK",
            "CONFIG_STACKPROTECTOR", "CONFIG_STACKPROTECTOR_STRONG",
            "CONFIG_FORTIFY_SOURCE", "CONFIG_SLAB_FREELIST_HARDENED",
            "CONFIG_SLAB_FREELIST_RANDOM", "CONFIG_GCC_PLUGIN_RANDSTRUCT",
            "CONFIG_GCC_PLUGIN_LATENT_ENTROPY", "CONFIG_RANDOMIZE_BASE",
            "CONFIG_SHUFFLE_PAGE_ALLOCATOR", "CONFIG_PAGE_TABLE_ISOLATION",
            "CONFIG_RETPOLINE", "CONFIG_ARM64_PTR_AUTH"
        ]
        var result: [String: Bool?] = [:]
        for key in keys {
            if content.contains("\(key)=y") { result[key] = true }
            else if content.contains("# \(key) is not set") { result[key] = false }
        }
        return result
    }

    private static func scoreHardening(_ info: KernelInfo) -> HardeningScore {
        var score = 0
        var indicators: [String] = []

        if let kptr = info.sysctl["kptr_restrict"], kptr != "0" { score += 1; indicators.append("kptr_restrict") }
        if info.sysctl["dmesg_restrict"] == "1" { score += 1; indicators.append("dmesg_restrict") }
        if let ptrace = info.sysctl["ptrace_scope"], ptrace != "0" { score += 1; indicators.append("ptrace_scope") }
        if info.sysctl["randomize_va_space"] == "2" { score += 1; indicators.append("randomize_va_space") }

        if let lockdown = info.lockdown, !lockdown.contains("none") { score += 1; indicators.append("lockdown") }

        for (k, v) in info.config { if v == true { score += 1; indicators.append(k) } }

        let mitigations = info.vulnerabilities.values.compactMap { $0 }.filter { $0.contains("Mitigation") }.count
        if mitigations > 0 {
            indicators.append("mitigations:\(mitigations)")
            score += min(3, mitigations / 4)
        }

        return HardeningScore(score: score, indicators: indicators)
    }
}
