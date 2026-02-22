import Foundation
#if canImport(Glibc)
import Glibc
#endif

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
            hardening_indicators: .init(score: 0, indicators: []) // Placeholder, will update
        )
        
        var finalInfo = info
        finalInfo.hardening_indicators = scoreHardening(info)
        return finalInfo
    }

    private static func readFile(_ path: String) -> String? {
        try? String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
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
        let kernelRelease = withUnsafePointer(to: utsname().release) { $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) } }
        let paths = ["/proc/config.gz", "/boot/config-\(kernelRelease)"]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path), !path.hasSuffix(".gz") {
                if let content = try? String(contentsOfFile: path, encoding: .utf8) {
                    return parseConfig(content)
                }
            }
        }
        return [:]
    }

    private static func parseConfig(_ content: String) -> [String: Bool?] {
        let keys = [
            "CONFIG_HARDENED_USERCOPY", "CONFIG_STACKPROTECTOR_STRONG", "CONFIG_FORTIFY_SOURCE",
            "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_SLAB_FREELIST_RANDOM", "CONFIG_RANDOMIZE_BASE",
            "CONFIG_PAGE_TABLE_ISOLATION", "CONFIG_RETPOLINE"
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
