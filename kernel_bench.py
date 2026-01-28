#!/usr/bin/env python3
import argparse
import ctypes
import errno
import gzip
import json
import os
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


LOG_DIR_DEFAULT = "bench_logs"


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None


def _read_first_line(path):
    txt = _read_text(path)
    if not txt:
        return None
    return txt.splitlines()[0].strip()


def _read_kernel_config():
    proc_cfg = "/proc/config.gz"
    boot_cfg = f"/boot/config-{platform.uname().release}"
    if os.path.exists(proc_cfg):
        try:
            with gzip.open(proc_cfg, "rt", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError:
            return None
    if os.path.exists(boot_cfg):
        return _read_text(boot_cfg)
    return None


def _config_enabled(config_text, key):
    if not config_text:
        return None
    needle = f"{key}=y"
    if needle in config_text:
        return True
    if f"# {key} is not set" in config_text:
        return False
    return None


def collect_kernel_info():
    uname = platform.uname()
    info = {
        "kernel_release": uname.release,
        "kernel_version": uname.version,
        "machine": uname.machine,
        "node": uname.node,
        "os": uname.system,
        "arch": platform.machine(),
    }

    sysctl_paths = {
        "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
        "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
        "ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
        "randomize_va_space": "/proc/sys/kernel/randomize_va_space",
    }
    sysctl = {}
    for k, p in sysctl_paths.items():
        sysctl[k] = _read_first_line(p)
    info["sysctl"] = sysctl

    lockdown = _read_first_line("/sys/kernel/security/lockdown")
    info["lockdown"] = lockdown

    vulns_dir = "/sys/devices/system/cpu/vulnerabilities"
    vulns = {}
    if os.path.isdir(vulns_dir):
        for name in sorted(os.listdir(vulns_dir)):
            vulns[name] = _read_first_line(os.path.join(vulns_dir, name))
    info["vulnerabilities"] = vulns

    config_text = _read_kernel_config()
    config_keys = [
        "CONFIG_HARDENED_USERCOPY",
        "CONFIG_HARDENED_USERCOPY_FALLBACK",
        "CONFIG_STACKPROTECTOR",
        "CONFIG_STACKPROTECTOR_STRONG",
        "CONFIG_FORTIFY_SOURCE",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_GCC_PLUGIN_RANDSTRUCT",
        "CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
        "CONFIG_PAGE_TABLE_ISOLATION",
        "CONFIG_RETPOLINE",
        "CONFIG_ARM64_PTR_AUTH",
    ]
    config = {}
    for k in config_keys:
        config[k] = _config_enabled(config_text, k)
    info["config"] = config

    info["hardening_indicators"] = _score_hardening(info)
    return info


def _score_hardening(info):
    score = 0
    indicators = []

    sysctl = info.get("sysctl", {})
    if sysctl.get("kptr_restrict") and sysctl["kptr_restrict"] != "0":
        score += 1
        indicators.append("kptr_restrict")
    if sysctl.get("dmesg_restrict") == "1":
        score += 1
        indicators.append("dmesg_restrict")
    if sysctl.get("ptrace_scope") and sysctl["ptrace_scope"] != "0":
        score += 1
        indicators.append("ptrace_scope")
    if sysctl.get("randomize_va_space") == "2":
        score += 1
        indicators.append("randomize_va_space")

    if info.get("lockdown") and "none" not in info["lockdown"]:
        score += 1
        indicators.append("lockdown")

    cfg = info.get("config", {})
    for k, v in cfg.items():
        if v:
            score += 1
            indicators.append(k)

    vulns = info.get("vulnerabilities", {})
    mitigated = sum(1 for v in vulns.values() if v and "Mitigation" in v)
    if mitigated:
        indicators.append(f"mitigations:{mitigated}")
        score += min(3, mitigated // 4)

    return {"score": score, "indicators": indicators}


def _timeit(fn, iters=1, progress_label=None):
    samples = []
    for i in range(iters):
        if progress_label:
            print(f"[{progress_label}] sample {i + 1}/{iters}...", file=sys.stderr, flush=True)
        t0 = time.perf_counter()
        ret = fn()
        t1 = time.perf_counter()
        if isinstance(ret, (int, float)) and ret >= 0:
            samples.append(float(ret))
        else:
            samples.append(t1 - t0)
        if progress_label:
            print(f"[{progress_label}] sample {i + 1}/{iters} done", file=sys.stderr, flush=True)
    return {
        "min_s": min(samples),
        "p50_s": statistics.median(samples),
        "mean_s": statistics.mean(samples),
        "max_s": max(samples),
        "samples": samples,
    }


def _bench_skip(reason):
    return {"skipped": reason}


def _libc():
    return ctypes.CDLL("libc.so.6", use_errno=True)


def _install_seccomp_allow_all():
    if platform.system() != "Linux":
        raise OSError(errno.ENOSYS, "seccomp only supported on Linux")
    if not hasattr(os, "SYS_seccomp"):
        raise OSError(errno.ENOSYS, "seccomp syscall not available")

    libc = _libc()
    PR_SET_NO_NEW_PRIVS = 38
    SECCOMP_SET_MODE_FILTER = 1
    SECCOMP_FILTER_FLAG_TSYNC = 0
    SECCOMP_RET_ALLOW = 0x7fff0000
    BPF_RET = 0x06
    BPF_K = 0x00

    class SockFilter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class SockFprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("filter", ctypes.POINTER(SockFilter)),
        ]

    filt = SockFilter(code=BPF_RET | BPF_K, jt=0, jf=0, k=SECCOMP_RET_ALLOW)
    prog = SockFprog(len=1, filter=ctypes.pointer(filt))

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    res = libc.syscall(os.SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ctypes.byref(prog))
    if res != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter install failed")


def _seccomp_child_syscall_loop(n):
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rfd)
            _install_seccomp_allow_all()
            t0 = time.perf_counter()
            for _ in range(n):
                os.getpid()
            t1 = time.perf_counter()
            os.write(wfd, struct.pack("d", t1 - t0))
        except BaseException:
            pass
        finally:
            try:
                os.close(wfd)
            except OSError:
                pass
            os._exit(0)
    os.close(wfd)
    data = os.read(rfd, 8)
    os.close(rfd)
    os.waitpid(pid, 0)
    if len(data) != 8:
        raise RuntimeError("seccomp child failed")
    return struct.unpack("d", data)[0]


def bench_syscall_loop(n=1_000_000):
    def run():
        for _ in range(n):
            os.getpid()
    return _timeit(run, iters=3)


def bench_stat_loop(n=300_000):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    path = tmp.name
    tmp.close()

    def run():
        for _ in range(n):
            os.stat(path)
    result = _timeit(run, iters=3)
    os.unlink(path)
    return result


def bench_fork_exec(n=300):
    def run():
        for _ in range(n):
            subprocess.run(["/bin/true"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return _timeit(run, iters=3)


def bench_thread_pingpong(n=200_000):
    import threading

    e1 = threading.Event()
    e2 = threading.Event()
    stop = threading.Event()
    e1.set()

    def worker():
        while not stop.is_set():
            if not e2.wait(0.1):
                continue
            e2.clear()
            if stop.is_set():
                break
            e1.set()

    t = threading.Thread(target=worker)
    t.start()

    def run():
        for _ in range(n):
            e1.wait()
            e1.clear()
            e2.set()
    try:
        result = _timeit(run, iters=3, progress_label="thread_pingpong")
    finally:
        stop.set()
        e2.set()
        e1.set()
        t.join(timeout=1)
    return result


def bench_seccomp_syscall_loop(n=1_000_000):
    if platform.system() != "Linux":
        return _bench_skip("seccomp bench requires Linux")
    if not hasattr(os, "SYS_seccomp"):
        return _bench_skip("seccomp syscall not available")

    def run():
        return _seccomp_child_syscall_loop(n)

    try:
        return _timeit(run, iters=3, progress_label="seccomp_syscall_loop")
    except OSError as exc:
        return _bench_skip(f"seccomp setup failed: {exc}")
    except RuntimeError as exc:
        return _bench_skip(str(exc))


def bench_perf_event_open(n=50_000):
    if platform.system() != "Linux":
        return _bench_skip("perf_event bench requires Linux")
    if not hasattr(os, "SYS_perf_event_open"):
        return _bench_skip("perf_event_open syscall not available")

    libc = _libc()
    libc.syscall.restype = ctypes.c_long

    PERF_TYPE_SOFTWARE = 1
    PERF_COUNT_SW_CPU_CLOCK = 0

    class PerfEventAttr(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_uint32),
            ("size", ctypes.c_uint32),
            ("config", ctypes.c_uint64),
            ("sample_period", ctypes.c_uint64),
            ("sample_type", ctypes.c_uint64),
            ("read_format", ctypes.c_uint64),
            ("flags", ctypes.c_uint64),
            ("wakeup_events", ctypes.c_uint32),
            ("bp_type", ctypes.c_uint32),
            ("bp_addr", ctypes.c_uint64),
        ]

    attr = PerfEventAttr()
    attr.type = PERF_TYPE_SOFTWARE
    attr.size = ctypes.sizeof(PerfEventAttr)
    attr.config = PERF_COUNT_SW_CPU_CLOCK

    def run():
        for _ in range(n):
            fd = libc.syscall(os.SYS_perf_event_open, ctypes.byref(attr), 0, -1, -1, 0)
            if fd < 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
            os.close(fd)

    try:
        return _timeit(run, iters=2)
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES, errno.ENOSYS):
            return _bench_skip(f"perf_event_open blocked: {exc}")
        return _bench_skip(f"perf_event_open failed: {exc}")


def bench_bpf_map_create(n=5_000):
    if platform.system() != "Linux":
        return _bench_skip("BPF bench requires Linux")
    if not hasattr(os, "SYS_bpf"):
        return _bench_skip("bpf syscall not available")

    libc = _libc()
    libc.syscall.restype = ctypes.c_long

    BPF_MAP_CREATE = 0
    BPF_MAP_TYPE_ARRAY = 2
    BPF_OBJ_NAME_LEN = 16

    class BpfAttrMapCreate(ctypes.Structure):
        _fields_ = [
            ("map_type", ctypes.c_uint32),
            ("key_size", ctypes.c_uint32),
            ("value_size", ctypes.c_uint32),
            ("max_entries", ctypes.c_uint32),
            ("map_flags", ctypes.c_uint32),
            ("inner_map_fd", ctypes.c_uint32),
            ("numa_node", ctypes.c_uint32),
            ("map_name", ctypes.c_char * BPF_OBJ_NAME_LEN),
            ("map_ifindex", ctypes.c_uint32),
            ("btf_fd", ctypes.c_uint32),
            ("btf_key_type_id", ctypes.c_uint32),
            ("btf_value_type_id", ctypes.c_uint32),
            ("btf_vmlinux_value_type_id", ctypes.c_uint32),
            ("map_extra", ctypes.c_uint64),
        ]

    attr = BpfAttrMapCreate()
    attr.map_type = BPF_MAP_TYPE_ARRAY
    attr.key_size = 4
    attr.value_size = 8
    attr.max_entries = 1
    attr.map_name = b"hb_bench\0"

    def run():
        for _ in range(n):
            fd = libc.syscall(os.SYS_bpf, BPF_MAP_CREATE, ctypes.byref(attr), ctypes.sizeof(attr))
            if fd < 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
            os.close(fd)

    try:
        return _timeit(run, iters=2)
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EINVAL):
            return _bench_skip(f"BPF map create blocked: {exc}")
        return _bench_skip(f"BPF map create failed: {exc}")


def bench_mmap_touch(mb=64):
    import mmap

    size = mb * 1024 * 1024
    with tempfile.TemporaryFile() as f:
        f.truncate(size)
        mm = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_WRITE)

        def run():
            step = 4096
            for i in range(0, size, step):
                mm[i:i+1] = b"\x01"
        result = _timeit(run, iters=2)
        mm.close()
    return result


def bench_file_io(mb=64):
    size = mb * 1024 * 1024
    data = os.urandom(1024 * 1024)

    def run():
        with tempfile.NamedTemporaryFile(delete=False) as f:
            remaining = size
            while remaining > 0:
                f.write(data)
                remaining -= len(data)
            fname = f.name
        with open(fname, "rb") as f:
            while f.read(1024 * 1024):
                pass
        os.unlink(fname)

    return _timeit(run, iters=2)


def run_benchmarks(args):
    benches = {
        "syscall_loop": lambda: bench_syscall_loop(n=args.syscall_iters),
        "stat_loop": lambda: bench_stat_loop(n=args.stat_iters),
        "fork_exec": lambda: bench_fork_exec(n=args.fork_iters),
        "thread_pingpong": lambda: bench_thread_pingpong(n=args.pingpong_iters),
        "seccomp_syscall_loop": lambda: bench_seccomp_syscall_loop(n=args.seccomp_iters),
        "perf_event_open": lambda: bench_perf_event_open(n=args.perf_iters),
        "bpf_map_create": lambda: bench_bpf_map_create(n=args.bpf_iters),
        "mmap_touch": lambda: bench_mmap_touch(mb=args.mmap_mb),
        "file_io": lambda: bench_file_io(mb=args.io_mb),
    }

    if args.only:
        benches = {k: v for k, v in benches.items() if k in args.only}

    results = {}
    for name, fn in benches.items():
        results[name] = fn()

    return results


def _run_id():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{random.randint(1000, 9999)}"


def _write_json_log(data, log_dir):
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{data['run_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    return path


def _load_run(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _find_run(log_dir, run_id):
    path = os.path.join(log_dir, f"{run_id}.json")
    if os.path.exists(path):
        return path
    return None


def _compare_runs(a, b):
    out = {"summary": {}, "benchmarks": {}}
    benches = sorted(set(a["benchmarks"].keys()) & set(b["benchmarks"].keys()))
    for name in benches:
        a_entry = a["benchmarks"][name]
        b_entry = b["benchmarks"][name]
        a_med = a_entry.get("p50_s")
        b_med = b_entry.get("p50_s")
        if a_med is None or b_med is None or a_med == 0:
            delta = None
        else:
            delta = ((b_med - a_med) / a_med) * 100.0
        out_entry = {
            "baseline_p50_s": a_med,
            "comparison_p50_s": b_med,
            "delta_percent": delta,
        }
        if "skipped" in a_entry:
            out_entry["baseline_skipped"] = a_entry["skipped"]
        if "skipped" in b_entry:
            out_entry["comparison_skipped"] = b_entry["skipped"]
        out["benchmarks"][name] = out_entry
    return out


def _classify_label(label):
    if not label:
        return None
    lowered = label.lower()
    if any(k in lowered for k in ("harden", "hardening", "lockdown", "secure", "grsec", "pax")):
        return "hardened"
    if any(k in lowered for k in ("normal", "standard", "vanilla", "stock", "default")):
        return "normal"
    return None


def _classify_kernel(kernel_info):
    if not kernel_info:
        return None
    tokens = " ".join(
        str(kernel_info.get(k, "")).lower() for k in ("kernel_release", "kernel_version")
    )
    if any(k in tokens for k in ("harden", "hardening", "lockdown", "grsec", "pax")):
        return "hardened"
    if any(k in tokens for k in ("vanilla", "stock", "default")):
        return "normal"
    return None


def _auto_compare(log_dir):
    if not os.path.isdir(log_dir):
        return
    runs = []
    for name in os.listdir(log_dir):
        if not name.endswith(".json"):
            continue
        path = os.path.join(log_dir, name)
        try:
            data = _load_run(path)
        except json.JSONDecodeError:
            continue
        label = data.get("label")
        kind = _classify_label(label) or _classify_kernel(data.get("kernel"))
        ts = data.get("timestamp_utc")
        runs.append((ts, kind, data, path))

    def pick_latest(kind):
        candidates = [r for r in runs if r[1] == kind]
        if not candidates:
            return None
        def key(r):
            ts = r[0]
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                try:
                    return datetime.fromtimestamp(os.path.getmtime(r[3]), timezone.utc)
                except OSError:
                    return datetime.fromtimestamp(0, timezone.utc)
        return max(candidates, key=key)

    normal = pick_latest("normal")
    hardened = pick_latest("hardened")

    if not normal or not hardened:
        missing = "hardened" if not hardened else "normal"
        print(
            f"auto-compare: need both normal and hardened runs. "
            f"Please boot a {missing} kernel and rerun with --label {missing}."
        )
        return

    report = _compare_runs(normal[2], hardened[2])
    print(
        f"auto-compare: baseline(normal)={normal[2].get('run_id')} "
        f"comparison(hardened)={hardened[2].get('run_id')}"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def cmd_run(args):
    kernel_info = collect_kernel_info()
    benchmarks = run_benchmarks(args)
    data = {
        "run_id": _run_id(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "kernel": kernel_info,
        "benchmarks": benchmarks,
        "bench_config": {
            "syscall_iters": args.syscall_iters,
            "stat_iters": args.stat_iters,
            "fork_iters": args.fork_iters,
            "pingpong_iters": args.pingpong_iters,
            "seccomp_iters": args.seccomp_iters,
            "perf_iters": args.perf_iters,
            "bpf_iters": args.bpf_iters,
            "mmap_mb": args.mmap_mb,
            "io_mb": args.io_mb,
        },
    }
    path = _write_json_log(data, args.log_dir)
    print(f"saved: {path}")
    print(f"run_id: {data['run_id']}")
    _auto_compare(args.log_dir)


def cmd_list(args):
    if not os.path.isdir(args.log_dir):
        print("no logs")
        return
    entries = []
    for name in os.listdir(args.log_dir):
        if not name.endswith(".json"):
            continue
        path = os.path.join(args.log_dir, name)
        try:
            data = _load_run(path)
            entries.append((data.get("timestamp_utc"), data.get("run_id"), data.get("label"), path))
        except json.JSONDecodeError:
            continue
    for ts, run_id, label, path in sorted(entries):
        print(f"{ts}  {run_id}  {label or '-'}  {path}")


def cmd_compare(args):
    a_path = _find_run(args.log_dir, args.baseline) or args.baseline
    b_path = _find_run(args.log_dir, args.comparison) or args.comparison
    if not os.path.exists(a_path):
        print(f"missing baseline: {a_path}")
        sys.exit(1)
    if not os.path.exists(b_path):
        print(f"missing comparison: {b_path}")
        sys.exit(1)
    a = _load_run(a_path)
    b = _load_run(b_path)
    report = _compare_runs(a, b)
    print(json.dumps(report, indent=2, sort_keys=True))


def build_parser():
    p = argparse.ArgumentParser(
        description="Benchmark kernel performance and detect hardening signals."
    )
    p.add_argument("--log-dir", default=LOG_DIR_DEFAULT, help="Directory for JSON logs")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run benchmarks and record kernel info")
    run.add_argument("--label", help="Label for the run (e.g., standard, hardened)")
    run.add_argument("--syscall-iters", type=int, default=1_000_000)
    run.add_argument("--stat-iters", type=int, default=300_000)
    run.add_argument("--fork-iters", type=int, default=300)
    run.add_argument("--pingpong-iters", type=int, default=200_000)
    run.add_argument("--seccomp-iters", type=int, default=1_000_000)
    run.add_argument("--perf-iters", type=int, default=50_000)
    run.add_argument("--bpf-iters", type=int, default=5_000)
    run.add_argument("--mmap-mb", type=int, default=64)
    run.add_argument("--io-mb", type=int, default=64)
    run.add_argument("--only", nargs="+", help="Run only specific benchmarks")
    run.set_defaults(func=cmd_run)

    lst = sub.add_parser("list", help="List existing runs")
    lst.set_defaults(func=cmd_list)

    cmp = sub.add_parser("compare", help="Compare two runs by run_id or path")
    cmp.add_argument("baseline", help="Baseline run_id or JSON path")
    cmp.add_argument("comparison", help="Comparison run_id or JSON path")
    cmp.set_defaults(func=cmd_compare)

    return p


def main():
    parser = build_parser()
    argv = sys.argv[1:]
    if argv and argv[0] == "run":
        print("warning: 'run' is the default subcommand; you can omit it", file=sys.stderr)
    if not argv or (argv and argv[0] not in {"run", "list", "compare"} and "--help" not in argv and "-h" not in argv):
        argv = ["run"] + argv
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        print(f"warning: ignoring unrecognized arguments: {' '.join(unknown)}", file=sys.stderr)
    args.func(args)


if __name__ == "__main__":
    main()
