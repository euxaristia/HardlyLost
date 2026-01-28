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
DATA_STORE_DEFAULT = "data_store"


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


def _build_report(a, b):
    report = _compare_runs(a, b)
    report["summary"] = {
        "baseline_run_id": a.get("run_id"),
        "comparison_run_id": b.get("run_id"),
        "baseline_kernel": (a.get("kernel") or {}).get("kernel_release"),
        "comparison_kernel": (b.get("kernel") or {}).get("kernel_release"),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    return report


def _aggregate_runs(runs):
    benches = {}
    for data in runs:
        for name, entry in (data.get("benchmarks") or {}).items():
            benches.setdefault(name, []).append(entry)

    out = {}
    for name, entries in benches.items():
        vals = [e.get("p50_s") for e in entries if e.get("p50_s") is not None]
        entry = {}
        if vals:
            entry["p50_s"] = statistics.median(vals)
        skipped = [e.get("skipped") for e in entries if e.get("skipped")]
        if skipped:
            entry["skipped"] = skipped[0]
        out[name] = entry
    return {"benchmarks": out}


def _compare_groups(a_runs, b_runs):
    a_agg = _aggregate_runs(a_runs)
    b_agg = _aggregate_runs(b_runs)
    report = _compare_runs(a_agg, b_agg)
    report["summary"] = {
        "baseline_runs": [r.get("run_id") for r in a_runs],
        "comparison_runs": [r.get("run_id") for r in b_runs],
        "baseline_kernel": (a_runs[-1].get("kernel") or {}).get("kernel_release") if a_runs else None,
        "comparison_kernel": (b_runs[-1].get("kernel") or {}).get("kernel_release") if b_runs else None,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    return report


def _format_seconds(value):
    if value is None:
        return "n/a"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "n/a"
    if v >= 1.0:
        return f"{v:.3f}s"
    if v >= 1e-3:
        return f"{v * 1e3:.2f}ms"
    if v >= 1e-6:
        return f"{v * 1e6:.1f}us"
    return f"{v * 1e9:.1f}ns"


def _format_delta(value):
    if value is None:
        return "n/a"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "n/a"
    return f"{v:+.1f}%"


def _write_report_json(report, data_store_dir, name_hint):
    if not data_store_dir:
        return None, "data store path not set"
    try:
        os.makedirs(data_store_dir, exist_ok=True)
    except OSError as exc:
        return None, f"mkdir failed: {exc}"
    path = os.path.join(data_store_dir, f"{name_hint}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
    except OSError as exc:
        return None, f"write failed: {exc}"
    return path, None


def _print_human_report(report):
    benches = report.get("benchmarks", {})
    rows = []
    deltas = []
    for name in sorted(benches.keys()):
        entry = benches[name]
        base = _format_seconds(entry.get("baseline_p50_s"))
        comp = _format_seconds(entry.get("comparison_p50_s"))
        delta = _format_delta(entry.get("delta_percent"))
        raw_delta = entry.get("delta_percent")
        if raw_delta is not None:
            try:
                deltas.append(float(raw_delta))
            except (TypeError, ValueError):
                pass
        rows.append((name, base, comp, delta))

    headers = ("benchmark", "baseline", "comparison", "delta")
    col_widths = [
        max(len(headers[0]), *(len(r[0]) for r in rows)) if rows else len(headers[0]),
        max(len(headers[1]), *(len(r[1]) for r in rows)) if rows else len(headers[1]),
        max(len(headers[2]), *(len(r[2]) for r in rows)) if rows else len(headers[2]),
        max(len(headers[3]), *(len(r[3]) for r in rows)) if rows else len(headers[3]),
    ]

    def fmt_row(r):
        return (
            f"{r[0]:<{col_widths[0]}}  "
            f"{r[1]:>{col_widths[1]}}  "
            f"{r[2]:>{col_widths[2]}}  "
            f"{r[3]:>{col_widths[3]}}"
        )

    if deltas:
        slower = sum(1 for d in deltas if d > 0)
        faster = sum(1 for d in deltas if d < 0)
        total = len(deltas)
        med = statistics.median(deltas)
        summary = report.get("summary", {})
        base_name = summary.get("baseline_kernel") or "baseline"
        comp_name = summary.get("comparison_kernel") or "comparison"
        if summary.get("baseline_runs") is not None:
            base_name = f"{base_name} ({len(summary.get('baseline_runs') or [])} runs)"
        if summary.get("comparison_runs") is not None:
            comp_name = f"{comp_name} ({len(summary.get('comparison_runs') or [])} runs)"
        if med > 0:
            winner = "A"
        elif med < 0:
            winner = "B"
        else:
            winner = "tie"
        print(
            f"overall: A={base_name} B={comp_name} -> "
            f"winner={winner}; B slower in {slower}/{total}, faster in {faster}/{total}, "
            f"median delta {_format_delta(med)}"
        )
    print(fmt_row(headers))
    print(
        f"{'-' * col_widths[0]}  "
        f"{'-' * col_widths[1]}  "
        f"{'-' * col_widths[2]}  "
        f"{'-' * col_widths[3]}"
    )
    for name, base, comp, delta in rows:
        print(fmt_row((name, base, comp, delta)))


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
    if tokens.strip():
        return "normal"
    return None


def _classify_run(data):
    kernel_info = data.get("kernel") or {}
    kind = _classify_kernel(kernel_info)
    if kind:
        return kind

    indicators = set(kernel_info.get("hardening_indicators", {}).get("indicators") or [])
    score = kernel_info.get("hardening_indicators", {}).get("score")
    lockdown = kernel_info.get("lockdown") or ""
    has_lockdown = "lockdown" in indicators or (lockdown and "none" not in lockdown)

    config_enabled = sum(1 for k in indicators if k.startswith("CONFIG_"))
    mitigations = 0
    for item in indicators:
        if item.startswith("mitigations:"):
            try:
                mitigations = int(item.split(":", 1)[1])
            except ValueError:
                mitigations = 0
            break

    # Heuristics: lockdown or consistently high hardening signals => hardened.
    if has_lockdown:
        return "hardened"
    if score is not None and score >= 10:
        return "hardened"
    if config_enabled >= 8 and mitigations >= 8:
        return "hardened"

    # Low signal set usually indicates a normal/stock kernel.
    if score is not None and score <= 4:
        return "normal"
    if config_enabled <= 3 and mitigations <= 3:
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
        kind = _classify_run(data)
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

    normal = [r for r in runs if r[1] == "normal"]
    hardened = [r for r in runs if r[1] == "hardened"]

    if not normal or not hardened:
        missing = "hardened" if not hardened else "normal"
        print(
            f"auto-compare: need both normal and hardened runs. "
            f"Could not infer a {missing} run from the logs; "
            f"make sure you have runs from both kernels."
        )
        return

    normal_runs = [r[2] for r in normal]
    hardened_runs = [r[2] for r in hardened]
    report = _compare_groups(normal_runs, hardened_runs)
    print(
        f"auto-compare: normal_runs={len(normal_runs)} "
        f"hardened_runs={len(hardened_runs)}"
    )
    _print_human_report(report)
    name_hint = f"compare_{len(normal_runs)}n_{len(hardened_runs)}h"
    path, err = _write_report_json(report, DATA_STORE_DEFAULT, name_hint)
    if path:
        print(f"saved report: {path}")
    else:
        print(
            f"warning: could not write report to {DATA_STORE_DEFAULT} ({err})",
            file=sys.stderr,
        )


def cmd_run(args):
    kernel_info = collect_kernel_info()
    benchmarks = run_benchmarks(args)
    data = {
        "run_id": _run_id(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "kernel": kernel_info,
        "benchmarks": benchmarks,
        "bench_config": {
            "syscall_iters": args.syscall_iters,
            "stat_iters": args.stat_iters,
            "fork_iters": args.fork_iters,
            "pingpong_iters": args.pingpong_iters,
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
            kind = _classify_run(data)
            entries.append((data.get("timestamp_utc"), data.get("run_id"), kind, path))
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
    report = _build_report(a, b)
    _print_human_report(report)
    name_hint = f"compare_{a.get('run_id')}_{b.get('run_id')}"
    path, err = _write_report_json(report, DATA_STORE_DEFAULT, name_hint)
    if path:
        print(f"saved report: {path}")
    else:
        print(
            f"warning: could not write report to {DATA_STORE_DEFAULT} ({err})",
            file=sys.stderr,
        )


def build_parser():
    p = argparse.ArgumentParser(
        description="Benchmark kernel performance and detect hardening signals."
    )
    p.add_argument("--log-dir", default=LOG_DIR_DEFAULT, help="Directory for JSON logs")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run benchmarks and record kernel info")
    run.add_argument("--syscall-iters", type=int, default=1_000_000)
    run.add_argument("--stat-iters", type=int, default=300_000)
    run.add_argument("--fork-iters", type=int, default=300)
    run.add_argument("--pingpong-iters", type=int, default=200_000)
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
