# HardlyLost

Lightweight kernel performance probe with an opinionated workflow: collect runs, compare normal vs hardened kernels, and keep the dataset clean by pruning outliers. The hot loops are in Cython to minimize interpreter noise, while the reporting stays in Python for hackability.

## Highlights
- JSON run logs, plus human-readable summaries
- Auto-compare of normal vs hardened runs
- Outlier detection and pruning (dry-run by default)
- Cython-powered benchmarks

## Quick start

```bash
./run.sh run
```

That builds the Cython extension (if needed) and runs the suite.

## Common commands

Run a full suite:
```bash
./run.sh
```

Run a single benchmark:
```bash
./run.sh --only syscall_loop
```
GPU benchmark alias examples:
```bash
./run.sh --only gpu_3d
./run.sh --only gpu3d
```

Compare two runs by id/path:
```bash
python3 kernel_bench.py compare <baseline_run_id_or_path> <comparison_run_id_or_path>
```

List stored runs:
```bash
python3 kernel_bench.py list
```

Prune outlier logs (dry run):
```bash
python3 kernel_bench.py prune
```

Prune outlier logs (apply):
```bash
python3 kernel_bench.py prune --apply
```

## What gets logged

Each run stores:
- kernel version & hardening indicators
- benchmark timing stats (p50/mean/min/max + samples)
- bench config (iteration counts, sizes)
- UTC timestamp + run id

Logs are written to `bench_logs/`. Comparison reports go to `data_store/`.

## Notes on Cython

The following benchmarks run in Cython when the extension is built:
- `syscall_loop`
- `stat_loop`
- `fork_exec`
- `mmap_touch`
- `file_io`
- `thread_pingpong`

The Cython extension is required to run benchmarks.

Optional GPU benchmark:
- `gpu_3d` (requires `pyglet` and a working OpenGL context; skipped if unavailable)

Install the optional dependency:
```bash
python3 -m pip install pyglet
```

To build manually:
```bash
python3 setup.py build_ext --inplace
```

## Outlier pruning

Pruning is conservative by default. A run is flagged if it’s an outlier on **any** benchmark or if its overall scale is extreme. You can tune thresholds:

```bash
python3 kernel_bench.py prune --z-thresh 2.5 --min-benchmarks 3 --min-runs 4
```

## License

MIT (add a LICENSE file if you want it explicit).
