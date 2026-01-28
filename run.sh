#!/usr/bin/env bash
set -euo pipefail

python3 setup.py build_ext --inplace
python3 kernel_bench.py "$@"
