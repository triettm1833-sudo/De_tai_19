#!/usr/bin/env bash
# Chạy lại toàn bộ thực nghiệm từ đầu. Cần: Python>=3.10, openssl CLI (tùy chọn cho E7).
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD"
[ "${1:-}" = "--fresh" ] && rm -rf keys artifacts results figures    # sinh lại khóa thử nghiệm
mkdir -p results
cd experiments
python3 e3_tamper.py                  # E3: 19 ca x 3 thuật toán
python3 e4_nonce.py                   # E4: nonce, tái sử dụng nonce ECDSA
python3 e5_e6_lifecycle.py            # E5/E6: luân chuyển & khóa bị lộ
python3 e7_openssl_interop.py || echo "bỏ qua E7 (không có openssl)"
for i in 1 2 3; do python3 e2_benchmark.py >/dev/null; cp ../results/benchmark.csv ../results/benchmark_run$i.csv; done   # E2: 3 lần chạy
python3 make_figures.py
cd .. && python3 -m pytest -q tests
