# Đề tài 19 – Đánh giá chữ ký số cho phần mềm và tài liệu điện tử

Đồ án môn An toàn thông tin (UTH). So sánh RSA-PSS, ECDSA (P-256) và Ed25519 trên một quy trình ký artifact
(tệp nhị phân, tài liệu, manifest metadata) có dấu thời gian mô phỏng, trust list có phiên bản,
luân chuyển khóa và kịch bản khóa ký bị lộ. Báo cáo đầy đủ: `BaoCao_DeTai19_ChuKySo.docx` / `.pdf`.

> **Cảnh báo:** toàn bộ khóa trong `keys/` là khóa thử nghiệm, không mã hóa, đã công khai trong kho mã.
> Không dùng để ký phần mềm thật. Mã khôi phục khóa (`sigeval/toyecdsa.py`) chỉ chạy trên khóa nạn nhân do nhóm tự sinh.

## Phiên bản công cụ (môi trường đã chạy)

| Thành phần | Phiên bản |
|---|---|
| Python | 3.13 (yêu cầu >= 3.10) |
| cryptography | 50.0.1 (yêu cầu >= 46) |
| OpenSSL đóng gói trong wheel | 4.0.2 |
| OpenSSL CLI của hệ điều hành (E7) | 3.0.13 (tùy chọn) |
| matplotlib, pytest, python-docx | xem `requirements.txt` |
| Phần cứng đo hiệu năng | Intel Xeon 2.1 GHz, 2 vCPU (máy ảo chia sẻ), 1 luồng |

## Cài đặt và chạy

```bash
pip install -r requirements.txt --break-system-packages   # bỏ cờ này nếu dùng virtualenv
./run_all.sh            # chạy E3–E7, benchmark E2 (3 lần), vẽ hình, pytest  (~30–60 giây)
./run_all.sh --fresh    # xóa rồi sinh lại khóa thử nghiệm, artifact, kết quả (quy trình hoàn nguyên)
python3 report/build_report.py   # dựng lại báo cáo Word + PDF từ results/ (cần LibreOffice `soffice`)
python3 -m pytest -q tests       # 10 kiểm thử tự động
```

## Dữ liệu mẫu và seed

* Artifact mẫu: `artifacts/original/` (`demo-app.bin`, `bien-ban.txt`, `conf/app.json`), sinh tất định.
* Seed ngẫu nhiên của bộ dữ liệu và thời gian mô phỏng là hằng số (`seed = 20260411`), nên E3–E7 cho
  kết quả quyết định (mã lỗi, đúng/sai) giống nhau trên mọi máy. Khóa sinh lại bằng `--fresh` có dấu vân tay khác
  nên các cột chứa key_id đổi theo. Chỉ số hiệu năng E2 phụ thuộc phần cứng (xem `results/benchmark_env.json`).

## Cấu trúc

| Đường dẫn | Nội dung |
|---|---|
| `sigeval/` | Thư viện: `core` (ba lược đồ, dấu vân tay), `manifest`, `trust` (trust list), `tsa` (dấu thời gian mô phỏng), `verify` (chính sách xác minh), `toyecdsa` (ECDSA đồ chơi cho E4), `cli` |
| `experiments/` | `e2_benchmark`, `e3_tamper`, `e4_nonce`, `e5_e6_lifecycle`, `e7_openssl_interop`, `make_figures`, `lab` |
| `tests/` | pytest, gồm kiểm thử tích hợp chạy lại E3/E5/E6 |
| `results/` | CSV/JSON kết quả: `benchmark*.csv`, `tamper_results.csv`, `rotation_results.csv`, `compromise_results.csv`, `nonce_results.json`, `interop_openssl.json`, `verify_log.txt` |
| `figures/` | Biểu đồ dùng trong báo cáo |
| `artifacts/` | Artifact gốc, bản bị sửa, bundle đã ký, trust list các phiên bản |
| `keys/` | Khóa thử nghiệm và `fingerprints.json` (LAB ONLY) |
| `report/` | Mã dựng báo cáo Word từ `results/` |

## Ví dụ dùng CLI

```bash
export PYTHONPATH=$PWD
python3 -m sigeval.cli keygen --alg ed25519 --out keys/demo
python3 -m sigeval.cli sign --dir artifacts/original --name demo --release 1.0.0 --seq 1 \
        --key keys/demo --alg ed25519 --out /tmp/demo.bundle.json
```
Xem docstring đầu `sigeval/cli.py` cho đủ tham số (`trustlist`, `verify`). Ví dụ có kết quả cụ thể ở mục 4.4 của báo cáo.

## Truy vết và giới hạn

Bảng truy vết minh chứng ở Phụ lục A của báo cáo (mã minh chứng – phép thử – kết quả mong đợi/thực tế – tệp liên quan).
Giới hạn chính: dấu thời gian là mô phỏng (không phải RFC 3161), không có PKI/X.509 thật hay HSM, đo hiệu năng trên
một máy ảo chia sẻ nên chỉ đọc theo bậc độ lớn và thứ hạng.
