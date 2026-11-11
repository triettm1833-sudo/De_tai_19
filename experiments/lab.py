"""Thiết lập dùng chung: khóa thử nghiệm (LAB ONLY), bộ artifact, môi trường ghi nhận."""
from __future__ import annotations

import json
import os
import platform
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sigeval import core  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEYS = os.path.join(ROOT, "keys")
ART = os.path.join(ROOT, "artifacts")
RES = os.path.join(ROOT, "results")
SEED = 20260411
for d in (KEYS, ART, RES):
    os.makedirs(d, exist_ok=True)


def get_key(name: str, alg: str):
    """Tạo khóa thử nghiệm một lần, lưu vào keys/ (có cảnh báo LAB ONLY); lần sau nạp lại để tái lập."""
    path = os.path.join(KEYS, f"{name}.priv.pem")
    if os.path.exists(path):
        priv = core.load_priv_pem(open(path, "rb").read())
    else:
        priv = core.generate(alg)
        open(path, "wb").write(core.priv_pem(priv))
        open(os.path.join(KEYS, f"{name}.pub.pem"), "wb").write(core.pub_pem(priv.public_key()))
    return priv, priv.public_key()


def write_fingerprints(named: dict):
    out = {n: {"alg": a, "key_id": core.key_id(p), "short": core.fp_fmt(core.key_id(p))} for n, (a, p) in named.items()}
    json.dump(out, open(os.path.join(KEYS, "fingerprints.json"), "w"), indent=2)
    with open(os.path.join(KEYS, "README_LAB_ONLY.txt"), "w") as f:
        f.write("KHÓA THỬ NGHIỆM - CHỈ DÙNG CHO ĐỒ ÁN. Khóa riêng không mã hóa, đã công khai trong kho mã.\n"
                "Không dùng để ký phần mềm thật; không gắn với danh tính/chứng thư của tổ chức nào.\n")


def make_artifacts(dest: str, variant: str = "v1"):
    """Bộ artifact xác định (seeded): tệp nhị phân nhỏ, tài liệu, cấu hình."""
    os.makedirs(dest, exist_ok=True)
    rnd = random.Random(SEED)
    open(os.path.join(dest, "demo-app.bin"), "wb").write(b"\x7fELF-LAB" + bytes(rnd.getrandbits(8) for _ in range(64 * 1024)))
    doc = ("BIÊN BẢN NGHIỆM THU PHẦN MỀM (TÀI LIỆU MÔ PHỎNG)\n"
           "Phiên bản: 1.0.0 – Đơn vị: Lab ATTT – Giá trị hợp đồng: 100.000.000 VND\n" + "Nội dung điều khoản mẫu.\n" * 200)
    open(os.path.join(dest, "bien-ban.txt"), "w", encoding="utf-8").write(doc)
    os.makedirs(os.path.join(dest, "conf"), exist_ok=True)
    open(os.path.join(dest, "conf", "app.json"), "w").write(json.dumps({"endpoint": "https://example.invalid", "debug": False}, indent=1))


def env_info() -> dict:
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    cpu = "?"
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip(); break
    except OSError:
        pass
    return {"python": sys.version.split()[0], "cryptography": cryptography.__version__,
            "openssl_backend": backend.openssl_version_text(), "platform": platform.platform(),
            "cpu": cpu, "cpu_count": os.cpu_count(), "seed": SEED}
