"""Tổng hợp benchmark (3 lần chạy) và vẽ hình cho báo cáo."""
import csv, json, os, statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from lab import RES, ROOT

FIG = os.path.join(ROOT, "figures"); os.makedirs(FIG, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 200, "savefig.bbox": "tight"})
COL = {"rsa-pss-3072": "#2B6CB0", "ecdsa-p256": "#DD6B20", "ed25519": "#2F855A", "rsa-pss-2048": "#90B4DC"}
LBL = {"rsa-pss-3072": "RSA-PSS 3072", "ecdsa-p256": "ECDSA P-256", "ed25519": "Ed25519", "rsa-pss-2048": "RSA-PSS 2048"}
ORDER = ["rsa-pss-3072", "ecdsa-p256", "ed25519", "rsa-pss-2048"]

# ---------- aggregate ----------
runs = [list(csv.DictReader(open(os.path.join(RES, f"benchmark_run{i}.csv")))) for i in (1, 2, 3)]
agg = []
for j, r in enumerate(runs[0]):
    meds = [float(x[j]["median_us"]) for x in runs]; p95 = [float(x[j]["p95_us"]) for x in runs]
    agg.append({"alg": r["alg"], "op": r["op"], "n_per_run": r["n"], "median_of_runs_us": round(st.median(meds), 2),
                "min_run_median_us": round(min(meds), 2), "max_run_median_us": round(max(meds), 2),
                "mean_p95_us": round(st.fmean(p95), 2), "ops_per_s": round(1e6 / st.median(meds), 1),
                "cv_pct": round(100 * st.pstdev(meds) / st.fmean(meds), 1)})
with open(os.path.join(RES, "benchmark_summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(agg[0])); w.writeheader(); w.writerows(agg)
A = {(r["alg"], r["op"]): r for r in agg}
sizes = {r["alg"]: r for r in csv.DictReader(open(os.path.join(RES, "sizes.csv")))}


def box(ax, x, y, w, h, text, fc="#EDF2F7", ec="#4A5568", fs=8.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=fc, ec=ec, lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, p, q, text="", color="#4A5568", style="-|>"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=11, color=color, lw=1.1))
    if text:
        ax.text((p[0] + q[0]) / 2, (p[1] + q[1]) / 2 + 0.07, text, ha="center", fontsize=7.5, color=color)


# ---------- F1 kiến trúc ----------
fig, ax = plt.subplots(figsize=(9.2, 4.4)); ax.set_xlim(0, 10); ax.set_ylim(0, 5); ax.axis("off")
ax.text(0.1, 4.75, "BÊN PHÁT HÀNH (offline/CI)", fontweight="bold", color="#2B6CB0")
box(ax, 0.1, 3.55, 1.7, 0.85, "Artifact\n(bin, tài liệu, cấu hình)")
box(ax, 2.2, 3.55, 1.9, 0.85, "Manifest JSON\nSHA-256 từng tệp +\nprovenance + phiên bản")
box(ax, 4.5, 3.55, 1.8, 0.85, "PAE(alg, key_id,\ncanonical(manifest))")
box(ax, 6.7, 3.55, 1.5, 0.85, "Ký bằng\nkhóa riêng", fc="#FEEBC8", bold=True)
box(ax, 8.4, 3.55, 1.5, 0.85, "Bundle:\nmanifest + chữ ký\n+ dấu thời gian", fc="#C6F6D5")
for a, b in ((1.8, 2.2), (4.1, 4.5), (6.3, 6.7), (8.2, 8.4)):
    arrow(ax, (a, 3.97), (b, 3.97))
box(ax, 6.7, 2.45, 1.5, 0.7, "TSA (mô phỏng)\nký thời gian", fc="#E9D8FD"); arrow(ax, (7.45, 3.15), (7.45, 3.55), "")
ax.text(0.1, 1.95, "BÊN XÁC MINH (client)", fontweight="bold", color="#2F855A")
box(ax, 0.1, 0.55, 2.0, 1.1, "Trust list v_n\n(ký bởi khóa gốc,\nhết hạn, chống rollback)", fc="#E9D8FD")
box(ax, 2.5, 0.55, 1.9, 1.1, "Kiểm tra chữ ký\nđúng khóa, đúng\nthuật toán", fc="#FEEBC8")
box(ax, 4.8, 0.55, 2.0, 1.1, "Trạng thái khóa:\nhiệu lực / nghỉ hưu /\nthu hồi + dấu thời gian", fc="#FED7D7")
box(ax, 7.2, 0.55, 1.4, 1.1, "Băm lại từng\ntệp, tệp thừa/\nthiếu?")
box(ax, 8.9, 0.55, 1.0, 1.1, "ACCEPT /\nREJECT\n+ mã lỗi", fc="#C6F6D5", bold=True)
for a, b in ((2.1, 2.5), (4.4, 4.8), (6.8, 7.2), (8.6, 8.9)):
    arrow(ax, (a, 1.1), (b, 1.1))
ax.plot([0.1, 9.9], [2.2, 2.2], ls="--", color="#A0AEC0", lw=0.9); ax.text(5.0, 2.27, "bundle + trust list được phân phối qua kênh KHÔNG tin cậy (CDN, mirror, email)", ha="center", fontsize=8, color="#4A5568")
fig.savefig(os.path.join(FIG, "f1_architecture.png")); plt.close(fig)

# ---------- F2 vòng đời khóa ký ----------
fig, ax = plt.subplots(figsize=(9.2, 4.6)); ax.set_xlim(0, 10); ax.set_ylim(0, 5); ax.axis("off")
states = [("1. Sinh khóa\n(CSPRNG, offline/HSM)", 0.2, 3.7), ("2. Phân phối\nkhóa công khai\nvào trust list", 2.7, 3.7),
          ("3. Kích hoạt\n(not_before, mục đích\n= ký phát hành)", 5.2, 3.7), ("4. Sử dụng\n(ký + dấu thời gian)", 7.7, 3.7),
          ("5. Luân chuyển\n(chồng lấn, ký kép)", 7.7, 1.9), ("6. Nghỉ hưu\n(not_after; chỉ xác minh\nbản cũ có timestamp)", 5.2, 1.9),
          ("7. Thu hồi\n(compromised_since,\nký lại)", 2.7, 1.9), ("8. Hủy khóa riêng\n(giữ khóa công khai\nđể kiểm toán)", 0.2, 1.9)]
for t, x, y in states:
    box(ax, x, y, 2.1, 1.0, t, fc="#EBF8FF" if y > 3 else "#FFF5F5", fs=8)
for i in range(3):
    arrow(ax, (states[i][1] + 2.1, 4.2), (states[i + 1][1], 4.2))
arrow(ax, (8.75, 3.7), (8.75, 2.9)); ax.text(8.85, 3.25, "theo chính sách", fontsize=7.5, color="#4A5568")
arrow(ax, (7.7, 2.4), (7.3, 2.4)); arrow(ax, (5.2, 2.4), (4.8, 2.4)); arrow(ax, (2.7, 2.4), (2.3, 2.4))
arrow(ax, (7.7, 2.7), (6.3, 3.7), "khóa mới\nvào vòng đời", color="#2F855A")
box(ax, 3.0, 0.2, 4.2, 0.8, "Sự cố: nghi lộ khóa ở BẤT KỲ giai đoạn 4–6 -> nhảy thẳng tới 7 (thu hồi khẩn cấp)", fc="#FED7D7", ec="#C53030", fs=8)
arrow(ax, (5.0, 1.0), (3.9, 1.9), color="#C53030")
fig.savefig(os.path.join(FIG, "f2_key_lifecycle.png")); plt.close(fig)

# ---------- F3 thời gian ký/xác minh (dot plot, log: không có đường gốc gây hiểu nhầm) ----------
fig, axs = plt.subplots(1, 2, figsize=(9, 3.0), sharey=True)
for ax, op, ttl in ((axs[0], "sign", "Ký (manifest ~1 KB)"), (axs[1], "verify", "Xác minh")):
    for i, a in enumerate(ORDER[::-1]):
        r = A[(a, op)]; v = r["median_of_runs_us"]
        ax.plot([r["min_run_median_us"], r["max_run_median_us"]], [i, i], color=COL[a], lw=2.2, alpha=0.6)
        ax.plot(v, i, "o", color=COL[a], ms=8)
        ax.text(max(r["max_run_median_us"], v) * 1.18, i, f"{v:,.0f} µs", va="center", fontsize=8)
    ax.set_xscale("log"); ax.set_xlim(15, 4000); ax.set_title(ttl, fontsize=10); ax.set_xlabel("µs (trung vị 3 lần chạy; đoạn = min–max)")
    ax.set_yticks(range(4)); ax.set_yticklabels([LBL[a] for a in ORDER[::-1]]); ax.grid(axis="x", alpha=0.25)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "f3_benchmark.png")); plt.close(fig)

# ---------- F4 kích thước ----------
fig, axs = plt.subplots(1, 2, figsize=(9, 3.1))
for ax, key, ttl in ((axs[0], "sig_mean_B", "Kích thước chữ ký (byte)"), (axs[1], "public_spki_der_B", "Khóa công khai SPKI DER (byte)")):
    vals = [float(sizes[a][key]) for a in ORDER]
    ax.bar(range(4), vals, color=[COL[a] for a in ORDER], width=0.65)
    for x, v in enumerate(vals):
        ax.text(x, v + max(vals) * 0.02, f"{v:.0f}" if v == int(v) else f"{v:.1f}", ha="center", fontsize=8)
    ax.set_xticks(range(4)); ax.set_xticklabels([LBL[a].replace(" ", "\n", 1) for a in ORDER], fontsize=8); ax.set_title(ttl, fontsize=10)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "f4_sizes.png")); plt.close(fig)

# ---------- F5 ký tệp lớn: trực tiếp vs băm trước ----------
big = list(csv.DictReader(open(os.path.join(RES, "benchmark_large.csv"))))
fig, ax = plt.subplots(figsize=(6.4, 3.1))
sel = [r for r in big if float(r["size_MiB"]) == 10 and r["alg"] in COL and r["alg"] != "rsa-pss-2048"]
xs = range(len(sel)); ax.bar([x - 0.2 for x in xs], [float(r["sign_direct_median_ms"]) for r in sel], 0.38, color=[COL[r["alg"]] for r in sel], label="ký trực tiếp 10 MiB")
ax.bar([x + 0.2 for x in xs], [float(r["sha256_only_median_ms"]) for r in sel], 0.38, color="#A0AEC0", label="chỉ SHA-256 10 MiB (thiết kế ký manifest)")
for x, r in zip(xs, sel):
    ax.text(x - 0.2, float(r["sign_direct_median_ms"]) + 0.6, f"{float(r['sign_direct_median_ms']):.1f}", ha="center", fontsize=8)
ax.set_xticks(list(xs)); ax.set_xticklabels([LBL[r["alg"]] for r in sel]); ax.set_ylabel("ms (trung vị)"); ax.legend(fontsize=8, frameon=False)
fig.savefig(os.path.join(FIG, "f5_large_file.png")); plt.close(fig)

# ---------- F6 ma trận tamper ----------
rows = list(csv.DictReader(open(os.path.join(RES, "tamper_results.csv"))))
tests = []
for r in rows:
    if r["test"] not in [t[0] for t in tests]:
        tests.append((r["test"], r["description"], r["expected"]))
algs = ["rsa-pss-3072", "ecdsa-p256", "ed25519"]
cell = {(r["test"], r["alg"]): r for r in rows}
fig, ax = plt.subplots(figsize=(9, 6.6)); ax.set_xlim(0, 11.6); ax.set_ylim(0, len(tests) + 1); ax.axis("off")
ax.text(0.1, len(tests) + 0.4, "Ca kiểm thử", fontweight="bold");
for j, a in enumerate(algs):
    ax.text(7.4 + j * 1.35 + 0.6, len(tests) + 0.4, LBL[a].replace(" ", "\n", 1), ha="center", fontweight="bold", fontsize=8, va="center")
for i, (tid, desc, exp) in enumerate(tests):
    y = len(tests) - 1 - i
    ax.text(0.1, y + 0.4, f"{tid}  {desc}", fontsize=7.2, va="center")
    for j, a in enumerate(algs):
        c = cell[(tid, a)]; good = c["verdict"] == "PASS"
        acc = c["actual"] == "OK"
        fc = ("#C6F6D5" if acc else "#FED7D7") if good else "#F6E05E"
        ax.add_patch(plt.Rectangle((7.4 + j * 1.35, y + 0.05), 1.25, 0.8, fc=fc, ec="white"))
        ax.text(7.4 + j * 1.35 + 0.62, y + 0.45, "ACCEPT" if acc else c["actual"].replace("_", "\n", 1) if len(c["actual"]) > 12 else c["actual"], ha="center", va="center", fontsize=6.3)
ax.text(0.1, -0.35, "Xanh = chấp nhận (đúng kỳ vọng) · Đỏ = từ chối với mã lỗi (đúng kỳ vọng) · Vàng = khác kỳ vọng (không có)", fontsize=7.5)
fig.savefig(os.path.join(FIG, "f6_tamper_matrix.png")); plt.close(fig)

# ---------- F7 timeline luân chuyển khóa ----------
import datetime as dt
D = lambda s: dt.date(2026, int(s[:2]), int(s[3:]))
fig, ax = plt.subplots(figsize=(9.2, 3.8))
bars = [("K1 Ed25519", "01-01", "03-31", "#2F855A", ""), ("K2 ECDSA P-256", "03-01", "06-20", "#DD6B20", "(thu hồi 20/06)"),
        ("K3 Ed25519", "06-20", "09-20", "#2B6CB0", "(thay thế)")]
for i, (n, a, b, c, t) in enumerate(bars):
    ax.barh(3 - i, (D(b) - D(a)).days, left=D(a).toordinal(), color=c, height=0.5)
    ax.text(D(a).toordinal() + (34 if i == 1 else 2), 3 - i, (n + " " + t).strip(), va="center", fontsize=7.5, color="white" if i != 1 else "black")
ax.axvspan(D("03-01").toordinal(), D("03-31").toordinal(), color="#FAF089", alpha=0.45); ax.text(D("03-02").toordinal(), 3.55, "chồng lấn", fontsize=7.5)
ax.axvspan(D("06-10").toordinal(), D("06-20").toordinal(), color="#FEB2B2", alpha=0.5); ax.text(D("06-04").toordinal(), 3.55, "cửa sổ nghi ngờ", fontsize=7.5)
for lab, d_, y in (("R1.0", "02-01", 0), ("R1.1\n(ký kép)", "03-15", 0), ("R1.2", "04-10", 0), ("R1.3", "06-15", 0)):
    ax.plot(D(d_).toordinal(), y, "v", color="#1A202C"); ax.text(D(d_).toordinal(), y - 0.5, lab, ha="center", fontsize=7.5)
ax.plot(D("06-12").toordinal(), 0, "x", color="#C53030", ms=9, mew=2); ax.text(D("06-08").toordinal(), 0.45, "mã độc ký bằng K2 (12/06)", ha="right", fontsize=7.5, color="#C53030")
for v, d_ in ((1, "01-01"), (2, "03-01"), (3, "04-01"), (4, "06-20")):
    ax.axvline(D(d_).toordinal(), color="#718096", ls=":", lw=0.8); ax.text(D(d_).toordinal() + 1, -1.0, f"TL v{v}", fontsize=7.5, color="#4A5568")
ticks = [D(f"{m:02d}-01") for m in range(1, 10)]
ax.set_xticks([t.toordinal() for t in ticks]); ax.set_xticklabels([t.strftime("%d/%m") for t in ticks], fontsize=8)
ax.set_yticks([]); ax.set_ylim(-1.2, 4); ax.spines["left"].set_visible(False)
fig.savefig(os.path.join(FIG, "f7_rotation_timeline.png")); plt.close(fig)
print("figures:", sorted(os.listdir(FIG)))
