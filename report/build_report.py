"""Dựng báo cáo Word từ số liệu thật trong results/. Chạy 3 lượt để có mục lục với số trang chính xác."""
import csv, glob, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from docx_lib import Doc
import part1, part2

RES = os.path.join(ROOT, "results"); FIGD = os.path.join(ROOT, "figures")
OUT = os.path.join(ROOT, "BaoCao_DeTai19_ChuKySo.docx")


def rd_csv(n):
    return list(csv.DictReader(open(os.path.join(RES, n), encoding="utf-8")))


def load():
    tam = rd_csv("tamper_results.csv")
    seen, cases = set(), []
    for r in tam:
        if r["test"] not in seen and r["alg"] == "ed25519":
            seen.add(r["test"]); cases.append(r)
    loc = {}
    for p in glob.glob(os.path.join(ROOT, "sigeval", "*.py")) + [os.path.join(ROOT, "tests", "test_sigeval.py")]:
        loc[os.path.relpath(p, ROOT)] = sum(1 for _ in open(p, encoding="utf-8"))
    loc["experiments/e2…e7, make_figures.py"] = sum(sum(1 for _ in open(p, encoding="utf-8")) for p in glob.glob(os.path.join(ROOT, "experiments", "*.py")))
    bundle = json.load(open(os.path.join(ROOT, "artifacts", "bundles", "ed25519.bundle.json")))
    return dict(
        sizes=rd_csv("sizes.csv"), summary=rd_csv("benchmark_summary.csv"), large=rd_csv("benchmark_large.csv"),
        tamper=tam, tamper_cases=cases, nonce=json.load(open(os.path.join(RES, "nonce_results.json"))),
        rotation=rd_csv("rotation_results.csv"), compromise=rd_csv("compromise_results.csv"),
        interop=json.load(open(os.path.join(RES, "interop_openssl.json"))), env=json.load(open(os.path.join(RES, "benchmark_env.json"))),
        manifest_arts=bundle["manifest"]["artifacts"], loc=loc, fp=json.load(open(os.path.join(ROOT, "keys", "fingerprints.json"))),
        fig=lambda n: os.path.join(FIGD, n))


def appendices(D, R):
    D.h("TÀI LIỆU THAM KHẢO", 1, page_break=True)
    for i, r in enumerate(part2.REFS, 1):
        para = D.d.add_paragraph(); para.paragraph_format.left_indent = __import__("docx").shared.Cm(1.0); para.paragraph_format.first_line_indent = __import__("docx").shared.Cm(-1.0)
        para.paragraph_format.space_after = __import__("docx").shared.Pt(3)
        D._runs(para, f"[{i}]  {r}", size=11)
    D.h("PHỤ LỤC A. BẢNG TRUY VẾT MINH CHỨNG", 1, page_break=True)
    tam_ok = sum(r["verdict"] == "PASS" for r in R["tamper"]); rot_ok = sum(r["verdict"] == "PASS" for r in R["rotation"]); cp_ok = sum(r["verdict"] == "PASS" for r in R["compromise"])
    D.table(["Mã", "Phép thử", "Kết quả mong đợi", "Kết quả thực tế", "Tệp minh chứng", "Phụ trách"], [
        ["E1", "Tạo bộ artifact + manifest", "3 tệp, băm khớp manifest", "Đạt", "`artifacts/original/`, `artifacts/bundles/*.json`", "[điền]"],
        ["E2a", "Kích thước khóa/chữ ký", "Ed25519 64 B; RSA-3072 384 B", "Đạt", "`results/sizes.csv`", "[điền]"],
        ["E2b", "Thời gian keygen/ký/xác minh (3 lần)", "Có trung vị, min–max", "Đã đo", "`results/benchmark_run1..3.csv`, `benchmark_summary.csv`, `benchmark_env.json`", "[điền]"],
        ["E2c", "Ký tệp lớn 1/10 MiB", "Ký trực tiếp vs băm", "Đã đo", "`results/benchmark_large.csv`", "[điền]"],
        ["E3", "19 ca sửa đổi × 3 thuật toán", "57/57 đúng kỳ vọng", f"{tam_ok}/{len(R['tamper'])}", "`results/tamper_results.csv`, `results/verify_log.txt`, `artifacts/tampered-*`", "[điền]"],
        ["E4", "Nonce, tái sử dụng nonce ECDSA", "Khôi phục được khóa; Ed25519 tất định", "Đạt", "`results/nonce_results.json`", "[điền]"],
        ["E5", "Luân chuyển khóa (12 ca)", "12/12", f"{rot_ok}/{len(R['rotation'])}", "`results/rotation_results.csv`, `artifacts/lifecycle/`", "[điền]"],
        ["E6", "Khóa bị lộ (9 ca)", "9/9", f"{cp_ok}/{len(R['compromise'])}", "`results/compromise_results.csv`", "[điền]"],
        ["E7", "Liên thông OpenSSL", "3/3 thuật toán, 2 chiều", "Đạt", "`results/interop_openssl.json`", "[điền]"],
        ["K1", "Khóa thử nghiệm + dấu vân tay công khai", "Có, ghi rõ LAB ONLY", "Có", "`keys/`, `keys/fingerprints.json`", "[điền]"],
        ["K2", "Sơ đồ vòng đời khóa ký", "Có", "Hình 3 ở Phụ lục E, `figures/f2_key_lifecycle.png`", "`figures/`", "[điền]"],
        ["K3", "Runbook khóa bị lộ", "Có, kèm bằng chứng kiểm thử", "Chương 7, `RUNBOOK.md`", "`RUNBOOK.md`", "[điền]"],
        ["T", "Kiểm thử tự động", "10/10 đạt", "10/10", "`tests/test_sigeval.py`", "[điền]"],
    ], widths=[1.1, 3.7, 3.3, 2.4, 4.3, 1.4], caption="Bảng truy vết: mỗi mục có thể tái tạo bằng `run_all.sh`.", size=8.5, align_center_cols=(0,))
    D.h("PHỤ LỤC B. ĐÓNG GÓP CỦA THÀNH VIÊN", 1)
    D.p("Theo yêu cầu của bộ đề tài, cả ba thành viên tham gia thiết kế, thực nghiệm, phân tích và bảo vệ. **Nhóm điền thông tin thật vào bảng này trước khi nộp**; các ô dưới đây là khung gợi ý, không phải ghi nhận đã xảy ra.", indent=False)
    D.table(["Thành viên", "Phần phụ trách chính (điền)", "Phần cùng tham gia", "Tỉ lệ đóng góp"], [
        ["[Họ tên 1]", "[vd: mô hình đe dọa, E3, vòng đời khóa]", "Thiết kế chung, kiểm thử chéo", "[ ]%"],
        ["[Họ tên 2]", "[vd: core/manifest, E2, E4]", "Thiết kế chung, kiểm thử chéo", "[ ]%"],
        ["[Họ tên 3]", "[vd: trust list/verify, E5, E6, runbook]", "Thiết kế chung, kiểm thử chéo", "[ ]%"],
    ], widths=[3.0, 6.3, 4.3, 2.2], caption="Phân công và đóng góp (mẫu cần điền).", size=10)
    D.h("PHỤ LỤC C. CÔNG KHAI SỬ DỤNG AI", 1)
    D.table(["Công cụ", "Mục đích sử dụng", "Nội dung đã kiểm tra", "Phần nhóm tự chịu trách nhiệm"], [
        ["Claude (Anthropic)", "Hỗ trợ viết mã nguyên mẫu `sigeval`, kịch bản thực nghiệm, biểu đồ và soạn thảo báo cáo này từ số liệu đo.",
         "Chạy lại toàn bộ thực nghiệm; pytest 10/10; đối chiếu bảng số liệu trong báo cáo với tệp CSV/JSON (báo cáo đọc trực tiếp từ các tệp này); kiểm chứng chéo chữ ký với OpenSSL; xem lại biểu đồ.",
         "Hiểu và giải thích được mọi thành phần khi bảo vệ; quyết định phạm vi, tiêu chí chấp nhận và kết luận; điền phân công thực tế; đối chiếu văn bản pháp luật và tài liệu tham khảo với nguồn gốc trước khi nộp."],
    ], widths=[2.4, 4.2, 4.9, 4.3], caption="Bảng công khai việc sử dụng AI (nhóm xác nhận/chỉnh sửa trước khi nộp).", size=9.5)
    D.h("PHỤ LỤC D. HƯỚNG DẪN TÁI LẬP", 1)
    D.code('''pip install -r requirements.txt --break-system-packages   # cryptography>=46, matplotlib, pytest, python-docx
./run_all.sh            # chạy E3–E7, benchmark 3 lần, vẽ hình, pytest   (~1 phút)
./run_all.sh --fresh    # xóa và sinh lại khóa thử nghiệm, artifact, kết quả
python3 report/build_report.py   # dựng lại báo cáo Word từ results/''')
    D.p("Thời gian mô phỏng và seed là hằng số nên E3–E7 cho kết quả giống nhau trên mọi máy; chỉ số đo hiệu năng (E2) thay đổi theo phần cứng và nên được ghi lại cùng `benchmark_env.json`.", indent=False)
    D.h("PHỤ LỤC E. DẤU VÂN TAY CÔNG KHAI VÀ TRÍCH LOG", 1)
    fp = R["fp"]
    want = [("root", "Khóa gốc ký trust list"), ("tsa", "Khóa TSA mô phỏng"), ("K1", "Luân chuyển: K1"), ("K2", "Luân chuyển: K2 (bị lộ)"), ("K3", "Luân chuyển: K3 (thay thế)"),
            ("tamper-rsa-pss-3072-a", "E3: khóa ký RSA-PSS 3072"), ("tamper-ecdsa-p256-a", "E3: khóa ký ECDSA P-256"), ("tamper-ed25519-a", "E3: khóa ký Ed25519")]
    D.table(["Khóa", "Thuật toán", "Dấu vân tay (8 byte đầu của SHA-256 SPKI)"], [[lab, fp[k]["alg"], f"`{fp[k]['short']}`"] for k, lab in want if k in fp],
            widths=[5.5, 3.0, 7.2], caption="Dấu vân tay khóa thử nghiệm (đầy đủ 64 hex trong `keys/fingerprints.json`). CHỈ DÙNG TRONG ĐỒ ÁN.", size=9.5)
    D.p("Trích `results/verify_log.txt` (Ed25519):", indent=False)
    lines = [l.rstrip("\n") for l in open(os.path.join(RES, "verify_log.txt"), encoding="utf-8") if l.startswith("[ed25519]")]
    D.code("\n".join((l[:118] + "…") if len(l) > 118 else l for l in lines[:14]), size=7)
    D.p("Mã nguồn đầy đủ, dữ liệu CSV và log nằm trong kho kèm theo (không tính vào số trang báo cáo).", indent=False, align="l")
    D.h("PHỤ LỤC F. SƠ ĐỒ VÒNG ĐỜI KHÓA KÝ", 1)
    D.figure(R["fig"]("f2_key_lifecycle.png"), "Vòng đời khóa ký (8 giai đoạn theo bài giảng) và đường tắt sang thu hồi khẩn cấp khi nghi ngờ lộ khóa.", 15.5)


def build(R, toc_entries, pages):
    D = Doc(); R = dict(R)
    part1.cover(D)
    part1.abstract(D, R)
    if toc_entries:
        part1.toc_placeholder(D, toc_entries, pages)
    part1.chapter1(D, R); part1.chapter2(D, R); part1.chapter3(D, R)
    part2.chapter4(D, R); part2.chapter5(D, R); part2.chapter6(D, R); part2.chapter7(D, R); part2.conclusion(D, R)
    appendices(D, R)
    D.footer_page_numbers()
    return D


def pdf_pages(docx_path):
    subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir", os.path.dirname(docx_path), docx_path], capture_output=True, check=True)
    pdf = docx_path.replace(".docx", ".pdf")
    n = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
    texts = [subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", pdf, "-"], capture_output=True, text=True).stdout for i in range(1, n + 1)]
    return pdf, n, texts


def find_pages(entries, texts):
    out = {}
    for lvl, h in entries:
        key = re.sub(r"\s+", " ", h)[:38]
        hit = None
        for i, t in enumerate(texts, 1):
            for line in t.splitlines():
                if re.sub(r"\s+", " ", line).strip().startswith(key) and "\t" not in line and not re.search(r"\.{3,}|\s\d+$", line.strip()[len(key):]):
                    hit = i
        out[h] = hit if hit else ""
    return out


if __name__ == "__main__":
    R = load()
    D0 = build(R, None, {})
    entries = list(D0.headings)
    tmp = os.path.join(ROOT, "report", "_tmp.docx")
    build(R, entries, {}).save(tmp)
    pdf, n, texts = pdf_pages(tmp)
    # mục lục nằm ở trang 3(+): chỉ lấy lần xuất hiện CUỐI (thân bài) của mỗi tiêu đề
    pages = find_pages(entries, texts)
    D = build(R, entries, pages); D.save(OUT)
    pdf, n, texts = pdf_pages(OUT)
    print("tổng số trang:", n, "->", OUT)
    for k, v in list(pages.items())[:60]:
        print(v, k)
    os.remove(tmp); os.path.exists(tmp.replace(".docx", ".pdf")) and os.remove(tmp.replace(".docx", ".pdf"))
