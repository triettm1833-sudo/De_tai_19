"""Phần 2: chương 4-7, kết luận, tài liệu tham khảo, phụ lục."""
import json, os


def f1(x, nd=1):
    return f"{float(x):,.{nd}f}"


def chapter4(D, R):
    E = R["env"]["env"]
    D.h("CHƯƠNG 4. TRIỂN KHAI NGUYÊN MẪU", 1, page_break=True)
    D.h("4.1. Môi trường và công cụ", 2)
    D.table(["Hạng mục", "Giá trị"], [
        ["Hệ điều hành / máy", f"{E['platform']}; {E['cpu']} ({E['cpu_count']} vCPU); container cô lập"],
        ["Python", E["python"]],
        ["Thư viện mật mã", f"`cryptography` {E['cryptography']} [20], backend {E['openssl_backend']}"],
        ["OpenSSL CLI (E7)", R["interop"]["openssl"].split(" (")[0] + " [24]"],
        ["Thư viện hỗ trợ", "matplotlib (biểu đồ), pytest (kiểm thử), python-docx (báo cáo)"],
        ["Seed dữ liệu", f"{E['seed']} (sinh tệp nhị phân xác định)"],
    ], widths=[4.2, 11.5], caption="Môi trường chạy thực nghiệm (ghi trong `results/benchmark_env.json`).", size=10)
    D.p("Lưu ý hai phiên bản OpenSSL khác nhau: Python dùng thư viện OpenSSL đóng gói kèm wheel của `cryptography`, còn E7 dùng chương trình `openssl` của hệ điều hành. Việc hai bản khác nhau lại xác minh được chữ ký của nhau là một điểm cộng cho tính liên thông (E7).")
    D.h("4.2. Cấu trúc mã nguồn", 2)
    rows = [[f"`{m}`", d, str(R['loc'].get(m, ''))] for m, d in [
        ("sigeval/core.py", "Sinh khóa, ký, xác minh RSA-PSS/ECDSA/Ed25519; dấu vân tay khóa"),
        ("sigeval/manifest.py", "Manifest, JSON chuẩn hóa, PAE, đóng gói bundle"),
        ("sigeval/trust.py", "Trust list có phiên bản; kiểm tra chữ ký gốc, hạn dùng, rollback"),
        ("sigeval/tsa.py", "TSA mô phỏng và kiểm tra dấu thời gian"),
        ("sigeval/verify.py", "Bộ xác minh theo chính sách (3.5); mã lỗi"),
        ("sigeval/toyecdsa.py", "ECDSA P-256 đồ chơi cho tấn công nonce (kiểm chứng chéo với thư viện)"),
        ("sigeval/cli.py", "Giao diện dòng lệnh: keygen, sign, trustlist, verify"),
        ("experiments/e2…e7, make_figures.py", "Các thực nghiệm và biểu đồ; `run_all.sh` chạy lại từ đầu"),
        ("tests/test_sigeval.py", "10 kiểm thử pytest")]]
    D.table(["Tệp", "Vai trò", "Dòng"], rows, widths=[5.2, 9.2, 1.4], caption="Cấu trúc mã nguồn.", size=9.5, align_center_cols=(2,))
    D.h("4.3. Quyết định triển khai đáng chú ý", 2)
    D.bullets([
        "**Chỉ dùng API cấp cao của thư viện.** Ký/xác minh gọi `PrivateKey.sign` và `PublicKey.verify`; nhóm không đụng tới số học đường cong hay đệm. Ngoại lệ duy nhất là `toyecdsa.py`, dùng riêng cho E4 và được kiểm chứng chéo: chữ ký đồ chơi phải được thư viện chấp nhận.",
        "**Xác minh trả về bool, mọi ngoại lệ mật mã bị bắt tại một chỗ** (`InvalidSignature`, `ValueError`, `TypeError`) để dữ liệu hỏng định dạng không làm bộ xác minh sập mà trở thành “từ chối” có mã lỗi.",
        "**Ghim thuật toán ở trust list**, không tin nhãn `alg` do bundle khai: khóa công khai được nạp từ trust list và kiểu khóa phải khớp, nhờ vậy chặn tấn công nhầm lẫn thuật toán (ca T10, T11).",
        "**Mã lỗi riêng cho từng nguyên nhân** thay vì một thông báo chung, để log xác minh dùng làm minh chứng (`results/verify_log.txt`) và để runbook phân loại sự cố.",
        "**Tái lập:** khóa thử nghiệm được lưu một lần trong `keys/`, artifact sinh bằng seed cố định, mọi thời gian mô phỏng là hằng số; `run_all.sh --fresh` sinh lại toàn bộ.",
    ])
    D.h("4.4. Ví dụ sử dụng", 2)
    D.code('''python -m sigeval.cli keygen --alg ed25519 --out keys/release
python -m sigeval.cli sign   --dir artifacts/original --key keys/release --alg ed25519 \\
                             --name demo-app --release 1.0.0 --out bundle.json
python -m sigeval.cli trustlist --version 1 --issued 2026-01-01T00:00:00Z \\
                             --expires 2026-04-01T00:00:00Z --key ed25519:keys/release.pub.pem \\
                             --root keys/root --out trustlist.json
python -m sigeval.cli verify --dir artifacts/original --bundle bundle.json \\
                             --trustlist trustlist.json --root-pub keys/root.pub.pem
# PASS OK                    (sửa 1 byte trong demo-app.bin ->  FAIL HASH_MISMATCH)''')
    D.h("4.5. Kiểm thử tự động", 2)
    D.p("Bộ pytest gồm 10 kiểm thử: vòng ký–xác minh và âm tính cho cả 4 cấu hình thuật toán (khóa khác, thông điệp khác, chữ ký bị lật bit), PAE ràng buộc alg/key_id, chuẩn hóa không phụ thuộc thứ tự khóa, tính tất định của Ed25519 so với ECDSA, kiểm chứng chéo ECDSA đồ chơi với thư viện cùng khôi phục khóa, "
        "và hai kiểm thử tích hợp chạy lại toàn bộ E3, E5, E6 rồi khẳng định mọi ca đúng kỳ vọng. Lần chạy cuối: 10/10 đạt.")


def chapter5(D, R):
    S = {r["alg"]: r for r in R["sizes"]}
    A = {(r["alg"], r["op"]): r for r in R["summary"]}
    L = {(r["alg"], int(float(r["size_MiB"]))): r for r in R["large"]}
    D.h("CHƯƠNG 5. THỰC NGHIỆM VÀ KẾT QUẢ", 1, page_break=True)
    D.h("5.1. E1 – Bộ artifact", 2)
    arts = R["manifest_arts"]
    D.table(["Tệp", "Kích thước (byte)", "SHA-256 (16 hex đầu)", "Loại"], [
        [f"`{a['path']}`", f"{a['size']:,}", a["sha256"][:16] + "…", t] for a, t in zip(arts, ["Cấu hình", "Tệp nhị phân mô phỏng", "Tài liệu văn bản"])
    ], widths=[4.0, 3.2, 5.2, 3.3], caption="Bộ artifact dùng cho E3 (sinh bằng seed cố định; nằm ở `artifacts/original`).", size=10, align_center_cols=(1,))
    D.p("Tệp nhị phân gồm tiêu đề giả ELF và 64 KiB byte ngẫu nhiên có seed; tài liệu mô phỏng một biên bản nghiệm thu có số tiền (để dễ hình dung hậu quả khi bị sửa). Manifest được dựng từ thư mục này, tệp được sắp theo đường dẫn. Các bản bị sửa mẫu nằm ở `artifacts/tampered-binary` và `artifacts/tampered-document`.")

    D.h("5.2. E2 – Kích thước và hiệu năng", 2)
    D.table(["Thuật toán", "Khóa riêng PKCS#8 (B)", "Khóa công khai SPKI (B)", "Chữ ký (B)", "Ghi chú"], [
        ["RSA-PSS 3072", S["rsa-pss-3072"]["private_pkcs8_der_B"], S["rsa-pss-3072"]["public_spki_der_B"], S["rsa-pss-3072"]["sig_mean_B"], "= độ dài modulus"],
        ["ECDSA P-256", S["ecdsa-p256"]["private_pkcs8_der_B"], S["ecdsa-p256"]["public_spki_der_B"], f"{S['ecdsa-p256']['sig_min_B']}–{S['ecdsa-p256']['sig_max_B']} (TB {S['ecdsa-p256']['sig_mean_B']})", "DER, độ dài đổi theo r, s"],
        ["Ed25519", S["ed25519"]["private_pkcs8_der_B"], S["ed25519"]["public_spki_der_B"], S["ed25519"]["sig_mean_B"], "Cố định"],
        ["RSA-PSS 2048 (đối chứng)", S["rsa-pss-2048"]["private_pkcs8_der_B"], S["rsa-pss-2048"]["public_spki_der_B"], S["rsa-pss-2048"]["sig_mean_B"], "≈ 112 bit"],
    ], widths=[3.9, 2.9, 2.9, 3.0, 3.0], caption="Kích thước khóa và chữ ký (300 chữ ký ngẫu nhiên mỗi thuật toán).", size=9.5, align_center_cols=(1, 2, 3))
    D.figure(R["fig"]("f4_sizes.png"), "Kích thước chữ ký và khóa công khai.", 13.5)
    rows = []
    for a, lab in (("rsa-pss-3072", "RSA-PSS 3072"), ("ecdsa-p256", "ECDSA P-256"), ("ed25519", "Ed25519"), ("rsa-pss-2048", "RSA-PSS 2048")):
        k, s, v = A[(a, "keygen")], A[(a, "sign")], A[(a, "verify")]
        rows.append([lab, f"{f1(k['median_of_runs_us'], 0)}", f"{f1(s['median_of_runs_us'], 1)} ({f1(s['min_run_median_us'], 0)}–{f1(s['max_run_median_us'], 0)})",
                     f"{f1(v['median_of_runs_us'], 1)} ({f1(v['min_run_median_us'], 0)}–{f1(v['max_run_median_us'], 0)})", f"{float(s['ops_per_s']):,.0f} / {float(v['ops_per_s']):,.0f}"])
    D.table(["Thuật toán", "Sinh khóa (µs)", "Ký (µs)", "Xác minh (µs)", "Ops/s: ký / xác minh"], rows, widths=[3.4, 2.9, 3.4, 3.4, 3.2],
            caption="Thời gian trung vị của 3 lần chạy (trong ngoặc: min–max giữa các lần), payload ≈ 1 KB.", size=9.5, align_center_cols=(1, 2, 3, 4))
    D.figure(R["fig"]("f3_benchmark.png"), "Thời gian ký và xác minh (thang log). Điểm = trung vị của 3 lần chạy; đoạn = min–max giữa các lần.", 15.5)
    rs, es, ds = float(A[("rsa-pss-3072", "sign")]["median_of_runs_us"]), float(A[("ecdsa-p256", "sign")]["median_of_runs_us"]), float(A[("ed25519", "sign")]["median_of_runs_us"])
    rv, ev, dv = (float(A[(a, "verify")]["median_of_runs_us"]) for a in ("rsa-pss-3072", "ecdsa-p256", "ed25519"))
    D.p(f"**Nhận xét.** (i) Về kích thước, Ed25519 gọn nhất (khóa công khai 44 B, chữ ký 64 B); RSA-PSS 3072 có chữ ký lớn gấp 6 lần và khóa công khai gấp gần 10 lần, nhưng với manifest vài KB phần chênh lệch này không đáng kể trong một bó phát hành. "
        f"(ii) Ký: RSA-PSS 3072 mất {rs:,.0f} µs, gấp {rs / es:.0f} lần ECDSA ({es:.0f} µs) và {rs / ds:.0f} lần Ed25519 ({ds:.0f} µs). "
        f"(iii) Xác minh: ngược lại, RSA-PSS nhanh nhất ({rv:.0f} µs) nhờ số mũ công khai nhỏ, ECDSA {ev:.0f} µs, Ed25519 {dv:.0f} µs. Với mô hình “ký một lần, xác minh nhiều lần”, RSA-PSS có lợi thế về CPU phía người dùng; đổi lại là băng thông và dung lượng. "
        f"(iv) **Điều đáng chú ý:** trên môi trường này Ed25519 *không* nhanh hơn ECDSA P-256 (ký {ds / es:.2f}×, xác minh {dv / ev:.2f}× thời gian của ECDSA). "
        "Nhóm chưa kiểm chứng nguyên nhân; một giả thuyết hợp lý là cài đặt P-256 trong OpenSSL được tối ưu bằng mã hợp ngữ chuyên biệt, trong khi Ed25519 dùng đường mã tổng quát hơn. Kết luận “Ed25519 nhanh hơn” từ tài liệu [9] là kết quả của phần cứng và cài đặt thời điểm đó và không nên coi là hằng đúng.")
    D.p(f"**Độ tin cậy của số đo.** Độ lệch giữa các lần chạy (hệ số biến thiên của trung vị) dao động từ {min(float(r['cv_pct']) for r in R['summary'])}% đến {max(float(r['cv_pct']) for r in R['summary'])}%; các phép tính cỡ chục µs (ECDSA) nhiễu nhiều nhất. Thời gian đo bao gồm chi phí gọi từ Python (vài µs) nên làm tỉ lệ giữa các phép nhanh bị nén lại. "
        "Chỉ nên đọc kết quả theo bậc độ lớn và thứ hạng, không theo con số tuyệt đối; thử nghiệm chạy trên một máy ảo 2 vCPU chia sẻ, một luồng.")
    D.h("5.2.1. Ký tệp lớn: ký trực tiếp so với ký manifest", 3)
    D.table(["Thuật toán", "Ký trực tiếp 1 MiB (ms)", "Ký trực tiếp 10 MiB (ms)", "Xác minh trực tiếp 10 MiB (ms)", "SHA-256 10 MiB (ms)"],
            [[lab, f1(L[(a, 1)]["sign_direct_median_ms"], 2), f1(L[(a, 10)]["sign_direct_median_ms"], 1), f1(L[(a, 10)]["verify_direct_median_ms"], 1), f1(L[(a, 10)]["sha256_only_median_ms"], 1)]
             for a, lab in (("rsa-pss-3072", "RSA-PSS 3072"), ("ecdsa-p256", "ECDSA P-256"), ("ed25519", "Ed25519"))],
            widths=[3.4, 3.1, 3.2, 3.5, 3.0], caption="Ký trực tiếp tệp lớn (trung vị, 1 lần chạy 5 mẫu).", size=9.5, align_center_cols=(1, 2, 3, 4))
    D.figure(R["fig"]("f5_large_file.png"), "Ký trực tiếp 10 MiB so với chỉ băm SHA-256 10 MiB.", 11.5)
    D.p(f"Với RSA-PSS và ECDSA, thư viện băm SHA-256 trước nên chi phí ký tệp lớn gần bằng chi phí băm ({f1(L[('rsa-pss-3072', 10)]['sign_direct_median_ms'], 1)} và {f1(L[('ecdsa-p256', 10)]['sign_direct_median_ms'], 1)} ms so với {f1(L[('ecdsa-p256', 10)]['sha256_only_median_ms'], 1)} ms băm). "
        f"Ed25519 “thuần” xử lý toàn bộ thông điệp trong một lượt và băm hai lần bằng SHA-512 nên mất {f1(L[('ed25519', 10)]['sign_direct_median_ms'], 1)} ms, gấp khoảng {float(L[('ed25519', 10)]['sign_direct_median_ms']) / float(L[('ed25519', 10)]['sha256_only_median_ms']):.1f} lần chi phí băm SHA-256 (và buộc nạp cả tệp vào bộ nhớ). "
        "Đây là lý do thực tế để thiết kế **ký manifest thay vì ký tệp**: chi phí chữ ký trở thành hằng số theo kích thước artifact, phần còn lại là băm từng tệp bằng SHA-256 vốn được tăng tốc phần cứng, và việc băm có thể thực hiện theo luồng.")

    D.h("5.3. E3 – Sửa từng thành phần và hành vi xác minh", 2)
    cases = R["tamper_cases"]
    D.table(["Ca", "Thao tác sửa đổi", "Thành phần", "Kết quả (cả 3 thuật toán)"],
            [[c["test"], c["description"], c["component"], f"`{c['actual']}`"] for c in cases],
            widths=[1.2, 6.2, 4.4, 3.9], caption="Kết quả E3: 19 ca; mỗi ca chạy với RSA-PSS 3072, ECDSA P-256 và Ed25519 (57 lần xác minh, đều đúng kỳ vọng).", size=9, align_center_cols=(0,))
    D.figure(R["fig"]("f6_tamper_matrix.png"), "Ma trận kết quả E3. Xanh: chấp nhận; đỏ: từ chối với mã lỗi. Không có ô nào khác kỳ vọng.", 14.5)
    D.p("**Phân tích.** (1) Có hai lớp phát hiện độc lập: sửa *nội dung tệp* (T01, T02) bị lớp băm bắt ở bước cuối (`HASH_MISMATCH`), trong khi sửa *manifest hoặc metadata* (T03–T07) bị lớp chữ ký bắt trước khi đụng tới tệp (`BAD_SIGNATURE`). "
        "T07 là ca quan trọng: kẻ tấn công sửa tệp rồi tính lại băm trong manifest cho khớp; chỉ chữ ký trên manifest mới ngăn được điều này. "
        "(2) Nhầm lẫn khóa và thuật toán (T09–T11) bị chặn bởi hai cơ chế khác nhau: PAE ràng buộc alg và key_id vào dữ liệu ký, và trust list ghim kiểu thuật toán của từng khóa. "
        "(3) Việc từ chối tệp thừa (T13) là quyết định thiết kế có chủ đích: nếu chỉ kiểm tra các tệp có trong manifest thì kẻ tấn công có thể thả thêm một tệp vào thư mục cài đặt (ví dụ thư viện bị nạp) mà không phá chữ ký nào. "
        "(4) T17 cho thấy chuẩn hóa JSON hấp thụ khác biệt định dạng vô hại, không gây từ chối nhầm.")
    D.p("**Ca T18 – ranh giới của bảo vệ.** Sửa trường `unprotected.notes` *không* làm xác minh thất bại, đúng như thiết kế. Ý nghĩa: chữ ký chỉ bảo vệ những gì nằm trong phạm vi được ký; việc thuật toán mạnh đến đâu không thay đổi điều này. "
        "Quy tắc rút ra: mọi dữ liệu dùng để ra quyết định hoặc hiển thị cho người dùng như thông tin đáng tin phải nằm trong manifest; bộ xác minh phải bỏ qua phần ngoài phạm vi ký. Đây cũng là nguyên nhân của một lớp lỗ hổng thực tế khi giao diện hiển thị trường chưa được ký.")
    D.p("**Giới hạn của E3.** Kỳ vọng do chính nhóm viết nên một lỗi hiểu nhầm có thể lọt cả ở mã lẫn ở kỳ vọng. Lớp mật mã nguyên thủy được bảo vệ một phần nhờ E7 (đối chiếu độc lập với OpenSSL); lớp chính sách (trust list, dấu thời gian) chỉ được kiểm chứng bằng kiểm thử của nhóm. Chưa thực hiện kiểm thử đột biến (cố ý chèn lỗi vào bộ xác minh) hay fuzzing định dạng bundle.")

    D.h("5.4. E4 – Nonce: tính tất định và tái sử dụng nonce", 2)
    N = R["nonce"]; dt = N["determinism"]
    D.table(["Cấu hình", "Số chữ ký khác nhau trong 20 lần ký cùng thông điệp", "Tất định?"], [
        ["RSA-PSS 3072 (muối ngẫu nhiên)", dt["rsa-pss-3072"]["distinct_signatures_in_20"], "Không"],
        ["ECDSA P-256 (nonce ngẫu nhiên)", dt["ecdsa-p256"]["distinct_signatures_in_20"], "Không"],
        ["ECDSA P-256 RFC 6979 (`deterministic_signing=True`)", dt["ecdsa-p256-rfc6979"]["distinct_signatures_in_20"], "Có (chữ ký vẫn xác minh đúng)"],
        ["Ed25519", dt["ed25519"]["distinct_signatures_in_20"], "Có"],
    ], widths=[7.2, 5.0, 3.5], caption="Tính tất định của chữ ký.", size=10, align_center_cols=(1,))
    e = N["ed25519_R"]; n = N["ecdsa_nonce_reuse"]
    D.p(f"Với Ed25519, nửa đầu chữ ký (điểm `R = r·B`) trùng khi ký lại cùng thông điệp và khác khi đổi thông điệp (`R₀ = {e['R_msg0'][:16]}…`, `R₁ = {e['R_msg1'][:16]}…`), xác nhận nonce là hàm tất định của (khóa, thông điệp).")
    D.p("**Tái sử dụng nonce ECDSA (chỉ trên khóa thử nghiệm).** Nhóm sinh khóa nạn nhân P-256, dùng `toyecdsa.py` ký hai thông điệp với cùng nonce `k`, rồi áp dụng công thức ở mục 2.4:")
    D.table(["Phép kiểm", "Kết quả"], [
        ["Hai chữ ký đồ chơi được thư viện chuẩn xác minh bằng khóa công khai nạn nhân", "Có (cả hai)" if all(n["toy_sigs_verify_with_library"]) else "Không"],
        ["Giá trị r của hai chữ ký trùng nhau", "Có" if n["same_r_observed"] else "Không"],
        ["Khóa riêng khôi phục từ (r, s₁, s₂, M₁, M₂) bằng khóa riêng thật", "Có" if n["recovered_equals_private_key"] else "Không"],
        ["Chữ ký giả mạo bằng khóa khôi phục được xác minh dưới khóa công khai nạn nhân", "Có" if n["forged_signature_verifies_under_victim_pub"] else "Không"],
        ["Đối chứng: hai nonce khác nhau cho cùng r?", "Không (công thức không áp dụng được)" if not n["control_distinct_nonces_same_r"] else "Có"],
    ], widths=[11.2, 4.5], caption="Kết quả tấn công tái sử dụng nonce.", size=10)
    D.p("Kết quả khẳng định điều bài giảng nêu: chỉ cần hai chữ ký dùng chung nonce là đủ để giả mạo mọi chữ ký tiếp theo, mà không phải phá bài toán logarit rời rạc. Cần nhấn mạnh rằng thư viện chuẩn sinh nonce an toàn; rủi ro nằm ở môi trường: RNG bị sao chép sau khi nhân bản máy ảo, RNG sau khởi động chưa đủ entropy, hay mã tự cài đặt. "
        "Phòng thủ gồm dùng Ed25519 hoặc ECDSA tất định (RFC 6979), ký trong HSM/KMS, và giám sát trùng giá trị `r` trên các chữ ký đã phát hành.")

    D.h("5.5. E5 – Luân chuyển khóa với giai đoạn chồng lấn", 2)
    D.figure(R["fig"]("f7_rotation_timeline.png"), "Dòng thời gian mô phỏng: K1 → K2 (chồng lấn 01–31/03), thu hồi K2 và chuyển sang K3 sau sự cố (E6). TL v1–v4 là các phiên bản trust list.", 15.5)
    D.p("Kịch bản dùng ba khóa với thuật toán khác nhau để thể hiện tính linh hoạt về thuật toán (K1 Ed25519, K2 ECDSA P-256, K3 Ed25519). Bốn trust list: v1 (chỉ K1), v2 (K1 và K2 cùng hiệu lực), v3 (K1 nghỉ hưu 31/03, K2 hiệu lực), v4 (sau sự cố, xem 5.6). Ba bản phát hành: 1.0.0 (K1, 01/02), 1.1.0 (ký kép K1 và K2, 15/03), 1.2.0 (chỉ K2, 10/04). Mọi chữ ký có dấu thời gian trừ ca R07.")
    rot = R["rotation"]
    D.table(["Ca", "Ngày", "Trust list client", "Bản", "Kết quả", "Diễn giải"], [[r["id"], r["now"][5:].replace("-", "/"), r["client_trust_list"].replace("v?(rollback)", "v1 phát lại"), r["release"], f"`{r['actual']}`", r["note"]] for r in rot],
            widths=[1.0, 1.4, 2.0, 1.3, 3.3, 6.7], caption="Kết quả E5 (12 kịch bản, đều đúng kỳ vọng).", size=8.5, align_center_cols=(0, 1, 3))
    D.p("**Phân tích.** (a) Chồng lấn có tác dụng: client chưa cập nhật (R02) vẫn xác minh bản ký kép nhờ chữ ký của khóa cũ, không phải buộc mọi người cập nhật cùng lúc. "
        "(b) Hết chồng lấn, client lạc hậu bị từ chối (R05, R10) – hỏng theo hướng an toàn nhưng có chi phí hỗ trợ người dùng, nên thời gian chồng lấn phải đủ dài so với chu kỳ cập nhật của người dùng. "
        "(c) Khóa nghỉ hưu vẫn xác minh được bản cũ **nếu và chỉ nếu** có dấu thời gian (R06 so với R07): cùng một bản phát hành, chỉ khác dấu thời gian, cho hai kết quả đối lập. "
        "(d) Trust list đóng vai trò “hạn dùng của niềm tin”: R10 và R12 cho thấy client không cập nhật bị từ chối khi trust list hết hạn thay vì tin mù; R11 cho thấy phát lại phiên bản cũ bị chặn nhờ số phiên bản đơn điệu.")
    D.h("5.6. E6 – Khóa ký bị lộ", 2)
    D.p("Kịch bản: khóa K2 bị lộ; thời điểm nghi ngờ sớm nhất là 10/06 (`compromised_since`); kẻ tấn công ký mã độc bản “1.2.1” ngày 12/06; đội phát hành phát hiện và phát hành trust list v4 ngày 20/06 (thu hồi K2, kích hoạt K3). Đội phát hành cũng đã ký bản hợp lệ 1.3.0 bằng K2 ngày 15/06, nằm trong cửa sổ nghi ngờ.")
    cp = R["compromise"]
    D.table(["Ca", "Ngày", "Trust list", "Đối tượng", "Kết quả", "Diễn giải"], [[r["id"], r["now"][5:].replace("-", "/"), r["client_trust_list"].replace("v?(rollback)", "v3 phát lại"), r["release"] + (" (mã độc)" if r["release"] == "1.2.1" else ""), f"`{r['actual']}`", r["note"]] for r in cp],
            widths=[1.0, 1.4, 1.8, 2.2, 3.1, 6.2], caption="Kết quả E6 (9 kịch bản, đều đúng kỳ vọng).", size=8.5, align_center_cols=(0, 1))
    D.p("**Phân tích.** (1) Chính sách “chấp nhận chữ ký có dấu thời gian trước `compromised_since`” giữ được hiệu lực cho bản phát hành cũ (C01) mà không cần ký lại hàng loạt, đồng thời loại mã độc dù kẻ tấn công xin được dấu thời gian **thật** tại thời điểm hiện tại (C04) hoặc không có dấu (C05). "
        "(2) Kẻ tấn công không thể lùi thời gian: dấu thời gian tự ký bị từ chối vì TSA không tin cậy (C06). Điều này đúng *với giả định TSA không bị chiếm* (A5). "
        "(3) Cái giá: bản hợp lệ ký trong cửa sổ nghi ngờ không phân biệt được với mã độc (C02) và phải ký lại bằng khóa mới (C03); do đó `compromised_since` nên đặt bảo thủ (sớm), đánh đổi số bản phải ký lại. "
        "(4) **Rủi ro dư quan trọng nhất:** client chưa nhận v4 vẫn chấp nhận mã độc (C07, C08). Thu hồi chỉ hiệu quả khi trust list mới đến được client. Phơi nhiễm tối đa của một client lạc hậu bằng khoảng thời gian từ lúc khóa bị lộ đến khi trust list cũ hết hạn: "
        "trong mô phỏng, 10/06 → 30/07 là 50 ngày (40 ngày kể từ khi v4 được phát hành). (5) Chặn phát lại trust list cũ chỉ hiệu quả với client đã từng thấy v4 (C09); client chưa từng thấy phiên bản mới hơn không có cách tự phát hiện.")
    D.table(["TTL trust list", "Phơi nhiễm tối đa sau khi v4 phát hành (client lạc hậu)", "Chi phí vận hành"], [
        ["≈120 ngày (như mô phỏng)", "Đến 120 ngày", "Thấp; client ít phải liên lạc"],
        ["30 ngày", "Đến 30 ngày", "Trung bình"],
        ["7 ngày", "Đến 7 ngày", "Cao; cần kênh cập nhật tin cậy, offline lâu sẽ bị từ chối"],
    ], widths=[3.7, 7.0, 5.0], caption="Đánh đổi giữa hạn dùng trust list và cửa sổ phơi nhiễm (suy luận từ mô hình, không phải số đo).", size=9.5)

    D.h("5.7. E7 – Kiểm chứng chéo với OpenSSL", 2)
    D.table(["Thuật toán", "Python ký → OpenSSL xác minh", "OpenSSL ký → Python xác minh", "OpenSSL từ chối bản bị sửa"], [
        [LBLS[r["alg"]], "Đạt" if r["python_sign_openssl_verify"] else "Lỗi", "Đạt" if r["openssl_sign_python_verify"] else "Lỗi", "Đạt" if r["openssl_rejects_modified_msg"] else "Lỗi"] for r in R["interop"]["results"]],
        widths=[4.0, 4.1, 4.1, 3.5], caption="Kết quả liên thông (OpenSSL 3.0.13 CLI so với backend OpenSSL của thư viện Python).", size=10, align_center_cols=(1, 2, 3))
    D.p("Cả ba thuật toán liên thông hai chiều với cùng tham số (RSA-PSS: SHA-256, MGF1-SHA-256, muối 32 B; ECDSA: SHA-256, DER; Ed25519: `-rawin`). Việc này kiểm chứng rằng bộ tham số nhóm công bố đủ để cài đặt độc lập, và là kiểm chứng độc lập duy nhất cho lớp nguyên thủy.")


LBLS = {"rsa-pss-3072": "RSA-PSS 3072", "ecdsa-p256": "ECDSA P-256", "ed25519": "Ed25519"}


def chapter6(D, R):
    D.h("CHƯƠNG 6. THẢO LUẬN, GIỚI HẠN VÀ KHUYẾN NGHỊ", 1, page_break=True)
    D.h("6.1. Trả lời các câu hỏi nghiên cứu", 2)
    D.table(["Câu hỏi", "Kết luận từ thực nghiệm", "Mức chắc chắn"], [
        ["RQ1", "Ed25519 gọn nhất (chữ ký 64 B); RSA-PSS 3072 ký chậm hơn ECDSA ≈34 lần nhưng xác minh nhanh nhất; Ed25519 không nhanh hơn ECDSA trên môi trường này. ECDSA đòi hỏi nonce duy nhất và không thiên lệch (đã chứng minh khôi phục khóa khi trùng); Ed25519 và ECDSA RFC 6979 tất định; PSS dùng muối ngẫu nhiên không nguy hiểm khi muối lặp.", "Cao về kích thước và nonce; trung bình về hiệu năng (một máy, nhiễu 1–24%)"],
        ["RQ2", "Mọi sửa đổi trong phạm vi bảo vệ bị từ chối với mã đúng nguyên nhân; trường ngoài phạm vi ký không được bảo vệ.", "Cao cho các ca đã thử; chưa phủ fuzzing"],
        ["RQ3", "Chồng lấn + trust list có phiên bản cho phép đổi khóa mượt; client lạc hậu hỏng theo hướng an toàn.", "Cao trong mô hình mô phỏng"],
        ["RQ4", "Dấu thời gian + compromised_since giữ hiệu lực bản cũ và loại mã độc; client chưa cập nhật vẫn bị phơi nhiễm đến khi trust list hết hạn.", "Cao về logic; phụ thuộc giả định TSA"],
    ], widths=[1.6, 10.2, 3.9], caption="Tổng hợp kết quả theo câu hỏi nghiên cứu.", size=9.5, align_center_cols=(0,))
    D.h("6.2. Những điều thực nghiệm cho thấy về thiết kế", 2)
    D.bullets([
        "**Thuật toán không phải điểm yếu chính.** Cả ba thuật toán cho kết quả giống hệt trong E3, E5, E6; sự khác biệt hành vi nằm ở nonce (E4) và hiệu năng (E2). Các lỗ hổng thực sự của hệ thống nằm ở phạm vi chữ ký (T18), độ “tươi” của trust list (C07/C08) và độ tin cậy của TSA.",
        "**Thu hồi luôn có độ trễ.** Không cơ chế nào trong mô hình offline xóa được cửa sổ giữa lúc khóa bị lộ và lúc mọi client biết. Có thể rút ngắn bằng TTL ngắn của trust list, nhưng đánh đổi độ sẵn sàng (bảng ở 5.6). Điều này phù hợp với hạn chế đã biết của CRL (chậm, nặng) so với OCSP stapling (nhanh, cần máy chủ) trong bài giảng.",
        "**Dấu thời gian là điều kiện để khóa cũ có ý nghĩa.** Nếu không có, nghỉ hưu hay thu hồi khóa đều buộc ký lại toàn bộ lịch sử hoặc chấp nhận vô hiệu hóa chúng (R07, C05).",
        "**Ký kép là chi phí nhỏ cho độ bền lớn.** Ký kép K1+K2 chỉ thêm một chữ ký (64–384 B trước khi mã hóa base64) mà giữ được toàn bộ client cũ trong giai đoạn chồng lấn.",
    ])
    D.h("6.3. Khuyến nghị chọn thuật toán", 2)
    D.table(["Bối cảnh", "Khuyến nghị", "Lý do (dựa trên số đo của báo cáo)"], [
        ["Phát hành phần mềm cho nhiều người dùng, môi trường cũ, chấp nhận gói lớn hơn", "RSA-PSS 3072", "Xác minh nhanh nhất (≈52 µs); hỗ trợ rộng; muối lặp không gây thảm họa. Chữ ký 384 B."],
        ["Hệ thống mới, thiết bị nhúng, RNG chưa chắc tin cậy, cần chữ ký gọn", "Ed25519", "Nonce tất định loại bỏ rủi ro RNG; chữ ký 64 B. Lưu ý: ký trực tiếp tệp lớn chậm; luôn ký manifest."],
        ["Phải tương thích HSM/PKI/tiêu chuẩn đã có ECDSA", "ECDSA P-256", "Ký nhanh nhất (≈31 µs). Bắt buộc quản lý nonce (HSM hoặc RFC 6979) và giám sát trùng r."],
    ], widths=[5.0, 3.0, 7.7], caption="Khuyến nghị theo bối cảnh (không phải đánh giá tuyệt đối).", size=9.5)
    D.p("Dù chọn thuật toán nào, khuyến nghị chung là: ký manifest thay vì tệp; ràng buộc alg và key_id vào dữ liệu ký; ghim thuật toán ở trust list; luôn kèm dấu thời gian; đặt TTL trust list ngắn nhất mà kênh cập nhật chịu được; ký kép khi luân chuyển.")
    D.h("6.4. Giới hạn của nghiên cứu", 2)
    D.bullets([
        "**Hiệu năng:** một máy ảo 2 vCPU chia sẻ, 3 lần chạy; chưa đo trên nhiều CPU, chưa đo bộ nhớ, chưa đo hằng thời gian (side channel). Chưa lý giải nguyên nhân Ed25519 chậm hơn kỳ vọng.",
        "**TSA mô phỏng** cho phép đặt thời gian tùy ý, không phải RFC 3161, không có chuỗi chứng thư; giả định TSA trung thực (A5) chưa được thử thách.",
        "**Không có CA/X.509 thật, không có OCSP/CRL thật:** trust list là mô hình thu nhỏ; chưa kiểm tra phân tích đường dẫn chứng thư, ràng buộc tên, EKU.",
        "**Khóa riêng lưu ở dạng PEM không mã hóa** vì là khóa thử nghiệm; hệ thống thật cần HSM/KMS, quy trình offline cho khóa gốc.",
        "**Chưa mô hình hóa tấn công trước khi ký** (A6: hệ thống build bị chiếm). Chữ ký trên mã độc do pipeline sinh ra vẫn hợp lệ; provenance trong manifest chỉ là khai báo.",
        "**Kỳ vọng kiểm thử do nhóm tự viết**, chưa có kiểm thử đột biến hay fuzzing; chưa có phân tích chống lại tấn công thời gian (timing) trong so sánh băm.",
        "**Phạm vi pháp lý:** nguyên mẫu không tạo chữ ký số có giá trị pháp lý theo quy định hiện hành của Việt Nam.",
    ])
    D.h("6.5. Hướng cải tiến", 2)
    D.bullets([
        "Dùng HSM/KMS (hoặc khóa phần cứng) cho khóa ký và khóa gốc; ký ngưỡng (nhiều người phê duyệt) cho trust list.",
        "Thêm nhật ký minh bạch (transparency log) kiểu Sigstore/Rekor để phát hiện ký trái phép ngay cả khi khóa bị lộ [23]; gắn tuyên bố provenance theo in-toto/SLSA [15], [22].",
        "Hiện thực TSA theo RFC 3161 với chuỗi chứng thư, và OCSP stapling cho phần chứng chỉ.",
        "**Linh hoạt thuật toán và hậu lượng tử:** RSA và ECDSA/EdDSA đều bị phá bởi máy tính lượng tử đủ lớn. NIST đã chuẩn hóa ML-DSA (FIPS 204) [26]; thiết kế trust list có nhãn thuật toán sẵn sàng cho chữ ký kép (cổ điển + hậu lượng tử) trong giai đoạn chuyển tiếp.",
        "Kiểm thử đột biến và fuzzing bộ phân tích bundle/manifest; mở rộng E2 sang nhiều máy và đo bộ nhớ.",
    ])


def chapter7(D, R):
    D.h("CHƯƠNG 7. RUNBOOK XỬ LÝ KHÓA KÝ BỊ LỘ", 1, page_break=True)
    D.p("Runbook này là sản phẩm bắt buộc của đề tài; các bước được kiểm chứng ở E6 (mã ca nêu trong ngoặc). Bản đầy đủ ở tệp `RUNBOOK.md`. Vai trò: **IC** (điều phối sự cố), **KC** (người giữ khóa), **RE** (kỹ sư phát hành), **CM** (truyền thông).", indent=False)
    D.table(["Bước", "Hành động", "Vai trò", "Mục tiêu thời gian", "Bằng chứng / kiểm chứng"], [
        ["0", "Phát hiện: chữ ký lạ trên log, báo cáo của người dùng, nghi ngờ lộ thiết bị chứa khóa. Mở sự cố, ghi giờ phát hiện.", "IC", "T+0", "Phiếu sự cố"],
        ["1", "Dừng ký: khóa K_cũ bị vô hiệu hóa trong CI/HSM; đóng băng phát hành.", "KC, RE", "≤ 30 phút", "Nhật ký HSM/CI"],
        ["2", "Xác định `compromised_since`: thời điểm sớm nhất có thể khóa bị lộ (bảo thủ). Liệt kê mọi bản đã ký sau mốc này và các bản không có dấu thời gian.", "IC, RE", "≤ 4 giờ", "Danh sách bản phát hành"],
        ["3", "Sinh khóa mới K_mới offline bằng CSPRNG/HSM; ghi dấu vân tay; hai người xác nhận qua kênh ngoài băng.", "KC", "≤ 4 giờ", "Dấu vân tay công khai"],
        ["4", "Phát hành trust list `v+1` ký bằng khóa gốc: K_cũ = revoked + compromised_since; K_mới = active; **TTL ngắn**. Số phiên bản tăng đơn điệu. (C02, C04, C09)", "KC", "≤ 8 giờ", "Tệp trust list, nhật ký ký"],
        ["5", "Ký lại bằng K_mới các bản có dấu thời gian ≥ mốc nghi ngờ hoặc không có dấu thời gian; bản có dấu thời gian trước mốc được giữ nhưng rà soát nội dung. (C01, C02, C03)", "RE", "≤ 24 giờ", "Bundle mới; log xác minh"],
        ["6", "Xác minh thử bằng client sạch ở đúng trạng thái `v+1`: bản cũ trước mốc đạt; bản mã độc/giả dấu thời gian bị từ chối. (C04–C06)", "RE", "Trước khi công bố", "Log xác minh"],
        ["7", "Công bố: đẩy trust list qua mọi kênh (CDN, ứng dụng, thông báo bảo mật) và cảnh báo người dùng; liệt kê dấu vân tay hợp lệ mới.", "CM, IC", "≤ 24 giờ", "Bản tin; mẫu cảnh báo bên dưới"],
        ["8", "Giám sát client lạc hậu: đo tỉ lệ client còn ở `v ≤ v_cũ`; kéo dài hỗ trợ, nhắc cập nhật. Nhớ rằng client chưa nhận `v+1` vẫn chấp nhận mã độc đến khi trust list cũ hết hạn. (C07, C08)", "IC, CM", "Đến khi trust list cũ hết hạn", "Báo cáo tỉ lệ cập nhật"],
        ["9", "Hậu kiểm: tìm nguyên nhân lộ; hủy an toàn khóa riêng cũ; giữ khóa công khai để xác minh bản cũ; cập nhật chính sách (TTL, HSM, giám sát trùng r).", "IC, KC", "≤ 14 ngày", "Báo cáo hậu kiểm"],
    ], widths=[1.0, 7.3, 1.8, 2.4, 3.2], caption="Runbook xử lý khóa ký bị lộ.", size=8.5, align_center_cols=(0,))
    D.p("**Mẫu cảnh báo người dùng.** “Ngày [ngày], chúng tôi phát hiện khóa ký phát hành [dấu vân tay cũ rút gọn] có thể đã bị lộ từ [compromised_since]. Vui lòng cập nhật danh sách tin cậy lên phiên bản [v+1] và chỉ cài đặt các bản có chữ ký từ khóa [dấu vân tay mới rút gọn]. "
        "Không cài các bản phát hành mang số phiên bản [danh sách] nếu tải trước khi cập nhật. Dấu vân tay đầy đủ có tại [kênh xác thực]. Nếu không cập nhật được, hãy liên hệ [đầu mối].”", indent=False)
    D.p("**Điều kiện dừng và leo thang.** Nếu nghi ngờ **khóa gốc** hoặc **khóa TSA** bị lộ (A5), runbook này không đủ: client phải được cấp lại điểm tin cậy ban đầu (ghim khóa gốc mới) qua kênh ngoài băng, tức là coi như phát hành lại toàn bộ.", indent=False)


def conclusion(D, R):
    D.h("KẾT LUẬN", 1, page_break=True)
    D.p("Báo cáo đã xây dựng và đánh giá một nguyên mẫu ký/xác minh artifact với ba lược đồ chữ ký chuẩn, bằng bảy thực nghiệm có số liệu tái lập. Về kỹ thuật: RSA-PSS 3072, ECDSA P-256 và Ed25519 đều phát hiện đầy đủ 57/57 sửa đổi trong phạm vi bảo vệ; khác biệt thực chất nằm ở kích thước (64 B so với 384 B), hiệu năng (RSA-PSS ký chậm ≈34 lần ECDSA nhưng xác minh nhanh nhất; Ed25519 không nhanh hơn ECDSA ở môi trường này) và yêu cầu nonce (ECDSA nhạy cảm tới mức hai chữ ký cùng nonce làm lộ khóa riêng, đã được chứng minh bằng thực nghiệm).")
    D.p("Về quy trình, đóng góp chính là các kết quả định lượng và kịch bản cho phần vòng đời khóa: chồng lấn và trust list có phiên bản cho phép luân chuyển an toàn; dấu thời gian cho phép giữ hiệu lực bản phát hành cũ sau khi khóa bị thu hồi; nhưng thu hồi không bao giờ tức thời – client lạc hậu vẫn chấp nhận mã độc cho đến khi trust list cũ hết hạn. "
        "Thông điệp chung khớp với bài giảng: **an toàn của chữ ký số được quyết định bởi quản lý khóa và phạm vi dữ liệu được ký không kém, và nhiều khi hơn, so với việc chọn thuật toán.**")
    D.p("Các giới hạn (TSA mô phỏng, không có PKI thật, một máy đo, kỳ vọng tự viết) đã nêu ở 6.4; kết luận chỉ áp dụng cho mô hình đe dọa ở 3.1. Hướng tiếp theo là HSM, nhật ký minh bạch, TSA theo RFC 3161 và chuẩn bị chữ ký hậu lượng tử.")


REFS = [
    "W. Diffie and M. E. Hellman, “New directions in cryptography,” IEEE Trans. Inf. Theory, vol. 22, no. 6, pp. 644–654, Nov. 1976.",
    "R. L. Rivest, A. Shamir, and L. Adleman, “A method for obtaining digital signatures and public-key cryptosystems,” Commun. ACM, vol. 21, no. 2, pp. 120–126, 1978.",
    "S. Goldwasser, S. Micali, and R. L. Rivest, “A digital signature scheme secure against adaptive chosen-message attacks,” SIAM J. Comput., vol. 17, no. 2, pp. 281–308, 1988.",
    "K. Moriarty, B. Kaliski, J. Jonsson, and A. Rusch, “PKCS #1: RSA Cryptography Specifications Version 2.2,” IETF RFC 8017, Nov. 2016.",
    "M. Bellare and P. Rogaway, “The exact security of digital signatures – How to sign with RSA and Rabin,” in Advances in Cryptology – EUROCRYPT ’96, LNCS 1070, 1996, pp. 399–416.",
    "National Institute of Standards and Technology, “Digital Signature Standard (DSS),” FIPS PUB 186-5, Feb. 2023.",
    "D. Johnson, A. Menezes, and S. Vanstone, “The Elliptic Curve Digital Signature Algorithm (ECDSA),” Int. J. Inf. Secur., vol. 1, no. 1, pp. 36–63, 2001.",
    "T. Pornin, “Deterministic usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA),” IETF RFC 6979, Aug. 2013.",
    "D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, and B.-Y. Yang, “High-speed high-security signatures,” J. Cryptographic Engineering, vol. 2, no. 2, pp. 77–89, 2012.",
    "fail0verflow (M. Bushing, H. Marcan, et al.), “Console hacking 2010: PS3 epic fail,” 27th Chaos Communication Congress (27C3), Dec. 2010.",
    "N. Heninger, Z. Durumeric, E. Wustrow, and J. A. Halderman, “Mining your Ps and Qs: Detection of widespread weak keys in network devices,” in Proc. 21st USENIX Security Symp., 2012.",
    "S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm (EdDSA),” IETF RFC 8032, Jan. 2017.",
    "E. Barker, “Recommendation for Key Management: Part 1 – General,” NIST SP 800-57 Part 1, Rev. 5, May 2020.",
    "J. Samuel, N. Mathewson, J. Cappos, and R. Dingledine, “Survivable key compromise in software update systems,” in Proc. ACM CCS, 2010, pp. 61–72.",
    "S. Torres-Arias, H. Weiss, I. Kuppusamy, and J. Cappos, “in-toto: Providing farm-to-table guarantees for bits and bytes,” in Proc. 28th USENIX Security Symp., 2019, pp. 1393–1410.",
    "D. Cooper et al., “Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile,” IETF RFC 5280, May 2008.",
    "S. Santesson et al., “X.509 Internet Public Key Infrastructure Online Certificate Status Protocol – OCSP,” IETF RFC 6960, Jun. 2013.",
    "Quốc hội nước CHXHCN Việt Nam, “Luật Giao dịch điện tử,” Luật số 20/2023/QH15, ngày 22/6/2023.",
    "Chính phủ, Nghị định 130/2018/NĐ-CP hướng dẫn Luật Giao dịch điện tử về chữ ký số và dịch vụ chứng thực chữ ký số; Nghị định 23/2025/NĐ-CP về chữ ký điện tử và dịch vụ tin cậy (nhóm cần đối chiếu văn bản còn hiệu lực).",
    "Python Cryptographic Authority, “cryptography documentation,” v50.0.1 (phiên bản dùng trong thực nghiệm).",
    "C. Adams, P. Cain, D. Pinkas, and R. Zuccherato, “Internet X.509 PKI Time-Stamp Protocol (TSP),” IETF RFC 3161, Aug. 2001.",
    "OpenSSF, “Supply-chain Levels for Software Artifacts (SLSA) specification, v1.0,” 2023. [Online]. Available: https://slsa.dev",
    "Z. Newman, J. S. Meyers, and S. Torres-Arias, “Sigstore: Software signing for everybody,” in Proc. ACM CCS, 2022.",
    "OpenSSL Project, “OpenSSL 3.0 manual pages: openssl-dgst(1), openssl-pkeyutl(1),” https://www.openssl.org/docs/.",
    "Bài giảng An toàn thông tin, Chương 4 – Các cơ chế mật mã hiện đại, Trường ĐH Giao thông vận tải TP.HCM, 2026.",
    "National Institute of Standards and Technology, “Module-Lattice-Based Digital Signature Standard,” FIPS PUB 204, Aug. 2024.",
]
