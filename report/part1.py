"""Phần 1: bìa, tóm tắt, chương 1-3 (vấn đề, lý thuyết, thiết kế)."""
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm
from docx_lib import _set_font

FIGS = None


def cover(D):
    D.p("TRƯỜNG ĐẠI HỌC GIAO THÔNG VẬN TẢI THÀNH PHỐ HỒ CHÍ MINH", bold=True, align="c", size=13, after=2)
    D.p("KHOA CÔNG NGHỆ THÔNG TIN", bold=True, align="c", size=12, after=60)
    D.p("BÁO CÁO ĐỒ ÁN MÔN HỌC", bold=True, align="c", size=16, after=4)
    D.p("AN TOÀN THÔNG TIN", bold=True, align="c", size=20, after=36)
    D.p("ĐỀ TÀI 19", bold=True, align="c", size=14, after=4)
    D.p("ĐÁNH GIÁ CHỮ KÝ SỐ CHO PHẦN MỀM VÀ TÀI LIỆU ĐIỆN TỬ", bold=True, align="c", size=18, after=6)
    D.p("So sánh RSA-PSS, ECDSA và Ed25519; quy trình ký, xác minh, dấu thời gian, luân chuyển và xử lý khóa bị lộ", italic=True, align="c", size=12, after=50)
    D.p("Học phần: An toàn thông tin (3 tín chỉ)   |   Giảng viên: TS. Lê Quốc Tuấn", align="c", size=12, after=2)
    D.p("Bám sát chương 4 – Các cơ chế mật mã hiện đại: mục 4.5, 4.7, 4.8 và 4.9.3", align="c", size=12, after=30)
    D.table(["STT", "Họ và tên", "MSSV", "Lớp"], [["1", "[điền]", "[điền]", "[điền]"], ["2", "[điền]", "[điền]", "[điền]"], ["3", "[điền]", "[điền]", "[điền]"]],
            widths=[1.5, 7, 3.5, 3.5], size=11, align_center_cols=(0, 2, 3))
    D.p("Thành phố Hồ Chí Minh, tháng 11 năm 2026", align="c", size=12)


def abstract(D, R):
    S = {r["alg"]: r for r in R["sizes"]}
    D.h("TÓM TẮT", 1, page_break=True)
    D.p("Báo cáo đánh giá thực nghiệm ba lược đồ chữ ký số – RSA-PSS (3072 bit), ECDSA trên đường cong P-256 và Ed25519 – trong bài toán ký và xác minh phần mềm cùng tài liệu điện tử. "
        "Nhóm xây dựng một nguyên mẫu gồm: manifest có phiên bản (băm SHA-256 từng tệp và thông tin nguồn gốc), bó chữ ký (bundle) có ràng buộc thuật toán và định danh khóa vào dữ liệu được ký, "
        "danh sách khóa tin cậy có phiên bản do khóa gốc ký, dấu thời gian mô phỏng và bộ xác minh theo chính sách “đóng khi nghi ngờ”. Toàn bộ thao tác mật mã đi qua API của thư viện chuẩn `cryptography` (OpenSSL); nhóm không tự thiết kế lược đồ mới.")
    D.p(f"Bảy thực nghiệm được thực hiện: (E1) tạo bộ artifact; (E2) đo kích thước và thời gian; (E3) 19 ca sửa đổi × 3 thuật toán = 57 lần xác minh; (E4) hành vi nonce, gồm minh họa khôi phục khóa riêng ECDSA khi tái sử dụng nonce; "
        "(E5) luân chuyển khóa có giai đoạn chồng lấn (12 kịch bản); (E6) khóa ký bị lộ (9 kịch bản); (E7) kiểm chứng chéo với OpenSSL CLI. "
        f"Kết quả chính: chữ ký Ed25519 dài {S['ed25519']['sig_mean_B']} byte, ECDSA P-256 khoảng {float(S['ecdsa-p256']['sig_mean_B']):.0f} byte (DER, thay đổi 69–72), RSA-PSS 3072 dài {S['rsa-pss-3072']['sig_mean_B']} byte. "
        "Ở mức 128 bit an toàn, RSA-PSS ký chậm hơn ECDSA khoảng 34 lần nhưng xác minh nhanh hơn; trên máy thử nghiệm Ed25519 không nhanh hơn ECDSA P-256 như thường được nhắc đến. "
        "Mọi sửa đổi nội dung, metadata được bảo vệ, chữ ký và nhãn thuật toán đều bị từ chối; trường nằm ngoài phạm vi ký vẫn được chấp nhận, cho thấy phạm vi bảo vệ do thiết kế manifest quyết định chứ không do thuật toán. "
        "Mô phỏng sự cố cho thấy thu hồi khóa chỉ có hiệu lực với client đã nhận trust list mới, vì vậy hạn dùng ngắn của trust list và dấu thời gian là hai cơ chế bắt buộc, không phải tùy chọn.")
    D.p("**Từ khóa:** chữ ký số, RSA-PSS, ECDSA, Ed25519, nonce, manifest, dấu thời gian, luân chuyển khóa, thu hồi khóa, toàn vẹn phần mềm.", indent=False)


def toc_placeholder(D, entries, pages):
    D.h("MỤC LỤC", 1, page_break=True)
    for lvl, text in entries:
        pg = pages.get(text, "")
        para = D.d.add_paragraph()
        para.paragraph_format.left_indent = Cm(0 if lvl == 1 else 0.8)
        para.paragraph_format.space_after = Pt(1); para.paragraph_format.line_spacing = 1.1
        para.paragraph_format.tab_stops.add_tab_stop(Cm(16.0), alignment=2, leader=1)  # right, dots
        r = para.add_run(f"{text}\t{pg}"); _set_font(r, 11.5, bold=(lvl == 1))
    # mục lục không tự đưa vào chính nó
    D.headings[:] = [h for h in D.headings if h[1] != "MỤC LỤC"]


def chapter1(D, R):
    D.h("CHƯƠNG 1. XÁC ĐỊNH VẤN ĐỀ VÀ PHẠM VI", 1, page_break=True)
    D.h("1.1. Bối cảnh", 2)
    D.p("Khi một tệp thực thi, một gói cập nhật hoặc một biên bản điện tử đi qua mạng, kho lưu trữ hay máy chủ phản chiếu (mirror), người nhận không có cách trực tiếp để biết nội dung có bị thay đổi hay không và do ai tạo ra. "
        "Chữ ký số trả lời hai câu hỏi đó bằng bằng chứng mật mã: bên ký dùng khóa riêng để tạo chữ ký, bên nhận dùng khóa công khai để kiểm tra [1], [2]. Khác với MAC, bên xác minh không cần giữ bất kỳ bí mật nào có khả năng tạo chữ ký.")
    D.p("Tuy nhiên, một thuật toán mạnh chưa đủ để hệ thống an toàn. Nội dung bài giảng chương 4 [25] nhấn mạnh rằng thuật toán mạnh không bù được cho khóa bị lộ, sinh yếu hoặc dùng sai mục đích, và chất lượng quản lý khóa nhiều khi quyết định mức an toàn thực tế không kém bản thân thuật toán. "
        "Các sự cố thực tế minh họa điều này: việc tái sử dụng nonce ECDSA đã làm lộ khóa ký firmware của một hãng máy chơi game [10]; các thiết bị sinh khóa với entropy yếu tạo ra khóa RSA trùng hoặc chia sẻ thừa số [11]. "
        "Vì vậy đề tài không chỉ so sánh ba thuật toán mà đánh giá cả quy trình bao quanh: định dạng dữ liệu được ký, danh sách khóa tin cậy, dấu thời gian, luân chuyển và thu hồi.")
    D.h("1.2. Câu hỏi nghiên cứu", 2)
    D.table(["Mã", "Câu hỏi", "Thực nghiệm trả lời"], [
        ["RQ1", "RSA-PSS, ECDSA và Ed25519 khác nhau thế nào về kích thước khóa/chữ ký, thời gian ký/xác minh và yêu cầu về nonce?", "E2, E4"],
        ["RQ2", "Một quy trình ký artifact (tệp + manifest + metadata) có phát hiện được mọi sửa đổi nằm trong phạm vi bảo vệ không, và phạm vi đó dừng ở đâu?", "E1, E3, E7"],
        ["RQ3", "Có thể thay khóa ký mà không làm hỏng người dùng còn dùng trust list cũ, và hỏng theo cách an toàn (từ chối) khi không còn tin được không?", "E5"],
        ["RQ4", "Khi khóa ký bị lộ, những bản phát hành nào vẫn đáng tin, những bản nào phải ký lại, và client nào vẫn bị phơi nhiễm?", "E6"],
    ], widths=[1.3, 11.2, 3.2], caption="Câu hỏi nghiên cứu và thực nghiệm tương ứng.", align_center_cols=(0, 2))
    D.h("1.3. Phạm vi, giả định và giới hạn an toàn", 2)
    D.bullets([
        "**Trong phạm vi:** ký và xác minh artifact ở mức nguyên mẫu; so sánh ba lược đồ qua API thư viện chuẩn; manifest có phiên bản; trust list có phiên bản; dấu thời gian mô phỏng; mô phỏng luân chuyển và sự cố khóa.",
        "**Ngoài phạm vi:** xây dựng lược đồ mật mã mới; hạ tầng PKI/CA thật và chứng thư X.509 đầy đủ; HSM thật; chữ ký có giá trị pháp lý theo quy định về chứng thư số; chống tấn công kênh kề; hậu lượng tử (chỉ bàn ở mục 6.5).",
        "**Giả định:** thư viện `cryptography` và OpenSSL cài đặt đúng các thuật toán chuẩn; khóa gốc được giữ offline; đồng hồ máy xác minh tương đối đúng; TSA trung thực (xem 3.1).",
        "**Đạo đức và an toàn:** mọi khóa chỉ là khóa thử nghiệm sinh trong đồ án, lưu ở thư mục `keys/` kèm cảnh báo LAB ONLY, không gắn với danh tính hay chứng thư của tổ chức nào và không dùng ký phần mềm thật. Mã tấn công khôi phục khóa chỉ chạy trên khóa nạn nhân do nhóm tự sinh. Mọi thử nghiệm chạy trong container cô lập, dữ liệu mô phỏng.",
    ])
    D.h("1.4. Tiêu chí chấp nhận", 2)
    D.table(["Mã", "Tiêu chí", "Cách đo"], [
        ["AC1", "100% ca sửa đổi nằm trong phạm vi bảo vệ bị từ chối, với mã lỗi đúng nguyên nhân", "E3: 19 ca × 3 thuật toán"],
        ["AC2", "0 ca từ chối nhầm trên các ca đối chứng dương (artifact nguyên vẹn, thay đổi định dạng JSON vô hại)", "E3: T00, T17"],
        ["AC3", "Chữ ký tạo bởi thư viện được OpenSSL CLI xác minh và ngược lại; OpenSSL từ chối thông điệp bị sửa", "E7"],
        ["AC4", "Số đo hiệu năng có lặp (3 lần × nhiều mẫu), báo cáo trung vị, dải min–max và môi trường", "E2"],
        ["AC5", "Trong giai đoạn chồng lấn, client dùng trust list cũ vẫn xác minh được bản ký kép; client lạc hậu bị từ chối thay vì chấp nhận mù", "E5"],
        ["AC6", "Sau thu hồi, client đã cập nhật từ chối mọi chữ ký của khóa bị lộ có dấu thời gian không trước thời điểm nghi ngờ; chữ ký trước đó vẫn hợp lệ", "E6"],
        ["AC7", "Chứng minh được (trên khóa thử nghiệm) tái sử dụng nonce ECDSA khôi phục khóa riêng, và Ed25519 sinh nonce tất định", "E4"],
    ], widths=[1.3, 10.4, 4.0], caption="Tiêu chí chấp nhận được đặt trước khi chạy thực nghiệm.", align_center_cols=(0,))
    D.h("1.5. Phương pháp và kế hoạch thực hiện", 2)
    D.p("Nhóm làm theo chu trình: xác định mô hình đe dọa, thiết kế kiểm thử và tiêu chí chấp nhận, hiện thực nguyên mẫu, chạy thực nghiệm có kiểm soát, rồi phân tích kèm giới hạn. Kế hoạch bám theo khung sáu tuần của bộ đề tài (đề 19 ghi dự kiến 7 tuần; tuần dôi ra dành cho kịch bản khóa bị lộ).")
    D.table(["Giai đoạn", "Tuần", "Nội dung", "Minh chứng"], [
        ["Đề cương", "1", "Câu hỏi nghiên cứu, phạm vi, tiêu chí chấp nhận, phân công", "Chương 1"],
        ["Thiết kế", "2", "Mô hình đe dọa, định dạng manifest/bundle/trust list, kế hoạch thử nghiệm", "Chương 3, sơ đồ"],
        ["Triển khai", "3–4", "Thư viện sigeval, CLI, bộ thử nghiệm, kiểm thử đơn vị", "Mã nguồn, pytest"],
        ["Đánh giá", "5–6", "Chạy lặp, tổng hợp, phân tích giới hạn, runbook", "CSV, biểu đồ, chương 5–6"],
        ["Bàn giao", "7", "Báo cáo, demo, hướng dẫn tái lập, bảng truy vết", "Phụ lục A–D"],
    ], widths=[2.4, 1.4, 8.6, 3.4], caption="Kế hoạch thực hiện.", align_center_cols=(1,))


def chapter2(D, R):
    D.h("CHƯƠNG 2. CƠ SỞ LÝ THUYẾT", 1, page_break=True)
    D.h("2.1. Mô hình chữ ký số", 2)
    D.p("Một lược đồ chữ ký gồm ba thuật giải: sinh khóa `Gen → (sk, pk)`, ký `Sign(sk, M) → σ` và xác minh `Verify(pk, M, σ) → {chấp nhận, từ chối}`. Tính đúng đắn đòi hỏi mọi chữ ký do `Sign` tạo ra đều được `Verify` chấp nhận. "
        "Mục tiêu an toàn chuẩn là không thể giả mạo hiện hữu dưới tấn công thông điệp chọn trước (EUF-CMA): kẻ tấn công được xin chữ ký trên các thông điệp tùy chọn vẫn không tạo được chữ ký hợp lệ cho một thông điệp mới [3].")
    D.p("Chữ ký số chỉ cung cấp hai tính chất: **toàn vẹn** (nội dung đã ký không bị đổi mà không bị phát hiện) và **xác thực nguồn gốc** (chữ ký do người giữ khóa riêng tạo ra). Chữ ký **không che giấu** nội dung; nó cũng không tự chứng minh ai là chủ khóa – việc gắn khóa công khai với một danh tính là nhiệm vụ của PKI hoặc của danh sách tin cậy.")
    D.h("2.2. Chống chối bỏ và giới hạn của khái niệm này", 2)
    D.p("Về mặt mật mã, “chống chối bỏ” nghĩa là bên ký không thể phủ nhận một cách đáng tin rằng mình đã tạo chữ ký. Thực tế điều này phụ thuộc vào những thứ nằm ngoài thuật toán: ai chứng minh khóa công khai thuộc về người đó (định danh), khóa riêng có thực sự do người đó kiểm soát độc quyền không (nếu khóa bị lộ thì chữ ký không còn phân biệt được người thật với kẻ trộm), "
        "và chữ ký được tạo vào thời điểm nào (nếu không có dấu thời gian đáng tin, bên ký có thể tuyên bố khóa đã bị lộ trước đó). Vì vậy hiệu lực pháp lý của chữ ký số còn phụ thuộc quy trình định danh, quản lý khóa, dấu thời gian và chính sách chứng thư, đúng như bài giảng nêu.")
    D.p("Ở Việt Nam, giá trị pháp lý của chữ ký số và chữ ký điện tử được quy định trong Luật Giao dịch điện tử 2023 (Luật số 20/2023/QH15) và các nghị định hướng dẫn về chữ ký số, dịch vụ chứng thực/tin cậy như Nghị định 130/2018/NĐ-CP và Nghị định 23/2025/NĐ-CP [18], [19]. "
        "Nguyên mẫu trong báo cáo này **không** phải là dịch vụ chứng thực chữ ký số theo các quy định đó và không tạo ra chữ ký có giá trị pháp lý; nhóm cần đối chiếu văn bản hiện hành nếu muốn áp dụng thực tế.")
    D.h("2.3. RSA-PSS", 2)
    D.p("RSASSA-PSS là phương án ký RSA có đệm xác suất, được định nghĩa trong PKCS#1 v2.2 (RFC 8017) [4]. Thông điệp được băm, trộn với một muối (salt) ngẫu nhiên rồi mã hóa theo hàm tạo mặt nạ MGF1 trước khi lũy thừa bằng khóa riêng. "
        "Bellare và Rogaway chứng minh PSS có chứng minh an toàn chặt trong mô hình oracle ngẫu nhiên, khác với đệm tất định PKCS#1 v1.5 [5]. Hệ quả cần nhớ: chữ ký PSS **không tất định** – ký cùng thông điệp hai lần cho hai chữ ký khác nhau – nhưng độ an toàn của PSS không sụp đổ nếu muối lặp, khác với nonce của ECDSA. "
        "Nhóm dùng SHA-256, MGF1-SHA-256 và độ dài muối 32 byte (bằng độ dài băm).")
    D.p("Slide chương 4 minh họa “RSA thô” (không đệm, ví dụ p = 61, q = 53, e = 17) chỉ để học phép toán; RSA thô có tính nhân (malleable) nên không bao giờ được dùng để ký trực tiếp. Mọi thử nghiệm trong báo cáo dùng RSA-PSS có đệm.")
    D.h("2.4. ECDSA và vai trò sống còn của nonce", 2)
    D.p("ECDSA trên đường cong P-256 (FIPS 186-5 [6]) chọn nonce `k` ngẫu nhiên trong `[1, n−1]`, tính `r = x(kG) mod n` và `s = k⁻¹(z + r·d) mod n`, với `z` là băm thông điệp (rút gọn) và `d` là khóa riêng [7]. "
        "Chữ ký là cặp `(r, s)`, thường mã hóa DER nên dài 70–72 byte (đôi khi 69).")
    D.p("Nếu cùng một `k` được dùng để ký hai thông điệp `M₁`, `M₂` dưới cùng khóa `d`, thì `r` trùng nhau và kẻ tấn công giải được hệ hai phương trình tuyến tính: "
        "`k = (z₁ − z₂)·(s₁ − s₂)⁻¹ mod n`, rồi `d = (s₁·k − z₁)·r⁻¹ mod n`. Chỉ cần phép toán số học đơn giản, không cần giải bài toán logarit rời rạc. Đây là điều đã xảy ra trong sự cố được công bố năm 2010 [10]. "
        "Nonce thiên lệch (biased) ngay cả khi không trùng cũng có thể làm lộ khóa qua tấn công mạng tinh thể; thí nghiệm E4 chỉ minh họa trường hợp trùng. "
        "RFC 6979 giảm rủi ro bằng cách sinh `k` tất định từ khóa riêng và thông điệp [8].")
    D.h("2.5. EdDSA / Ed25519", 2)
    D.p("Ed25519 là EdDSA trên đường cong Edwards xoắn tương đương Curve25519, chuẩn hóa trong RFC 8032 và được đưa vào FIPS 186-5 [6], [9], [12]. Khóa riêng 32 byte được băm bằng SHA-512; nửa đầu thành vô hướng bí mật, nửa sau là `prefix`. "
        "Nonce của mỗi chữ ký là `r = H(prefix ‖ M)` (bài giảng viết gọn là `k = H(prefix ‖ M)`). Do đó cùng thông điệp luôn cho cùng nonce và chữ ký, hai thông điệp khác nhau cho nonce khác nhau, và chất lượng bộ sinh số ngẫu nhiên lúc ký không còn là điểm yếu. "
        "Chữ ký dài đúng 64 byte, khóa công khai 32 byte. Ed25519 “thuần” băm toàn bộ thông điệp hai lần trong một lượt gọi và không hỗ trợ băm trước ở dạng này, một chi tiết ảnh hưởng hiệu năng khi ký tệp lớn (xem 5.2).")
    D.table(["Thuộc tính", "RSA-PSS 3072", "ECDSA P-256", "Ed25519"], [
        ["Mức an toàn danh định [13]", "≈ 128 bit (RSA-2048 ≈ 112 bit)", "≈ 128 bit", "≈ 128 bit"],
        ["Nonce / muối", "Muối ngẫu nhiên; lặp không làm lộ khóa", "Nonce ngẫu nhiên bắt buộc duy nhất và không thiên lệch; hoặc RFC 6979", "Tất định `H(prefix‖M)`"],
        ["Tính tất định của chữ ký", "Không", "Không (trừ RFC 6979)", "Có"],
        ["Chuẩn", "RFC 8017, FIPS 186-5", "FIPS 186-5, SEC 1", "RFC 8032, FIPS 186-5"],
        ["Rủi ro cài đặt chính", "Đệm sai, kích thước khóa nhỏ", "RNG yếu, nonce trùng/thiên lệch", "Nhập nhằm biến thể (pure/ph/ctx), kiểm tra điểm"],
    ], widths=[3.9, 3.9, 4.2, 3.7], caption="So sánh lý thuyết ba lược đồ (đối chiếu với kết quả thực nghiệm ở chương 5).", size=9.5)
    D.h("2.6. Băm, manifest và chuẩn hóa dữ liệu được ký", 2)
    D.p("Ký trực tiếp từng tệp lớn là không cần thiết và không tiện: thông lệ là băm từng tệp rồi ký một **manifest** liệt kê các băm cùng metadata. Khi đó an toàn của toàn bộ gói quy về (i) chống va chạm của SHA-256 và (ii) tính không thể giả mạo của chữ ký trên manifest. "
        "Hai chi tiết thiết kế hay bị bỏ qua: **chuẩn hóa** (canonicalization) – cùng nội dung logic phải ra cùng dãy byte khi ký và khi xác minh, nếu không sẽ có xác minh sai hoặc cơ hội cho tấn công nhập nhằm – và **ràng buộc ngữ cảnh** – dữ liệu thực sự được ký nên chứa loại payload, nhãn thuật toán và định danh khóa để chữ ký không bị chuyển sang ngữ cảnh khác (cách làm của DSSE/PAE trong in-toto và Sigstore [15], [23]).")
    D.h("2.7. Dấu vân tay khóa, chứng chỉ, danh sách tin cậy", 2)
    D.p("Dấu vân tay khóa là giá trị băm của khóa công khai ở dạng mã hóa chuẩn (ở đây SHA-256 của SubjectPublicKeyInfo DER). Nó là định danh ngắn gọn để so khớp ngoài băng (đọc cho nhau nghe, ghim trong tài liệu), và là khóa tra cứu trong trust list. "
        "PKI giải quyết việc gắn khóa với danh tính bằng chứng chỉ X.509: CA ký chứng chỉ thực thể cuối, tạo chuỗi tin cậy từ CA gốc qua CA trung gian [16]; bài giảng nêu thêm vai trò của RA, CRL và OCSP (kèm OCSP stapling) để kiểm tra thu hồi [17]. "
        "Với phân phối phần mềm, nhiều hệ thống chọn **danh sách khóa tin cậy** thay cho chuỗi CA: client ghim một khóa gốc, khóa gốc ký danh sách các khóa ký phát hành kèm trạng thái và thời hạn. Cách này gần với mô hình của TUF [14], được nhóm hiện thực ở dạng thu nhỏ.")
    D.h("2.8. Vòng đời khóa ký, luân chuyển và thu hồi", 2)
    D.p("Bài giảng chia vòng đời khóa thành tám giai đoạn: sinh, phân phối, kích hoạt, sử dụng, luân chuyển, thu hồi, lưu giữ và hủy [13]. Với khóa ký, hai điểm khác khóa mã hóa dữ liệu: khóa riêng **không bao giờ cần lưu giữ để giải mã lịch sử** (chỉ giữ khóa công khai để xác minh bản cũ), và việc hủy khóa riêng nên diễn ra sớm. "
        "Luân chuyển hiệu quả cần một **giai đoạn chồng lấn**, trong đó khóa cũ và khóa mới cùng hợp lệ và bản phát hành được ký kép, để client chưa cập nhật vẫn xác minh được. "
        "Thu hồi khóa ký có một vấn đề riêng: nếu thu hồi nghĩa là “mọi chữ ký của khóa này vô hiệu” thì toàn bộ phần mềm đã phát hành thành vô hiệu. Giải pháp thực tế là ghi **thời điểm nghi ngờ bị lộ** (compromised_since) và chỉ chấp nhận chữ ký có dấu thời gian đáng tin **trước** thời điểm đó [14], [16].")
    D.h("2.9. Dấu thời gian", 2)
    D.p("Dấu thời gian (RFC 3161 [21]) là chữ ký của một bên thứ ba (TSA) trên cặp (băm của dữ liệu, thời gian). Nó chứng minh dữ liệu đã tồn tại trước một thời điểm, nên cho phép chữ ký cũ vẫn đáng tin sau khi khóa hết hạn hoặc bị thu hồi, miễn là chữ ký được tạo trước thời điểm đó. "
        "Giới hạn: tin tưởng chuyển từ bên ký sang TSA; kẻ giữ khóa bị lộ vẫn có thể xin dấu thời gian **thật** cho thời điểm hiện tại nhưng không thể xin dấu thời gian lùi về quá khứ.")
    D.h("2.10. Provenance và chuỗi cung ứng", 2)
    D.p("Chữ ký chỉ cho biết “ai ký”, không cho biết “được build từ đâu”. Provenance ghi lại nguồn mã, trình build và thời điểm; các khung như in-toto, SLSA và Sigstore gắn các tuyên bố này vào chữ ký để người dùng xác minh chuỗi sản xuất [15], [22], [23]. "
        "Nguyên mẫu của nhóm nhúng một khối `provenance` tối giản (builder, repo, commit) vào manifest và kiểm tra rằng sửa khối này làm xác minh thất bại; nó không kiểm chứng tính đúng của giá trị khai báo.")


def chapter3(D, R):
    D.h("CHƯƠNG 3. THIẾT KẾ HỆ THỐNG VÀ PHƯƠNG PHÁP ĐÁNH GIÁ", 1, page_break=True)
    D.h("3.1. Mô hình đe dọa", 2)
    D.table(["Tác nhân", "Khả năng", "Mục tiêu", "Trong phạm vi?"], [
        ["A1 – Mirror/CDN độc hại hoặc MITM", "Sửa tệp, manifest, chữ ký, trường tùy ý trên đường truyền; xóa/thêm tệp", "Phát tán bản bị sửa", "Có"],
        ["A2 – Kẻ không có khóa", "Tạo bundle với khóa riêng của mình; đổi nhãn thuật toán/key_id", "Qua mặt người xác minh", "Có"],
        ["A3 – Kẻ đã lấy được khóa ký", "Ký bất kỳ nội dung; xin dấu thời gian thật tại thời điểm hiện tại", "Phát tán mã độc có chữ ký hợp lệ", "Có (E6)"],
        ["A4 – Kẻ phát lại dữ liệu cũ", "Gửi trust list/bản phát hành cũ", "Ép client dùng khóa đã thu hồi", "Có (rollback)"],
        ["A5 – Kẻ kiểm soát TSA hoặc khóa gốc", "Phát hành dấu thời gian/trust list tùy ý", "Phá toàn bộ chuỗi tin cậy", "Không (giả định ở 1.3)"],
        ["A6 – Kẻ chiếm hệ thống build trước khi ký", "Đưa mã độc vào artifact trước lúc ký", "Chữ ký “hợp lệ” cho mã độc", "Không (chỉ nêu ở mục 6.4)"],
    ], widths=[4.0, 5.3, 3.7, 2.7], caption="Mô hình đe dọa.", size=9.5)
    D.p("Tài sản cần bảo vệ: khóa riêng ký phát hành (quan trọng nhất), khóa gốc ký trust list, tính toàn vẹn của artifact và metadata, và tính “tươi” của trust list. Các yêu cầu an toàn rút ra: (R1) mọi byte ảnh hưởng quyết định cài đặt phải nằm trong phạm vi chữ ký; (R2) không thể chuyển chữ ký sang nhãn thuật toán hay khóa khác; (R3) khóa bị thu hồi không thể được dùng lại bằng cách lùi thời gian; (R4) client không thể bị ép dùng trust list cũ hơn đã thấy; (R5) khi không xác định được trạng thái, mặc định là từ chối.")
    D.h("3.2. Kiến trúc tổng quan", 2)
    D.figure(R["fig"]("f1_architecture.png"), "Kiến trúc ký và xác minh artifact. Dữ liệu thực sự được ký là PAE của (thuật toán, key_id, manifest chuẩn hóa).", 15.5)
    D.p("Bên phát hành gom artifact thành manifest, chuẩn hóa JSON, đóng gói theo PAE và ký bằng một hoặc nhiều khóa; mỗi chữ ký có thể kèm dấu thời gian. Bundle gồm manifest, danh sách chữ ký và một trường `unprotected` nằm ngoài phạm vi ký (cố ý đặt để kiểm chứng ranh giới bảo vệ ở ca T18). "
        "Bên xác minh giữ khóa gốc đã ghim và số phiên bản trust list lớn nhất từng thấy; nó kiểm tra theo thứ tự trust list → chữ ký → trạng thái khóa/thời gian → băm tệp.")
    D.h("3.3. Định dạng dữ liệu", 2)
    D.p("**Manifest** (JSON chuẩn hóa: khóa sắp xếp, không khoảng trắng, ASCII) gồm `schema`, `manifest_version`, `name`, `release`, `created`, `provenance{builder, source{repo, commit}}` và `artifacts[{path, sha256, size}]` sắp theo đường dẫn. "
        "**Dữ liệu được ký** (PAE) là nối các trường có tiền tố độ dài 8 byte: nhãn miền `SIGEVAL-v1`, loại payload, nhãn thuật toán, key_id và manifest chuẩn hóa. Tiền tố độ dài loại bỏ nhập nhằm ranh giới giữa các trường.")
    D.code('''{ "bundle_version": 1,
  "manifest": { "schema": "artifact-manifest/1", "manifest_version": 2, "release": "1.1.0",
                "provenance": {"builder": "ci-lab-01", "source": {"repo": "lab://demo", "commit": "..."}},
                "artifacts": [{"path": "demo-app.bin", "sha256": "…", "size": 65544}, …] },
  "signatures": [{"alg": "ed25519", "key_id": "<sha256 SPKI>", "sig": "<b64>",
                  "timestamp": {"time": "2026-03-15T00:00:00Z", "tsa_key_id": "…", "sig": "<b64>"}}],
  "unprotected": {"notes": ""} }''')
    D.h("3.4. Trust list có phiên bản", 2)
    D.p("Trust list gồm `version`, `issued`, `expires`, danh sách khóa ký (key_id, alg, khóa công khai, `status ∈ {active, retired, revoked}`, `not_before`, `not_after`, `compromised_since`) và danh sách khóa TSA. "
        "Khóa gốc Ed25519 (offline) ký toàn bộ trust list. Client lưu `last_version`; mọi trust list có `version < last_version` bị từ chối (chống rollback), và trust list quá `expires` bị từ chối (chống bị “đóng băng” ở trạng thái trước khi thu hồi). Thời hạn trust list là tham số cân bằng giữa an toàn và độ sẵn sàng (xem 6.2).")
    D.h("3.5. Chính sách xác minh", 2)
    D.numbered([
        "Kiểm tra trust list: khóa gốc đúng, chữ ký đúng, `version ≥ last_version`, chưa hết hạn. Lỗi → `TRUSTLIST_*`.",
        "Với từng chữ ký trong bundle: tra key_id; không có → `UNKNOWN_KEY`; nhãn alg khác trust list → `ALG_MISMATCH`.",
        "Xác minh chữ ký trên PAE(alg, key_id, manifest chuẩn hóa); sai → `BAD_SIGNATURE`.",
        "Nếu có dấu thời gian: kiểm tra TSA tin cậy và chữ ký của TSA trên (thời gian ‖ băm chữ ký); sai → `TS_INVALID`. Thời điểm ký hiệu lực `t` = thời gian trong dấu (nếu có) hoặc giờ hiện tại.",
        "Trạng thái khóa: `revoked` → chấp nhận chỉ khi có dấu thời gian hợp lệ và `t < compromised_since`, ngược lại `REVOKED`; `active/retired` → yêu cầu `not_before ≤ t ≤ not_after`, ngược lại `KEY_EXPIRED`.",
        "Cần ít nhất một chữ ký được chấp nhận (ngưỡng 1). Sau đó băm lại từng tệp: thiếu → `MISSING_FILE`, khác băm/kích thước → `HASH_MISMATCH`, có tệp không liệt kê → `UNLISTED_FILE`.",
    ])
    D.p("Quy tắc 5 là điểm mấu chốt của vòng đời: khóa nghỉ hưu **không có dấu thời gian** bị từ chối vì client không thể chứng minh chữ ký ra đời trong thời gian hiệu lực. Chính sách “từ chối khi không chắc” (R5) áp dụng xuyên suốt; mọi ngoại lệ đều ghi vào `notes` để truy vết.")
    D.h("3.6. Thiết kế thực nghiệm và chỉ số", 2)
    D.table(["TN", "Mục tiêu", "Biến/điều khiển", "Chỉ số"], [
        ["E1", "Tạo bộ artifact", "Tệp nhị phân 64 KiB (seed cố định), tài liệu văn bản, cấu hình JSON", "Băm SHA-256, kích thước"],
        ["E2", "Hiệu năng và kích thước", "3 thuật toán + RSA-2048 đối chứng; manifest ~1 KB; tệp 1 và 10 MiB; 3 lần chạy", "Trung vị, p95, độ lệch, kích thước khóa/chữ ký"],
        ["E3", "Sửa đổi từng thành phần", "19 ca × 3 thuật toán; đối chứng dương T00, T17, T18", "Mã kết quả so với kỳ vọng"],
        ["E4", "Nonce", "Ký 20 lần cùng thông điệp; hai chữ ký ECDSA cùng k", "Số chữ ký khác nhau; khôi phục d"],
        ["E5", "Luân chuyển khóa", "4 phiên bản trust list, 3 bản phát hành, các client giữ trust list khác nhau", "Ma trận chấp nhận/từ chối"],
        ["E6", "Khóa bị lộ", "Mã độc ký bằng K2 có/không dấu thời gian, dấu giả; client cũ/mới", "Ma trận và cửa sổ phơi nhiễm"],
        ["E7", "Kiểm chứng chéo", "Python ký → OpenSSL xác minh và ngược lại", "Đúng/sai"],
    ], widths=[1.1, 3.4, 7.2, 4.0], caption="Thiết kế thực nghiệm.", size=9.5, align_center_cols=(0,))
    D.p("Thời gian trong E5/E6 được mô phỏng bằng tham số `now` truyền vào bộ xác minh và bằng việc TSA mô phỏng cho phép đặt thời điểm; điều này cho phép tái lập mà không phải chờ, nhưng cũng nghĩa là TSA của nhóm **không** phải dịch vụ RFC 3161.")
