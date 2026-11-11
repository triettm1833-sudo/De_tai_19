"""E5 - Luân chuyển khóa có giai đoạn chồng lấn + trust list theo phiên bản.
   E6 - Khóa ký bị lộ: thu hồi, ký lại, cảnh báo. Thời gian được mô phỏng bằng tham số `now`."""
import copy, csv, json, os, shutil, tempfile
from lab import ART, RES, get_key, make_artifacts, write_fingerprints
from sigeval import core, manifest, trust, tsa, verify

root_priv, root_pub = get_key("root", "ed25519")
tsa_priv, tsa_pub = get_key("tsa", "ed25519")
atk_tsa_priv, atk_tsa_pub = get_key("attacker-tsa", "ed25519")
K1p, K1 = get_key("rot-K1-ed25519", "ed25519")
K2p, K2 = get_key("rot-K2-ecdsa", "ecdsa-p256")      # chuyển thuật toán trong lúc luân chuyển (đa dạng hóa)
K3p, K3 = get_key("rot-K3-ed25519", "ed25519")
A1, A2, A3 = "ed25519", "ecdsa-p256", "ed25519"
TSA = [trust.tsa_entry(tsa_pub)]
d = lambda s: f"2026-{s}T00:00:00Z"

# ---- Trust list theo phiên bản (ký bởi khóa gốc offline) ----
TL = {
    1: trust.issue(1, d("01-01"), d("05-01"), [trust.key_entry(A1, K1, not_before=d("01-01"))], TSA, root_priv, root_pub),
    2: trust.issue(2, d("03-01"), d("06-30"), [trust.key_entry(A1, K1, not_before=d("01-01")),
                                               trust.key_entry(A2, K2, not_before=d("03-01"))], TSA, root_priv, root_pub),
    3: trust.issue(3, d("04-01"), d("07-30"), [trust.key_entry(A1, K1, status="retired", not_before=d("01-01"), not_after=d("03-31")),
                                               trust.key_entry(A2, K2, not_before=d("03-01"))], TSA, root_priv, root_pub),
    # v4: sau sự cố — K2 bị thu hồi, khả nghi từ 06-10; K3 thay thế
    4: trust.issue(4, d("06-20"), d("09-20"), [trust.key_entry(A1, K1, status="retired", not_before=d("01-01"), not_after=d("03-31")),
                                               trust.key_entry(A2, K2, status="revoked", not_before=d("03-01"), compromised_since=d("06-10")),
                                               trust.key_entry(A3, K3, not_before=d("06-20"))], TSA, root_priv, root_pub),
}

work = tempfile.mkdtemp()
src = os.path.join(work, "art"); make_artifacts(src)


def release(rel, seq, when, signers, with_ts=True, tsa_pair=(tsa_priv, tsa_pub), ts_time=None):
    m = manifest.build_manifest(src, name="demo-app", release=rel, manifest_version=seq, created=when,
                                builder="ci-lab-01", source={"repo": "lab://demo", "commit": f"{seq:040x}"})
    ss = []
    for alg, pr, pu in signers:
        ss.append({"alg": alg, "priv": pr, "pub": pu,
                   "timestamper": tsa.make_timestamper(*tsa_pair, ts_time or when) if with_ts else None})
    return manifest.make_bundle(m, ss)


R10 = release("1.0.0", 1, d("02-01"), [(A1, K1p, K1)])
R11 = release("1.1.0", 2, d("03-15"), [(A1, K1p, K1), (A2, K2p, K2)])     # ký kép trong giai đoạn chồng lấn
R12 = release("1.2.0", 3, d("04-10"), [(A2, K2p, K2)])
R10_nots = release("1.0.0", 1, d("02-01"), [(A1, K1p, K1)], with_ts=False)


def run(label, now, tl_ver, bundle, expected, last_seen=None, tl_override=None, note=""):
    st = trust.ClientState(tl_ver if last_seen is None else last_seen)
    env = tl_override or TL[tl_ver]
    r = verify.verify_release(bundle, src, env, root_pub, st, now)
    return {"id": label, "now": now[:10], "client_trust_list": f"v{tl_ver}" if not tl_override else "v?(rollback)",
            "release": bundle["manifest"]["release"], "signers": "+".join(s["alg"] + ":" + s["key_id"][:4] for s in bundle["signatures"]),
            "expected": expected, "actual": r.code, "verdict": "PASS" if r.code == expected else "UNEXPECTED",
            "note": note or "; ".join(r.notes)[:140]}


rot = [
    run("R01", d("02-10"), 1, R10, "OK", note="Cơ sở: K1 duy nhất"),
    run("R02", d("03-20"), 1, R11, "OK", note="Client CHƯA cập nhật vẫn xác minh được nhờ chữ ký K1 (chồng lấn)"),
    run("R03", d("03-20"), 2, R11, "OK", note="Client đã cập nhật: chấp nhận cả hai chữ ký"),
    run("R04", d("04-15"), 3, R12, "OK", note="Chỉ ký K2 sau khi K1 nghỉ hưu"),
    run("R05", d("04-15"), 1, R12, "UNKNOWN_KEY", note="Client kẹt ở v1: fail-closed, buộc cập nhật trust list"),
    run("R06", d("06-01"), 3, R10, "OK", note="K1 đã nghỉ hưu nhưng chữ ký có dấu thời gian 02-01 nằm trong hiệu lực"),
    run("R07", d("06-01"), 3, R10_nots, "KEY_EXPIRED", note="Cùng bản phát hành nhưng KHÔNG có dấu thời gian: bị từ chối"),
    run("R08", d("06-01"), 3, R11, "OK", note="Bản ký kép vẫn xác minh qua K2 (và K1 nhờ dấu thời gian)"),
    run("R09", d("06-01"), 3, R12, "OK"),
    run("R10", d("06-01"), 1, R12, "TRUSTLIST_EXPIRED", note="Trust list v1 hết hạn 05-01: client không cập nhật bị từ chối thay vì tin mù"),
    run("R11", d("06-01"), 1, R12, "TRUSTLIST_ROLLBACK", last_seen=3, tl_override=TL[1], note="Kẻ tấn công phát lại v1 cho client đã thấy v3 (nhưng v1 đã hết hạn, kiểm tra rollback chạy trước hạn dùng)"),
    run("R12", d("08-15"), 3, R12, "TRUSTLIST_EXPIRED", note="Trust list v3 hết hạn 07-30"),
]
# R11: thứ tự kiểm tra trong trust.check -> rollback trước expired
# ---- E6: khóa K2 bị lộ ----
atk_dir = os.path.join(work, "atk"); shutil.copytree(src, atk_dir)
open(os.path.join(atk_dir, "demo-app.bin"), "ab").write(b"MALWARE")
m_atk = manifest.build_manifest(atk_dir, name="demo-app", release="1.2.1", manifest_version=4, created=d("06-12"),
                                builder="attacker", source={"repo": "evil://x", "commit": "e" * 40})
ATK_TS = manifest.make_bundle(m_atk, [{"alg": A2, "priv": K2p, "pub": K2, "timestamper": tsa.make_timestamper(tsa_priv, tsa_pub, d("06-12"))}])
ATK_NOTS = manifest.make_bundle(m_atk, [{"alg": A2, "priv": K2p, "pub": K2}])
ATK_BACKDATE = manifest.make_bundle(m_atk, [{"alg": A2, "priv": K2p, "pub": K2, "timestamper": tsa.make_timestamper(atk_tsa_priv, atk_tsa_pub, d("04-01"))}])
R13 = release("1.3.0", 5, d("06-15"), [(A2, K2p, K2)])  # bản hợp lệ do đội phát hành, ký K2 trong khoảng nghi ngờ
R13b = release("1.3.0", 5, d("06-21"), [(A3, K3p, K3)])  # ký lại bằng K3


def run_dir(label, now, tl_ver, bundle, directory, expected, note="", last_seen=None, tl_override=None):
    global src
    keep, src = src, directory
    try:
        return run(label, now, tl_ver, bundle, expected, last_seen=last_seen, tl_override=tl_override, note=note)
    finally:
        src = keep


comp = [
    run("C01", d("06-21"), 4, R12, "OK", note="Bản 1.2.0 ký K2 với dấu thời gian 04-10 < compromised_since 06-10: giữ hiệu lực"),
    run("C02", d("06-21"), 4, R13, "REVOKED", note="Bản hợp lệ 1.3.0 ký K2 ngày 06-15 nằm trong cửa sổ nghi ngờ: phải ký lại"),
    run("C03", d("06-21"), 4, R13b, "OK", note="1.3.0 ký lại bằng K3 (trust list v4)"),
    run_dir("C04", d("06-21"), 4, ATK_TS, atk_dir, "REVOKED", note="Mã độc ký K2, có dấu thời gian THẬT từ TSA (06-12 >= 06-10)"),
    run_dir("C05", d("06-21"), 4, ATK_NOTS, atk_dir, "REVOKED", note="Mã độc ký K2, không dấu thời gian"),
    run_dir("C06", d("06-21"), 4, ATK_BACKDATE, atk_dir, "TS_INVALID", note="Kẻ tấn công tự ký dấu thời gian lùi về 04-01: TSA không tin cậy"),
    run_dir("C07", d("06-15"), 3, ATK_TS, atk_dir, "OK", note="RỦI RO DƯ: client còn giữ trust list v3 (trước thu hồi) CHẤP NHẬN mã độc"),
    run_dir("C08", d("06-21"), 3, ATK_TS, atk_dir, "OK", note="Client chưa nhận v4 sau 1 ngày: vẫn nằm trong cửa sổ phơi nhiễm đến khi cập nhật/hết hạn v3 (07-30)"),
    run_dir("C09", d("06-21"), 4, ATK_TS, atk_dir, "TRUSTLIST_ROLLBACK", last_seen=4, tl_override=TL[3], note="Phát lại trust list v3 cho client đã thấy v4"),
]
for r in comp:
    if r["id"] == "C07":  # C07 có now=06-15, v3 chưa hết hạn, kẻ tấn công ký 06-12
        r["note"] = "RỦI RO DƯ: client còn trust list v3 (trước thu hồi) CHẤP NHẬN mã độc"

for name, data in (("rotation_results.csv", rot), ("compromise_results.csv", comp)):
    with open(os.path.join(RES, name), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
os.makedirs(os.path.join(ART, "lifecycle"), exist_ok=True)
for v, env in TL.items():
    json.dump(env, open(os.path.join(ART, "lifecycle", f"trustlist.v{v}.json"), "w"), indent=1)
for n, b in (("release-1.0.0", R10), ("release-1.1.0-dualsig", R11), ("release-1.2.0", R12), ("release-1.3.0-K2-in-suspect-window", R13),
             ("release-1.3.0-resigned-K3", R13b), ("attacker-1.2.1-K2-realTS", ATK_TS)):
    json.dump(b, open(os.path.join(ART, "lifecycle", n + ".bundle.json"), "w"), indent=1)
named = {"root": ("ed25519", root_pub), "tsa": ("ed25519", tsa_pub), "K1": (A1, K1), "K2": (A2, K2), "K3": (A3, K3)}
fp = json.load(open(os.path.join(os.path.dirname(RES), "keys", "fingerprints.json")))
fp.update({n: {"alg": a, "key_id": core.key_id(p), "short": core.fp_fmt(core.key_id(p))} for n, (a, p) in named.items()})
json.dump(fp, open(os.path.join(os.path.dirname(RES), "keys", "fingerprints.json"), "w"), indent=2)
for r in rot + comp:
    print(r["id"], r["now"], r["client_trust_list"], r["release"], r["expected"], r["actual"], r["verdict"])
shutil.rmtree(work)
