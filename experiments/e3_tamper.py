"""E3 - Sửa từng thành phần của artifact/manifest/bundle và ghi nhận hành vi xác minh (mỗi thuật toán)."""
import copy, csv, json, os, shutil, tempfile
from lab import ART, RES, get_key, make_artifacts, write_fingerprints
from sigeval import core, manifest, trust, tsa, verify

NOW = "2026-02-02T00:00:00Z"
TS_T = "2026-02-01T00:00:00Z"
T0 = "2026-01-01T00:00:00Z"
EXP = "2026-12-31T00:00:00Z"


def setup(alg):
    priv, pub = get_key(f"tamper-{alg}-a", alg)
    priv_b, pub_b = get_key(f"tamper-{alg}-b", alg)       # khóa tin cậy thứ hai CÙNG thuật toán (cho T8)
    atk_priv, atk_pub = get_key(f"attacker-{alg}", alg)   # khóa kẻ tấn công, KHÔNG nằm trong trust list
    root_priv, root_pub = get_key("root", "ed25519")
    tsa_priv, tsa_pub = get_key("tsa", "ed25519")
    tl = trust.issue(1, T0, EXP, [trust.key_entry(alg, pub, not_before=T0), trust.key_entry(alg, pub_b, not_before=T0)],
                     [trust.tsa_entry(tsa_pub)], root_priv, root_pub)
    d = tempfile.mkdtemp(prefix="orig_")
    make_artifacts(d)
    m = manifest.build_manifest(d, name="demo-app", release="1.0.0", manifest_version=1, created=TS_T,
                                builder="ci-lab-01", source={"repo": "lab://demo", "commit": "a" * 40})
    ts = tsa.make_timestamper(tsa_priv, tsa_pub, TS_T)
    bundle = manifest.make_bundle(m, [{"alg": alg, "priv": priv, "pub": pub, "timestamper": ts}])
    atk_bundle = manifest.make_bundle(m, [{"alg": alg, "priv": atk_priv, "pub": atk_pub}])
    return dict(dir=d, bundle=bundle, tl=tl, root_pub=root_pub, kid_b=core.key_id(pub_b), atk=atk_bundle, alg=alg)


def run_case(ctx, mutate):
    d = tempfile.mkdtemp(prefix="case_")
    shutil.rmtree(d); shutil.copytree(ctx["dir"], d)
    b = copy.deepcopy(ctx["bundle"])
    b = mutate(d, b, ctx) or b
    r = verify.verify_release(b, d, ctx["tl"], ctx["root_pub"], trust.ClientState(), NOW)
    shutil.rmtree(d)
    return r


def flip_file_byte(d, rel):
    p = os.path.join(d, rel); data = bytearray(open(p, "rb").read()); data[len(data) // 2] ^= 0x01
    open(p, "wb").write(bytes(data))


def set_manifest(path, val):
    def f(d, b, c):
        cur = b["manifest"]
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = val
    return f


def sig_flip(d, b, c):
    s = bytearray(core.b64d(b["signatures"][0]["sig"])); s[len(s) // 2] ^= 0x01
    b["signatures"][0]["sig"] = core.b64e(bytes(s))


def rehash_manifest(d, b, c):  # kẻ tấn công sửa tệp RỒI sửa luôn băm trong manifest (không có khóa ký)
    flip_file_byte(d, "demo-app.bin")
    b["manifest"]["artifacts"] = manifest.build_manifest(d, name="demo-app", release="1.0.0", manifest_version=1,
        created=TS_T, builder="ci-lab-01", source={"repo": "lab://demo", "commit": "a" * 40})["artifacts"]


def alg_relabel(d, b, c):
    b["signatures"][0]["alg"] = "ed25519" if c["alg"] != "ed25519" else "ecdsa-p256"


def key_swap(d, b, c):
    b["signatures"][0]["key_id"] = c["kid_b"]


def remove_file(d, b, c):
    os.remove(os.path.join(d, "bien-ban.txt"))


def add_file(d, b, c):
    open(os.path.join(d, "backdoor.sh"), "w").write("echo pwned\n")


def append_doc(d, b, c):
    open(os.path.join(d, "bien-ban.txt"), "a", encoding="utf-8").write(" ")


def strip(d, b, c):
    b["signatures"] = []


def unprotected(d, b, c):
    b["unprotected"]["notes"] = "ghi chú bị sửa ngoài phạm vi chữ ký"


def ts_tamper(d, b, c):
    b["signatures"][0]["timestamp"]["time"] = "2025-06-01T00:00:00Z"


def reorder(d, b, c):  # đổi thứ tự khóa & khoảng trắng: canonicalization phải hấp thụ
    b["manifest"] = json.loads(json.dumps(b["manifest"], sort_keys=False, indent=3)[::1])
    b["manifest"] = dict(reversed(list(b["manifest"].items())))


def attacker(d, b, c):
    return copy.deepcopy(c["atk"])


def replay_alg_confusion(d, b, c):  # đổi alg trong envelope VÀ key_id sang khóa khác alg: phải bị trust list chặn
    b["signatures"][0]["alg"] = "ed25519" if c["alg"] != "ed25519" else "ecdsa-p256"
    b["signatures"][0]["key_id"] = "0" * 64


CASES = [
    ("T00", "Đối chứng dương: artifact và bundle nguyên vẹn", "(không sửa)", None, "OK"),
    ("T01", "Lật 1 bit trong tệp nhị phân", "artifact: demo-app.bin", lambda d, b, c: flip_file_byte(d, "demo-app.bin"), "HASH_MISMATCH"),
    ("T02", "Thêm 1 ký tự vào tài liệu", "artifact: bien-ban.txt", append_doc, "HASH_MISMATCH"),
    ("T03", "Sửa metadata builder", "manifest.provenance.builder", set_manifest(["provenance", "builder"], "evil-ci"), "BAD_SIGNATURE"),
    ("T04", "Sửa số phiên bản phát hành", "manifest.release", set_manifest(["release"], "9.9.9"), "BAD_SIGNATURE"),
    ("T05", "Sửa commit nguồn (provenance)", "manifest.provenance.source.commit", set_manifest(["provenance", "source", "commit"], "b" * 40), "BAD_SIGNATURE"),
    ("T06", "Sửa manifest_version (hạ cấp)", "manifest.manifest_version", set_manifest(["manifest_version"], 0), "BAD_SIGNATURE"),
    ("T07", "Sửa tệp rồi tính lại băm trong manifest", "artifact + manifest.artifacts", rehash_manifest, "BAD_SIGNATURE"),
    ("T08", "Lật 1 bit trong chữ ký", "signature", sig_flip, "BAD_SIGNATURE"),
    ("T09", "Đổi key_id sang khóa tin cậy khác cùng thuật toán", "bundle.key_id", key_swap, "BAD_SIGNATURE"),
    ("T10", "Đổi nhãn thuật toán trong bundle", "bundle.alg", alg_relabel, "ALG_MISMATCH"),
    ("T11", "Đổi nhãn thuật toán và key_id không tồn tại", "bundle.alg + key_id", replay_alg_confusion, "UNKNOWN_KEY"),
    ("T12", "Xóa một tệp khỏi gói", "artifact: bien-ban.txt", remove_file, "MISSING_FILE"),
    ("T13", "Chèn thêm tệp không có trong manifest", "artifact: backdoor.sh", add_file, "UNLISTED_FILE"),
    ("T14", "Gỡ toàn bộ chữ ký", "signatures", strip, "NO_SIGNATURE"),
    ("T15", "Bundle ký bằng khóa kẻ tấn công (không trong trust list)", "signer", attacker, "UNKNOWN_KEY"),
    ("T16", "Sửa thời gian trong dấu thời gian", "signature.timestamp", ts_tamper, "TS_INVALID"),
    ("T17", "Đổi thứ tự khóa/khoảng trắng JSON của manifest (vô hại)", "manifest (định dạng)", reorder, "OK"),
    ("T18", "Sửa trường ngoài phạm vi ký (unprotected.notes)", "bundle.unprotected", unprotected, "OK"),
]


def main():
    rows = []
    log = open(os.path.join(RES, "verify_log.txt"), "w", encoding="utf-8")
    fp = {}
    for alg in core.ALGS:
        ctx = setup(alg)
        if alg == "ed25519":  # lưu minh chứng artifact gốc + bản bị sửa + bundle
            for sub in ("original", "tampered-binary", "tampered-document"):
                shutil.rmtree(os.path.join(ART, sub), ignore_errors=True)
            shutil.copytree(ctx["dir"], os.path.join(ART, "original"))
            shutil.copytree(ctx["dir"], os.path.join(ART, "tampered-binary")); flip_file_byte(os.path.join(ART, "tampered-binary"), "demo-app.bin")
            shutil.copytree(ctx["dir"], os.path.join(ART, "tampered-document")); append_doc(os.path.join(ART, "tampered-document"), None, None)
        os.makedirs(os.path.join(ART, "bundles"), exist_ok=True)
        json.dump(ctx["bundle"], open(os.path.join(ART, "bundles", f"{alg}.bundle.json"), "w"), indent=1)
        json.dump(ctx["tl"], open(os.path.join(ART, "bundles", f"{alg}.trustlist.json"), "w"), indent=1)
        fp[alg] = core.key_id(core.load_pub_der(core.b64d(ctx["tl"]["trust_list"]["keys"][0]["pub"])))
        for tid, desc, comp, mut, exp in CASES:
            r = run_case(ctx, mut or (lambda d, b, c: None))
            rows.append({"alg": alg, "test": tid, "description": desc, "component": comp, "expected": exp,
                         "actual": r.code, "verdict": "PASS" if r.code == exp else "UNEXPECTED"})
            log.write(f"[{alg}] {tid} {desc} -> {'ACCEPT' if r.ok else 'REJECT'} code={r.code} expected={exp} "
                      f"{'OK' if r.code == exp else '!!! UNEXPECTED'} {'; '.join(r.notes)}\n")
        shutil.rmtree(ctx["dir"])
    log.close()
    with open(os.path.join(RES, "tamper_results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    bad = [r for r in rows if r["verdict"] != "PASS"]
    print(f"tamper: {len(rows)} ca, {len(bad)} khác kỳ vọng")
    for r in bad:
        print("  UNEXPECTED", r)
    # dấu vân tay công khai
    named = {f"tamper-{a}-a": (a, get_key(f"tamper-{a}-a", a)[1]) for a in core.ALGS}
    named["root"] = ("ed25519", get_key("root", "ed25519")[1]); named["tsa"] = ("ed25519", get_key("tsa", "ed25519")[1])
    for a in core.ALGS:
        named[f"attacker-{a}"] = (a, get_key(f"attacker-{a}", a)[1])
    write_fingerprints(named)


if __name__ == "__main__":
    main()
