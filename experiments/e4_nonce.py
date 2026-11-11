"""E4 - Hành vi nonce: tính tất định, tái sử dụng nonce ECDSA -> lộ khóa riêng (minh họa, lab only)."""
import json, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from lab import RES, get_key
from sigeval import core, toyecdsa as T

out = {}
msgs = [b"phat hanh phan mem v1.0.0", b"phat hanh phan mem v1.0.1"]

# (a) Cùng khóa, cùng thông điệp, ký 20 lần: có bao nhiêu chữ ký khác nhau?
det = {}
for alg in core.ALGS:
    priv, pub = get_key(f"nonce-{alg}", alg)
    sigs = {core.sign(alg, priv, msgs[0]) for _ in range(20)}
    det[alg] = {"distinct_signatures_in_20": len(sigs), "deterministic": len(sigs) == 1}
# RFC 6979 (nếu thư viện hỗ trợ)
try:
    priv, pub = get_key("nonce-ecdsa-p256", "ecdsa-p256")
    s = {priv.sign(msgs[0], ec.ECDSA(hashes.SHA256(), deterministic_signing=True)) for _ in range(20)}
    ok = all(core.verify("ecdsa-p256", pub, x, msgs[0]) for x in s)
    det["ecdsa-p256-rfc6979"] = {"distinct_signatures_in_20": len(s), "deterministic": len(s) == 1, "verifies": ok}
except Exception as e:  # noqa
    det["ecdsa-p256-rfc6979"] = {"unsupported": repr(e)[:120]}
out["determinism"] = det

# (b) Ed25519: R = sig[:32] là điểm nonce k*B, k = H(prefix||M)
priv, pub = get_key("nonce-ed25519", "ed25519")
r1a, r1b, r2 = (core.sign("ed25519", priv, msgs[0])[:32], core.sign("ed25519", priv, msgs[0])[:32],
                core.sign("ed25519", priv, msgs[1])[:32])
out["ed25519_R"] = {"same_msg_same_R": r1a == r1b, "diff_msg_diff_R": r1a != r2,
                    "R_msg0": r1a.hex(), "R_msg1": r2.hex()}

# (c) ECDSA P-256: hai chữ ký cùng nonce k -> khôi phục khóa riêng
priv, pub = get_key("nonce-ecdsa-victim", "ecdsa-p256")
d = priv.private_numbers().private_value
k = int.from_bytes(os.urandom(32), "big") % (T.n - 1) + 1
(r1, s1), (r2_, s2) = T.sign(d, msgs[0], k), T.sign(d, msgs[1], k)
# kiểm chứng chéo: chữ ký đồ chơi phải được thư viện chuẩn chấp nhận
x_ok = [core.verify("ecdsa-p256", pub, utils.encode_dss_signature(r, s), m)
        for (r, s), m in (((r1, s1), msgs[0]), ((r2_, s2), msgs[1]))]
d_rec = T.recover_private_key(r1, s1, s2, msgs[0], msgs[1]) if r1 == r2_ else None
# đối chứng: hai nonce khác nhau thì công thức không ra khóa
k2 = (k + 12345) % T.n
(r3, s3) = T.sign(d, msgs[1], k2)
wrong = (T.recover_private_key(r1, s1, s3, msgs[0], msgs[1]) if r1 == r3 else None)
# khóa khôi phục có ký được thay nạn nhân không?
forged_priv = ec.derive_private_key(d_rec, ec.SECP256R1())
forged = forged_priv.sign(b"phan mem doc hai", ec.ECDSA(hashes.SHA256()))
out["ecdsa_nonce_reuse"] = {
    "toy_sigs_verify_with_library": x_ok, "same_r_observed": r1 == r2_,
    "recovered_equals_private_key": d_rec == d,
    "forged_signature_verifies_under_victim_pub": core.verify("ecdsa-p256", pub, forged, b"phan mem doc hai"),
    "control_distinct_nonces_same_r": r1 == r3,
    "victim_key_id": core.key_id(pub),
}
json.dump(out, open(os.path.join(RES, "nonce_results.json"), "w"), indent=2)
print(json.dumps(out, indent=2)[:1800])
