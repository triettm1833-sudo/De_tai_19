"""E7 - Kiểm chứng chéo: chữ ký sinh bởi Python `cryptography` được OpenSSL CLI xác minh (và ngược lại)."""
import json, os, subprocess, tempfile
from lab import RES, get_key
from sigeval import core

msg = b"interop test message\n"
rows = []
d = tempfile.mkdtemp()
open(f"{d}/m", "wb").write(msg)
ver = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()


def sh(*a):
    r = subprocess.run(list(a), capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


for alg in core.ALGS:
    priv, pub = get_key(f"interop-{alg}", alg)
    open(f"{d}/pub.pem", "wb").write(core.pub_pem(pub)); open(f"{d}/priv.pem", "wb").write(core.priv_pem(priv))
    # 1) Python ký -> OpenSSL xác minh
    sig = core.sign(alg, priv, msg); open(f"{d}/s1", "wb").write(sig)
    if alg == "ed25519":
        v = sh("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/pub.pem", "-rawin", "-in", f"{d}/m", "-sigfile", f"{d}/s1")
    elif alg == "ecdsa-p256":
        v = sh("openssl", "dgst", "-sha256", "-verify", f"{d}/pub.pem", "-signature", f"{d}/s1", f"{d}/m")
    else:
        v = sh("openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
               "-sigopt", "rsa_mgf1_md:sha256", "-verify", f"{d}/pub.pem", "-signature", f"{d}/s1", f"{d}/m")
    # 2) OpenSSL ký -> Python xác minh
    if alg == "ed25519":
        s = sh("openssl", "pkeyutl", "-sign", "-inkey", f"{d}/priv.pem", "-rawin", "-in", f"{d}/m", "-out", f"{d}/s2")
    elif alg == "ecdsa-p256":
        s = sh("openssl", "dgst", "-sha256", "-sign", f"{d}/priv.pem", "-out", f"{d}/s2", f"{d}/m")
    else:
        s = sh("openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
               "-sigopt", "rsa_mgf1_md:sha256", "-sign", f"{d}/priv.pem", "-out", f"{d}/s2", f"{d}/m")
    py_ok = s[0] and core.verify(alg, pub, open(f"{d}/s2", "rb").read(), msg)
    # 3) OpenSSL phải TỪ CHỐI thông điệp bị sửa
    open(f"{d}/m2", "wb").write(msg + b"x")
    if alg == "ed25519":
        neg = sh("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/pub.pem", "-rawin", "-in", f"{d}/m2", "-sigfile", f"{d}/s1")
    elif alg == "ecdsa-p256":
        neg = sh("openssl", "dgst", "-sha256", "-verify", f"{d}/pub.pem", "-signature", f"{d}/s1", f"{d}/m2")
    else:
        neg = sh("openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                 "-sigopt", "rsa_mgf1_md:sha256", "-verify", f"{d}/pub.pem", "-signature", f"{d}/s1", f"{d}/m2")
    rows.append({"alg": alg, "python_sign_openssl_verify": v[0], "openssl_sign_python_verify": py_ok,
                 "openssl_rejects_modified_msg": (not neg[0])})
json.dump({"openssl": ver, "results": rows}, open(os.path.join(RES, "interop_openssl.json"), "w"), indent=2)
print(ver); [print(r) for r in rows]
