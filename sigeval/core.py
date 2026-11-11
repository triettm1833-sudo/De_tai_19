"""Primitive layer: key generation, sign, verify for RSA-PSS / ECDSA P-256 / Ed25519.

Chỉ dùng API của thư viện `cryptography` (OpenSSL backend). Không tự cài đặt thuật toán mới.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = ("rsa-pss-3072", "ecdsa-p256", "ed25519")
ALGS_EXTRA = ("rsa-pss-2048",)  # đối chứng cấp độ an toàn thấp hơn
PSS_SALT = 32  # = độ dài SHA-256


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def generate(alg: str):
    if alg.startswith("rsa-pss-"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(alg.rsplit("-", 1)[1]))
    if alg == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported alg {alg}")


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT)


def sign(alg: str, priv, data: bytes) -> bytes:
    if alg.startswith("rsa-pss-"):
        return priv.sign(data, _pss(), hashes.SHA256())
    if alg == "ecdsa-p256":
        return priv.sign(data, ec.ECDSA(hashes.SHA256()))
    if alg == "ed25519":
        return priv.sign(data)
    raise ValueError(alg)


def verify(alg: str, pub, sig: bytes, data: bytes) -> bool:
    try:
        if alg.startswith("rsa-pss-"):
            pub.verify(sig, data, _pss(), hashes.SHA256())
        elif alg == "ecdsa-p256":
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        elif alg == "ed25519":
            pub.verify(sig, data)
        else:
            return False
        return True
    except (InvalidSignature, TypeError, ValueError, AttributeError):
        return False


def pub_der(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def priv_der(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def priv_pem(priv) -> bytes:  # LAB ONLY: không mã hóa khóa riêng
    return priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def pub_pem(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_pub_der(b: bytes):
    return serialization.load_der_public_key(b)


def load_priv_pem(b: bytes):
    return serialization.load_pem_private_key(b, password=None)


def key_id(pub) -> str:
    """Dấu vân tay khóa = SHA-256 của SubjectPublicKeyInfo DER (hex)."""
    return hashlib.sha256(pub_der(pub)).hexdigest()


def fp_fmt(kid: str, groups: int = 8) -> str:
    """Định dạng dễ đọc: 8 byte đầu, cách nhau bằng dấu ':'."""
    return ":".join(kid[i : i + 2] for i in range(0, groups * 2, 2)).upper()
