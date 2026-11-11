"""ECDSA P-256 đồ chơi, CHỈ ĐỂ MINH HỌA tấn công tái sử dụng nonce (slide chương 4).

Không dùng cho mục đích thật: số học không hằng thời gian, nonce do người gọi chỉ định.
Chữ ký sinh ra được kiểm chứng chéo bằng thư viện `cryptography` để chứng minh cài đặt đúng.
"""
import hashlib

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (Gx, Gy)


def inv(x, m):
    return pow(x, -1, m)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    lam = ((3 * x1 * x1 + a) * inv(2 * y1, p) if P == Q else (y2 - y1) * inv(x2 - x1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def mul(k, P):
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


def z_of(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def sign(d: int, msg: bytes, k: int):
    z = z_of(msg)
    r = mul(k, G)[0] % n
    s = inv(k, n) * (z + r * d) % n
    assert r and s
    return r, s


def recover_private_key(r, s1, s2, msg1: bytes, msg2: bytes) -> int:
    """Hai chữ ký cùng (d, k): k = (z1-z2)/(s1-s2); d = (s1*k - z1)/r (mod n)."""
    z1, z2 = z_of(msg1), z_of(msg2)
    k = (z1 - z2) * inv(s1 - s2, n) % n
    return (s1 * k - z1) * inv(r, n) % n
