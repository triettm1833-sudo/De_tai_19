"""TSA MÔ PHỎNG (không phải RFC 3161). Ký (thời_gian || SHA-256(chữ ký)) bằng Ed25519.

Cho phép đặt thời gian tùy ý để mô phỏng dòng thời gian; một TSA thật không cho phép điều này.
"""
from __future__ import annotations

import hashlib

from . import core


def _msg(time_iso: str, sig_bytes: bytes) -> bytes:
    return b"TS-v1\0" + time_iso.encode() + b"\0" + hashlib.sha256(sig_bytes).digest()


def make_timestamper(tsa_priv, tsa_pub, time_iso: str):
    kid = core.key_id(tsa_pub)

    def _ts(sig_bytes: bytes) -> dict:
        return {"time": time_iso, "tsa_key_id": kid,
                "sig": core.b64e(core.sign("ed25519", tsa_priv, _msg(time_iso, sig_bytes)))}

    return _ts


def check(token: dict, sig_bytes: bytes, tsa_keys: list[dict]) -> str | None:
    """Trả về thời gian (ISO) nếu token hợp lệ và do TSA tin cậy phát hành; ngược lại None."""
    for k in tsa_keys:
        if k["key_id"] == token.get("tsa_key_id"):
            pub = core.load_pub_der(core.b64d(k["pub"]))
            if core.verify("ed25519", pub, core.b64d(token["sig"]), _msg(token["time"], sig_bytes)):
                return token["time"]
    return None
