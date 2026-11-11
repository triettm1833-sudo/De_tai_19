"""Danh sách khóa tin cậy có phiên bản, ký bởi khóa gốc (offline), có hạn dùng và chống rollback."""
from __future__ import annotations

from datetime import datetime, timezone

from . import core
from .manifest import canonical

ROOT_ALG = "ed25519"


def parse_t(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def key_entry(alg, pub, *, status="active", not_before, not_after=None, compromised_since=None) -> dict:
    return {"key_id": core.key_id(pub), "alg": alg, "pub": core.b64e(core.pub_der(pub)), "status": status,
            "not_before": not_before, "not_after": not_after, "compromised_since": compromised_since}


def tsa_entry(pub) -> dict:
    return {"key_id": core.key_id(pub), "alg": "ed25519", "pub": core.b64e(core.pub_der(pub))}


def issue(version: int, issued: str, expires: str, keys: list[dict], tsa: list[dict], root_priv, root_pub) -> dict:
    tl = {"schema": "trust-list/1", "version": version, "issued": issued, "expires": expires,
          "keys": keys, "tsa": tsa}
    kid = core.key_id(root_pub)
    sig = core.sign(ROOT_ALG, root_priv, canonical(tl))
    return {"trust_list": tl, "root_key_id": kid, "sig": core.b64e(sig)}


class ClientState:
    """Trạng thái client lưu lâu dài: phiên bản trust list lớn nhất đã thấy (chống rollback)."""

    def __init__(self, last_version: int = 0):
        self.last_version = last_version


def check(env: dict, root_pub, state: ClientState, now: str):
    """Trả (trust_list | None, mã lỗi | None)."""
    if env.get("root_key_id") != core.key_id(root_pub):
        return None, "TRUSTLIST_BAD_ROOT"
    if not core.verify(ROOT_ALG, root_pub, core.b64d(env["sig"]), canonical(env["trust_list"])):
        return None, "TRUSTLIST_BAD_SIGNATURE"
    tl = env["trust_list"]
    if tl["version"] < state.last_version:
        return None, "TRUSTLIST_ROLLBACK"
    if parse_t(now) > parse_t(tl["expires"]):
        return None, "TRUSTLIST_EXPIRED"
    state.last_version = tl["version"]
    return tl, None
