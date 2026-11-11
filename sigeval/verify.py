"""Quy trình xác minh bundle: trust list -> chữ ký -> dấu thời gian/trạng thái khóa -> băm tệp."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import core, trust, tsa
from .manifest import canonical, list_files, pae, sha256_file


@dataclass
class Result:
    ok: bool = False
    code: str = "OK"
    notes: list[str] = field(default_factory=list)
    accepted_by: list[str] = field(default_factory=list)

    def fail(self, code: str, note: str = ""):
        self.ok, self.code = False, code
        if note:
            self.notes.append(note)
        return self


def verify_release(bundle: dict, root_dir: str, trust_env: dict, root_pub, state: trust.ClientState,
                   now: str, *, require_unlisted_check: bool = True) -> Result:
    res = Result()
    tl, err = trust.check(trust_env, root_pub, state, now)
    if err:
        return res.fail(err)

    sigs = bundle.get("signatures") or []
    if not sigs:
        return res.fail("NO_SIGNATURE")

    mbytes = canonical(bundle["manifest"])
    reasons: list[str] = []
    for s in sigs:
        kid, alg = s.get("key_id", ""), s.get("alg", "")
        tag = f"{alg}:{kid[:8]}"
        entry = next((k for k in tl["keys"] if k["key_id"] == kid), None)
        if entry is None:
            reasons.append("UNKNOWN_KEY"); res.notes.append(f"{tag} không có trong trust list v{tl['version']}")
            continue
        if entry["alg"] != alg:
            reasons.append("ALG_MISMATCH"); res.notes.append(f"{tag} nhãn thuật toán khác trust list ({entry['alg']})")
            continue
        pub = core.load_pub_der(core.b64d(entry["pub"]))
        try:
            sig = core.b64d(s["sig"])
        except Exception:
            reasons.append("BAD_SIGNATURE"); continue
        if not core.verify(alg, pub, sig, pae(alg, kid, mbytes)):
            reasons.append("BAD_SIGNATURE"); res.notes.append(f"{tag} chữ ký toán học không khớp")
            continue
        ts_time = None
        if s.get("timestamp"):
            ts_time = tsa.check(s["timestamp"], sig, tl["tsa"])
            if ts_time is None:
                reasons.append("TS_INVALID"); res.notes.append(f"{tag} dấu thời gian không hợp lệ/không tin cậy")
                continue
        t = ts_time or now  # thời điểm ký hiệu lực
        T = trust.parse_t
        if entry["status"] == "revoked":
            cs = entry.get("compromised_since")
            if cs and ts_time and T(ts_time) < T(cs):
                res.notes.append(f"{tag} đã thu hồi nhưng dấu thời gian {ts_time} < compromised_since {cs}: chấp nhận")
            else:
                reasons.append("REVOKED"); res.notes.append(f"{tag} khóa bị thu hồi (compromised_since={cs}, ts={ts_time})")
                continue
        else:
            if T(t) < T(entry["not_before"]):
                reasons.append("KEY_NOT_YET_VALID"); continue
            if entry["not_after"] and T(t) > T(entry["not_after"]):
                reasons.append("KEY_EXPIRED")
                res.notes.append(f"{tag} hết hạn {entry['not_after']}, thời điểm ký hiệu lực {t}"
                                 + ("" if ts_time else " (không có dấu thời gian)"))
                continue
        res.accepted_by.append(tag + (f"@{ts_time}" if ts_time else ""))

    if not res.accepted_by:
        return res.fail(reasons[0] if reasons else "BAD_SIGNATURE")

    arts = bundle["manifest"]["artifacts"]
    listed = {a["path"] for a in arts}
    for a in arts:
        p = os.path.join(root_dir, a["path"])
        if not os.path.isfile(p):
            return res.fail("MISSING_FILE", a["path"])
        if os.path.getsize(p) != a["size"] or sha256_file(p) != a["sha256"]:
            return res.fail("HASH_MISMATCH", a["path"])
    if require_unlisted_check:
        extra = [f for f in list_files(root_dir) if f not in listed]
        if extra:
            return res.fail("UNLISTED_FILE", ",".join(extra))
    res.ok, res.code = True, "OK"
    return res
