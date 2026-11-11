"""Manifest, canonical JSON, PAE (pre-authentication encoding) và đóng gói bundle chữ ký."""
from __future__ import annotations

import hashlib
import json
import os

from . import core

SCHEMA = "artifact-manifest/1"
PAYLOAD_TYPE = "application/vnd.sigeval.manifest+json"


def canonical(obj) -> bytes:
    """JSON chuẩn hóa: khóa sắp xếp, không khoảng trắng, ASCII. Cùng nội dung -> cùng byte."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pae(alg: str, kid: str, payload: bytes) -> bytes:
    """Dữ liệu thực sự được ký: ràng buộc loại payload, thuật toán và key_id (chống thay thế/đổi nhãn)."""
    parts = [b"SIGEVAL-v1", PAYLOAD_TYPE.encode(), alg.encode(), kid.encode(), payload]
    return b"".join(len(p).to_bytes(8, "big") + p for p in parts)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def list_files(root: str) -> list[str]:
    out = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            out.append(os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, "/"))
    return sorted(out)


def build_manifest(root: str, *, name: str, release: str, manifest_version: int, created: str,
                   builder: str, source: dict) -> dict:
    arts = []
    for rel in list_files(root):
        p = os.path.join(root, rel)
        arts.append({"path": rel, "sha256": sha256_file(p), "size": os.path.getsize(p)})
    return {
        "schema": SCHEMA,
        "manifest_version": manifest_version,
        "name": name,
        "release": release,
        "created": created,
        "provenance": {"builder": builder, "source": source},
        "artifacts": arts,
    }


def make_bundle(manifest: dict, signers: list[dict]) -> dict:
    """signers: [{alg, priv, pub, timestamp(optional callable sig_bytes->token)}]"""
    mbytes = canonical(manifest)
    sigs = []
    for s in signers:
        kid = core.key_id(s["pub"])
        sig = core.sign(s["alg"], s["priv"], pae(s["alg"], kid, mbytes))
        entry = {"alg": s["alg"], "key_id": kid, "sig": core.b64e(sig)}
        if s.get("timestamper"):
            entry["timestamp"] = s["timestamper"](sig)
        sigs.append(entry)
    # "unprotected" nằm NGOÀI phần được ký: dùng để minh họa giới hạn của phạm vi bảo vệ
    return {"bundle_version": 1, "manifest": manifest, "signatures": sigs, "unprotected": {"notes": ""}}
