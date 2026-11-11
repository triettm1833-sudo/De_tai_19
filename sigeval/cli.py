"""CLI nguyên mẫu.  python -m sigeval.cli <lệnh> ...   (KHÓA CHỈ DÙNG TRONG PHÒNG LAB)

  keygen    --alg ed25519 --out keys/mykey            -> mykey.priv.pem, mykey.pub.pem, in dấu vân tay
  sign      --dir ART --name N --release R --seq 1 --key keys/mykey --alg ed25519 --out bundle.json
  trustlist --version 1 --issued T --expires T --key alg:pub.pem[:status] ... --root keys/root --out tl.json
  verify    --dir ART --bundle bundle.json --trustlist tl.json --root-pub keys/root.pub.pem [--now T]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import core, manifest, trust, verify


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rd(p, mode="rb"):
    with open(p, mode) as f:
        return f.read()


def cmd_keygen(a):
    priv = core.generate(a.alg)
    pub = priv.public_key()
    open(a.out + ".priv.pem", "wb").write(core.priv_pem(priv))
    open(a.out + ".pub.pem", "wb").write(core.pub_pem(pub))
    print(f"alg={a.alg} key_id={core.key_id(pub)}")


def cmd_sign(a):
    priv = core.load_priv_pem(_rd(a.key + ".priv.pem"))
    pub = priv.public_key()
    m = manifest.build_manifest(a.dir, name=a.name, release=a.release, manifest_version=a.seq,
                                created=_now(), builder=a.builder, source={"repo": a.repo, "commit": a.commit})
    b = manifest.make_bundle(m, [{"alg": a.alg, "priv": priv, "pub": pub}])
    json.dump(b, open(a.out, "w"), indent=2)
    print("signed", a.out, "key_id", core.key_id(pub))


def cmd_trustlist(a):
    root = core.load_priv_pem(_rd(a.root + ".priv.pem"))
    keys = []
    for spec in a.key:
        alg, path, *st = spec.split(":")
        pub = core.serialization.load_pem_public_key(_rd(path))
        keys.append(trust.key_entry(alg, pub, status=(st[0] if st else "active"), not_before=a.issued))
    env = trust.issue(a.version, a.issued, a.expires, keys, [], root, root.public_key())
    json.dump(env, open(a.out, "w"), indent=2)
    print("trust list v%d ->" % a.version, a.out)


def cmd_verify(a):
    b = json.load(open(a.bundle))
    env = json.load(open(a.trustlist))
    root_pub = core.serialization.load_pem_public_key(_rd(a.root_pub))
    r = verify.verify_release(b, a.dir, env, root_pub, trust.ClientState(), a.now or _now())
    print(("PASS " if r.ok else "FAIL ") + r.code, *r.notes, sep="\n  ")
    sys.exit(0 if r.ok else 1)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sigeval")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("keygen"); p.add_argument("--alg", choices=core.ALGS + core.ALGS_EXTRA, required=True)
    p.add_argument("--out", required=True); p.set_defaults(f=cmd_keygen)
    p = sp.add_parser("sign"); p.add_argument("--dir", required=True); p.add_argument("--name", default="demo")
    p.add_argument("--release", default="1.0.0"); p.add_argument("--seq", type=int, default=1)
    p.add_argument("--key", required=True); p.add_argument("--alg", required=True)
    p.add_argument("--builder", default="local-lab"); p.add_argument("--repo", default="lab://demo")
    p.add_argument("--commit", default="0" * 40); p.add_argument("--out", required=True); p.set_defaults(f=cmd_sign)
    p = sp.add_parser("trustlist"); p.add_argument("--version", type=int, required=True)
    p.add_argument("--issued", required=True); p.add_argument("--expires", required=True)
    p.add_argument("--key", action="append", required=True); p.add_argument("--root", required=True)
    p.add_argument("--out", required=True); p.set_defaults(f=cmd_trustlist)
    p = sp.add_parser("verify"); p.add_argument("--dir", required=True); p.add_argument("--bundle", required=True)
    p.add_argument("--trustlist", required=True); p.add_argument("--root-pub", required=True)
    p.add_argument("--now"); p.set_defaults(f=cmd_verify)
    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
