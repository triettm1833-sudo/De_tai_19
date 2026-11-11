import csv, os, subprocess, sys
import pytest
HERE = os.path.dirname(__file__); ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path[:0] = [ROOT, os.path.join(ROOT, "experiments")]
from cryptography.hazmat.primitives.asymmetric import ec
from sigeval import core, manifest, toyecdsa as T


@pytest.mark.parametrize("alg", core.ALGS + core.ALGS_EXTRA)
def test_roundtrip_and_negative(alg):
    priv = core.generate(alg); pub = priv.public_key()
    sig = core.sign(alg, priv, b"msg")
    assert core.verify(alg, pub, sig, b"msg")
    assert not core.verify(alg, pub, sig, b"msg2")
    other = core.generate(alg).public_key()
    assert not core.verify(alg, other, sig, b"msg")
    assert not core.verify(alg, pub, sig[:-1] + bytes([sig[-1] ^ 1]), b"msg")


def test_pae_binds_alg_and_keyid():
    assert manifest.pae("ed25519", "aa", b"x") != manifest.pae("ecdsa-p256", "aa", b"x")
    assert manifest.pae("ed25519", "aa", b"x") != manifest.pae("ed25519", "ab", b"x")


def test_canonical_is_order_independent():
    assert manifest.canonical({"a": 1, "b": [1, 2]}) == manifest.canonical({"b": [1, 2], "a": 1})


def test_ed25519_deterministic_ecdsa_not():
    p = core.generate("ed25519"); q = core.generate("ecdsa-p256")
    assert core.sign("ed25519", p, b"m") == core.sign("ed25519", p, b"m")
    assert core.sign("ecdsa-p256", q, b"m") != core.sign("ecdsa-p256", q, b"m")


def test_toy_ecdsa_matches_library_and_nonce_reuse_breaks_key():
    from cryptography.hazmat.primitives.asymmetric import utils
    priv = ec.generate_private_key(ec.SECP256R1()); d = priv.private_numbers().private_value
    k = 0x1234567890ABCDEF1234567890ABCDEF
    (r1, s1), (r2, s2) = T.sign(d, b"m1", k), T.sign(d, b"m2", k)
    assert core.verify("ecdsa-p256", priv.public_key(), utils.encode_dss_signature(r1, s1), b"m1")
    assert r1 == r2 and T.recover_private_key(r1, s1, s2, b"m1", b"m2") == d


def test_tamper_matrix_all_as_expected():
    import e3_tamper
    e3_tamper.main()
    rows = list(csv.DictReader(open(os.path.join(ROOT, "results", "tamper_results.csv"), encoding="utf-8")))
    assert len(rows) == 19 * 3 and all(r["verdict"] == "PASS" for r in rows)


def test_rotation_and_compromise_all_as_expected():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "experiments", "e5_e6_lifecycle.py")],
                       capture_output=True, text=True, cwd=os.path.join(ROOT, "experiments"),
                       env={**os.environ, "PYTHONPATH": ROOT})
    assert r.returncode == 0, r.stderr
    for f in ("rotation_results.csv", "compromise_results.csv"):
        rows = list(csv.DictReader(open(os.path.join(ROOT, "results", f), encoding="utf-8")))
        assert rows and all(x["verdict"] == "PASS" for x in rows)
