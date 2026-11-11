"""E2 - Benchmark: kích thước khóa/chữ ký, thời gian keygen/ký/xác minh (thư viện chuẩn, OpenSSL backend)."""
import csv, json, os, statistics as st, sys, time, hashlib
from lab import RES, env_info, get_key
from sigeval import core
from sigeval.manifest import canonical, pae

QUICK = "--quick" in sys.argv
ALL = core.ALGS + core.ALGS_EXTRA
REPS = {"rsa-pss-3072": (10, 200, 1000), "rsa-pss-2048": (20, 400, 1500),
        "ecdsa-p256": (200, 1500, 1500), "ed25519": (500, 3000, 3000)}  # (keygen, sign, verify)
if QUICK:
    REPS = {a: tuple(max(3, x // 20) for x in v) for a, v in REPS.items()}


def timeit(fn, n, warm=5):
    for _ in range(warm):
        fn()
    xs = []
    for _ in range(n):
        t = time.perf_counter_ns(); fn(); xs.append((time.perf_counter_ns() - t) / 1000.0)  # µs
    xs.sort()
    return {"n": n, "mean_us": st.fmean(xs), "median_us": xs[len(xs) // 2], "p95_us": xs[int(0.95 * (len(xs) - 1))],
            "stdev_us": st.pstdev(xs), "min_us": xs[0], "max_us": xs[-1]}


manifest_like = canonical({"schema": "artifact-manifest/1", "artifacts": [
    {"path": f"file{i}.bin", "sha256": hashlib.sha256(bytes([i])).hexdigest(), "size": 1000 + i} for i in range(8)],
    "name": "demo", "release": "1.0.0"})
rows, sizes, big = [], [], []
for alg in ALL:
    kg, ns, nv = REPS[alg]
    k_t = timeit(lambda: core.generate(alg), kg, warm=1)
    priv, pub = get_key(f"bench-{alg}", alg)
    msg = pae(alg, core.key_id(pub), manifest_like)
    sig = core.sign(alg, priv, msg)
    s_t = timeit(lambda: core.sign(alg, priv, msg), ns)
    v_t = timeit(lambda: core.verify(alg, pub, sig, msg), nv)
    assert core.verify(alg, pub, sig, msg)
    for op, t in (("keygen", k_t), ("sign", s_t), ("verify", v_t)):
        rows.append({"alg": alg, "op": op, "payload": "manifest~%dB" % len(msg) if op != "keygen" else "-", **t})
    sl = [len(core.sign(alg, priv, os.urandom(64))) for _ in range(300)]
    sizes.append({"alg": alg, "private_pkcs8_der_B": len(core.priv_der(priv)), "public_spki_der_B": len(core.pub_der(pub)),
                  "sig_min_B": min(sl), "sig_mean_B": round(st.fmean(sl), 2), "sig_max_B": max(sl),
                  "key_id_hex_len": len(core.key_id(pub))})
    # ký trực tiếp tệp lớn (so với thiết kế ký manifest)
    for mb in (1, 10):
        data = os.urandom(mb << 20)
        reps = 5 if not QUICK else 2
        bs = timeit(lambda: core.sign(alg, priv, data), reps, warm=1)
        sg = core.sign(alg, priv, data)
        bv = timeit(lambda: core.verify(alg, pub, sg, data), reps, warm=1)
        hh = timeit(lambda: hashlib.sha256(data).digest(), reps, warm=1)
        big.append({"alg": alg, "size_MiB": mb, "sign_direct_median_ms": bs["median_us"] / 1000,
                    "verify_direct_median_ms": bv["median_us"] / 1000, "sha256_only_median_ms": hh["median_us"] / 1000})
    print(alg, "done", flush=True)

for name, data, keys in (("benchmark.csv", rows, None), ("sizes.csv", sizes, None), ("benchmark_large.csv", big, None)):
    with open(os.path.join(RES, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
json.dump({"env": env_info(), "reps": REPS, "quick": QUICK, "note": "thời gian tính bằng µs, perf_counter_ns, 1 luồng"},
          open(os.path.join(RES, "benchmark_env.json"), "w"), indent=2)
