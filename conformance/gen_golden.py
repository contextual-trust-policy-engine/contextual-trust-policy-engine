"""Generate conformance/golden_vectors.json from the checked-in modules.

Run from the repository root with scipy and numpy installed.
"""

from __future__ import annotations

import json
from pathlib import Path

from contextual_trust_policy_engine import stats
from contextual_trust_policy_engine.trust import Outcome, TrustOracle


def main() -> None:
    import numpy as np
    from scipy.stats import binomtest

    wil = []
    for k, n in [(100, 100), (0, 100), (500, 500), (0, 500), (95, 100), (1, 3), (30, 30), (7, 40)]:
        iv = stats.wilson(k, n)
        if n:
            ref = binomtest(k, n).proportion_ci(confidence_level=0.95, method="wilson")
            assert abs(ref.low - iv.low) < 1e-9 and abs(ref.high - iv.high) < 1e-9, (k, n, ref, iv)
        wil.append({"k": k, "n": n, "low": iv.low, "high": iv.high})

    qs = []
    data = [3.1, 9.7, 1.2, 8.8, 4.4, 15.0, 2.2, 7.3, 6.1, 5.5, 12.9]
    for q in [0.0, 0.5, 0.95, 0.99, 1.0]:
        v = stats.quantile(data, q)
        assert abs(v - float(np.quantile(data, q))) < 1e-12
        qs.append({"values": data, "q": q, "value": v})

    tci = stats.mean_t_ci([194.28, 193.92, 196.23, 199.37, 181.90, 194.57, 191.87])
    boot = stats.bootstrap_quantile_ci(data, 0.95, resamples=500, seed=7)

    seqs = {
        "cold_all_benign_10": ["benign"] * 10,
        "warm_benign_40": ["benign"] * 40,
        "mixed_50": (["benign"] * 3 + ["suspicious"]) * 12 + ["malicious", "unknown"],
        "attacker_35": ["benign"] * 20 + ["malicious"] * 15,
    }
    trust = []
    for name, seq in seqs.items():
        o = TrustOracle()
        for i, s in enumerate(seq):
            o.observe("a", Outcome(s), now_s=float(i))
        last = float(len(seq) - 1)
        trust.append(
            {
                "name": name,
                "outcomes": seq,
                "score_now": o.score("a", last),
                "score_after_2h": o.score("a", last + 7200.0),
                "components": o.components("a"),
            }
        )

    out = {
        "ref_version": stats.REF_VERSION,
        "tolerance": 1e-9,
        "wilson": wil,
        "quantile": qs,
        "mean_t_ci": {
            "values": [194.28, 193.92, 196.23, 199.37, 181.90, 194.57, 191.87],
            **tci.as_dict(),
        },
        "bootstrap_quantile_ci": {
            "values": data,
            "q": 0.95,
            "resamples": 500,
            "seed": 7,
            **boot.as_dict(),
        },
        "trust": trust,
    }
    Path(__file__).with_name("golden_vectors.json").write_text(json.dumps(out, indent=2) + "\n")
    print("wrote golden_vectors.json")


if __name__ == "__main__":
    main()
