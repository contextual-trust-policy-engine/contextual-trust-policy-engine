from __future__ import annotations

import csv
import hashlib
import itertools
import json
import platform
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

from starlette.testclient import TestClient

from contextual_trust_policy_engine.abac import AbacEngine
from contextual_trust_policy_engine.context import ContextAggregator, ToolMeta
from contextual_trust_policy_engine.policy import ContextualTrustDefense, PolicyDecisionPoint
from contextual_trust_policy_engine.rebac import RebacEngine, TupleStore
from contextual_trust_policy_engine.service import create_app
from contextual_trust_policy_engine.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson
from contextual_trust_policy_engine.trust import Outcome, TrustOracle


def _traces_path(*parts: str) -> str | None:
    path = Path("../zero-trust-agent-benchmark/traces", *parts)
    return str(path) if path.exists() else None


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-local"


def request(history: list[str] | None = None) -> dict[str, Any]:
    return {
        "trace_id": "bench",
        "step": 0,
        "agent": {
            "agent_id": "bench-agent",
            "spiffe_id": "spiffe://acme.test/agent/bench-agent",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": history or ["benign"] * 40,
            "scopes": ["net:read"],
        },
        "tool": "http.get",
        "args": {"url": "https://docs.acme.test"},
        "context": {"origin": "user", "content": "ok", "reasoning_tokens": 8},
    }


def _abac_engine(rule_count: int) -> AbacEngine:
    rules: list[dict[str, Any]] = [
        {
            "id": f"deny_never_{i}",
            "effect": "deny",
            "tools": [f"never.{i}"],
            "conditions": [{"field": "tool", "eq": f"never.{i}"}],
        }
        for i in range(max(0, rule_count - 1))
    ]
    rules.append(
        {
            "id": "allow_authenticated",
            "effect": "allow",
            "tools": ["http.get"],
            "conditions": [
                {"field": "svid_valid", "eq": True},
                {"field": "attestation_valid", "eq": True},
            ],
        }
    )
    return AbacEngine.from_dicts(rules)


def _pdp_for_rules(rule_count: int) -> PolicyDecisionPoint:
    catalog = {
        "http.get": ToolMeta("low", ("net:read",), {}, True),
        "*": ToolMeta("critical", (), {}, False),
    }
    return PolicyDecisionPoint(
        aggregator=ContextAggregator(tool_catalog=catalog, allowlist=("acme.test",)),
        abac=_abac_engine(rule_count),
    )


def _latencies_for_rules(rule_count: int, trials: int) -> list[float]:
    pdp = _pdp_for_rules(rule_count)
    req = request()
    values: list[float] = []
    for _ in range(trials):
        start = time.perf_counter()
        pdp.decide(req)
        values.append((time.perf_counter() - start) * 1000.0)
    return values


def _http_latencies_for_rules(rule_count: int, trials: int) -> list[float]:
    req = request()
    values: list[float] = []
    with TestClient(create_app(_pdp_for_rules(rule_count))) as client:
        for _ in range(trials):
            start = time.perf_counter()
            response = client.post("/v1/decide", json=req)
            response.raise_for_status()
            values.append((time.perf_counter() - start) * 1000.0)
    return values


def _tuples(tuple_count: int) -> Iterable[str]:
    unrelated = (f"doc:{i}#read@user:u{i}" for i in range(max(0, tuple_count - 1)))
    return itertools.chain(unrelated, ("doc:target#read@user:target",))


def _rebac_latencies(tuple_count: int, trials: int) -> list[float]:
    rebac = RebacEngine(TupleStore(_tuples(tuple_count)))
    values: list[float] = []
    for _ in range(trials):
        start = time.perf_counter()
        assert rebac.check("user:target", "doc:target", "read")
        values.append((time.perf_counter() - start) * 1000.0)
    return values


def _http_rebac_latencies(tuple_count: int, trials: int) -> list[float]:
    rebac = RebacEngine(TupleStore(_tuples(tuple_count)))
    pdp = PolicyDecisionPoint(rebac=rebac)
    body = {"subject": "user:target", "object": "doc:target", "relation": "read"}
    values: list[float] = []
    with TestClient(create_app(pdp)) as client:
        for _ in range(trials):
            start = time.perf_counter()
            response = client.post("/v1/check", json=body)
            response.raise_for_status()
            assert response.json()["allowed"]
            values.append((time.perf_counter() - start) * 1000.0)
    return values


def _lat_summary(values: list[float]) -> dict[str, Any]:
    return {
        "mean_ms": mean_t_ci(values).as_dict(),
        "p50_ms": quantile(values, 0.5),
        "p95_ms": bootstrap_quantile_ci(values, 0.95, resamples=500, seed=1).as_dict(),
        "p99_ms": bootstrap_quantile_ci(values, 0.99, resamples=500, seed=2).as_dict(),
    }


def _trust_histories(split: str = "test") -> list[list[str]]:
    from zero_trust_agent_benchmark import load_traces

    return [list(trace.agent.trust_history) for trace in load_traces(split, _traces_path())]


def _score_from_components(method: str, oracle: TrustOracle, agent_id: str, now_s: float) -> float:
    comps = oracle.components(agent_id)
    if method == "wilson":
        return comps["wilson_lb"]
    if method == "ewma":
        return comps["ewma"]
    if method == "dirichlet":
        return comps["dirichlet_benign"]
    return oracle.score(agent_id, now_s)


def _trust_samples(histories: list[list[str]]) -> list[dict[str, float]]:
    samples: list[dict[str, float]] = []
    for history_idx, seq in enumerate(histories):
        agent_id = f"agent-{history_idx}"
        oracle = TrustOracle()
        for i, outcome in enumerate(seq):
            oracle.observe(agent_id, outcome, float(i))
            comps = oracle.components(agent_id)
            samples.append(
                {
                    "truth": 1.0 if outcome == Outcome.BENIGN else 0.0,
                    "wilson": comps["wilson_lb"],
                    "ewma": comps["ewma"],
                    "dirichlet": comps["dirichlet_benign"],
                    "hybrid": oracle.score(agent_id, float(i)),
                }
            )
    return samples


def _brier(samples: list[dict[str, float]], method: str) -> float:
    return sum((sample[method] - sample["truth"]) ** 2 for sample in samples) / len(samples)


def _reliability_curve(samples: list[dict[str, float]], method: str) -> list[dict[str, Any]]:
    bins: list[list[dict[str, float]]] = [[] for _ in range(10)]
    for sample in samples:
        idx = min(9, int(sample[method] * 10.0))
        bins[idx].append(sample)
    rows: list[dict[str, Any]] = []
    for idx, bucket in enumerate(bins):
        if not bucket:
            continue
        rows.append(
            {
                "bin_low": idx / 10.0,
                "bin_high": (idx + 1) / 10.0,
                "count": len(bucket),
                "mean_score": mean(sample[method] for sample in bucket),
                "observed_benign_rate": mean(sample["truth"] for sample in bucket),
            }
        )
    return rows


def _fit_trust_weights(samples: list[dict[str, float]]) -> dict[str, Any]:
    best: dict[str, Any] | None = None
    grid = [i / 20.0 for i in range(21)]
    for w_wilson in grid:
        for w_ewma in grid:
            w_dirichlet = round(1.0 - w_wilson - w_ewma, 10)
            if w_dirichlet < 0.0:
                continue
            total = 0.0
            for sample in samples:
                score = (
                    w_wilson * sample["wilson"]
                    + w_ewma * sample["ewma"]
                    + w_dirichlet * sample["dirichlet"]
                )
                total += (score - sample["truth"]) ** 2
            brier = total / len(samples)
            if best is None or brier < best["brier"]:
                best = {
                    "weights": {
                        "wilson": w_wilson,
                        "ewma": w_ewma,
                        "dirichlet": w_dirichlet,
                    },
                    "brier": brier,
                }
    assert best is not None
    fixed = {
        "wilson": 0.4,
        "ewma": 0.0,
        "dirichlet": 0.6,
    }
    fixed_brier = sum(
        (
            fixed["wilson"] * sample["wilson"]
            + fixed["ewma"] * sample["ewma"]
            + fixed["dirichlet"] * sample["dirichlet"]
            - sample["truth"]
        )
        ** 2
        for sample in samples
    ) / len(samples)
    return {
        "grid_step": 0.05,
        "best": best,
        "fixed_warm_path": {"weights": fixed, "brier": fixed_brier},
    }


def _artifact_digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _benchmark_metadata() -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    try:
        from zero_trust_agent_benchmark.generator import DATASET_VERSION
        from zero_trust_agent_benchmark.profile import profile

        metadata["dataset_version"] = DATASET_VERSION
        metadata["profile_dataset_version"] = profile().get("dataset_version")
    except Exception as exc:
        metadata["dataset_version_error"] = exc.__class__.__name__
    test_path = Path("../zero-trust-agent-benchmark/traces/test.jsonl")
    digest = _artifact_digest(test_path)
    if digest:
        metadata["test_jsonl_sha256"] = digest
    return metadata


def _rate_row(k: int, n: int) -> dict[str, Any]:
    row: dict[str, Any] = {"count": k, "n": n}
    row.update(wilson(k, n).as_dict())
    return row


def _false_positive_breakdown(report: Any, traces: Iterable[Any]) -> dict[str, Any]:
    benign_ids = {trace.trace_id for trace in traces if trace.label == "benign"}
    by_component: dict[str, set[str]] = defaultdict(set)
    by_reason: dict[str, set[str]] = defaultdict(set)
    for step in report.step_results:
        if step.trace_id in benign_ids and step.decision == "deny":
            by_component[step.component].add(step.trace_id)
            by_reason[step.reason].add(step.trace_id)
    return {
        "denominator": "benign_traces",
        "by_component": {
            key: _rate_row(len(value), len(benign_ids))
            for key, value in sorted(by_component.items())
        },
        "by_reason": {
            key: _rate_row(len(value), len(benign_ids))
            for key, value in sorted(by_reason.items(), key=lambda item: (-len(item[1]), item[0]))
        },
    }


def _with_progress(label: str, thunk: Callable[[], Any]) -> Any:
    print(f"{utc_now()} {label}", flush=True)
    return thunk()


def _manifest(out: Path) -> None:
    rows = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}"
        for p in sorted(x for x in out.rglob("*") if x.is_file() and x.name != "manifest.sha256")
    ]
    (out / "manifest.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    import shutil

    trials = 100
    out = Path("results") / run_id()
    (out / "per-trial-logs").mkdir(parents=True)
    rows: list[dict[str, Any]] = []
    for trial in range(1, trials + 1):
        ts = utc_now()
        lat = _latencies_for_rules(100, 1)[0]
        rows.append(
            {"trial": trial, "timestamp_utc": ts, "kind": "pdp", "size": 100, "latency_ms": lat}
        )
        (out / "per-trial-logs" / f"trial-{trial:03d}.json").write_text(
            json.dumps({"trial": trial, "timestamp_utc": ts, "pdp_latency_ms": lat}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["trial", "timestamp_utc", "kind", "size", "latency_ms"]
        )
        writer.writeheader()
        writer.writerows(rows)
    abac = {
        "in_process": {
            str(n): _with_progress(
                f"ABAC in-process rules={n}",
                lambda n=n: _lat_summary(_latencies_for_rules(n, 100)),
            )
            for n in (10, 100, 1000, 10000)
        },
        "http": {
            str(n): _with_progress(
                f"ABAC HTTP rules={n}",
                lambda n=n: _lat_summary(_http_latencies_for_rules(n, 100)),
            )
            for n in (10, 100, 1000, 10000)
        },
    }
    rebac = {
        "in_process": {
            str(n): _with_progress(
                f"ReBAC in-process tuples={n}",
                lambda n=n: _lat_summary(_rebac_latencies(n, 100)),
            )
            for n in (1000, 10000, 100000, 1000000)
        },
        "http": {
            str(n): _with_progress(
                f"ReBAC HTTP tuples={n}",
                lambda n=n: _lat_summary(_http_rebac_latencies(n, 100)),
            )
            for n in (1000, 10000, 100000, 1000000)
        },
    }
    trust_histories = _trust_histories("dev")
    trust_samples = _trust_samples(trust_histories)
    trust_reliability = {
        "source": "zero_trust_agent_benchmark_dev_trust_histories",
        "history_count": len(trust_histories),
        "outcome_count": len(trust_samples),
        "brier": {
            name: _brier(trust_samples, name) for name in ("wilson", "ewma", "dirichlet", "hybrid")
        },
        "reliability_curve": {
            name: _reliability_curve(trust_samples, name)
            for name in ("wilson", "ewma", "dirichlet", "hybrid")
        },
        "fitted_weight_sensitivity": _fit_trust_weights(trust_samples),
    }
    try:
        from zero_trust_agent_benchmark import evaluate, load_traces

        traces = list(load_traces("test", _traces_path()))
        report = evaluate(ContextualTrustDefense(), traces)
        benchmark: dict[str, Any] = report.to_dict()
        benchmark["false_positive_breakdown"] = _false_positive_breakdown(report, traces)
        benchmark["available"] = True
    except Exception as exc:
        benchmark = {"available": False, "reason": exc.__class__.__name__}
    benchmark.update(_benchmark_metadata())
    summary = {
        "run": {"timestamp_utc": utc_now(), "trials": trials},
        "pdp_latency_by_rules": abac,
        "rebac_latency_by_tuples": rebac,
        "trust_reliability": trust_reliability,
        "zero_trust_agent_benchmark": benchmark,
        "hypotheses": {
            "H1": "PASS"
            if abac["in_process"]["10000"]["p50_ms"] <= 3
            and abac["in_process"]["10000"]["p95_ms"]["point"] <= 8
            and abac["in_process"]["10000"]["p99_ms"]["point"] <= 15
            else "FAIL",
            "H2": "PASS"
            if trust_reliability["brier"]["hybrid"]
            < min(trust_reliability["brier"][m] for m in ("wilson", "ewma", "dirichlet"))
            else "FAIL",
            "H3": "PASS"
            if rebac["in_process"]["1000000"]["p99_ms"]["point"]
            < 2 * rebac["in_process"]["1000"]["p99_ms"]["point"] + 1
            else "FAIL",
            "H4": "PASS"
            if benchmark.get("metrics", {}).get("block_rate", {}).get("point") == 1.0
            and (
                benchmark.get("metrics", {}).get("false_positive_rate", {}).get("point", 1.0)
                <= 0.05
            )
            and benchmark.get("metrics", {}).get("leak_count") == 0
            else "FAIL"
            if benchmark.get("available")
            else "INCONCLUSIVE",
        },
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    env: dict[str, Any] = {
        "python": sys.version,
        "platform": platform.platform(),
        "latency_row_mean_ms": mean(float(r["latency_ms"]) for r in rows),
    }
    try:
        env["git_sha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        env["git_sha"] = None
    (out / "env.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _manifest(out)
    latest = Path("results") / "reference-run"
    prior_tlc = (latest / "tlc.json").read_bytes() if (latest / "tlc.json").exists() else None
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(out, latest)
    if prior_tlc is not None:
        (latest / "tlc.json").write_bytes(prior_tlc)
        _manifest(latest)
    print(json.dumps({"out": str(out), "hypotheses": summary["hypotheses"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
