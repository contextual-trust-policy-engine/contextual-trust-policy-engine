"""Contextual Trust Policy Engine command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from .policy import PolicyDecisionPoint, default_defense
from .service import create_app


def _serve(args: argparse.Namespace) -> int:
    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


def _decide(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.request).read_text(encoding="utf-8")) if args.request else {}
    print(json.dumps(default_defense.decide(data), indent=2))
    return 0


def _bench(args: argparse.Namespace) -> int:
    pdp = PolicyDecisionPoint()
    req = {
        "step": 0,
        "agent": {
            "agent_id": "agent-cli",
            "spiffe_id": "spiffe://acme.test/agent/agent-cli",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"] * 40,
            "scopes": ["net:read"],
        },
        "tool": "http.get",
        "args": {"url": "https://docs.acme.test"},
        "context": {"origin": "user", "content": "read", "reasoning_tokens": 10},
    }
    for _ in range(args.repeats):
        pdp.decide(req)
    print(pdp.metrics_text())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="contextual_trust_policy_engine")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=18100)
    serve.set_defaults(func=_serve)
    decide = sub.add_parser("decide")
    decide.add_argument("request", nargs="?")
    decide.set_defaults(func=_decide)
    bench = sub.add_parser("bench")
    bench.add_argument("--repeats", type=int, default=1000)
    bench.set_defaults(func=_bench)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
