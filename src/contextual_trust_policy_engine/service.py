"""Starlette service exposing Contextual Trust Policy Engine PDP endpoints."""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .policy import PolicyDecisionPoint


def create_app(pdp: PolicyDecisionPoint | None = None) -> Starlette:
    engine = pdp or PolicyDecisionPoint()

    async def decide(request: Request) -> JSONResponse:
        body = await request.json()
        return JSONResponse(engine.decide(body).as_dict())

    async def check(request: Request) -> JSONResponse:
        body: dict[str, Any] = await request.json()
        allowed = engine.rebac.check(
            str(body.get("subject", "")), str(body.get("object", "")), str(body.get("relation", ""))
        )
        return JSONResponse({"allowed": allowed})

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def metrics(_request: Request) -> Response:
        return PlainTextResponse(engine.metrics_text(), media_type="text/plain; version=0.0.4")

    return Starlette(
        routes=[
            Route("/v1/decide", decide, methods=["POST"]),
            Route("/v1/check", check, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/metrics", metrics, methods=["GET"]),
        ]
    )


app = create_app()
