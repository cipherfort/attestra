# SPDX-License-Identifier: Apache-2.0
"""Browser sign-in routes (BFF, ADR-014). Mounted at /auth only when AAP_AUTH_MODE=oidc."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from aap.api.auth import (
    ABSOLUTE,
    SESSION_COOKIE,
    create_session,
    end_session,
    oidc_client,
    safe_return_to,
    session_principal,
    start_login,
    take_login,
)
from aap.api.oidc import OidcError, challenge_for

router = APIRouter(prefix="/auth", include_in_schema=False)


def _engine(request: Request) -> Any:
    return request.app.state.engine


@router.get("/login")
def login(request: Request, return_to: str = "/") -> RedirectResponse:
    client = oidc_client(request)
    state, nonce, verifier = start_login(_engine(request), safe_return_to(return_to))
    return RedirectResponse(client.authorization_url(state, nonce, challenge_for(verifier)), status_code=302)


@router.get("/callback")
def callback(request: Request, state: str = "", code: str = "", error: str = "") -> RedirectResponse:
    if error:
        raise HTTPException(401, f"sign-in was not completed ({error[:64]})")
    if not state or not code:
        raise HTTPException(400, "missing state or code")
    client = oidc_client(request)
    try:
        nonce, verifier, return_to = take_login(_engine(request), state)
        tokens = client.exchange_code(code, verifier)
        claims = client.validate_id_token(str(tokens.get("id_token", "")), nonce)
        session = create_session(_engine(request), claims, link_by_email=bool(client.s.tenant_id))
    except OidcError as e:
        raise HTTPException(401, f"sign-in failed: {e}") from e
    response = RedirectResponse(return_to, status_code=302)
    response.set_cookie(
        SESSION_COOKIE,
        session.cookie_value,
        max_age=int(ABSOLUTE.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session_principal(_engine(request), cookie, "POST", request.headers.get("X-AAP-CSRF"))  # CSRF-checked
        end_session(_engine(request), cookie)
    try:
        end_url = oidc_client(request).end_session_url()
    except (OidcError, HTTPException):
        end_url = None
    response = JSONResponse({"logged_out": True, "end_session_url": end_url})
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response
