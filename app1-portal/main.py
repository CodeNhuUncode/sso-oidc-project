"""
app 1 - portal (cong thong tin nhan vien techcorp)
de tai 12: xay dung mo hinh dang nhap tap trung bang openid connect va oauth 2.0
vai tro: nguoi 2 - code app 1 (portal) chay tai cong 3001
tinh nang: dang nhap oidc + pkce (s256), sso cheo ung dung, single logout
"""

import base64
import hashlib
import hmac
import json
import time
import os
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# load cau hinh tu file .env (khong ghi de bien moi truong do docker compose truyen vao)
load_dotenv()

APP_NAME = os.getenv("APP_NAME", "TechCorp - App 1 Portal")
APP_PORT = int(os.getenv("APP_PORT", 3001))
APP2_URL = os.getenv("APP2_URL", "http://localhost:3002")

# tach public url (trinh duyet redirect) va internal url (server-to-server trong docker)
PUBLIC_KEYCLOAK_URL = os.getenv(
    "PUBLIC_KEYCLOAK_URL",
    os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
)
INTERNAL_KEYCLOAK_URL = os.getenv(
    "INTERNAL_KEYCLOAK_URL",
    os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
)
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "enterprise-sso")

KEYCLOAK_ISSUER = f"{PUBLIC_KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
AUTHORIZATION_ENDPOINT = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/auth"
END_SESSION_ENDPOINT = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/logout"
TOKEN_ENDPOINT = f"{INTERNAL_KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
USERINFO_ENDPOINT = f"{INTERNAL_KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
JWKS_URI = f"{INTERNAL_KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

# thong tin client (khop voi idp-keycloak/realm-export.json)
CLIENT_ID = os.getenv("CLIENT_ID", "app1-portal")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "app1-secret-key-2026")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:3001/callback")

SESSION_SECRET_KEY = os.getenv(
    "SESSION_SECRET_KEY",
    "app1-portal-super-secret-key-change-in-production",
)

# khoi tao ung dung fastapi
app = FastAPI(
    title="sso-oidc-project",
    description="Cong thong tin nhan vien TechCorp - Tich hop SSO qua OpenID Connect va OAuth 2.0",
    version="1.0.0",
)

# cau hinh session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="app1_session",
    max_age=1800,
    same_site="lax",
    https_only=False,
)

# mount thu muc templates cho jinja2
templates = Jinja2Templates(directory="templates")


def generate_pkce_pair() -> tuple[str, str]:
    """
    sinh cap (code_verifier, code_challenge) theo chuan pkce s256 (rfc 7636).
    """
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


STATE_KEY = b"techcorp-hmac-state-2026"


def make_state(verifier: str) -> str:
    raw = json.dumps({"v": verifier, "t": int(time.time())}).encode()
    b64 = base64.urlsafe_b64encode(raw).decode()
    sig = hmac.new(STATE_KEY, b64.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{b64}.{sig}"


def verify_state(state: str) -> str | None:
    if not state or "." not in state:
        return None
    b64, sig = state.rsplit(".", 1)
    expected = hmac.new(STATE_KEY, b64.encode(), hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(b64 + "=="))
    except Exception:
        return None
    return data.get("v") if time.time() - data.get("t", 0) < 600 else None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    trang chu app 1 - portal.
    neu da dang nhap thi chuyen sang /profile, nguoc lai hien thi trang dang nhap.
    """
    user = request.session.get("user")
    if user:
        return RedirectResponse(url="/profile", status_code=302)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "app2_url": APP2_URL,
        },
    )


@app.get("/login")
async def login(request: Request):
    """
    khoi tao luong dang nhap authorization code + pkce (s256).
    """
    code_verifier, code_challenge = generate_pkce_pair()
    state = make_state(code_verifier)

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"

    return RedirectResponse(url=auth_url, status_code=302)


@app.get("/callback")
async def callback(request: Request):
    """
    xu ly callback tu keycloak: kiem tra state, doi code lay token kem code_verifier
    va client_secret, giai ma id_token, luu thong tin user vao session.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        error_description = request.query_params.get("error_description", "")
        return HTMLResponse(
            content=f"<h2>Loi dang nhap</h2><p>{error}: {error_description}</p>",
            status_code=400,
        )

    code_verifier = verify_state(state or "")
    if not code or not code_verifier:
        return HTMLResponse(
            content="<h2>Loi bao mat</h2><p>State HMAC khong hop le, het han hoac thieu authorization code.</p>",
            status_code=403,
        )

    # gui back-channel post request toi keycloak token endpoint
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    if CLIENT_SECRET:
        token_data["client_secret"] = CLIENT_SECRET

    async with httpx.AsyncClient() as client:
        token_response = await client.post(TOKEN_ENDPOINT, data=token_data)

    if token_response.status_code != 200:
        return HTMLResponse(
            content=f"<h2>Loi doi token</h2><pre>{token_response.text}</pre>",
            status_code=400,
        )

    tokens = token_response.json()
    id_token_raw = tokens.get("id_token")
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    # giai ma id_token va access_token bang pyjwt de lay claims va roles
    try:
        id_token_payload = jwt.decode(
            id_token_raw,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
        access_token_payload = jwt.decode(
            access_token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
    except jwt.exceptions.DecodeError as e:
        return HTMLResponse(
            content=f"<h2>Loi giai ma token</h2><p>{str(e)}</p>",
            status_code=400,
        )

    roles = (
        id_token_payload.get("realm_access", {}).get("roles")
        or access_token_payload.get("realm_access", {}).get("roles")
        or []
    )

    request.session["user"] = {
        "sub": id_token_payload.get("sub"),
        "preferred_username": id_token_payload.get("preferred_username"),
        "name": id_token_payload.get("name", id_token_payload.get("preferred_username")),
        "email": id_token_payload.get("email", ""),
        "email_verified": id_token_payload.get("email_verified", False),
        "roles": roles,
    }
    request.session["access_token"] = access_token
    request.session["id_token"] = id_token_raw
    request.session["refresh_token"] = refresh_token

    request.session.pop("code_verifier", None)
    request.session.pop("oauth_state", None)

    return RedirectResponse(url="/profile", status_code=302)


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    """
    hien thi trang ho so ca nhan nhan vien va cac chuc nang kiem thu sso / api.
    """
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)

    access_token = request.session.get("access_token", "")

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "app2_url": APP2_URL,
            "user": user,
            "access_token": access_token,
        },
    )


@app.get("/logout")
async def logout(request: Request):
    """
    thuc hien single logout (slo): xoa session cuc bo va goi end_session_endpoint
    cua keycloak de huy phien sso toan cuc tren ca app 1 va app 2.
    """
    id_token = request.session.get("id_token")
    request.session.clear()

    logout_params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": f"http://localhost:{APP_PORT}/",
    }
    if id_token:
        logout_params["id_token_hint"] = id_token

    logout_url = f"{END_SESSION_ENDPOINT}?{urlencode(logout_params)}"
    return RedirectResponse(url=logout_url, status_code=302)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=APP_PORT,
        reload=True,
    )
