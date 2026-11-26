import base64, hashlib, hmac, json, os, secrets, time, urllib.parse
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="App 1 - TechCorp Portal")
app.add_middleware(SessionMiddleware, secret_key="portal-secret-2026", session_cookie="app1_session", same_site="lax", https_only=False)

PUB_KC = os.getenv("PUBLIC_KEYCLOAK_URL", "http://localhost:8080")
INT_KC = os.getenv("INTERNAL_KEYCLOAK_URL", "http://localhost:8080")
REALM = "enterprise-sso"
AUTH_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/auth"
LOGOUT_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/logout"
TOKEN_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/token"
CLIENT_ID, CLIENT_SECRET = "app1-portal", "app1-secret-key-2026"
REDIRECT_URI = "http://localhost:3001/callback"
STATE_KEY = b"techcorp-hmac-state-2026"

def make_state(verifier: str) -> str:
    raw = json.dumps({"v": verifier, "t": int(time.time())}).encode()
    b64 = base64.urlsafe_b64encode(raw).decode()
    sig = hmac.new(STATE_KEY, b64.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{b64}.{sig}"

def verify_state(state: str) -> str | None:
    if "." not in state:
        return None
    b64, sig = state.rsplit(".", 1)
    expected = hmac.new(STATE_KEY, b64.encode(), hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(expected, sig):
        return None
    data = json.loads(base64.urlsafe_b64decode(b64 + "=="))
    return data.get("v") if time.time() - data.get("t", 0) < 600 else None

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = request.session.get("user")
    if not u:
        return '<h2>TechCorp - App 1: Cổng thông tin nhân viên (Port 3001)</h2><a href="/login"><button style="padding:10px 16px;">Đăng nhập SSO (PKCE S256)</button></a>'
    return f'<h2>Xin chào, {u.get("preferred_username")}!</h2><p>Roles: {u.get("realm_access", {}).get("roles")}</p><a href="/profile">Xem Token</a> | <a href="http://localhost:3002" target="_blank">Sang App 2 (Test SSO)</a> | <a href="/logout">Đăng xuất tập trung (SLO)</a>'

@app.get("/login")
def login():
    v = secrets.token_urlsafe(48)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    s = make_state(v)
    q = urllib.parse.urlencode({"client_id": CLIENT_ID, "response_type": "code", "scope": "openid", "redirect_uri": REDIRECT_URI, "state": s, "code_challenge": c, "code_challenge_method": "S256"})
    return RedirectResponse(f"{AUTH_URL}?{q}")

@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return HTMLResponse(f"<h3>Keycloak từ chối: {error}</h3><p>{error_description}</p>", status_code=400)
    verifier = verify_state(state)
    if not code or not verifier:
        return HTMLResponse(f"<h3>Lỗi xác thực state! (code={bool(code)}, state_len={len(state)})</h3>", status_code=400)
    async with httpx.AsyncClient() as client:
        res = await client.post(TOKEN_URL, data={"grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": verifier})
    if res.status_code != 200:
        return HTMLResponse(f"<h3>Lỗi đổi Token: {res.text}</h3>", status_code=400)
    t = res.json()
    request.session["access_token"], request.session["id_token"] = t["access_token"], t.get("id_token", "")
    request.session["user"] = json.loads(base64.urlsafe_b64decode(t["access_token"].split(".")[1] + "=="))
    return RedirectResponse("/")

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    u = request.session.get("user")
    if not u:
        return RedirectResponse("/")
    return f'<h3>Hồ sơ OIDC Claims</h3><pre>{json.dumps(u, indent=2, ensure_ascii=False)}</pre><p><b>Access Token:</b></p><textarea rows="5" cols="95">{request.session.get("access_token")}</textarea><br><br><a href="/">Quay lại</a>'

@app.get("/logout")
def logout(request: Request):
    idt = request.session.get("id_token", "")
    request.session.clear()
    q = {"client_id": CLIENT_ID, "post_logout_redirect_uri": "http://localhost:3001/"}
    if idt:
        q["id_token_hint"] = idt
    return RedirectResponse(f"{LOGOUT_URL}?{urllib.parse.urlencode(q)}")
