import base64, hashlib, json, os, secrets, urllib.parse
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="App 1 - TechCorp Portal")
app.add_middleware(SessionMiddleware, secret_key="portal-secret-2026", session_cookie="app1_session")

PUB_KC = os.getenv("PUBLIC_KEYCLOAK_URL", "http://localhost:8080")
INT_KC = os.getenv("INTERNAL_KEYCLOAK_URL", "http://localhost:8080")
REALM = "enterprise-sso"
AUTH_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/auth"
LOGOUT_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/logout"
TOKEN_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/token"
CLIENT_ID, CLIENT_SECRET, REDIRECT_URI = "app1-portal", "app1-secret-key-2026", "http://localhost:3001/callback"

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/profile")
    return '<h2>TechCorp - App 1 Portal (3001)</h2><a href="/login"><button>Dang nhap SSO (PKCE S256)</button></a> | <a href="http://localhost:3002" target="_blank">Mo App 2</a>'

@app.get("/login")
def login(request: Request):
    v = secrets.token_urlsafe(64)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    s = secrets.token_urlsafe(24)
    request.session["verifier"], request.session["state"] = v, s
    q = urllib.parse.urlencode({"client_id": CLIENT_ID, "response_type": "code", "scope": "openid profile email roles", "redirect_uri": REDIRECT_URI, "state": s, "code_challenge": c, "code_challenge_method": "S256"})
    return RedirectResponse(f"{AUTH_URL}?{q}")

@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if not code or state != request.session.get("state"):
        return HTMLResponse("Loi state!", status_code=400)
    async with httpx.AsyncClient() as client:
        res = await client.post(TOKEN_URL, data={"grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code, "redirect_uri": REDIRECT_URI, "code_verifier": request.session.get("verifier", "")})
    if res.status_code != 200:
        return HTMLResponse(f"Loi Token: {res.text}", status_code=400)
    tokens = res.json()
    request.session["tokens"] = tokens
    request.session["user"] = json.loads(base64.urlsafe_b64decode(tokens["access_token"].split(".")[1] + "=="))
    return RedirectResponse("/profile")

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    u, t = request.session.get("user"), request.session.get("tokens")
    if not u:
        return RedirectResponse("/")
    return f'<h2>App 1 Profile</h2><p>User: <b>{u.get("preferred_username")}</b> | Roles: <b>{u.get("realm_access", {}).get("roles")}</b></p><textarea rows="4" cols="80">{t.get("access_token")}</textarea><br><br><a href="http://localhost:3002" target="_blank"><button>Sang App 2 (Test SSO)</button></a> <a href="/logout"><button>Dang xuat tap trung (SLO)</button></a>'

@app.get("/logout")
def logout(request: Request):
    idt = request.session.get("tokens", {}).get("id_token", "")
    request.session.clear()
    q = {"client_id": CLIENT_ID, "post_logout_redirect_uri": "http://localhost:3001/"}
    if idt:
        q["id_token_hint"] = idt
    return RedirectResponse(f"{LOGOUT_URL}?{urllib.parse.urlencode(q)}")
