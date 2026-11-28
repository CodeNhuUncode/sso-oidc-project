import base64, hashlib, json, os, secrets, urllib.parse
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt, JWTError
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="App 2 - TechCorp Admin")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://localhost:3002"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key="admin-secret-2026", session_cookie="app2_session")

PUB_KC = os.getenv("PUBLIC_KEYCLOAK_URL", "http://localhost:8080")
INT_KC = os.getenv("INTERNAL_KEYCLOAK_URL", "http://localhost:8080")
REALM = "enterprise-sso"
ISSUER = f"{PUB_KC}/realms/{REALM}"
AUTH_URL = f"{ISSUER}/protocol/openid-connect/auth"
LOGOUT_URL = f"{ISSUER}/protocol/openid-connect/logout"
TOKEN_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/token"
JWKS_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/certs"
CLIENT_ID, CLIENT_SECRET, REDIRECT_URI = "app2-admin", "app2-secret-key-2026", "http://localhost:3002/callback"
_jwks = None

async def verify_token(token: str):
    global _jwks
    if not _jwks:
        async with httpx.AsyncClient() as c:
            _jwks = (await c.get(JWKS_URL)).json()
    try:
        return jwt.decode(token, _jwks, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token khong hop le hoac het han (60s): {e}")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = request.session.get("user")
    if not u:
        return '<h2>TechCorp - App 2 Admin (3002)</h2><a href="/login"><button>Dang nhap / Kiem tra SSO</button></a>'
    tok = request.session.get("access_token", "")
    return f'<h2>App 2 Admin Dashboard</h2><p>User: <b>{u.get("preferred_username")}</b> | Roles: <b>{u.get("realm_access", {}).get("roles")}</b> | Aud: <b>{u.get("aud")}</b></p><textarea id="t" rows="4" cols="80">{tok}</textarea><br><br><button onclick="call(\'/api/reports\',\'GET\')">GET /api/reports</button> <button onclick="call(\'/api/system-config\',\'POST\')">POST /api/system-config (Admin)</button> <a href="/logout"><button>Dang xuat</button></a><pre id="o"></pre><script>async function call(u,m){{let r=await fetch(u,{{method:m,headers:{{\'Authorization\':\'Bearer \'+document.getElementById(\'t\').value.trim()}}}});document.getElementById(\'o\').textContent=\'HTTP \'+r.status+\'\\n\'+JSON.stringify(await r.json(),null,2);}}</script>'

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
    tokens = res.json()
    request.session["access_token"] = tokens["access_token"]
    request.session["id_token"] = tokens.get("id_token", "")
    request.session["user"] = json.loads(base64.urlsafe_b64decode(tokens["access_token"].split(".")[1] + "=="))
    return RedirectResponse("/")

@app.get("/logout")
def logout(request: Request):
    idt = request.session.get("id_token", "")
    request.session.clear()
    q = {"client_id": CLIENT_ID, "post_logout_redirect_uri": "http://localhost:3002/"}
    if idt:
        q["id_token_hint"] = idt
    return RedirectResponse(f"{LOGOUT_URL}?{urllib.parse.urlencode(q)}")

@app.get("/api/reports")
async def reports(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thieu Bearer Token")
    c = await verify_token(authorization.split(" ")[1])
    return {"status": "OK", "user": c.get("preferred_username"), "data": "Bao cao doanh thu TechCorp"}

@app.post("/api/system-config")
async def config(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thieu Bearer Token")
    c = await verify_token(authorization.split(" ")[1])
    if "role_admin" not in c.get("realm_access", {}).get("roles", []):
        raise HTTPException(status_code=403, detail="403 Forbidden: Can quyen role_admin")
    return {"status": "OK", "message": "Da cap nhat cau hinh he thong"}
