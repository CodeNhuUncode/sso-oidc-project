import base64, hashlib, hmac, json, secrets, time, urllib.parse
import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from security import CLIENT_ID, PUB_KC, INT_KC, REALM, require_roles

app = FastAPI(title="App 2 - TechCorp Admin")
app.add_middleware(SessionMiddleware, secret_key="admin-secret-2026", session_cookie="app2_session", same_site="lax", https_only=False)

AUTH_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/auth"
LOGOUT_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/logout"
TOKEN_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/token"
CLIENT_SECRET = "app2-secret-key-2026"
REDIRECT_URI = "http://localhost:3002/callback"
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
        return """
        <div style="font-family:Arial;max-width:700px;margin:40px auto;">
            <h2>TechCorp - App 2: Hệ thống Quản trị Nội bộ (Port 3002)</h2>
            <p>Trạng thái: <b>Chưa xác thực cục bộ</b></p>
            <a href="/login"><button style="padding:10px 16px;cursor:pointer;">Đăng nhập / Đồng bộ phiên SSO</button></a>
            <hr><p><a href="http://localhost:3001" target="_blank">Quay lại App 1 Portal (Port 3001)</a></p>
        </div>
        """
    tok = request.session.get("access_token", "")
    roles = u.get("realm_access", {}).get("roles", [])
    return f"""
    <div style="font-family:Arial;max-width:820px;margin:30px auto;">
        <h2>App 2 Admin - Bảng điều khiển &amp; Kiểm thử RBAC / JWT</h2>
        <p><b>Tài khoản SSO:</b> {u.get("preferred_username")} | <b>Roles:</b> {roles} | <b>Audience (aud):</b> {u.get("aud")}</p>
        <p><b>Access Token hiện tại (sống 60s):</b></p>
        <textarea id="t" rows="4" style="width:100%;font-size:12px;">{tok}</textarea>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
            <button type="button" onclick="callApi('/api/reports','GET')" style="padding:8px 12px;cursor:pointer;">1. GET /api/reports (User &amp; Admin)</button>
            <button type="button" onclick="callApi('/api/system-config','POST')" style="padding:8px 12px;cursor:pointer;">2. POST /api/system-config (Chỉ Admin)</button>
            <button type="button" onclick="callApi('/api/audit-logs','GET')" style="padding:8px 12px;cursor:pointer;">3. GET /api/audit-logs (Chỉ Admin)</button>
            <a href="/logout"><button type="button" style="padding:8px 12px;background:#d9534f;color:white;border:none;cursor:pointer;">Đăng xuất (SLO)</button></a>
        </div>
        <pre id="o" style="background:#1e1e1e;color:#d4d4d4;padding:14px;margin-top:15px;border-radius:6px;overflow-x:auto;">Nhấn nút API phía trên để kiểm tra phản hồi...</pre>
        <script>
        async function callApi(url, method) {{
            const out = document.getElementById("o");
            out.textContent = "Đang gọi " + method + " " + url + "...";
            try {{
                const token = document.getElementById("t").value.trim();
                const res = await fetch(url, {{
                    method: method,
                    headers: {{ "Authorization": "Bearer " + token }}
                }});
                const text = await res.text();
                let formatted = text;
                try {{ formatted = JSON.stringify(JSON.parse(text), null, 2); }} catch (e) {{}}
                out.textContent = "HTTP Status: " + res.status + " " + res.statusText + "\n" + formatted;
            }} catch (err) {{
                out.textContent = "Lỗi kết nối: " + err;
            }}
        }}
        </script>
    </div>
    """

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
async def get_reports(claims: dict = Depends(require_roles(["role_user", "role_admin"]))):
    return {"status": "200 OK", "endpoint": "/api/reports", "user": claims.get("preferred_username"), "roles": claims.get("realm_access", {}).get("roles"), "data": ["Bao cao tai chinh Q3", "Bao cao van hanh TechCorp"]}

@app.post("/api/system-config")
async def update_system_config(claims: dict = Depends(require_roles(["role_admin"]))):
    return {"status": "200 OK", "endpoint": "/api/system-config", "admin": claims.get("preferred_username"), "message": "Cap nhat cau hinh bao mat he thong thanh cong!"}

@app.get("/api/audit-logs")
async def get_audit_logs(claims: dict = Depends(require_roles(["role_admin"]))):
    return {"status": "200 OK", "endpoint": "/api/audit-logs", "admin": claims.get("preferred_username"), "logs": [{"event": "SSO_LOGIN_PKCE", "user": "nv01", "client": "app1-portal"}]}
