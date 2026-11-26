import base64, hashlib, json, os, secrets, urllib.parse
import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from security import CLIENT_ID, PUB_KC, INT_KC, REALM, require_roles

app = FastAPI(title="App 2 - TechCorp Admin")
app.add_middleware(SessionMiddleware, secret_key="admin-secret-2026", session_cookie="app2_session")

AUTH_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/auth"
LOGOUT_URL = f"{PUB_KC}/realms/{REALM}/protocol/openid-connect/logout"
TOKEN_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/token"
CLIENT_SECRET = "app2-secret-key-2026"
REDIRECT_URI = "http://localhost:3002/callback"

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = request.session.get("user")
    if not u:
        return """
        <div style="font-family: Arial; max-width: 700px; margin: 40px auto;">
            <h2>TechCorp - App 2: Hệ thống Quản trị Nội bộ (Port 3002)</h2>
            <p>Trạng thái: <b>Chưa xác thực cục bộ</b></p>
            <a href="/login"><button style="padding:10px 16px; cursor:pointer;">Đăng nhập / Đồng bộ phiên SSO</button></a>
            <hr><p><a href="http://localhost:3001" target="_blank">Quay lại App 1 Portal (Port 3001)</a></p>
        </div>
        """
    tok = request.session.get("access_token", "")
    roles = u.get("realm_access", {}).get("roles", [])
    return f"""
    <div style="font-family: Arial; max-width: 820px; margin: 30px auto;">
        <h2>App 2 Admin - Bảng điều khiển & Kiểm thử RBAC / JWT</h2>
        <p><b>Tài khoản SSO:</b> {u.get('preferred_username')} | <b>Roles:</b> {roles} | <b>Audience (aud):</b> {u.get('aud')}</p>
        <p><b>Access Token hiện tại (sống 60s - có thể dán Token của App 1 vào đây để test lỗi Audience Confusion):</b></p>
        <textarea id="t" rows="4" style="width:100%; font-size:12px;">{tok}</textarea>
        <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
            <button onclick="callApi('/api/reports','GET')" style="padding:8px 12px;">1. GET /api/reports (User & Admin)</button>
            <button onclick="callApi('/api/system-config','POST')" style="padding:8px 12px;">2. POST /api/system-config (Chỉ Admin)</button>
            <button onclick="callApi('/api/audit-logs','GET')" style="padding:8px 12px;">3. GET /api/audit-logs (Chỉ Admin)</button>
            <a href="/logout"><button style="padding:8px 12px; background:#d9534f; color:white; border:none;">Đăng xuất (SLO)</button></a>
        </div>
        <pre id="o" style="background:#1e1e1e; color:#d4d4d4; padding:14px; margin-top:15px; border-radius:6px; overflow-x:auto;">Nhấn nút API phía trên để kiểm tra phản hồi...</pre>
        <script>
        async function callApi(url, method) {{
            const token = document.getElementById('t').value.trim();
            const res = await fetch(url, {{
                method: method,
                headers: {{ 'Authorization': 'Bearer ' + token }}
            }});
            const body = await res.json();
            document.getElementById('o').textContent = 'HTTP Status: ' + res.status + ' ' + res.statusText + '\\n' + JSON.stringify(body, null, 2);
        }}
        </script>
    </div>
    """

@app.get("/login")
def login(request: Request):
    v = secrets.token_urlsafe(64)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    s = secrets.token_urlsafe(24)
    request.session["verifier"], request.session["state"] = v, s
    q = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "response_type": "code",
        "scope": "openid profile email roles", "redirect_uri": REDIRECT_URI,
        "state": s, "code_challenge": c, "code_challenge_method": "S256"
    })
    return RedirectResponse(f"{AUTH_URL}?{q}")

@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if not code or state != request.session.get("state"):
        return HTMLResponse("<h3>Lỗi xác thực state!</h3>", status_code=400)
    async with httpx.AsyncClient() as client:
        res = await client.post(TOKEN_URL, data={
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET, "code": code,
            "redirect_uri": REDIRECT_URI, "code_verifier": request.session.get("verifier", "")
        })
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
    return {
        "status": "200 OK",
        "endpoint": "/api/reports",
        "user": claims.get("preferred_username"),
        "roles": claims.get("realm_access", {}).get("roles"),
        "data": ["Bao cao tai chinh Q3", "Bao cao van hanh TechCorp"]
    }

@app.post("/api/system-config")
async def update_system_config(claims: dict = Depends(require_roles(["role_admin"]))):
    return {
        "status": "200 OK",
        "endpoint": "/api/system-config",
        "admin": claims.get("preferred_username"),
        "message": "Cap nhat cau hinh bao mat he thong thanh cong!"
    }

@app.get("/api/audit-logs")
async def get_audit_logs(claims: dict = Depends(require_roles(["role_admin"]))):
    return {
        "status": "200 OK",
        "endpoint": "/api/audit-logs",
        "admin": claims.get("preferred_username"),
        "logs": [
            {"event": "SSO_LOGIN_PKCE", "user": "nv01", "client": "app1-portal"},
            {"event": "ACCESS_DENIED_403", "user": "nv01", "endpoint": "/api/system-config"}
        ]
    }
