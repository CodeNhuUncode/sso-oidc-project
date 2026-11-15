from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="App 2 - TechCorp Admin")

KEYCLOAK_ISSUER = "http://localhost:8080/realms/enterprise-sso"
JWKS_URL = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
EXPECTED_AUDIENCE = "app2-admin"

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h2>TechCorp - App 2: He thong Quan tri (Port 3002)</h2>
    <p>Trang thai: Khung khoi tao san sang. Nguoi 3 tich hop OIDC & JWT Middleware.</p>
    """

@app.get("/api/reports")
def get_reports(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Bearer Token")
    return {"status": "OK", "data": "Bao cao noi bo TechCorp"}

@app.post("/api/system-config")
def update_config(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Bearer Token")
    return {"status": "OK", "message": "Da cap nhat cau hinh he thong"}
