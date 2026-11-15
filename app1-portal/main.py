from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="App 1 - TechCorp Portal")

KEYCLOAK_ISSUER = "http://localhost:8080/realms/enterprise-sso"
CLIENT_ID = "app1-portal"
CLIENT_SECRET = "app1-secret-key-2026"
REDIRECT_URI = "http://localhost:3001/callback"

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h2>TechCorp - App 1: Cong thong tin nhan vien (Port 3001)</h2>
    <p>Trang thai: Khung khoi tao san sang. Nguoi 2 tich hop OIDC + PKCE tai day.</p>
    <a href="/login"><button>Dang nhap qua SSO (Keycloak)</button></a>
    """
