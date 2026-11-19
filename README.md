# De tai 12: Mo hinh dang nhap tap trung OpenID Connect & OAuth 2.0

## Thong so he thong
- Keycloak IdP: http://localhost:8080 (Admin: admin / admin | Realm: enterprise-sso)
- App 1 Portal: http://localhost:3001 (client_id: app1-portal)
- App 2 Admin: http://localhost:3002 (client_id: app2-admin)
- Tai khoan test: nv01 / 123456 (role_user) | admin01 / 123456 (role_admin)
- Access Token Lifespan: 60s

## Khoi chay toan he thong
docker compose up --build -d
