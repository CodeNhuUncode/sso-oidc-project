import os, time
import httpx
from fastapi import Depends, Header, HTTPException
from jose import jwt, JWTError

PUB_KC = os.getenv("PUBLIC_KEYCLOAK_URL", "http://localhost:8080")
INT_KC = os.getenv("INTERNAL_KEYCLOAK_URL", "http://localhost:8080")
REALM = "enterprise-sso"

ISSUER = f"{PUB_KC}/realms/{REALM}"
JWKS_URL = f"{INT_KC}/realms/{REALM}/protocol/openid-connect/certs"
CLIENT_ID = "app2-admin"

_jwks_cache = {"keys": None, "fetched_at": 0}

async def get_jwks(force_refresh: bool = False):
    now = time.time()
    if force_refresh or not _jwks_cache["keys"] or (now - _jwks_cache["fetched_at"] > 300):
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(JWKS_URL)
            res.raise_for_status()
            _jwks_cache["keys"] = res.json()
            _jwks_cache["fetched_at"] = now
    return _jwks_cache["keys"]

async def get_current_token_claims(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thieu header Authorization: Bearer <token>")
    token = authorization.split(" ", 1)[1].strip()
    try:
        unverified_header = jwt.get_unverified_header(token)
        jwks = await get_jwks()
        if not any(k.get("kid") == unverified_header.get("kid") for k in jwks.get("keys", [])):
            jwks = await get_jwks(force_refresh=True)

        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"JWT khong hop le (sai chu ky, sai aud, hoac da het han 60s): {str(e)}")

def require_roles(allowed_roles: list[str]):
    async def role_checker(claims: dict = Depends(get_current_token_claims)) -> dict:
        user_roles = claims.get("realm_access", {}).get("roles", [])
        if not any(role in user_roles for role in allowed_roles):
            raise HTTPException(
                status_code=403,
                detail=f"403 Forbidden: Tai khoan '{claims.get('preferred_username')}' (roles={user_roles}) khong co quyen {allowed_roles}"
            )
        return claims
    return role_checker
