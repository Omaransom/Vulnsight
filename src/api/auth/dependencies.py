from typing import Callable, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.api.auth.security import decode_access_token
from src.db.auth_repository import AuthRepository

bearer_scheme = HTTPBearer(auto_error=False)
auth_repository: AuthRepository | None = None


def set_auth_repository(repository: AuthRepository):
    global auth_repository
    auth_repository = repository


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
        )
    if auth_repository is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth repository is not configured",
        )

    claims = decode_access_token(credentials.credentials)
    user_id = int(claims.get("sub", 0))
    user = auth_repository.get_user_by_id(user_id)
    if not user or not user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or missing",
        )
    roles = auth_repository.get_user_roles(user_id)
    return {"id": user["id"], "username": user["username"], "roles": roles}


def require_roles(*required_roles: str) -> Callable:
    required = {r.strip().lower() for r in required_roles if r and r.strip()}

    def _dependency(current_user=Depends(get_current_user)):
        if not required:
            return current_user
        user_roles = {r.lower() for r in current_user["roles"]}
        if required.isdisjoint(user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions",
            )
        return current_user

    return _dependency
