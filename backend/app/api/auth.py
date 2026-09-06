from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from app.services.seed import create_default_environment
from app.core.database import get_db
from app.models import User
from app.schemas import (
    AuthLoginRequest,
    AuthRegisterRequest,
    AuthResponse,
    AuthUserResponse,
)
from app.services.seed import create_default_environment
from app.services.auth import (
    authenticate_user,
    create_access_token,
    decode_access_token,
    get_user_by_email,
    hash_password,
)


auth_router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


def _user_response(user: User) -> AuthUserResponse:
    return AuthUserResponse(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at,
    )


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header.",
        )

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token.",
        ) from exc

    user = db.get(User, user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User account is unavailable.",
        )

    return user


@auth_router.post(
    "/register",
    response_model=AuthResponse,
    status_code=201,
)
def register(
    request: AuthRegisterRequest,
    db: Session = Depends(get_db),
):
    email = str(request.email).lower().strip()

    existing_user = get_user_by_email(
        db,
        email,
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    full_name = request.full_name.strip()

    if len(full_name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Full name must contain at least 2 characters.",
        )

    user = User(
        full_name=full_name,
        email=email,
        password_hash=hash_password(
            request.password
        ),
        is_active=True,
    )

    db.add(user)
    db.flush()
    create_default_environment(db, user.id)
    db.commit()
    db.refresh(user)

    token = create_access_token(user)

    return AuthResponse(
        access_token=token,
        user=_user_response(user),
    )


@auth_router.post(
    "/login",
    response_model=AuthResponse,
)
def login(
    request: AuthLoginRequest,
    db: Session = Depends(get_db),
):
    user = authenticate_user(
        db,
        str(request.email),
        request.password,
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    user.last_login_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    token = create_access_token(user)

    return AuthResponse(
        access_token=token,
        user=_user_response(user),
    )


@auth_router.get(
    "/me",
    response_model=AuthUserResponse,
)
def me(
    current_user: User = Depends(get_current_user),
):
    return _user_response(current_user)


@auth_router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
):
    return {
        "message": "Signed out successfully.",
        "user_id": current_user.id,
    }