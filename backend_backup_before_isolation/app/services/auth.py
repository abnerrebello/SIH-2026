import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User


PBKDF2_ITERATIONS = 310_000
TOKEN_TTL_HOURS = 12


def _secret_key() -> bytes:
    secret = os.getenv("SECRET_KEY")

    if not secret or len(secret) < 32:
        raise RuntimeError(
            "SECRET_KEY must be set and contain at least 32 characters."
        )

    return secret.encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(
        value + "=" * (-len(value) % 4)
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256$"
        f"{PBKDF2_ITERATIONS}$"
        f"{_b64url(salt)}$"
        f"{_b64url(digest)}"
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split(
            "$",
            3,
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)
        salt = _b64url_decode(salt_text)
        expected = _b64url_decode(digest_text)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError):
        return False


def get_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    normalized_email = email.lower().strip()

    return db.scalar(
        select(User).where(User.email == normalized_email)
    )


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User | None:
    user = get_user_by_email(db, email)

    if user is None:
        return None

    if not user.is_active:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


def create_access_token(user: User) -> str:
    now = datetime.utcnow()

    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "name": user.full_name,
        "iat": int(now.timestamp()),
        "exp": int(
            (now + timedelta(hours=TOKEN_TTL_HOURS)).timestamp()
        ),
    }

    encoded_header = _b64url(
        json.dumps(
            header,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    encoded_payload = _b64url(
        json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    signing_input = (
        f"{encoded_header}.{encoded_payload}"
    ).encode("ascii")

    signature = hmac.new(
        _secret_key(),
        signing_input,
        hashlib.sha256,
    ).digest()

    return (
        f"{encoded_header}."
        f"{encoded_payload}."
        f"{_b64url(signature)}"
    )


def decode_access_token(token: str) -> dict:
    try:
        header_text, payload_text, signature_text = token.split(
            ".",
            2,
        )

        signing_input = (
            f"{header_text}.{payload_text}"
        ).encode("ascii")

        expected_signature = hmac.new(
            _secret_key(),
            signing_input,
            hashlib.sha256,
        ).digest()

        actual_signature = _b64url_decode(signature_text)

        if not hmac.compare_digest(
            expected_signature,
            actual_signature,
        ):
            raise ValueError("Invalid token signature")

        header = json.loads(
            _b64url_decode(header_text).decode("utf-8")
        )

        if (
            header.get("alg") != "HS256"
            or header.get("typ") != "JWT"
        ):
            raise ValueError("Unsupported token")

        payload = json.loads(
            _b64url_decode(payload_text).decode("utf-8")
        )

        if int(payload["exp"]) <= int(datetime.utcnow().timestamp()):
            raise ValueError("Token expired")

        return payload

    except (
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "Invalid or expired access token"
        ) from exc