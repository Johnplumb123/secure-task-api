from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from . import config
from .db import get_session
from .models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# A real hash used when the username doesn't exist, so a login attempt takes the
# same time whether or not the user exists (prevents username enumeration by timing).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode()

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _to_bytes(password: str) -> bytes:
    # bcrypt only uses the first 72 bytes; newer versions raise an error on longer input
    return password.encode()[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_to_bytes(password), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str | None) -> bool:
    if hashed is None:
        bcrypt.checkpw(_to_bytes(password), _DUMMY_HASH.encode())  # burn the same time
        return False
    return bcrypt.checkpw(_to_bytes(password), hashed.encode())


def create_access_token(user_id: int, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": str(user_id), "iat": now, "exp": expire}
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme),
                     session: Session = Depends(get_session)) -> User:
    try:
        # Pinning algorithms=[...] blocks the classic "alg: none" and algorithm-confusion attacks
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM],
                             options={"require": ["exp", "sub"]})
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise CREDENTIALS_ERROR
    user = session.get(User, user_id)
    if user is None:
        raise CREDENTIALS_ERROR
    return user
