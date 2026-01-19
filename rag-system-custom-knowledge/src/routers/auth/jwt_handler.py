from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "91e985334bbf5728603d832f511b43f3f7371a5819d262fb38ebc163a7b6744f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt