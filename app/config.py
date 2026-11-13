import os
import secrets

# In production, always set SECRET_KEY as an environment variable.
# The random fallback means tokens stop working on restart, which is safe but inconvenient.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tasks.db")
