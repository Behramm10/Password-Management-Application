from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi import Request

from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY environment variable not set. Please set it in your .env file.")

fernet = Fernet(FERNET_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Encrypt password (instead of hashing)
def encrypt(plain_text: str) -> str:
    return fernet.encrypt(plain_text.encode()).decode()

# Decrypt password for verification
def decrypt(encrypted_text: str) -> str:
    return fernet.decrypt(encrypted_text.encode()).decode()

# Verify password by decrypting and comparing
def verify_password(plain_password: str, encrypted_password: str) -> bool:
    try:
        decrypted_password = decrypt(encrypted_password)
        return decrypted_password == plain_password
    except Exception:
        return False

# Get encrypted password (instead of hashed password)
def get_password_hash(password: str) -> str:
    return encrypt(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception