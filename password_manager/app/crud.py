from typing import Optional, List
from sqlalchemy.orm import Session
from app import models, schemas
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

FERNET_KEY = os.getenv("FERNET_KEY")
if FERNET_KEY is None:
    print("Warning: FERNET_KEY env var not set, generating a new key (not for production).")
    FERNET_KEY = Fernet.generate_key()
else:
    FERNET_KEY = FERNET_KEY.encode()

fernet = Fernet(FERNET_KEY)

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """Fetch user by username."""
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, username: str, password: str) -> models.User:
    """Create a new user with encrypted password."""
    encrypted_password = fernet.encrypt(password.encode()).decode()
    db_user = models.User(username=username, password_encrypted=encrypted_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str) -> Optional[models.User]:
    """Verify username and password for authentication."""
    user = get_user_by_username(db, username)
    if not user:
        return None
    try:
        decrypted_password = fernet.decrypt(user.password_encrypted.encode()).decode()
    except Exception:
        return None
    if decrypted_password != password:
        return None
    return user

def create_password(
    db: Session, 
    user_id: int, 
    service: str, 
    url: str, 
    username: str, 
    password: str
) -> models.Password:
    """Create a new password entry with encrypted password."""
    encrypted_password = fernet.encrypt(password.encode()).decode()
    pwd = models.Password(
        service=service,
        url=url,
        username=username,
        password_encrypted=encrypted_password,
        owner_id=user_id
    )
    db.add(pwd)
    db.commit()
    db.refresh(pwd)

    # Attach decrypted password for response convenience
    pwd.password = password
    return pwd

def get_passwords_by_user(db: Session, user_id: int) -> List[models.Password]:
    """Return all password entries for a user with decrypted passwords."""
    pwds = db.query(models.Password).filter(models.Password.owner_id == user_id).all()
    for p in pwds:
        p.password = fernet.decrypt(p.password_encrypted.encode()).decode()
    return pwds

def update_password(
    db: Session, 
    user_id: int, 
    password_id: int, 
    service: str, 
    url: str, 
    username: str, 
    password: str
) -> Optional[models.Password]:
    """Update a password entry if owned by user."""
    pwd = db.query(models.Password).filter(
        models.Password.owner_id == user_id,
        models.Password.id == password_id
    ).first()
    if not pwd:
        return None
    pwd.service = service
    pwd.url = url
    pwd.username = username
    pwd.password_encrypted = fernet.encrypt(password.encode()).decode()
    db.commit()
    db.refresh(pwd)
    pwd.password = password
    return pwd

def delete_password(db: Session, user_id: int, password_id: int) -> bool:
    """Delete a password entry if owned by user."""
    pwd = db.query(models.Password).filter(
        models.Password.owner_id == user_id,
        models.Password.id == password_id
    ).first()
    if not pwd:
        return False
    db.delete(pwd)
    db.commit()
    return True

def get_user_login_password_by_username(db: Session, username: str):
    """Return the decrypted login password of a specific user by username."""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return None

    from app.auth import decrypt
    try:
        decrypted_password = fernet.decrypt(user.password_encrypted.encode()).decode()
    except Exception:
        decrypted_password = "<Unable to decrypt>"

    return {    
        "username": user.username,
        "password": decrypted_password
    }

