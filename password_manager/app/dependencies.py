from app.database import SessionLocal
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.auth import verify_token
from app import models

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return user
