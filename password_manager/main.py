from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from app import models, schemas, crud
from app.database import engine, Base
from app.dependencies import get_db, get_current_user
from app.auth import create_access_token

import os
import sys
from dotenv import load_dotenv

def find_env_file():
    # Helps locate the .env file even in a PyInstaller .exe
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, ".env")

load_dotenv(find_env_file())


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Password Manager API")

@app.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db, user.username, user.password)

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.UserOut)
def read_users_me(current_user=Depends(get_current_user)):
    return current_user

@app.post("/passwords/", response_model=schemas.PasswordOut)
def create_password(password: schemas.PasswordCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return crud.create_password(
        db,
        user_id=current_user.id,
        service=password.service,
        url=password.url,  
        username=password.username,
        password=password.password
    )

@app.get("/passwords/", response_model=list[schemas.PasswordOut])
def read_passwords(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return crud.get_passwords_by_user(db, current_user.id)

@app.put("/passwords/{password_id}", response_model=schemas.PasswordOut)
def update_password(password_id: int, password: schemas.PasswordCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    updated_pwd = crud.update_password(
        db,
        user_id=current_user.id,
        password_id=password_id,
        service=password.service,
        url=password.url,  
        username=password.username,
        password=password.password
    )
    if not updated_pwd:
        raise HTTPException(status_code=404, detail="Password not found")
    return updated_pwd

@app.delete("/passwords/{password_id}")
def delete_password(password_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    success = crud.delete_password(db, current_user.id, password_id)
    if not success:
        raise HTTPException(status_code=404, detail="Password not found")
    return {"detail": "Password deleted successfully"}

from app.utils import generate_password

@app.get("/generate-password")
def generate_password_api(length: int = 10, use_special: bool = True):
    if length < 6 or length > 128:
        raise HTTPException(status_code=400, detail="Password length must be between 6 and 128.")
    password = generate_password(length=length, use_special=use_special)
    return {"generated_password": password}

from app.models import User

@app.get("/admin/user-password")
def get_user_login_password(username: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = crud.get_user_login_password_by_username(db, username)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result
