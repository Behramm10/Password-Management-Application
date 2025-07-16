from pydantic import BaseModel

# --- User Schemas ---

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    is_admin: bool

    class Config:
        from_attributes = True

# --- Token Schema ---

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Password Schemas ---

class PasswordBase(BaseModel):
    service: str
    url: str
    username: str
    password: str  # Decrypted password shown only in output

class PasswordCreate(PasswordBase):
    pass  # Used for creating new passwords

class PasswordOut(PasswordBase):
    id: int  # Include ID so frontend can reference it for updates/deletes

    class Config:
        from_attributes = True

