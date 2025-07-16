from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from sqlalchemy import Boolean

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_encrypted = Column(String(512), nullable=False)  # Changed field name and size
    is_admin = Column(Boolean, default=False) 
    passwords = relationship("Password", back_populates="owner")

class Password(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String(100), index=True, nullable=False)
    url = Column(String(500))  
    username = Column(String(100), nullable=False)
    password_encrypted = Column(String(512), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="passwords")
