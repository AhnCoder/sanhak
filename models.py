# models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


class User(Base):
    __tablename__ = "User"
    id = Column(Integer, primary_key=True, index=True)
    student_number = Column(String(20), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    contact = Column(String(20))
    request_details = Column(String(200))
    department = Column(String(100))
    signup_date = Column(DateTime, default=datetime.utcnow)
    deactivation_date = Column(DateTime)


class AuthPhone(Base):
    __tablename__ = "auth_phone"
    auth_phone_id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String(20), index=True)
    auth_code = Column(String(6), index=True)
    is_verified = Column(Boolean, default=False)
    expires_at = Column(DateTime)


class AuthToken(Base):
    __tablename__ = "auth_token"
    token_id = Column(Integer, primary_key=True, index=True)
    student_number = Column(String(20), ForeignKey("User.student_number"), index=True)
    token_type = Column(String(255))
    token = Column(String(512))  # Increase length to 512 if necessary
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)