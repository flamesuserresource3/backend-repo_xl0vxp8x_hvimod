"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

# Example schemas (kept for reference):

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product" (lowercase of class name)
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Authentication schemas (used by auth endpoints)

class AuthUser(BaseModel):
    """
    Auth users collection schema
    Collection name: "authuser"
    Stores credential info with hashed password.
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address (unique)")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_active: bool = Field(True, description="Whether user is active")

class PasswordReset(BaseModel):
    """
    Password reset requests
    Collection name: "passwordreset"
    """
    email: EmailStr = Field(..., description="Associated account email")
    token: str = Field(..., description="One-time secure token")
    expires_at: datetime = Field(..., description="Expiration timestamp (UTC)")
    used: bool = Field(False, description="Whether token has been used")
