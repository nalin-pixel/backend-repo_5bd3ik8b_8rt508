"""
Database Schemas for ClipGen Studio

Each Pydantic model represents a MongoDB collection (collection name is the
lowercased class name). These schemas are used for validation when inserting
into the database via the provided helpers.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List


class User(BaseModel):
    email: EmailStr = Field(..., description="User email (unique)")
    password_hash: str = Field(..., description="BCrypt password hash")
    credits: int = Field(5, ge=0, description="Remaining generation credits")
    name: Optional[str] = Field(None, description="Display name")
    reset_token: Optional[str] = Field(None, description="Password reset token")


class Image(BaseModel):
    user_id: str = Field(..., description="Owner user id (stringified ObjectId)")
    prompt: str = Field(..., description="Prompt used to generate the image")
    url: str = Field(..., description="Public URL to the generated image")
    format: str = Field("jpg", description="File format (jpg, png)")
    width: int = Field(512, description="Image width")
    height: int = Field(512, description="Image height")


class Purchase(BaseModel):
    user_id: str = Field(..., description="Purchaser user id (stringified ObjectId)")
    tier: str = Field(..., description="Plan tier: starter|creator|pro")
    amount_eur: float = Field(..., description="Amount paid in EUR")
    credits_added: int = Field(..., description="Credits added by this purchase")
    stripe_session_id: Optional[str] = Field(None, description="Stripe checkout session id")
    stripe_payment_intent: Optional[str] = Field(None, description="Stripe payment intent id")
