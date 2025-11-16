import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
import secrets
from passlib.hash import bcrypt

from database import db, create_document, get_documents
from bson import ObjectId

from schemas import User as UserSchema, Image as ImageSchema, Purchase as PurchaseSchema

app = FastAPI(title="ClipGen Studio API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utilities

def oid_str(oid) -> str:
    return str(oid)


def ensure_user(doc: dict) -> dict:
    if not doc:
        return doc
    doc["id"] = oid_str(doc.get("_id"))
    doc.pop("_id", None)
    doc.pop("password_hash", None)
    doc.pop("reset_token", None)
    return doc


def ensure_image(doc: dict) -> dict:
    if not doc:
        return doc
    doc["id"] = oid_str(doc.get("_id"))
    doc.pop("_id", None)
    return doc


# Simple token auth (for demo/exportable app): store token on user document
# In production use JWT. Here we keep it simple and self-contained.

def make_token() -> str:
    return secrets.token_urlsafe(32)


def get_current_user(x_token: Optional[str] = Header(default=None)) -> dict:
    if not x_token:
        raise HTTPException(status_code=401, detail="Missing token")
    user = db["user"].find_one({"token": x_token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# Auth models

class AuthRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: dict


class ResetRequest(BaseModel):
    email: EmailStr


class ResetConfirm(BaseModel):
    token: str
    new_password: str


class UpdateEmail(BaseModel):
    email: EmailStr


class UpdatePassword(BaseModel):
    old_password: str
    new_password: str


class GenerateRequest(BaseModel):
    prompt: str


@app.get("/")
def read_root():
    return {"message": "ClipGen Studio API running"}


# Auth endpoints

@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: AuthRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(400, detail="Email already registered")
    pw_hash = bcrypt.hash(payload.password)
    token = make_token()
    user_data = UserSchema(email=payload.email, password_hash=pw_hash, credits=5, name=payload.name).model_dump()
    user_data.update({"token": token})
    user_id = db["user"].insert_one(user_data).inserted_id
    user = db["user"].find_one({"_id": user_id})
    return {"token": token, "user": ensure_user(user)}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: AuthRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not bcrypt.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(401, detail="Invalid credentials")
    token = user.get("token") or make_token()
    if not user.get("token"):
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"token": token}})
    return {"token": token, "user": ensure_user(user)}


@app.post("/auth/request-reset")
def request_reset(payload: ResetRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        return {"ok": True}  # do not leak
    token = make_token()
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"reset_token": token}})
    # In a real app, send email. Here we return the token so the demo can use it.
    return {"ok": True, "reset_token": token}


@app.post("/auth/confirm-reset")
def confirm_reset(payload: ResetConfirm):
    user = db["user"].find_one({"reset_token": payload.token})
    if not user:
        raise HTTPException(400, detail="Invalid token")
    pw_hash = bcrypt.hash(payload.new_password)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": pw_hash}, "$unset": {"reset_token": ""}})
    return {"ok": True}


# Profile / Settings

@app.get("/me")
def get_me(user=Depends(get_current_user)):
    return ensure_user(user)


@app.post("/settings/email")
def change_email(payload: UpdateEmail, user=Depends(get_current_user)):
    if db["user"].find_one({"email": payload.email, "_id": {"$ne": user["_id"]}}):
        raise HTTPException(400, detail="Email already in use")
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"email": payload.email}})
    user["email"] = payload.email
    return ensure_user(user)


@app.post("/settings/password")
def change_password(payload: UpdatePassword, user=Depends(get_current_user)):
    if not bcrypt.verify(payload.old_password, user.get("password_hash", "")):
        raise HTTPException(400, detail="Old password incorrect")
    pw_hash = bcrypt.hash(payload.new_password)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": pw_hash}})
    return {"ok": True}


@app.delete("/settings/delete-account")
def delete_account(user=Depends(get_current_user)):
    uid = user["_id"]
    db["image"].delete_many({"user_id": oid_str(uid)})
    db["purchase"].delete_many({"user_id": oid_str(uid)})
    db["user"].delete_one({"_id": uid})
    return {"ok": True}


# Credits

@app.get("/credits")
def get_credits(user=Depends(get_current_user)):
    return {"credits": user.get("credits", 0)}


# AI Generation (placeholder using a free image placeholder service)
# In a real implementation you'd call an AI image API. Here we generate a URL
# based on the prompt so the app works exportably.

@app.post("/generate")
def generate_clipart(payload: GenerateRequest, user=Depends(get_current_user)):
    credits = user.get("credits", 0)
    if credits <= 0:
        raise HTTPException(402, detail="No credits remaining")

    prompt = payload.prompt.strip()
    if not prompt:
        raise HTTPException(400, detail="Prompt required")

    # Fake AI image URL (picsum with seeded id)
    seed = abs(hash(prompt)) % 1000
    url = f"https://picsum.photos/seed/{seed}/768/768.jpg"

    # Deduct 1 credit
    db["user"].update_one({"_id": user["_id"]}, {"$inc": {"credits": -1}})

    return {"url": url, "prompt": prompt}


# Library

@app.post("/library/save")
def save_image(item: ImageSchema, user=Depends(get_current_user)):
    if item.user_id != oid_str(user["_id"]):
        raise HTTPException(403, detail="Forbidden")
    img_id = create_document("image", item)
    doc = db["image"].find_one({"_id": ObjectId(img_id)})
    return ensure_image(doc)


@app.get("/library", response_model=List[dict])
def list_library(user=Depends(get_current_user)):
    items = get_documents("image", {"user_id": oid_str(user["_id"])} )
    return [ensure_image(it) for it in items]


@app.delete("/library/{image_id}")
def delete_image(image_id: str, user=Depends(get_current_user)):
    doc = db["image"].find_one({"_id": ObjectId(image_id)})
    if not doc or doc.get("user_id") != oid_str(user["_id"]):
        raise HTTPException(404, detail="Not found")
    db["image"].delete_one({"_id": ObjectId(image_id)})
    return {"ok": True}


# Billing (Stripe placeholder flow)
# We simulate Stripe Checkout by creating purchase entries and adding credits.
# In a real app you'd integrate Stripe Sessions + webhooks.

class CheckoutRequest(BaseModel):
    tier: str


TIERS = {
    "starter": {"credits": 50, "amount_eur": 5},
    "creator": {"credits": 150, "amount_eur": 10},
    "pro": {"credits": 500, "amount_eur": 25},
}


@app.post("/billing/checkout")
def checkout(payload: CheckoutRequest, user=Depends(get_current_user)):
    tier = payload.tier.lower()
    if tier not in TIERS:
        raise HTTPException(400, detail="Invalid tier")
    plan = TIERS[tier]

    purchase = PurchaseSchema(
        user_id=oid_str(user["_id"]),
        tier=tier,
        amount_eur=plan["amount_eur"],
        credits_added=plan["credits"],
        stripe_session_id=None,
        stripe_payment_intent=None,
    )
    pid = create_document("purchase", purchase)
    # Add credits
    db["user"].update_one({"_id": user["_id"]}, {"$inc": {"credits": plan["credits"]}})

    doc = db["purchase"].find_one({"_id": ObjectId(pid)})
    doc["id"] = oid_str(doc.pop("_id"))
    return doc


@app.get("/billing/history")
def billing_history(user=Depends(get_current_user)):
    items = get_documents("purchase", {"user_id": oid_str(user["_id"])} )
    for it in items:
        it["id"] = oid_str(it.pop("_id"))
    return items


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
