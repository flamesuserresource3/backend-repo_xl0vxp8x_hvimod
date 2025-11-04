import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from passlib.context import CryptContext
from database import db, create_document, get_documents
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., description="Google ID Token from GIS")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=6, max_length=128)


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    return response


# -------------------- AUTH ENDPOINTS --------------------

@app.post("/auth/register")
def register(payload: RegisterRequest):
    email = payload.email.lower()
    # Check if user already exists
    existing = db["authuser"].find_one({"email": email}) if db else None
    if existing:
        raise HTTPException(status_code=409, detail="Email sudah terdaftar")

    password_hash = pwd_context.hash(payload.password)
    from schemas import AuthUser

    doc = AuthUser(name=payload.name, email=email, password_hash=password_hash, is_active=True)
    inserted_id = create_document("authuser", doc)

    return {"ok": True, "message": "Registrasi berhasil", "user_id": inserted_id}


@app.post("/auth/login")
def login(payload: LoginRequest):
    email = payload.email.lower()
    user = db["authuser"].find_one({"email": email}) if db else None
    if not user:
        raise HTTPException(status_code=401, detail="Email atau kata sandi salah")

    if not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email atau kata sandi salah")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Akun dinonaktifkan")

    # Simple session token mock (not JWT). For demo purposes only.
    return {
        "ok": True,
        "message": "Login berhasil",
        "user": {
            "id": str(user.get("_id")),
            "name": user.get("name"),
            "email": user.get("email"),
        },
        "token": "demo-token",
    }


@app.post("/auth/google")
def google_auth(payload: GoogleAuthRequest):
    """Verify Google ID token and sign-in/up the user.
    Expects an ID token from Google Identity Services (client-side).
    """
    try:
        verify_url = "https://oauth2.googleapis.com/tokeninfo"
        resp = requests.get(verify_url, params={"id_token": payload.id_token}, timeout=10)
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Token Google tidak valid")
        info = resp.json()
        email = (info.get("email") or "").lower()
        if not email:
            raise HTTPException(status_code=400, detail="Email tidak ditemukan dari Google")
        name = info.get("name") or f"Pengguna {email.split('@')[0]}"

        # Find or create user
        user = db["authuser"].find_one({"email": email}) if db else None
        if not user:
            from schemas import AuthUser
            # Store a placeholder password hash for social account
            placeholder_hash = pwd_context.hash(os.urandom(16).hex())
            doc = AuthUser(name=name, email=email, password_hash=placeholder_hash, is_active=True)
            inserted_id = create_document("authuser", doc)
            user = db["authuser"].find_one({"_id": inserted_id}) if db else {"_id": inserted_id, "name": name, "email": email}

        if not user.get("is_active", True):
            raise HTTPException(status_code=403, detail="Akun dinonaktifkan")

        return {
            "ok": True,
            "message": "Login Google berhasil",
            "user": {
                "id": str(user.get("_id")),
                "name": user.get("name"),
                "email": user.get("email"),
            },
            "token": "demo-token",
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Gagal memproses login Google")


@app.post("/auth/forgot")
def forgot_password(payload: ForgotPasswordRequest):
    # Always respond ok to avoid account enumeration, but generate a token if user exists
    email = payload.email.lower()
    user = db["authuser"].find_one({"email": email}) if db else None

    if user and db is not None:
        # Invalidate previous tokens
        db["passwordreset"].update_many({"email": email, "used": False}, {"$set": {"used": True}})
        from schemas import PasswordReset
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        doc = PasswordReset(email=email, token=token, expires_at=expires_at, used=False)
        create_document("passwordreset", doc)
        # In real app we would send email here. For demo we return the token so it can be used directly.
        return {"ok": True, "message": "Jika email terdaftar, tautan reset telah dikirim.", "token": token, "expires_in": 3600}

    # If no user, still return ok without token
    return {"ok": True, "message": "Jika email terdaftar, tautan reset telah dikirim."}


@app.post("/auth/reset")
def reset_password(payload: ResetPasswordRequest):
    email = payload.email.lower()
    if db is None:
        raise HTTPException(status_code=500, detail="Database tidak tersedia")

    token_doc = db["passwordreset"].find_one({"email": email, "token": payload.token})
    if not token_doc:
        raise HTTPException(status_code=400, detail="Token reset tidak valid")

    if token_doc.get("used", False):
        raise HTTPException(status_code=400, detail="Token reset sudah digunakan")

    expires_at = token_doc.get("expires_at")
    # expires_at may be datetime or string depending on driver settings; attempt parse/compare
    now = datetime.now(timezone.utc)
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except Exception:
            pass
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        raise HTTPException(status_code=400, detail="Token reset telah kedaluwarsa")

    user = db["authuser"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Pengguna tidak ditemukan")

    new_hash = pwd_context.hash(payload.new_password)
    db["authuser"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})
    db["passwordreset"].update_one({"_id": token_doc["_id"]}, {"$set": {"used": True}})

    return {"ok": True, "message": "Password berhasil direset. Silakan login kembali."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
