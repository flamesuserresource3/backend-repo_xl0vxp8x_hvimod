import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from passlib.context import CryptContext
from database import db, create_document, get_documents

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


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
