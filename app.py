"""
Bolt Earth EV Charging Station — Production Backend
FastAPI + MongoDB Atlas + JWT Authentication
Password Security: SHA-256 pre-hash + bcrypt (removes 72-byte bcrypt limit)
"""

# ─── Load .env file FIRST ────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ .env file loaded")
except ImportError:
    print("⚠️  python-dotenv not installed. Run: pip install python-dotenv")

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr, validator
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError, ConfigurationError
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib, bcrypt, random, string, os, base64

# ─── CONFIG ──────────────────────────────────────────────────────────────────
MONGO_URI: str  = os.getenv("MONGO_URI", "")
SECRET_KEY: str = os.getenv("SECRET_KEY", "bolt-earth-secret-key-2025-change-me")
ALGORITHM: str  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24   # 24 hours

# ─── STARTUP DIAGNOSTICS ─────────────────────────────────────────────────────
print("\n" + "="*60)
print("  BOLT EARTH SERVER STARTING")
print("="*60)
if not MONGO_URI:
    print("❌ MONGO_URI is EMPTY!  →  Add it to your .env file")
elif "<user>" in MONGO_URI or "YOUR_PASSWORD" in MONGO_URI:
    print("❌ MONGO_URI still has placeholder text!")
else:
    safe = MONGO_URI.split("@")[-1] if "@" in MONGO_URI else MONGO_URI[:40]
    print(f"✅ MONGO_URI found → ...@{safe}")
print("="*60 + "\n")

# ─── DB SETUP ────────────────────────────────────────────────────────────────
db_connected: bool = False
db = users_col = bookings_col = history_col = client = None

def connect_db() -> None:
    global db_connected, db, users_col, bookings_col, history_col, client
    if not MONGO_URI or "<user>" in MONGO_URI or "YOUR_PASSWORD" in MONGO_URI:
        print("⛔ Skipping DB connect — URI not configured"); return
    try:
        print("🔄 Connecting to MongoDB Atlas...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
        client.admin.command("ping")
        db           = client["boltearth"]
        users_col    = db["users"]
        bookings_col = db["bookings"]
        history_col  = db["history"]
        users_col.create_index("email", unique=True)
        db_connected = True
        print("✅ MongoDB connected!  Database: boltearth")
        print("   Collections ready: users · bookings · history\n")
    except ServerSelectionTimeoutError:
        print("❌ MongoDB TIMEOUT — Fix:")
        print("   1. Check password in MONGO_URI")
        print("   2. Atlas → Security → Network Access → Add your IP\n")
    except ConfigurationError as e:
        print(f"❌ MongoDB config error: {e}\n")
    except Exception as e:
        print(f"❌ MongoDB error: {type(e).__name__}: {e}\n")

connect_db()

# ─────────────────────────────────────────────────────────────────────────────
#  PASSWORD HASHING  —  SHA-256 pre-hash + bcrypt
# ─────────────────────────────────────────────────────────────────────────────

def _prehash(plain_password: str) -> bytes:
    sha256_digest = hashlib.sha256(plain_password.encode("utf-8")).digest()
    return base64.b64encode(sha256_digest)

def hash_password(plain_password: str) -> str:
    prehashed = _prehash(plain_password)
    salt      = bcrypt.gensalt(rounds=12)
    hashed    = bcrypt.hashpw(prehashed, salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, stored_hash: str) -> bool:
    prehashed: bytes    = _prehash(plain_password)
    stored_bytes: bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(prehashed, stored_bytes)

# ─── JWT HELPERS ─────────────────────────────────────────────────────────────
bearer = HTTPBearer()

def create_access_token(data: dict) -> str:
    payload = {**data, "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please login again.")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if not db_connected:
        raise HTTPException(status_code=503, detail="Database not connected. Check MONGO_URI in .env")
    payload = decode_token(creds.credentials)
    user = users_col.find_one({"email": payload["sub"]}, {"password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["_id"] = str(user["_id"])
    return user

def check_db() -> None:
    if not db_connected:
        raise HTTPException(
            status_code=503,
            detail="Database not connected. Fix MONGO_URI in .env file and restart."
        )

def generate_booking_token() -> str:
    return "EV" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

# ─── PYDANTIC SCHEMAS ────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    full_name:      str
    contact_number: str
    email:          EmailStr
    vehicle_model:  str
    number_plate:   str
    vehicle_id:     str
    password:       str

    @validator("password", pre=True, always=True)
    @classmethod
    def pw_strength(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v

    @validator("full_name", pre=True, always=True)
    @classmethod
    def full_name_ok(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Full name cannot be empty")
        return v.strip()

    @validator("number_plate", pre=True, always=True)
    @classmethod
    def plate_ok(cls, v: str) -> str:
        return v.strip().upper()

    class Config:
        anystr_strip_whitespace = True


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

    class Config:
        anystr_strip_whitespace = True


class BookSlotRequest(BaseModel):
    station_name:  str
    slot_id:       str
    slot_time:     str
    charging_mode: str
    duration_min:  int
    cost:          float

    class Config:
        anystr_strip_whitespace = True


# ─── APP SETUP ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Bolt Earth API",
    version="2.0.0",
    description="EV Charging Station Backend with SHA-256+bcrypt auth"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# ─── HEALTH CHECK ────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> Any:
    return JSONResponse({
        "server":        "✅ Running",
        "database":      "✅ Connected" if db_connected else "❌ NOT Connected",
        "mongo_uri_set": "✅ Yes" if MONGO_URI and "<user>" not in MONGO_URI else "❌ Missing/Wrong",
        "password_algo": "SHA-256 pre-hash + bcrypt (rounds=12)",
        "message":       "All systems go!" if db_connected else "Fix MONGO_URI in .env file",
        "fix_steps": [] if db_connected else [
            "1. Open .env in your bolt-earth folder",
            "2. MONGO_URI=mongodb+srv://user:pass@cluster.net/boltearth?retryWrites=true&w=majority",
            "3. Atlas → Security → Network Access → Add your IP / Allow from Anywhere",
            "4. Restart the server",
        ]
    })

# ─── STATIC PAGE ROUTES ──────────────────────────────────────────────────────
@app.get("/home")
def homepage() -> Any:       return FileResponse("static/index.html")

@app.get("/")
def root() -> Any:            return FileResponse("static/index.html")

@app.get("/login-page")
def login_page() -> Any:      return FileResponse("static/login.html")

@app.get("/register-page")
def register_page() -> Any:   return FileResponse("static/register.html")

@app.get("/dashboard-page")
def dashboard_page() -> Any:  return FileResponse("static/dashboard.html")

@app.get("/station-page")
def station_page() -> Any:    return FileResponse("static/in_station.html")

@app.get("/nearby-page")
def nearby_page() -> Any:     return FileResponse("static/nearby_station.html")

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
@app.post("/register", status_code=201)
def register(body: RegisterRequest) -> Dict[str, Any]:
    check_db()
    try:
        users_col.insert_one({
            "full_name":        body.full_name,
            "contact_number":   body.contact_number,
            "email":            body.email,
            "vehicle_model":    body.vehicle_model,
            "number_plate":     body.number_plate,
            "vehicle_id":       body.vehicle_id,
            "password":         hash_password(body.password),
            "created_at":       datetime.utcnow(),
            "booking_history":  [],
            "charging_history": [],
            "pw_algo":          "sha256+bcrypt",
        })
        token: str = create_access_token({"sub": body.email})
        print(f"✅ Registered: {body.email}")
        return {
            "message": "Registration successful",
            "token":   token,
            "user": {
                "full_name":     body.full_name,
                "email":         body.email,
                "vehicle_model": body.vehicle_model,
                "number_plate":  body.number_plate,
                "vehicle_id":    body.vehicle_id,
            }
        }
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Email already registered. Please login.")
    except Exception as e:
        print(f"❌ Register error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/login")
def login(body: LoginRequest) -> Dict[str, Any]:
    check_db()
    try:
        user = users_col.find_one({"email": body.email})
        if not user or not verify_password(body.password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        token: str = create_access_token({"sub": body.email})
        print(f"✅ Login: {body.email}")
        return {
            "message": "Login successful",
            "token":   token,
            "user": {
                "full_name":     user.get("full_name"),
                "email":         user.get("email"),
                "vehicle_model": user.get("vehicle_model"),
                "number_plate":  user.get("number_plate"),
                "vehicle_id":    user.get("vehicle_id"),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user)) -> dict:
    return current_user

# ─── STATION ROUTES ──────────────────────────────────────────────────────────
MOCK_STATIONS: List[Dict[str, Any]] = [
    {"id":"ST001","name":"Bolt Earth — Anna Nagar","address":"3rd Ave, Anna Nagar, Chennai",       "lat":13.0850,"lon":80.2100,"available_slots":4,"fast_chargers":2,"slow_chargers":2,"rating":4.7},
    {"id":"ST002","name":"Bolt Earth — T. Nagar",  "address":"Usman Rd, T. Nagar, Chennai",        "lat":13.0418,"lon":80.2341,"available_slots":3,"fast_chargers":1,"slow_chargers":2,"rating":4.5},
    {"id":"ST003","name":"Bolt Earth — OMR",       "address":"Sholinganallur, OMR, Chennai",       "lat":12.9010,"lon":80.2279,"available_slots":6,"fast_chargers":3,"slow_chargers":3,"rating":4.8},
    {"id":"ST004","name":"Bolt Earth — Velachery", "address":"Velachery Main Rd, Chennai",         "lat":12.9788,"lon":80.2209,"available_slots":2,"fast_chargers":1,"slow_chargers":1,"rating":4.3},
    {"id":"ST005","name":"Bolt Earth — Guindy",    "address":"Industrial Estate, Guindy, Chennai", "lat":13.0067,"lon":80.2206,"available_slots":5,"fast_chargers":2,"slow_chargers":3,"rating":4.6},
]

@app.get("/get-stations")
def get_stations(current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    return {"stations": MOCK_STATIONS, "total": len(MOCK_STATIONS)}

@app.get("/get-stations/public")
def get_stations_public() -> Dict[str, Any]:
    return {"stations": MOCK_STATIONS, "total": len(MOCK_STATIONS)}

# ─── BOOKING ROUTES ──────────────────────────────────────────────────────────
@app.post("/book-slot", status_code=201)
def book_slot(body: BookSlotRequest, current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    check_db()
    token: str = generate_booking_token()
    booking: Dict[str, Any] = {
        "user_id":       current_user["_id"],
        "user_email":    current_user["email"],
        "user_name":     current_user.get("full_name", ""),
        "station_name":  body.station_name,
        "slot_id":       body.slot_id,
        "slot_time":     body.slot_time,
        "charging_mode": body.charging_mode,
        "duration_min":  body.duration_min,
        "cost":          body.cost,
        "token":         token,
        "status":        "confirmed",
        "booked_at":     datetime.utcnow(),
    }
    result = bookings_col.insert_one(booking)
    history_col.insert_one({**booking, "booking_id": str(result.inserted_id)})
    print(f"✅ Booking: {token} → {body.station_name} @ {body.slot_time}")
    return {
        "message": "Slot booked successfully",
        "token":   token,
        "booking": {
            "id":        str(result.inserted_id),
            "station":   body.station_name,
            "slot_time": body.slot_time,
            "mode":      body.charging_mode,
            "duration":  body.duration_min,
            "cost":      body.cost,
            "token":     token,
            "status":    "confirmed",
        }
    }

@app.get("/user-history")
def user_history(current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    check_db()
    records: List[Dict] = list(history_col.find(
        {"user_email": current_user["email"]},
        {"_id": 0, "user_id": 0}
    ).sort("booked_at", -1).limit(50))
    for r in records:
        if isinstance(r.get("booked_at"), datetime):
            r["booked_at"] = r["booked_at"].strftime("%d %b %Y, %I:%M %p")
    return {"history": records, "total": len(records)}

@app.get("/current-bookings")
def current_bookings(current_user: dict = Depends(get_current_user)) -> Dict[str, Any]:
    check_db()
    records: List[Dict] = list(bookings_col.find(
        {"user_email": current_user["email"], "status": "confirmed"},
        {"_id": 0, "user_id": 0}
    ).sort("booked_at", -1))
    for r in records:
        if isinstance(r.get("booked_at"), datetime):
            r["booked_at"] = r["booked_at"].strftime("%d %b %Y, %I:%M %p")
    return {"bookings": records, "total": len(records)}
