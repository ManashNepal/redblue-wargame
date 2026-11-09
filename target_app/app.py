import hashlib
import hmac
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine, get_db
from .models import Product, User
from .schemas import LoginRequest, UserOut

LOG_PATH = Path(__file__).resolve().parent / "access.log"
SALT = b"redblue-practice-salt"  # extra data mixed with password before hashed

DbSession = Annotated[Session, Depends(get_db)]


def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 300_000).hex()


def seed_db() -> None:
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    username="admin",
                    email="admin@redblue.local",
                    role="admin",
                    password_hash=hash_password("S3cure!Admin#2026"),
                ),
                User(
                    username="manash",
                    email="manash@redblue.local",
                    password_hash=hash_password("manash-aoi-33"),
                ),
                User(
                    username="prasam",
                    email="prasam@redblue.local",
                    password_hash=hash_password("prasam-the-gang"),
                ),
                Product(
                    name="Wireless Mouse M240",
                    description="Silent-click Bluetooth mouse with 18-month battery life",
                ),
                Product(
                    name="Mechanical Keyboard K68",
                    description="Compact 68-key keyboard with hot-swappable brown switches",
                ),
                Product(
                    name="USB-C Hub 7-in-1",
                    description="HDMI 4K, 3x USB-A, SD/microSD reader, 100W pass-through charging",
                ),
                Product(
                    name="Noise Cancelling Headphones Q30",
                    description="Over-ear ANC headphones with 40-hour playtime",
                ),
                Product(
                    name="27-inch IPS Monitor",
                    description="2560x1440 QHD display, 75Hz, adjustable stand",
                ),
                Product(
                    name="Portable SSD 1TB",
                    description="USB 3.2 external drive, up to 1050MB/s read speed",
                ),
            ]
        )
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_db()
    yield


app = FastAPI(title="RedBlue Target", lifespan=lifespan)


@app.middleware("http")
async def access_log(request: Request, call_next):
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        client = request.client.host if request.client else "-"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with LOG_PATH.open("a") as log:
            log.write(
                f"{timestamp} {client} {request.method} {path} {status} {elapsed_ms:.1f}ms\n"
            )


@app.get("/")
def index():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginRequest, db: DbSession):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not hmac.compare_digest(
        hash_password(body.password), user.password_hash
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": f"session-{user.id}"}


@app.get("/account", response_model=UserOut)
def account(db: DbSession, authorization: Annotated[str | None, Header()] = None):
    token = (authorization or "").removeprefix("Bearer ")
    user_id = token.removeprefix("session-")
    if not token.startswith("session-") or not user_id.isdigit():
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.get(User, int(user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.get("/search")
def search(db: DbSession, q: str = ""):
    query = text(f"SELECT id, name, description FROM products WHERE name LIKE '%{q}%'")
    return [dict(row) for row in db.execute(query).mappings()]


@app.get("/admin", response_model=list[UserOut])
def admin(db: DbSession):
    return db.scalars(select(User)).all()
