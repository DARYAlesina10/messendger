from __future__ import annotations

import hashlib
import os
import secrets
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/task")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
ACCESS_TTL_MINUTES = int(os.getenv("ACCESS_TTL_MINUTES", "30"))
REFRESH_TTL_DAYS = int(os.getenv("REFRESH_TTL_DAYS", "14"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))

app = FastAPI(title="Task")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_async_engine(DATABASE_URL, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # channel | dm
    name: Mapped[str] = mapped_column(String(120), index=True)
    group_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    topic: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ConversationMember(Base):
    __tablename__ = "conversation_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(32), default="member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uploader_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(255), unique=True)
    original_name: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(120))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeviceToken(Base):
    __tablename__ = "device_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_token: Mapped[str] = mapped_column(String(255), index=True)
    platform: Mapped[str] = mapped_column(String(32), default="web")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=6, max_length=120)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class ChannelCreateRequest(BaseModel):
    group_name: str
    topic: str = "main"
    name: str


class PushSubscribeRequest(BaseModel):
    device_token: str
    platform: str = "web"


class PushNotifyRequest(BaseModel):
    conversation_id: int
    text: str


class PublicKeyRequest(BaseModel):
    public_key: str


class MessageIn(BaseModel):
    ciphertext: str
    nonce: str | None = None
    file_url: str | None = None


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    conversation_id: int
    sender_id: int
    ciphertext: str
    nonce: str | None
    file_url: str | None
    created_at: datetime


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_access_token(user_id: int, username: str) -> str:
    exp = datetime.now(UTC) + timedelta(minutes=ACCESS_TTL_MINUTES)
    payload = {"sub": str(user_id), "username": username, "type": "access", "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


async def issue_refresh_token(user_id: int, db: AsyncSession) -> str:
    plain = secrets.token_urlsafe(48)
    token_db = RefreshToken(
        user_id=user_id,
        token_hash=hash_refresh_token(plain),
        expires_at=datetime.now(UTC) + timedelta(days=REFRESH_TTL_DAYS),
    )
    db.add(token_db)
    await db.commit()
    return plain


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = int(payload["sub"])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def assert_membership(db: AsyncSession, conversation_id: int, user_id: int) -> None:
    stmt = select(ConversationMember).where(
        and_(ConversationMember.conversation_id == conversation_id, ConversationMember.user_id == user_id)
    )
    member = await db.scalar(stmt)
    if not member:
        raise HTTPException(status_code=403, detail="No access to conversation")


@app.on_event("startup")
async def startup() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.post("/auth/register")
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    existing = await db.scalar(select(User).where(User.username == payload.username))
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")

    user = User(username=payload.username, password_hash=pwd_context.hash(payload.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)

    access = issue_access_token(user.id, user.username)
    refresh = await issue_refresh_token(user.id, db)
    return {"access_token": access, "refresh_token": refresh}


@app.post("/auth/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    user = await db.scalar(select(User).where(User.username == payload.username))
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username/password")

    access = issue_access_token(user.id, user.username)
    refresh = await issue_refresh_token(user.id, db)
    return {"access_token": access, "refresh_token": refresh}


@app.post("/auth/refresh")
async def refresh_tokens(payload: TokenRefreshRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    token_hash = hash_refresh_token(payload.refresh_token)
    token_row = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if not token_row or token_row.revoked_at is not None or token_row.expires_at < datetime.now(UTC):
        raise HTTPException(status_code=401, detail="Refresh token expired/revoked")

    user = await db.get(User, token_row.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    token_row.revoked_at = datetime.now(UTC)
    await db.commit()

    access = issue_access_token(user.id, user.username)
    refresh = await issue_refresh_token(user.id, db)
    return {"access_token": access, "refresh_token": refresh}


@app.post("/auth/logout")
async def logout(payload: TokenRefreshRequest, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    token_hash = hash_refresh_token(payload.refresh_token)
    token_row = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if token_row:
        token_row.revoked_at = datetime.now(UTC)
        await db.commit()
    return {"status": "ok"}


@app.post("/e2e/public-key")
async def upload_public_key(payload: PublicKeyRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    user.public_key = payload.public_key
    await db.commit()
    return {"status": "saved"}


@app.get("/e2e/public-keys")
async def list_public_keys(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    users = (await db.scalars(select(User))).all()
    return [{"id": u.id, "username": u.username, "public_key": u.public_key} for u in users if u.public_key]


@app.post("/channels")
async def create_channel(payload: ChannelCreateRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    conv = Conversation(
        kind="channel",
        name=payload.name,
        group_name=payload.group_name,
        topic=payload.topic,
        created_by=user.id,
    )
    db.add(conv)
    await db.flush()

    db.add(ConversationMember(conversation_id=conv.id, user_id=user.id, role="owner"))
    await db.commit()
    return {"conversation_id": conv.id, "kind": conv.kind, "group": conv.group_name, "topic": conv.topic}


@app.post("/dm/{other_username}")
async def create_dm(other_username: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    other = await db.scalar(select(User).where(User.username == other_username))
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    if other.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot create DM with yourself")

    member_sub = (
        select(ConversationMember.conversation_id)
        .where(ConversationMember.user_id.in_([user.id, other.id]))
        .group_by(ConversationMember.conversation_id)
        .having(func.count(ConversationMember.user_id) == 2)
    )
    existing_stmt = select(Conversation).where(and_(Conversation.kind == "dm", Conversation.id.in_(member_sub)))
    existing = await db.scalar(existing_stmt)

    if existing:
        return {"conversation_id": existing.id, "kind": existing.kind}

    conv = Conversation(kind="dm", name=f"dm:{min(user.id, other.id)}:{max(user.id, other.id)}", created_by=user.id)
    db.add(conv)
    await db.flush()

    db.add_all(
        [
            ConversationMember(conversation_id=conv.id, user_id=user.id, role="member"),
            ConversationMember(conversation_id=conv.id, user_id=other.id, role="member"),
        ]
    )
    await db.commit()
    return {"conversation_id": conv.id, "kind": conv.kind}


@app.get("/conversations")
async def my_conversations(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> list[dict[str, Any]]:
    stmt = (
        select(Conversation)
        .join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
        .where(ConversationMember.user_id == user.id)
        .order_by(Conversation.id.desc())
    )
    rows = (await db.scalars(stmt)).all()
    return [
        {
            "id": row.id,
            "kind": row.kind,
            "name": row.name,
            "group_name": row.group_name,
            "topic": row.topic,
        }
        for row in rows
    ]


@app.get("/messages/{conversation_id}")
async def list_messages(conversation_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> list[MessageOut]:
    await assert_membership(db, conversation_id, user.id)
    stmt = (
        select(Message)
        .where(Message.conversation_id == conversation_id)
        .order_by(Message.id.desc())
        .limit(100)
    )
    items = list((await db.scalars(stmt)).all())
    items.reverse()
    return [MessageOut.model_validate(item) for item in items]


@app.post("/files/upload")
async def upload_file(
    upload: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    filename = f"{uuid4().hex}_{upload.filename or 'file.bin'}"
    destination = UPLOAD_DIR / filename

    content = await upload.read()
    destination.write_bytes(content)

    row = UploadedFile(
        uploader_id=user.id,
        path=str(destination),
        original_name=upload.filename or filename,
        mime_type=upload.content_type or "application/octet-stream",
        size=len(content),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    return {
        "file_id": row.id,
        "file_url": f"/uploads/{filename}",
        "size": row.size,
        "mime_type": row.mime_type,
    }


@app.post("/push/subscribe")
async def push_subscribe(payload: PushSubscribeRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    existing = await db.scalar(
        select(DeviceToken).where(and_(DeviceToken.user_id == user.id, DeviceToken.device_token == payload.device_token))
    )
    if not existing:
        db.add(DeviceToken(user_id=user.id, device_token=payload.device_token, platform=payload.platform))
        await db.commit()
    return {"status": "subscribed"}


@app.post("/push/notify")
async def push_notify(payload: PushNotifyRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    await assert_membership(db, payload.conversation_id, user.id)
    members = (await db.scalars(select(ConversationMember).where(ConversationMember.conversation_id == payload.conversation_id))).all()
    user_ids = [m.user_id for m in members if m.user_id != user.id]

    tokens = (
        await db.scalars(select(DeviceToken).where(DeviceToken.user_id.in_(user_ids)))
    ).all()

    # Здесь заглушка: вместо реальной отправки в APNS/FCM возвращаем список токенов.
    return {
        "status": "queued",
        "target_count": len(tokens),
        "targets": [token.device_token for token in tokens],
        "preview": payload.text,
    }


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[int, set[WebSocket]] = defaultdict(set)

    async def connect(self, conversation_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[conversation_id].add(websocket)

    def disconnect(self, conversation_id: int, websocket: WebSocket) -> None:
        self.active_connections[conversation_id].discard(websocket)
        if not self.active_connections[conversation_id]:
            del self.active_connections[conversation_id]

    async def broadcast(self, conversation_id: int, message: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for connection in self.active_connections.get(conversation_id, set()):
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001
                stale.append(connection)
        for conn in stale:
            self.disconnect(conversation_id, conn)


manager = ConnectionManager()


@app.websocket("/ws/{conversation_id}")
async def websocket_messages(websocket: WebSocket, conversation_id: int, token: str) -> None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = int(payload["sub"])
        username = payload["username"]
    except Exception:  # noqa: BLE001
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    async with SessionLocal() as db:
        member = await db.scalar(
            select(ConversationMember).where(
                and_(ConversationMember.conversation_id == conversation_id, ConversationMember.user_id == user_id)
            )
        )
        if not member:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await manager.connect(conversation_id, websocket)
        await manager.broadcast(
            conversation_id,
            {
                "type": "system",
                "conversation_id": conversation_id,
                "text": f"{username} joined",
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        try:
            while True:
                data = await websocket.receive_json()
                msg = MessageIn.model_validate(data)
                row = Message(
                    conversation_id=conversation_id,
                    sender_id=user_id,
                    ciphertext=msg.ciphertext,
                    nonce=msg.nonce,
                    file_url=msg.file_url,
                )
                db.add(row)
                await db.commit()
                await db.refresh(row)

                await manager.broadcast(
                    conversation_id,
                    {
                        "type": "message",
                        "id": row.id,
                        "conversation_id": conversation_id,
                        "sender_id": user_id,
                        "sender": username,
                        "ciphertext": row.ciphertext,
                        "nonce": row.nonce,
                        "file_url": row.file_url,
                        "timestamp": row.created_at.isoformat(),
                    },
                )
        except WebSocketDisconnect:
            manager.disconnect(conversation_id, websocket)
            await manager.broadcast(
                conversation_id,
                {
                    "type": "system",
                    "conversation_id": conversation_id,
                    "text": f"{username} left",
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            )


app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
