import uuid
import os
import shutil
import io
import re
import typer
import smtplib
import logging
from html import escape
from email.message import EmailMessage
from email.utils import formataddr
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Generator, Optional

import jwt
import qrcode
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from pwdlib import PasswordHash
from sqlalchemy import JSON, Column, DateTime, Enum as SAEnum, UniqueConstraint, event
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select


# app configuration
SECRET_KEY = os.getenv(
    "CAMPUS_TRACE_SECRET_KEY",
    "campus-trace-development-secret-change-me",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REMEMBER_TOKEN_EXPIRE_DAYS = 30
DATABASE_PATH = Path(
    os.getenv(
        "CAMPUS_TRACE_DATABASE_PATH",
        str(Path(__file__).resolve().parent / "campus_trace.db"),
    )
)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"
APP_BASE_URL = os.getenv("CAMPUS_TRACE_APP_URL", "http://localhost:5173")
UPLOAD_DIR = Path(
    os.getenv(
        "CAMPUS_TRACE_UPLOAD_DIR",
        str(Path(__file__).resolve().parent / "uploads" / "item_images"),
    )
)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
QR_DIR = UPLOAD_DIR.parent / "qrcodes"
QR_DIR.mkdir(parents=True, exist_ok=True)
MAX_FOUND_IMAGES = 5
MAX_IMAGE_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

SMTP_HOST = os.getenv("CAMPUS_TRACE_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("CAMPUS_TRACE_SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("CAMPUS_TRACE_SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("CAMPUS_TRACE_SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("CAMPUS_TRACE_SMTP_FROM", SMTP_USERNAME or "no-reply@campustrace.local")
SMTP_USE_TLS = os.getenv("CAMPUS_TRACE_SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}

logger = logging.getLogger("campus_trace")


# helpers
def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def enum_column(enum_class: type[StrEnum], *, index: bool = False) -> Column:
    return Column(
        SAEnum(
            enum_class,
            values_callable=lambda values: [member.value for member in values],
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            name=f"{enum_class.__name__.lower()}_enum",
        ),
        nullable=False,
        index=index,
    )


# enums
class AdminRole(StrEnum):
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class FoundReportStatus(StrEnum):
    SUBMITTED = "submitted"
    RECEIVED = "received"
    CLOSED = "closed"
    CANCELLED = "cancelled"

class LostReportStatus(StrEnum):
    OPEN = "open"
    MATCHED = "matched"
    RESOLVED = "resolved"
    CLOSED = "closed"

class ItemStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    RESERVED = "reserved"
    RETURNED = "returned"
    ARCHIVED = "archived"

class ClaimStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    WITHDRAWN = "withdrawn"

class NotificationType(StrEnum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"

class NotificationEvent(StrEnum):
    FOUND_REPORT_CREATED = "found_report_created"
    LOST_REPORT_CREATED = "lost_report_created"
    ITEM_RECEIVED = "item_received"
    ITEM_PUBLISHED = "item_published"
    CLAIM_SUBMITTED = "claim_submitted"
    CLAIM_APPROVED = "claim_approved"
    CLAIM_REJECTED = "claim_rejected"
    ITEM_RETURNED = "item_returned"

class LogAction(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    RECEIVED = "received"
    PUBLISHED = "published"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    RETURNED = "returned"
    LOGIN = "login"
    LOGOUT = "logout"

class LogEntity(StrEnum):
    FOUND_REPORT = "found_report"
    LOST_REPORT = "lost_report"
    ITEM = "item"
    CLAIM = "claim"
    ADMIN_USER = "admin_user"
    NOTIFICATION = "notification"


# shared base models
class TimestampMixin(SQLModel):
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        nullable=False,
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        nullable=False,
        sa_column_kwargs={"onupdate": utc_now},
    )

class ContactMixin(SQLModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: str = Field(max_length=255)
    phone_number: str = Field(max_length=30)

# database models
class FoundReport(TimestampMixin, ContactMixin, table=True):
    __tablename__ = "found_reports"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    item_name: str = Field(max_length=200)
    category: str = Field(max_length=100, index=True)
    description: str
    location_found: str = Field(max_length=255)
    found_at: datetime = Field(sa_type=DateTime(timezone=True))
    additional_notes: str | None = None
    status: FoundReportStatus = Field(
        default=FoundReportStatus.SUBMITTED,
        sa_column=enum_column(FoundReportStatus),
    )
    received_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    received_by_id: uuid.UUID | None = Field(default=None, foreign_key="admin_users.id")
    received_by: Optional["AdminUser"] = Relationship(back_populates="found_reports")
    item: Optional["Item"] = Relationship(
        back_populates="found_report",
        sa_relationship_kwargs={"uselist": False},
    )

class AdminUser(TimestampMixin, table=True):
    __tablename__ = "admin_users"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    full_name: str = Field(max_length=150)
    email: str = Field(max_length=255, unique=True, index=True)
    hashed_password: str = Field(max_length=255)
    role: AdminRole = Field(default=AdminRole.ADMIN, sa_column=enum_column(AdminRole))
    is_active: bool = Field(default=True)
    found_reports: list["FoundReport"] = Relationship(back_populates="received_by")
    published_items: list["Item"] = Relationship(
        back_populates="published_by",
        sa_relationship_kwargs={"foreign_keys": "[Item.published_by_id]"},
    )
    reviewed_claims: list["Claim"] = Relationship(back_populates="reviewed_by")
    logs: list["Log"] = Relationship(back_populates="admin")
    notification_reads: list["NotificationRead"] = Relationship(back_populates="admin")

class LostReport(TimestampMixin, ContactMixin, table=True):
    __tablename__ = "lost_reports"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    item_name: str = Field(max_length=200)
    category: str = Field(max_length=100, index=True)
    description: str
    last_seen_location: str = Field(max_length=255)
    lost_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    distinguishing_features: str | None = None
    additional_notes: str | None = None
    status: LostReportStatus = Field(
        default=LostReportStatus.OPEN,
        sa_column=enum_column(LostReportStatus),
    )
    claims: list["Claim"] = Relationship(back_populates="lost_report")

class Item(TimestampMixin, table=True):
    __tablename__ = "items"
    __table_args__ = (UniqueConstraint("found_report_id", name="uq_item_found_report"),)
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    found_report_id: uuid.UUID = Field(foreign_key="found_reports.id", index=True)
    title: str = Field(max_length=200)
    category: str = Field(max_length=100, index=True)
    public_description: str
    image_url: str | None = None
    location_found: str = Field(max_length=255)
    found_at: datetime = Field(sa_type=DateTime(timezone=True))
    status: ItemStatus = Field(default=ItemStatus.DRAFT, sa_column=enum_column(ItemStatus))
    published_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    published_by_id: uuid.UUID | None = Field(default=None, foreign_key="admin_users.id")
    returned_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    admin_notes: str | None = None
    found_report: "FoundReport" = Relationship(back_populates="item")
    published_by: Optional["AdminUser"] = Relationship(
        back_populates="published_items",
        sa_relationship_kwargs={"foreign_keys": "[Item.published_by_id]"},
    )
    claims: list["Claim"] = Relationship(back_populates="item")
    verification_questions: list["VerificationQuestion"] = Relationship(back_populates="item")
    images: list["ItemImage"] = Relationship(back_populates="item")

class Claim(TimestampMixin, ContactMixin, table=True):
    __tablename__ = "claims"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    item_id: uuid.UUID = Field(foreign_key="items.id", index=True)
    lost_report_id: uuid.UUID | None = Field(default=None, foreign_key="lost_reports.id", index=True)
    claim_description: str | None = None
    status: ClaimStatus = Field(default=ClaimStatus.PENDING, sa_column=enum_column(ClaimStatus))
    reviewed_by_id: uuid.UUID | None = Field(default=None, foreign_key="admin_users.id")
    reviewed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    rejection_reason: str | None = None
    admin_notes: str | None = None
    item: "Item" = Relationship(back_populates="claims")
    lost_report: Optional["LostReport"] = Relationship(back_populates="claims")
    reviewed_by: Optional["AdminUser"] = Relationship(back_populates="reviewed_claims")
    answers: list["ClaimAnswer"] = Relationship(back_populates="claim")

class VerificationQuestion(TimestampMixin, table=True):
    __tablename__ = "verification_questions"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    item_id: uuid.UUID = Field(foreign_key="items.id", index=True)
    question: str
    is_required: bool = Field(default=True)
    sort_order: int = Field(default=0)
    item: "Item" = Relationship(back_populates="verification_questions")
    answers: list["ClaimAnswer"] = Relationship(back_populates="question")

class ClaimAnswer(TimestampMixin, table=True):
    __tablename__ = "claim_answers"
    __table_args__ = (
        UniqueConstraint("claim_id", "question_id", name="uq_claim_question_answer"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    claim_id: uuid.UUID = Field(foreign_key="claims.id", index=True)
    question_id: uuid.UUID = Field(foreign_key="verification_questions.id")
    answer: str
    is_correct: bool | None = Field(default=None)
    claim: "Claim" = Relationship(back_populates="answers")
    question: "VerificationQuestion" = Relationship(back_populates="answers")


class ItemImage(TimestampMixin, table=True):
    __tablename__ = "item_images"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    item_id: uuid.UUID = Field(foreign_key="items.id", index=True)
    file_path: str = Field(max_length=500)
    url: str = Field(max_length=500)
    sort_order: int = Field(default=0)
    item: "Item" = Relationship(back_populates="images")

class Log(SQLModel, table=True):
    __tablename__ = "logs"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    admin_id: uuid.UUID | None = Field(default=None, foreign_key="admin_users.id", index=True)
    action: LogAction = Field(sa_column=enum_column(LogAction, index=True))
    entity: LogEntity = Field(sa_column=enum_column(LogEntity, index=True))
    entity_id: uuid.UUID | None = Field(default=None, index=True)
    description: str
    metadata_: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column("metadata", JSON, nullable=False),
    )
    ip_address: str | None = Field(default=None, max_length=45)
    user_agent: str | None = None
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), default=utc_now, nullable=False),
    )
    admin: Optional["AdminUser"] = Relationship(back_populates="logs")

class Notification(SQLModel, table=True):
    __tablename__ = "notifications"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    title: str = Field(max_length=200)
    message: str
    type: NotificationType = Field(
        default=NotificationType.INFO,
        sa_column=enum_column(NotificationType, index=True),
    )
    event: NotificationEvent = Field(sa_column=enum_column(NotificationEvent, index=True))
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), default=utc_now, nullable=False),
    )
    reads: list["NotificationRead"] = Relationship(back_populates="notification")

class NotificationRead(SQLModel, table=True):
    __tablename__ = "notification_reads"
    __table_args__ = (
        UniqueConstraint("notification_id", "admin_id", name="uq_notification_admin_read"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    notification_id: uuid.UUID = Field(
        foreign_key="notifications.id",
        index=True,
        ondelete="CASCADE",
    )
    admin_id: uuid.UUID = Field(
        foreign_key="admin_users.id",
        index=True,
        ondelete="CASCADE",
    )
    read_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), default=utc_now, nullable=False),
    )
    notification: "Notification" = Relationship(back_populates="reads")
    admin: "AdminUser" = Relationship(back_populates="notification_reads")


# database setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

@event.listens_for(engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection: Any, _: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

def create_bootstrap_admin() -> None:
    email = os.getenv("CAMPUS_TRACE_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("CAMPUS_TRACE_BOOTSTRAP_ADMIN_PASSWORD", "")
    full_name = os.getenv("CAMPUS_TRACE_BOOTSTRAP_ADMIN_NAME", "").strip()
    if not email or not password or not full_name:
        return
    with Session(engine) as session:
        existing = session.exec(select(AdminUser).where(AdminUser.email == email)).first()
        if existing:
            return
        session.add(
            AdminUser(
                full_name=full_name,
                email=email,
                hashed_password=password_hash.hash(password),
                role=AdminRole.SUPER_ADMIN,
            )
        )
        session.commit()
        logger.info("Created bootstrap super administrator %s", email)

@asynccontextmanager
async def lifespan(_: FastAPI):
    create_db_and_tables()
    create_bootstrap_admin()
    yield


app = FastAPI(lifespan=lifespan)
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CAMPUS_TRACE_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_origin_regex=os.getenv(
        "CAMPUS_TRACE_CORS_ORIGIN_REGEX",
        r"https://campus-trace(?:-[a-z0-9]+)?\.onrender\.com",
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR.parent), name="uploads")


# pydantic models
class UserCredentials(BaseModel):
    username: str
    password: str
    remember_me: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class AdminRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    full_name: str
    email: str
    role: AdminRole
    is_active: bool
    created_at: datetime
    updated_at: datetime

class AdminCreate(BaseModel):
    full_name: str
    email: str
    password: str
    role: AdminRole = AdminRole.ADMIN

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 2:
            raise ValueError("Full name must contain at least 2 characters")
        return normalized

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters")
        return value

class AdminUpdate(BaseModel):
    full_name: str
    email: str
    role: AdminRole
    is_active: bool
    password: str | None = None

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 2:
            raise ValueError("Full name must contain at least 2 characters")
        return normalized

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_optional_password(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters")
        return value

class ReceiveItemRequest(BaseModel):
    title: str
    public_description: str
    image_url: str | None = None
    image_urls: list[str] | None = None
    admin_notes: str | None = None
    verification_questions: list[str]

    @field_validator("title", "public_description")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("This field is required")
        return normalized

    @field_validator("verification_questions")
    @classmethod
    def validate_questions(cls, values: list[str]) -> list[str]:
        questions = [value.strip() for value in values if value.strip()]
        if not questions:
            raise ValueError("Add at least one private ownership question")
        return questions

class LostReportStatusRequest(BaseModel):
    status: LostReportStatus

class ClaimDecisionRequest(BaseModel):
    decision: str
    rejection_reason: str | None = None
    admin_notes: str | None = None

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        if value not in {"approve", "reject"}:
            raise ValueError("Decision must be approve or reject")
        return value


# authentication
def create_access_token(admin: AdminUser, remember_me: bool = False) -> str:
    expires_at = utc_now() + (
        timedelta(days=REMEMBER_TOKEN_EXPIRE_DAYS)
        if remember_me
        else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return jwt.encode(
        {"sub": str(admin.id), "exp": expires_at},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

def unauthorized_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

def get_current_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> AdminUser:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id = uuid.UUID(payload.get("sub", ""))
    except (InvalidTokenError, TypeError, ValueError):
        raise unauthorized_exception()
    admin = session.get(AdminUser, admin_id)
    if not admin or not admin.is_active:
        raise unauthorized_exception()
    return admin

def require_super_admin(
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
) -> AdminUser:
    if current_admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super administrator access is required",
        )
    return current_admin

def found_report_data(report: FoundReport) -> dict[str, Any]:
    images = []
    if report.additional_notes and "Uploaded images:" in report.additional_notes:
        try:
            idx = report.additional_notes.index("Uploaded images:")
            tail = report.additional_notes[idx + len("Uploaded images:"):].strip()
            images = [p.strip() for p in tail.split(",") if p.strip().startswith("/")]
        except Exception:
            images = []
    notes = report.additional_notes
    if notes and "Uploaded images:" in notes:
        notes = notes.split("Uploaded images:")[0].strip() or None
    return {
        "id": report.id,
        "full_name": report.full_name,
        "email": report.email,
        "phone_number": report.phone_number,
        "item_name": report.item_name,
        "category": report.category,
        "description": report.description,
        "location_found": report.location_found,
        "found_at": report.found_at,
        "additional_notes": notes,
        "uploaded_images": images,
        "status": report.status,
        "received_at": report.received_at,
        "received_by_name": report.received_by.full_name if report.received_by else None,
        "created_at": report.created_at,
        "updated_at": report.updated_at,
        "item": item_data(report.item) if report.item else None,
    }

def lost_report_data(report: LostReport) -> dict[str, Any]:
    return {
        "id": report.id,
        "full_name": report.full_name,
        "email": report.email,
        "phone_number": report.phone_number,
        "item_name": report.item_name,
        "category": report.category,
        "description": report.description,
        "last_seen_location": report.last_seen_location,
        "lost_at": report.lost_at,
        "distinguishing_features": report.distinguishing_features,
        "additional_notes": report.additional_notes,
        "status": report.status,
        "claim_count": len(report.claims),
        "created_at": report.created_at,
        "updated_at": report.updated_at,
    }

def item_data(item: Item | None) -> dict[str, Any] | None:
    if not item:
        return None
    imgs = [img.url for img in sorted(getattr(item, "images", []) or [], key=lambda x: x.sort_order)]
    return {
        "id": item.id,
        "found_report_id": item.found_report_id,
        "title": item.title,
        "category": item.category,
        "public_description": item.public_description,
        "image_url": imgs[0] if imgs else item.image_url,
        "image_urls": imgs or ([item.image_url] if item.image_url else []),
        "location_found": item.location_found,
        "found_at": item.found_at,
        "status": item.status,
        "published_at": item.published_at,
        "published_by_name": item.published_by.full_name if item.published_by else None,
        "returned_at": item.returned_at,
        "admin_notes": item.admin_notes,
        "verification_questions": [
            {"id": question.id, "question": question.question, "is_required": question.is_required}
            for question in sorted(item.verification_questions, key=lambda value: value.sort_order)
        ],
    }

def claim_data(claim: Claim, *, include_answers: bool = False) -> dict[str, Any]:
    data = {
        "id": claim.id,
        "item_id": claim.item_id,
        "item_title": claim.item.title,
        "full_name": claim.full_name,
        "email": claim.email,
        "phone_number": claim.phone_number,
        "claim_description": claim.claim_description,
        "status": claim.status,
        "lost_report_id": claim.lost_report_id,
        "reviewed_by_name": claim.reviewed_by.full_name if claim.reviewed_by else None,
        "reviewed_at": claim.reviewed_at,
        "rejection_reason": claim.rejection_reason,
        "admin_notes": claim.admin_notes,
        "created_at": claim.created_at,
        "updated_at": claim.updated_at,
        "item_status": claim.item.status,
    }
    if include_answers:
        data["answers"] = [
            {
                "id": answer.id,
                "question": answer.question.question,
                "answer": answer.answer,
                "is_correct": answer.is_correct,
            }
            for answer in claim.answers
        ]
    return data

def add_notification(
    session: Session,
    *,
    title: str,
    message: str,
    notification_type: NotificationType,
    event_type: NotificationEvent,
) -> None:
    session.add(
        Notification(
            title=title,
            message=message,
            type=notification_type,
            event=event_type,
        )
    )


# cli
cli = typer.Typer(no_args_is_help=True, help="Campus Trace administration commands.")

@cli.callback()
def cli_root() -> None:
    """Manage the Campus Trace backend."""

@cli.command("create-admin")
def create_admin(
    full_name: str = typer.Option(..., prompt="Full name"),
    email: str = typer.Option(..., prompt="Email address"),
    password: str = typer.Option(
        ...,
        prompt="Password",
        hide_input=True,
        confirmation_prompt=True,
    ),
    super_admin: bool = typer.Option(
        False,
        "--super-admin",
        help="Grant permission to manage other administrators.",
    ),
) -> None:
    """Create an administrator account for dashboard access."""
    normalized_email = email.strip().lower()
    normalized_name = full_name.strip()
    if len(normalized_name) < 2:
        typer.secho("Full name must contain at least 2 characters.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if "@" not in normalized_email or normalized_email.startswith("@") or normalized_email.endswith("@"):
        typer.secho("Enter a valid email address.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if len(password) < 8:
        typer.secho("Password must contain at least 8 characters.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    create_db_and_tables()
    with Session(engine) as session:
        existing_admin = session.exec(
            select(AdminUser).where(AdminUser.email == normalized_email)
        ).first()
        if existing_admin:
            typer.secho(
                f"An administrator with {normalized_email} already exists.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        admin = AdminUser(
            full_name=normalized_name,
            email=normalized_email,
            hashed_password=password_hash.hash(password),
            role=AdminRole.SUPER_ADMIN if super_admin else AdminRole.ADMIN,
        )
        session.add(admin)
        session.commit()
    typer.secho(f"Created administrator {normalized_email}.", fg=typer.colors.GREEN)


@app.get("/")
def index():
    return {"name": "Campus Trace API", "status": "ready"}

@app.post("/login", response_model=Token)
def login(credentials: UserCredentials, session: Annotated[Session, Depends(get_session)]):
    normalized_email = credentials.username.strip().lower()
    admin = session.exec(
        select(AdminUser).where(AdminUser.email == normalized_email)
    ).first()

    if not admin or not admin.is_active or not password_hash.verify(credentials.password, admin.hashed_password):
        raise unauthorized_exception()

    session.add(
        Log(
            admin_id=admin.id,
            action=LogAction.LOGIN,
            entity=LogEntity.ADMIN_USER,
            entity_id=admin.id,
            description="Administrator signed in",
        )
    )
    session.commit()
    return Token(
        access_token=create_access_token(admin, credentials.remember_me),
        token_type="bearer",
    )

@app.get("/admin/me", response_model=AdminRead)
def get_admin_profile(current_admin: Annotated[AdminUser, Depends(get_current_admin)]):
    return current_admin


@app.post("/admin/accounts", response_model=AdminRead, status_code=status.HTTP_201_CREATED)
def create_admin_account(
    account: AdminCreate,
    current_admin: Annotated[AdminUser, Depends(require_super_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    existing_admin = session.exec(
        select(AdminUser).where(AdminUser.email == account.email)
    ).first()
    if existing_admin:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An administrator with this email already exists",
        )
    admin = AdminUser(
        full_name=account.full_name,
        email=account.email,
        hashed_password=password_hash.hash(account.password),
        role=account.role,
    )
    session.add(admin)
    session.flush()
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.CREATED,
            entity=LogEntity.ADMIN_USER,
            entity_id=admin.id,
            description=f"Created administrator account for {admin.email}",
        )
    )
    session.commit()
    session.refresh(admin)
    return admin

@app.get("/admin/accounts", response_model=list[AdminRead])
def get_admin_accounts(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    return session.exec(
        select(AdminUser).order_by(AdminUser.created_at.desc())
    ).all()

@app.put("/admin/accounts/{admin_id}", response_model=AdminRead)
def edit_admin_account(
    admin_id: uuid.UUID,
    account: AdminUpdate,
    current_admin: Annotated[AdminUser, Depends(require_super_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    admin = session.get(AdminUser, admin_id)
    if not admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Administrator not found")
    if admin.id == current_admin.id and (
        account.role != current_admin.role or not account.is_active
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role or deactivate your own account",
        )
    duplicate = session.exec(
        select(AdminUser).where(
            AdminUser.email == account.email,
            AdminUser.id != admin.id,
        )
    ).first()
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An administrator with this email already exists",
        )
    admin.full_name = account.full_name
    admin.email = account.email
    admin.role = account.role
    admin.is_active = account.is_active
    if account.password:
        admin.hashed_password = password_hash.hash(account.password)
    session.add(admin)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.UPDATED,
            entity=LogEntity.ADMIN_USER,
            entity_id=admin.id,
            description=f"Updated administrator account for {admin.email}",
        )
    )
    session.commit()
    session.refresh(admin)
    return admin

@app.delete("/admin/accounts/{admin_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_admin_account(
    admin_id: uuid.UUID,
    current_admin: Annotated[AdminUser, Depends(require_super_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    admin = session.get(AdminUser, admin_id)
    if not admin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Administrator not found")
    if admin.id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account",
        )
    admin.is_active = False
    session.add(admin)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.UPDATED,
            entity=LogEntity.ADMIN_USER,
            entity_id=admin.id,
            description=f"Deactivated administrator account for {admin.email}",
        )
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/admin/dashboard")
def get_dashboard(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    found_reports = session.exec(select(FoundReport)).all()
    lost_reports = session.exec(select(LostReport)).all()
    items = session.exec(select(Item)).all()
    claims = session.exec(select(Claim)).all()
    recent_logs = session.exec(select(Log).order_by(Log.created_at.desc()).limit(6)).all()
    queue = []
    for report in found_reports:
        if report.status == FoundReportStatus.SUBMITTED:
            queue.append(("receipt", report.id, report.item_name, report.location_found, report.created_at))
    for item in items:
        if item.status == ItemStatus.DRAFT:
            queue.append(("publish", item.found_report_id, item.title, item.location_found, item.created_at))
    for claim in claims:
        if claim.status in (ClaimStatus.PENDING, ClaimStatus.APPROVED):
            stage = "review" if claim.status == ClaimStatus.PENDING else "handover"
            queue.append((stage, claim.id, claim.item.title, claim.item.location_found, claim.reviewed_at or claim.created_at))
    return {
        "work_queue": [
            dict(stage=stage, id=record_id, title=title, location=location, since=since)
            for stage, record_id, title, location, since in sorted(queue, key=lambda row: row[-1])
        ],
        "counts": {
            "found_waiting": sum(report.status == FoundReportStatus.SUBMITTED for report in found_reports),
            "lost_open": sum(report.status == LostReportStatus.OPEN for report in lost_reports),
            "items_published": sum(item.status == ItemStatus.PUBLISHED for item in items),
            "claims_pending": sum(claim.status == ClaimStatus.PENDING for claim in claims),
            "items_returned": sum(item.status == ItemStatus.RETURNED for item in items),
        },
        "recent_activity": [
            {
                "id": log.id,
                "action": log.action,
                "entity": log.entity,
                "description": log.description,
                "admin_name": log.admin.full_name if log.admin else "System",
                "created_at": log.created_at,
            }
            for log in recent_logs
        ],
    }

@app.get("/admin/reports/found")
def get_found_reports(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    reports = session.exec(select(FoundReport).order_by(FoundReport.created_at.desc())).all()
    return [found_report_data(report) for report in reports]

@app.get("/admin/reports/found/{report_id}")
def get_found_report(
    report_id: uuid.UUID,
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    report = session.get(FoundReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Found report not found")
    return found_report_data(report)

@app.post("/admin/reports/found/{report_id}/receive")
def receive_found_item(
    report_id: uuid.UUID,
    request: ReceiveItemRequest,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    report = session.get(FoundReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Found report not found")
    if report.status != FoundReportStatus.SUBMITTED or report.item:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This report has already been received")
    urls = request.image_urls or ([request.image_url] if request.image_url else [])
    if not urls and report.additional_notes and "Uploaded images:" in report.additional_notes:
        uploaded = report.additional_notes.split("Uploaded images:", 1)[1]
        urls = [value.strip() for value in uploaded.split(",") if value.strip().startswith("/uploads/")]
    item = Item(
        found_report_id=report.id,
        title=request.title,
        category=report.category,
        public_description=request.public_description,
        image_url=urls[0] if urls else None,
        location_found=report.location_found,
        found_at=report.found_at,
        admin_notes=request.admin_notes,
    )
    session.add(item)
    session.flush()
    for idx, u in enumerate(urls[:10]):
        if u:
            session.add(ItemImage(item_id=item.id, url=u, file_path=u, sort_order=idx))
    for order, question in enumerate(request.verification_questions):
        session.add(
            VerificationQuestion(item_id=item.id, question=question, sort_order=order)
        )
    report.status = FoundReportStatus.RECEIVED
    report.received_at = utc_now()
    report.received_by_id = current_admin.id
    session.add(report)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.RECEIVED,
            entity=LogEntity.ITEM,
            entity_id=item.id,
            description=f"Received {item.title} from {report.full_name}",
        )
    )
    add_notification(
        session,
        title="Found item received",
        message=f"{item.title} is ready for review and publication.",
        notification_type=NotificationType.INFO,
        event_type=NotificationEvent.ITEM_RECEIVED,
    )
    session.commit()
    session.refresh(report)
    return found_report_data(report)

@app.post("/admin/items/{item_id}/publish")
def publish_item(
    item_id: uuid.UUID,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    if item.status != ItemStatus.DRAFT:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only draft items can be published")
    if not item.verification_questions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Add at least one ownership question before publication",
        )
    item.status = ItemStatus.PUBLISHED
    item.published_at = utc_now()
    item.published_by_id = current_admin.id
    session.add(item)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.PUBLISHED,
            entity=LogEntity.ITEM,
            entity_id=item.id,
            description=f"Published {item.title} in the public catalogue",
        )
    )
    add_notification(
        session,
        title="Item published",
        message=f"{item.title} is now visible in the found-items catalogue.",
        notification_type=NotificationType.SUCCESS,
        event_type=NotificationEvent.ITEM_PUBLISHED,
    )
    session.commit()
    session.refresh(item)
    return item_data(item)

@app.get("/admin/reports/lost")
def get_lost_reports(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    reports = session.exec(select(LostReport).order_by(LostReport.created_at.desc())).all()
    return [lost_report_data(report) for report in reports]

@app.get("/admin/reports/lost/{report_id}")
def get_lost_report(
    report_id: uuid.UUID,
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    report = session.get(LostReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lost report not found")
    data = lost_report_data(report)
    data["claims"] = [claim_data(claim) for claim in report.claims]
    return data

@app.put("/admin/reports/lost/{report_id}/status")
def update_lost_report_status(
    report_id: uuid.UUID,
    request: LostReportStatusRequest,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    report = session.get(LostReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lost report not found")
    if request.status not in {LostReportStatus.OPEN, LostReportStatus.CLOSED}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Matched and resolved states are controlled by the claim workflow",
        )
    report.status = request.status
    session.add(report)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.UPDATED,
            entity=LogEntity.LOST_REPORT,
            entity_id=report.id,
            description=f"Set lost report for {report.item_name} to {report.status.value}",
        )
    )
    session.commit()
    session.refresh(report)
    return lost_report_data(report)

@app.get("/admin/claims")
def get_claims(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    claims = session.exec(select(Claim).order_by(Claim.created_at.desc())).all()
    return [claim_data(claim) for claim in claims]

@app.get("/admin/claims/{claim_id}")
def get_claim(
    claim_id: uuid.UUID,
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    claim = session.get(Claim, claim_id)
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")
    return claim_data(claim, include_answers=True)

def render_claim_decision_email_html(claim: Claim, approved: bool) -> str:
    item_title = escape(claim.item.title if claim.item else "your item")
    claimant_name = escape(claim.full_name)
    heading = "Claim approved" if approved else "Claim update"
    decision = (
        f"Your claim for <strong>{item_title}</strong> has been approved by the Campus Trace desk."
        if approved
        else f"Your claim for <strong>{item_title}</strong> was not approved by the Campus Trace desk."
    )
    next_step = (
        "Please wait for pickup instructions from the desk before collecting the item. "
        "Bring a valid ID and your claim reference when you go."
        if approved
        else "You may continue checking the public catalogue for other matching items. "
        "Contact the campus lost-property desk if you need help."
    )
    return f"""
<!doctype html>
<html>
<body style=\"font-family: Arial, sans-serif; color: #173552; line-height: 1.5;\">
  <div style=\"max-width: 560px; margin: 0 auto; padding: 24px;\">
    <h2 style=\"margin-top: 0;\">{heading}</h2>
    <p>Hi {claimant_name},</p>
    <p>{decision}</p>
    <p>{next_step}</p>
    <p style=\"margin-top: 24px;\">Campus Trace</p>
  </div>
</body>
</html>
"""


def send_claim_decision_email(claim: Claim, approved: bool) -> None:
    if not SMTP_HOST or not claim.email:
        return
    item_title = claim.item.title if claim.item else "your item"
    status_text = "approved" if approved else "not approved"
    msg = EmailMessage()
    msg["Subject"] = f"Campus Trace: Claim update for {item_title}"
    msg["From"] = formataddr(("Campus Trace", SMTP_FROM))
    msg["To"] = claim.email
    msg.set_content(
        f"Hi {claim.full_name},\n\nYour claim for {item_title} was {status_text}. "
        + ("Wait for pickup instructions from the desk." if approved else "You may continue checking the catalogue for other matching items.")
        + "\n\nCampus Trace"
    )
    msg.add_alternative(render_claim_decision_email_html(claim, approved), subtype="html")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as exc:
        logger.warning("Claim decision email failed for claim %s: %s", claim.id, exc)


@app.post("/admin/claims/{claim_id}/decision")
def decide_claim(
    claim_id: uuid.UUID,
    request: ClaimDecisionRequest,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    claim = session.get(Claim, claim_id)
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")
    if claim.status != ClaimStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This claim has already been reviewed")
    if request.decision == "reject" and not (request.rejection_reason or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Give a reason for rejection")
    automatically_rejected: list[Claim] = []
    if request.decision == "approve":
        if claim.item.status != ItemStatus.PUBLISHED:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This item is not available")
        claim.status = ClaimStatus.APPROVED
        claim.item.status = ItemStatus.RESERVED
        if claim.lost_report:
            claim.lost_report.status = LostReportStatus.MATCHED
            session.add(claim.lost_report)
        for competing_claim in claim.item.claims:
            if competing_claim.id != claim.id and competing_claim.status == ClaimStatus.PENDING:
                competing_claim.status = ClaimStatus.REJECTED
                competing_claim.rejection_reason = "Another claimant was verified as the owner"
                competing_claim.reviewed_by_id = current_admin.id
                competing_claim.reviewed_at = utc_now()
                session.add(competing_claim)
                automatically_rejected.append(competing_claim)
        action = LogAction.APPROVED
        event_type = NotificationEvent.CLAIM_APPROVED
        notification_type = NotificationType.SUCCESS
    else:
        claim.status = ClaimStatus.REJECTED
        claim.rejection_reason = request.rejection_reason.strip()
        action = LogAction.REJECTED
        event_type = NotificationEvent.CLAIM_REJECTED
        notification_type = NotificationType.WARNING
    claim.admin_notes = request.admin_notes
    claim.reviewed_by_id = current_admin.id
    claim.reviewed_at = utc_now()
    session.add(claim)
    session.add(claim.item)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=action,
            entity=LogEntity.CLAIM,
            entity_id=claim.id,
            description=(
                f"{'Approved' if request.decision == 'approve' else 'Rejected'} "
                f"claim by {claim.full_name} for {claim.item.title}"
            ),
        )
    )
    add_notification(
        session,
        title=f"Claim {claim.status.value}",
        message=f"The claim by {claim.full_name} for {claim.item.title} was {claim.status.value}.",
        notification_type=notification_type,
        event_type=event_type,
    )
    session.commit()
    send_claim_decision_email(claim, request.decision == "approve")
    for rejected_claim in automatically_rejected:
        send_claim_decision_email(rejected_claim, False)
    session.refresh(claim)
    return claim_data(claim, include_answers=True)

@app.post("/admin/claims/{claim_id}/complete")
def complete_claim_return(
    claim_id: uuid.UUID,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    claim = session.get(Claim, claim_id)
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")
    if claim.status != ClaimStatus.APPROVED or claim.item.status != ItemStatus.RESERVED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only an approved, reserved claim can be completed",
        )
    claim.status = ClaimStatus.COMPLETED
    claim.item.status = ItemStatus.RETURNED
    claim.item.returned_at = utc_now()
    claim.item.found_report.status = FoundReportStatus.CLOSED
    if claim.lost_report:
        claim.lost_report.status = LostReportStatus.RESOLVED
        session.add(claim.lost_report)
    session.add(claim)
    session.add(claim.item)
    session.add(claim.item.found_report)
    session.add(
        Log(
            admin_id=current_admin.id,
            action=LogAction.RETURNED,
            entity=LogEntity.ITEM,
            entity_id=claim.item.id,
            description=f"Returned {claim.item.title} to {claim.full_name}",
        )
    )
    add_notification(
        session,
        title="Item returned",
        message=f"{claim.item.title} was collected by its verified owner.",
        notification_type=NotificationType.SUCCESS,
        event_type=NotificationEvent.ITEM_RETURNED,
    )
    session.commit()
    session.refresh(claim)
    return claim_data(claim, include_answers=True)

@app.get("/admin/returned")
def get_returned_items(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    items = session.exec(
        select(Item).where(Item.status == ItemStatus.RETURNED).order_by(Item.returned_at.desc())
    ).all()
    results = []
    for item in items:
        completed_claim = next(
            (claim for claim in item.claims if claim.status == ClaimStatus.COMPLETED),
            None,
        )
        data = item_data(item)
        data["owner_name"] = completed_claim.full_name if completed_claim else None
        data["claim_id"] = completed_claim.id if completed_claim else None
        results.append(data)
    return results

@app.get("/admin/notifications")
def get_notifications(
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    notifications = session.exec(
        select(Notification).order_by(Notification.created_at.desc())
    ).all()
    read_ids = {
        value.notification_id
        for value in session.exec(
            select(NotificationRead).where(NotificationRead.admin_id == current_admin.id)
        ).all()
    }
    return [
        {
            "id": notification.id,
            "title": notification.title,
            "message": notification.message,
            "type": notification.type,
            "event": notification.event,
            "created_at": notification.created_at,
            "is_read": notification.id in read_ids,
        }
        for notification in notifications
    ]

@app.post("/admin/notifications/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
def mark_notification_read(
    notification_id: uuid.UUID,
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    if not session.get(Notification, notification_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")
    existing = session.exec(
        select(NotificationRead).where(
            NotificationRead.notification_id == notification_id,
            NotificationRead.admin_id == current_admin.id,
        )
    ).first()
    if not existing:
        session.add(NotificationRead(notification_id=notification_id, admin_id=current_admin.id))
        session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.post("/admin/notifications/read-all", status_code=status.HTTP_204_NO_CONTENT)
def mark_all_notifications_read(
    current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    notifications = session.exec(select(Notification)).all()
    read_ids = {
        value.notification_id
        for value in session.exec(
            select(NotificationRead).where(NotificationRead.admin_id == current_admin.id)
        ).all()
    }
    for notification in notifications:
        if notification.id not in read_ids:
            session.add(NotificationRead(notification_id=notification.id, admin_id=current_admin.id))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/admin/logs")
def get_activity_logs(
    _current_admin: Annotated[AdminUser, Depends(get_current_admin)],
    session: Annotated[Session, Depends(get_session)],
):
    logs = session.exec(select(Log).order_by(Log.created_at.desc())).all()
    return [
        {
            "id": log.id,
            "action": log.action,
            "entity": log.entity,
            "entity_id": log.entity_id,
            "description": log.description,
            "admin_name": log.admin.full_name if log.admin else "System",
            "created_at": log.created_at,
        }
        for log in logs
    ]


class PublicContact(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    full_name: Annotated[str, Field(min_length=2, max_length=150)]
    email: Annotated[str, StringConstraints(max_length=255, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
    phone_number: Annotated[str, Field(min_length=1, max_length=30)]


class PublicReport(PublicContact):
    item_name: Annotated[str, Field(min_length=1, max_length=200)]
    category: Annotated[str, Field(min_length=1, max_length=100)]
    description: Annotated[str, Field(min_length=1, max_length=4000)]

class FinderReportInput(PublicReport):
    location_found: Annotated[str, Field(min_length=1, max_length=255)]
    found_at: datetime

class LostReportInput(PublicReport):
    last_seen_location: Annotated[str, Field(min_length=1, max_length=255)]
    lost_at: datetime | None = None

class OwnershipInput(PublicContact):
    claim_description: Annotated[str, Field(min_length=1, max_length=4000)]
    answers: dict[uuid.UUID, Annotated[str, Field(min_length=1, max_length=2000)]]

def record_public_submission(session, record, entity, event_type, title, message):
    session.add(record)
    session.flush()
    session.add(Log(action=LogAction.SUBMITTED, entity=entity, entity_id=record.id, description=message))
    add_notification(session, title=title, message=message, notification_type=NotificationType.INFO, event_type=event_type)
    reference = record.id
    session.commit()
    return {"reference": reference}

def _save_image_file(upload: UploadFile) -> str:
    if upload.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail="Only JPEG, PNG, or WebP images are allowed.")
    ext = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}.get(upload.content_type, ".jpg")
    filename = f"{uuid.uuid4()}{ext}"
    dest = UPLOAD_DIR / filename
    size = 0
    with dest.open("wb") as f:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_IMAGE_BYTES:
                f.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=400, detail="Each image must be 5 MB or smaller.")
            f.write(chunk)
    return f"/uploads/item_images/{filename}"


@app.post("/public/reports/found", status_code=201)
async def submit_found_report(
    item_name: Annotated[str, Form(...)],
    category: Annotated[str, Form(...)],
    description: Annotated[str, Form(...)],
    full_name: Annotated[str, Form(...)],
    email: Annotated[str, Form(...)],
    phone_number: Annotated[str, Form(...)],
    location_found: Annotated[str, Form(...)],
    found_at: Annotated[str, Form(...)],
    images: list[UploadFile] | None = File(default=None),
    session: Session = Depends(get_session),
):
    if not images or not 3 <= len(images) <= MAX_FOUND_IMAGES:
        raise HTTPException(status_code=400, detail="Upload between 3 and 5 images.")
    try:
        found_dt = datetime.fromisoformat(found_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid found_at value.")
    report = FoundReport(
        item_name=item_name,
        category=category,
        description=description,
        full_name=full_name,
        email=email,
        phone_number=phone_number,
        location_found=location_found,
        found_at=found_dt,
    )
    session.add(report)
    session.flush()
    saved_paths: list[str] = []
    for upload in (images or [])[:MAX_FOUND_IMAGES]:
        if upload.filename:
            saved_paths.append(_save_image_file(upload))
    report.additional_notes = report.additional_notes or ""
    if saved_paths:
        report.additional_notes = (report.additional_notes + ("\n" if report.additional_notes else "") + "Uploaded images: " + ", ".join(saved_paths)).strip()
    session.add(Log(action=LogAction.SUBMITTED, entity=LogEntity.FOUND_REPORT, entity_id=report.id, description=f"Finder reported {report.item_name}"))
    add_notification(session, title="New found report", message=f"Finder reported {report.item_name}", notification_type=NotificationType.INFO, event_type=NotificationEvent.FOUND_REPORT_CREATED)
    session.commit()
    return {"reference": report.id, "images_saved": len(saved_paths)}

@app.post("/public/reports/lost", status_code=201)
def submit_lost_report(body: LostReportInput, session: Annotated[Session, Depends(get_session)]):
    return record_public_submission(session, LostReport(**body.model_dump()), LogEntity.LOST_REPORT,
                                    NotificationEvent.LOST_REPORT_CREATED, "New lost report",
                                    f"Owner reported {body.item_name} missing")

def item_images_data(item: Item) -> list[str]:
    return [img.url for img in sorted(getattr(item, "images", []) or [], key=lambda x: x.sort_order)]


def catalogue_entry(item):
    return {"id": item.id, "title": item.title, "category": item.category,
            "location_found": item.location_found, "found_at": item.found_at,
            "public_description": item.public_description}

def published_item(session, item_id):
    item = session.exec(select(Item).where(Item.id == item_id, Item.status == ItemStatus.PUBLISHED)).first()
    if not item:
        raise HTTPException(404, "This item is no longer available in the catalogue.")
    return item

@app.get("/public/items")
def public_catalogue(session: Annotated[Session, Depends(get_session)]):
    items = session.exec(select(Item).where(Item.status == ItemStatus.PUBLISHED).order_by(Item.published_at.desc()))
    return [catalogue_entry(item) for item in items]

@app.get("/public/items/{item_id}")
def public_item(item_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]):
    item = published_item(session, item_id)
    return {**catalogue_entry(item), "questions": [
        {"id": q.id, "question": q.question, "is_required": q.is_required}
        for q in sorted(item.verification_questions, key=lambda q: q.sort_order)
    ]}

@app.post("/public/items/{item_id}/claims", status_code=201)
def submit_ownership_claim(item_id: uuid.UUID, body: OwnershipInput, session: Annotated[Session, Depends(get_session)]):
    item = published_item(session, item_id)
    questions = {q.id: q for q in item.verification_questions}
    if body.answers.keys() - questions.keys() or any(q.is_required and q.id not in body.answers for q in questions.values()):
        raise HTTPException(422, "Answer each required ownership question for this item.")
    claim = Claim(item_id=item.id, **body.model_dump(exclude={"answers"}))
    claim.answers = [ClaimAnswer(question_id=key, answer=value) for key, value in body.answers.items()]
    return record_public_submission(session, claim, LogEntity.CLAIM, NotificationEvent.CLAIM_SUBMITTED,
                                    "New ownership claim", f"Ownership claim submitted for {item.title}")

@app.get("/admin/qr")
def get_qr_code(
    target: str = Query(..., pattern="^(home|found|lost|claim)$"),
    base_url: str | None = Query(default=None),
    current_admin: Annotated[AdminUser, Depends(get_current_admin)] = None,
):
    path_map = {"home": "/", "found": "/report-found", "lost": "/report-lost", "claim": "/item"}
    base = (base_url or APP_BASE_URL).rstrip("/")
    url = f"{base}{path_map[target]}"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png", headers={"Content-Disposition": f"attachment; filename=campus-trace-{target}-qr.png"})


@app.get("/logout")
async def logout():
    return {"success": True}


if __name__ == "__main__":
    cli()
