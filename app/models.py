from datetime import datetime, timezone
from enum import Enum

from pydantic import field_validator
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Status(str, Enum):
    todo = "todo"
    in_progress = "in_progress"
    done = "done"


# ---------- Users ----------

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=utcnow)


class UserCreate(SQLModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=72)  # bcrypt only uses the first 72 bytes

    @field_validator("username")
    @classmethod
    def username_chars(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("username may only contain letters, numbers, _ and -")
        return v.lower()


class UserRead(SQLModel):
    # Deliberately has no password field, so the hash can never be returned by accident
    id: int
    username: str
    created_at: datetime


class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# ---------- Tasks ----------

class TaskBase(SQLModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: Status = Status.todo


class Task(TaskBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class TaskCreate(TaskBase):
    pass


class TaskUpdate(SQLModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: Status | None = None


class TaskRead(TaskBase):
    id: int
    created_at: datetime
    updated_at: datetime
