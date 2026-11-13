from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from .db import get_session, init_db
from .models import (
    Status, Task, TaskCreate, TaskRead, TaskUpdate, Token, User, UserCreate, UserRead, utcnow,
)
from .security import create_access_token, get_current_user, hash_password, verify_password


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Secure Task API",
    description="A task tracker REST API with JWT authentication and per-user access control.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


# ---------- Auth ----------

@app.post("/auth/register", response_model=UserRead, status_code=201, tags=["auth"])
def register(data: UserCreate, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == data.username)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")
    user = User(username=data.username, hashed_password=hash_password(data.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form.username.lower())).first()
    # Same error for "no such user" and "wrong password", so attackers can't enumerate usernames
    if not verify_password(form.password, user.hashed_password if user else None):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    return Token(access_token=create_access_token(user.id))


@app.get("/auth/me", response_model=UserRead, tags=["auth"])
def me(user: User = Depends(get_current_user)):
    return user


# ---------- Tasks ----------

def get_owned_task(task_id: int, user: User, session: Session) -> Task:
    """Fetch a task only if it belongs to the user.

    Returns 404 (not 403) for other users' tasks so attackers can't tell which IDs exist.
    This is the fix for IDOR (Insecure Direct Object Reference) vulnerabilities.
    """
    task = session.get(Task, task_id)
    if task is None or task.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Task not found")
    return task


@app.post("/tasks", response_model=TaskRead, status_code=201, tags=["tasks"])
def create_task(data: TaskCreate, user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    # owner_id comes from the token, never from the request body (prevents mass assignment)
    task = Task(**data.model_dump(), owner_id=user.id)
    session.add(task)
    session.commit()
    session.refresh(task)
    return task


@app.get("/tasks", response_model=list[TaskRead], tags=["tasks"])
def list_tasks(status_filter: Status | None = None, limit: int = 50, offset: int = 0,
               user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    limit = max(1, min(limit, 100))
    query = select(Task).where(Task.owner_id == user.id)
    if status_filter:
        query = query.where(Task.status == status_filter)
    return session.exec(query.order_by(Task.id).offset(max(offset, 0)).limit(limit)).all()


@app.get("/tasks/{task_id}", response_model=TaskRead, tags=["tasks"])
def read_task(task_id: int, user: User = Depends(get_current_user),
              session: Session = Depends(get_session)):
    return get_owned_task(task_id, user, session)


@app.patch("/tasks/{task_id}", response_model=TaskRead, tags=["tasks"])
def update_task(task_id: int, data: TaskUpdate, user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    task = get_owned_task(task_id, user, session)
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    task.updated_at = utcnow()
    session.add(task)
    session.commit()
    session.refresh(task)
    return task


@app.delete("/tasks/{task_id}", status_code=204, tags=["tasks"])
def delete_task(task_id: int, user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    task = get_owned_task(task_id, user, session)
    session.delete(task)
    session.commit()
