from typing import Annotated
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, APIRouter, Security, status
from fastapi.security import APIKeyHeader, HTTPBasic, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select
import os
from dotenv import load_dotenv
from pydantic import BaseModel
from pwdlib import PasswordHash

from routers.auth.jwt_handler import create_access_token

import uuid 

from routers.user.models import User, ApiUserBase

load_dotenv()

router = APIRouter(prefix='/user', tags=["User"])
api_key = APIKeyHeader(name="x-api-key")
user_login = HTTPBasic()

db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")

DATABASE_URL = f"postgresql://{db_username}:{db_password}@{db_host}/{db_name}"
engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

# oauth way
password_hash = PasswordHash.recommended()
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# class User(BaseModel):
#     username: str
#     email: str | None = None
#     full_name: str | None = None
#     disabled: bool | None = None


class UserInDB(User):
    hashed_password: str



def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password):
    return password_hash.hash(password)


def get_user(username: str):
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user_info = session.exec(statement).first()
        if not user_info:
            raise HTTPException(status_code=401, detail="Wrong Username or Password")
        return user_info
    
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session:SessionDep
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    user.last_login = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)
    return Token(access_token=access_token, token_type="bearer")

# username password way 

def verify_api_key(api_key: uuid.UUID):
    with Session(engine) as session:
        statement = select(ApiUserBase).where(ApiUserBase.api_key == api_key)
        key_info = session.exec(statement).first()
        if not key_info:
            raise HTTPException(status_code=401, detail="Missing or invalid api key")
        if key_info.curr_credits <= 0:
            raise HTTPException(
                status_code=402,
                detail="You have no credits left for the month"
            )
        yield key_info

        # If successful, decrement the user's credits
        key_info.curr_credits -= 1
        session.commit()
        session.refresh(key_info)

def insert_api_key(api:ApiUserBase):
    with Session(engine) as session:
        session.add(api)
        session.commit()
        session.refresh(api)
        return f"Success get api key: {api.key_name}"


# @router.post('/login')
# def login_user(username: str, password: str, session: SessionDep) -> User:
#     statement = select(User).where(User.username == username)
#     user_info = session.exec(statement).first()
#     if not user_info:
#         raise HTTPException(status_code=401, detail="Wrong Username or Password")
#     if user_info.password != password:
#         raise HTTPException(status_code=401, detail="Wrong Username or Password")
#     user_info.last_login = datetime.now()
#     session.add(user_info)
#     session.commit()
#     session.refresh(user_info)
#     return user_info

@router.post('/signup')
def create_users(user: User, session: SessionDep) -> User:
    user.created_at = datetime.now()
    user.last_login = datetime.now()
    user.password = get_password_hash(user.password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@router.get('/{user_id}')
def get_users(user_id: int, session:SessionDep) -> User:
    user_info = session.get(User, user_id)
    if not user_info:
        raise HTTPException(status_code=401, detail="Not found user")
    return user_info

@router.put('/{user_id}')
def update_users(user_id:int, user: User, session:SessionDep) -> User:
    statement = select(User).where(User.id == user_id)
    user_info = session.exec(statement).first()
    if not user_info:
        raise HTTPException(status_code=401, detail="Not found user")
    if user.password != "":
        hashed_password = get_password_hash(user.password)
        if hashed_password != user_info.password:
            user.password = hashed_password
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

# @router.get('/reqKey')
# def request_apiKey(user: Annotated[User, Depends(login_user)]):
#     if not user:
#         api_key = uuid.uuid4()
#     return {"api_key": api_key}

# @router.get('/getItems')
# async def read_items(key: Annotated[uuid.UUID, Depends(verify_api_key)]):
#     return {"message": "Items accessed successfully", "key_used": key}








