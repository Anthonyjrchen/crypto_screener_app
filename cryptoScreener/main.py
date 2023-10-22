from cryptoScreener import models
from fastapi import FastAPI, Request, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from cryptoScreener.database import SessionLocal, engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from cryptoScreener.models import Data, Request_Status, Crypto
from pydantic import BaseModel
import os
from datetime import timedelta
from passlib.context import CryptContext
import random
import yfinance

class UserRequest(BaseModel):
    username: str
    password: str

class UsernameRequest(BaseModel):
    username: str

class CryptoRequest(BaseModel):
    symbol: str

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def fetch_crypto_data(id: int):
    db = SessionLocal()
    crypto = db.query(Crypto).filter(Crypto.id == id).first()
    y_data = yfinance.Ticker(crypto.symbol)
    crypto.ma200 = y_data.info['twoHundredDayAverage']   
    crypto.ma50 = y_data.info['fiftyDayAverage']
    crypto.price = y_data.info['previousClose']
    db.add(crypto)
    db.commit()

app = FastAPI()
app.mount("/static", StaticFiles(directory="cryptoScreener/static"), name="static")
templates = Jinja2Templates(directory = "cryptoScreener/templates")
models.Base.metadata.create_all(bind=engine)
IMAGEDIR = os.path.join(os.path.dirname(__file__), "uploads/")

SECRET_KEY = "a969379d6774b629d92dc6118ccb4c35f2676e5c3152bff4c9fbfb1bbff1bc0c"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Settings(BaseModel):
    authjwt_secret_key: str = SECRET_KEY
    authjwt_token_location: set = {"cookies"}
    authjwt_cookie_csrf_protect: bool = False
    authjwt_cookie_samesite: str = 'lax'

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    if exc.message=="Signature has expired":
        return RedirectResponse("/")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str, db):
    users = db.query(models.User).filter(models.User.username==username).first()
    return users
    
def authenticate_user(username: str, password: str, db):
    user = get_user(username, db)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# security end

@app.post("/login")
async def login_for_access_token(from_data: OAuth2PasswordRequestForm = Depends(), Authorize: AuthJWT = Depends(), db : Session = Depends(get_db)):
    user = authenticate_user(from_data.username, from_data.password, db)
    print("got some user")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    print("user is true")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = Authorize.create_access_token(subject=user.username, algorithm=ALGORITHM ,expires_time=access_token_expires)
    refresh_token = Authorize.create_refresh_token(subject=user.username, algorithm=ALGORITHM ,expires_time=access_token_expires)
    Authorize.set_access_cookies(access_token)
    Authorize.set_refresh_cookies(refresh_token)
    return {"msg":"Login Successful"}

@app.delete('/logout')
def logout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    Authorize.unset_jwt_cookies()
    return {"msg": "Logout Successful"}

@app.get('/retrieve/user')
def get_username(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return Authorize.get_jwt_subject()

@app.get("/")
def dashboard(request: Request):
    return templates.TemplateResponse("landing_page.html", {
        "request":request,
    })

@app.get("/signup")
def dashboard(request: Request):
    return templates.TemplateResponse("signup.html", {
        "request":request,
    })

@app.post("/signup")
async def verifyUser(user_request: UserRequest, db : Session = Depends(get_db)):
    try:
        print("entering signup func")
        hashed_password = get_password_hash(user_request.password)
        priv_key_list = db.query(models.User.private_key).all()
        print(priv_key_list)
        random_key = random.choice(list(set([x for x in range(0,100)]) - set(priv_key_list)))
        # generate user index_set
        user_index_set = random.sample(range(0,127),64)
        user = models.User(username=user_request.username, hashed_password=hashed_password, disabled=True, private_key=random_key, index_set=str(user_index_set))
        db.add(user)
        db.commit()
        return {"True"}
    except Exception as err:
        print(err)
        return {"False"}


@app.get("/dashboard")
async def dashboard(request: Request, db : Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    username = Authorize.get_jwt_subject()
    datas = db.query(Data).filter(Data.author!=username)
    cryptos = db.query(Crypto).filter(Crypto.user==username)
    token_list = db.query(models.Token).filter(models.Token.buyer_id==username).all()
    request_status_list = db.query(Request_Status.data_name,Request_Status.request_status).filter(Request_Status.requestor==username).all()
    status_dict = {}
    requested_data = []
    for status in request_status_list:
        status_dict[status.data_name]=status.request_status
        requested_data.append(status.data_name)
    return templates.TemplateResponse("dashboard.html", {
        "request":request,
        "datas":datas,
        "status_dict":status_dict,
        "token_list":token_list,
        "requested_data":requested_data,
        "page_location":"Dash",
        "cryptos": cryptos,
    })

@app.post("/cryptocurrency")
def create_crypto(crypto_request: CryptoRequest, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    username = Authorize.get_jwt_subject()
    crypto = Crypto()
    crypto.symbol = crypto_request.symbol
    crypto.user = username
    try:
        print(crypto.symbol)
        db.query(Crypto).filter(Crypto.symbol == crypto.symbol, Crypto.user == username).one()
        print("raising error")
        raise Exception("duplicate")
    except NoResultFound:
        db.add(crypto)
        db.commit()
        fetch_crypto_data(crypto.id)

    return {
        crypto_request.symbol + " added to database"
    }

@app.post("/reset/cryptocurrencies")
def reset_db(db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    db.query(Crypto).filter(Crypto.user==Authorize.get_jwt_subject()).delete(synchronize_session='fetch')
    db.commit()

@app.get("/user/priv_key")
def get_priv_key(db : Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    username = Authorize.get_jwt_subject()
    retrieved_key = db.query(models.User).filter(models.User.username==username).first()
    try:
        return retrieved_key.private_key
    except AttributeError as err:
        raise err

@app.get("/contacts")
def contacts(request:Request):
    return templates.TemplateResponse("contact.html", {
        "request":request,
    })
