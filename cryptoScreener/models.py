from sqlalchemy import Column, Integer, String, Date, Boolean, Identity, BLOB, Numeric
from sqlalchemy.orm import relationship, Mapped
from typing import List
from cryptoScreener.database import Base

class User(Base):
    __tablename__ = "users"
    username = Column(String, unique=True, index = True)
    user_id = Column(Integer, primary_key = True, index = True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=True)
    private_key = Column(Integer)
    index_set = Column(String)
    

class Data(Base):
    __tablename__ = "datas"
    id = Column(String, primary_key=True)
    data_cred = Column(String)
    data_name = Column(String)
    date_added = Column(String)
    author = Column(String)
    author_id = Column(Integer, index=True)

class Request_Status(Base):
    __tablename__ = "request_status_list"
    id = Column(Integer, primary_key = True, index=True)
    data_name = Column(String)
    requestor = Column(String)
    requestee = Column(String)
    request_status = Column(String)
    request_timestamp = Column(String)

class Status(Base):
    __tablename__ = "status_list"
    id = Column(Integer, primary_key=True)
    data_name = Column(String)
    data_author = Column(String)
    data_receiver = Column(String)
    approval_status = Column(Boolean, default=False)

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    requestee = Column(String)
    requestor = Column(String)
    data_name = Column(String)
    message = Column(String)

class Commitment(Base):
    __tablename__ = "commitment_list"
    commitment_id = Column(Integer, primary_key=True, index=True)
    time_stamp = Column(String)
    user_id = Column(Integer, index=True)
    commitment = Column(String)
    rx_value = Column(String)
    data_id = Column(String)
    approved_ids = Column(BLOB)

class Proof(Base):
    __tablename__ = "proof_list"
    proof_id = Column(Integer, primary_key=True, index=True)
    time_stamp = Column(String)
    user_id = Column(Integer)
    proof = Column(String)
    data_id = Column(String)
    approved_ids = Column(BLOB)

class Token(Base):
    __tablename__ = "token_list"
    token_id = Column(Integer, primary_key=True, index=True)
    time_stamp = Column(String)
    commitment_received = Column(String)
    buyer_id = Column(Integer)
    data_id = Column(String)
    approved_ids = Column(BLOB)

class Crypto(Base):
    __tablename__ = "cryptos"

    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String, index = True)
    price = Column(Numeric(10,5))
    ma50 = Column(Numeric(10,5))
    ma200 = Column(Numeric(10,5))
    user = Column(String)