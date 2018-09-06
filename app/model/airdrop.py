from ..extentions import db
from sqlalchemy import Column, String, Integer, func, DateTime, Index, DECIMAL


class Airdrop(db.Model):
    __table_args__ = (
        Index('idx_user_symbol', 'user_id', 'token', unique=True),
    )

    initialized = 0
    done = 1

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(String(50), nullable=False)
    token = Column(String(50), nullable=False)
    trace_id = Column(String(50), default=func.uuid(), nullable=False)
    state = Column(Integer, nullable=False)

    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    pass


class AirdropSupply(db.Model):
    id = Column(Integer, autoincrement=True, primary_key=True)
    token = Column(String(50), nullable=False, unique=True)
    asset_id = Column(String(50), nullable=False)

    total = Column(DECIMAL(16, 8), nullable=False)
    remaining = Column(DECIMAL(16, 8), nullable=False)
    per_person = Column(DECIMAL(16, 8), nullable=False)

    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
