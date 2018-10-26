from ..extentions import db
from sqlalchemy import String, Integer, func, DateTime, Index, Column, DECIMAL


class Payment(db.Model):
    snapshot_id = Column(String(50), primary_key=True)

    user_id = Column(String(50), nullable=False)
    amount = Column(DECIMAL, nullable=False)
    product = Column(String(150), nullable=False)

    ignore = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

