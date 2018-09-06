from ..extentions import db
from sqlalchemy import String, Integer, func, DateTime, Index, Column


class Vote(db.Model):
    user_id = Column(String(50), primary_key=True)
    snapshot_id = Column(String(50), primary_key=True)

    candidate_id = Column(Integer, nullable=False)

    ignore = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

