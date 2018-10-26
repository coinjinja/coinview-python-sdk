from flask import Blueprint, jsonify
from sqlalchemy import func

from ..extentions import db
from ..model import Payment

bp = Blueprint('cashier', __name__)


@bp.route('/cashier/payments', methods=['POST', 'GET'])
def payments():
    with db.session.begin():
        result = db.session\
            .query(func.count(Payment.snapshot_id), func.sum(Payment.amount), Payment.product)\
            .filter(Payment.ignore==0)\
            .filter(Payment.amount>0)\
            .group_by(Payment.product)\
            .all()

    return jsonify([
        {
            'amount': count,
            'sales': float(sum),
            'product': product,
        }
        for count, sum, product in result
    ])
