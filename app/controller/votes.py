from flask import Blueprint, jsonify
from sqlalchemy import func

from ..extentions import db
from ..model import Vote

bp = Blueprint('votes', __name__)


@bp.route('/votes', methods=['POST', 'GET'])
def votes():
    with db.session.begin():
        votes = db.session\
            .query(func.count(Vote.snapshot_id), Vote.candidate_id).group_by(Vote.candidate_id)\
            .filter(Vote.ignore==0)

    vote_map = {
        candidate: count
        for count, candidate in votes
    }

    return jsonify([
        {
            'votes': vote_map.get(i, 0),
            'candidate': i,
        }
        for i in range(1, 12)
    ])
