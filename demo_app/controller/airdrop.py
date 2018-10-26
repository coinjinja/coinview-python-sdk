from typing import List, Optional
from flask import Blueprint, request, g, jsonify, abort
from ..extentions import db, app_airdrop
from ..model import Airdrop, AirdropSupply

import logging

bp = Blueprint('airdrop', __name__)


@bp.route('/token/supply', methods=['POST'])
def get_supply():
    user_id = request.json.get('user_id')
    if not user_id:
        return abort(400)
    supplies = list_supplies()
    drops = find_airdrop_for(user_id) or []

    collected_by_token = {
        d.token: d.state == Airdrop.done
        for d in drops
    }

    return jsonify({
        sup.token: dict(supply=float(sup.total), remains=float(sup.remaining), collected=not not collected_by_token.get(sup.token))
        for sup in supplies
    })

    pass


@bp.route('/token/collect', methods=['POST'])
def collect():
    user_id = request.json.get('user_id')
    if not user_id:
        return abort(400)
    supplies = list_supplies()
    complete = 0
    for s in supplies:
        drop = get_drop(user_id, s.token)
        if not drop or drop.state == Airdrop.done:
            continue
        if send_token(drop, s):
            complete += 1
    return jsonify(collected=complete == len(supplies))


def find_airdrop_for(user_id) -> List[Airdrop]:
    return Airdrop.query.filter_by(user_id=user_id).all()


def list_supplies() -> List[AirdropSupply]:
    return AirdropSupply.query.all()


def get_drop(user_id, token) -> Optional[Airdrop]:
    with db.session.begin():
        supply = AirdropSupply.query.filter_by(token=token).first()
        if not supply:
            return
        drop = Airdrop.query.filter_by(user_id=user_id, token=token).first()
    if drop:
        return drop
    drop = Airdrop(user_id=user_id, token=token, state=Airdrop.initialized)
    with db.session.begin():
        db.session.add(drop)
        db.session.flush()
        drop_id = drop.id
    with db.session.begin():
        return Airdrop.query.filter_by(id=drop_id).first()
    pass


def send_token(drop: Airdrop, sup: AirdropSupply):
    payment = app_airdrop.transfer(
        receiver_id=drop.user_id,
        amount=str(sup.per_person),
        asset_id=sup.asset_id,
        trace_id=drop.trace_id,
        memo=None,
    )
    if not payment or not payment.get('snapshot_id'):
        return
    with db.session.begin():
        sup0 = AirdropSupply.query.filter_by(id=sup.id).first()
        sup0.remaining -= sup0.per_person
        drop0 = Airdrop.query.filter_by(id=drop.id).first()
        drop0.state = Airdrop.done
    return payment


