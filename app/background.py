from gevent import monkey
monkey.patch_all()

from gevent import spawn, joinall
import logging
import time

from .factory import create_app
from .extentions import app_receiver, db
from .model import Vote, Payment

app = create_app()

VOTE_CURRENCY_ID = app.config['VOTE_CURRENCY_ID']
CASHIER_CURRENCY_ID = app.config['CASHIER_CURRENCY_ID']


def safe_int(x):
    try:
        return int(x)
    except Exception:
        pass


def save_vote(user_id, snapshot_id, candidate_id):
    with db.session.begin():
        vote = Vote.query.filter_by(user_id=user_id, snapshot_id=snapshot_id).first()
        if vote:
            return
    vote = Vote(user_id=user_id, snapshot_id=snapshot_id, candidate_id=candidate_id)
    with db.session.begin():
        db.session.add(vote)


def save_payment(user_id, snapshot_id, amount, product):
    with db.session.begin():
        p = Payment.query.filter_by(snapshot_id=snapshot_id).first()
        if p:
            return
    payment = Payment(snapshot_id=snapshot_id, user_id=user_id, amount=float(amount), product=product)
    with db.session.begin():
        db.session.add(payment)


def refresh_votes():
    snapshots = app_receiver.asset_history(VOTE_CURRENCY_ID)
    for x in snapshots:
        user_id = x['opponent_id']
        snapshot_id = x['snapshot_id']
        memo = x.get('memo')
        candidate_id = safe_int(memo)
        if candidate_id is not None:
            save_vote(user_id, snapshot_id, candidate_id)


def refresh_cashier():
    snapshots = app_receiver.asset_history(CASHIER_CURRENCY_ID)
    for x in snapshots:
        if not x.get('memo'):
            continue
        save_payment(x['opponent_id'], x['snapshot_id'], x['amount'], x['memo'])
        pass


def run(sec, f, *args, **kwargs):
    while True:
        try:
            with app.app_context():
                f(*args, **kwargs)
        except Exception:
            logging.exception('Run error')
            pass
        pass
        time.sleep(sec)


def main():
    joinall([
        spawn(run, 1, refresh_cashier),
        spawn(run, 1, refresh_votes),
    ], timeout=60*10)


if __name__ == '__main__':
    main()
