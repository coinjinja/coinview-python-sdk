
from flask import Flask
from flask_cors import CORS

from .controller import airdrop, cashier, votes
from . import extentions
from coinview import Credential


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    CORS(app)

    from .extentions import db, migrate
    db.init_app(app)
    migrate.init_app(app=app, db=db)

    extentions.app_airdrop.credential = Credential(**app.config['DISTRIBUTE_ACCOUNT'])
    extentions.app_receiver.credential = Credential(**app.config['RECEIVER_ACCOUNT'])

    app.register_blueprint(airdrop.bp)
    app.register_blueprint(cashier.bp)
    app.register_blueprint(votes.bp)

    @app.after_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    return app
