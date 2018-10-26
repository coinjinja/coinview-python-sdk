from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from .sdk import CoinViewPay
db = SQLAlchemy(session_options={
    'autocommit': True,
})
migrate = Migrate()
app_airdrop = CoinViewPay(None)
app_receiver = CoinViewPay(None)