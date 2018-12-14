SQLALCHEMY_ECHO = False
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://test:test@localhost:3306/demo?charset=utf8mb4'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_BINDS = {}


DISTRIBUTE_ACCOUNT = dict(
    user_id='',
    session_id='',
    pin='',
    pin_token='',
    private_key='',
)

#  CASHIER
RECEIVER_ACCOUNT = dict(
    user_id='',
    session_id='',
    pin='',
    pin_token='',
    private_key='',
)

VOTE_CURRENCY = 'NEX'
CASHIER_CURRENCY = 'ECO'

VOTE_CURRENCY_ID = '07065d64-fd33-39b5-b275-9a2cc4806ef4'
CASHIER_CURRENCY_ID = '3d356f2b-a886-3693-bd2b-04c447ce2399'


