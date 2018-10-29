#!/usr/bin/env python3

from ..factory import create_app
from ..extentions import app_airdrop

app = create_app()
app.app_context().push()


print(app_airdrop.list_assets())
