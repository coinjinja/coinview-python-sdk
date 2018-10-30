.. coinview documentation master file, created by
   sphinx-quickstart on Fri Oct 26 20:33:00 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to CoinView Server(Python) SDK's documentation!
============================================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

.. module:: coinview

API document for CoinView's Python SDK package.

.. class:: Credential(user_id, session_id, pin, pin_token, private_key)

   The `Credential` class contains all user credentials for initialize the `CoinViewPay`
   object for interacting with server APIs.

   :param user_id: wallet's user id in UUID format
   :param session_id: amount of token you with to transfer
   :param pin: the pin setted when creating the wallet.
   :param pin_token: pin token can be extracted from the backup secret key
   :param private_key: private key can be extracted from the backup secret key

   :return: A credential object by which you can initialize the CoinViewPay

   .. code::

      credential = Credential(
         user_id='a76d6864-a758-46e6-8abc-aa5ddf0d3a51',
         session_id='33057864-864b-44cd-8dda-28ab514117da',
         pin='123321',
         pin_token='oYjrk1chVvnZ...',
         private_key='-----BEGIN RSA PRIVATE KEY-----\n...'
      )

   .. method:: Credential.from_backup(secret_key: str, pin: str)

      You can also create the *Credential* from a secret key which you can get from
      `CoinView <https://https://coinjinja.com/coinview>`_'s wallet's backup function.

      :param secret_key: The secret key
      :param pin: the 6 digits pin when you create your wallet

      :return: A credential object by which you can initialize the CoinViewPay

.. autoclass:: coinview.CoinViewPay
   :members:

.. Indices and tables
.. ==================
..
.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
