.. coinview documentation master file, created by
   sphinx-quickstart on Fri Oct 26 20:33:00 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to coinview's documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

.. module:: coinview

API doc for under coinview package.

.. class:: Credential(user_id, session_id, pin, pin_token, private_key)

   An value type with user credential for interacting with payment
   service

   .. code::

      credential = Credential(
         user_id='a76d6864-a758-46e6-8abc-aa5ddf0d3a51',
         session_id='33057864-864b-44cd-8dda-28ab514117da',
         pin='123321',
         pin_token='oYjrk1chVvnZ...',
         private_key='-----BEGIN RSA PRIVATE KEY-----\n...'
      )

   .. method:: Credential.from_backup(text: str, pin: str)

      Creates a *Credential* from backup text

.. autoclass:: coinview.CoinViewPay
   :members:

.. Indices and tables
.. ==================
..
.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
