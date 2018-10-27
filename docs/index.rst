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

   Contains user credential for interacting with server API

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
