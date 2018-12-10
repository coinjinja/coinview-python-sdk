# Server (Python) SDK for CoinView dApps

## Introduction

This repository contains [API install package](https://github.com/coinjinja/coinview-python-sdk/tree/master/coinview),
documentation for CoinView's Python SDK package. We've also included some demo dApps; an airdrop-style token distribution schema, a simple POS app with QR code scanning that can quickly reconcile sales with tokens, and a voting app that uses tokens to vote for speakers at an event.

### Client & Server API

To run a dApp on the CoinView platform, both client-side API ([document](https://github.com/coinjinja/coinview-js-sdk))
handling user interaction and the server-side API ([document](https://coinjinja.github.io/coinview-python-sdk/))
dealing with authentication, verification, and executing token transfers will be needed. The client-side API is written in pure Javascript and can be easily debugged in a normal browser environment.

### Installation


#### Using pip (recommended)

    $ pip install -e 'git+https://github.com/coinjinja/coinview-python-sdk@master#egg=coinview'

#### From source

Under `.` running

    $ python setup.py install

### Update the Documentation

Under `./docs` running. The document will also be updated automatically by Travis and hosted on github.io.

    $ make html

## Sample dApps

Here are a few simple and easy understanding examples of how to connect CoinView SDK to your dApp.

### Voting App

![voting](https://en.coinjinja.com/dist/img/example-vote@2x_en.29ab4a6ecdec6d7b.png)

Using this dApp developed in just two days, tokens were released exclusively for an event we held. Attendees were able to use them for purchasing goods and voting for their favorite panel speakers.

Here is the source codes for the [frontend](https://github.com/coinjinja/demo-voting) and
[server](https://github.com/coinjinja/coinview-python-sdk/blob/master/demo_app/controller/votes.py).

### Airdrop App

![airdrop](https://en.coinjinja.com/dist/img/example-airdrop@2x_en.c9373e07e8548183.png)

An airdrop function that can easily distribute tokens. For this event, two types of tokens (for voting and sales) were prepared and distributed.

Here is the source codes for the [frontend](https://github.com/coinjinja/demo-airdropper) and
[server](https://github.com/coinjinja/coinview-python-sdk/blob/master/demo_app/controller/airdrop.py).

### PoS (Point of Sale) App

![pos](https://en.coinjinja.com/dist/img/example-regi@2x_en.cf4bc9002a800a24.png)

A simple POS app with QR code scanning that can quickly reconcile sales with tokens. Commission-free and performs settlement in seconds.

Here are source codes for the [frontend](https://github.com/coinjinja/demo-cashier) and
[server](https://github.com/coinjinja/coinview-python-sdk/blob/master/demo_app/controller/cashier.py).

### Snake (Game)

![snake](https://en.coinjinja.com/dist/img/example-snake@2x_en.b9ea87245fb1d4b9.png)

Developed in just one day, this is a dApp remake of the 1970s arcade game, "Snake." We easily enabled it to have virtual currency billing.

Here is the [source code](https://github.com/coinjinja/demo-snake) for the game, including the billing function.
