import json
from typing import Optional
import time
import hashlib
import jwt
from uuid import uuid4
import struct
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
import requests
from requests.utils import default_user_agent
from requests.adapters import HTTPAdapter
from collections import namedtuple

http_session = requests.session()
http_session.mount('https://', HTTPAdapter(pool_maxsize=100))
http_session.headers.update({'User-Agent': 'CoinViewPayPython/1.0 %s' % default_user_agent()})


Credential = namedtuple('Credential', ['user_id', 'session_id', 'pin', 'pin_token', 'private_key'])
def _from_backup(text, pin):
    d = json.loads(str(b64decode(text), 'utf8'))
    c = Credential(
        user_id=d['id'],
        session_id=d['sessionId'],
        pin=pin,
        pin_token=d['pinToken'],
        private_key=d['privateKey'],
    )
    return c
Credential.from_backup = _from_backup


def sha256(*contents, encoding='utf-8') -> str:
    h = hashlib.sha256()
    for x in contents:
        if not x:
            continue
        elif type(x) == str:
            h.update(bytes(x, encoding))
        else:
            h.update(x)
    return h.hexdigest()


def generate_signature(cred: Credential, method: str, uri: str, content: Optional[str], timestamp: int=None, expire: int=None, uuid: str=None) -> str:
    timestamp = timestamp or int(time.time())
    expire_at = timestamp + (expire or 1*60*60)  # 1 hour
    payload = {
        "uid": cred.user_id,
        "sid": cred.session_id,
        "iat": timestamp,
        "exp": expire_at,
        "jti": uuid or str(uuid4()),
        "sig": sha256(method, uri, content),
    }
    private_key = cred.private_key
    if '--BEGIN RSA' not in private_key:
        private_key = load_der_private_key(b64decode(private_key), None, default_backend())
    return jwt.encode(payload, private_key, algorithm='RS512').decode('utf-8')


def encrypt_pin(cred: Credential, iterator: int=None, timestamp: int=None) -> str:
    timestamp = timestamp or int(time.time())
    iterator = iterator if iterator is not None else int(time.time()*1000000)
    pin_ts = struct.pack('<6sQQ', bytes(cred.pin, 'ascii'), timestamp, iterator)
    pad_len = AES.block_size - (len(pin_ts) % AES.block_size)
    to_sign = pin_ts + (struct.pack('B', pad_len) * pad_len)
    key_bytes = decrypt_pin_token(cred.session_id, cred.pin_token, cred.private_key)
    return aes_cbc_encrypt(key_bytes, to_sign)


def decrypt_pin_token(session_id: str, pin_token: str, private_key: str):
    if '--BEGIN RSA' in private_key:
        rsa_key = RSA.import_key(private_key)
    else:
        rsa_key = RSA.import_key(b64decode(private_key))
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256, label=bytes(session_id, 'ascii'))
    key_bytes = cipher.decrypt(b64decode(pin_token))
    return key_bytes


def aes_cbc_encrypt(key_bytes: bytes, content: bytes):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key_bytes, mode=AES.MODE_CBC, iv=iv)
    result = cipher.encrypt(content)
    return b64encode(iv + result).decode('ascii')


class CoinViewPay:
    BASE_URL = 'https://wallet.coinjinja.com/v1/api'

    def __init__(self, credential: Credential):
        self.credential = credential
        pass

    def _request(self, method, uri, content=None, content_type=None):
        data = json.dumps(content) if content else None
        body = {
            'method': method,
            'uri': uri,
            'content': data,
            'content_type': content_type,
            'signature': generate_signature(self.credential, method, uri, data),
        }
        for x in list(body.keys()):
            if body[x] is None:
                del body[x]
        r = http_session.post(self.BASE_URL + '/wallet', json=body)
        return r.json()

    def transfer(self, receiver_id: str, amount: str, asset_id: str, trace_id: str, memo: Optional[str]):
        """Make a direct transfer

        :param receiver_id: recipient user id
        :param amount: amount of token you with to transfer
        :param asset_id: asset id of the token
        :param trace_id: a UUID for identifying the transfer
        :param memo: optional note

        example response

        .. code::

            {
              "type": "transfer",
              "snapshot_id": "ab56be4c-5b20-41c6-a9c3-244f9a433f35",
              "opponent_id": "a465ffdb-4441-4cb9-8b45-00cf79dfbc46",
              "asset_id": "43d61dcd-e413-450d-80b8-101d5e903357",
              "amount": "-10",
              "trace_id": "7c67e8e8-b142-488b-80a3-61d4d29c90bf",
              "memo": "hello",
              "created_at": "2018-05-03T10:08:34.859542588Z"
            }
        """
        return self._request('POST', '/transfers', {
            'asset_id': asset_id,
            'opponent_id': receiver_id,
            'amount': amount,
            'trace_id': trace_id,
            'pin': encrypt_pin(self.credential),
            'memo': memo,
        }).get('data')

    def verify_payment(self, receiver_id: str, amount: str, asset_id: str, trace_id: str):
        """
            verify payment status

            response
                {
                  "recipient": {
                    "type": "user",
                    "user_id": "a465ffdb-4441-4cb9-8b45-00cf79dfbc46",
                    "identity_number": "20018",
                    "full_name": "OS105",
                    "avatar_url": "",
                    "relationship": "",
                    "mute_until": "0001-01-01T00:00:00Z",
                    "created_at": "2018-04-25T05:37:10.06433488Z",
                    "is_verified": false
                  },
                  "asset": {
                    "type": "asset",
                    "asset_id": "43d61dcd-e413-450d-80b8-101d5e903357",
                    "chain_id": "43d61dcd-e413-450d-80b8-101d5e903357",
                    "symbol": "EOS",
                    "name": "EOS",
                    "balance": "0",
                    "public_key": "",
                    "price_btc": "0.0776679",
                    "price_usd": "715.394"
                  },
                  "amount": "10",
                  "status": "pending"
                }
        """
        return self._request('POST', '/payments', {
            'asset_id': asset_id,
            'opponent_id': receiver_id,
            'amount': amount,
            'trace_id': trace_id,
        }).get('data')

    def list_assets(self):
        """
            list all your assets

            response:
                [
                  {
                    "asset_id": "07065d64-fd33-39b5-b275-9a2cc4806ef4",
                    "balance": "999607",
                    "chain_id": "43d61dcd-e413-450d-80b8-101d5e903357",
                    "confirmations": 100,
                    "name": "NXT Token for NEC2018",
                    "public_key": "0x4Ac80f604dA7c7Dd39B26774a84fB99c28Fe41e0",
                    "symbol": "NXT",
                    "type": "asset"
                  },
                  ...
                ]
        """
        return self._request('GET', '/assets').get('data')

    def get_asset(self, asset_id):
        """
            Get assets by asset_id

            response:
                {
                  "asset_id": "07065d64-fd33-39b5-b275-9a2cc4806ef4",
                  "balance": "999607",
                  "chain_id": "43d61dcd-e413-450d-80b8-101d5e903357",
                  "confirmations": 100,
                  "name": "NXT Token for NEC2018",
                  "public_key": "0x4Ac80f604dA7c7Dd39B26774a84fB99c28Fe41e0",
                  "symbol": "NXT",
                  "type": "asset"
                }
        """
        return self._request('GET', '/assets/{}'.format(asset_id)).get('data')

    def transactions(self):
        """
            list transactions

            response:
                [
                    {
                      "amount": "0.1",
                      "asset_id": "d0deee89-a0f3-34ec-a92c-1a4d16fd2c3d",
                      "counter_user_id": "729c1eec-f03f-3a52-b391-6092cfaba3fb",
                      "created_at": "2018-09-11T05:39:25.429083062Z",
                      "memo": "",
                      "opponent_id": "729c1eec-f03f-3a52-b391-6092cfaba1fb",
                      "snapshot_id": "9833191e-f379-4a18-ae49-5199e1ce8a59",
                      "trace_id": "49b990c7-cd3b-415b-8c5e-2f5909854202",
                      "type": "transfer"
                    },
                    ...
                ]
        """
        return self._request('GET', '/snapshots').get('data')

    def user(self, user_id):
        """
            get user detail

            response
            {
              "avatar_url": "",
              "created_at": "2018-09-04T03:34:18.484856821Z",
              "full_name": "Example",
              "identity_number": "0",
              "is_verified": false,
              "mute_until": "0001-01-01T00:00:00Z",
              "relationship": "STRANGER",
              "type": "user",
              "user_id": "729c1eec-f03f-3a52-b391-6092cfaba3fb"
            }
        """
        return self._request('GET', '/users/{}'.format(user_id)).get('data')

    pass


__all__ = [
    'CoinViewPay',
    'Credential',
]
