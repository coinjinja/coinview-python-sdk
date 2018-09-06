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
        return self._request('POST', '/transfers', {
            'asset_id': asset_id,
            'opponent_id': receiver_id,
            'amount': amount,
            'trace_id': trace_id,
            'pin': encrypt_pin(self.credential),
            'memo': memo,
        }).get('data')

    def verify_payment(self, receiver_id: str, amount: str, asset_id: str, trace_id: str):
        return self._request('POST', '/payments', {
            'asset_id': asset_id,
            'opponent_id': receiver_id,
            'amount': amount,
            'trace_id': trace_id,
        }).get('data')

    def list_assets(self):
        return self._request('GET', '/assets').get('data')

    def get_asset(self, asset_id):
        return self._request('GET', '/assets/{}'.format(asset_id)).get('data')

    def find_asset(self, symbol: str):
        for x in self.list_assets():
            if x['symbol'].upper() == symbol.upper():
                return x

    def asset_transactions(self, asset_id: str):
        return self._request('GET', '/assets/{}/snapshots'.format(asset_id)).get('data')

    def transactions(self):
        return self._request('GET', '/snapshots').get('data')

    def user(self, user_id):
        return self._request('GET', '/users/{}'.format(user_id)).get('data')

    pass


__all__ = [
    'CoinViewPay',
    'Credential',
]
