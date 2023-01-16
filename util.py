import base64
import hashlib
import logging
import os
import platform
import random

from Crypto.Cipher import AES


class FlaskLoggerFilter(logging.Filter):
    def filter(self, record):
        print(record.msg)
        return True


def get_random_token(key_len=128):
    return ''.join(
        [chr(random.choice(list(range(65, 91)) + list(range(97, 123)) + list(range(48, 58)))) for _ in range(key_len)])


def salted_hash(data, salt, additional_string=None):
    hash_salt = salt
    if additional_string is not None:
        hash_salt += hashlib.sha1(additional_string.encode('utf8')).hexdigest()
    return hashlib.sha1((data + hash_salt).encode('utf8')).hexdigest()


def request_parse(req_data):
    if req_data.method == 'POST':
        data = req_data.form
    elif req_data.method == 'GET':
        data_dict = {}
        for i in req_data.args.items():
            data_dict[i[0]] = i[1]
        data = data_dict
    else:
        data = {}
    return data


def ins(obj: iter, collection) -> bool:
    res = True
    for i in obj:
        res = res and (i in collection)
    return res


def not_ins(obj: iter, collection) -> bool:
    res = True
    for i in obj:
        res = res and (i not in collection)
    return res


def log_output(logger=__name__, log_level=logging.INFO, text=''):
    log = logging.getLogger(logger)

    log.log(log_level, text)


def get_pri_key():
    with open(os.path.join(os.getcwd(), 'pri.key'), 'r', encoding='utf8') as f:
        return f.read()


class AESCrypto:
    def __init__(self, key, mode=None):
        self.key = key
        self.mode = mode if mode else AES.MODE_ECB

    def encrypto(self, context=None):
        if type(context) == bytes:
            c_bytes = context
        elif type(context) == str:
            c_bytes = context.encode('utf8')
        else:
            c_bytes = bytes(context)
        c_bytes += bytes([0] * (len(c_bytes) % 16))
        return str(base64.b64encode(AES.new(self.key, self.mode).encrypt(c_bytes)), encoding='utf8')

    def decrypto(self, context=None):
        c_str = context if type(context) == str else str(context)
        return str(AES.new(self.key, self.mode).decrypt(base64.b64decode(c_str)), encoding='utf8').strip()
