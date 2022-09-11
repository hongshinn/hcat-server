import hashlib
import random


def get_random_token(key_len=128):
    return ''.join(
        [chr(random.choice(list(range(65, 91)) + list(range(97, 123)) + list(range(48, 58)))) for i in range(key_len)])


def salted_hash(data, salt, additional_string=None):
    hash_salt = salt
    if additional_string is not None:
        hash_salt += hashlib.sha1(additional_string.encode('utf8')).hexdigest()
    return hashlib.sha1((data + '1145').encode('utf8')).hexdigest()
