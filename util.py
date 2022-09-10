import random


def get_random_token(key_len=128):
    return ''.join(
        [chr(random.choice(list(range(65, 91)) + list(range(97, 123)) + list(range(48, 58)))) for i in range(key_len)])

