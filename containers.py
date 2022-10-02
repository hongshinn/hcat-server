from flask import jsonify

from util import get_random_token


class EventContainer:
    def __init__(self, data_base, lock):
        self.lock = lock
        self.lock.acquire()
        self.data_base = data_base
        while True:
            rid = get_random_token(8)
            if not self.data_base.exists(rid):
                break
        self.rid = rid
        self.json = {}
        self.can_write = True

    def __call__(self, key, value):
        self.json[key] = value

    def write(self):
        if self.can_write:
            self.data_base.set(self.rid, self.json)
            self.lock.release()
            self.can_write = False

    def __del__(self):
        if self.lock.locked():
            self.lock.release()

    def add(self, key, value):
        self.json[key] = value
        return self


class ReturnData:
    ERROR = 1
    NULL = 2
    OK = 0

    def __init__(self, status=0, msg=''):
        if status == 0:
            status_text = 'ok'
        elif status == 1:
            status_text = 'error'
        elif status == 2:
            status_text = 'null'
        else:
            status_text = 'error'
        self.json_data = {'status': status_text, 'message': msg}

    def add(self, key, value):
        self.json_data[key] = value
        return self

    def json(self):
        return jsonify(self.json_data)

    def __call__(self):
        return self.json_data
