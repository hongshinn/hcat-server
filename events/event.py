import json

from flask import Response, request
from werkzeug.local import LocalProxy

import util
from containers import ReturnData
from typing import Optional
from util import *


class Event:
    def __init__(self, server=None, req=None):
        self.cancel = False
        self.return_data = ReturnData(ReturnData.NULL)
        if type(self).__name__ != 'Login':
            print(1)
            aes = AESCrypto(util.get_pri_key())
            if type(req) is LocalProxy and 'auth_data' in req.cookies:

                self.auth_data = aes.decrypto(req.cookies['auth_data'])
                print(self.auth_data)
                auth_data_json = json.loads(self.auth_data)
                status, msg = server.authenticate_token(auth_data_json['username'], auth_data_json['token'])
                if status:
                    self._init(server, req)
                else:
                    self.return_data = msg
            else:
                print(2)
                req_data = request_parse(req)
                if ins(['username', 'token'], req_data):
                    self.auth_data = json.dumps({'username': req_data['username'], 'token': req_data['token'],
                                                 'salt': util.get_random_token()})
                    self._init(server, req)
                else:
                    self.auth_data = json.dumps({'username': '', 'token': '',
                                                 'salt': util.get_random_token()})
                    self.return_data = ReturnData(ReturnData.ERROR, 'token error')

    def _init(self, server, req):
        ...

    def _run(self, *args):
        return ReturnData(ReturnData.NULL)

    def _return(self):
        pass

    def e_return(self):
        if type(self).__name__ == 'Login':
            self.auth_data = json.dumps(
                {'username': self.username, 'token': self.token, 'salt': util.get_random_token()})
        else:
            auth_data_json = json.loads(self.auth_data)
            auth_data_json['salt'] = util.get_random_token()
            self.auth_data = json.dumps(auth_data_json)
        resp = Response(self.return_data.json_data)
        aes = AESCrypto(util.get_pri_key())
        resp.set_cookie('auth_data', aes.encrypto(self.auth_data))

        if not self.cancel:
            rt = self._return()
            if rt is not None:
                return rt.json()

        return resp
