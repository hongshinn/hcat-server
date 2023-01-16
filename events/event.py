import json

from flask import Response, request

import util
from containers import ReturnData
from typing import Optional
from util import *


class Event:
    def __init__(self, server=None, req=None):
        if req is not None:
            print(req.cookies.get("test"))
        self.cancel = False
        self.return_data = ReturnData(ReturnData.NULL)
        if type(self).__name__ != 'Login':
            aes = AESCrypto(util.get_pri_key())
            self.auth_data = aes.decrypto(request.cookies['auth_data'])
            if server.authenticate_token(self.auth_data['username'], self.auth_data['self.token']):
                self._init(server, req)

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
