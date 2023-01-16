from flask import Response

from containers import ReturnData


class Event:
    def __init__(self):
        self.cancel = False
        self.return_data = ReturnData(ReturnData.NULL)

    def _run(self, *args):
        return ReturnData(ReturnData.NULL)

    def _return(self):
        pass

    def e_return(self):
        if not self.cancel:
            rt = self._return()

            if rt is not None:
                return rt.json()
        resp = Response(self.return_data.json_data)
        resp.set_cookie('test', 'test')
        return resp
