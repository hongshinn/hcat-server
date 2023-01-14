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
            if rt:
                self.return_data = rt
        return self.return_data.json()
