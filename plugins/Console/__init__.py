import logging
import threading

from events.auth import Register
from plugin_manager.manager import HCat, PluginConfig
from server import HCatServer, log_output


class FakeReq:
    def __init__(self, form):
        self.method = 'POST'
        self.form = form


def main(hcat: HCat, workspace: str):
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    threading.Thread(target=console_thread, args=(hcat,), daemon=False).start()


def console_thread(hcat: HCat):
    while True:
        res = run_cmd(hcat.server, input())
        status = res['status']
        msg = res['message']
        if status == 'ok':
            log_level = logging.INFO
        elif status == 'null' or status == 'error':
            log_level = logging.ERROR
        else:
            log_level = logging.INFO
        log_output(log_level=log_level, text=msg)


def run_cmd(server: HCatServer, cmd):
    cmd_list = cmd.split(' ')
    if cmd_list[0] == 'auth':
        if len(cmd_list) == 4:
            if cmd_list[1] == 'reg':
                username = cmd_list[2]
                password = cmd_list[2]
                e = Register(server, FakeReq({'username': username, 'password': password, 'display_name': username}))
                server.hcat(e)
                return e.return_data.json_data
    else:
        return {'status': 'ERROR', 'msg': 'Invalid command'}
    return {'status': 'ERROR', 'msg': 'Missing parameters'}


class Config(PluginConfig):
    def __init__(self):
        super().__init__()
        self.name = 'Console'
        self.description = 'Implementing command line operations'
        self.author = 'hsn'
        self.depend = []
        self.version = '1.0.0'
