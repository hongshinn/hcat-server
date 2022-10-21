import re

from containers import ReturnData
from events.event import Event
from server import HCatServer
from util import request_parse, salted_hash, get_random_token


class AuthenticateToken(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            return ReturnData(ReturnData.OK)
        else:
            return msg


class GetDisplayName(Event):
    def __init__(self, server, username):
        super().__init__()
        self.username = username
        self.server = server
        self.return_data = self._run(server)

    def _run(self, server):
        if server.auth_db.exists(self.username):
            return ReturnData(ReturnData.OK).add('display_name', server.auth_db.get(self.username)['display_name'])
        else:
            return ReturnData(ReturnData.NULL, 'username not exists')


class GetTodoList(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 在线判断计次
            server.data_db_lock.acquire()
            if self.username in server.get_todo_list_count:
                server.get_todo_list_count[self.username] += 1
            else:
                server.get_todo_list_count[self.username] = 0

            data = server.get_user_data(self.username)
            # 取todo_list
            if 'todo_list' in data:
                # 取得结果
                res = data['todo_list']
            else:
                res = []
            # 清空todo_list
            data['todo_list'] = []
            # 计入数据库
            server.data_db.set(self.username, data)
            server.data_db_lock.release()
            return ReturnData(ReturnData.OK).add('data', res)

        else:
            return msg


class Login(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)

        # 判断请求体是否为空
        if 'username' not in req_data or 'password' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or password is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.password = req_data['password']

        # 判断用户名是否存在
        if self.username not in server.auth_db.getall():
            return ReturnData(ReturnData.NULL, 'username is not exist')

        # 判断用户名和密码是否正确
        if server.auth_db.get(self.username)['password'] == salted_hash(self.password,
                                                                        server.auth_db.get(self.username)['salt'],
                                                                        self.username):
            self.cancel = False
            # 生成随机密钥
            self.token = get_random_token()

            # 返回结果
            return ReturnData(ReturnData.OK, 'login success').add('token', self.token)
        else:

            return ReturnData(ReturnData.ERROR, 'username or password is incorrect')

    def _return(self):
        server = self.server
        server.data_db_lock.acquire()

        # 读取数据
        userdata = server.get_user_data(self.username)

        # 写入字典
        userdata['status'] = 'online'
        userdata['token'] = self.token
        # 写出
        server.data_db.set(self.username, userdata)
        server.data_db_lock.release()


class Logout(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)

        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']

        # 判断用户名是否存在
        if self.username not in server.auth_db.getall():
            return ReturnData(ReturnData.NULL, 'username is not exist')

            # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 写入数据库
            server.data_db_lock.acquire()
            userdata = server.get_user_data(self.username)
            userdata['status'] = 'offline'
            userdata['token'] = ''
            server.data_db.set(self.username, userdata)
            server.data_db_lock.release()

            return ReturnData(ReturnData.OK)

        else:
            return msg


class Register(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'password' not in req_data or 'display_name' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username password or display_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.password = req_data['password']
        self.display_name = req_data['display_name']

        # 判断用户名是否符合要求
        reg = r'^[a-zA-Z][a-zA-Z0-9_]{4,15}$'
        if not re.match(reg, self.username):
            return ReturnData(ReturnData.ERROR,
                              'Username does not meet the requirements of ^[a-zA-Z][a-zA-Z0-9_]{4,15}$')

        # 判断密码是否符合要求
        if len(self.password) < 6:
            return ReturnData(ReturnData.ERROR, 'password is too short')

        # 判断用户名是否存在
        if server.auth_db.exists(self.username):

            return ReturnData(ReturnData.ERROR, 'username already exists')
        else:
            self.cancel = False

            return ReturnData(ReturnData.OK, 'register success')

    def _return(self):
        server = self.server
        # 写入数据库
        salt = get_random_token(16)

        server.auth_db.set(self.username, {'password': salted_hash(self.password, salt, self.username),
                                           'salt': salt,
                                           'display_name': self.display_name})


class Status(Event):
    def __init__(self, server, username):
        super().__init__()
        self.username = username
        self.server = server
        self.return_data = self._run(server)

    def _run(self, server):
        # 判断用户名是否存在
        if server.data_db.exists(self.username):

            return ReturnData(ReturnData.OK).add('user_status', server.get_user_data(self.username)['status'])
        else:

            return ReturnData(ReturnData.NULL, 'username not exists')


class Rename(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'display_name' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username password or display_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.display_name = req_data['display_name']
        # 验证密钥
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False
            return ReturnData(ReturnData.OK)
        else:
            return msg

    def _return(self):
        server = self.server
        server.data_db_lock.acquire()
        auth_data = server.auth_db.get(self.username)
        self.former_name = auth_data['display_name']
        auth_data['display_name'] = self.display_name
        server.auth_db.set(self.username, auth_data)
        server.data_db_lock.release()


class ChangePassword(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'password' not in req_data or \
                'new_password' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username password or display_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.password = req_data['password']
        self.new_password = req_data['new_password']

        # 验证密钥
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断用户名是否存在
            if self.username not in server.auth_db.getall():
                return ReturnData(ReturnData.NULL, 'username is not exist')

            # 判断用户名和密码是否正确
            if server.auth_db.get(self.username)['password'] == salted_hash(self.password,
                                                                            server.auth_db.get(self.username)['salt'],
                                                                            self.username):
                # 判断密码是否符合要求
                if len(self.new_password) < 6:
                    return ReturnData(ReturnData.ERROR, 'password is too short')

                self.cancel = False

                # 返回结果

                return ReturnData(ReturnData.OK, 'change success')
            else:

                return ReturnData(ReturnData.ERROR, 'old password is incorrect')
        else:
            return msg

    def _return(self):
        server = self.server
        salt = get_random_token(16)
        server.auth_db_lock.acquire()
        auth_data = server.auth_db.get(self.username)
        auth_data['password'] = salted_hash(self.new_password, salt, self.username)
        auth_data['salt'] = salt
        server.auth_db.set(self.username, auth_data)
        server.auth_db_lock.release()
