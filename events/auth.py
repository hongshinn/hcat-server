import re

from containers import ReturnData
from server import HCatServer
from util import request_parse, get_user_data, salted_hash, get_random_token


class AuthenticateToken:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
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


class GetDisplayName:
    def __init__(self, server, username):
        self.username = username
        self.server = server
        self.return_data = self._run(server)

    def _run(self, server):
        if server.auth_db.exists(self.username):
            return ReturnData(ReturnData.OK).add('display_name', server.auth_db.get(self.username)['display_name'])
        else:
            return ReturnData(ReturnData.OK, 'username not exists')


class GetTodoList:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
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

            data = get_user_data(server.data_db, self.username)
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
            server.data_db_lock.release()
            return msg


class Login:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.password: str
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

            # 生成随机密钥
            token = get_random_token()

            # 写入数据库
            server.data_db_lock.acquire()

            # 读取数据
            userdata = get_user_data(server.data_db, self.username)

            # 写入字典
            userdata['status'] = 'online'
            userdata['token'] = token
            # 写出
            server.data_db.set(self.username, userdata)
            server.data_db_lock.release()

            # 返回结果

            return ReturnData(ReturnData.OK, 'login success').add('token', token)
        else:

            return ReturnData(ReturnData.ERROR, 'username or password is incorrect')


class Logout:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
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
            userdata = get_user_data(server.data_db, self.username)
            userdata['status'] = 'offline'
            userdata['token'] = ''
            server.data_db.set(self.username, userdata)
            server.data_db_lock.release()

            return ReturnData(ReturnData.OK)

        else:
            return msg


class Register:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.password: str
        self.display_name: str
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
            # 写入数据库
            salt = get_random_token(16)

            server.auth_db.set(self.username, {'password': salted_hash(self.password, salt, self.username),
                                               'salt': salt,
                                               'display_name': self.display_name})

            return ReturnData(ReturnData.OK, 'register success')


class Status:
    def __init__(self, server, username):
        self.username = username
        self.server = server
        self.return_data = self._run(server)

    def _run(self, server):
        # 判断用户名是否存在
        if server.data_db.exists(self.username):

            return ReturnData(ReturnData.OK).add('user_status', get_user_data(server.data_db, self.username)['status'])
        else:

            return ReturnData(ReturnData.NULL, 'username not exists')


class Rename:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.display_name: str
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
            auth_data = server.auth_db.get(self.username)
            self.former_name = auth_data['display_name']
            auth_data['display_name'] = self.display_name
            server.auth_db.set(self.username, auth_data)
            return ReturnData(ReturnData.OK)
        else:
            return msg
