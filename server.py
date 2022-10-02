import re
import threading
import time

import pickledb
from flask import Flask, request
from flask_cors import CORS

from containers import *
from util import *


class HCatServer:
    def __init__(self, address, gc_time, main_page_content):
        # 初始化Flask对象
        app = Flask(__name__)
        CORS(app)
        self.app = app
        # 初始化变量
        self.address = address
        self.gc_time = gc_time

        # 创建数据库对象
        self.auth_db = pickledb.load('auth.db', True)
        self.data_db = pickledb.load('data.db', True)
        self.event_log_db = pickledb.load('event_log.db', True)

        # 创建锁
        self.data_db_lock = threading.Lock()
        self.event_log_db_lock = threading.Lock()

        @self.app.route('/', methods=['GET'])
        def main_page():
            return main_page_content

        @self.app.route('/auth/logout', methods=['GET', 'POST'])
        def logout():
            """
            注册登出路由

            方法:POST/GET

            地址:/auth/logout

            参数:
             username: string

             token: string

            返回:
              status: string

              message: string
            """
            req_data = request_parse(request)

            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']

            # 判断用户名是否存在
            if username not in self.auth_db.getall():
                return ReturnData(ReturnData.NULL, 'username is not exist').json()

                # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:
                # 写入数据库
                self.data_db_lock.acquire()
                userdata = get_user_data(self.data_db, username)
                userdata['status'] = 'offline'
                userdata['token'] = ''
                self.data_db.set(username, userdata)
                self.data_db_lock.release()

                return ReturnData(ReturnData.OK).json()

            else:
                self.data_db_lock.release()
                return msg

        @self.app.route('/auth/login', methods=['GET', 'POST'])
        def login():
            """
            注册登录路由

            方法:POST/GET

            路径:/auth/login

            参数:
             username: string

             password: string

            返回:
             status: string

             token: string

             message: string
            """
            req_data = request_parse(request)

            # 判断请求体是否为空
            if 'username' not in req_data or 'password' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or password is missing').json()

            # 获取请求参数
            username = req_data['username']
            password = req_data['password']

            # 判断用户名是否存在
            if username not in self.auth_db.getall():
                return ReturnData(ReturnData.NULL, 'username is not exist').json()

            # 判断用户名和密码是否正确
            if self.auth_db.get(username)['password'] == salted_hash(password, self.auth_db.get(username)['salt'],
                                                                     username):

                # 生成随机密钥
                token = get_random_token()

                # 写入数据库
                self.data_db_lock.acquire()

                # 读取数据
                userdata = get_user_data(self.data_db, username)

                # 写入字典
                userdata['status'] = 'online'
                userdata['token'] = token
                # 写出
                self.data_db.set(username, userdata)
                self.data_db_lock.release()

                # 返回结果

                return ReturnData(ReturnData.OK, 'login success').add('token', token).json()
            else:

                return ReturnData(ReturnData.ERROR, 'username or password is incorrect').json()

        @self.app.route('/auth/register', methods=['POST', 'GET'])
        def register():
            """
            方法:POST/GET

            路径:/auth/register

            参数:
             username: string

             password: string

             display_name: string

            返回:
             status: string

             message: string
            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'password' not in req_data or 'display_name' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username password or display_name is missing').json()

            # 获取请求参数
            username = req_data['username']
            password = req_data['password']
            display_name = req_data['display_name']

            # 判断用户名是否符合要求
            reg = r'^[a-zA-Z][a-zA-Z0-9_]{4,15}$'
            if not re.match(reg, username):
                return ReturnData(ReturnData.ERROR,
                                  'Username does not meet the requirements of ^[a-zA-Z][a-zA-Z0-9_]{4,15}$').json()

            # 判断密码是否符合要求
            if len(password) < 6:
                return ReturnData(ReturnData.ERROR, 'password is too short').json()

            # 判断用户名是否存在
            if self.auth_db.exists(username):

                return ReturnData(ReturnData.ERROR, 'username already exists').json()
            else:
                # 写入数据库
                salt = get_random_token(16)

                self.auth_db.set(username, {'password': salted_hash(password, salt, username),
                                            'salt': salt,
                                            'display_name': display_name})

                return ReturnData(ReturnData.OK, 'register success').json()

        @self.app.route('/auth/get_display_name/<username>', methods=['GET'])
        def get_display_name(username):
            """
            获取显示名称

            方法:GET

            路径:/auth/get_display_name/<username>

            参数:
             username: string

            返回:
             status: string

             display_name: string
            """
            # 判断用户名是否存在
            if self.auth_db.exists(username):
                return ReturnData(ReturnData.OK).add('display_name', self.auth_db.get(username)['display_name']).json()
            else:
                return ReturnData(ReturnData.OK, 'username not exists').json()

        @self.app.route('/auth/status/<username>', methods=['GET'])
        def status(username):
            """
            获取状态

            方法:GET

            路径:/status/<username>

            参数:
             username: string

            返回:
             status: string (ok/null)

             user_status: string(online/offline)
            """
            # 判断用户名是否存在
            if self.data_db.exists(username):

                return ReturnData(ReturnData.OK).add('user_status',
                                                     get_user_data(self.data_db, username)['status']).json()
            else:

                return ReturnData(ReturnData.NULL, 'username not exists').json()

        @self.app.route('/friend/add/', methods=['POST', 'GET'])
        def add_friend():
            """
            添加好友

            方法:POST/GET

            路径:/friend/add/

            参数:
             username: string

             token: string

             friend_username: string

             additional_information: string

            返回:
             status: string (ok/error/null)

             message: string

            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data or 'friend_username' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']
            friend_username = req_data['friend_username']
            if 'additional_information' in req_data:
                additional_information = req_data['additional_information']
            else:
                additional_information = ''

            # 判断对象是否存在
            if not self.data_db.exists(friend_username):
                return ReturnData(ReturnData.NULL, 'friend not exists').json()

            # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:
                # 判断是否存在friends_list
                if 'friends_list' not in get_user_data(self.data_db, username):
                    user_data = get_user_data(self.data_db, username)
                    user_data['friends_list'] = {}
                    self.data_db.set(username, user_data)
                # 判断是否已经是好友
                if friend_username in get_user_data(self.data_db, username)['friends_list']:
                    return ReturnData(ReturnData.ERROR, 'already friend').json()
                else:
                    # 添加好友
                    friend_data = self.data_db.get(friend_username)

                    # 检测是否存在todo_list
                    if 'todo_list' not in friend_data:
                        friend_data['todo_list'] = []

                    # 将申请加入朋友的todo_list
                    rid = get_random_token(8)
                    while self.event_log_db.exists(rid):
                        rid = get_random_token(8)
                    # 加锁
                    ec = EventContainer(self.event_log_db, self.event_log_db_lock)
                    ec. \
                        add('type', 'friend_request'). \
                        add('rid', ec.rid). \
                        add('username', username). \
                        add('additional_information', additional_information). \
                        add('time', time.time())
                    ec.write()

                    friend_data['todo_list'].append(ec.json)
                    self.data_db.set(friend_username, friend_data)

                    return ReturnData(ReturnData.ERROR, 'add friend success').json()

            else:
                return msg

        @self.app.route('/friend/agree/', methods=['POST', 'GET'])
        def agree_friend():
            """
            同意好友申请

            方法:POST/GET

            路径:/friend/agree/

            参数:
             username: string

             token: string

             rid: string

            返回:
             status: string (ok/error/null)

             message: string

            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data or 'rid' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token or rid is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']
            rid = req_data['rid']

            if self.event_log_db.exists(rid):
                friend_username = self.event_log_db.get(rid)['username']
                self.event_log_db_lock.acquire()
                self.event_log_db.rem(rid)
                self.event_log_db_lock.release()
            else:

                return ReturnData(ReturnData.NULL, 'event not exists').json()

            # 判断对象是否存在
            if not self.data_db.exists(friend_username):
                return ReturnData(ReturnData.NULL, 'friend not exists').json()

            self.data_db_lock.acquire()
            # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:

                # 判断是否已经是好友
                if 'friends_list' in self.data_db.get(friend_username) and username in \
                        self.data_db.get(friend_username)['friends_list']:

                    return ReturnData(ReturnData.ERROR, 'already friend').json()
                else:
                    # 获取好友数据
                    friend_data = self.data_db.get(friend_username)
                    # 检测是否存在todo_list
                    if 'todo_list' not in friend_data:
                        friend_data['todo_list'] = []
                    # 创建事件
                    ec = EventContainer(self.event_log_db, self.event_log_db_lock)
                    ec. \
                        add('type', 'friend_agree'). \
                        add('rid', ec.rid). \
                        add('username', username). \
                        add('time', time.time())
                    ec.write()
                    # 将同意申请加入朋友的todo_list
                    friend_data['todo_list'].append(ec.json)

                    # 检测是否存在朋友列表
                    if 'friends_list' not in friend_data:
                        friend_data['friends_list'] = {}

                    # 加入朋友列表
                    display_name = self.auth_db.get(username)['display_name']
                    friend_data['friends_list'][username] = {'nick': display_name,
                                                             'time': time.time()}

                    # 获取用户状态
                    user_data = get_user_data(self.data_db, username)

                    # 检测是否存在朋友列表
                    if 'friends_list' not in user_data:
                        user_data['friends_list'] = {}

                    # 加入朋友列表
                    friend_display_name = self.auth_db.get(friend_username)['display_name']
                    user_data['friends_list'][friend_username] = {'nick': friend_display_name,
                                                                  'time': time.time()}
                    self.data_db.set(friend_username, friend_data)
                    self.data_db.set(username, user_data)
                    self.data_db_lock.release()
                    return ReturnData(ReturnData.OK, 'agree friend success').json()
            else:
                self.data_db_lock.release()
                return msg

        @self.app.route('/friend/delete/', methods=['POST', 'GET'])
        def delete_friend():
            """
            删除好友

            方法:POST/GET

            路径:/friend/delete/

            参数:
             username: string

             token: string

             friend_username: string

            返回:
             status: string (ok/error/null)

             message: string
            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data or 'friend_username' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']
            friend_username = req_data['friend_username']
            # 判断用户名是否存在
            self.data_db_lock.acquire()
            # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:
                friend_data = self.data_db.get(friend_username)

                # 检测是否存在todo_list
                if 'todo_list' not in friend_data:
                    friend_data['todo_list'] = []
                # 创建事件
                ec = EventContainer(self.event_log_db, self.event_log_db_lock)
                ec.add('type', 'friend_deleted').add('rid', ec.rid).add('username', username).add('time', time.time())
                ec.write()
                # 将好友删除事件加入朋友的todo_list
                friend_data['todo_list'].append(ec.json)
                if 'friends_list' in friend_data:
                    # 从好友的好友列表删除
                    del friend_data['friends_list'][username]
                    self.data_db.set(friend_username, friend_data)
                else:
                    friend_data['friends_list'] = {}
                    self.data_db.set(friend_username, friend_data)

                # 从好友列表删除

                user_data = get_user_data(self.data_db, username)
                if 'friends_list' in user_data:
                    # 从好友的好友列表删除
                    del user_data['friends_list'][friend_username]

                else:
                    user_data['friends_list'] = {}
                self.data_db.set(username, user_data)

                self.data_db_lock.release()
                return ReturnData(ReturnData.OK).json()

            else:
                self.data_db_lock.release()
                return msg

        @self.app.route('/friend/get_friends_list/', methods=['POST', 'GET'])
        def get_friend_list():
            """
            获取好友列表

            方法:POST/GET

            路径:/friend/get_friends_list/

            参数:
             username: string

             token: string

            返回:
             status: string (ok/error/null)

             message: string

             data: dict
            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']

            # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:
                # 取用户数据
                user_data = get_user_data(self.data_db, username)
                # 判断并返回好友列表
                if 'friends_list' in user_data:

                    return ReturnData(ReturnData.OK).add('data', user_data['friends_list']).json()
                else:
                    return ReturnData(ReturnData.OK).add('data', {}).json()

            else:
                return msg

        @self.app.route('/auth/get_todo_list/', methods=['POST', 'GET'])
        def get_todo_list():
            """
            获取todolist

            方法:POST/GET

            路径:/auth/get_todo_list/

            参数:
             username: string

             token: string

            返回:
             status: string (ok/error/null)

             message: string

             data: list<string>
            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data or 'token' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username or token is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']

            # 验证用户名与token
            auth_status, msg = self.authenticate_token(username, token)
            if auth_status:
                data = get_user_data(self.data_db, username)
                if 'todo_list' in data:
                    # 取得结果
                    res = data['todo_list']
                else:
                    res = []
                # 清空todo_list
                data['todo_list'] = []
                # 计入数据库
                self.data_db.set(username, data)
                return ReturnData(ReturnData.OK).add('data', res).json()

            else:
                return msg

        @app.route('/chat/friend/send_msg/', methods=['POST', 'GET'])
        def send_friend_msg():
            """
            发送好友信息

            方法:POST/GET

            路径:/chat/friend/send_msg/

            参数:
             username: string

             token: string

             friend_username: string

             msg: dict

            返回:
             status: string

             message: string
            """
            req_data = request_parse(request)
            # 判断请求体是否为空
            if 'username' not in req_data \
                    or 'token' not in req_data \
                    or 'friend_username' not in req_data \
                    or 'msg' not in req_data:
                return ReturnData(ReturnData.ERROR, 'username token friend_username or msg is missing').json()

            # 获取请求参数
            username = req_data['username']
            token = req_data['token']
            friend_username = req_data['friend_username']
            msg = req_data['msg']
            data = get_user_data(self.data_db, username)
            # 判断是否为空
            if 'friends_list' not in data:
                data['friends_list'] = {}

            if friend_username not in data['friends_list']:
                return ReturnData(ReturnData.NULL, 'friends not exists.').json()

            self.data_db_lock.acquire()
            # 验证用户名与token
            auth_status, rt_msg = self.authenticate_token(username, token)
            if auth_status:
                friend_data = self.data_db.get(friend_username)
                # 判断是否为空
                if 'todo_list' not in friend_data:
                    friend_data['todo_list'] = []

                ec = EventContainer(self.event_log_db, self.event_log_db_lock)
                ec. \
                    add('type', 'friend_msg'). \
                    add('rid', ec.rid). \
                    add('username', username). \
                    add('msg', msg). \
                    add('time', time.time())
                ec.write()
                # 清空todo_list
                friend_data['todo_list'].append(ec.json)

                # 计入数据库
                self.data_db.set(friend_username, friend_data)
                self.data_db_lock.release()

                return ReturnData(ReturnData.OK).json()

            else:
                self.data_db_lock.release()
                return rt_msg

    def start(self):
        threading.Thread(target=self._event_log_clear_thread).start()
        self.app.run(host=self.address[0], port=self.address[1])

    def _event_log_clear_thread(self):

        while True:
            i = 0
            self.event_log_db_lock.acquire()
            for j in self.event_log_db.getall():
                event_time = self.event_log_db.get(j)['time']
                if time.time() - event_time >= 604800:
                    i += 1
                    self.event_log_db.rem(j)
            self.event_log_db_lock.release()
            if i > 0:
                print('Cleaned up {} expired events.'.format(i))
            time.sleep(self.gc_time)

    def authenticate_token(self, username, token):
        if self.data_db.exists(username):
            if get_user_data(self.data_db, username)['token'] == token:
                return True, None
            else:

                return False, ReturnData(ReturnData.ERROR, 'token error').json()
        else:
            return False, ReturnData(ReturnData.NULL, 'username not exists').json()
