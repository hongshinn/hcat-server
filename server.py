import hashlib
import re
import threading
import time

from flask import Flask, request, jsonify
import pickledb

from util import get_random_token


class HCatServer:
    def __init__(self, address):
        # 初始化Flask对象
        app = Flask(__name__)
        self.app = app
        # 初始化变量
        self.address = address

        # 创建数据库对象
        self.auth_db = pickledb.load('auth.db', True)
        self.data_db = pickledb.load('data.db', True)
        self.event_log_db = pickledb.load('event_log.db', True)

        # 创建锁
        self.data_db_lock = threading.Lock()
        self.event_log_db_lock = threading.Lock()

        # 注册路由
        # 注册登录路由
        # POST /auth/login
        #  username: string
        #  password: string
        # return:
        #  status: string
        #  token: string
        #  message: string
        @self.app.route('/auth/login', methods=['POST'])
        def login():
            # 判断请求体是否为空
            if 'username' not in request.form or 'password' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or password is missing'})

            # 获取请求参数
            username = request.form['username']
            password = request.form['password']

            # 判断用户名是否存在
            if username not in self.auth_db.getall():
                return jsonify({'status': 'error', 'message': 'username is not exist'})

            # 判断用户名和密码是否正确
            if self.auth_db.get(username)['password'] == hashlib.sha1((password + '1145').encode('utf8')).hexdigest():

                # 生成随机密钥
                token = get_random_token()

                # 写入数据库
                self.data_db.set(username, {'status': 'online', 'token': token})

                # 返回结果
                return jsonify({'status': 'ok', 'token': token, 'message': 'login success'})
            else:
                return jsonify({'status': 'error', 'message': 'username or password is incorrect'})

        # 注册注册路由
        # POST /auth/register
        #  username: string
        #  password: string
        #  display_name: string
        # return:
        #  status: string
        #  message: string
        @self.app.route('/auth/register', methods=['POST'])
        def register():
            # 判断请求体是否为空
            if 'username' not in request.form or 'password' not in request.form or 'display_name' not in request.form:
                return jsonify({'status': 'error', 'message': 'username password or display_name is missing'})

            # 获取请求参数
            username = request.form['username']
            password = request.form['password']
            display_name = request.form['display_name']

            # 判断用户名是否符合要求
            reg = r'^[a-zA-Z][a-zA-Z0-9_]{4,15}$'
            if not re.match(reg, username):
                return jsonify({'status': 'error',
                                'message': 'Username does not meet the requirements of ^[a-zA-Z][a-zA-Z0-9_]{4,15}$'})

            # 判断密码是否符合要求
            if len(password) < 6:
                return jsonify({'status': 'error', 'message': 'password is too short'})

            # 判断用户名是否存在
            if self.auth_db.exists(username):
                return jsonify({'status': 'error', 'message': 'username already exists'})
            else:
                # 写入数据库

                self.auth_db.set(username, {'password': hashlib.sha1((password + '1145').encode('utf8')).hexdigest(),
                                            'display_name': display_name})
                return jsonify({'status': 'ok', 'message': 'register success'})

        # 获取显示名称
        # GET /auth/get_display_name/<username>
        #  username: string
        # return:
        #  status: string
        #  display_name: string
        @self.app.route('/auth/get_display_name/<username>', methods=['GET'])
        def get_display_name(username):
            # 判断用户名是否存在
            if self.auth_db.exists(username):
                return jsonify({'status': 'ok', 'display_name': self.auth_db.get(username)['display_name']})
            else:
                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 获取状态
        # GET /status/<username>
        #  username: string
        # return: json
        #  status: string (online/offline/null)
        @self.app.route('/auth/status/<username>', methods=['GET'])
        def status(username):
            # 判断用户名是否存在
            if self.data_db.exists(username):
                return jsonify({'status': self.data_db.get(username)['status']})
            else:
                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 添加好友
        # POST /friend/add/
        #  username: string
        #  token: string
        #  friend_username: string
        #  additional_information: string
        # return:
        #  status: string (ok/error/null)
        #  message: string
        @self.app.route('/friend/add/', methods=['POST'])
        def add_friend():
            # 判断请求体是否为空
            if 'username' not in request.form or 'token' not in request.form or 'friend_username' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or token or friend_username is missing'})

            # 获取请求参数
            username = request.form['username']
            token = request.form['token']
            friend_username = request.form['friend_username']
            if 'additional_information' in request.form:
                additional_information = request.form['additional_information']
            else:
                additional_information = ''

            # 判断对象是否存在
            if not self.data_db.exists(friend_username):
                return jsonify({'status': 'null', 'message': 'friend not exists'})

            # 判断用户名是否存在
            if self.data_db.exists(username):
                # 判断token是否正确
                if self.data_db.get(username)['token'] == token:
                    # 判断是否存在friends_list
                    if 'friends_list' not in self.data_db.get(username):
                        user_data = self.data_db.get(username)
                        user_data['friends_list'] = {}
                        self.data_db.set(username, user_data)
                    # 判断是否已经是好友
                    if friend_username in self.data_db.get(username)['friends_list']:
                        return jsonify({'status': 'error', 'message': 'already friend'})
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
                        self.event_log_db_lock.acquire()
                        self.event_log_db. \
                            set(rid,
                                {'type': 'friend_request',
                                 'username': username,
                                 'time': time.time()}
                                )
                        # 解锁
                        self.event_log_db_lock.release()
                        friend_data['todo_list'].append(
                            {'type': 'friend_request',
                             'rid': rid,
                             'username': username,
                             'additional_information': additional_information,
                             'time': time.time()})
                        self.data_db.set(friend_username, friend_data)
                        return jsonify({'status': 'ok', 'message': 'add friend success'})
                else:
                    return jsonify({'status': 'error', 'message': 'token error'})
            else:
                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 同意好友申请
        # POST /friend/agree/
        #  username: string
        #  token: string
        #  rid: string
        # return:
        #  status: string (ok/error/null)
        #  message: string
        @self.app.route('/friend/agree/', methods=['POST'])
        def agree_friend():
            # 判断请求体是否为空
            if 'username' not in request.form or 'token' not in request.form or 'rid' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or token or rid is missing'})

            # 获取请求参数
            username = request.form['username']
            token = request.form['token']
            rid = request.form['rid']

            if self.event_log_db.exists(rid):
                friend_username = self.event_log_db.get(rid)['username']
                self.event_log_db_lock.acquire()
                self.event_log_db.rem(rid)
                self.event_log_db_lock.release()
            else:
                return jsonify({'status': 'null', 'message': 'rid not exists'})

            # 判断对象是否存在
            if not self.data_db.exists(friend_username):
                return jsonify({'status': 'null', 'message': 'friend not exists'})

            self.data_db_lock.acquire()
            # 判断用户名是否存在
            if self.data_db.exists(username):
                # 判断token是否正确
                if self.data_db.get(username)['token'] == token:

                    # 判断是否已经是好友
                    if 'friends_list' in self.data_db.get(friend_username) and username in \
                            self.data_db.get(friend_username)['friends_list']:
                        return jsonify({'status': 'error', 'message': 'already friend.'})
                    else:
                        # 获取好友数据
                        friend_data = self.data_db.get(friend_username)
                        # 检测是否存在todo_list
                        if 'todo_list' not in friend_data:
                            friend_data['todo_list'] = []

                        # 将同意申请加入朋友的todo_list
                        friend_data['todo_list'].append(
                            {'type': 'friend_agree',
                             'rid': get_random_token(8),
                             'username': username,
                             'time': time.time()})

                        # 检测是否存在朋友列表
                        if 'friends_list' not in friend_data:
                            friend_data['friends_list'] = {}

                        # 加入朋友列表
                        display_name = self.auth_db.get(username)['display_name']
                        friend_data['friends_list'][username] = {'nick': display_name,
                                                                 'time': time.time()}

                        # 获取用户状态
                        user_data = self.data_db.get(username)

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
                        return jsonify({'status': 'ok', 'message': 'agree friend success'})
                else:
                    self.data_db_lock.release()
                    return jsonify({'status': 'error', 'message': 'token error'})
            else:
                self.data_db_lock.release()
                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 删除好友
        # POST /friend/delete/
        #  username: string
        #  token: string
        #  friend_username: string
        # return:
        #  status: string (ok/error/null)
        #  message: string
        @self.app.route('/friend/delete/', methods=['POST'])
        def delete_friend():
            # 判断请求体是否为空
            if 'username' not in request.form or 'token' not in request.form or 'friend_username' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or token or friend_username is missing'})

            # 获取请求参数
            username = request.form['username']
            token = request.form['token']
            friend_username = request.form['friend_username']
            # 判断用户名是否存在
            self.data_db_lock.acquire()
            if self.data_db.exists(username):
                if self.data_db.get(username)['token'] == token:
                    friend_data = self.data_db.get(friend_username)

                    # 检测是否存在todo_list
                    if 'todo_list' not in friend_data:
                        friend_data['todo_list'] = []

                    # 将好友删除事件加入朋友的todo_list
                    friend_data['todo_list'].append(
                        {'type': 'friend_deleted',
                         'rid': get_random_token(8),
                         'username': username,
                         'time': time.time()})

                    # 从好友的好友列表删除
                    del friend_data['friends_list'][username]
                    self.data_db.set(friend_username, friend_data)

                    # 从好友列表删除
                    user_data = self.data_db.get(username)
                    del user_data['friends_list'][friend_username]
                    self.data_db.set(username, user_data)
                    self.data_db_lock.release()
                    return jsonify({'status': 'ok'})
                else:
                    self.data_db_lock.release()
                    return jsonify({'status': 'error', 'message': 'token error'})
            else:
                self.data_db_lock.release()
                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 获取好友列表
        # POST /friend/get_friends_list/
        #  username: string
        #  token: string
        # return:
        #  status: string (ok/error/null)
        #  message: string
        #  data: dict
        @self.app.route('/friend/get_friends_list/', methods=['POST'])
        def get_friend_list():
            # 判断请求体是否为空
            if 'username' not in request.form or 'token' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or token is missing'})

            # 获取请求参数
            username = request.form['username']
            token = request.form['token']

            # 判断用户名是否存在

            if self.data_db.exists(username):
                # 判断token是否正确
                if self.data_db.get(username)['token'] == token:
                    # 取用户数据
                    user_data = self.data_db.get(username)
                    # 判断并返回好友列表
                    if 'friends_list' in user_data:
                        return jsonify({'status': 'ok', 'data': user_data['friends_list']})
                    else:
                        return jsonify({'status': 'ok', 'data': {}})
                else:

                    return jsonify({'status': 'error', 'message': 'token error'})
            else:

                return jsonify({'status': 'null', 'message': 'username not exists'})

        # 获取todolist
        # POST /auth/get_todo_list/
        #  username: string
        #  token: string
        # return:
        #  status: string (ok/error/null)
        #  message: string
        #  data: list<string>
        @self.app.route('/auth/get_todo_list/', methods=['POST'])
        def get_todo_list():
            # 判断请求体是否为空
            if 'username' not in request.form or 'token' not in request.form:
                return jsonify({'status': 'error', 'message': 'username or token is missing'})

            # 获取请求参数
            username = request.form['username']
            token = request.form['token']

            # 判断用户名是否存在
            if self.data_db.exists(username):
                # 判断token是否正确
                if self.data_db.get(username)['token'] == token:
                    data = self.data_db.get(username)
                    # 取得结果
                    res = data['todo_list']
                    # 清空todo_list
                    data['todo_list'] = []
                    # 计入数据库
                    self.data_db.set(username, data)
                    return jsonify({'status': 'ok', 'data': res})

                else:
                    return jsonify({'status': 'error', 'message': 'token error'})
            else:
                return jsonify({'status': 'null', 'message': 'username not exists'})

    def start(self):
        threading.Thread(target=self._event_log_clear_thread).start()
        self.app.run(host=self.address[0], port=self.address[1])

    def _event_log_clear_thread(self):

        while True:
            i = 0
            self.event_log_db_lock.acquire()
            for i in self.event_log_db.getall():
                event_time = self.event_log_db.get(i)['time']
                if time.time() - event_time >= 604800:
                    i += 1
                    self.event_log_db.rem(i)
            self.event_log_db_lock.release()
            if i > 0:
                print('Cleaned up {} expired events.'.format(i))
            time.sleep(30)
