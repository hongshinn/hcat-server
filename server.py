HCatServer = None
import threading
from typing import Union

import pickledb
from flask import Flask, request
from flask_cors import CORS

from events.auth import *
from events.chat import *
from events.friend import *
from plugin_manager.manager import HCat
from util import *

del HCatServer


class HCatServer:
    def __init__(self, address, gc_time, main_page_content, event_timeout):
        # 初始化Flask对象
        app = Flask(__name__)
        CORS(app)
        self.app = app

        # 初始化变量
        self.address = address
        self.gc_time = gc_time
        self.event_timeout = event_timeout
        self.get_todo_list_count = {}
        # 创建数据库对象
        self.auth_db = pickledb.load('auth.db', True)
        self.data_db = pickledb.load('data.db', True)
        self.event_log_db = pickledb.load('event_log.db', True)

        # 创建锁
        self.data_db_lock = threading.Lock()
        self.event_log_db_lock = threading.Lock()
        self.auth_db_lock = threading.Lock()

        # 加载插件
        self.hcat = HCat()
        self.hcat.load_all_plugins()

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
            e = Logout(self, request)
            self.hcat(e)
            return e.return_data.json()

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
            e = Login(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/auth/change_password', methods=['GET', 'POST'])
        def change_password():
            e = ChangePassword(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/auth/authenticate_token', methods=['GET', 'POST'])
        def authenticate_token():
            e = AuthenticateToken(self, request)
            self.hcat(e)
            return e.return_data.json()

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
            e = Register(self, request)
            self.hcat(e)
            return e.return_data.json()

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
            e = GetDisplayName(self, username)
            self.hcat(e)
            return e.return_data.json()

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

            e = Status(self, username)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/auth/rename', methods=['POST', 'GET'])
        def rename():
            """
            重命名

            方法:POST/GET

            路径:/auth/rename

            参数:
             username: string

             token: string

             display_name

            返回:
             status: string (ok/error/null)

             message: string
            """
            e = Rename(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/auth/get_todo_list', methods=['POST', 'GET'])
        def get_todo_list():
            """
            获取todolist

            方法:POST/GET

            路径:/auth/get_todo_list

            参数:
             username: string

             token: string

            返回:
             status: string (ok/error/null)

             message: string

             data: list<string>
            """
            e = GetTodoList(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/friend/add', methods=['POST', 'GET'])
        def add_friend():
            """
            添加好友

            方法:POST/GET

            路径:/friend/add

            参数:
             username: string

             token: string

             friend_username: string

             additional_information: string

            返回:
             status: string (ok/error/null)

             message: string

            """
            e = AddFriend(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/friend/agree', methods=['POST', 'GET'])
        def agree_friend():
            """
            同意好友申请

            方法:POST/GET

            路径:/friend/agree

            参数:
             username: string

             token: string

             rid: string

            返回:
             status: string (ok/error/null)

             message: string

            """
            e = AgreeFriendRequire(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/friend/delete', methods=['POST', 'GET'])
        def delete_friend():
            """
            删除好友

            方法:POST/GET

            路径:/friend/delete

            参数:
             username: string

             token: string

             friend_username: string

            返回:
             status: string (ok/error/null)

             message: string
            """
            e = DeleteFriend(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/friend/get_friends_list', methods=['POST', 'GET'])
        def get_friend_list():
            """
            获取好友列表

            方法:POST/GET

            路径:/friend/get_friends_list

            参数:
             username: string

             token: string

            返回:
             status: string (ok/error/null)

             message: string

             data: dict
            """
            e = GetFriendsList(self, request)
            self.hcat(e)
            return e.return_data.json()

        @self.app.route('/chat/friend/send_msg', methods=['POST', 'GET'])
        def send_friend_msg():
            """
            发送好友信息

            方法:POST/GET

            路径:/chat/friend/send_msg

            参数:
             username: string

             token: string

             friend_username: string

             msg: string

            返回:
             status: string

             message: string
            """
            e = SendFriendMsg(self, request)
            self.hcat(e)
            return e.return_data.json()

    def start(self):
        threading.Thread(target=self._detection_online_thread).start()
        threading.Thread(target=self._event_log_clear_thread).start()
        self.app.run(host=self.address[0], port=self.address[1])

    def _event_log_clear_thread(self):

        while True:
            i = 0
            self.event_log_db_lock.acquire()
            del_list = []
            for j in self.event_log_db.getall():
                event_time = self.event_log_db.get(j)['time']
                if time.time() - event_time >= self.event_timeout:
                    i += 1
                    del_list.append(j)
            [self.event_log_db.rem(j) for j in del_list]
            self.event_log_db_lock.release()
            if i > 0:
                print('Cleaned up {} expired events.'.format(i))
            time.sleep(self.gc_time)

    def _detection_online_thread(self):
        while True:
            self.data_db_lock.acquire()
            # 遍历用户
            for username in self.get_todo_list_count:
                # 获取用户数据
                user_data = get_user_data(self.data_db, username)
                # 判断
                if self.get_todo_list_count[username] == 0:
                    user_data['status'] = 'offline'
                else:
                    user_data['status'] = 'online'
                # 写入数据
                self.data_db.set(username, user_data)
                # 清空计次
                self.get_todo_list_count[username] = 0
            self.data_db_lock.release()
            time.sleep(30)

    def authenticate_token(self, username: str, token: str) -> tuple[bool, Union[ReturnData, None]]:
        """

        :param username: str
        :param token: str
        :return: tuple[bool, Union[dict, None]]
        """
        if self.data_db.exists(username):
            if get_user_data(self.data_db, username)['token'] == token:
                return True, None
            else:
                return False, ReturnData(ReturnData.ERROR, 'token error')
        else:
            return False, ReturnData(ReturnData.NULL, 'username not exists')

    def send_message_box(self, msg_type=0, title='', username='', text='', path='\\', param_name='text'):
        msg = 'message' if msg_type == 0 else 'question'

        ec = EventContainer(self.event_log_db, self.event_log_db_lock)
        ec. \
            add('type', msg). \
            add('rid', ec.rid). \
            add('title', title). \
            add('text', text). \
            add('path', path). \
            add('param_name', param_name). \
            add('time', time.time())
        ec.write()

        self.data_db_lock.acquire()
        user_data = self.data_db.get(username)
        # 检测是否存在todo_list
        if 'todo_list' not in user_data:
            user_data['todo_list'] = []

        user_data['todo_list'].append(ec.json)
        self.data_db.set(username, user_data)
        self.data_db_lock.release()
