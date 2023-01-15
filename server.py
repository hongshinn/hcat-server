import platform
import sys

HCatServer = None
from typing import Union, Tuple

from flask import Flask, request
from flask_cors import CORS
from gevent import pywsgi

from config_loader import Config
from events.auth import *
from events.chat import *
from events.friend import *
from events.group import *
from plugin_manager.manager import HCat
from rpdb.database import *

del HCatServer


class HCatServer:

    def __init__(self, config: Config):
        # 初始化Flask对象
        app = Flask(__name__)

        CORS(app)
        self.app = app

        # 初始化变量
        self.address = (config.IP, config.Port)
        self.gc_time = config.GCTime
        self.event_timeout = config.EventTimeout
        self.get_todo_list_count = {}
        self.config = config
        self.ver = '0.3.8'

        # 创建数据库对象
        log_output(__name__, text='Loading the database...')
        self.auth_db = RPDB(os.path.join(os.getcwd(), 'data', 'auth'), slice_multiplier=2)
        self.data_db = RPDB(os.path.join(os.getcwd(), 'data', 'data'), slice_multiplier=2)
        self.event_log_db = RPDB(os.path.join(os.getcwd(), 'data', 'event_log'), slice_multiplier=2)
        self.groups_db = RPDB(os.path.join(os.getcwd(), 'data', 'groups'), slice_multiplier=2)
        log_output(__name__, text='Database loading completed.')

        # 创建锁
        self.data_db_lock = threading.Lock()
        self.event_log_db_lock = threading.Lock()
        self.auth_db_lock = threading.Lock()
        self.groups_db_lock = threading.Lock()

        # 加载插件
        log_output(__name__, text='Loading the plugins...')
        self.hcat = HCat(self)
        self.hcat.load_all_plugins()
        log_output(__name__, text='Plugins loading completed.')

        @self.app.route('/', methods=['GET'])
        def main_page():
            return config.MainPageContent

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
            return e.e_return()

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
            return e.e_return()

        @self.app.route('/auth/change_password', methods=['GET', 'POST'])
        def change_password():
            e = ChangePassword(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/auth/authenticate_token', methods=['GET', 'POST'])
        def authenticate_token():
            e = AuthenticateToken(self, request)
            self.hcat(e)
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

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
            return e.e_return()

        @self.app.route('/group/create_group', methods=['POST', 'GET'])
        def create_group():
            e = CreateGroup(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/join_group', methods=['POST', 'GET'])
        def join_group():
            e = JoinGroup(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/agree_join_group_request', methods=['POST', 'GET'])
        def agree_join_group_request():
            e = AgreeJoinGroupRequest(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_group_members_list', methods=['POST', 'GET'])
        def get_group_members_list():
            e = GetGroupMembersList(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_group_settings', methods=['POST', 'GET'])
        def get_group_settings():
            e = GetGroupSettings(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/change_group_settings', methods=['POST', 'GET'])
        def change_group_settings():
            e = ChangeGroupSettings(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/chat/group/send_msg', methods=['POST', 'GET'])
        def send_group_msg():
            e = SendGroupMsg(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_group_name/<group_id>', methods=['GET'])
        def get_group_name(group_id):
            e = GetGroupName(self, group_id)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_groups_list', methods=['POST', 'GET'])
        def get_groups_list():
            e = GetGroupsList(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/group_rename', methods=['POST', 'GET'])
        def group_rename():
            e = GroupRename(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/leave', methods=['POST', 'GET'])
        def group_leave():
            e = Leave(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/kick', methods=['POST', 'GET'])
        def group_kick():
            e = Kick(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_group_admin_list', methods=['POST', 'GET'])
        def group_get_admin_list():
            e = GetGroupAdminList(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/get_group_owner', methods=['POST', 'GET'])
        def group_get_owner():
            e = GetGroupOwner(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.route('/group/ban', methods=['POST', 'GET'])
        def group_ban():
            e = Ban(self, request)
            self.hcat(e)
            return e.e_return()

        @self.app.before_request
        def log_each_request():
            # log_output('Flask', text='{} {} {}'.format(request.remote_addr, request.method, request.path))
            ...

    def _server_thread(self):
        # 判断是否ssl
        if self.config.SSLCert is not None:

            server = pywsgi.WSGIServer((self.address[0], self.address[1]), self.app,
                                       ssl_context=(self.config.SSLCert, self.config.SSLKey))
        else:
            server = pywsgi.WSGIServer((self.address[0], self.address[1]), self.app)

        server.serve_forever()

    def start(self):
        log_output(__name__, text='Server is starting up...')
        # 线程启动
        t_do = threading.Thread(target=self._detection_online_thread, daemon=True)
        t_elc = threading.Thread(target=self._event_log_clear_thread, daemon=True)
        t_s = threading.Thread(target=self._server_thread, daemon=True)

        t_do.start()
        t_elc.start()
        t_s.start()

        log_output(__name__, text='Server is listening to {}:{}.'.format(self.address[0], self.address[1]))
        log_output(text='----Server is loaded----')
        log_output(text='Version:{}'.format(self.ver))
        log_output(text='Py ver:{}'.format(sys.version))
        log_output(text='SYS ver:{}'.format(platform.platform()))
        log_output(text='------------------------')
        loop = True
        while loop:
            try:
                t_do.join(timeout=0.1)
            except KeyboardInterrupt:
                loop = False

    def _event_log_clear_thread(self):

        while True:
            # 上锁
            self.event_log_db_lock.acquire()
            # 初始化变量
            i = 0
            del_list = []
            # 遍历事件列表
            for j in self.event_log_db.getall():
                # 获取事件事件
                event_time = self.event_log_db.get(j)['time']
                # 检查是否超时
                if time.time() - event_time >= self.event_timeout:
                    i += 1
                    # 加入待删除
                    del_list.append(j)
            # 删除事件
            [self.event_log_db.rem(j) for j in del_list]
            # 解锁
            self.event_log_db_lock.release()
            # 输出
            if i > 0:
                log_output(text='Cleaned up {} expired events.'.format(i))
            time.sleep(self.gc_time)

    def _detection_online_thread(self):
        while True:
            self.data_db_lock.acquire()
            # 遍历用户
            for username in self.get_todo_list_count:
                # 获取用户数据
                user_data = self.get_user_data(username)
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

    def authenticate_token(self, username: str, token: str) -> Tuple[bool, Union[ReturnData, None]]:
        """
        :param username: str
        :param token: str
        :return: tuple[bool, Union[dict, None]]
        """
        if self.data_db.exists(username):  # 检查数据库中是否存在用户
            if self.get_user_data(username)['token'] == token:  # 检查token是否正确
                return True, None
            else:
                return False, ReturnData(ReturnData.ERROR, 'token error')
        else:
            return False, ReturnData(ReturnData.NULL, 'username not exists')

    def send_message_box(self, msg_type=0, title='', username='', text='', path='\\', param_name='text') -> str:
        """
        :param msg_type: int
        :param title: str
        :param username: str
        :param text: str
        :param path: str
        :param param_name: str
        :return: str
        """

        # 设置信息类型
        msg = 'message' if msg_type == 0 else 'question'

        # 创建事件容器
        ec = EventContainer(self.event_log_db, self.event_log_db_lock)
        ec. \
            add('type', msg). \
            add('rid', ec.rid). \
            add('title', title). \
            add('text', text). \
            add('path', path). \
            add('username', username). \
            add('param_name', param_name). \
            add('time', time.time())
        ec.write()
        # 写入用户待办列表
        self.set_user_todo_list(username, ec)
        return ec.rid

    def get_user_data(self, username: str) -> dict:
        """
        :param username: str
        :return: dict
        """
        if self.data_db.exists(username):  # 检查是否存在用户
            return self.data_db.get(username)
        else:
            return {}

    def set_user_todo_list(self, username: str, ec: EventContainer):
        """
        :param username: str
        :param ec: EventContainer
        """

        # 上锁
        self.data_db_lock.acquire()
        # 取用户数据
        data = self.get_user_data(username)
        # 检查是否存在待办列表
        if 'todo_list' not in data:
            data['todo_list'] = []
        # 加入事件
        data['todo_list'].append(ec.json)
        # 写入数据库
        self.data_db.set(username, data)
        # 解锁
        self.data_db_lock.release()
