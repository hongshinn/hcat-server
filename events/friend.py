import time

from containers import ReturnData, EventContainer
from events.event import Event
from server import HCatServer
from util import request_parse, ins


class AddFriend(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'friend_username'], req_data):
            return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']
        self.additional_information = req_data['additional_information'] if 'additional_information' in req_data else ''

        # 判断对象是否存在
        if not server.data_db.exists(self.friend_username):
            return ReturnData(ReturnData.NULL, 'friend not exists')

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在friends_list
            if 'friends_list' not in server.get_user_data(self.username):
                user_data = server.get_user_data(self.username)
                user_data['friends_list'] = {}
                server.data_db.set(self.username, user_data)

            # 判断是否已经是好友
            if self.friend_username in server.get_user_data(self.username)['friends_list']:
                return ReturnData(ReturnData.ERROR, 'already friend')
            else:
                # 将申请加入朋友的todo_list
                ec = EventContainer(server.event_log_db, server.event_log_db_lock)
                ec. \
                    add('type', 'friend_request'). \
                    add('rid', ec.rid). \
                    add('username', self.username). \
                    add('additional_information', self.additional_information). \
                    add('time', time.time())
                ec.write()

                server.set_user_todo_list(self.friend_username, ec)

                return ReturnData(ReturnData.OK, 'add friend success')

        else:
            return msg


class AgreeFriendRequire(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'rid'], req_data):
            return ReturnData(ReturnData.ERROR, 'username or token or rid is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.rid = req_data['rid']

        # 取事件
        if server.event_log_db.exists(self.rid):
            self.friend_username = server.event_log_db.get(self.rid)['username']

            server.event_log_db_lock.acquire()
            server.event_log_db.rem(self.rid)
            server.event_log_db_lock.release()
        else:

            return ReturnData(ReturnData.NULL, 'event not exists')

        # 判断对象是否存在
        if not server.data_db.exists(self.friend_username):
            return ReturnData(ReturnData.NULL, 'user not exists')

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:

            # 判断是否已经是好友
            if 'friends_list' in server.data_db.get(self.friend_username) and self.username in \
                    server.data_db.get(self.friend_username)['friends_list']:

                return ReturnData(ReturnData.ERROR, 'already friend')

            else:
                self.cancel = False

                return ReturnData(ReturnData.OK, 'agree friend success')
        else:
            return msg

    def _return(self):
        server = self.server

        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'friend_agree'). \
            add('rid', ec.rid). \
            add('username', self.username). \
            add('time', time.time())
        ec.write()

        # 将同意申请加入朋友的todo_list
        server.set_user_todo_list(self.friend_username, ec)

        server.data_db_lock.acquire()
        friend_data = server.data_db.get(self.friend_username)

        # 检测是否存在朋友列表
        if 'friends_list' not in friend_data:
            friend_data['friends_list'] = {}

        # 加入朋友列表
        display_name = server.auth_db.get(self.username)['display_name']
        friend_data['friends_list'][self.username] = {'nick': display_name,
                                                      'time': time.time()}

        # 获取用户状态
        user_data = server.get_user_data(self.username)

        # 检测是否存在朋友列表
        if 'friends_list' not in user_data:
            user_data['friends_list'] = {}

        # 加入朋友列表
        friend_display_name = server.auth_db.get(self.friend_username)['display_name']
        user_data['friends_list'][self.friend_username] = {'nick': friend_display_name,
                                                           'time': time.time()}
        server.data_db.set(self.friend_username, friend_data)
        server.data_db.set(self.username, user_data)
        server.data_db_lock.release()


class DeleteFriend(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)

        # 判断请求体是否为空
        if not ins(['username', 'token', 'friend_username'], req_data):
            return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False

            return ReturnData(ReturnData.OK)

        else:

            return msg

    def _return(self):
        server = self.server

        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec.add('type', 'friend_deleted').add('rid', ec.rid).add('username', self.username).add('time', time.time())
        ec.write()

        # 将好友删除事件加入朋友的todo_list
        server.set_user_todo_list(self.friend_username, ec)

        # 从对象的好友列表删除
        server.data_db_lock.acquire()
        friend_data = server.get_user_data(self.friend_username)
        if 'friends_list' in friend_data:
            # 删除数据
            del friend_data['friends_list'][self.username]
        else:
            friend_data['friends_list'] = {}

        server.data_db.set(self.friend_username, friend_data)

        # 从好友列表删除
        user_data = server.get_user_data(self.username)
        if 'friends_list' in user_data:
            # 从好友的好友列表删除
            del user_data['friends_list'][self.friend_username]
        else:
            user_data['friends_list'] = {}

        server.data_db.set(self.username, user_data)

        server.data_db_lock.release()


class GetFriendsList(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token'], req_data):
            return ReturnData(ReturnData.ERROR, 'username or token is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 取用户数据
            user_data = server.get_user_data(self.username)

            # 判断并返回好友列表
            if 'friends_list' in user_data:
                return ReturnData(ReturnData.OK).add('data', user_data['friends_list'])
            else:
                return ReturnData(ReturnData.OK).add('data', {})

        else:
            return msg
