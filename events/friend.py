import time

from containers import ReturnData, EventContainer
from server import HCatServer
from util import request_parse, get_user_data


class AddFriend:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.friend_username: str
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'friend_username' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']
        if 'additional_information' in req_data:
            additional_information = req_data['additional_information']
        else:
            additional_information = ''

        # 判断对象是否存在
        if not server.data_db.exists(self.friend_username):
            return ReturnData(ReturnData.NULL, 'friend not exists')

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在friends_list
            if 'friends_list' not in get_user_data(server.data_db, self.username):
                user_data = get_user_data(server.data_db, self.username)
                user_data['friends_list'] = {}
                server.data_db.set(self.username, user_data)
            # 判断是否已经是好友
            if self.friend_username in get_user_data(server.data_db, self.username)['friends_list']:
                return ReturnData(ReturnData.ERROR, 'already friend')
            else:
                # 添加好友
                server.data_db_lock.acquire()
                friend_data = server.data_db.get(self.friend_username)

                # 检测是否存在todo_list
                if 'todo_list' not in friend_data:
                    friend_data['todo_list'] = []

                # 将申请加入朋友的todo_list
                # 加锁
                ec = EventContainer(server.event_log_db, server.event_log_db_lock)
                ec. \
                    add('type', 'friend_request'). \
                    add('rid', ec.rid). \
                    add('username', self.username). \
                    add('additional_information', additional_information). \
                    add('time', time.time())
                ec.write()

                friend_data['todo_list'].append(ec.json)
                server.data_db.set(self.friend_username, friend_data)
                server.data_db_lock.release()
                return ReturnData(ReturnData.OK, 'add friend success')

        else:
            return msg


class AgreeFriendRequire:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.rid: str
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'rid' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token or rid is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.rid = req_data['rid']

        if server.event_log_db.exists(self.rid):
            friend_username = server.event_log_db.get(self.rid)['username']
            server.event_log_db_lock.acquire()
            server.event_log_db.rem(self.rid)
            server.event_log_db_lock.release()
        else:

            return ReturnData(ReturnData.NULL, 'event not exists')

        # 判断对象是否存在
        if not server.data_db.exists(friend_username):
            return ReturnData(ReturnData.NULL, 'friend not exists')

        server.data_db_lock.acquire()
        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:

            # 判断是否已经是好友
            if 'friends_list' in server.data_db.get(friend_username) and self.username in \
                    server.data_db.get(friend_username)['friends_list']:

                return ReturnData(ReturnData.ERROR, 'already friend')
            else:
                # 获取好友数据
                friend_data = server.data_db.get(friend_username)
                # 检测是否存在todo_list
                if 'todo_list' not in friend_data:
                    friend_data['todo_list'] = []
                # 创建事件
                ec = EventContainer(server.event_log_db, server.event_log_db_lock)
                ec. \
                    add('type', 'friend_agree'). \
                    add('rid', ec.rid). \
                    add('username', self.username). \
                    add('time', time.time())
                ec.write()
                # 将同意申请加入朋友的todo_list
                friend_data['todo_list'].append(ec.json)

                # 检测是否存在朋友列表
                if 'friends_list' not in friend_data:
                    friend_data['friends_list'] = {}

                # 加入朋友列表
                display_name = server.auth_db.get(self.username)['display_name']
                friend_data['friends_list'][self.username] = {'nick': display_name,
                                                              'time': time.time()}

                # 获取用户状态
                user_data = get_user_data(server.data_db, self.username)

                # 检测是否存在朋友列表
                if 'friends_list' not in user_data:
                    user_data['friends_list'] = {}

                # 加入朋友列表
                friend_display_name = server.auth_db.get(friend_username)['display_name']
                user_data['friends_list'][friend_username] = {'nick': friend_display_name,
                                                              'time': time.time()}
                server.data_db.set(friend_username, friend_data)
                server.data_db.set(self.username, user_data)
                server.data_db_lock.release()
                return ReturnData(ReturnData.OK, 'agree friend success')
        else:
            server.data_db_lock.release()
            return msg


class DeleteFriend:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.friend_username: str
        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'friend_username' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username or token or friend_username is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']
        # 判断用户名是否存在
        server.data_db_lock.acquire()
        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            friend_data = server.data_db.get(self.friend_username)

            # 检测是否存在todo_list
            if 'todo_list' not in friend_data:
                friend_data['todo_list'] = []
            # 创建事件
            ec = EventContainer(server.event_log_db, server.event_log_db_lock)
            ec.add('type', 'friend_deleted').add('rid', ec.rid).add('username', self.username).add('time', time.time())
            ec.write()
            # 将好友删除事件加入朋友的todo_list
            friend_data['todo_list'].append(ec.json)
            del ec
            if 'friends_list' in friend_data:
                # 从好友的好友列表删除
                del friend_data['friends_list'][self.username]
                server.data_db.set(self.friend_username, friend_data)
            else:
                friend_data['friends_list'] = {}
                server.data_db.set(self.friend_username, friend_data)

            # 从好友列表删除

            user_data = get_user_data(server.data_db, self.username)
            if 'friends_list' in user_data:
                # 从好友的好友列表删除
                del user_data['friends_list'][self.friend_username]

            else:
                user_data['friends_list'] = {}
            server.data_db.set(self.username, user_data)

            server.data_db_lock.release()
            return ReturnData(ReturnData.OK)

        else:
            server.data_db_lock.release()
            return msg


class GetFriendsList:
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
            # 取用户数据
            user_data = get_user_data(server.data_db, self.username)
            # 判断并返回好友列表
            if 'friends_list' in user_data:

                return ReturnData(ReturnData.OK).add('data', user_data['friends_list'])
            else:
                return ReturnData(ReturnData.OK).add('data', {})

        else:
            return msg
