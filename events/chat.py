import time

from containers import ReturnData, EventContainer
from util import request_parse, get_user_data


class ChatFriendSendMsg:
    def __init__(self, server, req):
        self.username: str
        self.token: str
        self.server = server
        self.friend_username: str
        self.msg: str
        self.return_data = self._run(server, req)

    def _run(self, server, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data \
                or 'token' not in req_data \
                or 'friend_username' not in req_data \
                or 'msg' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username token friend_username or msg is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']
        self.msg = req_data['msg']
        data = get_user_data(server.data_db, self.username)
        # 判断是否为空
        if 'friends_list' not in data:
            data['friends_list'] = {}

        if self.friend_username not in data['friends_list']:
            return ReturnData(ReturnData.NULL, 'friends not exists.')

        server.data_db_lock.acquire()
        # 验证用户名与token
        auth_status, rt_msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            friend_data = server.data_db.get(self.friend_username)
            # 判断是否为空
            if 'todo_list' not in friend_data:
                friend_data['todo_list'] = []

            ec = EventContainer(server.event_log_db, server.event_log_db_lock)
            ec. \
                add('type', 'friend_msg'). \
                add('rid', ec.rid). \
                add('username', self.username). \
                add('msg', self.msg). \
                add('time', time.time())
            ec.write()
            # 清空todo_list
            friend_data['todo_list'].append(ec.json)

            # 计入数据库
            server.data_db.set(self.friend_username, friend_data)
            server.data_db_lock.release()

            return ReturnData(ReturnData.OK)

        else:
            server.data_db_lock.release()
            return rt_msg
