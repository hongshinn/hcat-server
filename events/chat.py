import time

from containers import ReturnData, EventContainer, Group
from server import HCatServer
from util import request_parse, ins


class SendFriendMsg:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.server = server
        self.friend_username: str
        self.msg: str
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
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
        data = server.get_user_data(self.username)
        # 判断是否为空
        if 'friends_list' not in data:
            data['friends_list'] = {}

        if self.friend_username not in data['friends_list']:
            return ReturnData(ReturnData.NULL, 'friends not exists.')

        # 验证用户名与token
        auth_status, rt_msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False

        else:
            server.data_db_lock.release()
            return rt_msg

    def e_return(self):
        if not self.cancel:
            self.server.data_db_lock.acquire()
            friend_data = self.server.data_db.get(self.friend_username)
            # 判断是否为空
            if 'todo_list' not in friend_data:
                friend_data['todo_list'] = []

            ec = EventContainer(self.server.event_log_db, self.server.event_log_db_lock)
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
            self.server.data_db.set(self.friend_username, friend_data)
            self.server.data_db_lock.release()

            self.return_data = ReturnData(ReturnData.OK)

        if self.return_data is None:
            self.return_data = ReturnData(ReturnData.ERROR)
        return self.return_data.json()


class SendGroupMsg:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.group_id: str
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token or group_id is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.msg = req_data['msg']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在群聊
            if not server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            server.groups_db_lock.acquire()
            # 获取群租
            group: Group = server.groups_db.get(self.group_id)

            # 返回数据
            if self.username in group.member_list:
                group.send_msg(server, self.username, self.msg)
                return ReturnData(ReturnData.OK)
            else:
                server.groups_db_lock.release()
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg
