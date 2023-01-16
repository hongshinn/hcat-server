import time

from containers import ReturnData, EventContainer, Group
from events.event import Event
from server import HCatServer
from util import *


class SendFriendMsg(Event):
    def _init(self, server: HCatServer, req):
        

        self.server = server

        self.cancel = True
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'friend_username', 'msg'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token friend_username or msg is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.friend_username = req_data['friend_username']
        self.msg = req_data['msg']

        # 取用户数据
        data = server.get_user_data(self.username)

        # 判断是否为空
        if 'friends_list' not in data:
            data['friends_list'] = {}

        # 判断是否存在好友列表
        if self.friend_username not in data['friends_list']:
            return ReturnData(ReturnData.NULL, 'friends not exists.')

        # 验证用户名与token
        auth_status, rt_msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False

        else:

            return rt_msg

    def _return(self):
        if not self.cancel:
            # 创建事件
            ec = EventContainer(self.server.event_log_db, self.server.event_log_db_lock)
            ec. \
                add('type', 'friend_msg'). \
                add('rid', ec.rid). \
                add('username', self.username). \
                add('msg', self.msg). \
                add('time', time.time())
            ec.write()

            # 写入好友待办列表
            self.server.set_user_todo_list(self.friend_username, ec)

            self.return_data = ReturnData(ReturnData.OK)

        if self.return_data is None:
            self.return_data = ReturnData(ReturnData.ERROR)


class SendGroupMsg(Event):
    def _init(self, server: HCatServer, req):
        
        self.cancel = True
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

            # 获取群租
            group: Group = server.groups_db.get(self.group_id)

            # 返回数据
            if self.username in group.member_list:
                self.cancel = False

                return ReturnData(ReturnData.OK)
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg

    def _return(self):
        if not self.cancel:

            self.server.groups_db_lock.acquire()
            try:
                # 获取群租
                group: Group = self.server.groups_db.get(self.group_id)
                if self.username in group.ban_dict:
                    if group.ban_dict[self.username]['time'] < time.time():
                        del group.ban_dict[self.username]
                    else:
                        return ReturnData(ReturnData.ERROR, 'you have been banned by admin')
                group.send_msg(self.server, self.username, self.msg)
            finally:
                self.server.groups_db_lock.release()
