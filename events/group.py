from containers import *
from server import HCatServer
from util import *


class CreateGroup:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.group_name: str
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'group_name' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username token or group_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_name = req_data['group_name']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 取群聊唯一id
            while True:
                group_id = get_random_token(5)
                if group_id not in server.groups_db.getall():
                    break
            # 实例化群租
            group = Group(group_id)

            # 设置群租
            group.name = self.group_name
            group.member_list.append(self.username)
            group.member_data[self.username] = {}

            # 将群租加入用户groups_list
            server.groups_db.set(group_id, group)
            server.data_db_lock.acquire()
            user_data = server.get_user_data(self.username)
            if 'groups_list' not in user_data:
                user_data['groups_list'] = {}
            user_data['groups_list'][group_id] = {'remark': group.name, 'time': time.time()}
            server.data_db_lock.release()

            return ReturnData(ReturnData.OK, '').add('group_id', group_id)
        else:
            return msg
