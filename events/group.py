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
                if not server.groups_db.exists(group_id):
                    break
            # 实例化群租
            group = Group(group_id)

            # 设置群租
            group.name = self.group_name
            group.member_list.append(self.username)
            group.member_data[self.username] = {'nick': server.auth_db.get(self.username)['display_name'],
                                                'time': time.time()}
            group.owner = self.username

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


class JoinGroup:
    def __init__(self, server: HCatServer, req):
        self.username: str
        self.token: str
        self.group_id: str
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if 'username' not in req_data or 'token' not in req_data or 'group_id' not in req_data or \
                'additional_information' not in req_data:
            return ReturnData(ReturnData.ERROR, 'username token additional_information or group_id is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.additional_information = req_data['additional_information']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在群聊
            if not server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            # 获取群租
            group: Group = server.groups_db.get(self.group_id)

            # 创建事件
            ec = EventContainer(server.event_log_db, server.event_log_db_lock)
            ec. \
                add('type', 'group_join_request'). \
                add('rid', ec.rid). \
                add('username', self.username). \
                add('additional_information', self.additional_information). \
                add('time', time.time())
            if group.group_settings['verification_method'] == 'ac':
                # 写入管理者的todo_list
                server.set_user_todo_list(group.owner, ec)
                for admin in group.admin_list:
                    server.set_user_todo_list(admin, ec)
            elif group.group_settings['verification_method'] == 'fr':
                server.groups_db_lock.acquire()
                group = server.groups_db.get(self.group_id)
                group.member_list.append(self.username)
                server.groups_db.set(self.group_id, group)
                server.data_db_lock.release()
            elif group.group_settings['verification_method'] == 'aw':
                if self.additional_information == group.group_settings['answer']:
                    server.groups_db_lock.acquire()
                    group = server.groups_db.get(self.group_id)
                    group.member_list.append(self.username)
                    server.groups_db.set(self.group_id, group)
                    server.data_db_lock.release()
            else:
                return ReturnData(ReturnData.ERROR, 'groups do not allow anyone to join')
            return ReturnData(ReturnData.OK, '')
        else:
            return msg
