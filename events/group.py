import json

from containers import *
from events.event import Event
from server import HCatServer
from util import *


class CreateGroup(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()
        self.server: HCatServer = server
        self.cancel = True
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        # 获取请求数据
        req_data = request_parse(request)

        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_name'], req_data):
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
                self.group_id = get_random_token(5)
                if not server.groups_db.exists(self.group_id):
                    break

            # 实例化群租
            self.group = Group(self.group_id)

            # 设置群租
            self.group.name = self.group_name
            self.group.member_list.add(self.username)
            self.group.member_data[self.username] = {'nick': server.auth_db.get(self.username)['display_name'],
                                                     'time': time.time()}
            self.group.owner = self.username

            self.cancel = False
            return ReturnData(ReturnData.OK, '').add('group_id', self.group_id)
        else:
            return msg

    def _return(self):
        server = self.server

        # 将群租写入数据库
        server.groups_db.set(self.group_id, self.group)

        # 将群租加入用户groups_list
        server.data_db_lock.acquire()
        user_data = server.get_user_data(self.username)
        if 'groups_list' not in user_data:
            user_data['groups_list'] = {}
        user_data['groups_list'][self.group_id] = {'remark': self.group.name, 'time': time.time()}

        server.data_db.set(self.username, user_data)

        server.data_db_lock.release()


class JoinGroup(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()
        self.server: HCatServer = server
        self.cancel = True
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        # 获取请求数据
        req_data = request_parse(request)

        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id', 'additional_information'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token additional_information or group_id is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.additional_information = req_data['additional_information']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断用户是否存在群聊
            if not server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            # 获取群租
            self.group: Group = server.groups_db.get(self.group_id)

            self.cancel = False

            return ReturnData(ReturnData.OK, '')
        else:
            return msg

    def _return(self):
        server = self.server
        group = self.group
        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'group_join_request'). \
            add('rid', ec.rid). \
            add('group_id', self.group_id). \
            add('username', self.username). \
            add('additional_information', self.additional_information). \
            add('time', time.time())
        ec.write()
        if group.group_settings['verification_method'] == 'ac':
            # 需要管理同意
            # 写入管理者的todo_list
            server.set_user_todo_list(group.owner, ec)
            for admin in group.admin_list:
                server.set_user_todo_list(admin, ec)

        # 入群规则判断
        elif group.group_settings['verification_method'] == 'fr':
            # 自由加入
            server.groups_db_lock.acquire()
            group = server.groups_db.get(self.group_id)
            group.member_list.append(self.username)
            server.groups_db.set(self.group_id, group)
            server.data_db_lock.release()

            # 写入入群者的代办列表
            ec = EventContainer(server.event_log_db, server.event_log_db_lock)
            ec. \
                add('type', 'group_join_request_agreed'). \
                add('rid', ec.rid). \
                add('group_id', self.group_id). \
                add('time', time.time())
            ec.write()
            server.set_user_todo_list(self.username, ec)

            # 将群租加入用户groups_list
            server.data_db_lock.acquire()
            user_data = server.get_user_data(self.username)
            if 'groups_list' not in user_data:
                user_data['groups_list'] = {}
            user_data['groups_list'][self.group_id] = {'remark': group.name, 'time': time.time()}
            server.data_db_lock.release()

        elif group.group_settings['verification_method'] == 'aw':
            # 需要回答问题
            if self.additional_information == group.group_settings['answer']:
                server.groups_db_lock.acquire()
                group = server.groups_db.get(self.group_id)
                group.member_list.append(self.username)
                server.groups_db.set(self.group_id, group)
                server.data_db_lock.release()

                # 写入入群者的代办列表
                ec = EventContainer(server.event_log_db, server.event_log_db_lock)
                ec. \
                    add('type', 'group_join_request_agreed'). \
                    add('rid', ec.rid). \
                    add('group_id', self.group_id). \
                    add('time', time.time())
                ec.write()
                server.set_user_todo_list(self.username, ec)

                # 将群租加入用户groups_list
                server.data_db_lock.acquire()
                user_data = server.get_user_data(self.username)
                if 'groups_list' not in user_data:
                    user_data['groups_list'] = {}
                user_data['groups_list'][self.group_id] = {'remark': group.name, 'time': time.time()}
                server.data_db_lock.release()
        else:
            self.return_data = ReturnData(ReturnData.ERROR, 'groups do not allow anyone to join')


class AgreeJoinGroupRequest(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.server: HCatServer = server
        self.cancel = True
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'rid'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token or rid is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.rid = req_data['rid']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 检查是否存在事件
            if not server.event_log_db.exists(self.rid):
                return ReturnData(ReturnData.NULL, 'event not exists')
            # 获取事件
            self.event_json = server.event_log_db.get(self.rid)
            # 获取群租id
            self.group_id = self.event_json['group_id']

            self.cancel = False

            return ReturnData(ReturnData.OK)
        else:
            return msg

    def _return(self):
        server = self.server

        # 上锁
        server.groups_db_lock.acquire()

        # 获取群租
        group: Group = server.groups_db.get(self.group_id)

        # 检查权限

        if not group.permission_match(self.username):
            return ReturnData(ReturnData.ERROR, 'you do not have permission')

        # 加入成员
        group.member_list.add(self.event_json['username'])
        server.groups_db.set(self.group_id, group)
        server.groups_db_lock.release()

        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'group_join_request_agreed'). \
            add('rid', ec.rid). \
            add('group_id', self.group_id). \
            add('time', time.time())
        ec.write()

        # 写入入群者的代办列表
        server.set_user_todo_list(self.event_json['username'], ec)

        # 将群租加入入群者的groups_list
        server.data_db_lock.acquire()
        user_data = server.get_user_data(self.event_json['username'])

        if 'groups_list' not in user_data:
            user_data['groups_list'] = {}
        user_data['groups_list'][self.group_id] = {'remark': group.name, 'time': time.time()}
        server.data_db.set(self.event_json['username'], user_data)
        server.data_db_lock.release()


class GetGroupMembersList(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

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
                return ReturnData(ReturnData.OK).add('data', list(group.member_list))
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg


class GetGroupSettings(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

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
                return ReturnData(ReturnData.OK).add('data', group.group_settings)
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg


class ChangeGroupSettings(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id', 'settings'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token group_id or settings is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        try:
            self.settings = json.loads(req_data['settings'])
        except Exception as err:
            return ReturnData(ReturnData.ERROR, err)

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在群聊
            if not server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            # 获取群租
            group: Group = server.groups_db.get(self.group_id)

            # 返回数据
            if self.username in group.admin_list and self.username != group.owner:
                self.cancel = False
                return ReturnData(ReturnData.OK)
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg

    def _return(self):
        server = self.server

        server.groups_db_lock.acquire()

        # 获取群租
        group: Group = server.groups_db.get(self.group_id)

        # 检测键是否存在
        for i in self.settings:
            if i not in group.group_settings:
                server.groups_db_lock.release()
                return ReturnData(ReturnData.NULL, 'key does not exist')
        for i in self.settings:
            group.group_settings[i] = self.settings[i]
        server.groups_db_lock.release()


class GetGroupName(Event):
    def __init__(self, server, group_id):
        super().__init__()
        self.group_id = group_id
        self.server = server
        self.return_data = self._run(server)

    def _run(self, server):
        server.groups_db_lock.acquire()

        if server.groups_db.exists(self.group_id):
            # 获取群租
            group: Group = server.groups_db.get(self.group_id)

            # 返回数据
            server.groups_db_lock.release()
            return ReturnData(ReturnData.OK).add('group_name', group.name)
        else:
            server.groups_db_lock.release()
            return ReturnData(ReturnData.NULL, 'group rent does not exist')


class GetGroupsList(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.server = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        # 取请求参数
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

            # 判断并返回群租列表
            rt_data = user_data['groups_list'] if 'groups_list' in user_data else {}
            return ReturnData(ReturnData.OK).add('data', rt_data)

        else:
            return msg


class GroupRename(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id', 'group_name'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token group_id or group_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.group_name = req_data['group_name']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False
            return ReturnData(ReturnData.OK, '')
        else:
            return msg

    def _return(self):
        server = self.server

        server.groups_db_lock.acquire()

        # 获取群聊
        group: Group = server.groups_db.get(self.group_id)

        # 检查权限
        if not group.permission_match(self.username):
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'you do not have permission')
        old_name = group.name
        # 重命名
        group.name = self.group_name

        # 写入数据
        server.groups_db.set(self.group_id, group)

        server.groups_db_lock.release()

        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'group_rename'). \
            add('rid', ec.rid). \
            add('group_id', self.group_id). \
            add('time', time.time()). \
            add('old_name', old_name). \
            add('new_name', group.name)
        ec.write()

        # 写入入群者的代办列表
        [server.set_user_todo_list(m, ec) for m in group.member_list]


class Leave(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token group_id is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False
            return ReturnData(ReturnData.OK, '')
        else:
            return msg

    def _return(self):
        server = self.server

        server.groups_db_lock.acquire()

        # 获取群聊
        group: Group = server.groups_db.get(self.group_id)

        # 检查权限
        if self.username not in group.member_list:
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'you are not in the group')
        # 检查是否为群主
        if self.username == group.owner:
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'you can not leave the group rent, because you are the owner')

        # 移除群员
        group.member_list.remove(self.username)

        # 检查是否为管理员
        if self.username in group.admin_list:
            group.admin_list.remove(self.username)

        # 写入数据
        server.groups_db.set(self.group_id, group)

        server.groups_db_lock.release()
        server.data_db_lock.acquire()
        user_data = server.get_user_data(self.username)
        if 'groups_list' not in user_data:
            user_data['groups_list'] = {}
        user_data['groups_list'].pop(self.group_id)
        server.data_db.set(self.username, user_data)
        server.data_db_lock.release()
        return ReturnData(ReturnData.OK, '')


# todo:群转让

class Kick(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id', 'member_name'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token group_id or member_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.member_name = req_data['member_name']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False
            return ReturnData(ReturnData.OK, '')
        else:
            return msg

    def _return(self):
        server = self.server

        server.groups_db_lock.acquire()

        # 获取群聊
        group: Group = server.groups_db.get(self.group_id)

        # 检查权限
        if (
                not group.permission_match(self.username)) or (
                self.member_name in group.admin_list and self.username != group.owner) or (
                self.member_name == group.owner
        ):
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'you do not have permission')

        # 移除群员
        group.member_list.remove(self.member_name)

        # 检查是否为管理员
        if self.member_name in group.admin_list:
            group.admin_list.remove(self.member_name)

        # 写入数据
        server.groups_db.set(self.group_id, group)

        server.groups_db_lock.release()

        server.data_db_lock.acquire()
        user_data = server.get_user_data(self.member_name)
        if 'groups_list' not in user_data:
            user_data['groups_list'] = {}
        user_data['groups_list'].pop(self.group_id)
        server.data_db.set(self.member_name, user_data)
        server.data_db_lock.release()
        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'group_deleted'). \
            add('rid', ec.rid). \
            add('group_id', self.group_id). \
            add('time', time.time())
        ec.write()

        # 写入入群者的代办列表
        server.set_user_todo_list(self.member_name, ec)
        return ReturnData(ReturnData.OK, '')


class GetGroupAdminList(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

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

    def _return(self):

        # 验证用户名与token
        auth_status, msg = self.server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在群聊
            if not self.server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            # 获取群租
            group: Group = self.server.groups_db.get(self.group_id)

            # 返回数据
            if self.username in group.member_list:
                return ReturnData(ReturnData.OK).add('data', [group.owner] + list(group.admin_list))
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg


class GetGroupOwner(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

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

    def _return(self):

        # 验证用户名与token
        auth_status, msg = self.server.authenticate_token(self.username, self.token)
        if auth_status:
            # 判断是否存在群聊
            if not self.server.groups_db.exists(self.group_id):
                return ReturnData(ReturnData.NULL, 'group not exists')

            # 获取群租
            group: Group = self.server.groups_db.get(self.group_id)

            # 返回数据
            if self.username in group.member_list:
                return ReturnData(ReturnData.OK).add('data', group.owner)
            else:
                return ReturnData(ReturnData.ERROR, 'you are not yet a member of this group')
        else:
            return msg


class Ban(Event):
    def __init__(self, server: HCatServer, req):
        super().__init__()

        self.cancel = True
        self.server: HCatServer = server
        self.return_data = self._run(server, req)

    def _run(self, server: HCatServer, request):
        req_data = request_parse(request)
        # 判断请求体是否为空
        if not ins(['username', 'token', 'group_id', 'member_name', 'time'], req_data):
            return ReturnData(ReturnData.ERROR, 'username token group_id time or member_name is missing')

        # 获取请求参数
        self.username = req_data['username']
        self.token = req_data['token']
        self.group_id = req_data['group_id']
        self.member_name = req_data['member_name']
        self.time = req_data['time']

        # 验证用户名与token
        auth_status, msg = server.authenticate_token(self.username, self.token)
        if auth_status:
            self.cancel = False
            return ReturnData(ReturnData.OK, '')
        else:
            return msg

    def _return(self):
        server = self.server

        server.groups_db_lock.acquire()

        # 获取群聊
        group: Group = server.groups_db.get(self.group_id)

        # 检查权限
        if (
                not group.permission_match(self.username)) or (
                self.member_name in group.admin_list and self.username != group.owner) or (
                self.member_name == group.owner
        ):
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'you do not have permission')

        # 禁言群员
        try:
            group.ban_dict[self.member_name] = {'time': time.time() + float(self.time)}
        except:
            server.groups_db_lock.release()
            return ReturnData(ReturnData.ERROR, 'wrong data type')
        # 写入数据
        server.groups_db.set(self.group_id, group)

        server.groups_db_lock.release()
        # 创建事件
        ec = EventContainer(server.event_log_db, server.event_log_db_lock)
        ec. \
            add('type', 'banned'). \
            add('rid', ec.rid). \
            add('group_id', self.group_id). \
            add('time', time.time()). \
            add('ban_time', self.time)  # 精确到秒
        ec.write()

        # 写入入群者的代办列表
        server.set_user_todo_list(self.member_name, ec)
        return ReturnData(ReturnData.OK, '')

# todo:获取自己在群聊中的身份
