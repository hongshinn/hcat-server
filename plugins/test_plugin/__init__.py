from events.auth import AuthLogout

from plugin_manager.manager import HCat


def init(hcat: HCat):
    @hcat.event_handle
    def auth_logout(e: AuthLogout):
        # e.return_data = ReturnData(ReturnData.ERROR, '测试')

        pass
