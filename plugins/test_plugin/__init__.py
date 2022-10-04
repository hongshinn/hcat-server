from events.auth import AuthLogout

from plugin_manager.manager import HCat, PluginConfig


def main(hcat: HCat, workspace: str):
    @hcat.event_handle
    def auth_logout(e: AuthLogout):
        # e.return_data = ReturnData(ReturnData.ERROR, '测试')

        pass


class Config(PluginConfig):
    def __init__(self):
        super().__init__()
        self.name = 'test'
        self.description = 'this is an test plugin'
        self.author = 'hsn'
        self.depend = []
        self.version = '1.0.0'
