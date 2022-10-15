from config_loader import Config
from server import HCatServer

config = Config()
HCatServer(config).start()
