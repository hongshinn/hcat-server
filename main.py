from config_loader import Config
from server import HCatServer

config = Config()
HCatServer((config.IP, config.Port), config.GCTime, config.MainPageContent).start()
