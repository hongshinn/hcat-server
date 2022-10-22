import logging

import util
from config_loader import Config
from server import HCatServer

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(name)s][%(levelname)s] %(message)s')
logging.getLogger().addFilter(util.FlaskLoggerFilter())
config = Config()
HCatServer(config).start()
