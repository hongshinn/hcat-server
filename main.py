import logging
import os.path

import util
from config_loader import Config
from server import HCatServer

if not os.path.exists(os.path.join(os.getcwd(), 'pri.key')):
    with open(os.path.join(os.getcwd(), 'pri.key'), 'w', encoding='utf8') as f:
        f.write(util.get_random_token(16))

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(name)s][%(levelname)s] %(message)s')
logging.getLogger().addFilter(util.FlaskLoggerFilter())
config = Config()
HCatServer(config).start()
