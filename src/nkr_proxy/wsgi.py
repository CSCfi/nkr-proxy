
import logging
import time

from nkr_proxy.proxy_app import app


logging.config.fileConfig("../../config/logging.ini", disable_existing_loggers=False)
logging.Formatter.converter = time.gmtime


if __name__ == "__main__":
    app.run('127.0.0.1')
