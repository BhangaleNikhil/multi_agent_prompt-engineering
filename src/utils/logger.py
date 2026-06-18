from datetime import datetime
import json
import logging
from src.utils import LogCacheHandler

log_cache_handler = LogCacheHandler()

class RedisLogHandler(logging.Handler):
    def emit(self, record):
        formatted_message = f"{record.levelname}: {record.getMessage()}"
        log_message = json.dumps({"timestamp":datetime.now().isoformat(),"log_message":formatted_message})
        log_cache_handler.save_logs(log=log_message)


def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if not root_logger.handlers:
        root_logger.addHandler(RedisLogHandler())