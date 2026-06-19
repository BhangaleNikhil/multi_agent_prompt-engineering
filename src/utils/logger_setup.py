from datetime import datetime
import json
import logging
import threading
from src.utils import LogCacheHandler

log_cache_handler = LogCacheHandler()

class RedisLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self._local = threading.local()

    def emit(self, record):

        if getattr(self._local, 'emitting', False):
            return
        
        try:
            self._local.emitting = True
            message = record.getMessage()

            formatted_message = f"{record.levelname}: {record.filename}:{record.lineno} : {record.getMessage()}"
            log_message = json.dumps({"timestamp":datetime.now().isoformat(),"log_message":formatted_message})
            log_cache_handler.save_logs(log=log_message)
        except Exception:
            import sys
            sys.stderr.write(f"RedisLogHandler internal failure: {record.levelname} - {record.getMessage()}\n")
        finally:
            self._local.emitting = False


def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if not root_logger.handlers:
        root_logger.addHandler(RedisLogHandler())