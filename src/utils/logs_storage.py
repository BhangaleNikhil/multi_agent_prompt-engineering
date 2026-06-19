import sqlite3
from src.config.config import Config
from typing import List

import logging
logger = logging.getLogger(__name__)

config = Config()

class LogStorage:
    def __init__(self):
        print(config.get_logs_storage())
        self.connection = sqlite3.Connection(config.get_logs_storage())
        self.cursor = sqlite3.Cursor(self.connection)

        self.cursor.execute("CREATE TABLE IF NOT EXISTS workflow_logs(timestamp TIMESTAMP,log_message TEXT)")

    def store_logs(self,logs:List) -> bool:
        try:
            self.cursor.executemany("INSERT INTO workflow_logs (timestamp, log_message) VALUES (?, ?)",logs)

            self.connection.commit()

            return True
        except Exception as e:
            logger.error(e)
            return False