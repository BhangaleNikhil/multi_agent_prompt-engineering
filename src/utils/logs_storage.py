import sqlite3
from src.config.config import Config
from typing import List

config = Config()

class LogStorage:
    def __int__(self):
        self.connection = sqlite3.Connection(config.get_logs_storage())
        self.cursor = sqlite3.Cursor(self.connection)

        self.cursor.execute("CREATE TABLE IF NOT EXISTS workflow_logs(timestamp TIMESTAMP,log_message TEXT)")

    def store_logs(self,logs:List) -> bool:
        self.cursor.executemany("INSERT INTO workflow_logs (timestamp, log) VALUES (?, ?)",logs)

        self.connection.commit()

        return True