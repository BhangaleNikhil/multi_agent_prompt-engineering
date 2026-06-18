import sqlite3
from src.config.config import Config
from typing import List

config = Config()

connection = sqlite3.Connection(config.get_logs_storage())
cursor = sqlite3.Cursor(connection)

cursor.execute("CREATE TABLE IF NOT EXISTS workflow_logs(timestamp TIMESTAMP,log TEXT)")

def store_logs(logs:List) -> bool:
    cursor.executemany("INSERT INTO workflow_logs (timestamp, log) VALUES (?, ?)",logs)

    connection.commit()

    return True