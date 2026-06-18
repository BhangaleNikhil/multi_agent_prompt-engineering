import redis
from typing import List, Dict
from src.config.config import Config
import json

config = Config()
redis_details = config.get_redis_log_config()

class LogCacheHandler():
    def __init__(self) -> None:
        host = redis_details.get("host")
        port = redis_details.get("port")
        self.client = redis.Redis(host=host,port=port,decode_responses=True)
    
    def save_logs(self, log:str,key:str="logs") -> None:
        self.client.rpush(key,log)

    def get_logs(self,key:str="logs")->List[Dict[str,str]]:
        return [json.loads(log) for log in self.client.lrange(key,0,-1)]
    
    def delete_all_logs(self,key):
        self.client.delete(key)