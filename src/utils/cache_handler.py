import redis
import json
from typing import Dict, Any,Optional,cast
from redis.typing import EncodableT
from src.config.config import Config

config = Config()
redis_details = config.get_redis_config()

class CacheHandler:
    def __init__(self) -> None:
        host = redis_details.get("host")
        port = redis_details.get("port")
        self.client = redis.Redis(host=host,port=port,decode_responses=True)
    def _get_doc_key(self,doc_id):
        return f"doc:{doc_id}"
    
    def save_document(self,doc_id:str,document:Dict[str,Any]):
        doc_key = self._get_doc_key(doc_id)
        self.client.hset(doc_key,mapping=cast(dict[EncodableT, EncodableT],document))
        return doc_key

    def get_document(self,doc_key:str) -> Dict:
        return self.client.hgetall(name=doc_key)

    def delete_document(self, doc_id: str):
        key = self._get_doc_key(doc_id)
        result = self.client.delete(key)