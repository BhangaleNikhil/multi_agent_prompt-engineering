from langchain_ollama import ChatOllama
from typing import Any
import os

class Config:
    def __init__(self):
        pass

    def get_model(self) -> Any:
        return ChatOllama(model="gemma4:latest",temperature=0)
    
    def get_redis_config(self) -> Any:
        host = os.getenv("REDIS_HOST")
        port = int(os.getenv("REDIS_PORT","6379"))

        return {"host":host,"port":port}