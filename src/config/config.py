from langchain_ollama import ChatOllama
from typing import Any

class Config:
    def __init__(self):
        pass

    def get_model(self) -> Any:
        return ChatOllama(model="gemma4:latest",temperature=0)