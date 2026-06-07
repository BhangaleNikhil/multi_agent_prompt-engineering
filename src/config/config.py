from langchain_ollama import ChatOllama
from typing import Any

class Config:
    def __init__(self):
        self.model = ChatOllama(model="gemma4:latest",temperature=0)

    def get_model(self) -> Any:
        return self.model