from langchain.agents import create_agent
from src.tools.py_read import py_read
from src.config.config import Config
from src.states.app_state import AppState
from langchain_core.messages import message_to_dict
from src.utils.cache_handler import CacheHandler
import json
import os
from datetime import datetime

cache_handler = CacheHandler()
config = Config()
def python_agent(state:AppState)->AppState:
    model = config.get_model()
    agent = create_agent(model=model,tools=[py_read])

    file_name = state["py_docs"]["docs"].pop() if state["py_docs"]["docs"] else "there is no file"
    root_path_name = state["root_path"].split("/")[-1]
    print(root_path_name)
    relative_path = file_name.split(root_path_name)[-1].lstrip("/")
    timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
    doc_id = f"{root_path_name}:{relative_path}:{timestamp}"

    print(doc_id)

    result = agent.invoke({"messages": [{"role": "user", "content": f"Read the file {file_name} and find the issues with the code."}]})
    messages = result.get("messages", [])
    serializable_messages = [message_to_dict(msg) for msg in messages]

    response = {"messages": str(serializable_messages)}

    cache_handler.save_document(doc_id=doc_id,document=response)

    return state