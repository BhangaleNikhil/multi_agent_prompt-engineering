from langchain.agents import create_agent
from src.tools.py_read import py_read
from src.config.config import Config
from src.states.app_state import AppState
from langchain_core.messages import message_to_dict
from src.utils import CacheHandler
import json
import os
from datetime import datetime

cache_handler = CacheHandler()
config = Config()

def python_agent(state:AppState)->AppState:
    model = config.get_model()
    agent = create_agent(model=model,tools=[py_read])

    file_path = state["py_docs"]["docs"].pop() if state["py_docs"]["docs"] else "there is no file"
    file_name = file_path.split(os.path.sep)[-1]
    timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
    doc_id = f"{file_name}:{timestamp}"

    result = agent.invoke({"messages": [{"role": "user", "content": f"Read the file {file_path} and find the issues with the code."}]})
    messages = result.get("messages", [])

    serializable_messages = [message_to_dict(msg) for msg in messages]

    ai_response = ""
    for msg in serializable_messages:
        if msg["type"]=="ai" and msg["data"]["content"]:
            ai_response = msg["data"]["content"]
            state["py_docs"]["input_tokens_agent"] += msg["data"]["usage_metadata"]["input_tokens"]
            state["py_docs"]["output_tokens_agent"] += msg["data"]["usage_metadata"]["output_tokens"]
        elif msg["type"]=="ai" and msg["data"]["tool_calls"]:
            state["py_docs"]["input_tokens_tool"] += msg["data"]["usage_metadata"]["input_tokens"]
            state["py_docs"]["output_tokens_tool"] += msg["data"]["usage_metadata"]["output_tokens"]

    response = {"message": ai_response, "file_path":file_path }

    state["py_docs"]["processed_docs"].append(file_path)

    doc_key = cache_handler.save_document(doc_id=doc_id,document=response)
    doc_key = cache_handler._get_doc_key(doc_id)
    print(doc_key)
    state["cache_key"].append(doc_key)

    return state