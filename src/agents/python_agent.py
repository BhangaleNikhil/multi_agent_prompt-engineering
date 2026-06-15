from langchain.agents import create_agent
from src.tools.py_read import py_read
from src.config.config import Config
from src.states.app_state import AppState
from langchain_core.messages import message_to_dict
import json

config = Config()
def python_agent(state:AppState)->AppState:
    model = config.get_model()
    agent = create_agent(model=model,tools=[py_read])
    file_name = state["py_docs"]["docs"].pop() if state["py_docs"]["docs"] else "there is no file"
    print(f"{30*'='}")
    result = agent.invoke({"messages": [{"role": "user", "content": f"Read the file {file_name} and find the issues with the code."}]})
    messages = result.get("messages", [])
    serializable_messages = [message_to_dict(msg) for msg in messages]

    print(json.dumps({"messages": serializable_messages}, indent=4))
    return state