from langchain.agents import create_agent
from src.tools.dir_read import get_dir_structure
from src.config.config import Config
from src.states.app_state import AppState
import json

config = Config()

def master_agent(state:AppState) -> AppState:
    model = config.get_model()
    agent = create_agent(model=model,tools=[get_dir_structure])
    file_name = state["reports"]["docs"].pop() if state["reports"]["docs"] else "there is no file"
    result = agent.invoke({"messages":[{"role": "user", "content": f"Read the directory {file_name} and simply return all markdown file names in the directory."}]})
    print(result)
    return state