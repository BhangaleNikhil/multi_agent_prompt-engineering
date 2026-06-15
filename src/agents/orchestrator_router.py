from src.config.config import Config
from langchain.agents import create_agent
from src.tools.dir_read import get_relevant_file
from src.states.app_state import AppState

config = Config()

def orchestrator_router(state:AppState) -> str:
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]

    if not py_doc_count and not py_files:
        return "get_relevant_files"
    elif py_doc_count and py_files:
        return "python_agent"
    elif py_doc_count and not py_files:
        return "master_agent"
    else:
        return "end"