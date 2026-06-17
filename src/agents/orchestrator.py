from src.states import AppState
from src.config.config import Config

config = Config()

def orchestrator(state:AppState)->AppState:
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]
    reports = state["reports"]["docs"]
    if not py_doc_count and not py_files:
        retrieved =config.get_prompts(state["prompt_technique"])
        print("Prompts are retrived\n") if retrieved else print("Prompts retrieval failed\n")
        state["file_filter"] = "python"
    elif py_doc_count and (not py_files and reports):
        state["file_filter"] = "master"
    return state