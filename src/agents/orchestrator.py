from src.states import AppState
from src.config.config import Config
import logging
logger = logging.getLogger(__name__)

config = Config()

def orchestrator(state:AppState)->AppState:
    logger.info(f"Agenting workflow started. Details:\nRoot Path: {state['root_path']}\nPrompt Technique: {state['prompt_technique']}\nStorage Folder: {state["storage_folder"]}")
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]
    reports = state["reports"]["docs"]
    if not py_doc_count and not py_files:
        retrieved = config.get_prompts(state["prompt_technique"])
        state["prompts"] = retrieved
        logger.debug(f"Retrived Prompts are as follows:\nPython Agent: {state["prompts"].get("python_agent")}\nMaster Agent: {state["prompts"].get("master_agent")}")
        print("Prompts are retrived\n") if retrieved else print("Prompts retrieval failed\n")
        state["file_filter"] = "python"
    elif py_doc_count and (not py_files and reports):
        state["file_filter"] = "master"
    return state