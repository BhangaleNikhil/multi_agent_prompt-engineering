from src.config.config import Config
from langchain.agents import create_agent
from src.tools.dir_read import get_relevant_file
from src.states.app_state import AppState

import logging
logger = logging.getLogger(__name__)

config = Config()

def orchestrator_router(state:AppState) -> str:
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]

    processed = state["py_docs"]["processed_docs"]

    if processed and ((len(processed) % 10 == 0 and state["cache_key"]) or (not py_files and state["cache_key"])):
        logger.debug(f"Count of processed: {len(processed)} & count of cache keys: {len(state["cache_key"])}")
        return "report_writer"
    else:
        if not py_doc_count and not py_files:
            logger.debug(f"Py doc count: {py_doc_count} and py file count: {len(py_files) if py_files else 0}")
            return "get_relevant_files"
        elif py_doc_count and py_files:
            logger.debug(f"Py doc count: {py_doc_count} and py file count: {len(py_files) if py_files else 0}")
            return "python_agent"
        elif py_doc_count and not py_files:
            logger.debug(f"Py doc count: {py_doc_count} and py file count: {len(py_files) if py_files else 0}")
            return "master_agent"
        else:
            logger.debug(f"Py doc count: {py_doc_count} and py file count: {len(py_files) if py_files else 0}")
            return "end"