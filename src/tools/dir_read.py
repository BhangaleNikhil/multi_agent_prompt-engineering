import os
from typing import List
from langchain.tools import tool
from src.states import AppState

import logging
logger = logging.getLogger(__name__)

def get_relevant_file(state:AppState)->AppState:
    """get_relevant_file function gets the root directory path and returns the list of relevant file paths

    Args:
    get_relevant_file:str
    file_filter:str (python or master to select file type to retrieve)

    returns:
    relevant_file_list:List
    """
    try:
        print("get relevant_file is called")
        file_filter = state["file_filter"]
        root_dir_path = state["root_path"]

        if os.path.exists(root_dir_path):
            file_filters = {"python":".py","master":".md"}

            filtered_files = []
            for root,dir,files in os.walk(root_dir_path):
                filtered_files.extend([os.path.abspath(os.path.join(root,file)) for file in files if file.endswith(file_filters[file_filter])])

            state["py_docs"]["count"] = len(filtered_files)
            state["py_docs"]["docs"] = filtered_files

    except Exception as e:
        logger.error(e)
    return state