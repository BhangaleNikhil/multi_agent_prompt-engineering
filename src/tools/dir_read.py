import os
from typing import Dict, Any
from langchain.tools import tool

def get_dir_structure(root_dir_path:str):
    """get_dir_structure function gets the root directory path root_dir_path and returns the entire directory structure"""
    structure :Dict[str,Any] = {}
    for element in os.listdir(root_dir_path):
        element_path = os.path.join(root_dir_path,element)
        if element not in ["__pycache__"]:
            if os.path.isdir(element_path):
                structure[element] = get_dir_structure(element_path)
            else:
                structure[element] = None

    return structure

@tool
def dir_structure(root_dir_path):
    """dir_structure function gets the root directory path root_dir_path and returns the entire directory structure"""
    return get_dir_structure(root_dir_path=root_dir_path)