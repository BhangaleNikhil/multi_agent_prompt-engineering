import os
from typing import List
import os
from langchain.tools import tool

@tool
def get_relevant_file(root_dir_path:str,file_filter:str)->List:
    """get_relevant_file function gets the root directory path and returns the list of relevant file paths

    Args:
    get_relevant_file:str
    file_filter:str (python or master to select file type to retrieve)

    returns:
    relevant_file_list:List
    """

    file_filters={"python":".py","master":".md"}

    filtered_files = []
    for root,dir,files in os.walk("./src"):
        filtered_files.extend([os.path.abspath(os.path.join(root,file)) for file in files if file.endswith(file_filters[file_filter])])

    return filtered_files