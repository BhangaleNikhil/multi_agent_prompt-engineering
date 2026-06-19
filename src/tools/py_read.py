from langchain.tools import tool
import logging
logger = logging.getLogger(__name__)

def py_read(file_name:str) -> str:
    """py_red function read .py python files and return their code
    
    Args:
    file_name:str

    return:
    str
    """
    try:
        with open(file_name,"r") as file:
            data = file.read()
    except Exception as e:
        data = ""
    return data