from langchain.tools import tool

def py_read(file_name:str) -> str:
    """py_red function read .py python files and return their code
    
    Args:
    file_name:str

    return:
    str
    """
    with open(file_name,"r") as file:
        data = file.read()
    return data