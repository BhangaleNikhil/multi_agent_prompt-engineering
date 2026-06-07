def py_read(file_name:str) -> str:
    with open(file_name,"r") as file:
        data = file.read()

    return data