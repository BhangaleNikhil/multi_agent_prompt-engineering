from src.states import AppState
from src.utils import CacheHandler
import os
from pathlib import Path

cache_handler = CacheHandler()
def report_writer(state:AppState)->AppState:
    print(f"{25*'='}Report Writer is called{25*'='}\n")
    cache_keys = state["cache_key"]
    root_path = os.path.abspath(state["root_path"])
    store_path = os.path.abspath(state["storage_folder"])

    counter = 0

    for key in cache_keys:
        document = cache_handler.get_document(doc_key=key)

        file_path = document.get("file_path","")
        file_path = file_path.replace(root_path,store_path)
        file_path = Path(file_path.replace(".py",".md"))
        print(f"{35*'='}Calling from report writer{file_path}")
        if not file_path.parent.exists():
            file_path.parent.mkdir()

        response = document.get("message","")

        with open(file_path,"w+",encoding="utf-8") as file:
            file.write(response)
        
        counter += 1

    state["reports"]["docs"].extend(cache_keys)
    state["reports"]["count"] += counter
    state["cache_key"].clear()
    return state