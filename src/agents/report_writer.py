from src.states import AppState
from src.utils import CacheHandler
import os
from pathlib import Path

cache_handler = CacheHandler()
def report_writer(state:AppState)->AppState:
    cache_keys = state["cache_key"]
    root_path = state["root_path"]
    store_path = state["storage_folder"]

    processed_docs = []
    counter = 0

    for key in cache_keys:
        document = cache_handler.get_document(doc_key=key)

        file_path = document.get("file_path","")
        file_path = Path(os.path.join(store_path, file_path.split(root_path)[-1])).absolute()
        response = document.get("message","")
        file_path.parent.mkdir()

        with open(file_path,"w+") as file:
            file.write(response)
        
        processed_docs.append(str(file_path))
        counter += 1

        cache_handler.delete_document(doc_key=key)

    state["reports"]["docs"].extend(processed_docs)
    state["reports"]["count"] = counter
    state["cache_key"].clear()
    return state