from src.states import AppState
from src.utils import CacheHandler, LogCacheHandler, LogStorage
import os
from pathlib import Path
import json
import logging
logger = logging.getLogger(__name__)

import time

cache_handler = CacheHandler()
log_cache_handler = LogCacheHandler()
log_storage = LogStorage()

def report_writer(state:AppState)->AppState:
    print(f"{25*'='}Report Writer is called{25*'='}\n")
    try:
        cache_keys = state["cache_key"]
        logger.debug(f"Cheche keys length: {len(cache_keys)}")
        root_path = os.path.abspath(state["root_path"])
        store_path = os.path.abspath(state["storage_folder"])

        counter = 0

        for key in cache_keys:
            try:
                document = cache_handler.get_document(doc_key=key)

                file_path = document.get("file_path","")
                file_path = file_path.replace(root_path,store_path)
                file_path = Path(file_path.replace(".py",".md"))
                print(f"{35*'='}Calling from report writer{file_path}")
                if not file_path.parent.exists():
                    logger.info(f"Directory did not exist. Creating dir: {file_path.parent}")
                    file_path.parent.mkdir()

                response = document.get("message","")
                try:
                    with open(file_path,"w+",encoding="utf-8") as file:
                        file.write(response)
                except Exception as e:
                    logger.error(e)
                
                counter += 1
            except Exception as e:
                logger.error(e)

        logger.info("Getting logs from cache")
        try:
            logs = [(log.get("timestamp",""),log.get("log_message","")) for log in log_cache_handler.get_logs(key="logs")]
            logger.info("Storing logs to long term storage")
            execution_status = log_storage.store_logs(logs=logs)
            logger.info("Stored logs to long term storage")
            if execution_status:
                logger.info("Deleting logs from cache")
                log_cache_handler.delete_all_logs(key="logs")
        except Exception as e:
                logger.error(e)
        state["reports"]["docs"].extend(cache_keys)
        state["reports"]["count"] += counter
        state["cache_key"].clear()

        if len(state["py_docs"]["processed_docs"]) % 100 == 0:
            time.sleep(30)
    except Exception as e:
        logger.error(e)
    return state